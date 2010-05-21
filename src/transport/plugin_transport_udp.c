/*
     This file is part of GNUnet
     (C) 2010 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file transport/plugin_transport_udp.c
 * @brief Implementation of the UDP transport service
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_connection_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_protocols.h"
#include "gnunet_resolver_service.h"
#include "gnunet_server_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "plugin_transport.h"
#include "transport.h"

#define DEBUG_UDP GNUNET_NO

/**
 * Transport cost to peer, always 1 for UDP (direct connection)
 */
#define UDP_DIRECT_DISTANCE 1

/**
 * How long until we give up on transmitting the welcome message?
 */
#define HOSTNAME_RESOLVE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)


/**
 * Message-Packet header.
 */
struct UDPMessage
{
  /**
   * size of the message, in bytes, including this header.
   */
  struct GNUNET_MessageHeader header;

  /**
   * What is the identity of the sender (GNUNET_hash of public key)
   */
  struct GNUNET_PeerIdentity sender;

};


/**
 * Network format for IPv4 addresses.
 */
struct IPv4UdpAddress
{
  /**
   * IPv4 address, in network byte order.
   */
  uint32_t ipv4_addr;

  /**
   * Port number, in network byte order.
   */
  uint16_t u_port;

};


/**
 * Network format for IPv6 addresses.
 */
struct IPv6UdpAddress
{
  /**
   * IPv6 address.
   */
  struct in6_addr ipv6_addr;

  /**
   * Port number, in network byte order.
   */
  uint16_t u6_port;

};


/**
 *
 */
struct PrettyPrinterContext
{
  /**
   *
   */
  GNUNET_TRANSPORT_AddressStringCallback asc;

  /**
   * Closure for 'asc'.
   */
  void *asc_cls;

  /**
   *
   */
  uint16_t port;
};


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin
{
  /**
   * Our environment.
   */
  struct GNUNET_TRANSPORT_PluginEnvironment *env;

  /**
   * Handle to the network service.
   */
  struct GNUNET_SERVICE_Context *service;

  /**
   * Handle for request of hostname resolution, non-NULL if pending.
   */
  struct GNUNET_RESOLVER_RequestHandle *hostname_dns;

  /**
   * FD Read set
   */
  struct GNUNET_NETWORK_FDSet *rs;

  /**
   * ID of task used to update our addresses when one expires.
   */
  GNUNET_SCHEDULER_TaskIdentifier address_update_task;

  /**
   * ID of select task
   */
  GNUNET_SCHEDULER_TaskIdentifier select_task;

  /**
   * Port that we are actually listening on.
   */
  uint16_t open_port;

  /**
   * Port that the user said we would have visible to the
   * rest of the world.
   */
  uint16_t adv_port;

};

/* *********** globals ************* */

/**
 * The socket that we transmit all data with
 */
static struct GNUNET_NETWORK_Handle *udp_sock;

/**
 * Disconnect from a remote node.
 *
 * @param cls closure ('struct Plugin'), unused
 * @param target peer do disconnect
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
void
udp_disconnect (void *cls, 
		const struct GNUNET_PeerIdentity *target)
{
  /* nothing to do, UDP is stateless */
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 *
 * @param cls closure, the 'struct Plugin*'
 */
static int
udp_transport_server_stop (void *cls)
{
  struct Plugin *plugin = cls;
  int ret;

  GNUNET_assert (udp_sock != NULL);
  if (plugin->select_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->env->sched, plugin->select_task);
      plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
    }

  ret = GNUNET_NETWORK_socket_close (udp_sock);
  if (ret != GNUNET_SYSERR)
    udp_sock = NULL;
  return ret;
}

/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.
 *
 * @param cls closure, the 'struct Plugin*'
 * @param target who should receive this message (ignored by UDP)
 * @param msgbuf one or more GNUNET_MessageHeader(s) strung together
 * @param msgbuf_size the size of the msgbuf to send
 * @param priority how important is the message (ignored by UDP)
 * @param timeout when should we time out (give up) if we can not transmit?
 * @param session which session must be used (always NULL for UDP)
 * @param addr the addr to send the message to, needs to be a sockaddr for us
 * @param addrlen the len of addr
 * @param force_address GNUNET_YES if the plugin MUST use the given address,
 *                GNUNET_NO means the plugin may use any other address and
 *                GNUNET_SYSERR means that only reliable existing
 *                bi-directional connections should be used (regardless
 *                of address)
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 *
 * @return the number of bytes written, -1 on error (in this case, cont is not called)
 */
static ssize_t
udp_plugin_send (void *cls,
                 const struct GNUNET_PeerIdentity *target,
                 const char *msgbuf,
                 size_t msgbuf_size,
                 unsigned int priority,
                 struct GNUNET_TIME_Relative timeout,
		 struct Session *session,
                 const void *addr,
                 size_t addrlen,
                 int force_address,
                 GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct UDPMessage *message;
  int ssize;
  ssize_t sent;
  const void *sb;
  size_t sbs;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  const struct IPv4UdpAddress *t4;
  const struct IPv6UdpAddress *t6;

  GNUNET_assert (NULL == session);
  GNUNET_assert(udp_sock != NULL);
  if ( (addr == NULL) || (addrlen == 0) )
    {
#if DEBUG_UDP
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                   ("udp_plugin_send called without address, returning!\n"));
#endif
      return -1; /* Can never send if we don't have an address!! */
    }
  if (force_address == GNUNET_SYSERR)
    return -1; /* never reliable */

  if (addrlen == sizeof (struct IPv6UdpAddress))
    {
      t6 = addr;
      memset (&a6, 0, sizeof (a6));
#if HAVE_SOCKADDR_IN_SIN_LEN
      a6.sin6_len = sizeof (a6);
#endif
      a6.sin6_family = AF_INET6;
      a6.sin6_port = t6->u6_port;
      memcpy (a6.sin6_addr.s6_addr,
	      &t6->ipv6_addr,
	      16);      
      sb = &a6;
      sbs = sizeof (a6);
    }
  else if (addrlen == sizeof (struct IPv4UdpAddress))
    {
      t4 = addr;
      memset (&a4, 0, sizeof (a4));
#if HAVE_SOCKADDR_IN_SIN_LEN
      a4.sin_len = sizeof (a4);
#endif
      a4.sin_family = AF_INET;
      a4.sin_port = t4->u_port;
      a4.sin_addr.s_addr = t4->ipv4_addr;
      sb = &a4;
      sbs = sizeof (a4);
    }
  else
    {
      GNUNET_break_op (0);
      return -1;
    }

  /* Build the message to be sent */
  message = GNUNET_malloc (sizeof (struct UDPMessage) + msgbuf_size);
  ssize = sizeof (struct UDPMessage) + msgbuf_size;

#if DEBUG_UDP
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", 
                   "In udp_send, ssize is %d, sending message to `%s'\n", 
		   ssize, 
		   GNUNET_a2s(sb, sbs));
#endif
  message->header.size = htons (ssize);
  message->header.type = htons (0);
  memcpy (&message->sender, plugin->env->my_identity,
          sizeof (struct GNUNET_PeerIdentity));
  memcpy (&message[1], msgbuf, msgbuf_size);
  sent =
    GNUNET_NETWORK_socket_sendto (udp_sock, message, ssize,
                                  sb, sbs);
  if ( (cont != NULL) &&
       (sent != -1) )
    cont (cont_cls, target, GNUNET_OK);
  GNUNET_free (message);
  return sent;
}


/**
 * Add the IP of our network interface to the list of
 * our external IP addresses.
 *
 * @param cls closure (the 'struct Plugin*')
 * @param name name of the interface (can be NULL for unknown)
 * @param isDefault is this presumably the default interface
 * @param addr address of this interface (can be NULL for unknown or unassigned)
 * @param addrlen length of the address
 * @return GNUNET_OK to continue iterating
 */
static int
process_interfaces (void *cls,
                    const char *name,
                    int isDefault,
                    const struct sockaddr *addr, socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  int af;
  struct IPv4UdpAddress t4;
  struct IPv6UdpAddress t6;
  void *arg;
  uint16_t args;

  af = addr->sa_family;
  if (af == AF_INET)
    {
      t4.ipv4_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
      t4.u_port = htons (plugin->adv_port);
      arg = &t4;
      args = sizeof (t4);
    }
  else if (af == AF_INET6)
    {
      memcpy (&t6.ipv6_addr,
	      ((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr,
	      16);
      t6.u6_port = htons (plugin->adv_port);
      arg = &t6;
      args = sizeof (t6);
    }
  else
    {
      GNUNET_break (0);
      return GNUNET_OK;
    }
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO |
                   GNUNET_ERROR_TYPE_BULK,
                   "udp", 
		   _("Found address `%s' (%s)\n"),
                   GNUNET_a2s (addr, addrlen), 
		   name);
  plugin->env->notify_address (plugin->env->cls,
                               "udp",
                               arg, args, GNUNET_TIME_UNIT_FOREVER_REL);
  return GNUNET_OK;
}


/**
 * Function called by the resolver for each address obtained from DNS
 * for our own hostname.  Add the addresses to the list of our
 * external IP addresses.
 *
 * @param cls closure
 * @param addr one of the addresses of the host, NULL for the last address
 * @param addrlen length of the address
 */
static void
process_hostname_ips (void *cls,
                      const struct sockaddr *addr, socklen_t addrlen)
{
  struct Plugin *plugin = cls;

  if (addr == NULL)
    {
      plugin->hostname_dns = NULL;
      return;
    }
  process_interfaces (plugin, "<hostname>", GNUNET_YES, addr, addrlen);
}


/*
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 *
 * We have been notified that our writeset has something to read.  Presumably
 * select has been called already, so we can go ahead and start reading from
 * the socket immediately.  Then we check if there is more to be read by
 * calling select ourselves while there is stuff on the wire.  Then reschedule
 * this function to be called again once more is available.
 *
 */
static void
udp_plugin_select (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  char *buf;
  struct UDPMessage *msg;
  struct GNUNET_PeerIdentity *sender;
  unsigned int buflen;
  socklen_t fromlen;
  struct sockaddr_storage addr;
  ssize_t ret;
  int offset;
  int count;
  int tsize;
  char *msgbuf;
  const struct GNUNET_MessageHeader *currhdr;
  struct IPv4UdpAddress t4;
  struct IPv6UdpAddress t6;
  const struct sockaddr_in *s4;
  const struct sockaddr_in6 *s6;
  const void *ca;
  size_t calen;

#if DEBUG_UDP
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                       ("entered select...\n"));
#endif

      buflen = GNUNET_NETWORK_socket_recvfrom_amount (udp_sock);

#if DEBUG_UDP
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                       ("we expect to read %u bytes\n"), buflen);
#endif

    if (buflen == GNUNET_NO)
      return;

    buf = GNUNET_malloc (buflen);
    fromlen = sizeof (addr);

    memset (&addr, 0, fromlen);
    ret =
      GNUNET_NETWORK_socket_recvfrom (udp_sock, buf, buflen,
                                      (struct sockaddr *) &addr, &fromlen);

#if DEBUG_UDP
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                     ("socket_recv returned %u, src_addr_len is %u\n"), ret,
                     fromlen);
#endif

    if (ret <= 0)
      {
        GNUNET_free (buf);
        return;
      }
    msg = (struct UDPMessage *) buf;

#if DEBUG_UDP
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                     ("header reports message size of %d\n"),
                     ntohs (msg->header.size));

    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                     ("header reports message type of %d\n"),
                     ntohs (msg->header.type));
#endif
    if (ntohs (msg->header.size) < sizeof (struct UDPMessage))
      {
        GNUNET_free (buf);
        GNUNET_NETWORK_fdset_zero (plugin->rs);
        GNUNET_NETWORK_fdset_set (plugin->rs, udp_sock);
        return;
      }
    msgbuf = (char *)&msg[1];
    sender = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
    memcpy (sender, &msg->sender, sizeof (struct GNUNET_PeerIdentity));

    offset = 0;
    count = 0;
    tsize = ntohs (msg->header.size) - sizeof(struct UDPMessage);
#if DEBUG_UDP
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "UDP", _
                     ("offset is %d, tsize is %d (UDPMessage size is %d)\n"),
                     offset, tsize, sizeof(struct UDPMessage));
#endif

    if (fromlen == sizeof (struct sockaddr_in))
      {
	s4 = (const struct sockaddr_in*) &addr;
	t4.u_port = s4->sin_port;
	t4.ipv4_addr = s4->sin_addr.s_addr;
	ca = &t4;
	calen = sizeof (struct IPv4UdpAddress);
      }
    else if (fromlen == sizeof (struct sockaddr_in6))
      {
	s6 = (const struct sockaddr_in6*) &addr;
	t6.u6_port = s6->sin6_port;
	memcpy (&t6.ipv6_addr,
		s6->sin6_addr.s6_addr,
		16);
	ca = &t6;
	calen = sizeof (struct IPv6UdpAddress);
      }
    else
      {
	GNUNET_break (0);
	ca = NULL;
	calen = 0;
      }
    while (offset < tsize)
      {
        currhdr = (struct GNUNET_MessageHeader *)&msgbuf[offset];
#if DEBUG_UDP
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                     ("processing msg %d: type %d, size %d at offset %d\n"),
                     count, ntohs(currhdr->type), ntohs(currhdr->size), offset);
#endif
        plugin->env->receive (plugin->env->cls,
			      sender, currhdr, UDP_DIRECT_DISTANCE, 
			      NULL, ca, calen);
        offset += ntohs(currhdr->size);
#if DEBUG_UDP
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                     ("offset now %d, tsize %d\n"),
                     offset, tsize);
#endif
        count++;
      }

    GNUNET_free (sender);
    GNUNET_free (buf);

  plugin->select_task =
    GNUNET_SCHEDULER_add_select (plugin->env->sched,
                                 GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                 GNUNET_SCHEDULER_NO_TASK,
                                 GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
                                 NULL, &udp_plugin_select, plugin);

}

/**
 * Create a UDP socket.  If possible, use IPv6, otherwise
 * try IPv4.
 * @param cls closure, the 'struct Plugin*'
 */
static struct GNUNET_NETWORK_Handle *
udp_transport_server_start (void *cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_NETWORK_Handle *desc;
  struct sockaddr_in serverAddrv4;
  struct sockaddr_in6 serverAddrv6;
  struct sockaddr *serverAddr;
  socklen_t addrlen;

  desc = NULL;
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg, "GNUNETD",
                                            "DISABLE-IPV6"))
    {
      desc = GNUNET_NETWORK_socket_create (PF_INET6, SOCK_DGRAM, 17);
      if (desc != NULL)
        {
          memset (&serverAddrv6, 0, sizeof (serverAddrv6));
#if HAVE_SOCKADDR_IN_SIN_LEN
          serverAddrv6.sin6_len = sizeof (serverAddrv6);
#endif
          serverAddrv6.sin6_family = AF_INET6;
          serverAddrv6.sin6_addr = in6addr_any;
          serverAddrv6.sin6_port = htons (plugin->open_port);
          addrlen = sizeof (serverAddrv6);
          serverAddr = (struct sockaddr *) &serverAddrv6;
        }
    }
  if (NULL == desc)
    {
      desc = GNUNET_NETWORK_socket_create (PF_INET, SOCK_DGRAM, 17);
      if (NULL == desc)
        {
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp", "socket");
          return NULL;
        }
      else
        {
          memset (&serverAddrv4, 0, sizeof (serverAddrv4));
#if HAVE_SOCKADDR_IN_SIN_LEN
          serverAddrv4.sin_len = sizeof (serverAddrv4);
#endif
          serverAddrv4.sin_family = AF_INET;
          serverAddrv4.sin_addr.s_addr = INADDR_ANY;
          serverAddrv4.sin_port = htons (plugin->open_port);
          addrlen = sizeof (serverAddrv4);
          serverAddr = (struct sockaddr *) &serverAddrv4;
        }
    }

  if (desc != NULL)
    {
      GNUNET_assert (GNUNET_NETWORK_socket_bind (desc, serverAddr, addrlen) ==
                     GNUNET_OK);
    }

  plugin->rs = GNUNET_NETWORK_fdset_create ();

  GNUNET_NETWORK_fdset_zero (plugin->rs);
  GNUNET_NETWORK_fdset_set (plugin->rs, desc);

  plugin->select_task =
    GNUNET_SCHEDULER_add_select (plugin->env->sched,
                                 GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                 GNUNET_SCHEDULER_NO_TASK,
                                 GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
                                 NULL, &udp_plugin_select, plugin);

  return desc;
}


/**
 * Check if the given port is plausible (must be either
 * our listen port or our advertised port).  If it is
 * neither, we return one of these two ports at random.
 *
 * @return either in_port or a more plausible port
 */
static uint16_t
check_port (struct Plugin *plugin, uint16_t in_port)
{
  if ((in_port == plugin->adv_port) || (in_port == plugin->open_port))
    return in_port;
  return (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                    2) == 0)
    ? plugin->open_port : plugin->adv_port;
}


/**
 * Another peer has suggested an address for this peer and transport
 * plugin.  Check that this could be a valid address.  This function
 * is not expected to 'validate' the address in the sense of trying to
 * connect to it but simply to see if the binary format is technically
 * legal for establishing a connection.
 *
 * @param cls handle to Plugin
 * @param addr address to check
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport, GNUNET_SYSERR if not
 */
static int
udp_check_address (void *cls, void *addr, size_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4UdpAddress *v4;
  struct IPv6UdpAddress *v6;

  if ((addrlen != sizeof (struct IPv4UdpAddress)) &&
      (addrlen != sizeof (struct IPv6UdpAddress)))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (addrlen == sizeof (struct IPv4UdpAddress))
    {
      v4 = (struct IPv4UdpAddress *) addr;
      v4->u_port = htons (check_port (plugin, ntohs (v4->u_port)));
    }
  else
    {
      v6 = (struct IPv6UdpAddress *) addr;
      v6->u6_port = htons (check_port (plugin, ntohs (v6->u6_port)));
    }
  return GNUNET_OK;
}


/**
 * Append our port and forward the result.
 */
static void
append_port (void *cls, const char *hostname)
{
  struct PrettyPrinterContext *ppc = cls;
  char *ret;

  if (hostname == NULL)
    {
      ppc->asc (ppc->asc_cls, NULL);
      GNUNET_free (ppc);
      return;
    }
  GNUNET_asprintf (&ret, "%s:%d", hostname, ppc->port);
  ppc->asc (ppc->asc_cls, ret);
  GNUNET_free (ret);
}


/**
 * Convert the transports address to a nice, human-readable
 * format.
 *
 * @param cls closure
 * @param type name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 * @param numeric should (IP) addresses be displayed in numeric form?
 * @param timeout after how long should we give up?
 * @param asc function to call on each string
 * @param asc_cls closure for asc
 */
static void
udp_plugin_address_pretty_printer (void *cls,
                                   const char *type,
                                   const void *addr,
                                   size_t addrlen,
                                   int numeric,
                                   struct GNUNET_TIME_Relative timeout,
                                   GNUNET_TRANSPORT_AddressStringCallback asc,
                                   void *asc_cls)
{
  struct Plugin *plugin = cls;
  struct PrettyPrinterContext *ppc;
  const void *sb;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  const struct IPv4UdpAddress *t4;
  const struct IPv6UdpAddress *t6;
  size_t sbs;
  uint16_t port;

  if (addrlen == sizeof (struct IPv6UdpAddress))
    {
      t6 = addr;
      memset (&a6, 0, sizeof (a6));
      a6.sin6_family = AF_INET6;
      a6.sin6_port = t6->u6_port;
      port = ntohs (t6->u6_port);
      memcpy (a6.sin6_addr.s6_addr,
	      &t6->ipv6_addr,
	      16);      
      sb = &a6;
      sbs = sizeof (a6);
    }
  else if (addrlen == sizeof (struct IPv4UdpAddress))
    {
      t4 = addr;
      memset (&a4, 0, sizeof (a4));
      a4.sin_family = AF_INET;
      a4.sin_port = t4->u_port;
      a4.sin_addr.s_addr = t4->ipv4_addr;
      port = ntohs (t4->u_port);
      sb = &a4;
      sbs = sizeof (a4);
    }
  else
    {
      /* invalid address */
      GNUNET_break_op (0);
      asc (asc_cls, NULL);
      return;
    }
  ppc = GNUNET_malloc (sizeof (struct PrettyPrinterContext));
  ppc->asc = asc;
  ppc->asc_cls = asc_cls;
  ppc->port = port;
  GNUNET_RESOLVER_hostname_get (plugin->env->sched,
                                plugin->env->cfg,
                                sb,
                                sbs,
                                !numeric, timeout, &append_port, ppc);
}



/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the 
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param cls closure
 * @param addr binary address
 * @param addrlen length of the address
 * @return string representing the same address 
 */
static const char* 
udp_address_to_string (void *cls,
		       const void *addr,
		       size_t addrlen)
{
  static char rbuf[INET6_ADDRSTRLEN + 10];
  char buf[INET6_ADDRSTRLEN];
  const void *sb;
  struct in_addr a4;
  struct in6_addr a6;
  const struct IPv4UdpAddress *t4;
  const struct IPv6UdpAddress *t6;
  int af;
  uint16_t port;

  if (addrlen == sizeof (struct IPv6UdpAddress))
    {
      t6 = addr;
      af = AF_INET6;
      port = ntohs (t6->u6_port);
      memcpy (&a6, &t6->ipv6_addr, sizeof (a6));
      sb = &a6;
    }
  else if (addrlen == sizeof (struct IPv4UdpAddress))
    {
      t4 = addr;
      af = AF_INET;
      port = ntohs (t4->u_port);
      memcpy (&a4, &t4->ipv4_addr, sizeof (a4));
      sb = &a4;
    }
  else
    return NULL;
  inet_ntop (af, sb, buf, INET6_ADDRSTRLEN);
  GNUNET_snprintf (rbuf,
		   sizeof (rbuf),
		   "%s:%u",
		   buf,
		   port);
  return rbuf;
}


/**
 * The exported method. Makes the core api available via a global and
 * returns the udp transport API.
 *
 * @param cls closure, the 'struct GNUNET_TRANSPORT_PluginEnvironment*'
 * @return the 'struct GNUNET_TRANSPORT_PluginFunctions*' or NULL on error
 */
void *
libgnunet_plugin_transport_udp_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  struct GNUNET_SERVICE_Context *service;
  unsigned long long aport;
  unsigned long long bport;
  unsigned long long mtu;

  service = GNUNET_SERVICE_start ("transport-udp", env->sched, env->cfg);
  if (service == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "udp", _
                       ("Failed to start service for `%s' transport plugin.\n"),
                       "udp");
      return NULL;
    }
  aport = 0;
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (env->cfg,
                                              "transport-udp",
                                              "PORT",
                                              &bport)) ||
      (bport > 65535) ||
      ((GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_number (env->cfg,
                                               "transport-udp",
                                               "ADVERTISED-PORT",
                                               &aport)) && (aport > 65535)))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "udp",
                       _
                       ("Require valid port number for service `%s' in configuration!\n"),
                       "transport-udp");
      GNUNET_SERVICE_stop (service);
      return NULL;
    }
  if (aport == 0)
    aport = bport;

  mtu = 1240;
  if (mtu < 1200)
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                     "udp",
                     _("MTU %llu for `%s' is probably too low!\n"), mtu,
                     "UDP");

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->open_port = bport;
  plugin->adv_port = aport;
  plugin->env = env;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;

  api->send = &udp_plugin_send;
  api->disconnect = &udp_disconnect;
  api->address_pretty_printer = &udp_plugin_address_pretty_printer;
  api->check_address = &udp_check_address;
  api->address_to_string = &udp_address_to_string;
  plugin->service = service;

  /* FIXME: do the two calls below periodically again and
     not just once (since the info we get might change...) */
  GNUNET_OS_network_interfaces_list (&process_interfaces, plugin);
  plugin->hostname_dns = GNUNET_RESOLVER_hostname_resolve (env->sched,
                                                           env->cfg,
                                                           AF_UNSPEC,
                                                           HOSTNAME_RESOLVE_TIMEOUT,
                                                           &process_hostname_ips,
                                                           plugin);

  udp_sock = udp_transport_server_start (plugin);

  GNUNET_assert (udp_sock != NULL);

  return api;
}

void *
libgnunet_plugin_transport_udp_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  udp_transport_server_stop (plugin);
  if (NULL != plugin->hostname_dns)
    {
      GNUNET_RESOLVER_request_cancel (plugin->hostname_dns);
      plugin->hostname_dns = NULL;
    }
  GNUNET_SERVICE_stop (plugin->service);

  GNUNET_NETWORK_fdset_destroy (plugin->rs);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_udp.c */
