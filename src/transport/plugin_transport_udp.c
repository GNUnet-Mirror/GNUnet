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

/*
 * Transport cost to peer, always 1 for UDP (direct connection)
 */
#define UDP_DIRECT_DISTANCE 1

/**
 * Handle for request of hostname resolution, non-NULL if pending.
 */
static struct GNUNET_RESOLVER_RequestHandle *hostname_dns;

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


struct PrettyPrinterContext
{
  GNUNET_TRANSPORT_AddressStringCallback asc;
  void *asc_cls;
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
   * Handle for the statistics service.
   */
  struct GNUNET_STATISTICS_Handle *statistics;

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
 * the socket that we transmit all data with
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
udp_disconnect (void *cls, const struct GNUNET_PeerIdentity *target)
{
  /* nothing to do, UDP is stateless */
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
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
 * @param cls closure
 * @param target who should receive this message (ignored by UDP)
 * @param msgbuf one or more GNUNET_MessageHeader(s) strung together
 * @param msgbuf_size the size of the msgbuf to send
 * @param priority how important is the message (ignored by UDP)
 * @param timeout when should we time out (give up) if we can not transmit?
 * @param addr the addr to send the message to, needs to be a sockaddr for us
 * @param addrlen the len of addr
 * @param force_address not used, we had better have an address to send to
 *        because we are stateless!!
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 *
 * @return the number of bytes written
 */

static ssize_t
udp_plugin_send (void *cls,
                 const struct GNUNET_PeerIdentity *target,
                 const char *msgbuf,
                 size_t msgbuf_size,
                 unsigned int priority,
                 struct GNUNET_TIME_Relative timeout,
                 const void *addr,
                 size_t addrlen,
                 int force_address,
                 GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct UDPMessage *message;
  int ssize;
  ssize_t sent;

  GNUNET_assert(udp_sock != NULL);

  if ((addr == NULL) || (addrlen == 0))
    {
#if DEBUG_UDP
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                   ("udp_plugin_send called without address, returning!\n"));
#endif
      cont (cont_cls, target, GNUNET_OK);
      return 0; /* Can never send if we don't have an address!! */
    }

  /* Build the message to be sent */
  message = GNUNET_malloc (sizeof (struct UDPMessage) + msgbuf_size);
  ssize = sizeof (struct UDPMessage) + msgbuf_size;

#if DEBUG_UDP
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                   ("In udp_send, ssize is %d, sending message to %s\n"), ssize, GNUNET_a2s((const struct sockaddr *)addr, addrlen));
#endif
  message->header.size = htons (ssize);
  message->header.type = htons (0);
  memcpy (&message->sender, plugin->env->my_identity,
          sizeof (struct GNUNET_PeerIdentity));
  memcpy (&message[1], msgbuf, msgbuf_size);

  /* Actually send the message */
  sent =
    GNUNET_NETWORK_socket_sendto (udp_sock, message, ssize,
                                  addr,
                                  addrlen);

  if (cont != NULL)
    {
      if (sent == GNUNET_SYSERR)
        cont (cont_cls, target, GNUNET_SYSERR);
      else
        {
#if DEBUG_UDP
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                   ("Sucessfully sent message, calling transmit continuation!\n"));
#endif
          cont (cont_cls, target, GNUNET_OK);
        }
    }
  GNUNET_free (message);
  return sent;
}


/**
 * Add the IP of our network interface to the list of
 * our external IP addresses.
 */
static int
process_interfaces (void *cls,
                    const char *name,
                    int isDefault,
                    const struct sockaddr *addr, socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  int af;
  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;

  af = addr->sa_family;
  if (af == AF_INET)
    {
      v4 = (struct sockaddr_in *) addr;
      v4->sin_port = htons (plugin->adv_port);
    }
  else
    {
      GNUNET_assert (af == AF_INET6);
      v6 = (struct sockaddr_in6 *) addr;
      v6->sin6_port = htons (plugin->adv_port);
    }
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO |
                   GNUNET_ERROR_TYPE_BULK,
                   "udp", _("Found address `%s' (%s)\n"),
                   GNUNET_a2s (addr, addrlen), name);
  plugin->env->notify_address (plugin->env->cls,
                               "udp",
                               addr, addrlen, GNUNET_TIME_UNIT_FOREVER_REL);

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
    while (offset < tsize)
      {
        currhdr = (struct GNUNET_MessageHeader *)&msgbuf[offset];
#if DEBUG_UDP
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                     ("processing msg %d: type %d, size %d at offset %d\n"),
                     count, ntohs(currhdr->type), ntohs(currhdr->size), offset);
#endif
        plugin->env->receive (plugin->env->cls,
            sender, currhdr, UDP_DIRECT_DISTANCE, (char *)&addr, fromlen);
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
 *
 * TODO: perhaps make everything work with sockaddr_storage, it may
 *       be a cleaner way to handle addresses in UDP
 */
static int
udp_check_address (void *cls, void *addr, size_t addrlen)
{
  struct Plugin *plugin = cls;
  char buf[sizeof (struct sockaddr_in6)];

  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;

  if ((addrlen != sizeof (struct sockaddr_in)) &&
      (addrlen != sizeof (struct sockaddr_in6)))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  memcpy (buf, addr, sizeof (struct sockaddr_in6));
  if (addrlen == sizeof (struct sockaddr_in))
    {
      v4 = (struct sockaddr_in *) buf;
      v4->sin_port = htons (check_port (plugin, ntohs (v4->sin_port)));
    }
  else
    {
      v6 = (struct sockaddr_in6 *) buf;
      v6->sin6_port = htons (check_port (plugin, ntohs (v6->sin6_port)));
    }
#if DEBUG_UDP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp",
                   "Informing transport service about my address `%s'.\n",
                   GNUNET_a2s (addr, addrlen));
#endif
  return GNUNET_OK;
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
  const struct sockaddr_in *v4;
  const struct sockaddr_in6 *v6;
  struct PrettyPrinterContext *ppc;

  if ((addrlen != sizeof (struct sockaddr_in)) &&
      (addrlen != sizeof (struct sockaddr_in6)))
    {
      /* invalid address */
      GNUNET_break_op (0);
      asc (asc_cls, NULL);
      return;
    }
  ppc = GNUNET_malloc (sizeof (struct PrettyPrinterContext));
  ppc->asc = asc;
  ppc->asc_cls = asc_cls;
  if (addrlen == sizeof (struct sockaddr_in))
    {
      v4 = (const struct sockaddr_in *) addr;
      ppc->port = ntohs (v4->sin_port);
    }
  else
    {
      v6 = (const struct sockaddr_in6 *) addr;
      ppc->port = ntohs (v6->sin6_port);

    }
  GNUNET_RESOLVER_hostname_get (plugin->env->sched,
                                plugin->env->cfg,
                                addr,
                                addrlen,
                                !numeric, timeout, &append_port, ppc);
}


/**
 * The exported method. Makes the core api available via a global and
 * returns the udp transport API.
 */
void *
libgnunet_plugin_transport_udp_init (void *cls)
{
  unsigned long long mtu;

  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  struct GNUNET_SERVICE_Context *service;
  unsigned long long aport;
  unsigned long long bport;

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
  plugin->statistics = NULL;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;

  api->send = &udp_plugin_send;
  api->disconnect = &udp_disconnect;
  api->address_pretty_printer = &udp_plugin_address_pretty_printer;
  api->check_address = &udp_check_address;

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
  if (NULL != hostname_dns)
    {
      GNUNET_RESOLVER_request_cancel (hostname_dns);
      hostname_dns = NULL;
    }
  GNUNET_SERVICE_stop (plugin->service);

  GNUNET_NETWORK_fdset_destroy (plugin->rs);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_udp.c */
