/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004, 2005, 2008 Christian Grothoff (and other contributing authors)

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
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "gnunet_stats_service.h"
#include "gnunet_upnp_service.h"
#include "ip.h"

#define DEBUG_UDP GNUNET_YES

/**
 * The default maximum size of each outbound UDP message,
 * optimal value for Ethernet (10 or 100 MBit).
 */
#define MESSAGE_SIZE 1472

/**
 * Message-Packet header.
 */
typedef struct
{
  /**
   * size of the message, in bytes, including this header.
   */
  GNUNET_MessageHeader header;

  /**
   * What is the identity of the sender (GNUNET_hash of public key)
   */
  GNUNET_PeerIdentity sender;

} UDPMessage;

#define MY_TRANSPORT_NAME "UDP"
#include "common.c"

/* *********** globals ************* */

static int stat_bytesReceived;

static int stat_bytesSent;

static int stat_bytesDropped;

static int stat_udpConnected;

/**
 * thread that listens for inbound messages
 */
static struct GNUNET_SelectHandle *selector;

/**
 * the socket that we transmit all data with
 */
static struct GNUNET_SocketHandle *udp_sock;

static struct GNUNET_LoadMonitor *load_monitor;


/**
 * The socket of session has data waiting, process!
 *
 * This function may only be called if the tcplock is
 * already held by the caller.
 */
static int
select_message_handler (void *mh_cls,
                        struct GNUNET_SelectHandle *sh,
                        struct GNUNET_SocketHandle *sock,
                        void *sock_ctx, const GNUNET_MessageHeader * msg)
{
  unsigned int len;
  GNUNET_TransportPacket *mp;
  const UDPMessage *um;

  len = ntohs (msg->size);
  if (len <= sizeof (UDPMessage))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _("Received malformed message via %s. Ignored.\n"),
                     "UDP");
      return GNUNET_SYSERR;
    }
  um = (const UDPMessage *) msg;
  mp = GNUNET_malloc (sizeof (GNUNET_TransportPacket));
  mp->msg = GNUNET_malloc (len - sizeof (UDPMessage));
  memcpy (mp->msg, &um[1], len - sizeof (UDPMessage));
  mp->sender = um->sender;
  mp->size = len - sizeof (UDPMessage);
  mp->tsession = NULL;
  coreAPI->receive (mp);
  if (stats != NULL)
    stats->change (stat_bytesReceived, len);
  return GNUNET_OK;
}

static void *
select_accept_handler (void *ah_cls,
                       struct GNUNET_SelectHandle *sh,
                       struct GNUNET_SocketHandle *sock,
                       const void *addr, unsigned int addr_len)
{
  static int nonnullpointer;

  if (GNUNET_NO != is_rejected_tester (addr, addr_len))
    return NULL;
  return &nonnullpointer;
}

/**
 * Select has been forced to close a connection.
 * Free the associated context.
 */
static void
select_close_handler (void *ch_cls,
                      struct GNUNET_SelectHandle *sh,
                      struct GNUNET_SocketHandle *sock, void *sock_ctx)
{
  /* do nothing */
}

/**
 * Establish a connection to a remote node.
 *
 * @param hello the hello-Message for the target node
 * @param tsessionPtr the session handle that is to be set
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
udp_connect (const GNUNET_MessageHello * hello,
             GNUNET_TSession ** tsessionPtr, int may_reuse)
{
  GNUNET_TSession *tsession;

  tsession = GNUNET_malloc (sizeof (GNUNET_TSession));
  memset (tsession, 0, sizeof (GNUNET_TSession));
  tsession->internal = GNUNET_malloc (GNUNET_sizeof_hello (hello));
  memcpy (tsession->internal, hello, GNUNET_sizeof_hello (hello));
  tsession->ttype = myAPI.protocol_number;
  tsession->peer = hello->senderIdentity;
  *tsessionPtr = tsession;
  if (stats != NULL)
    stats->change (stat_udpConnected, 1);
  return GNUNET_OK;
}

/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed.
 *
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return GNUNET_OK if the session could be associated,
 *         GNUNET_SYSERR if not.
 */
int
udp_associate (GNUNET_TSession * tsession)
{
  return GNUNET_SYSERR;         /* UDP connections can never be associated */
}

/**
 * Disconnect from a remote node.
 *
 * @param tsession the session that is closed
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
udp_disconnect (GNUNET_TSession * tsession)
{
  if (tsession != NULL)
    {
      if (tsession->internal != NULL)
        GNUNET_free (tsession->internal);
      GNUNET_free (tsession);
      if (stats != NULL)
        stats->change (stat_udpConnected, -1);
    }
  return GNUNET_OK;
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 */
static int
udp_transport_server_stop ()
{
  GNUNET_GE_ASSERT (coreAPI->ectx, udp_sock != NULL);
  if (selector != NULL)
    {
      GNUNET_select_destroy (selector);
      selector = NULL;
    }
  GNUNET_socket_destroy (udp_sock);
  udp_sock = NULL;
  return GNUNET_OK;
}

/**
 * Test if the transport would even try to send
 * a message of the given size and importance
 * for the given session.<br>
 * This function is used to check if the core should
 * even bother to construct (and encrypt) this kind
 * of message.
 *
 * @return GNUNET_YES if the transport would try (i.e. queue
 *         the message or call the OS to send),
 *         GNUNET_NO if the transport would just drop the message,
 *         GNUNET_SYSERR if the size/session is invalid
 */
static int
udp_test_would_try (GNUNET_TSession * tsession, unsigned int size,
                    int important)
{
  const GNUNET_MessageHello *hello;

  if (udp_sock == NULL)
    return GNUNET_SYSERR;
  if (size == 0)
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      return GNUNET_SYSERR;
    }
  if (size > myAPI.mtu)
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      return GNUNET_SYSERR;
    }
  hello = (const GNUNET_MessageHello *) tsession->internal;
  if (hello == NULL)
    return GNUNET_SYSERR;
  return GNUNET_YES;
}

/**
 * Create a UDP socket.  If possible, use IPv6, otherwise
 * try IPv4.  Update available_protocols accordingly.
 */
static struct GNUNET_NETWORK_Handle *
udp_create_socket ()
{
  struct GNUNET_NETWORK_Handle *desc;

  available_protocols = VERSION_AVAILABLE_NONE;
  desc = NULL;
  if (GNUNET_YES !=
      GNUNET_GC_get_configuration_value_yesno (cfg, "GNUNETD", "DISABLE-IPV6",
                                               GNUNET_YES))
    {
      desc = GNUNET_net_socket (PF_INET6, SOCK_DGRAM, 17);
    }
  if (NULL == desc)
    {
      desc = GNUNET_net_socket (PF_INET, SOCK_DGRAM, 17);
      if (NULL == desc)
        {
          GNUNET_GE_LOG_STRERROR (coreAPI->ectx,
                                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                  GNUNET_GE_BULK, "socket");
          return GNUNET_SYSERR;
        }
      available_protocols = VERSION_AVAILABLE_IPV4;
    }
  else
    {
      available_protocols = VERSION_AVAILABLE_IPV6 | VERSION_AVAILABLE_IPV4;
    }
  return desc;
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the GNUNET_MessageHello identifying the remote node
 * @param message what to send
 * @param size the size of the message
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
static int
udp_send (GNUNET_TSession * tsession,
          const void *message, const unsigned int size, int important)
{
  const GNUNET_MessageHello *hello;
  const HostAddress *haddr;
  UDPMessage *mp;
  struct sockaddr_in serverAddrv4;
  struct sockaddr_in6 serverAddrv6;
  struct sockaddr *serverAddr;
  socklen_t addrlen;
  unsigned short available;
  int ok;
  int ssize;
  size_t sent;

  GNUNET_GE_ASSERT (NULL, tsession != NULL);
  if (udp_sock == NULL)
    return GNUNET_SYSERR;
  if (size == 0)
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      return GNUNET_SYSERR;
    }
  if (size > myAPI.mtu)
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      return GNUNET_SYSERR;
    }
  hello = (const GNUNET_MessageHello *) tsession->internal;
  if (hello == NULL)
    return GNUNET_SYSERR;

  haddr = (const HostAddress *) &hello[1];
  available = ntohs (haddr->availability) & available_protocols;
  if (available == VERSION_AVAILABLE_NONE)
    return GNUNET_SYSERR;
  if (available == (VERSION_AVAILABLE_IPV4 | VERSION_AVAILABLE_IPV6))
    {
      if (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 2) == 0)
        available = VERSION_AVAILABLE_IPV4;
      else
        available = VERSION_AVAILABLE_IPV6;
    }
  ssize = size + sizeof (UDPMessage);
  mp = GNUNET_malloc (ssize);
  mp->header.size = htons (ssize);
  mp->header.type = 0;
  mp->sender = *(coreAPI->my_identity);
  memcpy (&mp[1], message, size);
  ok = GNUNET_SYSERR;

  if ((available & VERSION_AVAILABLE_IPV4) > 0)
    {
      memset (&serverAddrv4, 0, sizeof (serverAddrv4));
      serverAddrv4.sin_family = AF_INET;
      serverAddrv4.sin_port = haddr->port;
      memcpy (&serverAddrv4.sin_addr, &haddr->ipv4, sizeof (struct in_addr));
      addrlen = sizeof (serverAddrv4);
      serverAddr = (struct sockaddr *) &serverAddrv4;
    }
  else
    {
      memset (&serverAddrv6, 0, sizeof (serverAddrv6));
      serverAddrv6.sin6_family = AF_INET;
      serverAddrv6.sin6_port = haddr->port;
      memcpy (&serverAddrv6.sin6_addr, &haddr->ipv6,
              sizeof (struct in6_addr));
      addrlen = sizeof (serverAddrv6);
      serverAddr = (struct sockaddr *) &serverAddrv6;
    }
#ifndef MINGW
  if (GNUNET_YES == GNUNET_socket_send_to (udp_sock,
                                           GNUNET_NC_NONBLOCKING,
                                           mp,
                                           ssize, &sent,
                                           (const char *) serverAddr,
                                           addrlen))
#else
  sent =
    win_ols_sendto (udp_sock, mp, ssize, (const char *) serverAddr, addrlen);
  if (sent != SOCKET_ERROR)
#endif
    {
      ok = GNUNET_OK;
      if (stats != NULL)
        stats->change (stat_bytesSent, sent);
    }
  else
    {
      if (stats != NULL)
        stats->change (stat_bytesDropped, ssize);
    }
  GNUNET_free (mp);
  return ok;
}

/**
 * Start the server process to receive inbound traffic.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
udp_transport_server_start ()
{
  struct sockaddr_in serverAddrv4;
  struct sockaddr_in6 serverAddrv6;
  struct sockaddr *serverAddr;
  socklen_t addrlen;
  GNUNET_NETWORK_Handle *desc;
  const int on = 1;
  unsigned short port;

  GNUNET_GE_ASSERT (coreAPI->ectx, selector == NULL);
  /* initialize UDP network */
  port = get_port ();
  if (port != 0)
    {
      desc = udp_create_socket ();
      if (NULL == desc)
        return GNUNET_SYSERR;
      if (GNUNET_net_setsockopt (desc, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0)
        {
          GNUNET_GE_DIE_STRERROR (coreAPI->ectx,
                                  GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                                  GNUNET_GE_IMMEDIATE, "setsockopt");
          return GNUNET_SYSERR;
        }
      if (available_protocols == VERSION_AVAILABLE_IPV4)
        {
          memset (&serverAddrv4, 0, sizeof (serverAddrv4));
          serverAddrv4.sin_family = AF_INET;
          serverAddrv4.sin_addr.s_addr = INADDR_ANY;
          serverAddrv4.sin_port = htons (port);
          addrlen = sizeof (serverAddrv4);
          serverAddr = (struct sockaddr *) &serverAddrv4;
        }
      else
        {
          memset (&serverAddrv6, 0, sizeof (serverAddrv6));
          serverAddrv6.sin6_family = AF_INET6;
          serverAddrv6.sin6_addr = in6addr_any;
          serverAddrv6.sin6_port = htons (port);
          addrlen = sizeof (serverAddrv6);
          serverAddr = (struct sockaddr *) &serverAddrv6;
        }
      if (GNUNET_net_bind (desc, serverAddr, addrlen) < 0)
        {
          GNUNET_GE_LOG_STRERROR (coreAPI->ectx,
                                  GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                                  GNUNET_GE_IMMEDIATE, "bind");
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                         GNUNET_GE_IMMEDIATE,
                         _("Failed to bind to %s port %d.\n"),
                         MY_TRANSPORT_NAME, port);
          if (0 != GNUNET_net_close (&desc))
            GNUNET_GE_LOG_STRERROR (coreAPI->ectx,
                                    GNUNET_GE_ERROR | GNUNET_GE_USER |
                                    GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                                    "close");
          return GNUNET_SYSERR;
        }
      selector = GNUNET_select_create ("udp", GNUNET_YES, coreAPI->ectx, load_monitor, desc, addrlen, 0,        /* timeout */
                                       &select_message_handler,
                                       NULL,
                                       &select_accept_handler,
                                       NULL,
                                       &select_close_handler,
                                       NULL, 64 * 1024,
                                       16 /* max sockets */ );
      if (selector == NULL)
        return GNUNET_SYSERR;
    }
  desc = udp_create_socket ();
  if (NULL == desc)
    {
      GNUNET_GE_LOG_STRERROR (coreAPI->ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_BULK, "socket");
      GNUNET_select_destroy (selector);
      selector = NULL;
      return GNUNET_SYSERR;
    }
  udp_sock = GNUNET_socket_create (coreAPI->ectx, load_monitor, desc);
  GNUNET_GE_ASSERT (coreAPI->ectx, udp_sock != NULL);
  return GNUNET_OK;
}

/**
 * The exported method. Makes the core api available via a global and
 * returns the udp transport API.
 */
GNUNET_TransportAPI *
inittransport_udp (GNUNET_CoreAPIForTransport * core)
{
  unsigned long long mtu;

  cfg = core->cfg;
  load_monitor = core->load_monitor;
  GNUNET_GE_ASSERT (coreAPI->ectx, sizeof (UDPMessage) == 68);
  GNUNET_GE_ASSERT (coreAPI->ectx, sizeof (HostAddress) == 24);
  coreAPI = core;
  if (-1 == GNUNET_GC_get_configuration_value_number (cfg,
                                                      "UDP",
                                                      "MTU",
                                                      sizeof (UDPMessage)
                                                      +
                                                      GNUNET_P2P_MESSAGE_OVERHEAD
                                                      +
                                                      sizeof
                                                      (GNUNET_MessageHeader) +
                                                      32, 65500,
                                                      MESSAGE_SIZE, &mtu))
    {
      return NULL;
    }
  if (mtu < 1200)
    GNUNET_GE_LOG (coreAPI->ectx,
                   GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_IMMEDIATE,
                   _("MTU %llu for `%s' is probably too low!\n"), mtu, "UDP");
  lock = GNUNET_mutex_create (GNUNET_NO);
  if (0 !=
      GNUNET_GC_attach_change_listener (cfg, &reload_configuration, NULL))
    {
      GNUNET_mutex_destroy (lock);
      lock = NULL;
      return NULL;
    }
  if (GNUNET_GC_get_configuration_value_yesno (cfg, "UDP", "UPNP", GNUNET_YES)
      == GNUNET_YES)
    {
      upnp = coreAPI->service_request ("upnp");
      if (upnp == NULL)
        GNUNET_GE_LOG (coreAPI->ectx,
                       GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_IMMEDIATE,
                       "The UPnP service could not be loaded. To disable UPnP, set the "
                       "configuration option \"UPNP\" in section \"%s\" to \"NO\"\n",
                       "UDP");
    }
  stats = coreAPI->service_request ("stats");
  if (stats != NULL)
    {
      stat_bytesReceived
        = stats->create (gettext_noop ("# bytes received via UDP"));
      stat_bytesSent = stats->create (gettext_noop ("# bytes sent via UDP"));
      stat_bytesDropped
        = stats->create (gettext_noop ("# bytes dropped by UDP (outgoing)"));
      stat_udpConnected
        = stats->create (gettext_noop ("# UDP connections (right now)"));
    }
  myAPI.protocol_number = GNUNET_TRANSPORT_PROTOCOL_NUMBER_UDP;
  myAPI.mtu = mtu - sizeof (UDPMessage);
  myAPI.cost = 20000;
  myAPI.hello_verify = &verify_hello;
  myAPI.hello_create = &create_hello;
  myAPI.connect = &udp_connect;
  myAPI.send = &udp_send;
  myAPI.associate = &udp_associate;
  myAPI.disconnect = &udp_disconnect;
  myAPI.server_start = &udp_transport_server_start;
  myAPI.server_stop = &udp_transport_server_stop;
  myAPI.hello_to_address = &hello_to_address;
  myAPI.send_now_test = &udp_test_would_try;

  return &myAPI;
}

void
donetransport_udp ()
{
  do_shutdown ();
}

/* end of udp.c */
