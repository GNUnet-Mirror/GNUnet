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

#define DEBUG_UDP GNUNET_YES

/**
 * The default maximum size of each outbound UDP message,
 * optimal value for Ethernet (10 or 100 MBit).
 */
#define MESSAGE_SIZE 1472

/**
 * Handle for request of hostname resolution, non-NULL if pending.
 */
static struct GNUNET_RESOLVER_RequestHandle *hostname_dns;

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

/* Forward definition */
struct Plugin;

/**
 * Session handle for UDP connections.
 */
struct Session
{

  /**
   * Stored in a linked list.
   */
  struct Session *next;

  /**
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;

  /**
   * To whom are we talking to (set to our identity
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Address of the other peer if WE initiated the connection
   * (and hence can be sure what it is), otherwise NULL.
   */
  void *connect_addr;

  /**
   * Length of connect_addr, can be 0.
   */
  size_t connect_alen;

  /*
   * Random challenge number for validation
   */
  int challenge;

  /*
   * Have we received validation (performed ping/pong) from this peer?
   */
  unsigned int validated;

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
   * List of open TCP sessions.
   */
  struct Session *sessions;

  /**
   * Handle for the statistics service.
   */
  struct GNUNET_STATISTICS_Handle *statistics;

  /**
   * Handle to the network service.
   */
  struct GNUNET_SERVICE_Context *service;

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

  /*
   * FD Read set
   */
  struct GNUNET_NETWORK_FDSet * rs;

};

/**
 * Message used to ask a peer to validate receipt (to check an address
 * from a HELLO).  Followed by the address used.  Note that the
 * recipients response does not affirm that he has this address,
 * only that he got the challenge message.
 */
struct UDPPingMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_PING
   */
  struct GNUNET_MessageHeader header;

  /**
   * Random challenge number (in network byte order).
   */
  uint32_t challenge GNUNET_PACKED;



};


/**
 * Message used to validate a HELLO.  The challenge is included in the
 * confirmation to make matching of replies to requests possible.  The
 * signature signs the original challenge number, our public key, the
 * sender's address (so that the sender can check that the address we
 * saw is plausible for him and possibly detect a MiM attack) and a
 * timestamp (to limit replay).<p>
 *
 * This message is followed by the address of the
 * client that we are observing (which is part of what
 * is being signed).
 */
struct UDPPongMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_PONG
   */
  struct GNUNET_MessageHeader header;

  /**
   * Random challenge number (in network byte order).
   */
  uint32_t challenge GNUNET_PACKED;

  /* Length of addr, appended to end of message */
  unsigned int addrlen;
};

/* *********** globals ************* */

/**
 * the socket that we transmit all data with
 */
static struct GNUNET_NETWORK_Handle *udp_sock;


/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed.
 *
 * @param session the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return GNUNET_OK if the session could be associated,
 *         GNUNET_SYSERR if not.
 */
int
udp_associate (struct Session * session)
{
  return GNUNET_SYSERR;         /* UDP connections can never be associated */
}

/**
 * Disconnect from a remote node.
 *
 * @param tsession the session that is closed
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
void
udp_disconnect (void *cls,
                const struct GNUNET_PeerIdentity *
                target)
{
  return;
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 */
static int
udp_transport_server_stop (void *cls)
{
  struct Plugin *plugin = cls;
  GNUNET_assert (udp_sock != NULL);
  if (plugin->select_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->env->sched, plugin->select_task);
      plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
    }

  GNUNET_NETWORK_socket_close (udp_sock);
  udp_sock = NULL;
  return GNUNET_OK;
}

static struct Session *
find_session(void *cls, struct Session * session_list, const struct GNUNET_PeerIdentity *peer)
{
  struct Plugin *plugin = cls;
  struct Session *pos;
  pos = session_list;

  while (pos != NULL)
  {
    if (memcmp(peer, &pos->target, sizeof(struct GNUNET_PeerIdentity)) == 0)
      return pos;
    pos = pos->next;
  }

  return NULL;
}

/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.
 *
 * @param cls closure
 * @param service_context value passed to the transport-service
 *        to identify the neighbour
 * @param target who should receive this message
 * @param priority how important is the message
 * @param msg the message to transmit
 * @param timeout when should we time out (give up) if we can not transmit?
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 */
static void
udp_plugin_send (void *cls,
                 const struct GNUNET_PeerIdentity *target,
                 unsigned int priority,
                 const struct GNUNET_MessageHeader *msg,
                 struct GNUNET_TIME_Relative timeout,
                 GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct Session *session;
  struct UDPMessage *message;
  int ssize;
  size_t sent;

  session = find_session(plugin, plugin->sessions, target);

  if ((session == NULL) || (udp_sock == NULL))
    return;

  /* Build the message to be sent */
  message = GNUNET_malloc(sizeof(struct UDPMessage) + ntohs(msg->size));
  ssize = sizeof(struct UDPMessage) + ntohs(msg->size);

#if DEBUG_UDP
  GNUNET_log_from(GNUNET_ERROR_TYPE_INFO, "udp", _
                 ("In udp_send, ssize is %d\n"), ssize);
#endif
  message->header.size = htons(ssize);
  message->header.type = htons(0);
  memcpy (&message->sender, plugin->env->my_identity, sizeof(struct GNUNET_PeerIdentity));
  memcpy (&message[1], msg, ntohs (msg->size));

  /* Actually send the message */
  sent = GNUNET_NETWORK_socket_sendto (udp_sock, message, ssize, session->connect_addr,
                                session->connect_alen);

  if (cont != NULL)
    {
      if (sent == GNUNET_SYSERR)
        cont(cont_cls, target, GNUNET_SYSERR);
      else
        cont(cont_cls, target, GNUNET_OK);
    }

  return;
}

/**
 * We've received a PING from this peer via UDP.
 * Send back our PONG.
 *
 * @param cls closure
 * @param sender the Identity of the sender
 * @param message the actual message
 */
static void
handle_udp_ping (void *cls,
                 struct GNUNET_PeerIdentity *sender, struct sockaddr_storage * addr, size_t addrlen,
                 const struct GNUNET_MessageHeader *message)
{
  struct Plugin *plugin = cls;
  struct Session *head = plugin->sessions;
  const struct UDPPingMessage *ping = (const struct UDPPingMessage *)message;
  struct UDPPongMessage *pong;
  struct Session *found;

#if DEBUG_UDP
      GNUNET_log_from(GNUNET_ERROR_TYPE_INFO, "udp", _
            ("handling ping, challenge is %d\n"), ntohs(ping->challenge));
#endif
  found = find_session(plugin, head, sender);
  if (found != NULL)
    {
      pong = GNUNET_malloc(sizeof(struct UDPPongMessage) + addrlen);
      pong->header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_PONG);
      pong->header.size = htons(sizeof(struct UDPPongMessage) + addrlen);
      pong->challenge = ping->challenge;
      memcpy(&pong[1], addr, addrlen);
      pong->addrlen = htons(addrlen);

      udp_plugin_send(plugin, sender, GNUNET_SCHEDULER_PRIORITY_DEFAULT, &pong->header, GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30), NULL, NULL);
    }

  return;

}

/**
 * We've received a PONG from this peer via UDP.
 * Great. Call validate func if we haven't already
 * received a PONG.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_udp_pong (void *cls,
                 struct GNUNET_PeerIdentity *sender,
                 const struct GNUNET_MessageHeader *message)
{
  struct Plugin *plugin = cls;
  const struct UDPPongMessage *pong = (struct UDPPongMessage *)message;
  struct Session *found;
  unsigned int addr_len;
  struct sockaddr_storage addr;

#if DEBUG_UDP
      GNUNET_log_from(GNUNET_ERROR_TYPE_INFO, "udp", _
            ("handling pong\n"));
#endif
  found = find_session(plugin, plugin->sessions, sender);
#if DEBUG_UDP
      GNUNET_log_from(GNUNET_ERROR_TYPE_INFO, "udp", _
            ("found->challenge %d, pong->challenge %d\n"), found->challenge, ntohs(pong->challenge));
#endif
  if ((found != NULL) && (found->challenge == ntohs(pong->challenge)))
    {
      found->validated = GNUNET_YES;
      addr_len = ntohs(pong->addrlen);
#if DEBUG_UDP
      GNUNET_log_from(GNUNET_ERROR_TYPE_INFO, "udp", _
            ("found associated ping, addr is %u bytes\n"), addr_len);
#endif
      memcpy(&addr, &pong[1], addr_len);
      plugin->env->notify_validation(plugin->env->cls, "udp", sender, ntohs(pong->challenge), (char *)&addr);
    }
  else
    {

#if DEBUG_UDP
      GNUNET_log_from(GNUNET_ERROR_TYPE_INFO, "udp", _
            ("Session not found!\n"));
#endif
    }
  return;
}

static void
udp_plugin_select (void *cls,
                   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  struct GNUNET_TIME_Relative timeout  = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 500);
  char * buf;
  struct UDPMessage *msg;
  const struct GNUNET_MessageHeader *hdr;
  struct GNUNET_PeerIdentity *sender;
  unsigned int buflen;
  socklen_t fromlen;
  struct sockaddr_storage addr;
  ssize_t ret;

   do
    {
      buflen = GNUNET_NETWORK_socket_recvfrom_amount(udp_sock);

#if DEBUG_UDP
      GNUNET_log_from(GNUNET_ERROR_TYPE_INFO, "udp", _
            ("we expect to read %u bytes\n"), buflen);
#endif

      if (buflen == GNUNET_NO)
        return;

      buf = GNUNET_malloc(buflen);
      fromlen = sizeof(addr);

#if DEBUG_UDP
      GNUNET_log_from(GNUNET_ERROR_TYPE_INFO, "udp", _
            ("src_addr_len is %u\n"), fromlen);
#endif

      memset(&addr, 0, fromlen);
      ret = GNUNET_NETWORK_socket_recvfrom(udp_sock, buf, buflen, (struct sockaddr *)&addr, &fromlen);

#if DEBUG_UDP
      GNUNET_log_from(GNUNET_ERROR_TYPE_INFO, "udp", _
            ("socket_recv returned %u, src_addr_len is %u\n"), ret, fromlen);
#endif

      if (ret <= 0)
        {
          GNUNET_free(buf);
          return;
        }

      msg = (struct UDPMessage *)buf;

#if DEBUG_UDP
      GNUNET_log_from(GNUNET_ERROR_TYPE_INFO, "udp", _
            ("header reports message size of %d\n"), ntohs(msg->header.size));

      GNUNET_log_from(GNUNET_ERROR_TYPE_INFO, "udp", _
            ("header reports message type of %d\n"), ntohs(msg->header.type));
#endif
      /*if (ntohs(hdr->size) < sizeof(struct UDPMessage))
        {
          GNUNET_free(buf);
          GNUNET_NETWORK_fdset_zero(plugin->rs);
          GNUNET_NETWORK_fdset_set(plugin->rs, udp_sock);
          break;
        }*/
      hdr = (const struct GNUNET_MessageHeader *)&msg[1];
      sender = GNUNET_malloc(sizeof(struct GNUNET_PeerIdentity));
      memcpy(sender, &msg->sender, sizeof(struct GNUNET_PeerIdentity));

#if DEBUG_UDP
      GNUNET_log_from(GNUNET_ERROR_TYPE_INFO, "udp", _
            ("msg reports message size of %d\n"), ntohs(hdr->size));

      GNUNET_log_from(GNUNET_ERROR_TYPE_INFO, "udp", _
            ("msg reports message type of %d\n"), ntohs(hdr->type));
#endif

      if (ntohs(hdr->type) == GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_PING)
        {
          handle_udp_ping(plugin, sender, &addr, fromlen, hdr);
        }

      if (ntohs(hdr->type) == GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_PONG)
        {
          handle_udp_pong(plugin, sender, hdr);
        }

      GNUNET_free(buf);

    }
    while (GNUNET_NETWORK_socket_select (plugin->rs,
                                         NULL,
                                         NULL,
                                         timeout) > 0 && GNUNET_NETWORK_fdset_isset(plugin->rs, udp_sock));

    plugin->select_task = GNUNET_SCHEDULER_add_select(plugin->env->sched, GNUNET_SCHEDULER_PRIORITY_DEFAULT, GNUNET_SCHEDULER_NO_TASK,
      GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs, NULL, &udp_plugin_select, plugin);

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
      GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg, "GNUNETD", "DISABLE-IPV6"))
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
          GNUNET_log_from(GNUNET_ERROR_TYPE_DEBUG,
                         "udp",
                         "socket");
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
      GNUNET_assert(GNUNET_NETWORK_socket_bind(desc, serverAddr, addrlen) == GNUNET_OK);
    }

  plugin->rs = GNUNET_NETWORK_fdset_create ();

  GNUNET_NETWORK_fdset_zero(plugin->rs);
  GNUNET_NETWORK_fdset_set(plugin->rs, desc);

  plugin->select_task = GNUNET_SCHEDULER_add_select(plugin->env->sched, GNUNET_SCHEDULER_PRIORITY_DEFAULT, GNUNET_SCHEDULER_NO_TASK,
      GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs, NULL, &udp_plugin_select, plugin);

  return desc;
}

/**
 * Function that can be used by the transport service to validate that
 * another peer is reachable at a particular address (even if we
 * already have a connection to this peer, this function is required
 * to establish a new one).
 *
 * @param cls closure
 * @param target who should receive this message
 * @param challenge challenge code to use
 * @param addrlen length of the address
 * @param addr the address
 * @param timeout how long should we try to transmit these?
 * @return GNUNET_OK if the transmission has been scheduled
 */
static int
udp_plugin_validate (void *cls,
		     const struct GNUNET_PeerIdentity *target,
		     uint32_t challenge,
		     struct GNUNET_TIME_Relative timeout,
		     const void *addr, size_t addrlen)
{
  struct Plugin *plugin = cls;
  struct Session *new_session;
  struct UDPPongMessage *msg;

  if (addrlen <= 0)
    return GNUNET_SYSERR;

  new_session = GNUNET_malloc(sizeof(struct Session));
  new_session->connect_addr = GNUNET_malloc(addrlen);
  memcpy(new_session->connect_addr, addr, addrlen);
  new_session->connect_alen = addrlen;
#if DEBUG_UDP
  if (memcmp(target, plugin->env->my_identity, sizeof(struct GNUNET_PeerIdentity)) == 0)
    {
      GNUNET_log_from(GNUNET_ERROR_TYPE_INFO, "udp", _
              ("definitely adding self to session list... hmmm\n"));
    }
#endif
  memcpy(&new_session->target, target, sizeof(struct GNUNET_PeerIdentity));
  new_session->challenge = challenge;
  new_session->validated = GNUNET_NO;
  new_session->next = plugin->sessions;
  plugin->sessions = new_session;

  msg = GNUNET_malloc (sizeof (struct UDPPongMessage));
  msg->header.size = htons(sizeof(struct UDPPongMessage));
  msg->header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_PING);
  msg->challenge = htons(challenge);
#if DEBUG_UDP
  GNUNET_log_from(GNUNET_ERROR_TYPE_INFO, "udp", _
                 ("In validate, header size is %d, type %d, challenge %u\n"), ntohs(msg->header.size), ntohs(msg->header.type), ntohl(msg->challenge));
#endif
  udp_plugin_send(plugin, target, GNUNET_SCHEDULER_PRIORITY_DEFAULT, &msg->header, timeout, NULL, NULL);

  return GNUNET_OK;
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

}

/**
 * Set a quota for receiving data from the given peer; this is a
 * per-transport limit.  The transport should limit its read/select
 * calls to stay below the quota (in terms of incoming data).
 *
 * @param cls closure
 * @param target the peer for whom the quota is given
 * @param quota_in quota for receiving/sending data in bytes per ms
 */
static void
udp_plugin_set_receive_quota (void *cls,
                              const struct GNUNET_PeerIdentity *target,
                              uint32_t quota_in)
{

}

/**
 * Another peer has suggested an address for this
 * peer and transport plugin.  Check that this could be a valid
 * address.  If so, consider adding it to the list
 * of addresses.
 *
 * @param cls closure
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport
 */
static int
udp_plugin_address_suggested (void *cls, const void *addr, size_t addrlen)
{

  return GNUNET_SYSERR;
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
      GNUNET_log_from(GNUNET_ERROR_TYPE_WARNING, "udp", _
      ("Failed to start service for `%s' transport plugin.\n"), "udp");
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
    GNUNET_log_from(GNUNET_ERROR_TYPE_INFO,
                    "udp",
                    _("MTU %llu for `%s' is probably too low!\n"), mtu, "UDP");

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->open_port = bport;
  plugin->adv_port = aport;
  plugin->env = env;
  plugin->statistics = NULL;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  plugin->sessions = NULL;
  api->cls = plugin;

  api->validate = &udp_plugin_validate;
  api->send = &udp_plugin_send;
  api->disconnect = &udp_disconnect;
  api->address_pretty_printer = &udp_plugin_address_pretty_printer;
  api->set_receive_quota = &udp_plugin_set_receive_quota;
  api->address_suggested = &udp_plugin_address_suggested;
  api->cost_estimate = 17;      /* TODO: ATS */
  plugin->service = service;

  udp_sock = udp_transport_server_start(plugin);

  GNUNET_assert(udp_sock != NULL);

  return api;
}

void *
libgnunet_plugin_transport_udp_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  udp_transport_server_stop(plugin);
  if (NULL != hostname_dns)
    {
      GNUNET_RESOLVER_request_cancel (hostname_dns);
      hostname_dns = NULL;
    }
  GNUNET_SERVICE_stop (plugin->service);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_udp.c */
