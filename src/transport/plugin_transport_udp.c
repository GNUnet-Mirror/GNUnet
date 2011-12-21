/*
     This file is part of GNUnet
     (C) 2010, 2011 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
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
 * @brief Implementation of the UDP NAT punching
 *        transport service
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_fragmentation_lib.h"
#include "gnunet_nat_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_resolver_service.h"
#include "gnunet_signatures.h"
#include "gnunet_constants.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"

#define LOG(kind,...) GNUNET_log_from (kind, "transport-udp", __VA_ARGS__)


#define DEBUG_UDP GNUNET_EXTRA_LOGGING

/**
 * MTU for fragmentation subsystem.  Should be conservative since
 * all communicating peers MUST work with this MTU.
 */
#define UDP_MTU 1400

/**
 * Number of messages we can defragment in parallel.  We only really
 * defragment 1 message at a time, but if messages get re-ordered, we
 * may want to keep knowledge about the previous message to avoid
 * discarding the current message in favor of a single fragment of a
 * previous message.  3 should be good since we don't expect massive
 * message reorderings with UDP.
 */
#define UDP_MAX_MESSAGES_IN_DEFRAG 3

/**
 * We keep a defragmentation queue per sender address.  How many
 * sender addresses do we support at the same time? Memory consumption
 * is roughly a factor of 32k * UDP_MAX_MESSAGES_IN_DEFRAG times this
 * value. (So 128 corresponds to 12 MB and should suffice for
 * connecting to roughly 128 peers via UDP).
 */
#define UDP_MAX_SENDER_ADDRESSES_WITH_DEFRAG 128


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * UDP Message-Packet header (after defragmentation).
 */
struct UDPMessage
{
  /**
   * Message header.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero for now.
   */
  uint32_t reserved;

  /**
   * What is the identity of the sender
   */
  struct GNUNET_PeerIdentity sender;

};

/**
 * UDP ACK Message-Packet header (after defragmentation).
 */
struct UDP_ACK_Message
{
  /**
   * Message header.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Desired delay for flow control
   */
  uint32_t delay;

  /**
   * What is the identity of the sender
   */
  struct GNUNET_PeerIdentity sender;
};


struct UDP_Beacon_Message
{
 /**
  * Message header.
  */
  struct GNUNET_MessageHeader header;

 /**
  * What is the identity of the sender
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
  uint32_t ipv4_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t u4_port GNUNET_PACKED;
};


/**
 * Network format for IPv6 addresses.
 */
struct IPv6UdpAddress
{

  /**
   * IPv6 address.
   */
  struct in6_addr ipv6_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t u6_port GNUNET_PACKED;
};
GNUNET_NETWORK_STRUCT_END

/* Forward definition */
struct Plugin;


/**
 * Session with another peer.  FIXME: why not make this into
 * a regular 'struct Session' and pass it around!?
 */
struct Session
{

  /**
   * Which peer is this session for?
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;

  /**
   * Address of the other peer
   */
  const struct sockaddr *sock_addr;

  size_t addrlen;

  /**
   * ATS network type in NBO
   */
  uint32_t ats_address_network_type;

  /**
   * Function to call upon completion of the transmission.
   */
  GNUNET_TRANSPORT_TransmitContinuation cont;

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * Current outgoing message to this peer.
   */
  struct GNUNET_FRAGMENT_Context *frag;

  struct GNUNET_TIME_Absolute valid_until;

  GNUNET_SCHEDULER_TaskIdentifier invalidation_task;

  GNUNET_SCHEDULER_TaskIdentifier delayed_cont_task;

  /**
   * Desired delay for next sending we send to other peer
   */
  struct GNUNET_TIME_Relative flow_delay_for_other_peer;

  /**
   * Desired delay for next sending we received from other peer
   */
  struct GNUNET_TIME_Absolute flow_delay_from_other_peer;
};


/**
 * Data structure to track defragmentation contexts based
 * on the source of the UDP traffic.
 */
struct ReceiveContext
{

  /**
   * Defragmentation context.
   */
  struct GNUNET_DEFRAGMENT_Context *defrag;

  /**
   * Source address this receive context is for (allocated at the
   * end of the struct).
   */
  const struct sockaddr *src_addr;

  /**
   * Reference to master plugin struct.
   */
  struct Plugin *plugin;

  /**
   * Node in the defrag heap.
   */
  struct GNUNET_CONTAINER_HeapNode *hnode;

  /**
   * Length of 'src_addr'
   */
  size_t addr_len;

  struct GNUNET_PeerIdentity id;

};

struct BroadcastAddress
{
  struct BroadcastAddress *next;
  struct BroadcastAddress *prev;

  void *addr;
  socklen_t addrlen;
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
   * Session of peers with whom we are currently connected,
   * map of peer identity to 'struct PeerSession'.
   */
  struct GNUNET_CONTAINER_MultiHashMap *sessions;

  /**
   * Session of peers with whom we are currently connected,
   * map of peer identity to 'struct PeerSession'.
   */
  struct GNUNET_CONTAINER_MultiHashMap *inbound_sessions;

  /**
   * Heap with all of our defragmentation activities.
   */
  struct GNUNET_CONTAINER_Heap *defrags;

  /**
   * ID of select task
   */
  GNUNET_SCHEDULER_TaskIdentifier select_task;

  /**
   * Tokenizer for inbound messages.
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *mst;

  /**
   * Bandwidth tracker to limit global UDP traffic.
   */
  struct GNUNET_BANDWIDTH_Tracker tracker;

  /**
   * Address we were told to bind to exclusively (IPv4).
   */
  char *bind4_address;

  /**
   * Address we were told to bind to exclusively (IPv6).
   */
  char *bind6_address;

  /**
   * Handle to NAT traversal support.
   */
  struct GNUNET_NAT_Handle *nat;

  /**
   * FD Read set
   */
  struct GNUNET_NETWORK_FDSet *rs;

  /**
   * The read socket for IPv4
   */
  struct GNUNET_NETWORK_Handle *sockv4;

  /**
   * The read socket for IPv6
   */
  struct GNUNET_NETWORK_Handle *sockv6;

  /**
   * Beacon broadcasting
   * -------------------
   */

  /**
   * Broadcast interval
   */
  struct GNUNET_TIME_Relative broadcast_interval;

  /**
   * Broadcast with IPv4
   */
  int broadcast_ipv4;

  /**
   * Broadcast with IPv6
   */
  int broadcast_ipv6;


  /**
   * Tokenizer for inbound messages.
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *broadcast_ipv6_mst;
  struct GNUNET_SERVER_MessageStreamTokenizer *broadcast_ipv4_mst;

  /**
   * ID of select broadcast task
   */
  GNUNET_SCHEDULER_TaskIdentifier send_ipv4_broadcast_task;

  /**
   * ID of select broadcast task
   */
  GNUNET_SCHEDULER_TaskIdentifier send_ipv6_broadcast_task;

  /**
   * IPv6 multicast address
   */
  struct sockaddr_in6 ipv6_multicast_address;

  /**
   * DLL of IPv4 broadcast addresses
   */
  struct BroadcastAddress *ipv4_broadcast_tail;
  struct BroadcastAddress *ipv4_broadcast_head;


  /**
   * expected delay for ACKs
   */
  struct GNUNET_TIME_Relative last_expected_delay;

  /**
   * Port we broadcasting on.
   */
  uint16_t broadcast_port;

  /**
   * Port we listen on.
   */
  uint16_t port;

  /**
   * Port we advertise on.
   */
  uint16_t aport;

};

struct PeerSessionIteratorContext
{
  struct Session *result;
  const void *addr;
  size_t addrlen;
};


/**
 * Lookup the session for the given peer.
 *
 * @param plugin the plugin
 * @param peer peer's identity
 * @return NULL if we have no session
 */
static struct Session *
find_session (struct Plugin *plugin, const struct GNUNET_PeerIdentity *peer)
{
  return GNUNET_CONTAINER_multihashmap_get (plugin->sessions,
                                            &peer->hashPubKey);
}


static int
inbound_session_iterator (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct PeerSessionIteratorContext *psc = cls;
  struct Session *s = value;

  if (s->addrlen == psc->addrlen)
  {
    if (0 == memcmp (&s[1], psc->addr, s->addrlen))
      psc->result = s;
  }
  if (psc->result != NULL)
    return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Lookup the session for the given peer.
 *
 * @param plugin the plugin
 * @param peer peer's identity
 * @param addr address
 * @param addrlen address length
 * @return NULL if we have no session
 */
static struct Session *
find_inbound_session (struct Plugin *plugin,
                      const struct GNUNET_PeerIdentity *peer, const void *addr,
                      size_t addrlen)
{
  struct PeerSessionIteratorContext psc;

  psc.result = NULL;
  psc.addrlen = addrlen;
  psc.addr = addr;

  GNUNET_CONTAINER_multihashmap_get_multiple (plugin->inbound_sessions,
                                              &peer->hashPubKey,
                                              &inbound_session_iterator, &psc);
  return psc.result;
}


static int
inbound_session_by_addr_iterator (void *cls, const GNUNET_HashCode * key,
                                  void *value)
{
  struct PeerSessionIteratorContext *psc = cls;
  struct Session *s = value;

  if (s->addrlen == psc->addrlen)
  {
    if (0 == memcmp (&s[1], psc->addr, s->addrlen))
      psc->result = s;
  }
  if (psc->result != NULL)
    return GNUNET_NO;
  else
    return GNUNET_YES;
};

/**
 * Lookup the session for the given peer just by address.
 *
 * @param plugin the plugin
 * @param addr address
 * @param addrlen address length
 * @return NULL if we have no session
 */
static struct Session *
find_inbound_session_by_addr (struct Plugin *plugin, const void *addr,
                              size_t addrlen)
{
  struct PeerSessionIteratorContext psc;

  psc.result = NULL;
  psc.addrlen = addrlen;
  psc.addr = addr;

  GNUNET_CONTAINER_multihashmap_iterate (plugin->inbound_sessions,
                                         &inbound_session_by_addr_iterator,
                                         &psc);
  return psc.result;
}


/**
 * Destroy a session, plugin is being unloaded.
 *
 * @param cls unused
 * @param key hash of public key of target peer
 * @param value a 'struct PeerSession*' to clean up
 * @return GNUNET_OK (continue to iterate)
 */
static int
destroy_session (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct Session *peer_session = value;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (peer_session->
                                                       plugin->sessions,
                                                       &peer_session->
                                                       target.hashPubKey,
                                                       peer_session));
  if (peer_session->frag != NULL)
    GNUNET_FRAGMENT_context_destroy (peer_session->frag);
  if (GNUNET_SCHEDULER_NO_TASK != peer_session->delayed_cont_task)
    GNUNET_SCHEDULER_cancel (peer_session->delayed_cont_task);
  GNUNET_free (peer_session);
  return GNUNET_OK;
}


/**
 * Destroy a session, plugin is being unloaded.
 *
 * @param cls unused
 * @param key hash of public key of target peer
 * @param value a 'struct PeerSession*' to clean up
 * @return GNUNET_OK (continue to iterate)
 */
static int
destroy_inbound_session (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct Session *s = value;

  if (s->invalidation_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (s->invalidation_task);
  if (GNUNET_SCHEDULER_NO_TASK != s->delayed_cont_task)
    GNUNET_SCHEDULER_cancel (s->delayed_cont_task);
  GNUNET_CONTAINER_multihashmap_remove (s->plugin->inbound_sessions,
                                        &s->target.hashPubKey, s);
  GNUNET_free (s);
  return GNUNET_OK;
}


/**
 * Disconnect from a remote node.  Clean up session if we have one for this peer
 *
 * @param cls closure for this call (should be handle to Plugin)
 * @param target the peeridentity of the peer to disconnect
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static void
udp_disconnect (void *cls, const struct GNUNET_PeerIdentity *target)
{
  struct Plugin *plugin = cls;
  struct Session *session;

  session = find_session (plugin, target);
  if (NULL == session)
    return;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_remove (plugin->sessions,
                                                       &target->hashPubKey,
                                                       session));

  GNUNET_CONTAINER_multihashmap_get_multiple (plugin->inbound_sessions,
                                              &target->hashPubKey,
                                              &destroy_inbound_session, NULL);
  plugin->last_expected_delay = GNUNET_FRAGMENT_context_destroy (session->frag);
  if (GNUNET_SCHEDULER_NO_TASK != session->delayed_cont_task)
    GNUNET_SCHEDULER_cancel (session->delayed_cont_task);
  if (session->cont != NULL)
    session->cont (session->cont_cls, target, GNUNET_SYSERR);
  GNUNET_free (session);
}


/**
 * Actually send out the message.
 *
 * @param plugin the plugin
 * @param sa the address to send the message to
 * @param msg message to transmit
 * @return the number of bytes written
 */
static ssize_t
udp_send (struct Plugin *plugin, const struct sockaddr *sa,
          const struct GNUNET_MessageHeader *msg)
{
  ssize_t sent;
  size_t slen;

  switch (sa->sa_family)
  {
  case AF_INET:
    if (NULL == plugin->sockv4)
      return 0;
    sent =
        GNUNET_NETWORK_socket_sendto (plugin->sockv4, msg, ntohs (msg->size),
                                      sa, slen = sizeof (struct sockaddr_in));
    break;
  case AF_INET6:
    if (NULL == plugin->sockv6)
      return 0;
    sent =
        GNUNET_NETWORK_socket_sendto (plugin->sockv6, msg, ntohs (msg->size),
                                      sa, slen = sizeof (struct sockaddr_in6));
    break;
  default:
    GNUNET_break (0);
    return 0;
  }
  if (GNUNET_SYSERR == sent)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "sendto");
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "UDP transmited %u-byte message to %s (%d: %s)\n",
         (unsigned int) ntohs (msg->size), GNUNET_a2s (sa, slen), (int) sent,
         (sent < 0) ? STRERROR (errno) : "ok");

  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "UDP transmited %u-byte message to %s (%d: %s)\n",
       (unsigned int) ntohs (msg->size), GNUNET_a2s (sa, slen), (int) sent,
       (sent < 0) ? STRERROR (errno) : "ok");
  return sent;
}


/**
 * Function that is called with messages created by the fragmentation
 * module.  In the case of the 'proc' callback of the
 * GNUNET_FRAGMENT_context_create function, this function must
 * eventually call 'GNUNET_FRAGMENT_context_transmission_done'.
 *
 * @param cls closure, the 'struct PeerSession'
 * @param msg the message that was created
 */
static void
send_fragment (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct Session *session = cls;

  udp_send (session->plugin, session->sock_addr, msg);
  GNUNET_FRAGMENT_context_transmission_done (session->frag);
}


static struct Session *
create_session (struct Plugin *plugin, const struct GNUNET_PeerIdentity *target,
                const void *addr, size_t addrlen,
                GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Session *peer_session;
  const struct IPv4UdpAddress *t4;
  const struct IPv6UdpAddress *t6;
  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;
  size_t len;
  struct GNUNET_ATS_Information ats;

  switch (addrlen)
  {
  case sizeof (struct IPv4UdpAddress):
    if (NULL == plugin->sockv4)
    {
      return NULL;
    }
    t4 = addr;
    peer_session =
        GNUNET_malloc (sizeof (struct Session) + sizeof (struct sockaddr_in));
    len = sizeof (struct sockaddr_in);
    v4 = (struct sockaddr_in *) &peer_session[1];
    v4->sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
    v4->sin_len = sizeof (struct sockaddr_in);
#endif
    v4->sin_port = t4->u4_port;
    v4->sin_addr.s_addr = t4->ipv4_addr;
    ats = plugin->env->get_address_type (plugin->env->cls, (const struct sockaddr *) v4, sizeof (struct sockaddr_in));
    break;
  case sizeof (struct IPv6UdpAddress):
    if (NULL == plugin->sockv6)
    {
      return NULL;
    }
    t6 = addr;
    peer_session =
        GNUNET_malloc (sizeof (struct Session) + sizeof (struct sockaddr_in6));
    len = sizeof (struct sockaddr_in6);
    v6 = (struct sockaddr_in6 *) &peer_session[1];
    v6->sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    v6->sin6_len = sizeof (struct sockaddr_in6);
#endif
    v6->sin6_port = t6->u6_port;
    v6->sin6_addr = t6->ipv6_addr;
    ats = plugin->env->get_address_type (plugin->env->cls, (const struct sockaddr *) v6, sizeof (struct sockaddr_in6));
    break;
  default:
    /* Must have a valid address to send to */
    GNUNET_break_op (0);
    return NULL;
  }

  peer_session->ats_address_network_type = ats.value;
  peer_session->valid_until = GNUNET_TIME_absolute_get_zero ();
  peer_session->invalidation_task = GNUNET_SCHEDULER_NO_TASK;
  peer_session->addrlen = len;
  peer_session->target = *target;
  peer_session->plugin = plugin;
  peer_session->sock_addr = (const struct sockaddr *) &peer_session[1];
  peer_session->cont = cont;
  peer_session->cont_cls = cont_cls;

  return peer_session;
}

static const char *
udp_address_to_string (void *cls, const void *addr, size_t addrlen);


static void
udp_call_continuation (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *s = cls;
  GNUNET_TRANSPORT_TransmitContinuation cont = s->cont;

  s->delayed_cont_task = GNUNET_SCHEDULER_NO_TASK;
  s->cont = NULL;
  cont (s->cont_cls, &s->target, GNUNET_OK);
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
 * @param session identifier used for this session (NULL for UDP)
 * @param addr the addr to send the message to
 * @param addrlen the len of addr
 * @param force_address not used, we had better have an address to send to
 *        because we are stateless!!
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 *
 * @return the number of bytes written (may return 0 and the message can
 *         still be transmitted later!)
 */
static ssize_t
udp_plugin_send (void *cls, const struct GNUNET_PeerIdentity *target,
                 const char *msgbuf, size_t msgbuf_size, unsigned int priority,
                 struct GNUNET_TIME_Relative timeout, struct Session *session,
                 const void *addr, size_t addrlen, int force_address,
                 GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct Session *peer_session;
  struct Session *s;
  const struct IPv4UdpAddress *t4;
  const struct IPv6UdpAddress *t6;
  size_t mlen = msgbuf_size + sizeof (struct UDPMessage);
  char mbuf[mlen];
  struct UDPMessage *udp;
  struct GNUNET_TIME_Relative delta;

  if (mlen >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "UDP transmits %u-byte message to `%s' using address `%s' session 0x%X mode %i\n",
       msgbuf_size, GNUNET_i2s (target), udp_address_to_string (NULL, addr,
                                                                addrlen),
       session, force_address);

  if ((force_address == GNUNET_SYSERR) && (session == NULL))
    return GNUNET_SYSERR;

  s = NULL;
  /* safety check: comparing address to address stored in session */
  if ((session != NULL) && (addr != NULL) && (addrlen != 0))
  {
    s = session;
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_contains_value
                   (plugin->inbound_sessions, &target->hashPubKey, s));

    if (0 != memcmp (&s->target, target, sizeof (struct GNUNET_PeerIdentity)))
      return GNUNET_SYSERR;
    switch (addrlen)
    {
    case sizeof (struct IPv4UdpAddress):
      if (NULL == plugin->sockv4)
      {
        if (cont != NULL)
          cont (cont_cls, target, GNUNET_SYSERR);
        return GNUNET_SYSERR;
      }
      t4 = addr;
      if (s->addrlen != (sizeof (struct sockaddr_in)))
        return GNUNET_SYSERR;
      struct sockaddr_in *a4 = (struct sockaddr_in *) s->sock_addr;

      GNUNET_assert (a4->sin_port == t4->u4_port);
      GNUNET_assert (0 ==
                     memcmp (&a4->sin_addr, &t4->ipv4_addr,
                             sizeof (struct in_addr)));
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Session 0x%X successfully checked!\n",
           session);
      break;
    case sizeof (struct IPv6UdpAddress):
      if (NULL == plugin->sockv6)
      {
        if (cont != NULL)
          cont (cont_cls, target, GNUNET_SYSERR);
        return GNUNET_SYSERR;
      }
      t6 = addr;
      GNUNET_assert (s->addrlen == sizeof (struct sockaddr_in6));
      struct sockaddr_in6 *a6 = (struct sockaddr_in6 *) s->sock_addr;

      GNUNET_assert (a6->sin6_port == t6->u6_port);
      GNUNET_assert (0 ==
                     memcmp (&a6->sin6_addr, &t6->ipv6_addr,
                             sizeof (struct in6_addr)));
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Session 0x%X successfully checked!\n",
           session);
      break;
    default:
      /* Must have a valid address to send to */
      GNUNET_break_op (0);
    }
  }
//session_invalid:
  if ((addr == NULL) || (addrlen == 0))
    return GNUNET_SYSERR;
  peer_session = create_session (plugin, target, addr, addrlen, cont, cont_cls);
  if (peer_session == NULL)
  {
    if (cont != NULL)
      cont (cont_cls, target, GNUNET_SYSERR);
    return GNUNET_SYSERR;;
  }

  /* Message */
  udp = (struct UDPMessage *) mbuf;
  udp->header.size = htons (mlen);
  udp->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_MESSAGE);
  udp->reserved = htonl (0);
  udp->sender = *plugin->env->my_identity;
  memcpy (&udp[1], msgbuf, msgbuf_size);

  if (s != NULL)
    delta = GNUNET_TIME_absolute_get_remaining (s->flow_delay_from_other_peer);
  else
    delta = GNUNET_TIME_UNIT_ZERO;
  if (mlen <= UDP_MTU)
  {
    mlen = udp_send (plugin, peer_session->sock_addr, &udp->header);
    if (cont != NULL)
    {
      if ((delta.rel_value > 0) && (mlen > 0))
      {
        s->cont = cont;
        s->cont_cls = cont_cls;
        s->delayed_cont_task =
            GNUNET_SCHEDULER_add_delayed (delta, &udp_call_continuation, s);
      }
      else
        cont (cont_cls, target, (mlen > 0) ? GNUNET_OK : GNUNET_SYSERR);
    }
    GNUNET_free_non_null (peer_session);
  }
  else
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (plugin->sessions,
                                                      &target->hashPubKey,
                                                      peer_session,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    peer_session->frag =
        GNUNET_FRAGMENT_context_create (plugin->env->stats, UDP_MTU,
                                        &plugin->tracker,
                                        plugin->last_expected_delay,
                                        &udp->header, &send_fragment,
                                        peer_session);
  }
  return mlen;
}


/**
 * Closure for 'process_inbound_tokenized_messages'
 */
struct SourceInformation
{
  /**
   * Sender identity.
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Source address.
   */
  const void *arg;

  /**
   * Number of bytes in source address.
   */
  size_t args;

  struct Session *session;
};


/**
 * Message tokenizer has broken up an incomming message. Pass it on
 * to the service.
 *
 * @param cls the 'struct Plugin'
 * @param client the 'struct SourceInformation'
 * @param hdr the actual message
 */
static void
process_inbound_tokenized_messages (void *cls, void *client,
                                    const struct GNUNET_MessageHeader *hdr)
{
  struct Plugin *plugin = cls;
  struct SourceInformation *si = client;
  struct GNUNET_ATS_Information atsi[2];
  struct GNUNET_TIME_Relative delay;

  /* setup ATS */
  atsi[0].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  atsi[0].value = htonl (1);
  atsi[1].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  atsi[1].value = si->session->ats_address_network_type;
  GNUNET_break (ntohl(si->session->ats_address_network_type) != GNUNET_ATS_NET_UNSPECIFIED);


  LOG (GNUNET_ERROR_TYPE_DEBUG, "Giving Session %X %s  to transport\n",
       si->session, GNUNET_i2s (&si->session->target));
  delay =
      plugin->env->receive (plugin->env->cls, &si->sender, hdr,
                            (const struct GNUNET_ATS_Information *) &atsi, 2,
                            si->session, si->arg, si->args);
  si->session->flow_delay_for_other_peer = delay;
}

static void
invalidation_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *s = cls;

  s->invalidation_task = GNUNET_SCHEDULER_NO_TASK;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Session %X (`%s') is now invalid\n", s,
       GNUNET_a2s (s->sock_addr, s->addrlen));

  s->plugin->env->session_end (s->plugin->env->cls, &s->target, s);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (s->
                                                       plugin->inbound_sessions,
                                                       &s->target.hashPubKey,
                                                       s));
  GNUNET_free (s);
}


/**
 * We've received a UDP Message.  Process it (pass contents to main service).
 *
 * @param plugin plugin context
 * @param msg the message
 * @param sender_addr sender address
 * @param sender_addr_len number of bytes in sender_addr
 */
static void
process_udp_message (struct Plugin *plugin, const struct UDPMessage *msg,
                     const struct sockaddr *sender_addr,
                     socklen_t sender_addr_len)
{
  struct SourceInformation si;
  struct IPv4UdpAddress u4;
  struct IPv6UdpAddress u6;
  struct GNUNET_ATS_Information ats;
  const void *arg;
  size_t args;

  if (0 != ntohl (msg->reserved))
  {
    GNUNET_break_op (0);
    return;
  }
  if (ntohs (msg->header.size) <
      sizeof (struct GNUNET_MessageHeader) + sizeof (struct UDPMessage))
  {
    GNUNET_break_op (0);
    return;
  }

  ats.type = htonl (GNUNET_ATS_NETWORK_TYPE);
  ats.value = htonl (GNUNET_ATS_NET_UNSPECIFIED);
  /* convert address */
  switch (sender_addr->sa_family)
  {
  case AF_INET:
    GNUNET_assert (sender_addr_len == sizeof (struct sockaddr_in));
    u4.ipv4_addr = ((struct sockaddr_in *) sender_addr)->sin_addr.s_addr;
    u4.u4_port = ((struct sockaddr_in *) sender_addr)->sin_port;
    arg = &u4;
    args = sizeof (u4);
    break;
  case AF_INET6:
    GNUNET_assert (sender_addr_len == sizeof (struct sockaddr_in6));
    u6.ipv6_addr = ((struct sockaddr_in6 *) sender_addr)->sin6_addr;
    u6.u6_port = ((struct sockaddr_in6 *) sender_addr)->sin6_port;
    arg = &u6;
    args = sizeof (u6);
    break;
  default:
    GNUNET_break (0);
    return;
  }
#if DEBUG_UDP
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message with %u bytes from peer `%s' at `%s'\n",
       (unsigned int) ntohs (msg->header.size), GNUNET_i2s (&msg->sender),
       GNUNET_a2s (sender_addr, sender_addr_len));
#endif

  /* create a session for inbound connections */
  const struct UDPMessage *udp_msg = (const struct UDPMessage *) msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Lookup inbound UDP sessions for peer `%s' address `%s'\n",
       GNUNET_i2s (&udp_msg->sender), udp_address_to_string (NULL, arg, args));

  struct Session *s = NULL;

  s = find_inbound_session (plugin, &udp_msg->sender, sender_addr,
                            sender_addr_len);

  if (s != NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Found existing inbound UDP sessions 0x%X for peer `%s' address `%s'\n",
         s, GNUNET_i2s (&s->target), udp_address_to_string (NULL, arg, args));
  }
  else
  {
    s = create_session (plugin, &udp_msg->sender, arg, args, NULL, NULL);
    ats = plugin->env->get_address_type (plugin->env->cls, sender_addr, sender_addr_len);
    s->ats_address_network_type = ats.value;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Creating inbound UDP sessions 0x%X for peer `%s' address `%s'\n", s,
         GNUNET_i2s (&s->target), udp_address_to_string (NULL, arg, args));

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (plugin->inbound_sessions,
                                                      &s->target.hashPubKey, s,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  }
  s->valid_until =
      GNUNET_TIME_relative_to_absolute
      (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  if (s->invalidation_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (s->invalidation_task);
    s->invalidation_task = GNUNET_SCHEDULER_NO_TASK;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Rescheduling %X' `%s'\n", s,
         udp_address_to_string (NULL, arg, args));
  }
  s->invalidation_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                    &invalidation_task, s);
  /* iterate over all embedded messages */
  si.sender = msg->sender;
  si.arg = arg;
  si.args = args;
  si.session = s;
  GNUNET_SERVER_mst_receive (plugin->mst, &si, (const char *) &msg[1],
                             ntohs (msg->header.size) -
                             sizeof (struct UDPMessage), GNUNET_YES, GNUNET_NO);
}


/**
 * Process a defragmented message.
 *
 * @param cls the 'struct ReceiveContext'
 * @param msg the message
 */
static void
fragment_msg_proc (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct ReceiveContext *rc = cls;

  if (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_MESSAGE)
  {
    GNUNET_break (0);
    return;
  }
  if (ntohs (msg->size) < sizeof (struct UDPMessage))
  {
    GNUNET_break (0);
    return;
  }
  process_udp_message (rc->plugin, (const struct UDPMessage *) msg,
                       rc->src_addr, rc->addr_len);
}


/**
 * Transmit an acknowledgement.
 *
 * @param cls the 'struct ReceiveContext'
 * @param id message ID (unused)
 * @param msg ack to transmit
 */
static void
ack_proc (void *cls, uint32_t id, const struct GNUNET_MessageHeader *msg)
{
  struct ReceiveContext *rc = cls;

  size_t msize = sizeof (struct UDP_ACK_Message) + ntohs (msg->size);
  char buf[msize];
  struct UDP_ACK_Message *udp_ack;
  uint32_t delay = 0;

  struct Session *s;

  s = find_inbound_session_by_addr (rc->plugin, rc->src_addr, rc->addr_len);
  if (s != NULL)
  {
    if (s->flow_delay_for_other_peer.rel_value <= UINT32_MAX)
      delay = s->flow_delay_for_other_peer.rel_value;
    else
      delay = UINT32_MAX;
  }


#if DEBUG_UDP
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending ACK to `%s' including delay of %u ms\n",
       GNUNET_a2s (rc->src_addr,
                   (rc->src_addr->sa_family ==
                    AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct
                                                                     sockaddr_in6)),
       delay);
#endif
  udp_ack = (struct UDP_ACK_Message *) buf;
  udp_ack->header.size = htons ((uint16_t) msize);
  udp_ack->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_ACK);
  udp_ack->delay = htonl (delay);
  udp_ack->sender = *rc->plugin->env->my_identity;
  memcpy (&udp_ack[1], msg, ntohs (msg->size));
  (void) udp_send (rc->plugin, rc->src_addr, &udp_ack->header);
}


/**
 * Closure for 'find_receive_context'.
 */
struct FindReceiveContext
{
  /**
   * Where to store the result.
   */
  struct ReceiveContext *rc;

  /**
   * Address to find.
   */
  const struct sockaddr *addr;

  /**
   * Number of bytes in 'addr'.
   */
  socklen_t addr_len;

  struct Session *session;
};


/**
 * Scan the heap for a receive context with the given address.
 *
 * @param cls the 'struct FindReceiveContext'
 * @param node internal node of the heap
 * @param element value stored at the node (a 'struct ReceiveContext')
 * @param cost cost associated with the node
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not.
 */
static int
find_receive_context (void *cls, struct GNUNET_CONTAINER_HeapNode *node,
                      void *element, GNUNET_CONTAINER_HeapCostType cost)
{
  struct FindReceiveContext *frc = cls;
  struct ReceiveContext *e = element;

  if ((frc->addr_len == e->addr_len) &&
      (0 == memcmp (frc->addr, e->src_addr, frc->addr_len)))
  {
    frc->rc = e;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}

struct Mstv4Context
{
  struct Plugin *plugin;

  struct IPv4UdpAddress addr;
  /**
   * ATS network type in NBO
   */
  uint32_t ats_address_network_type;
};

struct Mstv6Context
{
  struct Plugin *plugin;

  struct IPv6UdpAddress addr;
  /**
   * ATS network type in NBO
   */
  uint32_t ats_address_network_type;
};


/**
 * Read and process a message from the given socket.
 *
 * @param plugin the overall plugin
 * @param rsock socket to read from
 */
static void
udp_read (struct Plugin *plugin, struct GNUNET_NETWORK_Handle *rsock)
{
  socklen_t fromlen;
  char addr[32];
  char buf[65536];
  ssize_t ret;
  const struct GNUNET_MessageHeader *msg;
  const struct GNUNET_MessageHeader *ack;
  struct Session *peer_session;
  const struct UDP_ACK_Message *udp_ack;
  struct ReceiveContext *rc;
  struct GNUNET_TIME_Absolute now;
  struct FindReceiveContext frc;
  struct Session *s = NULL;
  struct GNUNET_TIME_Relative flow_delay;
  struct GNUNET_ATS_Information ats;

  fromlen = sizeof (addr);
  memset (&addr, 0, sizeof (addr));
  ret =
      GNUNET_NETWORK_socket_recvfrom (rsock, buf, sizeof (buf),
                                      (struct sockaddr *) &addr, &fromlen);
  if (ret < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return;
  }
  msg = (const struct GNUNET_MessageHeader *) buf;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "UDP received %u-byte message from `%s' type %i\n", (unsigned int) ret,
       GNUNET_a2s ((const struct sockaddr *) addr, fromlen), ntohs (msg->type));

  if (ret != ntohs (msg->size))
  {
    GNUNET_break_op (0);
    return;
  }
  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON:
  {
    if (fromlen == sizeof (struct sockaddr_in))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Received IPv4 HELLO beacon broadcast with %i bytes from address %s\n",
           ret, GNUNET_a2s ((const struct sockaddr *) &addr, fromlen));

      struct Mstv4Context *mc;

      mc = GNUNET_malloc (sizeof (struct Mstv4Context));
      struct sockaddr_in *av4 = (struct sockaddr_in *) &addr;

      mc->addr.ipv4_addr = av4->sin_addr.s_addr;
      mc->addr.u4_port = av4->sin_port;
      ats = plugin->env->get_address_type (plugin->env->cls, (const struct sockaddr *) &addr, fromlen);
      mc->ats_address_network_type = ats.value;
      if (GNUNET_OK !=
          GNUNET_SERVER_mst_receive (plugin->broadcast_ipv4_mst, mc, buf, ret,
                                     GNUNET_NO, GNUNET_NO))
        GNUNET_free (mc);
    }
    else if (fromlen == sizeof (struct sockaddr_in6))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Received IPv6 HELLO beacon broadcast with %i bytes from address %s\n",
           ret, GNUNET_a2s ((const struct sockaddr *) &addr, fromlen));

      struct Mstv6Context *mc;

      mc = GNUNET_malloc (sizeof (struct Mstv6Context));
      struct sockaddr_in6 *av6 = (struct sockaddr_in6 *) &addr;

      mc->addr.ipv6_addr = av6->sin6_addr;
      mc->addr.u6_port = av6->sin6_port;
      ats = plugin->env->get_address_type (plugin->env->cls, (const struct sockaddr *) &addr, fromlen);
      mc->ats_address_network_type = ats.value;

      if (GNUNET_OK !=
          GNUNET_SERVER_mst_receive (plugin->broadcast_ipv6_mst, mc, buf, ret,
                                     GNUNET_NO, GNUNET_NO))
        GNUNET_free (mc);
    }
    return;
  }
  case GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_MESSAGE:
    if (ntohs (msg->size) < sizeof (struct UDPMessage))
    {
      GNUNET_break_op (0);
      return;
    }
    process_udp_message (plugin, (const struct UDPMessage *) msg,
                         (const struct sockaddr *) addr, fromlen);
    return;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_ACK:

    if (ntohs (msg->size) <
        sizeof (struct UDP_ACK_Message) + sizeof (struct GNUNET_MessageHeader))
    {
      GNUNET_break_op (0);
      return;
    }
    udp_ack = (const struct UDP_ACK_Message *) msg;
    s = find_inbound_session (plugin, &udp_ack->sender, addr, fromlen);
    if (s != NULL)
    {
      flow_delay.rel_value = (uint64_t) ntohl (udp_ack->delay);

      LOG (GNUNET_ERROR_TYPE_DEBUG, "We received a sending delay of %llu\n",
           flow_delay.rel_value);

      s->flow_delay_from_other_peer =
          GNUNET_TIME_relative_to_absolute (flow_delay);
    }
    ack = (const struct GNUNET_MessageHeader *) &udp_ack[1];
    if (ntohs (ack->size) !=
        ntohs (msg->size) - sizeof (struct UDP_ACK_Message))
    {
      GNUNET_break_op (0);
      return;
    }
#if DEBUG_UDP
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "UDP processes %u-byte acknowledgement from `%s' at `%s'\n",
         (unsigned int) ntohs (msg->size), GNUNET_i2s (&udp_ack->sender),
         GNUNET_a2s ((const struct sockaddr *) addr, fromlen));
#endif

    peer_session = find_session (plugin, &udp_ack->sender);
    if (NULL == peer_session)
    {
#if DEBUG_UDP
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Session for ACK not found, dropping ACK!\n");
#endif
      return;
    }
    if (GNUNET_OK != GNUNET_FRAGMENT_process_ack (peer_session->frag, ack))
      return;
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_remove (plugin->sessions,
                                                         &udp_ack->
                                                         sender.hashPubKey,
                                                         peer_session));
    plugin->last_expected_delay =
        GNUNET_FRAGMENT_context_destroy (peer_session->frag);
    if (peer_session->cont != NULL)
      peer_session->cont (peer_session->cont_cls, &udp_ack->sender, GNUNET_OK);
    GNUNET_free (peer_session);
    return;
  case GNUNET_MESSAGE_TYPE_FRAGMENT:
    frc.rc = NULL;
    frc.addr = (const struct sockaddr *) addr;
    frc.addr_len = fromlen;
    GNUNET_CONTAINER_heap_iterate (plugin->defrags, &find_receive_context,
                                   &frc);
    now = GNUNET_TIME_absolute_get ();
    rc = frc.rc;
    if (rc == NULL)
    {
      /* need to create a new RC */
      rc = GNUNET_malloc (sizeof (struct ReceiveContext) + fromlen);
      memcpy (&rc[1], addr, fromlen);
      rc->src_addr = (const struct sockaddr *) &rc[1];
      rc->addr_len = fromlen;
      rc->plugin = plugin;
      rc->defrag =
          GNUNET_DEFRAGMENT_context_create (plugin->env->stats, UDP_MTU,
                                            UDP_MAX_MESSAGES_IN_DEFRAG, rc,
                                            &fragment_msg_proc, &ack_proc);
      rc->hnode =
          GNUNET_CONTAINER_heap_insert (plugin->defrags, rc,
                                        (GNUNET_CONTAINER_HeapCostType)
                                        now.abs_value);
    }
#if DEBUG_UDP
    LOG (GNUNET_ERROR_TYPE_DEBUG, "UDP processes %u-byte fragment from `%s'\n",
         (unsigned int) ntohs (msg->size),
         GNUNET_a2s ((const struct sockaddr *) addr, fromlen));
#endif

    if (GNUNET_OK == GNUNET_DEFRAGMENT_process_fragment (rc->defrag, msg))
    {
      /* keep this 'rc' from expiring */
      GNUNET_CONTAINER_heap_update_cost (plugin->defrags, rc->hnode,
                                         (GNUNET_CONTAINER_HeapCostType)
                                         now.abs_value);
    }
    if (GNUNET_CONTAINER_heap_get_size (plugin->defrags) >
        UDP_MAX_SENDER_ADDRESSES_WITH_DEFRAG)
    {
      /* remove 'rc' that was inactive the longest */
      rc = GNUNET_CONTAINER_heap_remove_root (plugin->defrags);
      GNUNET_assert (NULL != rc);
      GNUNET_DEFRAGMENT_context_destroy (rc->defrag);
      GNUNET_free (rc);
    }
    return;
  default:
    GNUNET_break_op (0);
    return;
  }
}


/**
 * We have been notified that our writeset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 */
static void
udp_plugin_select (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

  plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  if ((NULL != plugin->sockv4) &&
      (GNUNET_NETWORK_fdset_isset (tc->read_ready, plugin->sockv4)))
    udp_read (plugin, plugin->sockv4);
  if ((NULL != plugin->sockv6) &&
      (GNUNET_NETWORK_fdset_isset (tc->read_ready, plugin->sockv6)))
    udp_read (plugin, plugin->sockv6);
  plugin->select_task =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   GNUNET_SCHEDULER_NO_TASK,
                                   GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
                                   NULL, &udp_plugin_select, plugin);

}


void
broadcast_ipv4_mst_cb (void *cls, void *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct Plugin *plugin = cls;
  struct Mstv4Context *mc = client;
  const struct GNUNET_MessageHeader *hello;
  struct UDP_Beacon_Message *msg;

  msg = (struct UDP_Beacon_Message *) message;

  if (GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON !=
      ntohs (msg->header.type))
    return;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received beacon with %u bytes from peer `%s' via address `%s'\n",
       ntohs (msg->header.size), GNUNET_i2s (&msg->sender),
       udp_address_to_string (NULL, &mc->addr, sizeof (mc->addr)));

  struct GNUNET_ATS_Information atsi[2];

  /* setup ATS */
  atsi[0].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  atsi[0].value = htonl (1);
  atsi[1].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  atsi[1].value = mc->ats_address_network_type;
  GNUNET_break (ntohl(mc->ats_address_network_type) != GNUNET_ATS_NET_UNSPECIFIED);

  hello = (struct GNUNET_MessageHeader *) &msg[1];
  plugin->env->receive (plugin->env->cls, &msg->sender, hello,
                        (const struct GNUNET_ATS_Information *) &atsi, 2, NULL,
                        (const char *) &mc->addr, sizeof (mc->addr));

  GNUNET_STATISTICS_update (plugin->env->stats,
                            _
                            ("# IPv4 broadcast HELLO beacons received via udp"),
                            1, GNUNET_NO);
  GNUNET_free (mc);
}


void
broadcast_ipv6_mst_cb (void *cls, void *client,
                       const struct GNUNET_MessageHeader *message)
{

  struct Plugin *plugin = cls;
  struct Mstv6Context *mc = client;
  const struct GNUNET_MessageHeader *hello;
  struct UDP_Beacon_Message *msg;

  msg = (struct UDP_Beacon_Message *) message;

  if (GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON !=
      ntohs (msg->header.type))
    return;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received beacon with %u bytes from peer `%s' via address `%s'\n",
       ntohs (msg->header.size), GNUNET_i2s (&msg->sender),
       udp_address_to_string (NULL, &mc->addr, sizeof (mc->addr)));

  struct GNUNET_ATS_Information atsi[2];

  /* setup ATS */
  atsi[0].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  atsi[0].value = htonl (1);
  atsi[1].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  atsi[1].value = mc->ats_address_network_type;
  GNUNET_break (ntohl(mc->ats_address_network_type) != GNUNET_ATS_NET_UNSPECIFIED);

  hello = (struct GNUNET_MessageHeader *) &msg[1];
  plugin->env->receive (plugin->env->cls, &msg->sender, hello,
                        (const struct GNUNET_ATS_Information *) &atsi, 2, NULL,
                        (const char *) &mc->addr, sizeof (mc->addr));

  GNUNET_STATISTICS_update (plugin->env->stats,
                            _
                            ("# IPv6 multicast HELLO beacons received via udp"),
                            1, GNUNET_NO);
  GNUNET_free (mc);
}


static void
udp_ipv4_broadcast_send (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  int sent;
  uint16_t msg_size;
  uint16_t hello_size;
  char buf[65536];

  const struct GNUNET_MessageHeader *hello;
  struct UDP_Beacon_Message *msg;
  struct BroadcastAddress *baddr;

  plugin->send_ipv4_broadcast_task = GNUNET_SCHEDULER_NO_TASK;

  hello = plugin->env->get_our_hello ();
  hello_size = GNUNET_HELLO_size ((struct GNUNET_HELLO_Message *) hello);
  msg_size = hello_size + sizeof (struct UDP_Beacon_Message);

  if (hello_size < (sizeof (struct GNUNET_MessageHeader)) ||
      (msg_size > (UDP_MTU)))
    return;

  msg = (struct UDP_Beacon_Message *) buf;
  msg->sender = *(plugin->env->my_identity);
  msg->header.size = ntohs (msg_size);
  msg->header.type = ntohs (GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON);
  memcpy (&msg[1], hello, hello_size);
  sent = 0;

  baddr = plugin->ipv4_broadcast_head;
  /* just IPv4 */
  while ((baddr != NULL) && (baddr->addrlen == sizeof (struct sockaddr_in)))
  {
    struct sockaddr_in *addr = (struct sockaddr_in *) baddr->addr;

    addr->sin_port = htons (plugin->port);

    sent =
        GNUNET_NETWORK_socket_sendto (plugin->sockv4, msg, msg_size,
                                      (const struct sockaddr *) addr,
                                      baddr->addrlen);
    if (sent == GNUNET_SYSERR)
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "sendto");
    else
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Sent HELLO beacon broadcast with  %i bytes to address %s\n", sent,
           GNUNET_a2s (baddr->addr, baddr->addrlen));
    baddr = baddr->next;
  }

  plugin->send_ipv4_broadcast_task =
      GNUNET_SCHEDULER_add_delayed (plugin->broadcast_interval,
                                    &udp_ipv4_broadcast_send, plugin);
}

static void
udp_ipv6_broadcast_send (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  int sent;
  uint16_t msg_size;
  uint16_t hello_size;
  char buf[65536];

  const struct GNUNET_MessageHeader *hello;
  struct UDP_Beacon_Message *msg;

  plugin->send_ipv6_broadcast_task = GNUNET_SCHEDULER_NO_TASK;

  hello = plugin->env->get_our_hello ();
  hello_size = GNUNET_HELLO_size ((struct GNUNET_HELLO_Message *) hello);
  msg_size = hello_size + sizeof (struct UDP_Beacon_Message);

  if (hello_size < (sizeof (struct GNUNET_MessageHeader)) ||
      (msg_size > (UDP_MTU)))
    return;

  msg = (struct UDP_Beacon_Message *) buf;
  msg->sender = *(plugin->env->my_identity);
  msg->header.size = ntohs (msg_size);
  msg->header.type = ntohs (GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON);
  memcpy (&msg[1], hello, hello_size);
  sent = 0;

  sent =
      GNUNET_NETWORK_socket_sendto (plugin->sockv6, msg, msg_size,
                                    (const struct sockaddr *)
                                    &plugin->ipv6_multicast_address,
                                    sizeof (struct sockaddr_in6));
  if (sent == GNUNET_SYSERR)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "sendto");
  else
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Sending IPv6 HELLO beacon broadcast with  %i bytes to address %s\n",
         sent,
         GNUNET_a2s ((const struct sockaddr *) &plugin->ipv6_multicast_address,
                     sizeof (struct sockaddr_in6)));



  plugin->send_ipv6_broadcast_task =
      GNUNET_SCHEDULER_add_delayed (plugin->broadcast_interval,
                                    &udp_ipv6_broadcast_send, plugin);
}

/**
 * Check if the given port is plausible (must be either our listen
 * port or our advertised port).  If it is neither, we return
 * GNUNET_SYSERR.
 *
 * @param plugin global variables
 * @param in_port port number to check
 * @return GNUNET_OK if port is either open_port or adv_port
 */
static int
check_port (struct Plugin *plugin, uint16_t in_port)
{
  if ((in_port == plugin->port) || (in_port == plugin->aport))
    return GNUNET_OK;
  return GNUNET_SYSERR;
}


/**
 * Function that will be called to check if a binary address for this
 * plugin is well-formed and corresponds to an address for THIS peer
 * (as per our configuration).  Naturally, if absolutely necessary,
 * plugins can be a bit conservative in their answer, but in general
 * plugins should make sure that the address does not redirect
 * traffic to a 3rd party that might try to man-in-the-middle our
 * traffic.
 *
 * @param cls closure, should be our handle to the Plugin
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport, GNUNET_SYSERR if not
 *
 */
static int
udp_plugin_check_address (void *cls, const void *addr, size_t addrlen)
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
    if (GNUNET_OK != check_port (plugin, ntohs (v4->u4_port)))
      return GNUNET_SYSERR;
    if (GNUNET_OK !=
        GNUNET_NAT_test_address (plugin->nat, &v4->ipv4_addr,
                                 sizeof (struct in_addr)))
      return GNUNET_SYSERR;
  }
  else
  {
    v6 = (struct IPv6UdpAddress *) addr;
    if (IN6_IS_ADDR_LINKLOCAL (&v6->ipv6_addr))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != check_port (plugin, ntohs (v6->u6_port)))
      return GNUNET_SYSERR;
    if (GNUNET_OK !=
        GNUNET_NAT_test_address (plugin->nat, &v6->ipv6_addr,
                                 sizeof (struct in6_addr)))
      return GNUNET_SYSERR;
  }
  return GNUNET_OK;
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
static const char *
udp_address_to_string (void *cls, const void *addr, size_t addrlen)
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
    port = ntohs (t4->u4_port);
    memcpy (&a4, &t4->ipv4_addr, sizeof (a4));
    sb = &a4;
  }
  else
  {
    GNUNET_break_op (0);
    return NULL;
  }
  inet_ntop (af, sb, buf, INET6_ADDRSTRLEN);
  GNUNET_snprintf (rbuf, sizeof (rbuf), (af == AF_INET6) ? "[%s]:%u" : "%s:%u",
                   buf, port);
  return rbuf;
}


/**
 * Closure for 'append_port'.
 */
struct PrettyPrinterContext
{
  /**
   * Function to call with the result.
   */
  GNUNET_TRANSPORT_AddressStringCallback asc;

  /**
   * Clsoure for 'asc'.
   */
  void *asc_cls;

  /**
   * Port to add after the IP address.
   */
  uint16_t port;
};


/**
 * Append our port and forward the result.
 *
 * @param cls a 'struct PrettyPrinterContext'
 * @param hostname result from DNS resolver
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
udp_plugin_address_pretty_printer (void *cls, const char *type,
                                   const void *addr, size_t addrlen,
                                   int numeric,
                                   struct GNUNET_TIME_Relative timeout,
                                   GNUNET_TRANSPORT_AddressStringCallback asc,
                                   void *asc_cls)
{
  struct PrettyPrinterContext *ppc;
  const void *sb;
  size_t sbs;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  const struct IPv4UdpAddress *u4;
  const struct IPv6UdpAddress *u6;
  uint16_t port;

  if (addrlen == sizeof (struct IPv6UdpAddress))
  {
    u6 = addr;
    memset (&a6, 0, sizeof (a6));
    a6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    a6.sin6_len = sizeof (a6);
#endif
    a6.sin6_port = u6->u6_port;
    memcpy (&a6.sin6_addr, &u6->ipv6_addr, sizeof (struct in6_addr));
    port = ntohs (u6->u6_port);
    sb = &a6;
    sbs = sizeof (a6);
  }
  else if (addrlen == sizeof (struct IPv4UdpAddress))
  {
    u4 = addr;
    memset (&a4, 0, sizeof (a4));
    a4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
    a4.sin_len = sizeof (a4);
#endif
    a4.sin_port = u4->u4_port;
    a4.sin_addr.s_addr = u4->ipv4_addr;
    port = ntohs (u4->u4_port);
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
  GNUNET_RESOLVER_hostname_get (sb, sbs, !numeric, timeout, &append_port, ppc);
}


/**
 * Our external IP address/port mapping has changed.
 *
 * @param cls closure, the 'struct LocalAddrList'
 * @param add_remove GNUNET_YES to mean the new public IP address, GNUNET_NO to mean
 *     the previous (now invalid) one
 * @param addr either the previous or the new public IP address
 * @param addrlen actual lenght of the address
 */
static void
udp_nat_port_map_callback (void *cls, int add_remove,
                           const struct sockaddr *addr, socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4UdpAddress u4;
  struct IPv6UdpAddress u6;
  void *arg;
  size_t args;

  /* convert 'addr' to our internal format */
  switch (addr->sa_family)
  {
  case AF_INET:
    GNUNET_assert (addrlen == sizeof (struct sockaddr_in));
    u4.ipv4_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
    u4.u4_port = ((struct sockaddr_in *) addr)->sin_port;
    arg = &u4;
    args = sizeof (u4);
    break;
  case AF_INET6:
    GNUNET_assert (addrlen == sizeof (struct sockaddr_in6));
    memcpy (&u6.ipv6_addr, &((struct sockaddr_in6 *) addr)->sin6_addr,
            sizeof (struct in6_addr));
    u6.u6_port = ((struct sockaddr_in6 *) addr)->sin6_port;
    arg = &u6;
    args = sizeof (u6);
    break;
  default:
    GNUNET_break (0);
    return;
  }
  /* modify our published address list */
  plugin->env->notify_address (plugin->env->cls, add_remove, arg, args);
}


static int
iface_proc (void *cls, const char *name, int isDefault,
            const struct sockaddr *addr, const struct sockaddr *broadcast_addr,
            const struct sockaddr *netmask, socklen_t addrlen)
{
  struct Plugin *plugin = cls;

  if (addr != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "address %s for interface %s %p\n ",
                GNUNET_a2s (addr, addrlen), name, addr);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "broadcast address %s for interface %s %p\n ",
                GNUNET_a2s (broadcast_addr, addrlen), name, broadcast_addr);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "netmask %s for interface %s %p\n ",
                GNUNET_a2s (netmask, addrlen), name, netmask);


    /* Collecting broadcast addresses */
    if (broadcast_addr != NULL)
    {
      struct BroadcastAddress *ba =
          GNUNET_malloc (sizeof (struct BroadcastAddress));
      ba->addr = GNUNET_malloc (addrlen);
      memcpy (ba->addr, broadcast_addr, addrlen);
      ba->addrlen = addrlen;
      GNUNET_CONTAINER_DLL_insert (plugin->ipv4_broadcast_head,
                                   plugin->ipv4_broadcast_tail, ba);
    }
  }
  return GNUNET_OK;
}


/**
 * The exported method. Makes the core api available via a global and
 * returns the udp transport API.
 *
 * @param cls our 'struct GNUNET_TRANSPORT_PluginEnvironment'
 * @return our 'struct GNUNET_TRANSPORT_PluginFunctions'
 */
void *
libgnunet_plugin_transport_udp_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  unsigned long long port;
  unsigned long long aport;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  int sockets_created;
  int broadcast;
  struct GNUNET_TIME_Relative interval;
  struct sockaddr_in serverAddrv4;
  struct sockaddr_in6 serverAddrv6;
  struct sockaddr *serverAddr;
  struct sockaddr *addrs[2];
  socklen_t addrlens[2];
  socklen_t addrlen;
  unsigned int tries;
  unsigned long long udp_max_bps;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-udp", "PORT",
                                             &port))
    port = 2086;

  broadcast =
      GNUNET_CONFIGURATION_get_value_yesno (env->cfg, "transport-udp",
                                            "BROADCAST");
  if (broadcast == GNUNET_SYSERR)
    broadcast = GNUNET_NO;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_time (env->cfg, "transport-udp",
                                           "BROADCAST_INTERVAL", &interval))
    interval = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-udp",
                                             "MAX_BPS", &udp_max_bps))
    udp_max_bps = 1024 * 1024 * 50;     /* 50 MB/s == infinity for practical purposes */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-udp",
                                             "ADVERTISED_PORT", &aport))
    aport = port;
  if (port > 65535)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Given `%s' option is out of range: %llu > %u\n"), "PORT", port,
         65535);
    return NULL;
  }
  memset (&serverAddrv6, 0, sizeof (serverAddrv6));
  memset (&serverAddrv4, 0, sizeof (serverAddrv4));

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  GNUNET_BANDWIDTH_tracker_init (&plugin->tracker,
                                 GNUNET_BANDWIDTH_value_init ((uint32_t)
                                                              udp_max_bps), 30);
  plugin->last_expected_delay = GNUNET_TIME_UNIT_SECONDS;
  plugin->port = port;
  plugin->aport = aport;
  plugin->env = env;
  plugin->broadcast_interval = interval;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;

  api->send = &udp_plugin_send;
  api->disconnect = &udp_disconnect;
  api->address_pretty_printer = &udp_plugin_address_pretty_printer;
  api->address_to_string = &udp_address_to_string;
  api->check_address = &udp_plugin_check_address;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (env->cfg, "transport-udp",
                                             "BINDTO", &plugin->bind4_address))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Binding udp plugin to specific address: `%s'\n",
         plugin->bind4_address);
    if (1 != inet_pton (AF_INET, plugin->bind4_address, &serverAddrv4.sin_addr))
    {
      GNUNET_free (plugin->bind4_address);
      GNUNET_free (plugin);
      GNUNET_free (api);
      return NULL;
    }
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (env->cfg, "transport-udp",
                                             "BINDTO6", &plugin->bind6_address))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Binding udp plugin to specific address: `%s'\n",
         plugin->bind6_address);
    if (1 !=
        inet_pton (AF_INET6, plugin->bind6_address, &serverAddrv6.sin6_addr))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid IPv6 address: `%s'\n"),
           plugin->bind6_address);
      GNUNET_free_non_null (plugin->bind4_address);
      GNUNET_free (plugin->bind6_address);
      GNUNET_free (plugin);
      GNUNET_free (api);
      return NULL;
    }
  }

  plugin->defrags =
      GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  plugin->sessions =
      GNUNET_CONTAINER_multihashmap_create (UDP_MAX_SENDER_ADDRESSES_WITH_DEFRAG
                                            * 2);
  plugin->inbound_sessions =
      GNUNET_CONTAINER_multihashmap_create (UDP_MAX_SENDER_ADDRESSES_WITH_DEFRAG
                                            * 2);
  sockets_created = 0;
  if ((GNUNET_YES !=
       GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg, "nat",
                                             "DISABLEV6")))
  {
    plugin->sockv6 = GNUNET_NETWORK_socket_create (PF_INET6, SOCK_DGRAM, 0);
    if (NULL == plugin->sockv6)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "socket");
    }
    else
    {
#if HAVE_SOCKADDR_IN_SIN_LEN
      serverAddrv6.sin6_len = sizeof (serverAddrv6);
#endif
      serverAddrv6.sin6_family = AF_INET6;
      serverAddrv6.sin6_addr = in6addr_any;
      serverAddrv6.sin6_port = htons (plugin->port);
      addrlen = sizeof (serverAddrv6);
      serverAddr = (struct sockaddr *) &serverAddrv6;
#if DEBUG_UDP
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Binding to IPv6 port %d\n",
           ntohs (serverAddrv6.sin6_port));
#endif
      tries = 0;
      while (GNUNET_NETWORK_socket_bind (plugin->sockv6, serverAddr, addrlen) !=
             GNUNET_OK)
      {
        serverAddrv6.sin6_port = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000);        /* Find a good, non-root port */
#if DEBUG_UDP
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "IPv6 Binding failed, trying new port %d\n",
             ntohs (serverAddrv6.sin6_port));
#endif
        tries++;
        if (tries > 10)
        {
          GNUNET_NETWORK_socket_close (plugin->sockv6);
          plugin->sockv6 = NULL;
          break;
        }
      }
      if (plugin->sockv6 != NULL)
      {
        addrs[sockets_created] = (struct sockaddr *) &serverAddrv6;
        addrlens[sockets_created] = sizeof (serverAddrv6);
        sockets_created++;
      }
    }
  }

  plugin->mst =
      GNUNET_SERVER_mst_create (&process_inbound_tokenized_messages, plugin);
  plugin->sockv4 = GNUNET_NETWORK_socket_create (PF_INET, SOCK_DGRAM, 0);
  if (NULL == plugin->sockv4)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "socket");
  }
  else
  {
#if HAVE_SOCKADDR_IN_SIN_LEN
    serverAddrv4.sin_len = sizeof (serverAddrv4);
#endif
    serverAddrv4.sin_family = AF_INET;
    serverAddrv4.sin_addr.s_addr = INADDR_ANY;
    serverAddrv4.sin_port = htons (plugin->port);
    addrlen = sizeof (serverAddrv4);
    serverAddr = (struct sockaddr *) &serverAddrv4;
#if DEBUG_UDP
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Binding to IPv4 port %d\n",
         ntohs (serverAddrv4.sin_port));
#endif
    tries = 0;
    while (GNUNET_NETWORK_socket_bind (plugin->sockv4, serverAddr, addrlen) !=
           GNUNET_OK)
    {
      serverAddrv4.sin_port = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000);   /* Find a good, non-root port */
#if DEBUG_UDP
      LOG (GNUNET_ERROR_TYPE_DEBUG, "IPv4 Binding failed, trying new port %d\n",
           ntohs (serverAddrv4.sin_port));
#endif
      tries++;
      if (tries > 10)
      {
        GNUNET_NETWORK_socket_close (plugin->sockv4);
        plugin->sockv4 = NULL;
        break;
      }
    }
    if (plugin->sockv4 != NULL)
    {
      addrs[sockets_created] = (struct sockaddr *) &serverAddrv4;
      addrlens[sockets_created] = sizeof (serverAddrv4);
      sockets_created++;
    }
  }

  plugin->rs = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_zero (plugin->rs);
  if (NULL != plugin->sockv4)
    GNUNET_NETWORK_fdset_set (plugin->rs, plugin->sockv4);
  if (NULL != plugin->sockv6)
    GNUNET_NETWORK_fdset_set (plugin->rs, plugin->sockv6);

  plugin->select_task =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   GNUNET_SCHEDULER_NO_TASK,
                                   GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
                                   NULL, &udp_plugin_select, plugin);



  if (broadcast)
  {
    /* create IPv4 broadcast socket */
    plugin->broadcast_ipv4 = GNUNET_NO;
    if (plugin->sockv4 != NULL)
    {
      int yes = 1;

      if (GNUNET_NETWORK_socket_setsockopt
          (plugin->sockv4, SOL_SOCKET, SO_BROADCAST, &yes,
           sizeof (int)) != GNUNET_OK)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _
             ("Failed to set IPv4 broadcast option for broadcast socket on port %d\n"),
             ntohs (serverAddrv4.sin_port));
      }
      else
      {
        GNUNET_OS_network_interfaces_list (iface_proc, plugin);
        plugin->send_ipv4_broadcast_task =
            GNUNET_SCHEDULER_add_now (&udp_ipv4_broadcast_send, plugin);

        plugin->broadcast_ipv4_mst =
            GNUNET_SERVER_mst_create (broadcast_ipv4_mst_cb, plugin);

        LOG (GNUNET_ERROR_TYPE_DEBUG, "IPv4 Broadcasting running\n");
        plugin->broadcast_ipv4 = GNUNET_YES;
      }
    }

    plugin->broadcast_ipv6 = GNUNET_NO;
    if (plugin->sockv6 != NULL)
    {
      memset (&plugin->ipv6_multicast_address, 0, sizeof (struct sockaddr_in6));
      GNUNET_assert (1 ==
                     inet_pton (AF_INET6, "FF05::13B",
                                &plugin->ipv6_multicast_address.sin6_addr));

      plugin->ipv6_multicast_address.sin6_family = AF_INET6;
      plugin->ipv6_multicast_address.sin6_port = htons (plugin->port);

      plugin->broadcast_ipv6_mst =
          GNUNET_SERVER_mst_create (broadcast_ipv6_mst_cb, plugin);

      /* Create IPv6 multicast request */
      struct ipv6_mreq multicastRequest;

      multicastRequest.ipv6mr_multiaddr =
          plugin->ipv6_multicast_address.sin6_addr;
      /* TODO: 0 selects the "best" interface, tweak to use all interfaces
       *
       * http://tools.ietf.org/html/rfc2553#section-5.2:
       *
       * IPV6_JOIN_GROUP
       *
       * Join a multicast group on a specified local interface.  If the
       * interface index is specified as 0, the kernel chooses the local
       * interface.  For example, some kernels look up the multicast
       * group in the normal IPv6 routing table and using the resulting
       * interface.
       * */
      multicastRequest.ipv6mr_interface = 0;

      /* Join the multicast group */
      if (GNUNET_NETWORK_socket_setsockopt
          (plugin->sockv6, IPPROTO_IPV6, IPV6_JOIN_GROUP,
           (char *) &multicastRequest, sizeof (multicastRequest)) == GNUNET_OK)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "IPv6 broadcasting running\n");

        plugin->send_ipv6_broadcast_task =
            GNUNET_SCHEDULER_add_now (&udp_ipv6_broadcast_send, plugin);
        plugin->broadcast_ipv6 = GNUNET_YES;
      }
      else
        LOG (GNUNET_ERROR_TYPE_DEBUG, "IPv6 broadcasting not running\n");
    }
  }

  if (sockets_created == 0)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _("Failed to open UDP sockets\n"));
  plugin->nat =
      GNUNET_NAT_register (env->cfg, GNUNET_NO, port, sockets_created,
                           (const struct sockaddr **) addrs, addrlens,
                           &udp_nat_port_map_callback, NULL, plugin);
  return api;
}

/**
 * Shutdown the plugin.
 *
 * @param cls our 'struct GNUNET_TRANSPORT_PluginFunctions'
 * @return NULL
 */
void *
libgnunet_plugin_transport_udp_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  struct ReceiveContext *rc;

  /* FIXME: clean up heap and hashmap */
  GNUNET_CONTAINER_multihashmap_iterate (plugin->sessions, &destroy_session,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (plugin->sessions);
  plugin->sessions = NULL;
  GNUNET_CONTAINER_multihashmap_iterate (plugin->inbound_sessions,
                                         &destroy_inbound_session, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (plugin->inbound_sessions);
  plugin->inbound_sessions = NULL;
  while (NULL != (rc = GNUNET_CONTAINER_heap_remove_root (plugin->defrags)))
  {
    GNUNET_DEFRAGMENT_context_destroy (rc->defrag);
    GNUNET_free (rc);
  }
  GNUNET_CONTAINER_heap_destroy (plugin->defrags);

  if (plugin->select_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->select_task);
    plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (plugin->broadcast_ipv4)
  {
    if (plugin->send_ipv4_broadcast_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->send_ipv4_broadcast_task);
      plugin->send_ipv4_broadcast_task = GNUNET_SCHEDULER_NO_TASK;
    }

    if (plugin->broadcast_ipv4_mst != NULL)
      GNUNET_SERVER_mst_destroy (plugin->broadcast_ipv4_mst);

    while (plugin->ipv4_broadcast_head != NULL)
    {
      struct BroadcastAddress *p = plugin->ipv4_broadcast_head;

      GNUNET_CONTAINER_DLL_remove (plugin->ipv4_broadcast_head,
                                   plugin->ipv4_broadcast_tail, p);
      GNUNET_free (p->addr);
      GNUNET_free (p);
    }
  }

  if (plugin->broadcast_ipv6)
  {
    /* Create IPv6 multicast request */
    struct ipv6_mreq multicastRequest;

    multicastRequest.ipv6mr_multiaddr =
        plugin->ipv6_multicast_address.sin6_addr;
    multicastRequest.ipv6mr_interface = 0;

    /* Join the multicast address */
    if (GNUNET_NETWORK_socket_setsockopt
        (plugin->sockv6, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
         (char *) &multicastRequest, sizeof (multicastRequest)) == GNUNET_OK)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "IPv6 Broadcasting stopped\n");
    }
    else
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, setsockopt);

    if (plugin->send_ipv6_broadcast_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->send_ipv6_broadcast_task);
      plugin->send_ipv6_broadcast_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (plugin->broadcast_ipv6_mst != NULL)
      GNUNET_SERVER_mst_destroy (plugin->broadcast_ipv6_mst);
  }


  if (plugin->sockv4 != NULL)
  {
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (plugin->sockv4));
    plugin->sockv4 = NULL;
  }
  if (plugin->sockv6 != NULL)
  {
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (plugin->sockv6));
    plugin->sockv6 = NULL;
  }

  GNUNET_SERVER_mst_destroy (plugin->mst);
  GNUNET_NETWORK_fdset_destroy (plugin->rs);

  GNUNET_NAT_unregister (plugin->nat);
  plugin->nat = NULL;
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_udp.c */
