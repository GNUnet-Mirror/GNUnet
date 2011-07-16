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
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"

#define DEBUG_UDP GNUNET_NO

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


/* Forward definition */
struct Plugin;


/**
 * Session with another peer.
 */
struct PeerSession
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
   * expected delay for ACKs 
   */
  struct GNUNET_TIME_Relative last_expected_delay;

  /**
   * Port we listen on.
   */
  uint16_t port;

  /**
   * Port we advertise on.
   */
  uint16_t aport;

};


/**
 * Lookup the session for the given peer.
 *
 * @param plugin the plugin
 * @param peer peer's identity
 * @return NULL if we have no session
 */
struct PeerSession *
find_session (struct Plugin *plugin,
	      const struct GNUNET_PeerIdentity *peer)
{
  return GNUNET_CONTAINER_multihashmap_get (plugin->sessions, 
					    &peer->hashPubKey);
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
  struct PeerSession *session;

  session = find_session (plugin, target);
  if (NULL == session)
    return;
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_remove (plugin->sessions,
						       &target->hashPubKey,
						       session));
  plugin->last_expected_delay = GNUNET_FRAGMENT_context_destroy (session->frag);
  session->cont (session->cont_cls, target, GNUNET_SYSERR);
  GNUNET_free (session);
}


/**
 * Actually send out the message.
 *
 * @param plugin the plugin
 * @param send_handle which handle to send message on
 * @param target who should receive this message (ignored by UDP)
 * @param msgbuf one or more GNUNET_MessageHeader(s) strung together
 * @param msgbuf_size the size of the msgbuf to send
 * @param priority how important is the message (ignored by UDP)
 * @param timeout when should we time out (give up) if we can not transmit?
 * @param addr the addr to send the message to, needs to be a sockaddr for us
 * @param addrlen the len of addr
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 * @return the number of bytes written
 */
static ssize_t
udp_send (struct Plugin *plugin,
	  const struct sockaddr *sa,
	  const struct GNUNET_MessageHeader *msg)
{
  ssize_t sent;
  size_t slen;

  switch (sa->sa_family)
    {
    case AF_INET:
      sent =
	GNUNET_NETWORK_socket_sendto (plugin->sockv4,
				      msg,
				      ntohs (msg->size),
				      sa,
				      slen = sizeof (struct sockaddr_in));
      break;
    case AF_INET6:
      sent =
	GNUNET_NETWORK_socket_sendto (plugin->sockv6,
				      msg,
				      ntohs (msg->size),
				      sa,
				      slen = sizeof (struct sockaddr_in6));
      break;
    default:
      GNUNET_break (0);
      return 0;
    }
  if (GNUNET_SYSERR == sent)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_INFO, 
			 "sendto");
#if DEBUG_UDP
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "UDP transmited %u-byte message to %s (%d: %s)\n",
	      (unsigned int) ntohs (msg->size),
	      GNUNET_a2s (sa, slen),
	      (int) sent,
	      (sent < 0) ? STRERROR (errno) : "ok");
#endif
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
send_fragment (void *cls,
	       const struct GNUNET_MessageHeader *msg)
{
  struct PeerSession *session = cls;

  udp_send (session->plugin,
	    session->sock_addr,
	    msg);
  GNUNET_FRAGMENT_context_transmission_done (session->frag);
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
  struct PeerSession *peer_session;
  const struct IPv4UdpAddress *t4;
  const struct IPv6UdpAddress *t6;
  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;
  size_t mlen = msgbuf_size + sizeof (struct UDPMessage);
  char mbuf[mlen];
  struct UDPMessage *udp;

  if (force_address == GNUNET_SYSERR)
    return GNUNET_SYSERR;
  GNUNET_assert (NULL == session);
  if (mlen >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  switch (addrlen)
    {
    case sizeof(struct IPv4UdpAddress):   
      t4 = addr;
      peer_session = GNUNET_malloc (sizeof (struct PeerSession) + sizeof (struct sockaddr_in));
      v4 = (struct sockaddr_in*) &peer_session[1];
      v4->sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
      v4->sin_len = sizeof (struct sockaddr_in);
#endif
      v4->sin_port = t4->u4_port;
      v4->sin_addr.s_addr = t4->ipv4_addr;
      break;
    case sizeof(struct IPv6UdpAddress):
      t6 = addr;
      peer_session = GNUNET_malloc (sizeof (struct PeerSession) + sizeof (struct sockaddr_in6));
      v6 = (struct sockaddr_in6*) &peer_session[1];
      v6->sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
      v6->sin6_len = sizeof (struct sockaddr_in6);
#endif
      v6->sin6_port = t6->u6_port;
      v6->sin6_addr = t6->ipv6_addr;
      break;
    default:
      /* Must have a valid address to send to */
      GNUNET_break_op(0);
      return GNUNET_SYSERR;
    }
  udp = (struct UDPMessage*) mbuf;
  udp->header.size = htons (mlen);
  udp->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_MESSAGE);
  udp->reserved = htonl (0);
  udp->sender = *plugin->env->my_identity;
  memcpy (&udp[1], msgbuf, msgbuf_size);
  peer_session->target = *target;
  peer_session->plugin = plugin;
  peer_session->sock_addr = (const struct sockaddr*) &peer_session[1];
  peer_session->cont = cont;
  peer_session->cont_cls = cont_cls;  
  if (mlen <= UDP_MTU)
    {
      mlen = udp_send (plugin, 
		       peer_session->sock_addr,
		       &udp->header);
      cont (cont_cls, target, (mlen > 0) ? GNUNET_OK : GNUNET_SYSERR);
      GNUNET_free (peer_session);      
    }
  else
    {
      GNUNET_assert (GNUNET_OK ==
		     GNUNET_CONTAINER_multihashmap_put (plugin->sessions,
							&target->hashPubKey,
							peer_session,
							GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
      peer_session->frag = GNUNET_FRAGMENT_context_create (plugin->env->stats,
							   UDP_MTU,
							   &plugin->tracker,
							   plugin->last_expected_delay,
							   &udp->header,
							   &send_fragment,
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
process_inbound_tokenized_messages (void *cls,
				    void *client,
				    const struct GNUNET_MessageHeader *hdr)
{
  struct Plugin *plugin = cls;
  struct SourceInformation* si = client;
  struct GNUNET_TRANSPORT_ATS_Information distance[2];

  /* setup ATS */
  distance[0].type = htonl (GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE);
  distance[0].value = htonl (1);
  distance[1].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  distance[1].value = htonl (0);

  plugin->env->receive (plugin->env->cls, 
			&si->sender, 
			hdr,
			distance, 2,
			NULL, 
			si->arg, si->args);
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
process_udp_message (struct Plugin *plugin,
		     const struct UDPMessage *msg,
		     const struct sockaddr *sender_addr,
		     socklen_t sender_addr_len)
{
  struct SourceInformation si;
  struct IPv4UdpAddress u4;
  struct IPv6UdpAddress u6;
  const void *arg;
  size_t args;
					  
  if (0 != ntohl (msg->reserved))
    {
      GNUNET_break_op (0);
      return;
    }
  if (ntohs (msg->header.size) < sizeof (struct GNUNET_MessageHeader) + sizeof (struct UDPMessage))
    {
      GNUNET_break_op (0);
      return;
    }

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
      u6.ipv6_addr = ((struct sockaddr_in6*) sender_addr)->sin6_addr;
      u6.u6_port = ((struct sockaddr_in6 *) sender_addr)->sin6_port;
      arg = &u6;
      args = sizeof (u6);    
      break;
    default:
      GNUNET_break (0);
      return;
    }
#if DEBUG_UDP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "udp",
		   "Received message with %u bytes from peer `%s' at `%s'\n",
		   (unsigned int) ntohs (msg->header.size),
		   GNUNET_i2s (&msg->sender),
		   GNUNET_a2s (sender_addr, sender_addr_len));
#endif

  /* iterate over all embedded messages */
  si.sender = msg->sender;
  si.arg = arg;
  si.args = args;
  GNUNET_SERVER_mst_receive (plugin->mst,
			     &si,
			     (const char*) &msg[1],
			     ntohs (msg->header.size) - sizeof (struct UDPMessage),
			     GNUNET_YES,
			     GNUNET_NO);
}


/**
 * Process a defragmented message.
 *
 * @param cls the 'struct ReceiveContext'
 * @param msg the message
 */
static void
fragment_msg_proc (void *cls,
		   const struct GNUNET_MessageHeader *msg)
{
  struct ReceiveContext *rc = cls;

  if (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_MESSAGE)
    {
      GNUNET_break (0);
      return;
    }
  if (ntohs (msg->size) < sizeof(struct UDPMessage))
    {
      GNUNET_break (0);
      return;
    }   
  process_udp_message (rc->plugin,
		       (const struct UDPMessage*) msg,
		       rc->src_addr,
		       rc->addr_len);
}		   


/**
 * Transmit an acknowledgement.
 *
 * @param cls the 'struct ReceiveContext'
 * @param id message ID (unused)
 * @param msg ack to transmit
 */
static void
ack_proc (void *cls,
	  uint32_t id,
	  const struct GNUNET_MessageHeader *msg)
{
  struct ReceiveContext *rc = cls;
  size_t msize = sizeof (struct UDPMessage) + ntohs (msg->size);
  char buf[msize];
  struct UDPMessage *udp;

#if DEBUG_UDP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "udp",
		   "Sending ACK to `%s'\n",
		   GNUNET_a2s (rc->src_addr, 
			       (rc->src_addr->sa_family == AF_INET)
			       ? sizeof (struct sockaddr_in) 
			       : sizeof (struct sockaddr_in6)));
#endif
  udp = (struct UDPMessage*) buf;
  udp->header.size = htons ((uint16_t) msize);
  udp->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_ACK);
  udp->reserved = htonl (0);
  udp->sender = *rc->plugin->env->my_identity;
  memcpy (&udp[1], msg, ntohs (msg->size));
  (void) udp_send (rc->plugin, 
		   rc->src_addr,
		   &udp->header);
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
find_receive_context (void *cls,
		      struct GNUNET_CONTAINER_HeapNode *node,
		      void *element,
		      GNUNET_CONTAINER_HeapCostType cost)
{
  struct FindReceiveContext *frc = cls;
  struct ReceiveContext *e = element;

  if ( (frc->addr_len == e->addr_len) &&
       (0 == memcmp (frc->addr,
		     e->src_addr,
		     frc->addr_len) ) )
    {
      frc->rc = e;
      return GNUNET_NO;
    }
  return GNUNET_YES;
}


/**
 * Read and process a message from the given socket.
 *
 * @param plugin the overall plugin
 * @param rsock socket to read from
 */
static void
udp_read (struct Plugin *plugin,
	  struct GNUNET_NETWORK_Handle *rsock)
{
  socklen_t fromlen;
  char addr[32];
  char buf[65536];
  ssize_t ret;
  const struct GNUNET_MessageHeader *msg;
  const struct GNUNET_MessageHeader *ack;
  struct PeerSession *peer_session;
  const struct UDPMessage *udp;
  struct ReceiveContext *rc;
  struct GNUNET_TIME_Absolute now;
  struct FindReceiveContext frc;

  fromlen = sizeof (addr);
  memset (&addr, 0, sizeof(addr));
  ret = GNUNET_NETWORK_socket_recvfrom (rsock, buf, sizeof (buf),
					(struct sockaddr *)&addr, &fromlen);
  if (ret < sizeof (struct GNUNET_MessageHeader))
    {
      GNUNET_break_op (0);
      return;
    }
#if DEBUG_UDP
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "UDP received %u-byte message from `%s'\n",
	      (unsigned int) ret,
	      GNUNET_a2s ((const struct sockaddr*) addr, fromlen));
#endif
  msg = (const struct GNUNET_MessageHeader *) buf;
  if (ret != ntohs (msg->size))
    {
      GNUNET_break_op (0);
      return;
    }
  switch (ntohs (msg->type))
    {
    case GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_MESSAGE:
      if (ntohs (msg->size) < sizeof (struct UDPMessage))
	{
	  GNUNET_break_op (0);
	  return;
	}
      process_udp_message (plugin,
			   (const struct UDPMessage *) msg,
			   (const struct sockaddr*) addr,
			   fromlen);
      return;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_ACK:
      if (ntohs (msg->size) < sizeof (struct UDPMessage) + sizeof (struct GNUNET_MessageHeader))
	{
	  GNUNET_break_op (0);
	  return;
	}
      udp = (const struct UDPMessage *) msg;
      if (ntohl (udp->reserved) != 0)
	{
	  GNUNET_break_op (0);
	  return;
	}
      ack = (const struct GNUNET_MessageHeader*) &udp[1];      
      if (ntohs (ack->size) != ntohs (msg->size) - sizeof (struct UDPMessage))
	{
	  GNUNET_break_op (0);
	  return;
	}
#if DEBUG_UDP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "UDP processes %u-byte acknowledgement from `%s' at `%s'\n",
		  (unsigned int) ntohs (msg->size),
		  GNUNET_i2s (&udp->sender),
		  GNUNET_a2s ((const struct sockaddr*) addr, fromlen));
#endif

      peer_session = find_session (plugin, &udp->sender);
      if (NULL == peer_session)
	{
#if DEBUG_UDP
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Session for ACK not found, dropping ACK!\n");
#endif
	  return; 
	}
      if (GNUNET_OK !=
	  GNUNET_FRAGMENT_process_ack (peer_session->frag,
				       ack))
	return; 
      GNUNET_assert (GNUNET_OK ==
		     GNUNET_CONTAINER_multihashmap_remove (plugin->sessions,
							   &udp->sender.hashPubKey,
							   peer_session));
      plugin->last_expected_delay = GNUNET_FRAGMENT_context_destroy (peer_session->frag);
      peer_session->cont (peer_session->cont_cls,
			  &udp->sender, 
			  GNUNET_OK);
      GNUNET_free (peer_session);
      return;
    case GNUNET_MESSAGE_TYPE_FRAGMENT:
      frc.rc = NULL;
      frc.addr = (const struct sockaddr*) addr;
      frc.addr_len = fromlen;
      GNUNET_CONTAINER_heap_iterate (plugin->defrags,
				     &find_receive_context,
				     &frc);
      now = GNUNET_TIME_absolute_get ();
      rc = frc.rc;
      if (rc == NULL)
	{
	  /* need to create a new RC */
	  rc = GNUNET_malloc (sizeof (struct ReceiveContext) + fromlen);
	  memcpy (&rc[1], addr, fromlen);
  	  rc->src_addr = (const struct sockaddr*) &rc[1];
	  rc->addr_len = fromlen;
	  rc->plugin = plugin;
	  rc->defrag = GNUNET_DEFRAGMENT_context_create (plugin->env->stats,
							 UDP_MTU,
							 UDP_MAX_MESSAGES_IN_DEFRAG,
							 rc,
							 &fragment_msg_proc,
							 &ack_proc);
	  rc->hnode = GNUNET_CONTAINER_heap_insert (plugin->defrags,
						    rc,
						    (GNUNET_CONTAINER_HeapCostType) now.abs_value);
	}
#if DEBUG_UDP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "UDP processes %u-byte fragment from `%s'\n",
		  (unsigned int) ntohs (msg->size),
		  GNUNET_a2s ((const struct sockaddr*) addr, fromlen));
#endif

      if (GNUNET_OK == 
	  GNUNET_DEFRAGMENT_process_fragment (rc->defrag,
					      msg))
	{
	  /* keep this 'rc' from expiring */
	  GNUNET_CONTAINER_heap_update_cost (plugin->defrags,
					     rc->hnode,
					     (GNUNET_CONTAINER_HeapCostType) now.abs_value);
	}
      if (GNUNET_CONTAINER_heap_get_size (plugin->defrags) > UDP_MAX_SENDER_ADDRESSES_WITH_DEFRAG)
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
udp_plugin_select (void *cls,
		   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

  plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
  if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  if ( (NULL != plugin->sockv4) &&
       (GNUNET_NETWORK_fdset_isset (tc->read_ready,
				    plugin->sockv4)) )
    udp_read (plugin, plugin->sockv4);
  if ( (NULL != plugin->sockv6) &&
       (GNUNET_NETWORK_fdset_isset (tc->read_ready,
				    plugin->sockv6)) )
    udp_read (plugin, plugin->sockv6);
  plugin->select_task =
    GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
				 GNUNET_SCHEDULER_NO_TASK,
				 GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
				 NULL, &udp_plugin_select, plugin);
  
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
  if ( (in_port == plugin->port) ||
       (in_port == plugin->aport) )
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
udp_plugin_check_address (void *cls,
			  const void *addr,
			  size_t addrlen)
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
      if (GNUNET_OK !=
	  check_port (plugin, ntohs (v4->u4_port)))
	return GNUNET_SYSERR;
      if (GNUNET_OK !=
	  GNUNET_NAT_test_address (plugin->nat, 
				   &v4->ipv4_addr, sizeof (struct in_addr)))
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
      if (GNUNET_OK !=
	  check_port (plugin, ntohs (v6->u6_port)))
	return GNUNET_SYSERR;
      if (GNUNET_OK !=
	  GNUNET_NAT_test_address (plugin->nat,
				   &v6->ipv6_addr, sizeof (struct in6_addr)))
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
  GNUNET_snprintf (rbuf,
                   sizeof (rbuf),
                   "%s:%u",
                   buf,
                   port);
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
  GNUNET_asprintf (&ret,
		   "%s:%d",
		   hostname, 
		   ppc->port);
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
      memcpy (&a6.sin6_addr,
              &u6->ipv6_addr,
              sizeof (struct in6_addr));
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
  GNUNET_RESOLVER_hostname_get (sb,
                                sbs,
                                !numeric, timeout,
				&append_port, ppc);
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
udp_nat_port_map_callback (void *cls,
			   int add_remove,
			   const struct sockaddr *addr,
			   socklen_t addrlen)
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
      memcpy (&u6.ipv6_addr,
	      &((struct sockaddr_in6 *) addr)->sin6_addr,
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
  plugin->env->notify_address (plugin->env->cls,
			       add_remove,
			       arg, args);
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
  struct sockaddr_in serverAddrv4;
  struct sockaddr_in6 serverAddrv6;
  struct sockaddr *serverAddr;
  struct sockaddr *addrs[2];
  socklen_t addrlens[2];
  socklen_t addrlen;
  unsigned int tries;
  unsigned long long udp_max_bps;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg,
					     "transport-udp",
					     "PORT",
					     &port))
    port = 2086;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg,
					     "transport-udp",
					     "MAX_BPS",
					     &udp_max_bps))
    udp_max_bps = 1024 * 1024 * 50; /* 50 MB/s == infinity for practical purposes */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg,
					     "transport-udp",
					     "ADVERTISED_PORT",
					     &aport))
    aport = port;
  if (port > 65535)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Given `%s' option is out of range: %llu > %u\n"),
                  "PORT",
                  port,
                  65535);
      return NULL;
    }
  memset (&serverAddrv6, 0, sizeof (serverAddrv6));
  memset (&serverAddrv4, 0, sizeof (serverAddrv4));

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  GNUNET_BANDWIDTH_tracker_init (&plugin->tracker,
				 GNUNET_BANDWIDTH_value_init ((uint32_t) udp_max_bps),
				 30);
  plugin->last_expected_delay = GNUNET_TIME_UNIT_SECONDS;
  plugin->port = port;
  plugin->aport = aport;
  plugin->env = env;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;

  api->send = &udp_plugin_send;
  api->disconnect = &udp_disconnect;
  api->address_pretty_printer = &udp_plugin_address_pretty_printer;
  api->address_to_string = &udp_address_to_string;
  api->check_address = &udp_plugin_check_address;

  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_string(env->cfg, 
							  "transport-udp", 
							  "BINDTO", 
							  &plugin->bind4_address))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, 
		 "Binding udp plugin to specific address: `%s'\n", 
		 plugin->bind4_address);
      if (1 != inet_pton(AF_INET,
			 plugin->bind4_address, 
			 &serverAddrv4.sin_addr))
	{
	  GNUNET_free (plugin->bind4_address);
	  GNUNET_free (plugin);
	  GNUNET_free (api);
	  return NULL;
	}
    }

  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_string(env->cfg, 
							  "transport-udp",
							  "BINDTO6", 
							  &plugin->bind6_address))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
		 "Binding udp plugin to specific address: `%s'\n",
		 plugin->bind6_address);
      if (1 != inet_pton(AF_INET6, 
			 plugin->bind6_address, 
			 &serverAddrv6.sin6_addr))
	{
	  GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
		     _("Invalid IPv6 address: `%s'\n"),
		     plugin->bind6_address);
	  GNUNET_free_non_null (plugin->bind4_address);
	  GNUNET_free (plugin->bind6_address);
	  GNUNET_free (plugin);
	  GNUNET_free (api);
	  return NULL;
	}
    }

  plugin->defrags = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  plugin->sessions = GNUNET_CONTAINER_multihashmap_create (UDP_MAX_SENDER_ADDRESSES_WITH_DEFRAG * 2);
  sockets_created = 0;
  if ( (GNUNET_YES !=
	GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg,
					      "nat",
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
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			   "Binding to IPv6 port %d\n",
			   ntohs(serverAddrv6.sin6_port));
#endif
	  tries = 0;
	  while (GNUNET_NETWORK_socket_bind (plugin->sockv6, 
					     serverAddr, addrlen) !=
		 GNUNET_OK)
	    {
	      serverAddrv6.sin6_port
		= htons (GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000); /* Find a good, non-root port */
#if DEBUG_UDP
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			       "IPv6 Binding failed, trying new port %d\n",
			       ntohs(serverAddrv6.sin6_port));
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
	      addrs[sockets_created] = (struct sockaddr*)  &serverAddrv6;
	      addrlens[sockets_created] = sizeof (serverAddrv6);
	      sockets_created++;
	    }
	}
    }

  plugin->mst = GNUNET_SERVER_mst_create (&process_inbound_tokenized_messages,
					  plugin);
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
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		       "Binding to IPv4 port %d\n",
		       ntohs(serverAddrv4.sin_port));
#endif
      tries = 0;
      while (GNUNET_NETWORK_socket_bind (plugin->sockv4, serverAddr, addrlen) !=
	     GNUNET_OK)
	{
	  serverAddrv4.sin_port = htons (GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000); /* Find a good, non-root port */
#if DEBUG_UDP
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			   "IPv4 Binding failed, trying new port %d\n",
			   ntohs(serverAddrv4.sin_port));
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
	  addrs[sockets_created] = (struct sockaddr*) &serverAddrv4;
	  addrlens[sockets_created] = sizeof (serverAddrv4);
	  sockets_created++;
	}
    }

  plugin->rs = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_zero (plugin->rs);
  if (NULL != plugin->sockv4)
    GNUNET_NETWORK_fdset_set (plugin->rs,
			      plugin->sockv4);
  if (NULL != plugin->sockv6)
    GNUNET_NETWORK_fdset_set (plugin->rs,
			      plugin->sockv6);

  plugin->select_task =
    GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                 GNUNET_SCHEDULER_NO_TASK,
                                 GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
                                 NULL, &udp_plugin_select, plugin);
  if (sockets_created == 0)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to open UDP sockets\n"));
  plugin->nat = GNUNET_NAT_register (env->cfg,
				     GNUNET_NO,
				     port,
				     sockets_created,
				     (const struct sockaddr**) addrs, addrlens,
				     &udp_nat_port_map_callback, 
				     NULL,
				     plugin);
  return api;
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
destroy_session (void *cls,
		 const GNUNET_HashCode *key,
		 void *value)
{
  struct PeerSession *peer_session = value;

  GNUNET_FRAGMENT_context_destroy (peer_session->frag);
  GNUNET_free (peer_session);
  return GNUNET_OK;
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
  GNUNET_CONTAINER_multihashmap_iterate (plugin->sessions,
					 &destroy_session,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (plugin->sessions);
  plugin->sessions = NULL;
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
