/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_tcp.c
 * @brief Implementation of the TCP transport service
 * @author Christian Grothoff
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

#define DEBUG_TCP GNUNET_NO

/**
 * After how long do we expire an address that we
 * learned from another peer if it is not reconfirmed
 * by anyone?
 */
#define LEARNED_ADDRESS_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 6)

/**
 * How long until we give up on transmitting the welcome message?
 */
#define WELCOME_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * How long until we give up on transmitting the welcome message?
 */
#define HOSTNAME_RESOLVE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * For how many messages back to we keep transmission times?
 */
#define ACK_LOG_SIZE 32



/**
 * Message used to ask a peer to validate receipt (to check an address
 * from a HELLO).  Followed by the address used.  Note that the
 * recipients response does not affirm that he has this address,
 * only that he got the challenge message.
 */
struct ValidationChallengeMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_PING
   */
  struct GNUNET_MessageHeader header;

  /**
   * Random challenge number (in network byte order).
   */
  uint32_t challenge GNUNET_PACKED;

  /**
   * Who is the intended recipient?
   */
  struct GNUNET_PeerIdentity target;

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
struct ValidationChallengeResponse
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_PONG
   */
  struct GNUNET_MessageHeader header;

  /**
   * For padding, always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Signature.
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

  /**
   * What are we signing and why?
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * Random challenge number (in network byte order).
   */
  uint32_t challenge GNUNET_PACKED;

  /**
   * Who signed this message?
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded signer;

};



/**
 * Initial handshake message for a session.  This header
 * is followed by the address that the other peer used to
 * connect to us (so that we may learn it) or the address
 * that the other peer got from the accept call.
 */
struct WelcomeMessage
{
  struct GNUNET_MessageHeader header;

  /**
   * Identity of the node connecting (TCP client)
   */
  struct GNUNET_PeerIdentity clientIdentity;

};


/**
 * Encapsulation for normal TCP traffic.
 */
struct DataMessage
{
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Number of the last message that was received from the other peer.
   */
  uint64_t ack_in GNUNET_PACKED;

  /**
   * Number of this outgoing message.
   */
  uint64_t ack_out GNUNET_PACKED;

  /**
   * How long was sending this ack delayed by the other peer
   * (estimate).  The receiver of this message can use the delay
   * between sending his message number 'ack' and receiving this ack
   * minus the delay as an estimate of the round-trip time.
   */
  struct GNUNET_TIME_RelativeNBO delay;

};


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin;


/**
 * Information kept for each message that is yet to
 * be transmitted.
 */
struct PendingMessage
{

  /**
   * This is a linked list.
   */
  struct PendingMessage *next;

  /**
   * The pending message, pointer to the end
   * of this struct, do not free!
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * Continuation function to call once the message
   * has been sent.  Can be  NULL if there is no
   * continuation to call.
   */
  GNUNET_TRANSPORT_TransmitContinuation transmit_cont;

  /**
   * Closure for transmit_cont.
   */
  void *transmit_cont_cls;

  /**
   * Timeout value for the pending message.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * GNUNET_YES if this is a welcome message;
   * otherwise this should be a DATA message.
   */
  int is_welcome;

};


/**
 * Session handle for TCP connections.
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
   * The client (used to identify this connection)
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * gnunet-service-transport context for this connection.
   */
  struct ReadyList *service_context;

  /**
   * Messages currently pending for transmission
   * to this peer, if any.
   */
  struct PendingMessage *pending_messages;

  /**
   * Handle for pending transmission request.
   */
  struct GNUNET_CONNECTION_TransmitHandle *transmit_handle;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity target;

  /**
   * At what time did we reset last_received last?
   */
  struct GNUNET_TIME_Absolute last_quota_update;

  /**
   * Address of the other peer if WE initiated the connection
   * (and hence can be sure what it is), otherwise NULL.
   */
  void *connect_addr;

  /**
   * How many bytes have we received since the "last_quota_update"
   * timestamp?
   */
  uint64_t last_received;

  /**
   * Our current latency estimate (in ms).
   */
  double latency_estimate;

  /**
   * Time when we generated the last ACK_LOG_SIZE acks.
   * (the "last" refers to the "out_msg_counter" here)
   */
  struct GNUNET_TIME_Absolute gen_time[ACK_LOG_SIZE];

  /**
   * Our current sequence number.
   */
  uint64_t out_msg_counter;

  /**
   * Highest received incoming sequence number.
   */
  uint64_t max_in_msg_counter;

  /**
   * Number of bytes per ms that this peer is allowed
   * to send to us.
   */
  uint32_t quota_in;

  /**
   * Length of connect_addr, can be 0.
   */
  size_t connect_alen;

  /**
   * Are we still expecting the welcome message? (GNUNET_YES/GNUNET_NO)
   * GNUNET_SYSERR is used to mark non-welcoming connections (HELLO
   * validation only).
   */
  int expecting_welcome;

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
   * The listen socket.
   */
  struct GNUNET_CONNECTION_Handle *lsock;

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
   * Handle to the server for this service.
   */
  struct GNUNET_SERVER_Handle *server;

  /**
   * Copy of the handler array where the closures are
   * set to this struct's instance.
   */
  struct GNUNET_SERVER_MessageHandler *handlers;

  /**
   * ID of task used to update our addresses when one expires.
   */
  GNUNET_SCHEDULER_TaskIdentifier address_update_task;

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


/**
 * Find the session handle for the given peer.
 */
static struct Session *
find_session_by_target (struct Plugin *plugin,
                        const struct GNUNET_PeerIdentity *target)
{
  struct Session *ret;

  ret = plugin->sessions;
  while ((ret != NULL) &&
	 ( (GNUNET_SYSERR == ret->expecting_welcome) ||
	   (0 != memcmp (target,
			 &ret->target, sizeof (struct GNUNET_PeerIdentity)))))
    ret = ret->next;
  return ret;
}


/**
 * Find the session handle for the given peer.
 */
static struct Session *
find_session_by_client (struct Plugin *plugin,
                        const struct GNUNET_SERVER_Client *client)
{
  struct Session *ret;

  ret = plugin->sessions;
  while ((ret != NULL) && (client != ret->client))
    ret = ret->next;
  return ret;
}


/**
 * Create a welcome message.
 */
static struct PendingMessage *
create_welcome (size_t addrlen, const void *addr, struct Plugin *plugin)
{
  struct PendingMessage *pm;
  struct WelcomeMessage *welcome;

  pm = GNUNET_malloc (sizeof (struct PendingMessage) +
                      sizeof (struct WelcomeMessage) + addrlen);
  pm->msg = (struct GNUNET_MessageHeader *) &pm[1];
  welcome = (struct WelcomeMessage *) &pm[1];
  welcome->header.size = htons (sizeof (struct WelcomeMessage) + addrlen);
  welcome->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME);
  GNUNET_CRYPTO_hash (plugin->env->my_public_key,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &welcome->clientIdentity.hashPubKey);
  memcpy (&welcome[1], addr, addrlen);
  pm->timeout = GNUNET_TIME_relative_to_absolute (WELCOME_TIMEOUT);
  pm->is_welcome = GNUNET_YES;
  return pm;
}


/**
 * Create a new session using the specified address
 * for the welcome message.
 *
 * @param plugin us
 * @param target peer to connect to
 * @param client client to use
 * @param addrlen IPv4 or IPv6
 * @param addr either struct sockaddr_in or struct sockaddr_in6
 * @return NULL connection failed / invalid address
 */
static struct Session *
create_session (struct Plugin *plugin,
                const struct GNUNET_PeerIdentity *target,
                struct GNUNET_SERVER_Client *client,
                const void *addr, size_t addrlen)
{
  struct Session *ret;

  ret = GNUNET_malloc (sizeof (struct Session));
  ret->plugin = plugin;
  ret->next = plugin->sessions;
  plugin->sessions = ret;
  ret->client = client;
  ret->target = *target;
  ret->last_quota_update = GNUNET_TIME_absolute_get ();
  ret->quota_in = plugin->env->default_quota_in;
  ret->expecting_welcome = GNUNET_YES;
  ret->pending_messages = create_welcome (addrlen, addr, plugin);
  return ret;
}


/**
 * If we have pending messages, ask the server to
 * transmit them (schedule the respective tasks, etc.)
 *
 * @param session for which session should we do this
 */
static void process_pending_messages (struct Session *session);


/**
 * Function called to notify a client about the socket
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
do_transmit (void *cls, size_t size, void *buf)
{
  struct Session *session = cls;
  struct PendingMessage *pm;
  char *cbuf;
  uint16_t msize;
  size_t ret;
  struct DataMessage *dm;

  session->transmit_handle = NULL;
  if (buf == NULL)
    {
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp", 
		       "Timeout trying to transmit to peer `%4s', discarding message queue.\n",
		       GNUNET_i2s(&session->target));
#endif
      /* timeout */
      while (NULL != (pm = session->pending_messages))
        {
          session->pending_messages = pm->next;
#if DEBUG_TCP
	  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
			   "tcp", 
			   "Failed to transmit message of type %u to `%4s'.\n",
			   ntohs(pm->msg->type),
			   GNUNET_i2s(&session->target));
#endif
          if (pm->transmit_cont != NULL)
	    pm->transmit_cont (pm->transmit_cont_cls,
			       session->service_context,
			       &session->target, GNUNET_SYSERR);	    
          GNUNET_free (pm);
        }
      return 0;
    }
  ret = 0;
  cbuf = buf;
  while (NULL != (pm = session->pending_messages))
    {
      if (pm->is_welcome)
        {
          if (size < (msize = htons (pm->msg->size)))
            break;
          memcpy (cbuf, pm->msg, msize);
          cbuf += msize;
          ret += msize;
          size -= msize;
        }
      else
        {
          if (size <
              sizeof (struct DataMessage) + (msize = htons (pm->msg->size)))
            break;
          dm = (struct DataMessage *) cbuf;
          dm->header.size = htons (sizeof (struct DataMessage) + msize);
          dm->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_DATA);
          dm->ack_out = GNUNET_htonll (++session->out_msg_counter);
          dm->ack_in = GNUNET_htonll (session->max_in_msg_counter);
          cbuf += sizeof (struct DataMessage);
          ret += sizeof (struct DataMessage);
          size -= sizeof (struct DataMessage);
          memcpy (cbuf, pm->msg, msize);
          cbuf += msize;
          ret += msize;
          size -= msize;
        }
      session->pending_messages = pm->next;
      if (pm->transmit_cont != NULL)
        pm->transmit_cont (pm->transmit_cont_cls,
                           session->service_context,
                           &session->target, GNUNET_OK);
      GNUNET_free (pm);
      session->gen_time[session->out_msg_counter % ACK_LOG_SIZE]
        = GNUNET_TIME_absolute_get ();
    }
  process_pending_messages (session);
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp", "Transmitting %u bytes\n", ret);
#endif
  return ret;
}


/**
 * If we have pending messages, ask the server to
 * transmit them (schedule the respective tasks, etc.)
 *
 * @param session for which session should we do this
 */
static void
process_pending_messages (struct Session *session)
{
  GNUNET_assert (session->client != NULL);
  if (session->pending_messages == NULL)
    return;
  if (session->transmit_handle != NULL)
    return;
  session->transmit_handle
    = GNUNET_SERVER_notify_transmit_ready (session->client,
                                           htons (session->
                                                  pending_messages->msg->
                                                  size) +
                                           (session->
                                            pending_messages->is_welcome ? 0 :
                                            sizeof (struct DataMessage)),
                                           GNUNET_TIME_absolute_get_remaining
                                           (session->
                                            pending_messages[0].timeout),
                                           &do_transmit, session);
}



/**
 * Create a new session connecting to the specified
 * target at the specified address.  The session will
 * be used to verify an address in a HELLO and should
 * not expect to receive a WELCOME.
 *
 * @param plugin us
 * @param target peer to connect to
 * @param addrlen IPv4 or IPv6
 * @param addr either struct sockaddr_in or struct sockaddr_in6
 * @return NULL connection failed / invalid address
 */
static struct Session *
connect_and_create_validation_session (struct Plugin *plugin,
				       const struct GNUNET_PeerIdentity *target,
				       const void *addr, size_t addrlen)
{
  struct GNUNET_SERVER_Client *client;
  struct GNUNET_CONNECTION_Handle *conn;
  struct Session *session;
  int af;

  if (addrlen == sizeof (struct sockaddr_in))
    af = AF_INET;
  else if (addrlen == sizeof (struct sockaddr_in6))
    af = AF_INET6;    
  else
    {
      GNUNET_break_op (0);
      return NULL;              /* invalid address */
    }
  conn = GNUNET_CONNECTION_create_from_sockaddr (plugin->env->sched,
                                                     af,
                                                     addr,
                                                     addrlen,
                                                     GNUNET_SERVER_MAX_MESSAGE_SIZE);
  if (conn == NULL)
    {
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp",
                       "Failed to create connection to peer at `%s'.\n",
		       GNUNET_a2s(addr, addrlen));
#endif
      return NULL;
    }
  client = GNUNET_SERVER_connect_socket (plugin->server, conn);
  GNUNET_assert (client != NULL);
  session = create_session (plugin, target, client, addr, addrlen);
  /* kill welcome */
  GNUNET_free (session->pending_messages);
  session->pending_messages = NULL;
  session->connect_alen = addrlen;
  session->connect_addr = GNUNET_malloc (addrlen);
  session->expecting_welcome = GNUNET_SYSERR;  
  memcpy (session->connect_addr, addr, addrlen);
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp",
                   "Creating new session %p with `%s' for `%4s' based on `%s' request.\n",
                   session, 
		   GNUNET_a2s (addr, addrlen),
		   GNUNET_i2s (&session->target),
		   "VALIDATE");
#endif
  return session;
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
tcp_plugin_validate (void *cls,
		     const struct GNUNET_PeerIdentity *target,
		     uint32_t challenge,
		     struct GNUNET_TIME_Relative timeout,
		     const void *addr, size_t addrlen)
{
  struct Plugin *plugin = cls;
  struct Session *session;
  struct PendingMessage *pm;
  struct ValidationChallengeMessage *vcm;

  session = connect_and_create_validation_session (plugin, target, addr, addrlen);
  if (session == NULL)
    {
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp", "Failed to create fresh session.\n");
#endif
      return GNUNET_SYSERR;
    }
  pm = GNUNET_malloc (sizeof (struct PendingMessage) +
		      sizeof (struct ValidationChallengeMessage) + addrlen);
  pm->msg = (struct GNUNET_MessageHeader *) &pm[1];
  pm->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  pm->is_welcome = GNUNET_YES;
  vcm = (struct ValidationChallengeMessage*) &pm[1];
  vcm->header.size =
    htons (sizeof (struct ValidationChallengeMessage) + addrlen);
  vcm->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_PING);
  vcm->challenge = htonl(challenge);
  vcm->target = *target;
  memcpy (&vcm[1], addr, addrlen);
  GNUNET_assert (session->pending_messages == NULL);
  session->pending_messages = pm;
  process_pending_messages (session);
  return GNUNET_OK;
}


/**
 * Functions with this signature are called whenever we need
 * to close a session due to a disconnect or failure to
 * establish a connection.
 *
 * @param session session to close down
 */
static void
disconnect_session (struct Session *session)
{
  struct Session *prev;
  struct Session *pos;
  struct PendingMessage *pm;

#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp",
                   "Disconnecting from `%4s' at %s (session %p).\n", 
		   GNUNET_i2s(&session->target),
		   (session->connect_addr != NULL) ? 
		   GNUNET_a2s(session->connect_addr,
			      session->connect_alen) : "*",
		   session);
#endif
  /* remove from session list */
  prev = NULL;
  pos = session->plugin->sessions;
  while (pos != session)
    {
      prev = pos;
      pos = pos->next;
    }
  if (prev == NULL)
    session->plugin->sessions = session->next;
  else
    prev->next = session->next;
  /* clean up state */
  if (session->transmit_handle != NULL)
    {
      GNUNET_CONNECTION_notify_transmit_ready_cancel (session->transmit_handle);
      session->transmit_handle = NULL;
    }
  while (NULL != (pm = session->pending_messages))
    {
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "tcp",
		       pm->transmit_cont != NULL 
		       ? "Could not deliver message of type %u to `%4s'.\n" 
		       : "Could not deliver message of type %u to `%4s', notifying.\n",
		       ntohs(pm->msg->type),		       
		       GNUNET_i2s(&session->target));
#endif
      session->pending_messages = pm->next;
      if (NULL != pm->transmit_cont)
        pm->transmit_cont (pm->transmit_cont_cls,
                           session->service_context,
                           &session->target, GNUNET_SYSERR);
      GNUNET_free (pm);
    }
  if (GNUNET_NO == session->expecting_welcome)
    {
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "tcp",
		       "Notifying transport service about loss of data connection with `%4s'.\n",
		       GNUNET_i2s(&session->target));
#endif
      /* Data session that actually went past the 
	 initial handshake; transport service may
	 know about this one, so we need to 
	 notify transport service about disconnect */
      session->plugin->env->receive (session->plugin->env->cls,
				     session,
				     session->service_context,
				     GNUNET_TIME_UNIT_ZERO,
				     &session->target, NULL);
    }
  if (session->client != NULL)
    {
      GNUNET_SERVER_client_drop (session->client);
      session->client = NULL;
    }
  GNUNET_free_non_null (session->connect_addr);
  GNUNET_free (session);
}


/**
 * Iterator callback to go over all addresses.  If we get
 * a TCP address, increment the counter
 *
 * @param cls closure, points to the counter
 * @param tname name of the transport
 * @param expiration expiration time
 * @param addr the address
 * @param addrlen length of the address
 * @return GNUNET_OK to keep the address,
 *         GNUNET_NO to delete it from the HELLO
 *         GNUNET_SYSERR to stop iterating (but keep current address)
 */
static int
count_tcp_addresses (void *cls,
                     const char *tname,
                     struct GNUNET_TIME_Absolute expiration,
                     const void *addr, size_t addrlen)
{
  unsigned int *counter = cls;

  if (0 != strcmp (tname, "tcp"))
    return GNUNET_OK;           /* not one of ours */
  (*counter)++;
  return GNUNET_OK;             /* failed to connect */
}


struct ConnectContext
{
  struct Plugin *plugin;

  struct GNUNET_CONNECTION_Handle *sa;

  struct PendingMessage *welcome;

  unsigned int pos;
};


/**
 * Iterator callback to go over all addresses.  If we get
 * the "pos" TCP address, try to connect to it.
 *
 * @param cls closure
 * @param tname name of the transport
 * @param expiration expiration time
 * @param addrlen length of the address
 * @param addr the address
 * @return GNUNET_OK to keep the address,
 *         GNUNET_NO to delete it from the HELLO
 *         GNUNET_SYSERR to stop iterating (but keep current address)
 */
static int
try_connect_to_address (void *cls,
                        const char *tname,
                        struct GNUNET_TIME_Absolute expiration,
                        const void *addr, size_t addrlen)
{
  struct ConnectContext *cc = cls;
  int af;

  if (0 != strcmp (tname, "tcp"))
    return GNUNET_OK;           /* not one of ours */
  if (sizeof (struct sockaddr_in) == addrlen)
    af = AF_INET;
  else if (sizeof (struct sockaddr_in6) == addrlen)
    af = AF_INET6;
  else
    {
      /* not a valid address */
      GNUNET_break (0);
      return GNUNET_NO;
    }
  if (0 == cc->pos--)
    {
      cc->welcome = create_welcome (addrlen, addr, cc->plugin);
      cc->sa =
        GNUNET_CONNECTION_create_from_sockaddr (cc->plugin->env->sched,
                                                    af, addr, addrlen,
                                                    GNUNET_SERVER_MAX_MESSAGE_SIZE);
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp", 
		       "Connecting using address %s.\n",
		       GNUNET_a2s(addr, addrlen));
#endif
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;             /* failed to connect */
}


/**
 * Type of an iterator over the hosts.  Note that each
 * host will be called with each available protocol.
 *
 * @param cls closure
 * @param peer id of the peer, NULL for last call
 * @param hello hello message for the peer (can be NULL)
 * @param trust amount of trust we have in the peer
 */
static void
session_try_connect (void *cls,
                     const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_HELLO_Message *hello, uint32_t trust)
{
  struct Session *session = cls;
  unsigned int count;
  struct ConnectContext cctx;
  struct PendingMessage *pm;

  if (peer == NULL)
    {
      /* last call, destroy session if we are still not
         connected */
      if (session->client != NULL)
        {
#if DEBUG_TCP
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                           "tcp",
                           "Now connected to `%4s', now processing messages.\n",
			   GNUNET_i2s(&session->target));
#endif
          process_pending_messages (session);
        }
      else
        {
#if DEBUG_TCP
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                           "tcp",
                           "Failed to connect to `%4s' (no working `%s'), closing session.\n",
			   GNUNET_i2s(&session->target),
			   "HELLO");
#endif
          disconnect_session (session);
        }
      return;
    }
  if ((hello == NULL) || (session->client != NULL))
    {
      GNUNET_break (0);         /* should this ever happen!? */
      return;
    }
  count = 0;
  GNUNET_HELLO_iterate_addresses (hello,
                                  GNUNET_NO, &count_tcp_addresses, &count);
  if (count == 0)
    {
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp",
                       "Asked to connect to `%4s', but have no addresses to try.\n",
		       GNUNET_i2s(&session->target));
#endif
      return;
    }
  cctx.plugin = session->plugin;
  cctx.sa = NULL;
  cctx.welcome = NULL;
  cctx.pos = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, count);
  GNUNET_HELLO_iterate_addresses (hello,
                                  GNUNET_NO, &try_connect_to_address, &cctx);
  if (cctx.sa == NULL)
    {
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp",
                       "Asked to connect, but all addresses failed.\n");
#endif
      GNUNET_free_non_null (cctx.welcome);
      return;
    }
  session->client = GNUNET_SERVER_connect_socket (session->plugin->server,
                                                  cctx.sa);
#if DEBUG_TCP
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connected to `%4s' for session %p\n",
	      GNUNET_i2s(&session->target),
	      session->client);
#endif
  if (session->client == NULL)
    {
      GNUNET_break (0);         /* how could this happen? */
      GNUNET_free_non_null (cctx.welcome);
      return;
    }
  pm = cctx.welcome;
  /* prepend (!) */
  pm->next = session->pending_messages;
  session->pending_messages = pm;
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp",
                   "Connected to `%4s', now sending `%s' message.\n",
		   GNUNET_i2s(&session->target),
                   "WELCOME");
#endif
}


/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.
 *
 * @param cls closure
 * @param plugin_context value we were asked to pass to this plugin
 *        to respond to the given peer (use is optional,
 *        but may speed up processing), can be NULL
 * @param service_context value passed to the transport-service
 *        to identify the neighbour
 * @param target who should receive this message
 * @param priority how important is the message
 * @param msg the message to transmit
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 * @return plugin_context that should be used next time for
 *         sending messages to the specified peer
 */
static void *
tcp_plugin_send (void *cls,
                 void *plugin_context,
                 struct ReadyList *service_context,
                 const struct GNUNET_PeerIdentity *target,   
		 unsigned int priority,
                 const struct GNUNET_MessageHeader *msg,
                 struct GNUNET_TIME_Relative timeout,
                 GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct Session *session = plugin_context;
  struct PendingMessage *pm;
  struct PendingMessage *pme;

  if (session == NULL)
    session = find_session_by_target (plugin, target);  
  pm = GNUNET_malloc (sizeof (struct PendingMessage) + ntohs (msg->size));
  pm->msg = (struct GNUNET_MessageHeader *) &pm[1];
  memcpy (pm->msg, msg, ntohs (msg->size));
  pm->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  pm->transmit_cont = cont;
  pm->transmit_cont_cls = cont_cls;
  if (session == NULL)
    {
      session = GNUNET_malloc (sizeof (struct Session));
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp",
                       "Asked to transmit, creating fresh session %p.\n",
                       session);
#endif
      session->next = plugin->sessions;
      plugin->sessions = session;
      session->plugin = plugin;
      session->target = *target;
      session->last_quota_update = GNUNET_TIME_absolute_get ();
      session->quota_in = plugin->env->default_quota_in;
      session->expecting_welcome = GNUNET_YES;
      session->pending_messages = pm;
      session->service_context = service_context;
      GNUNET_PEERINFO_for_all (plugin->env->cfg,
                               plugin->env->sched,
                               target,
                               0, timeout, &session_try_connect, session);
      return session;
    }
  GNUNET_assert (session != NULL);
  GNUNET_assert (session->client != NULL);
  session->service_context = service_context;
  /* append pm to pending_messages list */
  pme = session->pending_messages;
  if (pme == NULL)
    {
      session->pending_messages = pm;
    }
  else
    {
      while (NULL != pme->next)
        pme = pme->next;
      pme->next = pm;
    }
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp", "Asked to transmit, added message to list.\n");
#endif
  process_pending_messages (session);
  return session;
}



/**
 * Function that can be called to force a disconnect from the
 * specified neighbour.  This should also cancel all previously
 * scheduled transmissions.  Obviously the transmission may have been
 * partially completed already, which is OK.  The plugin is supposed
 * to close the connection (if applicable) and no longer call the
 * transmit continuation(s).
 *
 * Finally, plugin MUST NOT call the services's receive function to
 * notify the service that the connection to the specified target was
 * closed after a getting this call.
 *
 * @param cls closure
 * @param plugin_context value we were asked to pass to this plugin
 *        to respond to the given peer (use is optional,
 *        but may speed up processing), can be NULL (if
 *        NULL was returned from the transmit function); note
 *        that use of NULL is dangerous since then this call may
 *        cancel any session with the target peer (including
 *        HELLO validation sessions), which is likely not what
 *        is intended.
 * @param service_context must correspond to the service context
 *        of the corresponding Transmit call; the plugin should
 *        not cancel a send call made with a different service
 *        context pointer!  Never NULL.
 * @param target peer for which the last transmission is
 *        to be cancelled
 */
static void
tcp_plugin_cancel (void *cls,
                   void *plugin_context,
                   struct ReadyList *service_context,
                   const struct GNUNET_PeerIdentity *target)
{
  struct Plugin *plugin = cls;
  struct Session *session = plugin_context;
  struct PendingMessage *pm;
  
  if (session == NULL)
    {
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
		       "tcp",
		       "Asked to cancel with `%4s' without specification of specifics; will try to find an applicable session\n",
		       GNUNET_i2s(target));
#endif
      session = find_session_by_target (plugin, target);
    }
  if (session == NULL)
    {
      GNUNET_break (0);
      return;
    }
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "tcp",
		   "Asked to cancel session %p with `%4s'\n",
		   plugin_context,
		   GNUNET_i2s(target));
#endif
  pm = session->pending_messages;
  while (pm != NULL)
    {
      pm->transmit_cont = NULL;
      pm->transmit_cont_cls = NULL;
      pm = pm->next;
    }
  session->service_context = NULL;
  if (session->client != NULL)
    {
      GNUNET_SERVER_client_drop (session->client);
      session->client = NULL;
    }
  /* rest of the clean-up of the session will be done as part of
     disconnect_notify which should be triggered any time now 
     (or which may be triggering this call in the first place) */
}


struct PrettyPrinterContext
{
  GNUNET_TRANSPORT_AddressStringCallback asc;
  void *asc_cls;
  uint16_t port;
};


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
 * @param name name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 * @param numeric should (IP) addresses be displayed in numeric form?
 * @param timeout after how long should we give up?
 * @param asc function to call on each string
 * @param asc_cls closure for asc
 */
static void
tcp_plugin_address_pretty_printer (void *cls,
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
 * Update the last-received and bandwidth quota values
 * for this session.
 *
 * @param session session to update
 * @param force set to GNUNET_YES if we should update even
 *        though the minimum refresh time has not yet expired
 */
static void
update_quota (struct Session *session, int force)
{
  struct GNUNET_TIME_Absolute now;
  unsigned long long delta;
  unsigned long long total_allowed;
  unsigned long long total_remaining;

  now = GNUNET_TIME_absolute_get ();
  delta = now.value - session->last_quota_update.value;
  if ((delta < MIN_QUOTA_REFRESH_TIME) && (!force))
    return;                     /* too early, not enough data */

  total_allowed = session->quota_in * delta;
  if (total_allowed > session->last_received)
    {
      /* got less than acceptable */
      total_remaining = total_allowed - session->last_received;
      session->last_received = 0;
      delta = total_remaining / session->quota_in;      /* bonus seconds */
      if (delta > MAX_BANDWIDTH_CARRY)
        delta = MAX_BANDWIDTH_CARRY;    /* limit amount of carry-over */
    }
  else
    {
      /* got more than acceptable */
      total_remaining = 0;
      session->last_received -= total_allowed;
      delta = 0;
    }
  session->last_quota_update.value = now.value - delta;
}


/**
 * Set a quota for receiving data from the given peer; this is a
 * per-transport limit.  The transport should limit its read/select
 * calls to stay below the quota (in terms of incoming data).
 *
 * @param cls closure
 * @param peer the peer for whom the quota is given
 * @param quota_in quota for receiving/sending data in bytes per ms
 */
static void
tcp_plugin_set_receive_quota (void *cls,
                              const struct GNUNET_PeerIdentity *target,
                              uint32_t quota_in)
{
  struct Plugin *plugin = cls;
  struct Session *session;

  session = find_session_by_target (plugin, target);
  if (session == NULL)
    return; /* peer must have disconnected, ignore */
  if (session->quota_in != quota_in)
    {
      update_quota (session, GNUNET_YES);
      if (session->quota_in > quota_in)
        session->last_quota_update = GNUNET_TIME_absolute_get ();
      session->quota_in = quota_in;
    }
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
tcp_plugin_address_suggested (void *cls, const void *addr, size_t addrlen)
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
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp",
                   "Informing transport service about my address `%s'.\n",
                   GNUNET_a2s(addr, addrlen));
#endif
  plugin->env->notify_address (plugin->env->cls,
                               "tcp",
                               buf, addrlen, LEARNED_ADDRESS_EXPIRATION);
  return GNUNET_OK;
}


/**
 * Send a validation challenge response.
 */
static size_t
send_vcr (void *cls,
	  size_t size,
	  void *buf)
{
  struct ValidationChallengeResponse *vcr = cls;
  uint16_t msize;

  if (NULL == buf)
    {
      GNUNET_free (vcr);
      return 0;
    }
  msize = ntohs(vcr->header.size);
  GNUNET_assert (size >= msize);
  memcpy (buf, vcr, msize);
  GNUNET_free (vcr);
  return msize;
}


/**
 * We've received a PING from this peer via TCP.
 * Send back our PONG.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_tcp_ping (void *cls,
		 struct GNUNET_SERVER_Client *client,
		 const struct GNUNET_MessageHeader *message)
{
  struct Plugin *plugin = cls;
  const struct ValidationChallengeMessage *vcm;
  struct ValidationChallengeResponse *vcr;
  uint16_t msize;
  size_t addrlen;
  void *addr;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Processing PING\n");
#endif
  msize = ntohs (message->size);
  if (msize < sizeof (struct ValidationChallengeMessage))
    {
      GNUNET_break_op (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);  
      return;
    }
  vcm = (const struct ValidationChallengeMessage *) message;
  if (0 != memcmp (&vcm->target,
                   plugin->env->my_identity, sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Received `%s' message not destined for me!\n"), "PING");
      /* TODO: call statistics */
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);  
      return;
    }
  msize -= sizeof (struct ValidationChallengeMessage);
  if (GNUNET_OK !=
      tcp_plugin_address_suggested (plugin, &vcm[1], msize))
    {
      GNUNET_break_op (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);  
      return;
    }
  if (GNUNET_OK !=
      GNUNET_SERVER_client_get_address (client,
					&addr,
					&addrlen))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);  
      return;
    }
  vcr = GNUNET_malloc (sizeof (struct ValidationChallengeResponse) + addrlen);
  vcr->header.size = htons (sizeof (struct ValidationChallengeResponse) + addrlen);
  vcr->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_PONG);
  vcr->purpose.size =
    htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
	   sizeof (uint32_t) +
	   sizeof ( struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) +
	   addrlen);
  vcr->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_TCP_PING);
  vcr->challenge = vcm->challenge;
  vcr->signer = *plugin->env->my_public_key;
  memcpy (&vcr[1],
	  addr,
	  addrlen);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_sign (plugin->env->my_private_key,
                                         &vcr->purpose,
					 &vcr->signature));
#if EXTRA_CHECKS
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_verify
                 (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_TCP_PING,
		  &vcr->purpose,
                  &vcr->signature,
		  plugin->env->my_public_key));
#endif
  GNUNET_free (addr);
  if (NULL ==
      GNUNET_SERVER_notify_transmit_ready (client,
					   sizeof (struct ValidationChallengeResponse) + addrlen,
					   GNUNET_TIME_UNIT_SECONDS,
					   &send_vcr,
					   vcr))
    {
      GNUNET_break (0);
      GNUNET_free (vcr);
    }
  /* after a PING, we always close the connection */
  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);  
}


/**
 * Handle PING-message.  If the plugin that gave us the message is
 * able to queue the PONG immediately, we only queue one PONG.
 * Otherwise we send at most TWO PONG messages, one via an unconfirmed
 * transport and one via a confirmed transport.  Both addresses are
 * selected randomly among those available.
 *
 * @param plugin plugin that gave us the message
 * @param sender claimed sender of the PING
 * @param plugin_context context that might be used to send response
 * @param message the actual message
 */
/**
 * We've received a PING from this peer via TCP.
 * Send back our PONG.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_tcp_pong (void *cls,
		 struct GNUNET_SERVER_Client *client,
		 const struct GNUNET_MessageHeader *message)
{
  struct Plugin *plugin = cls;
  const struct ValidationChallengeResponse *vcr;
  struct GNUNET_PeerIdentity peer;
  char *sender_addr;
  size_t addrlen;
  const struct sockaddr *addr;
  struct sockaddr_in v4;
  struct sockaddr_in6 v6;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Processing PONG\n");
#endif
  if (ntohs(message->size) < sizeof(struct ValidationChallengeResponse))
    {
      GNUNET_break_op (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);  
      return;
    }
  addrlen = ntohs(message->size) - sizeof(struct ValidationChallengeResponse);
  vcr = (const struct ValidationChallengeResponse *) message;
  if ( (ntohl(vcr->purpose.size) !=
	sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
	sizeof (uint32_t) +
	sizeof ( struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) +
	addrlen))
    {
      GNUNET_break_op (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);  
      return;
    }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_rsa_verify
      (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_TCP_PING, 
       &vcr->purpose,
       &vcr->signature, 
       &vcr->signer))
    {
      GNUNET_break_op (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);  
      return;
    }
  GNUNET_CRYPTO_hash (&vcr->signer,
		      sizeof(  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
		      &peer.hashPubKey);
  addr = (const struct sockaddr*) &vcr[1];
  if (addrlen == sizeof (struct sockaddr_in))
    {
      memcpy (&v4, addr, sizeof (struct sockaddr_in));
      v4.sin_port = htons(check_port (plugin, ntohs (v4.sin_port)));
      sender_addr = GNUNET_strdup (GNUNET_a2s((const struct sockaddr*) &v4,
					      addrlen));
    }
  else if (addrlen == sizeof (struct sockaddr_in6))
    {
      memcpy (&v6, addr, sizeof (struct sockaddr_in6));
      v6.sin6_port = htons(check_port (plugin, ntohs (v6.sin6_port)));
      sender_addr = GNUNET_strdup (GNUNET_a2s((const struct sockaddr*) &v6,
					      addrlen));
    }
  else
    {
      GNUNET_break_op (0); 
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);  
      return;
    }
  plugin->env->notify_validation (plugin->env->cls,
				  "tcp",
				  &peer,
				  ntohl(vcr->challenge),
				  sender_addr);
  GNUNET_free (sender_addr);
  /* after a PONG, we always close the connection */
  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);  
}


/**
 * We've received a welcome from this peer via TCP.
 * Possibly create a fresh client record and send back
 * our welcome.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_tcp_welcome (void *cls,
                    struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  struct Plugin *plugin = cls;
  struct Session *session_c;
  const struct WelcomeMessage *wm;
  uint16_t msize;
  uint32_t addrlen;
  size_t alen;
  void *vaddr;
  const struct sockaddr *addr;

  msize = ntohs (message->size);
  if (msize < sizeof (struct WelcomeMessage))
    {
      GNUNET_break_op (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  wm = (const struct WelcomeMessage *) message;
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp",
                   "Received `%s' message from `%4s/%p'.\n", "WELCOME",
		   GNUNET_i2s(&wm->clientIdentity),
		   client);
#endif
  session_c = find_session_by_client (plugin, client);
  if (session_c == NULL)
    {
      vaddr = NULL;
      GNUNET_SERVER_client_get_address (client, &vaddr, &alen);
      GNUNET_SERVER_client_keep (client);
      session_c = create_session (plugin,
                                  &wm->clientIdentity, client, vaddr, alen);
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp",
                       "Creating new session %p for incoming `%s' message.\n",
                       session_c, "WELCOME");
#endif
      GNUNET_free_non_null (vaddr);
      process_pending_messages (session_c);
    }
  if (session_c->expecting_welcome != GNUNET_YES)
    {
      GNUNET_break_op (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  session_c->expecting_welcome = GNUNET_NO;
  if (0 < (addrlen = msize - sizeof (struct WelcomeMessage)))
    {
      addr = (const struct sockaddr *) &wm[1];
      tcp_plugin_address_suggested (plugin, addr, addrlen);
    }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Calculate how long we should delay reading from the TCP socket to
 * ensure that we stay within our bandwidth limits (push back).
 *
 * @param session for which client should this be calculated
 */
static struct GNUNET_TIME_Relative
calculate_throttle_delay (struct Session *session)
{
  struct GNUNET_TIME_Relative ret;
  struct GNUNET_TIME_Absolute now;
  uint64_t del;
  uint64_t avail;
  uint64_t excess;

  now = GNUNET_TIME_absolute_get ();
  del = now.value - session->last_quota_update.value;
  if (del > MAX_BANDWIDTH_CARRY)
    {
      update_quota (session, GNUNET_YES);
      del = now.value - session->last_quota_update.value;
      GNUNET_assert (del <= MAX_BANDWIDTH_CARRY);
    }
  if (session->quota_in == 0)
    session->quota_in = 1;      /* avoid divison by zero */
  avail = del * session->quota_in;
  if (avail > session->last_received)
    return GNUNET_TIME_UNIT_ZERO;       /* can receive right now */
  excess = session->last_received - avail;
  ret.value = excess / session->quota_in;
  return ret;
}


/**
 * Task to signal the server that we can continue
 * receiving from the TCP client now.
 */
static void
delayed_done (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *session = cls;
  GNUNET_SERVER_receive_done (session->client, GNUNET_OK);
}


/**
 * We've received data for this peer via TCP.  Unbox,
 * compute latency and forward.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_tcp_data (void *cls,
                 struct GNUNET_SERVER_Client *client,
                 const struct GNUNET_MessageHeader *message)
{
  struct Plugin *plugin = cls;
  struct Session *session;
  const struct DataMessage *dm;
  uint16_t msize;
  const struct GNUNET_MessageHeader *msg;
  struct GNUNET_TIME_Relative latency;
  struct GNUNET_TIME_Absolute ttime;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Relative delay;
  uint64_t ack_in;

  msize = ntohs (message->size);
  if ((msize <
       sizeof (struct DataMessage) + sizeof (struct GNUNET_MessageHeader)))
    {
      GNUNET_break_op (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  session = find_session_by_client (plugin, client);
  if ((NULL == session) || (GNUNET_NO != session->expecting_welcome))
    {
      GNUNET_break_op (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp", "Receiving %u bytes from `%4s'.\n",
		   msize,
		   GNUNET_i2s(&session->target));
#endif
  dm = (const struct DataMessage *) message;
  session->max_in_msg_counter = GNUNET_MAX (session->max_in_msg_counter,
                                            GNUNET_ntohll (dm->ack_out));
  msg = (const struct GNUNET_MessageHeader *) &dm[1];
  if (msize != sizeof (struct DataMessage) + ntohs (msg->size))
    {
      GNUNET_break_op (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  /* estimate latency */
  ack_in = GNUNET_ntohll (dm->ack_in);
  if ((ack_in <= session->out_msg_counter) &&
      (session->out_msg_counter - ack_in < ACK_LOG_SIZE))
    {
      delay = GNUNET_TIME_relative_ntoh (dm->delay);
      ttime = session->gen_time[ack_in % ACK_LOG_SIZE];
      now = GNUNET_TIME_absolute_get ();
      if (delay.value > now.value - ttime.value)
        delay.value = 0;        /* not plausible */
      /* update (round-trip) latency using ageing; we
         use 7:1 so that we can reasonably quickly react
         to changes, but not so fast that latency is largely
         jitter... */
      session->latency_estimate
        = ((7 * session->latency_estimate) +
           (now.value - ttime.value - delay.value)) / 8;
    }
  latency.value = (uint64_t) session->latency_estimate;
  /* deliver on */
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp",
                   "Forwarding data of type %u to transport service.\n",
                   ntohs (msg->type));
#endif
  session->service_context
    = plugin->env->receive (plugin->env->cls,
                            session,
                            session->service_context,
                            latency, &session->target, msg);
  /* update bandwidth used */
  session->last_received += msize;
  update_quota (session, GNUNET_NO);

  delay = calculate_throttle_delay (session);
  if (delay.value == 0)
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
  else
    GNUNET_SCHEDULER_add_delayed (session->plugin->env->sched,
                                  GNUNET_NO,
                                  GNUNET_SCHEDULER_PRIORITY_HIGH,
                                  GNUNET_SCHEDULER_NO_TASK,
                                  delay, &delayed_done, session);
}


/**
 * Handlers for the various TCP messages.
 */
static struct GNUNET_SERVER_MessageHandler my_handlers[] = {
  {&handle_tcp_ping, NULL, GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_PING, 0},
  {&handle_tcp_pong, NULL, GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_PONG, 0},
  {&handle_tcp_welcome, NULL, GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME, 0},
  {&handle_tcp_data, NULL, GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_DATA, 0},
  {NULL, NULL, 0, 0}
};


static void
create_tcp_handlers (struct Plugin *plugin)
{
  unsigned int i;
  plugin->handlers = GNUNET_malloc (sizeof (my_handlers));
  memcpy (plugin->handlers, my_handlers, sizeof (my_handlers));
  for (i = 0;
       i <
       sizeof (my_handlers) / sizeof (struct GNUNET_SERVER_MessageHandler);
       i++)
    plugin->handlers[i].callback_cls = plugin;
  GNUNET_SERVER_add_handlers (plugin->server, plugin->handlers);
}


/**
 * Functions with this signature are called whenever a peer
 * is disconnected on the network level.
 *
 * @param cls closure
 * @param client identification of the client
 */
static void
disconnect_notify (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct Plugin *plugin = cls;
  struct Session *session;

  session = find_session_by_client (plugin, client);
  if (session == NULL)
    return;                     /* unknown, nothing to do */
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp",
                   "Destroying session of `%4s' with %s (%p) due to network-level disconnect.\n",
		   GNUNET_i2s(&session->target),
		   (session->connect_addr != NULL) ? 
		   GNUNET_a2s(session->connect_addr,
			      session->connect_alen) : "*",
                   client);
#endif
  disconnect_session (session);
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
                   "tcp", _("Found address `%s' (%s)\n"), 
		   GNUNET_a2s(addr, addrlen), name);
  plugin->env->notify_address (plugin->env->cls,
                               "tcp",
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
    return;
  plugin->env->notify_address (plugin->env->cls,
                               "tcp",
                               addr, addrlen, GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_transport_tcp_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  struct GNUNET_SERVICE_Context *service;
  unsigned long long aport;
  unsigned long long bport;

  service = GNUNET_SERVICE_start ("transport-tcp", env->sched, env->cfg);
  if (service == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
                       "tcp",
                       _
                       ("Failed to start service for `%s' transport plugin.\n"),
                       "tcp");
      return NULL;
    }
  aport = 0;
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (env->cfg,
                                              "transport-tcp",
                                              "PORT",
                                              &bport)) ||
      (bport > 65535) ||
      ((GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_number (env->cfg,
                                               "transport-tcp",
                                               "ADVERTISED-PORT",
                                               &aport)) && (aport > 65535)))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "tcp",
                       _
                       ("Require valid port number for service `%s' in configuration!\n"),
                       "transport-tcp");
      GNUNET_SERVICE_stop (service);
      return NULL;
    }
  if (aport == 0)
    aport = bport;
  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->open_port = bport;
  plugin->adv_port = aport;
  plugin->env = env;
  plugin->lsock = NULL;
  plugin->statistics = NULL;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->validate = &tcp_plugin_validate;
  api->send = &tcp_plugin_send;
  api->cancel = &tcp_plugin_cancel;
  api->address_pretty_printer = &tcp_plugin_address_pretty_printer;
  api->set_receive_quota = &tcp_plugin_set_receive_quota;
  api->address_suggested = &tcp_plugin_address_suggested;
  api->cost_estimate = 42;      /* TODO: ATS */
  plugin->service = service;
  plugin->server = GNUNET_SERVICE_get_server (service);
  create_tcp_handlers (plugin);
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                   "tcp", _("TCP transport listening on port %u\n"), bport);
  if (aport != bport)
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                     "tcp",
                     _
                     ("TCP transport advertises itself as being on port %u\n"),
                     aport);
  GNUNET_SERVER_disconnect_notify (plugin->server, &disconnect_notify,
                                   plugin);
  GNUNET_OS_network_interfaces_list (&process_interfaces, plugin);
  GNUNET_RESOLVER_hostname_resolve (env->sched,
                                    env->cfg,
                                    AF_UNSPEC,
                                    HOSTNAME_RESOLVE_TIMEOUT,
                                    &process_hostname_ips, plugin);
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_transport_tcp_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  struct Session *session;

  while (NULL != (session = plugin->sessions))
    disconnect_session (session);    
  GNUNET_SERVICE_stop (plugin->service);
  GNUNET_free (plugin->handlers);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_tcp.c */
