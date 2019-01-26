/*
     This file is part of GNUnet
     Copyright (C) 2010-2014, 2018 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/

/**
 * @file transport/gnunet-communicator-tcp.c
 * @brief Transport plugin using TCP.
 * @author Christian Grothoff
 *
 * TODO:
 * - lots of basic adaptations (see FIXMEs)
 * - better message queue management
 * - actually encrypt, hmac, decrypt
 * - actually transmit
 * - 
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_constants.h"
#include "gnunet_nt_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_communication_service.h"

/**
 * How many messages do we keep at most in the queue to the
 * transport service before we start to drop (default,
 * can be changed via the configuration file).
 * Should be _below_ the level of the communicator API, as
 * otherwise we may read messages just to have them dropped
 * by the communicator API.
 */
#define DEFAULT_MAX_QUEUE_LENGTH 8

/**
 * Address prefix used by the communicator.
 */
#define COMMUNICATOR_ADDRESS_PREFIX "tcp"

/**
 * Configuration section used by the communicator.
 */
#define COMMUNICATOR_CONFIG_SECTION "communicator-tcp"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * TCP initial bytes on the wire (in either direction), used to 
 * establish a shared secret.
 */
struct TCPHandshake
{
  /**
   * First bytes: ephemeral key for KX.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey ephemeral;

};


/**
 * Signature we use to verify that the ephemeral key was really chosen by
 * the specified sender.
 */
struct TcpHandshakeSignature
{
  /**
   * Purpose must be #GNUNET_SIGNATURE_COMMUNICATOR_TCP_HANDSHAKE
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Identity of the inititor of the TCP connection (TCP client).
   */ 
  struct GNUNET_PeerIdentity sender;

  /**
   * Presumed identity of the target of the TCP connection (TCP server)
   */ 
  struct GNUNET_PeerIdentity receiver;

  /**
   * Ephemeral key used by the @e sender.
   */ 
  struct GNUNET_CRYPTO_EcdhePublicKey ephemeral;

  /**
   * Monotonic time of @e sender, to possibly help detect replay attacks
   * (if receiver persists times by sender).
   */ 
  struct GNUNET_TIME_AbsoluteNBO monotonic_time;
};


/**
 * Encrypted continuation of TCP initial handshake.
 */
struct TCPConfirmation
{
  /**
   * Sender's identity
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Sender's signature of type #GNUNET_SIGNATURE_COMMUNICATOR_TCP_HANDSHAKE
   */
  struct GNUNET_CRYPTO_EddsaSignature sender_sig;

  /**
   * Monotonic time of @e sender, to possibly help detect replay attacks
   * (if receiver persists times by sender).
   */ 
  struct GNUNET_TIME_AbsoluteNBO monotonic_time;

};


/**
 * TCP message box.  Always sent encrypted!
 */ 
struct TCPBox
{
  
  /**
   * Type is #GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_BOX.
   */ 
  struct GNUNET_MessageHeader header;

  /**
   * HMAC for the following encrypted message.  Yes, we MUST use
   * mac-then-encrypt here, as we want to hide the message sizes on
   * the wire (zero plaintext design!).  Using CTR mode padding oracle
   * attacks do not apply.  Besides, due to the use of ephemeral keys
   * (hopefully with effective replay protection from monotonic time!)
   * the attacker is limited in using the oracle.
   */ 
  struct GNUNET_ShortHashCode hmac;

  /* followed by as may bytes of payload as indicated in @e header */
  
};


/**
 * TCP rekey message box.  Always sent encrypted!  Data after
 * this message will use the new key.
 */ 
struct TCPRekey
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_REKEY.
   */ 
  struct GNUNET_MessageHeader header;

  /**
   * HMAC for the following encrypted message.  Yes, we MUST use
   * mac-then-encrypt here, as we want to hide the message sizes on
   * the wire (zero plaintext design!).  Using CTR mode padding oracle
   * attacks do not apply.  Besides, due to the use of ephemeral keys
   * (hopefully with effective replay protection from monotonic time!)
   * the attacker is limited in using the oracle.
   */ 
  struct GNUNET_ShortHashCode hmac;

  /**
   * New ephemeral key.
   */ 
  struct GNUNET_CRYPTO_EcdhePublicKey ephemeral;
  
  /**
   * Sender's signature of type #GNUNET_SIGNATURE_COMMUNICATOR_TCP_HANDSHAKE
   */
  struct GNUNET_CRYPTO_EddsaSignature sender_sig;

  /**
   * Monotonic time of @e sender, to possibly help detect replay attacks
   * (if receiver persists times by sender).
   */ 
  struct GNUNET_TIME_AbsoluteNBO monotonic_time;

};


/**
 * TCP finish. Sender asks for the connection to be closed.
 * Needed/useful in case we drop RST/FIN packets on the GNUnet
 * port due to the possibility of malicious RST/FIN injection.
 */ 
struct TCPFinish
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_FINISH.
   */ 
  struct GNUNET_MessageHeader header;

  /**
   * HMAC for the following encrypted message.  Yes, we MUST use
   * mac-then-encrypt here, as we want to hide the message sizes on
   * the wire (zero plaintext design!).  Using CTR mode padding oracle
   * attacks do not apply.  Besides, due to the use of ephemeral keys
   * (hopefully with effective replay protection from monotonic time!)
   * the attacker is limited in using the oracle.
   */ 
  struct GNUNET_ShortHashCode hmac;

};


GNUNET_NETWORK_STRUCT_END


/**
 * Handle for a queue.
 */
struct Queue
{

  /**
   * To whom are we talking to.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * socket that we transmit all data with on this queue
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * cipher for decryption of incoming data.
   */ 
  gcry_cipher_hd_t in_cipher;

  /**
   * cipher for encryption of outgoing data.
   */
  gcry_cipher_hd_t out_cipher;

  /**
   * Shared secret for HMAC verification on incoming data.
   */ 
  struct GNUNET_HashCode in_hmac;

  /**
   * Shared secret for HMAC generation on outgoing data.
   */ 
  struct GNUNET_HashCode out_hmac;

  /**
   * ID of read task for this connection.
   */
  struct GNUNET_SCHEDULER_Task *read_task;

  /**
   * ID of write task for this connection.
   */
  struct GNUNET_SCHEDULER_Task *write_task;

  /**
   * Address of the other peer.
   */
  struct sockaddr *address;
  
  /**
   * How many more bytes may we sent with the current @e out_cipher
   * before we should rekey?
   */
  uint64_t rekey_left_bytes;

  /**
   * Until what time may we sent with the current @e out_cipher
   * before we should rekey?
   */
  struct GNUNET_TIME_Absolute rekey_time;
  
  /**
   * Length of the address.
   */
  socklen_t address_len;

  /**
   * Message currently scheduled for transmission, non-NULL if and only
   * if this queue is in the #queue_head DLL.
   */
  const struct GNUNET_MessageHeader *msg;

  /**
   * Message queue we are providing for the #ch.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * handle for this queue with the #ch.
   */
  struct GNUNET_TRANSPORT_QueueHandle *qh;

  /**
   * Number of bytes we currently have in our write queue.
   */
  unsigned long long bytes_in_queue;

  /**
   * Timeout for this queue.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Which network type does this queue use?
   */
  enum GNUNET_NetworkType nt;
  
};


/**
 * ID of listen task
 */
static struct GNUNET_SCHEDULER_Task *listen_task;

/**
 * Number of messages we currently have in our queues towards the transport service.
 */
static unsigned long long delivering_messages;

/**
 * Maximum queue length before we stop reading towards the transport service.
 */
static unsigned long long max_queue_length;

/**
 * For logging statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Our environment.
 */
static struct GNUNET_TRANSPORT_CommunicatorHandle *ch;

/**
 * Queues (map from peer identity to `struct Queue`)
 */
static struct GNUNET_CONTAINER_MultiPeerMap *queue_map;

/**
 * Listen socket.
 */
static struct GNUNET_NETWORK_Handle *listen_sock;

/**
 * Handle to the operation that publishes our address.
 */
static struct GNUNET_TRANSPORT_AddressIdentifier *ai;


/**
 * We have been notified that our listen socket has something to
 * read. Do the read and reschedule this function to be called again
 * once more is available.
 *
 * @param cls NULL
 */
static void
listen_cb (void *cls);


/**
 * Functions with this signature are called whenever we need
 * to close a queue due to a disconnect or failure to
 * establish a connection.
 *
 * @param queue queue to close down
 */
static void
queue_destroy (struct Queue *queue)
{
  struct GNUNET_MQ_Handle *mq;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Disconnecting queue for peer `%s'\n",
	      GNUNET_i2s (&queue->target));
  if (NULL != (mq = queue->mq))
  {
    queue->mq = NULL;
    GNUNET_MQ_destroy (mq);
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (queue_map,
						       &queue->target,
						       queue));
  GNUNET_STATISTICS_set (stats,
			 "# UNIX queues active",
			 GNUNET_CONTAINER_multipeermap_size (queue_map),
			 GNUNET_NO);
  if (NULL != queue->read_task)
  {
    GNUNET_SCHEDULER_cancel (queue->read_task);
    queue->read_task = NULL;
  }
  if (NULL != queue->write_task)
  {
    GNUNET_SCHEDULER_cancel (queue->write_task);
    queue->write_task = NULL;
  }
  GNUNET_NETWORK_socket_close (queue->sock);
  gcry_cipher_close (queue->in_cipher);
  gcry_cipher_close (queue->out_cipher);
  GNUNET_free (queue->address);
  GNUNET_free (queue);
  if (NULL == listen_task)
    listen_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
						 listen_sock,
						 &listen_cb,
						 NULL);

}


/**
 * Queue read task. If we hit the timeout, disconnect it
 *
 * @param cls the `struct Queue *` to disconnect
 */
static void
queue_read (void *cls)
{
  struct Queue *queue = cls;
  struct GNUNET_TIME_Relative left;

  queue->read_task = NULL;
  /* CHECK IF READ-ready, then perform read! */
  
  left = GNUNET_TIME_absolute_get_remaining (queue->timeout);
  if (0 != left.rel_value_us)
  {
    /* not actually our turn yet, but let's at least update
       the monitor, it may think we're about to die ... */
    queue->read_task
      = GNUNET_SCHEDULER_add_read_net (left,
				       queue->sock,
				       &queue_read,
				       queue);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Queue %p was idle for %s, disconnecting\n",
	      queue,
	      GNUNET_STRINGS_relative_time_to_string (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
						      GNUNET_YES));
  // FIXME: try to send 'finish' message first!?
  queue_destroy (queue);
}


/**
 * Increment queue timeout due to activity.  We do not immediately
 * notify the monitor here as that might generate excessive
 * signalling.
 *
 * @param queue queue for which the timeout should be rescheduled
 */
static void
reschedule_queue_timeout (struct Queue *queue)
{
  GNUNET_assert (NULL != queue->read_task);
  queue->timeout
    = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
}


/**
 * Convert TCP bind specification to a `struct sockaddr *`
 *
 * @param bindto bind specification to convert
 * @param[out] sock_len set to the length of the address
 * @return converted bindto specification
 */
static struct sockaddr *
tcp_address_to_sockaddr (const char *bindto,
			 socklen_t *sock_len)
{
  struct sockaddr *in;
  size_t slen;

  /* FIXME: parse, allocate, return! */
  return NULL;
}


/**
 * We have been notified that our socket is ready to write.
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls a `struct Queue`
 */
static void
queue_write (void *cls)
{
  struct Queue *queue = cls;
  const struct GNUNET_MessageHeader *msg = queue->msg;
  size_t msg_size = ntohs (msg->size);

  queue->write_task = NULL;
  /* FIXME: send 'msg' */
  /* FIXME: check if we have more messages pending */
  queue->write_task 
    = GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
				      queue->sock,
				      &queue_write,
				      queue);
}


/**
 * Signature of functions implementing the sending functionality of a
 * message queue.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state our `struct Queue`
 */
static void
mq_send (struct GNUNET_MQ_Handle *mq,
	 const struct GNUNET_MessageHeader *msg,
	 void *impl_state)
{
  struct Queue *queue = impl_state;

  GNUNET_assert (mq == queue->mq);
  GNUNET_assert (NULL == queue->msg);
  queue->msg = msg;
  GNUNET_assert (NULL != queue->sock);
  if (NULL == queue->write_task)
    queue->write_task =
      GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                      queue->sock,
                                      &queue_write,
				      queue);
}


/**
 * Signature of functions implementing the destruction of a message
 * queue.  Implementations must not free @a mq, but should take care
 * of @a impl_state.
 *
 * @param mq the message queue to destroy
 * @param impl_state our `struct Queue`
 */
static void
mq_destroy (struct GNUNET_MQ_Handle *mq,
	    void *impl_state)
{
  struct Queue *queue = impl_state;

  if (mq == queue->mq)
  {
    queue->mq = NULL;
    queue_destroy (queue);
  }
}


/**
 * Implementation function that cancels the currently sent message.
 *
 * @param mq message queue
 * @param impl_state our `struct Queue`
 */
static void
mq_cancel (struct GNUNET_MQ_Handle *mq,
	   void *impl_state)
{
  struct Queue *queue = impl_state;

  GNUNET_assert (NULL != queue->msg);
  queue->msg = NULL;
  GNUNET_assert (NULL != queue->write_task);
  if (1) // FIXME?
  {
    GNUNET_SCHEDULER_cancel (queue->write_task);
    queue->write_task = NULL;
  }
}


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls our `struct Queue`
 * @param error error code
 */
static void
mq_error (void *cls,
	  enum GNUNET_MQ_Error error)
{
  struct Queue *queue = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
	      "TCP MQ error in queue to %s: %d\n",
	      GNUNET_i2s (&queue->target),
	      (int) error);
  queue_destroy (queue);
}


/**
 * Creates a new outbound queue the transport service will use to send
 * data to another peer.
 *
 * @param peer the target peer
 * @param cs inbound or outbound queue
 * @param in the address
 * @param in_len number of bytes in @a in
 * @return the queue or NULL of max connections exceeded
 */
static struct Queue *
setup_queue (struct GNUNET_NETWORK_Handle *sock,
	     enum GNUNET_TRANSPORT_ConnectionStatus cs,
	     const struct sockaddr *in,
	     socklen_t in_len)
{
  struct Queue *queue;

  queue = GNUNET_new (struct Queue);
  // queue->target = *target; // FIXME: handle case that we don't know the target yet!
  queue->address = GNUNET_memdup (in,
				  in_len);
  queue->address_len = in_len;
  queue->sock = sock; 
  queue->nt = 0; // FIXME: determine NT!
  (void) GNUNET_CONTAINER_multipeermap_put (queue_map,
					    &queue->target,
					    queue,
					    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_STATISTICS_set (stats,
			 "# queues active",
			 GNUNET_CONTAINER_multipeermap_size (queue_map),
			 GNUNET_NO);
  queue->timeout
    = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  queue->read_task
    = GNUNET_SCHEDULER_add_read_net (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
				     queue->sock,
				     &queue_read,
				     queue);
  queue->mq
    = GNUNET_MQ_queue_for_callbacks (&mq_send,
				     &mq_destroy,
				     &mq_cancel,
				     queue,
				     NULL,
				     &mq_error,
				     queue);
  {
    char *foreign_addr;

    switch (queue->address->sa_family)
    {
    case AF_INET:
      GNUNET_asprintf (&foreign_addr,
		       "%s-%s:%d",
		       COMMUNICATOR_ADDRESS_PREFIX,
		       "inet-ntop-fixme",
		       4242);
      break;
    case AF_INET6:
      GNUNET_asprintf (&foreign_addr,
		       "%s-%s:%d",
		       COMMUNICATOR_ADDRESS_PREFIX,
		       "inet-ntop-fixme",
		       4242);
      break;
    default:
      GNUNET_assert (0);
    }
    queue->qh
      = GNUNET_TRANSPORT_communicator_mq_add (ch,
					      &queue->target,
					      foreign_addr,
					      0 /* no MTU */,
					      queue->nt,
					      cs,
					      queue->mq);
    GNUNET_free (foreign_addr);
  }
  return queue;
}


/**
 * We have been notified that our listen socket has something to
 * read. Do the read and reschedule this function to be called again
 * once more is available.
 *
 * @param cls NULL
 */
static void
listen_cb (void *cls);


/**
 * We have been notified that our listen socket has something to
 * read. Do the read and reschedule this function to be called again
 * once more is available.
 *
 * @param cls NULL
 */
static void
listen_cb (void *cls)
{
  char buf[65536] GNUNET_ALIGN;
  struct Queue *queue;
  struct sockaddr_storage in;
  socklen_t addrlen;
  ssize_t ret;
  uint16_t msize;
  struct GNUNET_NETWORK_Handle *sock;

  listen_task = NULL;
  GNUNET_assert (NULL != listen_sock);
  addrlen = sizeof (in);
  memset (&in,
	  0,
	  sizeof (in));
  sock = GNUNET_NETWORK_socket_accept (listen_sock,
				       (struct sockaddr *) &in,
				       &addrlen);
  if ( (NULL == sock) &&
       ( (EMFILE == errno) ||
	 (ENFILE == errno) ) )
    return; /* system limit reached, wait until connection goes down */
  listen_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
					       listen_sock,
					       &listen_cb,
					       NULL);
  if ( (NULL == sock) &&
       ( (EAGAIN == errno) ||
	 (ENOBUFS == errno) ) )
    return;
  if (NULL == sock)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "accept");
    return;
  }
  queue = setup_queue (sock,
		       GNUNET_TRANSPORT_CS_INBOUND,
		       (struct sockaddr *) &in,
		       addrlen);
  if (NULL == queue)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Maximum number of TCP connections exceeded, dropping incoming connection\n"));
    return;
  }
}


/**
 * Function called by the transport service to initialize a
 * message queue given address information about another peer.
 * If and when the communication channel is established, the
 * communicator must call #GNUNET_TRANSPORT_communicator_mq_add()
 * to notify the service that the channel is now up.  It is
 * the responsibility of the communicator to manage sane
 * retries and timeouts for any @a peer/@a address combination
 * provided by the transport service.  Timeouts and retries
 * do not need to be signalled to the transport service.
 *
 * @param cls closure
 * @param peer identity of the other peer
 * @param address where to send the message, human-readable
 *        communicator-specific format, 0-terminated, UTF-8
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the provided address is invalid
 */
static int
mq_init (void *cls,
	 const struct GNUNET_PeerIdentity *peer,
	 const char *address)
{
  struct Queue *queue;
  const char *path;
  struct sockaddr *in;
  socklen_t in_len;

  if (0 != strncmp (address,
		    COMMUNICATOR_ADDRESS_PREFIX "-",
		    strlen (COMMUNICATOR_ADDRESS_PREFIX "-")))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  path = &address[strlen (COMMUNICATOR_ADDRESS_PREFIX "-")];
  in = tcp_address_to_sockaddr (path,
				&in_len);
#if FIXME
  queue = setup_queue (peer,
		       GNUNET_TRANSPORT_CS_OUTBOUND,
		       in,
		       in_len);
#endif
  GNUNET_free (in);
  if (NULL == queue)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Failed to setup queue to %s at `%s'\n",
		GNUNET_i2s (peer),
		path);
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


/**
 * Iterator over all message queues to clean up.
 *
 * @param cls NULL
 * @param target unused
 * @param value the queue to destroy
 * @return #GNUNET_OK to continue to iterate
 */
static int
get_queue_delete_it (void *cls,
		     const struct GNUNET_PeerIdentity *target,
		     void *value)
{
  struct Queue *queue = value;

  (void) cls;
  (void) target;
  queue_destroy (queue);
  return GNUNET_OK;
}


/**
 * Shutdown the UNIX communicator.
 *
 * @param cls NULL (always)
 */
static void
do_shutdown (void *cls)
{
  if (NULL != listen_task)
  {
    GNUNET_SCHEDULER_cancel (listen_task);
    listen_task = NULL;
  }
  if (NULL != listen_sock)
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (listen_sock));
    listen_sock = NULL;
  }
  GNUNET_CONTAINER_multipeermap_iterate (queue_map,
					 &get_queue_delete_it,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (queue_map);
  if (NULL != ai)
  {
    GNUNET_TRANSPORT_communicator_address_remove (ai);
    ai = NULL;
  }
  if (NULL != ch)
  {
    GNUNET_TRANSPORT_communicator_disconnect (ch);
    ch = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats,
			       GNUNET_NO);
    stats = NULL;
  }
}


/**
 * Function called when the transport service has received an
 * acknowledgement for this communicator (!) via a different return
 * path.
 *
 * Not applicable for UNIX.
 *
 * @param cls closure
 * @param sender which peer sent the notification
 * @param msg payload
 */
static void
enc_notify_cb (void *cls,
               const struct GNUNET_PeerIdentity *sender,
               const struct GNUNET_MessageHeader *msg)
{
  (void) cls;
  (void) sender;
  (void) msg;
  GNUNET_break_op (0);
}


/**
 * Setup communicator and launch network interactions.
 *
 * @param cls NULL (always)
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *bindto;
  struct sockaddr *in;
  socklen_t in_len;
  char *my_addr;
  (void) cls;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
					       COMMUNICATOR_CONFIG_SECTION,
					       "BINDTO",
					       &bindto))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               COMMUNICATOR_CONFIG_SECTION,
                               "BINDTO");
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
					     COMMUNICATOR_CONFIG_SECTION,
					     "MAX_QUEUE_LENGTH",
					     &max_queue_length))
    max_queue_length = DEFAULT_MAX_QUEUE_LENGTH;

  in = tcp_address_to_sockaddr (bindto,
				&in_len);
  if (NULL == in)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Failed to setup TCP socket address with path `%s'\n",
		bindto);
    GNUNET_free (bindto);
    return;
  }
  listen_sock = GNUNET_NETWORK_socket_create (in->sa_family,
					      SOCK_STREAM,
					      IPPROTO_TCP);
  if (NULL == listen_sock)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
			 "socket");
    GNUNET_free (in);
    GNUNET_free (bindto);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_bind (listen_sock,
                                  in,
				  in_len))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
			      "bind",
			      bindto);
    GNUNET_NETWORK_socket_close (listen_sock);
    listen_sock = NULL;
    GNUNET_free (in);
    GNUNET_free (bindto);
    return;
  }
  GNUNET_free (in);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Bound to `%s'\n",
	      bindto);
  stats = GNUNET_STATISTICS_create ("C-TCP",
				    cfg);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
				 NULL);
  listen_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
					       listen_sock,
					       &listen_cb,
					       NULL);
  queue_map = GNUNET_CONTAINER_multipeermap_create (10,
						      GNUNET_NO);
  ch = GNUNET_TRANSPORT_communicator_connect (cfg,
					      COMMUNICATOR_CONFIG_SECTION,
					      COMMUNICATOR_ADDRESS_PREFIX,
                                              GNUNET_TRANSPORT_CC_RELIABLE,
					      &mq_init,
					      NULL,
                                              &enc_notify_cb,
                                              NULL);
  if (NULL == ch)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (bindto);
    return;
  }
  // FIXME: bindto is wrong here, we MUST get our external
  // IP address and really look at 'in' here as we might
  // be bound to loopback or some other specific IP address!
  GNUNET_asprintf (&my_addr,
		   "%s-%s",
		   COMMUNICATOR_ADDRESS_PREFIX,
		   bindto);
  GNUNET_free (bindto);
  // FIXME: based on our bindto, we might not be able to tell the
  // network type yet! What to do here!?
  ai = GNUNET_TRANSPORT_communicator_address_add (ch,
						  my_addr,
						  GNUNET_NT_LOOPBACK, // FIXME: wrong NT!
						  GNUNET_TIME_UNIT_FOREVER_REL);
  GNUNET_free (my_addr);
}


/**
 * The main function for the UNIX communicator.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
				    &argc, &argv))
    return 2;

  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv,
                           "gnunet-communicator-tcp",
                           _("GNUnet TCP communicator"),
                           options,
			   &run,
			   NULL)) ? 0 : 1;
  GNUNET_free ((void*) argv);
  return ret;
}


#if defined(LINUX) && defined(__GLIBC__)
#include <malloc.h>

/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor))
GNUNET_ARM_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}
#endif

/* end of gnunet-communicator-tcp.c */
