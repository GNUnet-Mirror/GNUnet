/*
     This file is part of GNUnet.
     (C) 2009--2013 Christian Grothoff (and other contributing authors)

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
 * @file dv/dv_api.c
 * @brief library to access the DV service
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dv_service.h"
#include "gnunet_protocols.h"
#include "dv.h"
#include "gnunet_transport_plugin.h"

#define LOG(kind,...) GNUNET_log_from (kind, "dv-api",__VA_ARGS__)


/**
 * Handle for a send operation.
 */
struct GNUNET_DV_TransmitHandle
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_DV_TransmitHandle *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_DV_TransmitHandle *prev;

  /**
   * Handle to the service.
   */
  struct GNUNET_DV_ServiceHandle *sh;

  /**
   * Function to call upon completion.
   */
  GNUNET_DV_MessageSentCallback cb;

  /**
   * Closure for 'cb'.
   */
  void *cb_cls;

  /**
   * The actual message (allocated at the end of this struct).
   */
  const struct GNUNET_MessageHeader *msg;

  /**
   * Destination for the message.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * UID of our message, if any.
   */
  uint32_t uid;

};


/**
 * Handle to the DV service.
 */
struct GNUNET_DV_ServiceHandle
{

  /**
   * Connection to DV service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Active request for transmission to DV service.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Closure for the callbacks.
   */
  void *cls;

  /**
   * Function to call on connect events.
   */
  GNUNET_DV_ConnectCallback connect_cb;

  /**
   * Function to call on distance change events.
   */
  GNUNET_DV_DistanceChangedCallback distance_cb;

  /**
   * Function to call on disconnect events.
   */
  GNUNET_DV_DisconnectCallback disconnect_cb;

  /**
   * Function to call on receiving messages events.
   */
  GNUNET_DV_MessageReceivedCallback message_cb;

  /**
   * Head of messages to transmit.
   */
  struct GNUNET_DV_TransmitHandle *th_head;

  /**
   * Tail of messages to transmit.
   */
  struct GNUNET_DV_TransmitHandle *th_tail;

  /**
   * Mapping of peer identities to TransmitHandles to invoke
   * upon successful transmission.  The respective
   * transmissions have already been done.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *send_callbacks;

  /**
   * Current unique ID
   */
  uint32_t uid_gen;

};


/**
 * Disconnect and then reconnect to the DV service.
 *
 * @param sh service handle
 */
static void
reconnect (struct GNUNET_DV_ServiceHandle *sh);


/**
 * Gives a message from our queue to the DV service.
 *
 * @param cls handle to the dv service (struct GNUNET_DV_ServiceHandle)
 * @param size how many bytes can we send
 * @param buf where to copy the message to send
 * @return how many bytes we copied to buf
 */
static size_t
transmit_pending (void *cls, size_t size, void *buf)
{
  struct GNUNET_DV_ServiceHandle *sh = cls;
  char *cbuf = buf;
  struct GNUNET_DV_TransmitHandle *th;
  size_t ret;
  size_t tsize;

  sh->th = NULL;
  if (NULL == buf)
  {
    reconnect (sh);
    return 0;
  }
  ret = 0;
  while ( (NULL != (th = sh->th_head)) &&
	  (size - ret >= (tsize = ntohs (th->msg->size)) ))
  {
    GNUNET_CONTAINER_DLL_remove (sh->th_head,
				 sh->th_tail,
				 th);
    memcpy (&cbuf[ret], th->msg, tsize);
    ret += tsize;
    if (NULL != th->cb)
    {
      (void) GNUNET_CONTAINER_multipeermap_put (sh->send_callbacks,
						&th->target,
						th,
						GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    }
    else
    {
      GNUNET_free (th);
    }
  }
  return ret;
}


/**
 * Start sending messages from our queue to the service.
 *
 * @param sh service handle
 */
static void
start_transmit (struct GNUNET_DV_ServiceHandle *sh)
{
  if (NULL != sh->th)
    return;
  if (NULL == sh->th_head)
    return;
  sh->th =
    GNUNET_CLIENT_notify_transmit_ready (sh->client,
					 ntohs (sh->th_head->msg->size),
					 GNUNET_TIME_UNIT_FOREVER_REL,
					 GNUNET_NO,
					 &transmit_pending, sh);
}


/**
 * Closure for 'process_ack'.
 */
struct AckContext
{
  /**
   * The ACK message.
   */
  const struct GNUNET_DV_AckMessage *ack;

  /**
   * Our service handle.
   */
  struct GNUNET_DV_ServiceHandle *sh;
};


/**
 * We got an ACK.  Check if it matches the given transmit handle, and if
 * so call the continuation.
 *
 * @param cls the 'struct AckContext'
 * @param key peer identity
 * @param value the 'struct GNUNET_DV_TransmitHandle'
 * @return GNUNET_OK if the ACK did not match (continue to iterate)
 */
static int
process_ack (void *cls,
	     const struct GNUNET_PeerIdentity *key,
	     void *value)
{
  struct AckContext *ctx = cls;
  struct GNUNET_DV_TransmitHandle *th = value;

  if (th->uid != ntohl (ctx->ack->uid))
    return GNUNET_OK;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Matchedk ACK for message to peer %s\n",
       GNUNET_i2s (key));
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multipeermap_remove (ctx->sh->send_callbacks,
						       key,
						       th));
  th->cb (th->cb_cls,
	  (ntohs (ctx->ack->header.type) == GNUNET_MESSAGE_TYPE_DV_SEND_ACK)
	  ? GNUNET_OK
	  : GNUNET_SYSERR);
  GNUNET_free (th);
  return GNUNET_NO;
}


/**
 * Handles a message sent from the DV service to us.
 * Parse it out and give it to the plugin.
 *
 * @param cls the handle to the DV API
 * @param msg the message that was received
 */
static void
handle_message_receipt (void *cls,
			const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_DV_ServiceHandle *sh = cls;
  const struct GNUNET_DV_ConnectMessage *cm;
  const struct GNUNET_DV_DistanceUpdateMessage *dum;
  const struct GNUNET_DV_DisconnectMessage *dm;
  const struct GNUNET_DV_ReceivedMessage *rm;
  const struct GNUNET_MessageHeader *payload;
  const struct GNUNET_DV_AckMessage *ack;
  struct AckContext ctx;

  if (NULL == msg)
  {
    /* Connection closed */
    reconnect (sh);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message of type %u from DV service\n",
       (unsigned int) msg->type);
  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_DV_CONNECT:
    if (ntohs (msg->size) != sizeof (struct GNUNET_DV_ConnectMessage))
    {
      GNUNET_break (0);
      reconnect (sh);
      return;
    }
    cm = (const struct GNUNET_DV_ConnectMessage *) msg;
    sh->connect_cb (sh->cls,
		    &cm->peer,
		    ntohl (cm->distance));
    break;
  case GNUNET_MESSAGE_TYPE_DV_DISTANCE_CHANGED:
    if (ntohs (msg->size) != sizeof (struct GNUNET_DV_DistanceUpdateMessage))
    {
      GNUNET_break (0);
      reconnect (sh);
      return;
    }
    dum = (const struct GNUNET_DV_DistanceUpdateMessage *) msg;
    sh->distance_cb (sh->cls,
		     &dum->peer,
		     ntohl (dum->distance));
    break;
  case GNUNET_MESSAGE_TYPE_DV_DISCONNECT:
    if (ntohs (msg->size) != sizeof (struct GNUNET_DV_DisconnectMessage))
    {
      GNUNET_break (0);
      reconnect (sh);
      return;
    }
    dm = (const struct GNUNET_DV_DisconnectMessage *) msg;
    sh->disconnect_cb (sh->cls,
		       &dm->peer);
    break;
  case GNUNET_MESSAGE_TYPE_DV_RECV:
    if (ntohs (msg->size) < sizeof (struct GNUNET_DV_ReceivedMessage) + sizeof (struct GNUNET_MessageHeader))
    {
      GNUNET_break (0);
      reconnect (sh);
      return;
    }
    rm = (const struct GNUNET_DV_ReceivedMessage *) msg;
    payload = (const struct GNUNET_MessageHeader *) &rm[1];
    if (ntohs (msg->size) != sizeof (struct GNUNET_DV_ReceivedMessage) + ntohs (payload->size))
    {
      GNUNET_break (0);
      reconnect (sh);
      return;
    }
    sh->message_cb (sh->cls,
		    &rm->sender,
		    ntohl (rm->distance),
		    payload);
    break;
  case GNUNET_MESSAGE_TYPE_DV_SEND_ACK:
  case GNUNET_MESSAGE_TYPE_DV_SEND_NACK:
    if (ntohs (msg->size) != sizeof (struct GNUNET_DV_AckMessage))
    {
      GNUNET_break (0);
      reconnect (sh);
      return;
    }
    ack = (const struct GNUNET_DV_AckMessage *) msg;
    ctx.ack = ack;
    ctx.sh = sh;
    GNUNET_CONTAINER_multipeermap_get_multiple (sh->send_callbacks,
						&ack->target,
						&process_ack,
						&ctx);
    break;
  default:
    reconnect (sh);
    break;
  }
  GNUNET_CLIENT_receive (sh->client,
			 &handle_message_receipt, sh,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Transmit the start message to the DV service.
 *
 * @param cls the 'struct GNUNET_DV_ServiceHandle'
 * @param size number of bytes available in buf
 * @param buf where to copy the message
 * @return number of bytes written to buf
 */
static size_t
transmit_start (void *cls,
		size_t size,
		void *buf)
{
  struct GNUNET_DV_ServiceHandle *sh = cls;
  struct GNUNET_MessageHeader start_message;

  sh->th = NULL;
  if (NULL == buf)
  {
    GNUNET_break (0);
    reconnect (sh);
    return 0;
  }
  GNUNET_assert (size >= sizeof (start_message));
  start_message.size = htons (sizeof (struct GNUNET_MessageHeader));
  start_message.type = htons (GNUNET_MESSAGE_TYPE_DV_START);
  memcpy (buf, &start_message, sizeof (start_message));
  GNUNET_CLIENT_receive (sh->client,
			 &handle_message_receipt, sh,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  start_transmit (sh);
  return sizeof (start_message);
}


/**
 * We got disconnected from the service and thus all of the
 * pending send callbacks will never be confirmed.  Clean up.
 *
 * @param cls the 'struct GNUNET_DV_ServiceHandle'
 * @param key a peer identity
 * @param value a 'struct GNUNET_DV_TransmitHandle' to clean up
 * @return GNUNET_OK (continue to iterate)
 */
static int
cleanup_send_cb (void *cls,
		 const struct GNUNET_PeerIdentity *key,
		 void *value)
{
  struct GNUNET_DV_ServiceHandle *sh = cls;
  struct GNUNET_DV_TransmitHandle *th = value;

  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multipeermap_remove (sh->send_callbacks,
						       key,
						       th));
  th->cb (th->cb_cls, GNUNET_SYSERR);
  GNUNET_free (th);
  return GNUNET_OK;
}


/**
 * Disconnect and then reconnect to the DV service.
 *
 * @param sh service handle
 */
static void
reconnect (struct GNUNET_DV_ServiceHandle *sh)
{
  if (NULL != sh->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (sh->th);
    sh->th = NULL;
  }
  if (NULL != sh->client)
  {
    GNUNET_CLIENT_disconnect (sh->client);
    sh->client = NULL;
  }
  GNUNET_CONTAINER_multipeermap_iterate (sh->send_callbacks,
					 &cleanup_send_cb,
					 sh);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to DV service\n");
  sh->client = GNUNET_CLIENT_connect ("dv", sh->cfg);
  if (NULL == sh->client)
  {
    GNUNET_break (0);
    return;
  }
  sh->th = GNUNET_CLIENT_notify_transmit_ready (sh->client,
						sizeof (struct GNUNET_MessageHeader),
						GNUNET_TIME_UNIT_FOREVER_REL,
						GNUNET_YES,
						&transmit_start,
						sh);
}


/**
 * Connect to the DV service.
 *
 * @param cfg configuration
 * @param cls closure for callbacks
 * @param connect_cb function to call on connects
 * @param distance_cb function to call if distances change
 * @param disconnect_cb function to call on disconnects
 * @param message_cb function to call if we receive messages
 * @return handle to access the service
 */
struct GNUNET_DV_ServiceHandle *
GNUNET_DV_service_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
			   void *cls,
			   GNUNET_DV_ConnectCallback connect_cb,
			   GNUNET_DV_DistanceChangedCallback distance_cb,
			   GNUNET_DV_DisconnectCallback disconnect_cb,
			   GNUNET_DV_MessageReceivedCallback message_cb)
{
  struct GNUNET_DV_ServiceHandle *sh;

  sh = GNUNET_new (struct GNUNET_DV_ServiceHandle);
  sh->cfg = cfg;
  sh->cls = cls;
  sh->connect_cb = connect_cb;
  sh->distance_cb = distance_cb;
  sh->disconnect_cb = disconnect_cb;
  sh->message_cb = message_cb;
  sh->send_callbacks = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_YES);
  reconnect (sh);
  return sh;
}


/**
 * Disconnect from DV service.
 *
 * @param sh service handle
 */
void
GNUNET_DV_service_disconnect (struct GNUNET_DV_ServiceHandle *sh)
{
  struct GNUNET_DV_TransmitHandle *pos;

  if (NULL == sh)
    return;
  if (NULL != sh->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (sh->th);
    sh->th = NULL;
  }
  while (NULL != (pos = sh->th_head))
  {
    GNUNET_CONTAINER_DLL_remove (sh->th_head,
				 sh->th_tail,
				 pos);
    GNUNET_free (pos);
  }
  if (NULL != sh->client)
  {
    GNUNET_CLIENT_disconnect (sh->client);
    sh->client = NULL;
  }
  GNUNET_CONTAINER_multipeermap_iterate (sh->send_callbacks,
					 &cleanup_send_cb,
					 sh);
  GNUNET_CONTAINER_multipeermap_destroy (sh->send_callbacks);
  GNUNET_free (sh);
}


/**
 * Send a message via DV service.
 *
 * @param sh service handle
 * @param target intended recpient
 * @param msg message payload
 * @param cb function to invoke when done
 * @param cb_cls closure for 'cb'
 * @return handle to cancel the operation
 */
struct GNUNET_DV_TransmitHandle *
GNUNET_DV_send (struct GNUNET_DV_ServiceHandle *sh,
		const struct GNUNET_PeerIdentity *target,
		const struct GNUNET_MessageHeader *msg,
		GNUNET_DV_MessageSentCallback cb,
		void *cb_cls)
{
  struct GNUNET_DV_TransmitHandle *th;
  struct GNUNET_DV_SendMessage *sm;

  if (ntohs (msg->size) + sizeof (struct GNUNET_DV_SendMessage) >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to send %u bytes of type %u to %s\n",
       (unsigned int) msg->size,
       (unsigned int) msg->type,
       GNUNET_i2s (target));

  th = GNUNET_malloc (sizeof (struct GNUNET_DV_TransmitHandle) +
		      sizeof (struct GNUNET_DV_SendMessage) +
		      ntohs (msg->size));
  th->sh = sh;
  th->target = *target;
  th->cb = cb;
  th->cb_cls = cb_cls;
  th->msg = (const struct GNUNET_MessageHeader *) &th[1];
  sm = (struct GNUNET_DV_SendMessage *) &th[1];
  sm->header.type = htons (GNUNET_MESSAGE_TYPE_DV_SEND);
  sm->header.size = htons (sizeof (struct GNUNET_DV_SendMessage) +
			   ntohs (msg->size));
  if (0 == sh->uid_gen)
    sh->uid_gen = 1;
  th->uid = sh->uid_gen;
  sm->uid = htonl (sh->uid_gen++);
  /* use memcpy here as 'target' may not be sufficiently aligned */
  memcpy (&sm->target, target, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&sm[1], msg, ntohs (msg->size));
  GNUNET_CONTAINER_DLL_insert (sh->th_head,
			       sh->th_tail,
			       th);
  start_transmit (sh);
  return th;
}


/**
 * Abort send operation (naturally, the message may have
 * already been transmitted; this only stops the 'cb'
 * from being called again).
 *
 * @param th send operation to cancel
 */
void
GNUNET_DV_send_cancel (struct GNUNET_DV_TransmitHandle *th)
{
  struct GNUNET_DV_ServiceHandle *sh = th->sh;
  int ret;

  ret = GNUNET_CONTAINER_multipeermap_remove (sh->send_callbacks,
					      &th->target,
					      th);
  if (GNUNET_YES != ret)
    GNUNET_CONTAINER_DLL_remove (sh->th_head,
				 sh->th_tail,
				 th);
  GNUNET_free (th);
}


/* end of dv_api.c */
