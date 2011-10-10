/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
#include "gnunet_bandwidth_lib.h"
#include "gnunet_client_lib.h"
#include "gnunet_constants.h"
#include "gnunet_container_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_dv_service.h"
#include "dv.h"
#include "gnunet_transport_plugin.h"

#define LOG(kind,...) GNUNET_log_from (kind, "dv-api",__VA_ARGS__)

/**
 * Store ready to send messages
 */
struct PendingMessages
{
  /**
   * Linked list of pending messages
   */
  struct PendingMessages *next;

  /**
   * Message that is pending
   */
  struct GNUNET_DV_SendMessage *msg;

  /**
   * Timeout for this message
   */
  struct GNUNET_TIME_Absolute timeout;

};

/**
 * Handle for the service.
 */
struct GNUNET_DV_Handle
{

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Currently pending transmission request.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * List of the currently pending messages for the DV service.
   */
  struct PendingMessages *pending_list;

  /**
   * Message we are currently sending.
   */
  struct PendingMessages *current;

  /**
   * Handler for messages we receive from the DV service
   */
  GNUNET_DV_MessageReceivedHandler receive_handler;

  /**
   * Closure for the receive handler
   */
  void *receive_cls;

  /**
   * Current unique ID
   */
  uint32_t uid_gen;

  /**
   * Hashmap containing outstanding send requests awaiting confirmation.
   */
  struct GNUNET_CONTAINER_MultiHashMap *send_callbacks;

};


struct StartContext
{
  /**
   * Start message
   */
  struct GNUNET_MessageHeader *message;

  /**
   * Handle to service, in case of timeout
   */
  struct GNUNET_DV_Handle *handle;
};

struct SendCallbackContext
{
  /**
   * The continuation to call once a message is confirmed sent (or failed)
   */
  GNUNET_TRANSPORT_TransmitContinuation cont;

  /**
   * Closure to call with send continuation.
   */
  void *cont_cls;

  /**
   * Target of the message.
   */
  struct GNUNET_PeerIdentity target;
};

/**
 * Convert unique ID to hash code.
 *
 * @param uid unique ID to convert
 * @param hash set to uid (extended with zeros)
 */
static void
hash_from_uid (uint32_t uid, GNUNET_HashCode * hash)
{
  memset (hash, 0, sizeof (GNUNET_HashCode));
  *((uint32_t *) hash) = uid;
}

/**
 * Try to (re)connect to the dv service.
 *
 * @param ret handle to the (disconnected) dv service
 *
 * @return GNUNET_YES on success, GNUNET_NO on failure.
 */
static int
try_connect (struct GNUNET_DV_Handle *ret)
{
  if (ret->client != NULL)
    return GNUNET_OK;
  ret->client = GNUNET_CLIENT_connect ("dv", ret->cfg);
  if (ret->client != NULL)
    return GNUNET_YES;
#if DEBUG_DV_MESSAGES
  LOG (GNUNET_ERROR_TYPE_DEBUG, _("Failed to connect to the dv service!\n"));
#endif
  return GNUNET_NO;
}

static void
process_pending_message (struct GNUNET_DV_Handle *handle);

/**
 * Send complete, schedule next
 *
 * @param handle handle to the dv service
 * @param code return code for send (unused)
 */
static void
finish (struct GNUNET_DV_Handle *handle, int code)
{
  struct PendingMessages *pos = handle->current;

  handle->current = NULL;
  process_pending_message (handle);

  GNUNET_free (pos->msg);
  GNUNET_free (pos);
}

/**
 * Notification that we can send data
 *
 * @param cls handle to the dv service (struct GNUNET_DV_Handle)
 * @param size how many bytes can we send
 * @param buf where to copy the message to send
 *
 * @return how many bytes we copied to buf
 */
static size_t
transmit_pending (void *cls, size_t size, void *buf)
{
  struct GNUNET_DV_Handle *handle = cls;
  size_t ret;
  size_t tsize;

#if DEBUG_DV
  if (handle->current != NULL)
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "DV API: Transmit pending called with message type %d\n",
         ntohs (handle->current->msg->header.type));
#endif

  if (buf == NULL)
  {
#if DEBUG_DV
    LOG (GNUNET_ERROR_TYPE_DEBUG, "DV API: Transmit pending FAILED!\n\n\n");
#endif
    finish (handle, GNUNET_SYSERR);
    return 0;
  }
  handle->th = NULL;

  ret = 0;

  if (handle->current != NULL)
  {
    tsize = ntohs (handle->current->msg->header.size);
    if (size >= tsize)
    {
      memcpy (buf, handle->current->msg, tsize);
#if DEBUG_DV
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "DV API: Copied %d bytes into buffer!\n\n\n", tsize);
#endif
      finish (handle, GNUNET_OK);
      return tsize;
    }

  }

  return ret;
}

/**
 * Try to send messages from list of messages to send
 *
 * @param handle handle to the distance vector service
 */
static void
process_pending_message (struct GNUNET_DV_Handle *handle)
{

  if (handle->current != NULL)
    return;                     /* action already pending */
  if (GNUNET_YES != try_connect (handle))
  {
    finish (handle, GNUNET_SYSERR);
    return;
  }

  /* schedule next action */
  handle->current = handle->pending_list;
  if (NULL == handle->current)
  {
    return;
  }
  handle->pending_list = handle->pending_list->next;
  handle->current->next = NULL;

  if (NULL ==
      (handle->th =
       GNUNET_CLIENT_notify_transmit_ready (handle->client,
                                            ntohs (handle->current->msg->
                                                   header.size),
                                            handle->current->msg->timeout,
                                            GNUNET_YES, &transmit_pending,
                                            handle)))
  {
#if DEBUG_DV
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Failed to transmit request to dv service.\n");
#endif
    finish (handle, GNUNET_SYSERR);
  }
}

/**
 * Add a pending message to the linked list
 *
 * @param handle handle to the specified DV api
 * @param msg the message to add to the list
 */
static void
add_pending (struct GNUNET_DV_Handle *handle, struct GNUNET_DV_SendMessage *msg)
{
  struct PendingMessages *new_message;
  struct PendingMessages *pos;
  struct PendingMessages *last;

  new_message = GNUNET_malloc (sizeof (struct PendingMessages));
  new_message->msg = msg;

  if (handle->pending_list != NULL)
  {
    pos = handle->pending_list;
    while (pos != NULL)
    {
      last = pos;
      pos = pos->next;
    }
    last->next = new_message;
  }
  else
  {
    handle->pending_list = new_message;
  }

  process_pending_message (handle);
}

/**
 * Handles a message sent from the DV service to us.
 * Parse it out and give it to the plugin.
 *
 * @param cls the handle to the DV API
 * @param msg the message that was received
 */
void
handle_message_receipt (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_DV_Handle *handle = cls;
  struct GNUNET_DV_MessageReceived *received_msg;
  struct GNUNET_DV_SendResultMessage *send_result_msg;
  size_t packed_msg_len;
  size_t sender_address_len;
  char *sender_address;
  char *packed_msg;
  char *packed_msg_start;
  GNUNET_HashCode uidhash;
  struct SendCallbackContext *send_ctx;

  if (msg == NULL)
  {
#if DEBUG_DV_MESSAGES
    LOG (GNUNET_ERROR_TYPE_DEBUG, "DV_API receive: connection closed\n");
#endif
    return;                     /* Connection closed? */
  }

  GNUNET_assert ((ntohs (msg->type) == GNUNET_MESSAGE_TYPE_TRANSPORT_DV_RECEIVE)
                 || (ntohs (msg->type) ==
                     GNUNET_MESSAGE_TYPE_TRANSPORT_DV_SEND_RESULT));

  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_TRANSPORT_DV_RECEIVE:
    if (ntohs (msg->size) < sizeof (struct GNUNET_DV_MessageReceived))
      return;

    received_msg = (struct GNUNET_DV_MessageReceived *) msg;
    packed_msg_len = ntohl (received_msg->msg_len);
    sender_address_len =
        ntohs (msg->size) - packed_msg_len -
        sizeof (struct GNUNET_DV_MessageReceived);
    GNUNET_assert (sender_address_len > 0);
    sender_address = GNUNET_malloc (sender_address_len);
    memcpy (sender_address, &received_msg[1], sender_address_len);
    packed_msg_start = (char *) &received_msg[1];
    packed_msg = GNUNET_malloc (packed_msg_len);
    memcpy (packed_msg, &packed_msg_start[sender_address_len], packed_msg_len);

#if DEBUG_DV_MESSAGES
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "DV_API receive: packed message type: %d or %d\n",
         ntohs (((struct GNUNET_MessageHeader *) packed_msg)->type),
         ((struct GNUNET_MessageHeader *) packed_msg)->type);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "DV_API receive: message sender reported as %s\n",
         GNUNET_i2s (&received_msg->sender));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "DV_API receive: distance is %u\n",
         ntohl (received_msg->distance));
#endif

    handle->receive_handler (handle->receive_cls, &received_msg->sender,
                             packed_msg, packed_msg_len,
                             ntohl (received_msg->distance), sender_address,
                             sender_address_len);

    GNUNET_free (sender_address);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_DV_SEND_RESULT:
    if (ntohs (msg->size) < sizeof (struct GNUNET_DV_SendResultMessage))
      return;

    send_result_msg = (struct GNUNET_DV_SendResultMessage *) msg;
    hash_from_uid (ntohl (send_result_msg->uid), &uidhash);
    send_ctx =
        GNUNET_CONTAINER_multihashmap_get (handle->send_callbacks, &uidhash);

    if ((send_ctx != NULL) && (send_ctx->cont != NULL))
    {
      if (ntohl (send_result_msg->result) == 0)
      {
        send_ctx->cont (send_ctx->cont_cls, &send_ctx->target, GNUNET_OK);
      }
      else
      {
        send_ctx->cont (send_ctx->cont_cls, &send_ctx->target, GNUNET_SYSERR);
      }
    }
    GNUNET_free_non_null (send_ctx);
    break;
  default:
    break;
  }
  GNUNET_CLIENT_receive (handle->client, &handle_message_receipt, handle,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}

/**
 * Send a message from the plugin to the DV service indicating that
 * a message should be sent via DV to some peer.
 *
 * @param dv_handle the handle to the DV api
 * @param target the final target of the message
 * @param msgbuf the msg(s) to send
 * @param msgbuf_size the size of msgbuf
 * @param priority priority to pass on to core when sending the message
 * @param timeout how long can this message be delayed (pass through to core)
 * @param addr the address of this peer (internally known to DV)
 * @param addrlen the length of the peer address
 * @param cont continuation to call once the message has been sent (or failed)
 * @param cont_cls closure for continuation
 *
 */
int
GNUNET_DV_send (struct GNUNET_DV_Handle *dv_handle,
                const struct GNUNET_PeerIdentity *target, const char *msgbuf,
                size_t msgbuf_size, unsigned int priority,
                struct GNUNET_TIME_Relative timeout, const void *addr,
                size_t addrlen, GNUNET_TRANSPORT_TransmitContinuation cont,
                void *cont_cls)
{
  struct GNUNET_DV_SendMessage *msg;
  struct SendCallbackContext *send_ctx;
  char *end_of_message;
  GNUNET_HashCode uidhash;
  int msize;

#if DEBUG_DV_MESSAGES
  dv_handle->uid_gen =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, UINT32_MAX);
#else
  dv_handle->uid_gen++;
#endif

  msize = sizeof (struct GNUNET_DV_SendMessage) + addrlen + msgbuf_size;
  msg = GNUNET_malloc (msize);
  msg->header.size = htons (msize);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_DV_SEND);
  memcpy (&msg->target, target, sizeof (struct GNUNET_PeerIdentity));
  msg->priority = htonl (priority);
  msg->timeout = timeout;
  msg->addrlen = htonl (addrlen);
  msg->uid = htonl (dv_handle->uid_gen);
  memcpy (&msg[1], addr, addrlen);
  end_of_message = (char *) &msg[1];
  end_of_message = &end_of_message[addrlen];
  memcpy (end_of_message, msgbuf, msgbuf_size);
  add_pending (dv_handle, msg);
  send_ctx = GNUNET_malloc (sizeof (struct SendCallbackContext));
  send_ctx->cont = cont;
  send_ctx->cont_cls = cont_cls;
  memcpy (&send_ctx->target, target, sizeof (struct GNUNET_PeerIdentity));
  hash_from_uid (dv_handle->uid_gen, &uidhash);
  GNUNET_CONTAINER_multihashmap_put (dv_handle->send_callbacks, &uidhash,
                                     send_ctx,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);

  return GNUNET_OK;
}

/**
 * Callback to transmit a start message to
 * the DV service, once we can send
 *
 * @param cls struct StartContext
 * @param size how much can we send
 * @param buf where to copy the message
 *
 * @return number of bytes copied to buf
 */
static size_t
transmit_start (void *cls, size_t size, void *buf)
{
  struct StartContext *start_context = cls;
  struct GNUNET_DV_Handle *handle = start_context->handle;
  size_t tsize;

#if DEBUG_DV
  LOG (GNUNET_ERROR_TYPE_DEBUG, "DV API: sending start request to service\n");
#endif
  if (buf == NULL)
  {
    GNUNET_free (start_context->message);
    GNUNET_free (start_context);
    GNUNET_DV_disconnect (handle);
    return 0;
  }

  tsize = ntohs (start_context->message->size);
  if (size >= tsize)
  {
    memcpy (buf, start_context->message, tsize);
    GNUNET_free (start_context->message);
    GNUNET_free (start_context);
    GNUNET_CLIENT_receive (handle->client, &handle_message_receipt, handle,
                           GNUNET_TIME_UNIT_FOREVER_REL);


    return tsize;
  }

  return 0;
}

/**
 * Connect to the DV service
 *
 * @param cfg the configuration to use
 * @param receive_handler method call when on receipt from the service
 * @param receive_handler_cls closure for receive_handler
 *
 * @return handle to the DV service
 */
struct GNUNET_DV_Handle *
GNUNET_DV_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                   GNUNET_DV_MessageReceivedHandler receive_handler,
                   void *receive_handler_cls)
{
  struct GNUNET_DV_Handle *handle;
  struct GNUNET_MessageHeader *start_message;
  struct StartContext *start_context;

  handle = GNUNET_malloc (sizeof (struct GNUNET_DV_Handle));

  handle->cfg = cfg;
  handle->pending_list = NULL;
  handle->current = NULL;
  handle->th = NULL;
  handle->client = GNUNET_CLIENT_connect ("dv", cfg);
  handle->receive_handler = receive_handler;
  handle->receive_cls = receive_handler_cls;

  if (handle->client == NULL)
  {
    GNUNET_free (handle);
    return NULL;
  }

  start_message = GNUNET_malloc (sizeof (struct GNUNET_MessageHeader));
  start_message->size = htons (sizeof (struct GNUNET_MessageHeader));
  start_message->type = htons (GNUNET_MESSAGE_TYPE_DV_START);

  start_context = GNUNET_malloc (sizeof (struct StartContext));
  start_context->handle = handle;
  start_context->message = start_message;
  GNUNET_CLIENT_notify_transmit_ready (handle->client,
                                       sizeof (struct GNUNET_MessageHeader),
                                       GNUNET_TIME_relative_multiply
                                       (GNUNET_TIME_UNIT_SECONDS, 60),
                                       GNUNET_YES, &transmit_start,
                                       start_context);

  handle->send_callbacks = GNUNET_CONTAINER_multihashmap_create (100);

  return handle;
}

/**
 * Disconnect from the DV service
 *
 * @param handle the current handle to the service to disconnect
 */
void
GNUNET_DV_disconnect (struct GNUNET_DV_Handle *handle)
{
  struct PendingMessages *pos;

  GNUNET_assert (handle != NULL);

  if (handle->th != NULL)       /* We have a live transmit request in the Aether */
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (handle->th);
    handle->th = NULL;
  }
  if (handle->current != NULL)  /* We are trying to send something now, clean it up */
    GNUNET_free (handle->current);
  while (NULL != (pos = handle->pending_list))  /* Remove all pending sends from the list */
  {
    handle->pending_list = pos->next;
    GNUNET_free (pos);
  }
  if (handle->client != NULL)   /* Finally, disconnect from the service */
  {
    GNUNET_CLIENT_disconnect (handle->client, GNUNET_NO);
    handle->client = NULL;
  }

  GNUNET_free (handle);
}

/* end of dv_api.c */
