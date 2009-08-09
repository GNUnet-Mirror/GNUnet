/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file core/core_api.c
 * @brief core service; this is the main API for encrypted P2P
 *        communications
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_core_service.h"
#include "core.h"


/**
 * Context for the core service connection.
 */
struct GNUNET_CORE_Handle
{

  /**
   * Our scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Configuration we're using.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Closure for the various callbacks.
   */
  void *cls;

  /**
   * Function to call once we've handshaked with the core service.
   */
  GNUNET_CORE_StartupCallback init;

  /**
   * Function to call whenever we're notified about a peer connecting.
   */
  GNUNET_CORE_ClientEventHandler connects;

  /**
   * Function to call whenever we're notified about a peer disconnecting.
   */
  GNUNET_CORE_ClientEventHandler disconnects;

  /**
   * Function to call whenever we're asked to generate traffic
   * (data provided to be transmitted back to the service).
   */
  GNUNET_CORE_BufferFillCallback bfc;

  /**
   * Function to call whenever we receive an inbound message.
   */
  GNUNET_CORE_MessageCallback inbound_notify;

  /**
   * Function to call whenever we receive an outbound message.
   */
  GNUNET_CORE_MessageCallback outbound_notify;

  /**
   * Function handlers for messages of particular type.
   */
  const struct GNUNET_CORE_MessageHandler *handlers;

  /**
   * Our connection to the service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Handle for our current transmission request.
   */
  struct GNUNET_NETWORK_TransmitHandle *th;

  /**
   * Head of doubly-linked list of pending requests.
   */
  struct GNUNET_CORE_TransmitHandle *pending_head;

  /**
   * Tail of doubly-linked list of pending requests.
   */
  struct GNUNET_CORE_TransmitHandle *pending_tail;

  /**
   * Currently submitted request (or NULL)
   */
  struct GNUNET_CORE_TransmitHandle *submitted;

  /**
   * How long to wait until we time out the connection attempt?
   */
  struct GNUNET_TIME_Absolute startup_timeout;

  /**
   * ID of reconnect task (if any).
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

  /**
   * Number of entries in the handlers array.
   */
  unsigned int hcnt;

  /**
   * For inbound notifications without a specific handler, do
   * we expect to only receive headers?
   */
  int inbound_hdr_only;

  /**
   * For outbound notifications without a specific handler, do
   * we expect to only receive headers?
   */
  int outbound_hdr_only;

  /**
   * Are we currently disconnected and hence unable to forward
   * requests?
   */
  int currently_down;
};


/**
 * Handle for a transmission request.
 */
struct GNUNET_CORE_TransmitHandle
{

  /**
   * We keep active transmit handles in a doubly-linked list.
   */
  struct GNUNET_CORE_TransmitHandle *next;

  /**
   * We keep active transmit handles in a doubly-linked list.
   */
  struct GNUNET_CORE_TransmitHandle *prev;

  /**
   * Corresponding core handle.
   */
  struct GNUNET_CORE_Handle *ch;

  /**
   * Function that will be called to get the actual request
   * (once we are ready to transmit this request to the core).
   * The function will be called with a NULL buffer to signal
   * timeout.
   */
  GNUNET_NETWORK_TransmitReadyNotify get_message;

  /**
   * Closure for get_message.
   */
  void *get_message_cls;

  /**
   * If this entry is for a configuration request, pointer
   * to the information callback; otherwise NULL.
   */
  GNUNET_CORE_PeerConfigurationInfoCallback info;

  /**
   * Closure for info.
   */
  void *info_cls;

  /**
   * If this entry is for a transmission request, pointer
   * to the notify callback; otherwise NULL.
   */
  GNUNET_NETWORK_TransmitReadyNotify notify;

  /**
   * Closure for notify.
   */
  void *notify_cls;

  /**
   * Peer the request is about.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Timeout for this handle.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * ID of timeout task.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * How important is this message?
   */
  uint32_t priority;

  /**
   * Size of this request.
   */
  uint16_t msize;


};


/**
 * Function called when we are ready to transmit our
 * "START" message (or when this operation timed out).
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t transmit_start (void *cls, size_t size, void *buf);


/**
 * Our current client connection went down.  Clean it up
 * and try to reconnect!
 */
static void
reconnect (struct GNUNET_CORE_Handle *h)
{
  GNUNET_CLIENT_disconnect (h->client);
  h->currently_down = GNUNET_YES;
  h->client = GNUNET_CLIENT_connect (h->sched, "core", h->cfg);
  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client,
                                               sizeof (struct InitMessage) +
                                               sizeof (uint16_t) * h->hcnt,
                                               GNUNET_TIME_UNIT_SECONDS,
                                               &transmit_start, h);
}


/**
 * The given request hit its timeout.  Remove from the
 * doubly-linked list and call the respective continuation.
 *
 * @param cls the transmit handle of the request that timed out
 * @param tc context, can be NULL (!)
 */
static void
timeout_request (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CORE_TransmitHandle *th = cls;
  struct GNUNET_CORE_Handle *h;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmission request timed out.\n");
  h = th->ch;
  th->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (0 == th->get_message (th->get_message_cls, 0, NULL));
  GNUNET_CORE_notify_transmit_ready_cancel (th);
}


/**
 * Function called when we are ready to transmit a request from our
 * request list (or when this operation timed out).
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
request_start (void *cls, size_t size, void *buf)
{
  struct GNUNET_CORE_Handle *h = cls;
  struct GNUNET_CORE_TransmitHandle *th;
  size_t ret;

  h->th = NULL;
  th = h->pending_head;
  if (buf == NULL)
    {
      timeout_request (th, NULL);
      return 0;
    }
  /* create new timeout task (in case core takes too long to respond!) */
  th->timeout_task = GNUNET_SCHEDULER_add_delayed (h->sched,
                                                   GNUNET_NO,
                                                   GNUNET_SCHEDULER_PRIORITY_KEEP,
                                                   GNUNET_SCHEDULER_NO_TASK,
                                                   GNUNET_TIME_absolute_get_remaining
                                                   (th->timeout),
                                                   &timeout_request, th);
  /* remove th from doubly-linked pending list, move to submitted */
  GNUNET_assert (th->prev == NULL);
  h->pending_head = th->next;
  if (th->next == NULL)
    h->pending_tail = NULL;
  else
    th->next->prev = NULL;
  GNUNET_assert (h->submitted == NULL);
  h->submitted = th;
  GNUNET_assert (size >= th->msize);
  ret = th->get_message (th->get_message_cls, size, buf);
  GNUNET_assert (ret <= size);
  return ret;
}


/**
 * Check the list of pending requests, send the next
 * one to the core.
 */
static void
trigger_next_request (struct GNUNET_CORE_Handle *h)
{
  struct GNUNET_CORE_TransmitHandle *th;
  if (h->currently_down)
    return;                     /* connection temporarily down */
  if (NULL == (th = h->pending_head))
    return;                     /* no requests pending */
  GNUNET_assert (NULL == h->th);
  GNUNET_SCHEDULER_cancel (h->sched, th->timeout_task);
  th->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client,
                                               th->msize,
                                               GNUNET_TIME_absolute_get_remaining
                                               (th->timeout), &request_start,
                                               h);
}


/**
 * cls is a pointer to a 32 bit number followed by that
 * amount of data.  If possible, copy to buf and return
 * number of bytes copied.  Always free the buffer.
 */
static size_t
copy_and_free (void *cls, size_t size, void *buf)
{
  char *cbuf = cls;
  uint32_t have;

  memcpy (&have, cbuf, sizeof (uint32_t));
  if (have > size)
    {
      /* timeout / error case */
      GNUNET_free (cbuf);
      return 0;
    }
  memcpy (buf, cbuf + sizeof (uint32_t), have);
  GNUNET_free (cbuf);
  return have;
}


/**
 * Call bfc callback to solicit traffic for the given peer.
 */
static void
solicit_traffic (struct GNUNET_CORE_Handle *h,
                 const struct GNUNET_PeerIdentity *peer, uint32_t amount)
{
  char buf[amount];
  size_t have;
  char *cbuf;

  have = h->bfc (h->cls, peer, buf, amount);
  if (have == 0)
    return;
  GNUNET_assert (have >= sizeof (struct GNUNET_MessageHeader));
  cbuf = GNUNET_malloc (have + sizeof (uint32_t));
  memcpy (cbuf, &have, sizeof (uint32_t));
  memcpy (cbuf + sizeof (uint32_t), buf, have);
  GNUNET_CORE_notify_transmit_ready (h,
                                     0,
                                     GNUNET_TIME_UNIT_SECONDS,
                                     peer, have, &copy_and_free, cbuf);
}


/**
 * Handler for most messages received from the core.
 */
static void
main_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CORE_Handle *h = cls;
  unsigned int hpos;
  const struct ConnectNotifyMessage *cnm;
  const struct NotifyTrafficMessage *ntm;
  const struct ConfigurationInfoMessage *cim;
  const struct SolicitTrafficMessage *stm;
  const struct GNUNET_MessageHeader *em;
  uint16_t msize;
  uint16_t et;
  uint32_t ss;
  const struct GNUNET_CORE_MessageHandler *mh;

  if (msg == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Client was disconnected from core service, trying to reconnect.\n"));
      reconnect (h);
      return;
    }
  msize = ntohs (msg->size);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing message of type %u and size %u from core service\n",
              ntohs (msg->type), msize);
#endif
  switch (ntohs (msg->type))
    {
    case GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT:
      if (NULL == h->connects)
        {
          GNUNET_break (0);
          break;
        }
      if (msize != sizeof (struct ConnectNotifyMessage))
        {
          GNUNET_break (0);
          break;
        }
      cnm = (const struct ConnectNotifyMessage *) msg;
      h->connects (h->cls,
		   &cnm->peer);
      break;
    case GNUNET_MESSAGE_TYPE_CORE_NOTIFY_DISCONNECT:
      if (NULL == h->disconnects)
        {
          GNUNET_break (0);
          break;
        }
      if (msize != sizeof (struct ConnectNotifyMessage))
        {
          GNUNET_break (0);
          break;
        }
      cnm = (const struct ConnectNotifyMessage *) msg;
      h->disconnects (h->cls,
		      &cnm->peer);
      break;
    case GNUNET_MESSAGE_TYPE_CORE_NOTIFY_INBOUND:
      if (msize <
          sizeof (struct NotifyTrafficMessage) +
          sizeof (struct GNUNET_MessageHeader))
        {
          GNUNET_break (0);
          break;
        }
      ntm = (const struct NotifyTrafficMessage *) msg;
      em = (const struct GNUNET_MessageHeader *) &ntm[1];
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received message of type %u from peer `%4s'\n",
                  ntohs (em->type), GNUNET_i2s (&ntm->peer));
#endif
      if ((GNUNET_NO == h->inbound_hdr_only) &&
          (msize != ntohs (em->size) + sizeof (struct NotifyTrafficMessage)))
        {
          GNUNET_break (0);
          break;
        }
      et = ntohs (em->type);
      for (hpos = 0; hpos < h->hcnt; hpos++)
        {
          mh = &h->handlers[hpos];
          if (mh->type != et)
            continue;
          if ((mh->expected_size != ntohs (em->size)) &&
              (mh->expected_size != 0))
            {
              GNUNET_break (0);
              continue;
            }
          if (GNUNET_OK !=
              h->handlers[hpos].callback (h->cls, &ntm->peer, em))
            {
              /* error in processing, disconnect ! */
              reconnect (h);
              return;
            }
        }
      if (NULL != h->inbound_notify)
        h->inbound_notify (h->cls, &ntm->peer, em);
      break;
    case GNUNET_MESSAGE_TYPE_CORE_NOTIFY_OUTBOUND:
      if (msize <
          sizeof (struct NotifyTrafficMessage) +
          sizeof (struct GNUNET_MessageHeader))
        {
          GNUNET_break (0);
          break;
        }
      ntm = (const struct NotifyTrafficMessage *) msg;
      em = (const struct GNUNET_MessageHeader *) &ntm[1];
      if ((GNUNET_NO == h->outbound_hdr_only) &&
          (msize != ntohs (em->size) + sizeof (struct NotifyTrafficMessage)))
        {
          GNUNET_break (0);
          break;
        }
      if (NULL == h->outbound_notify)
        {
          GNUNET_break (0);
          break;
        }
      h->outbound_notify (h->cls, &ntm->peer, em);
      break;
    case GNUNET_MESSAGE_TYPE_CORE_CONFIGURATION_INFO:
      if (msize != sizeof (struct ConfigurationInfoMessage))
        {
          GNUNET_break (0);
          break;
        }
      if (NULL == h->submitted)
        break;
      cim = (const struct ConfigurationInfoMessage *) msg;

      /* process configuration data */
      if (h->submitted->info != NULL)
        h->submitted->info (h->submitted->info_cls,
                            &h->submitted->peer,
                            ntohl (cim->bpm_in),
                            ntohl (cim->bpm_out),
                            GNUNET_TIME_relative_ntoh (cim->latency),
                            (int) ntohl (cim->reserved_amount),
                            cim->preference);
      /* done, clean up! */
      GNUNET_CORE_notify_transmit_ready_cancel (h->submitted);
      trigger_next_request (h);
      break;
    case GNUNET_MESSAGE_TYPE_CORE_SOLICIT_TRAFFIC:
      if (msize != sizeof (struct SolicitTrafficMessage))
        {
          GNUNET_break (0);
          break;
        }
      stm = (const struct SolicitTrafficMessage *) msg;
      if (NULL == h->bfc)
        {
          GNUNET_break (0);
          break;
        }
      ss = ntohl (stm->solicit_size);
      if ((ss > GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
          (ss + sizeof (struct SendMessage) > GNUNET_SERVER_MAX_MESSAGE_SIZE))
        {
          GNUNET_break (0);
          break;
        }
      solicit_traffic (h, &stm->peer, ss);
      break;
    default:
      GNUNET_break (0);
      break;
    }
  GNUNET_CLIENT_receive (h->client,
                         &main_handler, h, GNUNET_TIME_UNIT_FOREVER_REL);
}



/**
 * Function called when we are ready to transmit our
 * "START" message (or when this operation timed out).
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t transmit_start (void *cls, size_t size, void *buf);


/**
 * Function called on the first message received from
 * the service (contains our public key, etc.).
 * Should trigger calling the init callback
 * and then start our regular message processing.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
init_reply_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CORE_Handle *h = cls;
  const struct InitReplyMessage *m;
  GNUNET_CORE_StartupCallback init;
  struct GNUNET_PeerIdentity my_identity;

  if ((msg == NULL) ||
      (ntohs (msg->size) != sizeof (struct InitReplyMessage)) ||
      (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_CORE_INIT_REPLY))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _
                  ("Error connecting to core service (failed to receive `%s' message).\n"),
                  "INIT_REPLY");
      GNUNET_break (msg == NULL);
      transmit_start (h, 0, NULL);
      return;
    }
  m = (const struct InitReplyMessage *) msg;
  /* start our message processing loop */
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _
              ("Successfully connected to core service, starting processing loop.\n"));
#endif
  h->currently_down = GNUNET_NO;
  trigger_next_request (h);
  GNUNET_CLIENT_receive (h->client,
                         &main_handler, h, GNUNET_TIME_UNIT_FOREVER_REL);
  if (NULL != (init = h->init))
    {
      /* mark so we don't call init on reconnect */
      h->init = NULL;
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Successfully connected to core service.\n"));
#endif
      GNUNET_CRYPTO_hash (&m->publicKey,
                          sizeof (struct
                                  GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                          &my_identity.hashPubKey);
      init (h->cls, h, &my_identity, &m->publicKey);
    }
}


static void
reconnect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CORE_Handle *h = cls;
  h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  reconnect (h);
}


/**
 * Function called when we are ready to transmit our
 * "START" message (or when this operation timed out).
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_start (void *cls, size_t size, void *buf)
{
  struct GNUNET_CORE_Handle *h = cls;
  struct InitMessage *init;
  uint16_t *ts;
  uint16_t msize;
  uint32_t opt;
  unsigned int hpos;
  struct GNUNET_TIME_Relative delay;

  h->th = NULL;
  if (size == 0)
    {
      if ((h->init == NULL) ||
          (GNUNET_TIME_absolute_get ().value < h->startup_timeout.value))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      _("Failed to connect to core service, retrying.\n"));
          delay = GNUNET_TIME_absolute_get_remaining (h->startup_timeout);
          if ((h->init == NULL) || (delay.value > 1000))
            delay = GNUNET_TIME_UNIT_SECONDS;
          if (h->init == NULL)
            h->startup_timeout =
              GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES);
          h->reconnect_task =
            GNUNET_SCHEDULER_add_delayed (h->sched, GNUNET_NO,
                                          GNUNET_SCHEDULER_PRIORITY_IDLE,
                                          GNUNET_SCHEDULER_NO_TASK,
                                          delay, &reconnect_task, h);
          return 0;
        }
      /* timeout on initial connect */
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to connect to core service, giving up.\n"));
      h->init (h->cls, NULL, NULL, NULL);
      GNUNET_CORE_disconnect (h);
      return 0;
    }
  msize = h->hcnt * sizeof (uint16_t) + sizeof (struct InitMessage);
  GNUNET_assert (size >= msize);
  init = buf;
  init->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_INIT);
  init->header.size = htons (msize);
  opt = GNUNET_CORE_OPTION_NOTHING;
  if (h->connects != NULL)
    opt |= GNUNET_CORE_OPTION_SEND_CONNECT;
  if (h->disconnects != NULL)
    opt |= GNUNET_CORE_OPTION_SEND_DISCONNECT;
  if (h->bfc != NULL)
    opt |= GNUNET_CORE_OPTION_SEND_BFC;
  if (h->inbound_notify != NULL)
    {
      if (h->inbound_hdr_only)
        opt |= GNUNET_CORE_OPTION_SEND_HDR_INBOUND;
      else
        opt |= GNUNET_CORE_OPTION_SEND_FULL_INBOUND;
    }
  if (h->outbound_notify != NULL)
    {
      if (h->outbound_hdr_only)
        opt |= GNUNET_CORE_OPTION_SEND_HDR_OUTBOUND;
      else
        opt |= GNUNET_CORE_OPTION_SEND_FULL_OUTBOUND;
    }
  init->options = htonl (opt);
  ts = (uint16_t *) & init[1];
  for (hpos = 0; hpos < h->hcnt; hpos++)
    ts[hpos] = htons (h->handlers[hpos].type);
  GNUNET_CLIENT_receive (h->client,
                         &init_reply_handler,
                         h,
                         GNUNET_TIME_absolute_get_remaining
                         (h->startup_timeout));
  return sizeof (struct InitMessage) + h->hcnt * sizeof (uint16_t);
}


/**
 * Connect to the core service.  Note that the connection may
 * complete (or fail) asynchronously.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param timeout after how long should we give up trying to connect to the core service?
 * @param cls closure for the various callbacks that follow (including handlers in the handlers array)
 * @param init callback to call on timeout or once we have successfully
 *        connected to the core service
 * @param connects function to call on peer connect, can be NULL
 * @param disconnects function to call on peer disconnect / timeout, can be NULL
 * @param bfc function to call to fill up spare bandwidth, can be NULL
 * @param inbound_notify function to call for all inbound messages, can be NULL
 * @param inbound_hdr_only set to GNUNET_YES if inbound_notify will only read the
 *                GNUNET_MessageHeader and hence we do not need to give it the full message;
 *                can be used to improve efficiency, ignored if inbound_notify is NULLL
 * @param outbound_notify function to call for all outbound messages, can be NULL
 * @param outbound_hdr_only set to GNUNET_YES if outbound_notify will only read the
 *                GNUNET_MessageHeader and hence we do not need to give it the full message
 *                can be used to improve efficiency, ignored if outbound_notify is NULLL
 * @param handlers callbacks for messages we care about, NULL-terminated
 */
void
GNUNET_CORE_connect (struct GNUNET_SCHEDULER_Handle *sched,
                     const struct GNUNET_CONFIGURATION_Handle *cfg,
                     struct GNUNET_TIME_Relative timeout,
                     void *cls,
                     GNUNET_CORE_StartupCallback init,
                     GNUNET_CORE_ClientEventHandler connects,
                     GNUNET_CORE_ClientEventHandler disconnects,
                     GNUNET_CORE_BufferFillCallback bfc,
                     GNUNET_CORE_MessageCallback inbound_notify,
                     int inbound_hdr_only,
                     GNUNET_CORE_MessageCallback outbound_notify,
                     int outbound_hdr_only,
                     const struct GNUNET_CORE_MessageHandler *handlers)
{
  struct GNUNET_CORE_Handle *h;

  GNUNET_assert (init != NULL);
  h = GNUNET_malloc (sizeof (struct GNUNET_CORE_Handle));
  h->sched = sched;
  h->cfg = cfg;
  h->cls = cls;
  h->init = init;
  h->connects = connects;
  h->disconnects = disconnects;
  h->bfc = bfc;
  h->inbound_notify = inbound_notify;
  h->outbound_notify = outbound_notify;
  h->inbound_hdr_only = inbound_hdr_only;
  h->outbound_hdr_only = outbound_hdr_only;
  h->handlers = handlers;
  h->client = GNUNET_CLIENT_connect (sched, "core", cfg);
  h->startup_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  h->hcnt = 0;
  while (handlers[h->hcnt].callback != NULL)
    h->hcnt++;
  GNUNET_assert (h->hcnt <
                 (GNUNET_SERVER_MAX_MESSAGE_SIZE -
                  sizeof (struct InitMessage)) / sizeof (uint16_t));
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Trying to connect to core service in next %llu ms.\n",
              timeout.value);
#endif
  h->th =
    GNUNET_CLIENT_notify_transmit_ready (h->client,
                                         sizeof (struct InitMessage) +
                                         sizeof (uint16_t) * h->hcnt, timeout,
                                         &transmit_start, h);
}


/**
 * Disconnect from the core service.
 *
 * @param handle connection to core to disconnect
 */
void
GNUNET_CORE_disconnect (struct GNUNET_CORE_Handle *handle)
{
  if (handle->th != NULL)
    GNUNET_NETWORK_connection_notify_transmit_ready_cancel (handle->th);
  if (handle->reconnect_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (handle->sched, handle->reconnect_task);
  GNUNET_CLIENT_disconnect (handle->client);
  GNUNET_free (handle);
}


/**
 * Build the configure message.
 */
static size_t
produce_configure_message (void *cls, size_t size, void *buf)
{
  struct GNUNET_CORE_TransmitHandle *th = cls;
  struct GNUNET_CORE_Handle *ch = th->ch;

  if (buf == NULL)
    {
      /* communicate handle timeout/error! */
      if (th->info != NULL)
        th->info (th->info_cls, NULL, 0, 0, GNUNET_TIME_UNIT_ZERO, 0, 0.0);
      if (th->timeout_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_CORE_notify_transmit_ready_cancel (th);
      if (ch->submitted == th)
        ch->submitted = NULL;
      trigger_next_request (ch);
      return 0;
    }
  GNUNET_assert (size >= sizeof (struct RequestConfigureMessage));
  memcpy (buf, &th[1], sizeof (struct RequestConfigureMessage));
  if (th->prev == NULL)
    ch->pending_head = th->next;
  else
    th->prev->next = th->next;
  if (th->next == NULL)
    ch->pending_tail = th->prev;
  else
    th->next->prev = th->prev;
  GNUNET_assert (ch->submitted == NULL);
  ch->submitted = th;
  return sizeof (struct RequestConfigureMessage);
}


/**
 * Obtain statistics and/or change preferences for the given peer.
 *
 * @param handle connection to core to use
 * @param peer identifies the peer
 * @param timeout after how long should we give up (and call "info" with NULL
 *                for "peer" to signal an error)?
 * @param bpm_out set to the current bandwidth limit (sending) for this peer,
 *                caller should set "bpm_out" to "-1" to avoid changing
 *                the current value; otherwise "bpm_out" will be lowered to
 *                the specified value; passing a pointer to "0" can be used to force
 *                us to disconnect from the peer; "bpm_out" might not increase
 *                as specified since the upper bound is generally
 *                determined by the other peer!
 * @param amount reserve N bytes for receiving, negative
 *                amounts can be used to undo a (recent) reservation;
 * @param preference increase incoming traffic share preference by this amount;
 *                in the absence of "amount" reservations, we use this
 *                preference value to assign proportional bandwidth shares
 *                to all connected peers
 * @param info function to call with the resulting configuration information
 * @param info_cls closure for info
 */
void
GNUNET_CORE_peer_configure (struct GNUNET_CORE_Handle *handle,
                            const struct GNUNET_PeerIdentity *peer,
                            struct GNUNET_TIME_Relative timeout,
                            unsigned int bpm_out,
                            int amount,
                            unsigned long long preference,
                            GNUNET_CORE_PeerConfigurationInfoCallback info,
                            void *info_cls)
{
  struct RequestConfigureMessage *rcm;
  struct GNUNET_CORE_TransmitHandle *th;

  th = GNUNET_malloc (sizeof (struct GNUNET_CORE_TransmitHandle) +
                      sizeof (struct RequestConfigureMessage));
  /* append to list */
  th->prev = handle->pending_tail;
  if (handle->pending_tail == NULL)
    handle->pending_head = th;
  else
    handle->pending_tail->next = th;
  th->ch = handle;
  th->get_message = &produce_configure_message;
  th->get_message_cls = th;
  th->info = info;
  th->info_cls = info_cls;
  th->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  th->timeout_task = GNUNET_SCHEDULER_add_delayed (handle->sched,
                                                   GNUNET_NO,
                                                   GNUNET_SCHEDULER_PRIORITY_KEEP,
                                                   GNUNET_SCHEDULER_NO_TASK,
                                                   timeout,
                                                   &timeout_request, th);
  th->msize = sizeof (struct RequestConfigureMessage);
  rcm = (struct RequestConfigureMessage *) &th[1];
  rcm->header.size = htons (sizeof (struct RequestConfigureMessage));
  rcm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_REQUEST_CONFIGURE);
  rcm->reserved = htonl (0);
  rcm->limit_outbound_bpm = htonl (bpm_out);
  rcm->reserve_inbound = htonl (amount);
  rcm->preference_change = GNUNET_htonll(preference);
  rcm->peer = *peer;
  if (handle->pending_head == th)
    trigger_next_request (handle);
}


/**
 * Build the message requesting data transmission.
 */
static size_t
produce_send (void *cls, size_t size, void *buf)
{
  struct GNUNET_CORE_TransmitHandle *th = cls;
  struct GNUNET_CORE_Handle *h;
  struct SendMessage *sm;
  size_t dt;
  GNUNET_NETWORK_TransmitReadyNotify notify;
  void *notify_cls;

  h = th->ch;
  if (buf == NULL)
    {
      /* timeout or error */
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "P2P transmission request for `%4s' timed out.\n",
		  GNUNET_i2s(&th->peer));
#endif
      GNUNET_assert (0 == th->notify (th->notify_cls, 0, NULL));
      if (th->timeout_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_CORE_notify_transmit_ready_cancel (th);
      trigger_next_request (h);
      return 0;
    }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Preparing for P2P transmission to `%4s'.\n",
	      GNUNET_i2s(&th->peer));
#endif
  GNUNET_assert (th->timeout_task != GNUNET_SCHEDULER_NO_TASK);
  sm = (struct SendMessage *) buf;
  sm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_SEND);
  sm->priority = htonl (th->priority);
  sm->deadline = GNUNET_TIME_absolute_hton (th->timeout);
  sm->peer = th->peer;
  notify = th->notify;
  notify_cls = th->notify_cls;
  GNUNET_CORE_notify_transmit_ready_cancel (th);
  trigger_next_request (h);
  GNUNET_assert (size >= sizeof (struct SendMessage));
  dt = notify (notify_cls, size - sizeof (struct SendMessage), &sm[1]);
  sm->header.size = htons (dt + sizeof (struct SendMessage));
  GNUNET_assert (dt + sizeof (struct SendMessage) < size);
  return dt + sizeof (struct SendMessage);
}


/**
 * Ask the core to call "notify" once it is ready to transmit the
 * given number of bytes to the specified "target".  If we are not yet
 * connected to the specified peer, a call to this function will cause
 * us to try to establish a connection.
 *
 * @param handle connection to core service
 * @param priority how important is the message?
 * @param maxdelay how long can the message wait?
 * @param target who should receive the message,
 *        use NULL for this peer (loopback)
 * @param notify_size how many bytes of buffer space does notify want?
 * @param notify function to call when buffer space is available
 * @param notify_cls closure for notify
 * @return non-NULL if the notify callback was queued,
 *         NULL if we can not even queue the request (insufficient
 *         memory); if NULL is returned, "notify" will NOT be called.
 */
struct GNUNET_CORE_TransmitHandle *
GNUNET_CORE_notify_transmit_ready (struct GNUNET_CORE_Handle *handle,
                                   unsigned int priority,
                                   struct GNUNET_TIME_Relative maxdelay,
                                   const struct GNUNET_PeerIdentity *target,
                                   size_t notify_size,
                                   GNUNET_NETWORK_TransmitReadyNotify notify,
                                   void *notify_cls)
{
  struct GNUNET_CORE_TransmitHandle *th;

  GNUNET_assert (notify_size + sizeof (struct SendMessage) <
                 GNUNET_SERVER_MAX_MESSAGE_SIZE);
  th = GNUNET_malloc (sizeof (struct GNUNET_CORE_TransmitHandle));
  th->ch = handle;
  /* append to list */
  th->prev = handle->pending_tail;
  if (handle->pending_tail == NULL)
    handle->pending_head = th;
  else
    handle->pending_tail->next = th;
  th->get_message = &produce_send;
  th->get_message_cls = th;
  th->notify = notify;
  th->notify_cls = notify_cls;
  th->peer = *target;
  th->timeout = GNUNET_TIME_relative_to_absolute (maxdelay);
  th->timeout_task = GNUNET_SCHEDULER_add_delayed (handle->sched,
                                                   GNUNET_NO,
                                                   GNUNET_SCHEDULER_PRIORITY_KEEP,
                                                   GNUNET_SCHEDULER_NO_TASK,
                                                   maxdelay,
                                                   &timeout_request, th);
  th->priority = priority;
  th->msize = sizeof (struct SendMessage) + notify_size;
  /* was the request queue previously empty? */
  if (handle->pending_head == th)
    trigger_next_request (handle);
  return th;
}


/**
 * Cancel the specified transmission-ready notification.
 *
 * @param h handle that was returned by "notify_transmit_ready".
 */
void
GNUNET_CORE_notify_transmit_ready_cancel (struct GNUNET_CORE_TransmitHandle
                                          *h)
{
  struct GNUNET_CORE_Handle *handle = h->ch;

  if (handle->submitted == h)
    {
      handle->submitted = NULL;
    }
  else
    {
      if (h->prev == NULL)
        handle->pending_head = h->next;
      else
        h->prev->next = h->next;
      if (h->next == NULL)
        handle->pending_tail = h->prev;
      else
        h->next->prev = h->prev;
    }
  if (h->timeout_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (handle->sched, h->timeout_task);
  GNUNET_free (h);
}


/* end of core_api.c */
