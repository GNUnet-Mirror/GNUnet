/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2012, 2016 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file dht/dht_api.c
 * @brief library to access the DHT service
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_service.h"
#include "dht.h"

#define LOG(kind,...) GNUNET_log_from (kind, "dht-api",__VA_ARGS__)


/**
 * Handle to a PUT request.
 */
struct GNUNET_DHT_PutHandle
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_DHT_PutHandle *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_DHT_PutHandle *prev;

  /**
   * Continuation to call when done.
   */
  GNUNET_DHT_PutContinuation cont;

  /**
   * Main handle to this DHT api
   */
  struct GNUNET_DHT_Handle *dht_handle;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;

  /**
   * Unique ID for the PUT operation.
   */
  uint64_t unique_id;

};

/**
 * Handle to a GET request
 */
struct GNUNET_DHT_GetHandle
{

  /**
   * Iterator to call on data receipt
   */
  GNUNET_DHT_GetIterator iter;

  /**
   * Closure for @a iter.
   */
  void *iter_cls;

  /**
   * Main handle to this DHT api
   */
  struct GNUNET_DHT_Handle *dht_handle;

  /**
   * Array of hash codes over the results that we have already
   * seen.
   */
  struct GNUNET_HashCode *seen_results;

  /**
   * Key that this get request is for
   */
  struct GNUNET_HashCode key;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint64_t unique_id;

  /**
   * Size of the extended query, allocated at the end of this struct.
   */
  size_t xquery_size;

  /**
   * Desired replication level.
   */
  uint32_t desired_replication_level;

  /**
   * Type of the block we are looking for.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Routing options.
   */
  enum GNUNET_DHT_RouteOption options;

  /**
   * Size of the @e seen_results array.  Note that not
   * all positions might be used (as we over-allocate).
   */
  unsigned int seen_results_size;

  /**
   * Offset into the @e seen_results array marking the
   * end of the positions that are actually used.
   */
  unsigned int seen_results_end;

};


/**
 * Handle to a monitoring request.
 */
struct GNUNET_DHT_MonitorHandle
{
  /**
   * DLL.
   */
  struct GNUNET_DHT_MonitorHandle *next;

  /**
   * DLL.
   */
  struct GNUNET_DHT_MonitorHandle *prev;

  /**
   * Main handle to this DHT api.
   */
  struct GNUNET_DHT_Handle *dht_handle;

  /**
   * Type of block looked for.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Key being looked for, NULL == all.
   */
  struct GNUNET_HashCode *key;

  /**
   * Callback for each received message of type get.
   */
  GNUNET_DHT_MonitorGetCB get_cb;

  /**
   * Callback for each received message of type get response.
   */
  GNUNET_DHT_MonitorGetRespCB get_resp_cb;

  /**
   * Callback for each received message of type put.
   */
  GNUNET_DHT_MonitorPutCB put_cb;

  /**
   * Closure for @e get_cb, @e put_cb and @e get_resp_cb.
   */
  void *cb_cls;

};


/**
 * Connection to the DHT service.
 */
struct GNUNET_DHT_Handle
{

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Connection to DHT service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Head of linked list of messages we would like to monitor.
   */
  struct GNUNET_DHT_MonitorHandle *monitor_head;

  /**
   * Tail of linked list of messages we would like to monitor.
   */
  struct GNUNET_DHT_MonitorHandle *monitor_tail;

  /**
   * Head of active PUT requests.
   */
  struct GNUNET_DHT_PutHandle *put_head;

  /**
   * Tail of active PUT requests.
   */
  struct GNUNET_DHT_PutHandle *put_tail;

  /**
   * Hash map containing the current outstanding unique GET requests
   * (values are of type `struct GNUNET_DHT_GetHandle`).
   */
  struct GNUNET_CONTAINER_MultiHashMap *active_requests;

  /**
   * Task for trying to reconnect.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * How quickly should we retry?  Used for exponential back-off on
   * connect-errors.
   */
  struct GNUNET_TIME_Relative retry_time;

  /**
   * Generator for unique ids.
   */
  uint64_t uid_gen;


};


/**
 * Try to (re)connect to the DHT service.
 *
 * @param h DHT handle to reconnect
 * @return #GNUNET_YES on success, #GNUNET_NO on failure.
 */
static int
try_connect (struct GNUNET_DHT_Handle *h);


/**
 * Send GET message for a @a get_handle to DHT.
 *
 * @param gh GET to generate messages for.
 */
static void
send_get (struct GNUNET_DHT_GetHandle *gh)
{
  struct GNUNET_DHT_Handle *h = gh->dht_handle;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DHT_ClientGetMessage *get_msg;

  env = GNUNET_MQ_msg_extra (get_msg,
                             gh->xquery_size,
                             GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET);
  get_msg->options = htonl ((uint32_t) gh->options);
  get_msg->desired_replication_level = htonl (gh->desired_replication_level);
  get_msg->type = htonl (gh->type);
  get_msg->key = gh->key;
  get_msg->unique_id = gh->unique_id;
  GNUNET_memcpy (&get_msg[1],
          &gh[1],
          gh->xquery_size);
  GNUNET_MQ_send (h->mq,
                  env);
}


/**
 * Send GET message(s) for indicating which results are already known
 * for a @a get_handle to DHT.  Complex as we need to send the list of
 * known results, which means we may need mulitple messages to block
 * known results from the result set.
 *
 * @param gh GET to generate messages for
 * @param transmission_offset_start at which offset should we start?
 */
static void
send_get_known_results (struct GNUNET_DHT_GetHandle *gh,
                        unsigned int transmission_offset_start)
{
  struct GNUNET_DHT_Handle *h = gh->dht_handle;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DHT_ClientGetResultSeenMessage *msg;
  unsigned int delta;
  unsigned int max;
  unsigned int transmission_offset;

  max = (GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (*msg))
    / sizeof (struct GNUNET_HashCode);
  transmission_offset = transmission_offset_start;
  while (transmission_offset < gh->seen_results_end)
  {
    delta = gh->seen_results_end - transmission_offset;
    if (delta > max)
      delta = max;
    env = GNUNET_MQ_msg_extra (msg,
                               delta * sizeof (struct GNUNET_HashCode),
                               GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_RESULTS_KNOWN);
    msg->key = gh->key;
    msg->unique_id = gh->unique_id;
    GNUNET_memcpy (&msg[1],
	    &gh->seen_results[transmission_offset],
	    sizeof (struct GNUNET_HashCode) * delta);
    GNUNET_MQ_send (h->mq,
                    env);
    transmission_offset += delta;
  }
}


/**
 * Add the GET request corresponding to the given route handle
 * to the pending queue (if it is not already in there).
 *
 * @param cls the `struct GNUNET_DHT_Handle *`
 * @param key key for the request (not used)
 * @param value the `struct GNUNET_DHT_GetHandle *`
 * @return #GNUNET_YES (always)
 */
static int
add_get_request_to_pending (void *cls,
                            const struct GNUNET_HashCode *key,
                            void *value)
{
  struct GNUNET_DHT_Handle *handle = cls;
  struct GNUNET_DHT_GetHandle *gh = value;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Retransmitting request related to %s to DHT %p\n",
       GNUNET_h2s (key),
       handle);
  send_get (gh);
  send_get_known_results (gh, 0);
  return GNUNET_YES;
}


/**
 * Send #GNUNET_MESSAGE_TYPE_DHT_MONITOR_START message.
 *
 * @param mh monitor handle to generate start message for
 */
static void
send_monitor_start (struct GNUNET_DHT_MonitorHandle *mh)
{
  struct GNUNET_DHT_Handle *h = mh->dht_handle;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DHT_MonitorStartStopMessage *m;

  env = GNUNET_MQ_msg (m,
                       GNUNET_MESSAGE_TYPE_DHT_MONITOR_START);
  m->type = htonl (mh->type);
  m->get = htons (NULL != mh->get_cb);
  m->get_resp = htons (NULL != mh->get_resp_cb);
  m->put = htons (NULL != mh->put_cb);
  if (NULL != mh->key)
  {
    m->filter_key = htons(1);
    m->key = *mh->key;
  }
  GNUNET_MQ_send (h->mq,
                  env);
}


/**
 * Try reconnecting to the dht service.
 *
 * @param cls a `struct GNUNET_DHT_Handle`
 */
static void
try_reconnect (void *cls)
{
  struct GNUNET_DHT_Handle *h = cls;
  struct GNUNET_DHT_MonitorHandle *mh;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Reconnecting with DHT %p\n",
       h);
  h->retry_time = GNUNET_TIME_STD_BACKOFF (h->retry_time);
  h->reconnect_task = NULL;
  if (GNUNET_YES != try_connect (h))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "DHT reconnect failed!\n");
    h->reconnect_task
      = GNUNET_SCHEDULER_add_delayed (h->retry_time,
                                      &try_reconnect,
                                      h);
    return;
  }
  GNUNET_CONTAINER_multihashmap_iterate (h->active_requests,
                                         &add_get_request_to_pending,
                                         h);
  for (mh = h->monitor_head; NULL != mh; mh = mh->next)
    send_monitor_start (mh);
}


/**
 * Try reconnecting to the DHT service.
 *
 * @param h handle to dht to (possibly) disconnect and reconnect
 */
static void
do_disconnect (struct GNUNET_DHT_Handle *h)
{
  struct GNUNET_DHT_PutHandle *ph;
  GNUNET_DHT_PutContinuation cont;
  void *cont_cls;

  if (NULL == h->mq)
    return;
  GNUNET_MQ_destroy (h->mq);
  h->mq = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting from DHT service, will try to reconnect in %s\n",
              GNUNET_STRINGS_relative_time_to_string (h->retry_time,
						      GNUNET_YES));
  /* notify client about all PUTs that (may) have failed due to disconnect */
  while (NULL != (ph = h->put_head))
  {
    cont = ph->cont;
    cont_cls = ph->cont_cls;
    GNUNET_DHT_put_cancel (ph);
    if (NULL != cont)
      cont (cont_cls,
            GNUNET_SYSERR);
  }
  GNUNET_assert (NULL == h->reconnect_task);
  h->reconnect_task
    = GNUNET_SCHEDULER_add_delayed (h->retry_time,
                                    &try_reconnect,
                                    h);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_DHT_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_DHT_Handle *h = cls;

  do_disconnect (h);
}


/**
 * Verify integrity of a get monitor message from the service.
 *
 * @param cls The DHT handle.
 * @param msg Monitor get message from the service.
 * @return #GNUNET_OK if everything went fine,
 *         #GNUNET_SYSERR if the message is malformed.
 */
static int
check_monitor_get (void *cls,
                   const struct GNUNET_DHT_MonitorGetMessage *msg)
{
  uint32_t plen = ntohl (msg->get_path_length);
  uint16_t msize = ntohs (msg->header.size) - sizeof (*msg);

  if ( (plen > UINT16_MAX) ||
       (plen * sizeof (struct GNUNET_HashCode) != msize) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a get monitor message from the service.
 *
 * @param cls The DHT handle.
 * @param msg Monitor get message from the service.
 */
static void
handle_monitor_get (void *cls,
                    const struct GNUNET_DHT_MonitorGetMessage *msg)
{
  struct GNUNET_DHT_Handle *handle = cls;
  struct GNUNET_DHT_MonitorHandle *mh;

  for (mh = handle->monitor_head; NULL != mh; mh = mh->next)
  {
    if (NULL == mh->get_cb)
      continue;
    if ( ( (GNUNET_BLOCK_TYPE_ANY == mh->type) ||
           (mh->type == ntohl (msg->type)) ) &&
         ( (NULL == mh->key) ||
           (0 == memcmp (mh->key,
                         &msg->key,
                         sizeof (struct GNUNET_HashCode))) ) )
      mh->get_cb (mh->cb_cls,
                  ntohl (msg->options),
                  (enum GNUNET_BLOCK_Type) ntohl(msg->type),
                  ntohl (msg->hop_count),
                  ntohl (msg->desired_replication_level),
                  ntohl (msg->get_path_length),
                  (struct GNUNET_PeerIdentity *) &msg[1],
                  &msg->key);
  }
}


/**
 * Validate a get response monitor message from the service.
 *
 * @param cls The DHT handle.
 * @param msg monitor get response message from the service
 * @return #GNUNET_OK if everything went fine,
 *         #GNUNET_SYSERR if the message is malformed.
 */
static int
check_monitor_get_resp (void *cls,
                        const struct GNUNET_DHT_MonitorGetRespMessage *msg)
{
  size_t msize = ntohs (msg->header.size) - sizeof (*msg);
  uint32_t getl = ntohl (msg->get_path_length);
  uint32_t putl = ntohl (msg->put_path_length);

  if ( (getl + putl < getl) ||
       ( (msize / sizeof (struct GNUNET_PeerIdentity)) < getl + putl) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a get response monitor message from the service.
 *
 * @param cls The DHT handle.
 * @param msg monitor get response message from the service
 */
static void
handle_monitor_get_resp (void *cls,
                         const struct GNUNET_DHT_MonitorGetRespMessage *msg)
{
  struct GNUNET_DHT_Handle *handle = cls;
  size_t msize = ntohs (msg->header.size) - sizeof (*msg);
  const struct GNUNET_PeerIdentity *path;
  uint32_t getl = ntohl (msg->get_path_length);
  uint32_t putl = ntohl (msg->put_path_length);
  struct GNUNET_DHT_MonitorHandle *mh;

  path = (const struct GNUNET_PeerIdentity *) &msg[1];
  for (mh = handle->monitor_head; NULL != mh; mh = mh->next)
  {
    if (NULL == mh->get_resp_cb)
      continue;
    if ( ( (GNUNET_BLOCK_TYPE_ANY == mh->type) ||
           (mh->type == ntohl(msg->type)) ) &&
         ( (NULL == mh->key) ||
           (0 == memcmp (mh->key,
                         &msg->key,
                         sizeof (struct GNUNET_HashCode))) ) )
      mh->get_resp_cb (mh->cb_cls,
                       (enum GNUNET_BLOCK_Type) ntohl (msg->type),
                       path,
                       getl,
                       &path[getl],
                       putl,
                       GNUNET_TIME_absolute_ntoh(msg->expiration_time),
                       &msg->key,
                       (const void *) &path[getl + putl],
                       msize - sizeof (struct GNUNET_PeerIdentity) * (putl + getl));
  }
}


/**
 * Check validity of a put monitor message from the service.
 *
 * @param cls The DHT handle.
 * @param msg Monitor put message from the service.
 * @return #GNUNET_OK if everything went fine,
 *         #GNUNET_SYSERR if the message is malformed.
 */
static int
check_monitor_put (void *cls,
                   const struct GNUNET_DHT_MonitorPutMessage *msg)
{
  size_t msize;
  uint32_t putl;

  msize = ntohs (msg->header.size) - sizeof (*msg);
  putl = ntohl (msg->put_path_length);
  if ((msize / sizeof (struct GNUNET_PeerIdentity)) < putl)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a put monitor message from the service.
 *
 * @param cls The DHT handle.
 * @param msg Monitor put message from the service.
 */
static void
handle_monitor_put (void *cls,
                    const struct GNUNET_DHT_MonitorPutMessage *msg)
{
  struct GNUNET_DHT_Handle *handle = cls;
  size_t msize = ntohs (msg->header.size) - sizeof (*msg);
  uint32_t putl = ntohl (msg->put_path_length);
  const struct GNUNET_PeerIdentity *path;
  struct GNUNET_DHT_MonitorHandle *mh;

  path = (const struct GNUNET_PeerIdentity *) &msg[1];
  for (mh = handle->monitor_head; NULL != mh; mh = mh->next)
  {
    if (NULL == mh->put_cb)
      continue;
    if ( ( (GNUNET_BLOCK_TYPE_ANY == mh->type) ||
           (mh->type == ntohl(msg->type)) ) &&
         ( (NULL == mh->key) ||
           (0 == memcmp (mh->key,
                         &msg->key,
                         sizeof (struct GNUNET_HashCode))) ) )
      mh->put_cb (mh->cb_cls,
                  ntohl (msg->options),
                  (enum GNUNET_BLOCK_Type) ntohl(msg->type),
                  ntohl (msg->hop_count),
                  ntohl (msg->desired_replication_level),
                  putl,
                  path,
                  GNUNET_TIME_absolute_ntoh(msg->expiration_time),
                  &msg->key,
                  (const void *) &path[putl],
                  msize - sizeof (struct GNUNET_PeerIdentity) * putl);
  }
}


/**
 * Verify that client result  message received from the service is well-formed.
 *
 * @param cls The DHT handle.
 * @param msg Monitor put message from the service.
 * @return #GNUNET_OK if everything went fine,
 *         #GNUNET_SYSERR if the message is malformed.
 */
static int
check_client_result (void *cls,
                     const struct GNUNET_DHT_ClientResultMessage *msg)
{
  size_t msize = ntohs (msg->header.size) - sizeof (*msg);
  uint32_t put_path_length = ntohl (msg->put_path_length);
  uint32_t get_path_length = ntohl (msg->get_path_length);
  size_t meta_length;

  meta_length =
    sizeof (struct GNUNET_PeerIdentity) * (get_path_length + put_path_length);
  if ( (msize < meta_length) ||
       (get_path_length >
        GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)) ||
       (put_path_length >
        GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a given reply that might match the given request.
 *
 * @param cls the `struct GNUNET_DHT_ClientResultMessage`
 * @param key query of the request
 * @param value the `struct GNUNET_DHT_GetHandle` of a request matching the same key
 * @return #GNUNET_YES to continue to iterate over all results
 */
static int
process_client_result (void *cls,
                       const struct GNUNET_HashCode *key,
                       void *value)
{
  const struct GNUNET_DHT_ClientResultMessage *crm = cls;
  struct GNUNET_DHT_GetHandle *get_handle = value;
  size_t msize = ntohs (crm->header.size) - sizeof (*crm);
  uint32_t put_path_length = ntohl (crm->put_path_length);
  uint32_t get_path_length = ntohl (crm->get_path_length);
  const struct GNUNET_PeerIdentity *put_path;
  const struct GNUNET_PeerIdentity *get_path;
  struct GNUNET_HashCode hc;
  size_t data_length;
  size_t meta_length;
  const void *data;

  if (crm->unique_id != get_handle->unique_id)
  {
    /* UID mismatch */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ignoring reply for %s: UID mismatch: %llu/%llu\n",
         GNUNET_h2s (key),
         crm->unique_id,
         get_handle->unique_id);
    return GNUNET_YES;
  }
  /* FIXME: might want to check that type matches */
  meta_length =
      sizeof (struct GNUNET_PeerIdentity) * (get_path_length + put_path_length);
  data_length = msize - meta_length;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Giving %u byte reply for %s to application\n",
       (unsigned int) data_length,
       GNUNET_h2s (key));
  put_path = (const struct GNUNET_PeerIdentity *) &crm[1];
  get_path = &put_path[put_path_length];
  data = &get_path[get_path_length];
  /* remember that we've seen this result */
  GNUNET_CRYPTO_hash (data,
                      data_length,
                      &hc);
  if (get_handle->seen_results_size == get_handle->seen_results_end)
    GNUNET_array_grow (get_handle->seen_results,
		       get_handle->seen_results_size,
		       get_handle->seen_results_size * 2 + 1);
  get_handle->seen_results[get_handle->seen_results_end++] = hc;
  /* no need to block it explicitly, service already knows about it! */
  get_handle->iter (get_handle->iter_cls,
                    GNUNET_TIME_absolute_ntoh (crm->expiration),
                    key,
                    get_path,
                    get_path_length,
                    put_path,
                    put_path_length,
                    ntohl (crm->type),
                    data_length,
                    data);
  return GNUNET_YES;
}


/**
 * Process a client result  message received from the service.
 *
 * @param cls The DHT handle.
 * @param msg Monitor put message from the service.
 */
static void
handle_client_result (void *cls,
                      const struct GNUNET_DHT_ClientResultMessage *msg)
{
  struct GNUNET_DHT_Handle *handle = cls;

  GNUNET_CONTAINER_multihashmap_get_multiple (handle->active_requests,
                                              &msg->key,
                                              &process_client_result,
                                              (void *) msg);
}


/**
 * Process a put confirmation message from the service.
 *
 * @param cls The DHT handle.
 * @param msg confirmation message from the service.
 */
static void
handle_put_confirmation (void *cls,
                         const struct GNUNET_DHT_ClientPutConfirmationMessage *msg)
{
  struct GNUNET_DHT_Handle *handle = cls;
  struct GNUNET_DHT_PutHandle *ph;
  GNUNET_DHT_PutContinuation cont;
  void *cont_cls;

  for (ph = handle->put_head; NULL != ph; ph = ph->next)
    if (ph->unique_id == msg->unique_id)
      break;
  if (NULL == ph)
    return;
  cont = ph->cont;
  cont_cls = ph->cont_cls;
  GNUNET_DHT_put_cancel (ph);
  if (NULL != cont)
    cont (cont_cls,
          GNUNET_OK);
}


/**
 * Try to (re)connect to the DHT service.
 *
 * @param h DHT handle to reconnect
 * @return #GNUNET_YES on success, #GNUNET_NO on failure.
 */
static int
try_connect (struct GNUNET_DHT_Handle *h)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (monitor_get,
                           GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET,
                           struct GNUNET_DHT_MonitorGetMessage,
                           h),
    GNUNET_MQ_hd_var_size (monitor_get_resp,
                           GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET_RESP,
                           struct GNUNET_DHT_MonitorGetRespMessage,
                           h),
    GNUNET_MQ_hd_var_size (monitor_put,
                           GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT,
                           struct GNUNET_DHT_MonitorPutMessage,
                           h),
    GNUNET_MQ_hd_var_size (client_result,
                           GNUNET_MESSAGE_TYPE_DHT_CLIENT_RESULT,
                           struct GNUNET_DHT_ClientResultMessage,
                           h),
    GNUNET_MQ_hd_fixed_size (put_confirmation,
                             GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT_OK,
                             struct GNUNET_DHT_ClientPutConfirmationMessage,
                             h),
    GNUNET_MQ_handler_end ()
  };
  if (NULL != h->mq)
    return GNUNET_OK;
  h->mq = GNUNET_CLIENT_connecT (h->cfg,
                                 "dht",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Failed to connect to the DHT service!\n");
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Initialize the connection with the DHT service.
 *
 * @param cfg configuration to use
 * @param ht_len size of the internal hash table to use for
 *               processing multiple GET/FIND requests in parallel
 * @return handle to the DHT service, or NULL on error
 */
struct GNUNET_DHT_Handle *
GNUNET_DHT_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    unsigned int ht_len)
{
  struct GNUNET_DHT_Handle *handle;

  handle = GNUNET_new (struct GNUNET_DHT_Handle);
  handle->cfg = cfg;
  handle->uid_gen
    = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                UINT64_MAX);
  handle->active_requests
    = GNUNET_CONTAINER_multihashmap_create (ht_len,
                                            GNUNET_YES);
  if (GNUNET_NO == try_connect (handle))
  {
    GNUNET_DHT_disconnect (handle);
    return NULL;
  }
  return handle;
}


/**
 * Shutdown connection with the DHT service.
 *
 * @param handle handle of the DHT connection to stop
 */
void
GNUNET_DHT_disconnect (struct GNUNET_DHT_Handle *handle)
{
  struct GNUNET_DHT_PutHandle *ph;

  GNUNET_assert (0 ==
                 GNUNET_CONTAINER_multihashmap_size (handle->active_requests));
  while (NULL != (ph = handle->put_head))
  {
    if (NULL != ph->cont)
      ph->cont (ph->cont_cls,
                GNUNET_SYSERR);
    GNUNET_DHT_put_cancel (ph);
  }
  if (NULL != handle->mq)
  {
    GNUNET_MQ_destroy (handle->mq);
    handle->mq = NULL;
  }
  if (NULL != handle->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);
    handle->reconnect_task = NULL;
  }
  GNUNET_CONTAINER_multihashmap_destroy (handle->active_requests);
  GNUNET_free (handle);
}


/**
 * Perform a PUT operation storing data in the DHT.  FIXME: we should
 * change the protocol to get a confirmation for the PUT from the DHT
 * and call 'cont' only after getting the confirmation; otherwise, the
 * client has no good way of telling if the 'PUT' message actually got
 * to the DHT service!
 *
 * @param handle handle to DHT service
 * @param key the key to store under
 * @param desired_replication_level estimate of how many
 *                nearest peers this request should reach
 * @param options routing options for this message
 * @param type type of the value
 * @param size number of bytes in data; must be less than 64k
 * @param data the data to store
 * @param exp desired expiration time for the value
 * @param cont continuation to call when done (transmitting request to service)
 *        You must not call #GNUNET_DHT_disconnect in this continuation
 * @param cont_cls closure for @a cont
 */
struct GNUNET_DHT_PutHandle *
GNUNET_DHT_put (struct GNUNET_DHT_Handle *handle,
                const struct GNUNET_HashCode *key,
                uint32_t desired_replication_level,
                enum GNUNET_DHT_RouteOption options,
                enum GNUNET_BLOCK_Type type,
                size_t size,
                const void *data,
                struct GNUNET_TIME_Absolute exp,
                GNUNET_DHT_PutContinuation cont,
                void *cont_cls)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DHT_ClientPutMessage *put_msg;
  size_t msize;
  struct GNUNET_DHT_PutHandle *ph;

  msize = sizeof (struct GNUNET_DHT_ClientPutMessage) + size;
  if ((msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE))
  {
    GNUNET_break (0);
    return NULL;
  }
  if (NULL == handle->mq)
    return NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending PUT for %s to DHT via %p\n",
       GNUNET_h2s (key),
       handle);
  ph = GNUNET_new (struct GNUNET_DHT_PutHandle);
  ph->dht_handle = handle;
  ph->cont = cont;
  ph->cont_cls = cont_cls;
  ph->unique_id = ++handle->uid_gen;
  GNUNET_CONTAINER_DLL_insert_tail (handle->put_head,
				    handle->put_tail,
				    ph);
  env = GNUNET_MQ_msg_extra (put_msg,
                             size,
                             GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT);
  put_msg->type = htonl ((uint32_t) type);
  put_msg->options = htonl ((uint32_t) options);
  put_msg->desired_replication_level = htonl (desired_replication_level);
  put_msg->unique_id = ph->unique_id;
  put_msg->expiration = GNUNET_TIME_absolute_hton (exp);
  put_msg->key = *key;
  GNUNET_memcpy (&put_msg[1],
          data,
          size);
  GNUNET_MQ_send (handle->mq,
                  env);
  return ph;
}


/**
 * Cancels a DHT PUT operation.  Note that the PUT request may still
 * go out over the network (we can't stop that); However, if the PUT
 * has not yet been sent to the service, cancelling the PUT will stop
 * this from happening (but there is no way for the user of this API
 * to tell if that is the case).  The only use for this API is to
 * prevent a later call to 'cont' from #GNUNET_DHT_put (i.e. because
 * the system is shutting down).
 *
 * @param ph put operation to cancel ('cont' will no longer be called)
 */
void
GNUNET_DHT_put_cancel (struct GNUNET_DHT_PutHandle *ph)
{
  struct GNUNET_DHT_Handle *handle = ph->dht_handle;

  GNUNET_CONTAINER_DLL_remove (handle->put_head,
			       handle->put_tail,
			       ph);
  GNUNET_free (ph);
}


/**
 * Perform an asynchronous GET operation on the DHT identified. See
 * also #GNUNET_BLOCK_evaluate.
 *
 * @param handle handle to the DHT service
 * @param type expected type of the response object
 * @param key the key to look up
 * @param desired_replication_level estimate of how many
                  nearest peers this request should reach
 * @param options routing options for this message
 * @param xquery extended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in @a xquery
 * @param iter function to call on each result
 * @param iter_cls closure for @a iter
 * @return handle to stop the async get
 */
struct GNUNET_DHT_GetHandle *
GNUNET_DHT_get_start (struct GNUNET_DHT_Handle *handle,
                      enum GNUNET_BLOCK_Type type,
                      const struct GNUNET_HashCode *key,
                      uint32_t desired_replication_level,
                      enum GNUNET_DHT_RouteOption options,
                      const void *xquery,
                      size_t xquery_size,
                      GNUNET_DHT_GetIterator iter,
                      void *iter_cls)
{
  struct GNUNET_DHT_GetHandle *gh;
  size_t msize;

  msize = sizeof (struct GNUNET_DHT_ClientGetMessage) + xquery_size;
  if ((msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (xquery_size >= GNUNET_SERVER_MAX_MESSAGE_SIZE))
  {
    GNUNET_break (0);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending query for %s to DHT %p\n",
       GNUNET_h2s (key),
       handle);
  gh = GNUNET_malloc (sizeof (struct GNUNET_DHT_GetHandle) +
                      xquery_size);
  gh->iter = iter;
  gh->iter_cls = iter_cls;
  gh->dht_handle = handle;
  gh->key = *key;
  gh->unique_id = ++handle->uid_gen;
  gh->xquery_size = xquery_size;
  gh->desired_replication_level = desired_replication_level;
  gh->type = type;
  gh->options = options;
  GNUNET_memcpy (&gh[1],
          xquery,
          xquery_size);
  GNUNET_CONTAINER_multihashmap_put (handle->active_requests,
                                     &gh->key,
                                     gh,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  if (NULL != handle->mq)
    send_get (gh);
  return gh;
}


/**
 * Tell the DHT not to return any of the following known results
 * to this client.
 *
 * @param get_handle get operation for which results should be filtered
 * @param num_results number of results to be blocked that are
 *        provided in this call (size of the @a results array)
 * @param results array of hash codes over the 'data' of the results
 *        to be blocked
 */
void
GNUNET_DHT_get_filter_known_results (struct GNUNET_DHT_GetHandle *get_handle,
				     unsigned int num_results,
				     const struct GNUNET_HashCode *results)
{
  unsigned int needed;
  unsigned int had;

  had = get_handle->seen_results_end;
  needed = had + num_results;
  if (needed > get_handle->seen_results_size)
    GNUNET_array_grow (get_handle->seen_results,
		       get_handle->seen_results_size,
		       needed);
  GNUNET_memcpy (&get_handle->seen_results[get_handle->seen_results_end],
	  results,
	  num_results * sizeof (struct GNUNET_HashCode));
  get_handle->seen_results_end += num_results;
  if (NULL != get_handle->dht_handle->mq)
    send_get_known_results (get_handle,
                            had);
}


/**
 * Stop async DHT-get.
 *
 * @param get_handle handle to the GET operation to stop
 */
void
GNUNET_DHT_get_stop (struct GNUNET_DHT_GetHandle *get_handle)
{
  struct GNUNET_DHT_Handle *handle = get_handle->dht_handle;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending STOP for %s to DHT via %p\n",
       GNUNET_h2s (&get_handle->key),
       handle);
  if (NULL != handle->mq)
  {
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_DHT_ClientGetStopMessage *stop_msg;

    env = GNUNET_MQ_msg (stop_msg,
                         GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_STOP);
    stop_msg->reserved = htonl (0);
    stop_msg->unique_id = get_handle->unique_id;
    stop_msg->key = get_handle->key;
    GNUNET_MQ_send (handle->mq,
                    env);
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (handle->active_requests,
                                                       &get_handle->key,
                                                       get_handle));
  GNUNET_array_grow (get_handle->seen_results,
		     get_handle->seen_results_end,
		     0);
  GNUNET_free (get_handle);
}


/**
 * Start monitoring the local DHT service.
 *
 * @param handle Handle to the DHT service.
 * @param type Type of blocks that are of interest.
 * @param key Key of data of interest, NULL for all.
 * @param get_cb Callback to process monitored get messages.
 * @param get_resp_cb Callback to process monitored get response messages.
 * @param put_cb Callback to process monitored put messages.
 * @param cb_cls Closure for callbacks.
 * @return Handle to stop monitoring.
 */
struct GNUNET_DHT_MonitorHandle *
GNUNET_DHT_monitor_start (struct GNUNET_DHT_Handle *handle,
                          enum GNUNET_BLOCK_Type type,
                          const struct GNUNET_HashCode *key,
                          GNUNET_DHT_MonitorGetCB get_cb,
                          GNUNET_DHT_MonitorGetRespCB get_resp_cb,
                          GNUNET_DHT_MonitorPutCB put_cb,
                          void *cb_cls)
{
  struct GNUNET_DHT_MonitorHandle *mh;

  mh = GNUNET_new (struct GNUNET_DHT_MonitorHandle);
  mh->get_cb = get_cb;
  mh->get_resp_cb = get_resp_cb;
  mh->put_cb = put_cb;
  mh->cb_cls = cb_cls;
  mh->type = type;
  mh->dht_handle = handle;
  if (NULL != key)
  {
    mh->key = GNUNET_new (struct GNUNET_HashCode);
    *mh->key = *key;
  }
  GNUNET_CONTAINER_DLL_insert (handle->monitor_head,
                               handle->monitor_tail,
                               mh);
  if (NULL != handle->mq)
    send_monitor_start (mh);
  return mh;
}


/**
 * Stop monitoring.
 *
 * @param mh The handle to the monitor request returned by monitor_start.
 *
 * On return get_handle will no longer be valid, caller must not use again!!!
 */
void
GNUNET_DHT_monitor_stop (struct GNUNET_DHT_MonitorHandle *mh)
{
  struct GNUNET_DHT_Handle *handle = mh->dht_handle;
  struct GNUNET_DHT_MonitorStartStopMessage *m;
  struct GNUNET_MQ_Envelope *env;

  GNUNET_CONTAINER_DLL_remove (handle->monitor_head,
                               handle->monitor_tail,
                               mh);
  env = GNUNET_MQ_msg (m,
                       GNUNET_MESSAGE_TYPE_DHT_MONITOR_STOP);
  m->type = htonl (mh->type);
  m->get = htons (NULL != mh->get_cb);
  m->get_resp = htons(NULL != mh->get_resp_cb);
  m->put = htons (NULL != mh->put_cb);
  if (NULL != mh->key)
  {
    m->filter_key = htons (1);
    m->key = *mh->key;
  }
  GNUNET_MQ_send (handle->mq,
                  env);
  GNUNET_free_non_null (mh->key);
  GNUNET_free (mh);
}


/* end of dht_api.c */
