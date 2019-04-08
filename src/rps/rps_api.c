/*
     This file is part of GNUnet.
     Copyright (C)

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
 * @file rps/rps_api.c
 * @brief API for rps
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "rps.h"
#include "gnunet_rps_service.h"
#include "rps-sampler_client.h"

#include "gnunet_nse_service.h"

#include <inttypes.h>

#define LOG(kind,...) GNUNET_log_from (kind, "rps-api",__VA_ARGS__)

/**
 * Handle for a request to get peers from biased stream of ids
 */
struct GNUNET_RPS_StreamRequestHandle
{
  /**
   * The client issuing the request.
   */
  struct GNUNET_RPS_Handle *rps_handle;

  /**
   * The callback to be called when we receive an answer.
   */
  GNUNET_RPS_NotifyReadyCB ready_cb;

  /**
   * The closure for the callback.
   */
  void *ready_cb_cls;

  /**
   * @brief Scheduler task for scheduled callback
   */
  struct GNUNET_SCHEDULER_Task *callback_task;

  /**
   * @brief Next element of the DLL
   */
  struct GNUNET_RPS_StreamRequestHandle *next;

  /**
   * @brief Previous element of the DLL
   */
  struct GNUNET_RPS_StreamRequestHandle *prev;
};


/**
 * Handler to handle requests from a client.
 */
struct GNUNET_RPS_Handle
{
  /**
   * The handle to the client configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The message queue to the client.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * @brief Callback called on each update of the view
   */
  GNUNET_RPS_NotifyReadyCB view_update_cb;

  /**
   * @brief Closure to each requested update of the view
   */
  void *view_update_cls;

  /**
   * @brief Closure to each requested peer from the biased stream
   */
  void *stream_input_cls;

  /**
   * @brief Head of the DLL of stream requests
   */
  struct GNUNET_RPS_StreamRequestHandle *stream_requests_head;

  /**
   * @brief Tail of the DLL of stream requests
   */
  struct GNUNET_RPS_StreamRequestHandle *stream_requests_tail;

  /**
   * @brief Handle to nse service
   */
  struct GNUNET_NSE_Handle *nse;

  /**
   * @brief Pointer to the head element in DLL of request handles
   */
  struct GNUNET_RPS_Request_Handle *rh_head;

  /**
   * @brief Pointer to the tail element in DLL of request handles
   */
  struct GNUNET_RPS_Request_Handle *rh_tail;

  /**
   * @brief Pointer to the head element in DLL of single request handles
   */
  struct GNUNET_RPS_Request_Handle_Single_Info *rhs_head;

  /**
   * @brief Pointer to the tail element in DLL of single request handles
   */
  struct GNUNET_RPS_Request_Handle_Single_Info *rhs_tail;

  /**
   * @brief The desired probability with which we want to have observed all
   * peers.
   */
  float desired_probability;

  /**
   * @brief A factor that catches the 'bias' of a random stream of peer ids.
   *
   * As introduced by Brahms: Factor between the number of unique ids in a
   * truly random stream and number of unique ids in the gossip stream.
   */
  float deficiency_factor;
};


/**
 * Handler for a single request from a client.
 */
struct GNUNET_RPS_Request_Handle
{
  /**
   * The client issuing the request.
   */
  struct GNUNET_RPS_Handle *rps_handle;

  /**
   * The number of requested peers.
   */
  uint32_t num_requests;

  /**
   * @brief The Sampler for the client request
   */
  struct RPS_Sampler *sampler;

  /**
   * @brief Request handle of the request to the sampler - needed to cancel the request
   */
  struct RPS_SamplerRequestHandle *sampler_rh;

  /**
   * @brief Request handle of the request of the biased stream of peers -
   * needed to cancel the request
   */
  struct GNUNET_RPS_StreamRequestHandle *srh;

  /**
   * The callback to be called when we receive an answer.
   */
  GNUNET_RPS_NotifyReadyCB ready_cb;

  /**
   * The closure for the callback.
   */
  void *ready_cb_cls;

  /**
   * @brief Pointer to next element in DLL
   */
  struct GNUNET_RPS_Request_Handle *next;

  /**
   * @brief Pointer to previous element in DLL
   */
  struct GNUNET_RPS_Request_Handle *prev;
};


/**
 * Handler for a single request from a client.
 */
struct GNUNET_RPS_Request_Handle_Single_Info
{
  /**
   * The client issuing the request.
   */
  struct GNUNET_RPS_Handle *rps_handle;

  /**
   * @brief The Sampler for the client request
   */
  struct RPS_Sampler *sampler;

  /**
   * @brief Request handle of the request to the sampler - needed to cancel the request
   */
  struct RPS_SamplerRequestHandleSingleInfo *sampler_rh;

  /**
   * @brief Request handle of the request of the biased stream of peers -
   * needed to cancel the request
   */
  struct GNUNET_RPS_StreamRequestHandle *srh;

  /**
   * The callback to be called when we receive an answer.
   */
  GNUNET_RPS_NotifyReadySingleInfoCB ready_cb;

  /**
   * The closure for the callback.
   */
  void *ready_cb_cls;

  /**
   * @brief Pointer to next element in DLL
   */
  struct GNUNET_RPS_Request_Handle_Single_Info *next;

  /**
   * @brief Pointer to previous element in DLL
   */
  struct GNUNET_RPS_Request_Handle_Single_Info *prev;
};


/**
 * Struct used to pack the callback, its closure (provided by the caller)
 * and the connection handler to the service to pass it to a callback function.
 */
struct cb_cls_pack
{
  /**
   * Callback provided by the client
   */
  GNUNET_RPS_NotifyReadyCB cb;

  /**
   * Closure provided by the client
   */
  void *cls;

  /**
   * Handle to the service connection
   */
 struct GNUNET_CLIENT_Connection *service_conn;
};


/**
 * @brief Peers received from the biased stream to be passed to all
 * srh_handlers
 */
static struct GNUNET_PeerIdentity *srh_callback_peers;

/**
 * @brief Number of peers in the biased stream that are to be passed to all
 * srh_handlers
 */
static uint64_t srh_callback_num_peers;


/**
 * @brief Create a new handle for a stream request
 *
 * @param rps_handle The rps handle
 * @param num_peers The number of desired peers
 * @param ready_cb The callback to be called, once all peers are ready
 * @param cls The colsure to provide to the callback
 *
 * @return The handle to the stream request
 */
static struct GNUNET_RPS_StreamRequestHandle *
new_stream_request (struct GNUNET_RPS_Handle *rps_handle,
                    GNUNET_RPS_NotifyReadyCB ready_cb,
                    void *cls)
{
  struct GNUNET_RPS_StreamRequestHandle *srh;

  srh = GNUNET_new (struct GNUNET_RPS_StreamRequestHandle);
  srh->rps_handle = rps_handle;
  srh->ready_cb = ready_cb;
  srh->ready_cb_cls = cls;
  GNUNET_CONTAINER_DLL_insert (rps_handle->stream_requests_head,
                               rps_handle->stream_requests_tail,
                               srh);

  return srh;
}


/**
 * @brief Remove the given stream request from the list of requests and memory
 *
 * @param srh The request to be removed
 */
static void
remove_stream_request (struct GNUNET_RPS_StreamRequestHandle *srh)
{
  struct GNUNET_RPS_Handle *rps_handle = srh->rps_handle;

  GNUNET_assert (NULL != srh);
  if (NULL != srh->callback_task)
  {
    GNUNET_SCHEDULER_cancel (srh->callback_task);
    srh->callback_task = NULL;
  }
  GNUNET_CONTAINER_DLL_remove (rps_handle->stream_requests_head,
                               rps_handle->stream_requests_tail,
                               srh);
  GNUNET_free (srh);
}


/**
 * @brief Called once the sampler has collected all requested peers.
 *
 * Calls the callback provided by the client with the corresponding cls.
 *
 * @param peers The array of @a num_peers that has been returned.
 * @param num_peers The number of peers that have been returned
 * @param cls The #GNUNET_RPS_Request_Handle
 */
static void
peers_ready_cb (const struct GNUNET_PeerIdentity *peers,
                uint32_t num_peers,
                void *cls)
{
  struct GNUNET_RPS_Request_Handle *rh = cls;

  rh->sampler_rh = NULL;
  rh->ready_cb (rh->ready_cb_cls,
                num_peers,
                peers);
  GNUNET_RPS_request_cancel (rh);
}


/**
 * @brief Called once the sampler has collected the requested peer.
 *
 * Calls the callback provided by the client with the corresponding cls.
 *
 * @param peers The array of @a num_peers that has been returned.
 * @param num_peers The number of peers that have been returned
 * @param cls The #GNUNET_RPS_Request_Handle
 * @param probability Probability with which all IDs have been observed
 * @param num_observed Number of observed IDs
 */
static void
peer_info_ready_cb (const struct GNUNET_PeerIdentity *peers,
                    void *cls,
                    double probability,
                    uint32_t num_observed)
{
  struct GNUNET_RPS_Request_Handle_Single_Info *rh = cls;

  rh->sampler_rh = NULL;
  rh->ready_cb (rh->ready_cb_cls,
                peers,
                probability,
                num_observed);
  GNUNET_RPS_request_single_info_cancel (rh);
}


/**
 * @brief Callback to collect the peers from the biased stream and put those
 * into the sampler.
 *
 * @param cls The #GNUNET_RPS_Request_Handle
 * @param num_peers The number of peer that have been returned
 * @param peers The array of @a num_peers that have been returned
 */
static void
collect_peers_cb (void *cls,
                  uint64_t num_peers,
                  const struct GNUNET_PeerIdentity *peers)
{
  struct GNUNET_RPS_Request_Handle *rh = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Service sent %" PRIu64 " peers from stream\n",
       num_peers);
  for (uint64_t i = 0; i < num_peers; i++)
  {
    RPS_sampler_update (rh->sampler, &peers[i]);
  }
}


/**
 * @brief Callback to collect the peers from the biased stream and put those
 * into the sampler.
 *
 * This version is for the modified #GNUNET_RPS_Request_Handle_Single_Info
 *
 * @param cls The #GNUNET_RPS_Request_Handle
 * @param num_peers The number of peer that have been returned
 * @param peers The array of @a num_peers that have been returned
 */
static void
collect_peers_info_cb (void *cls,
                       uint64_t num_peers,
                       const struct GNUNET_PeerIdentity *peers)
{
  struct GNUNET_RPS_Request_Handle_Single_Info *rhs = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Service sent %" PRIu64 " peers from stream\n",
       num_peers);
  for (uint64_t i = 0; i < num_peers; i++)
  {
    RPS_sampler_update (rhs->sampler, &peers[i]);
  }
}


/* Get internals for debugging/profiling purposes */

/**
 * Request updates of view
 *
 * @param rps_handle handle to the rps service
 * @param num_req_peers number of peers we want to receive
 *        (0 for infinite updates)
 * @param cls a closure that will be given to the callback
 * @param ready_cb the callback called when the peers are available
 */
void
GNUNET_RPS_view_request (struct GNUNET_RPS_Handle *rps_handle,
                         uint32_t num_updates,
                         GNUNET_RPS_NotifyReadyCB view_update_cb,
                         void *cls)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_DEBUG_ViewRequest *msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client requests %" PRIu32 " view updates\n",
       num_updates);
  rps_handle->view_update_cb = view_update_cb;
  rps_handle->view_update_cls = cls;

  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_VIEW_REQUEST);
  msg->num_updates = htonl (num_updates);
  GNUNET_MQ_send (rps_handle->mq, ev);
}


void
GNUNET_RPS_view_request_cancel (struct GNUNET_RPS_Handle *rps_handle)
{
  struct GNUNET_MQ_Envelope *ev;

  GNUNET_assert (NULL != rps_handle->view_update_cb);

  rps_handle->view_update_cb = NULL;

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_VIEW_CANCEL);
  GNUNET_MQ_send (rps_handle->mq, ev);
}


/**
 * Request biased stream of peers that are being put into the sampler
 *
 * @param rps_handle handle to the rps service
 * @param cls a closure that will be given to the callback
 * @param ready_cb the callback called when the peers are available
 */
struct GNUNET_RPS_StreamRequestHandle *
GNUNET_RPS_stream_request (struct GNUNET_RPS_Handle *rps_handle,
                           GNUNET_RPS_NotifyReadyCB stream_input_cb,
                           void *cls)
{
  struct GNUNET_RPS_StreamRequestHandle *srh;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_DEBUG_StreamRequest *msg;

  srh = new_stream_request (rps_handle,
                            stream_input_cb,
                            cls);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Client requests biased stream updates\n");

  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_STREAM_REQUEST);
  GNUNET_MQ_send (rps_handle->mq, ev);
  return srh;
}


/**
 * This function is called, when the service updates the view.
 * It verifies that @a msg is well-formed.
 *
 * @param cls the closure
 * @param msg the message
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_view_update (void *cls,
                   const struct GNUNET_RPS_CS_DEBUG_ViewReply *msg)
{
  uint16_t msize = ntohs (msg->header.size);
  uint32_t num_peers = ntohl (msg->num_peers);
  (void) cls;

  msize -= sizeof (struct GNUNET_RPS_CS_DEBUG_ViewReply);
  if ( (msize / sizeof (struct GNUNET_PeerIdentity) != num_peers) ||
       (msize % sizeof (struct GNUNET_PeerIdentity) != 0) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * This function is called, when the service updated its view.
 * It calls the callback the caller provided
 * and disconnects afterwards.
 *
 * @param msg the message
 */
static void
handle_view_update (void *cls,
                    const struct GNUNET_RPS_CS_DEBUG_ViewReply *msg)
{
  struct GNUNET_RPS_Handle *h = cls;
  struct GNUNET_PeerIdentity *peers;

  /* Give the peers back */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "New view of %" PRIu32 " peers:\n",
       ntohl (msg->num_peers));

  peers = (struct GNUNET_PeerIdentity *) &msg[1];
  GNUNET_assert (NULL != h);
  GNUNET_assert (NULL != h->view_update_cb);
  h->view_update_cb (h->view_update_cls, ntohl (msg->num_peers), peers);
}


/**
 * @brief Send message to service that this client does not want to receive
 * further updates from the biased peer stream
 *
 * @param rps_handle The handle representing the service to the client
 */
static void
cancel_stream (struct GNUNET_RPS_Handle *rps_handle)
{
  struct GNUNET_MQ_Envelope *ev;

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_STREAM_CANCEL);
  GNUNET_MQ_send (rps_handle->mq, ev);
}


/**
 * @brief Cancel a specific request for updates from the biased peer stream
 *
 * @param srh The request handle to cancel
 */
void
GNUNET_RPS_stream_cancel (struct GNUNET_RPS_StreamRequestHandle *srh)
{
  struct GNUNET_RPS_Handle *rps_handle;

  rps_handle = srh->rps_handle;
  remove_stream_request (srh);
  if (NULL == rps_handle->stream_requests_head)
    cancel_stream (rps_handle);
}


/**
 * This function is called, when the service sends another peer from the biased
 * stream.
 * It calls the callback the caller provided
 * and disconnects afterwards.
 *
 * TODO merge with check_view_update
 *
 * @param msg the message
 */
static int
check_stream_input (void *cls,
                    const struct GNUNET_RPS_CS_DEBUG_StreamReply *msg)
{
  uint16_t msize = ntohs (msg->header.size);
  uint32_t num_peers = ntohl (msg->num_peers);
  (void) cls;

  msize -= sizeof (struct GNUNET_RPS_CS_DEBUG_StreamReply);
  if ( (msize / sizeof (struct GNUNET_PeerIdentity) != num_peers) ||
       (msize % sizeof (struct GNUNET_PeerIdentity) != 0) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * @brief Called by the scheduler to call the callbacks of the srh handlers
 *
 * @param cls Stream request handle
 */
static void
srh_callback_scheduled (void *cls)
{
  struct GNUNET_RPS_StreamRequestHandle *srh = cls;

  srh->callback_task = NULL;
  srh->ready_cb (srh->ready_cb_cls,
                 srh_callback_num_peers,
                 srh_callback_peers);
}


/**
 * This function is called, when the service sends another peer from the biased
 * stream.
 * It calls the callback the caller provided
 * and disconnects afterwards.
 *
 * @param msg the message
 */
static void
handle_stream_input (void *cls,
                     const struct GNUNET_RPS_CS_DEBUG_StreamReply *msg)
{
  struct GNUNET_RPS_Handle *h = cls;
  //const struct GNUNET_PeerIdentity *peers;
  uint64_t num_peers;
  struct GNUNET_RPS_StreamRequestHandle *srh_iter;
  struct GNUNET_RPS_StreamRequestHandle *srh_next;

  //peers = (struct GNUNET_PeerIdentity *) &msg[1];
  num_peers = ntohl (msg->num_peers);
  srh_callback_num_peers = num_peers;
  GNUNET_free_non_null (srh_callback_peers);
  srh_callback_peers = GNUNET_new_array (num_peers,
					 struct GNUNET_PeerIdentity);
  GNUNET_memcpy (srh_callback_peers,
                 &msg[1],
                 num_peers * sizeof (struct GNUNET_PeerIdentity));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received %" PRIu64 " peer(s) from stream input.\n",
       num_peers);
  for (srh_iter = h->stream_requests_head;
       NULL != srh_iter;
       srh_iter = srh_next)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Calling srh \n");
    /* Store next pointer - srh might be removed/freed in callback */
    srh_next = srh_iter->next;
    if (NULL != srh_iter->callback_task)
      GNUNET_SCHEDULER_cancel (srh_iter->callback_task);
    srh_iter->callback_task =
      GNUNET_SCHEDULER_add_now (&srh_callback_scheduled,
				srh_iter);
  }

  if (NULL == h->stream_requests_head)
  {
    cancel_stream (h);
  }
}


/**
 * Reconnect to the service
 */
static void
reconnect (struct GNUNET_RPS_Handle *h);


/**
 * Error handler for mq.
 *
 * This function is called whan mq encounters an error.
 * Until now mq doesn't provide useful error messages.
 *
 * @param cls the closure
 * @param error error code without specyfied meaning
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_RPS_Handle *h = cls;
  //TODO LOG
  LOG (GNUNET_ERROR_TYPE_WARNING, "Problem with message queue. error: %i\n\
       1: READ,\n\
       2: WRITE,\n\
       4: TIMEOUT\n",
       // TODO: write GNUNET_MQ_strerror (error)
       error);
  reconnect (h);
  /* Resend all pending request as the service destroyed its knowledge
   * about them */
}


/**
 * @brief Create the hash value from the share value that defines the sub
 * (-group)
 *
 * @param share_val Share value
 * @param hash[out] Pointer to the location in which the hash will be stored.
 */
static void
hash_from_share_val (const char *share_val,
                     struct GNUNET_HashCode *hash)
{
  GNUNET_CRYPTO_kdf (hash,
                     sizeof (struct GNUNET_HashCode),
                     "rps",
                     strlen ("rps"),
                     share_val,
                     strlen (share_val),
                     NULL, 0);
}


/**
 * @brief Callback for network size estimate - called with new estimates about
 * the network size, updates all samplers with the new estimate
 *
 * Implements #GNUNET_NSE_Callback
 *
 * @param cls the rps handle
 * @param timestamp unused
 * @param logestimate the estimate
 * @param std_dev the standard distribution
 */
static void
nse_cb (void *cls,
        struct GNUNET_TIME_Absolute timestamp,
        double logestimate,
        double std_dev)
{
  struct GNUNET_RPS_Handle *h = cls;
  (void) timestamp;
  (void) std_dev;

  for (struct GNUNET_RPS_Request_Handle *rh_iter = h->rh_head;
       NULL != rh_iter && NULL != rh_iter->next;
       rh_iter = rh_iter->next)
  {
    RPS_sampler_update_with_nw_size (rh_iter->sampler,
                                     GNUNET_NSE_log_estimate_to_n (logestimate));
  }
  for (struct GNUNET_RPS_Request_Handle_Single_Info *rhs_iter = h->rhs_head;
       NULL != rhs_iter && NULL != rhs_iter->next;
       rhs_iter = rhs_iter->next)
  {
    RPS_sampler_update_with_nw_size (rhs_iter->sampler,
                                     GNUNET_NSE_log_estimate_to_n (logestimate));
  }
}


/**
 * Reconnect to the service
 */
static void
reconnect (struct GNUNET_RPS_Handle *h)
{
  struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    GNUNET_MQ_hd_var_size (view_update,
                           GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_VIEW_REPLY,
                           struct GNUNET_RPS_CS_DEBUG_ViewReply,
                           h),
    GNUNET_MQ_hd_var_size (stream_input,
                           GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_STREAM_REPLY,
                           struct GNUNET_RPS_CS_DEBUG_StreamReply,
                           h),
    GNUNET_MQ_handler_end ()
  };

  if (NULL != h->mq)
    GNUNET_MQ_destroy (h->mq);
  h->mq = GNUNET_CLIENT_connect (h->cfg,
                                 "rps",
                                 mq_handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL != h->nse)
    GNUNET_NSE_disconnect (h->nse);
  h->nse = GNUNET_NSE_connect (h->cfg, &nse_cb, h);
}


/**
 * Connect to the rps service
 *
 * @param cfg configuration to use
 * @return a handle to the service, NULL on error
 */
struct GNUNET_RPS_Handle *
GNUNET_RPS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_RPS_Handle *h;

  h = GNUNET_new (struct GNUNET_RPS_Handle);
  h->cfg = cfg;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_float (cfg,
                                           "RPS",
                                           "DESIRED_PROBABILITY",
                                           &h->desired_probability))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "RPS", "DESIRED_PROBABILITY");
    GNUNET_free (h);
    return NULL;
  }
  if (0 > h->desired_probability ||
      1 < h->desired_probability)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        "The desired probability must be in the interval [0;1]\n");
    GNUNET_free (h);
    return NULL;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_float (cfg,
                                           "RPS",
                                           "DEFICIENCY_FACTOR",
                                           &h->deficiency_factor))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "RPS", "DEFICIENCY_FACTOR");
    GNUNET_free (h);
    return NULL;
  }
  if (0 > h->desired_probability ||
      1 < h->desired_probability)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        "The deficiency factor must be in the interval [0;1]\n");
    GNUNET_free (h);
    return NULL;
  }
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
  return h;
}


/**
 * @brief Start a sub with the given shared value
 *
 * @param h Handle to rps
 * @param shared_value The shared value that defines the members of the sub (-gorup)
 */
void
GNUNET_RPS_sub_start (struct GNUNET_RPS_Handle *h,
                      const char *shared_value)
{
  struct GNUNET_RPS_CS_SubStartMessage *msg;
  struct GNUNET_MQ_Envelope *ev;

  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RPS_CS_SUB_START);
  hash_from_share_val (shared_value, &msg->hash);
  msg->round_interval = GNUNET_TIME_relative_hton (// TODO read from config!
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30));
  GNUNET_assert (0 != msg->round_interval.rel_value_us__);

  GNUNET_MQ_send (h->mq, ev);
}


/**
 * @brief Stop a sub with the given shared value
 *
 * @param h Handle to rps
 * @param shared_value The shared value that defines the members of the sub (-gorup)
 */
void
GNUNET_RPS_sub_stop (struct GNUNET_RPS_Handle *h,
                     const char *shared_value)
{
  struct GNUNET_RPS_CS_SubStopMessage *msg;
  struct GNUNET_MQ_Envelope *ev;

  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RPS_CS_SUB_STOP);
  hash_from_share_val (shared_value, &msg->hash);

  GNUNET_MQ_send (h->mq, ev);
}


/**
 * Request n random peers.
 *
 * @param rps_handle handle to the rps service
 * @param num_req_peers number of peers we want to receive
 * @param ready_cb the callback called when the peers are available
 * @param cls closure given to the callback
 * @return a handle to cancel this request
 */
struct GNUNET_RPS_Request_Handle *
GNUNET_RPS_request_peers (struct GNUNET_RPS_Handle *rps_handle,
                          uint32_t num_req_peers,
                          GNUNET_RPS_NotifyReadyCB ready_cb,
                          void *cls)
{
  struct GNUNET_RPS_Request_Handle *rh;

  LOG (GNUNET_ERROR_TYPE_INFO,
       "Client requested %" PRIu32 " peers\n",
       num_req_peers);
  rh = GNUNET_new (struct GNUNET_RPS_Request_Handle);
  rh->rps_handle = rps_handle;
  rh->num_requests = num_req_peers;
  rh->sampler = RPS_sampler_mod_init (num_req_peers,
                                      GNUNET_TIME_UNIT_SECONDS); // TODO remove this time-stuff
  RPS_sampler_set_desired_probability (rh->sampler,
                                       rps_handle->desired_probability);
  RPS_sampler_set_deficiency_factor (rh->sampler,
                                     rps_handle->deficiency_factor);
  rh->sampler_rh = RPS_sampler_get_n_rand_peers (rh->sampler,
                                                 num_req_peers,
                                                 peers_ready_cb,
                                                 rh);
  rh->srh = GNUNET_RPS_stream_request (rps_handle,
                                       collect_peers_cb,
                                       rh); /* cls */
  rh->ready_cb = ready_cb;
  rh->ready_cb_cls = cls;
  GNUNET_CONTAINER_DLL_insert (rps_handle->rh_head,
                               rps_handle->rh_tail,
                               rh);

  return rh;
}


/**
 * Request one random peer, getting additional information.
 *
 * @param rps_handle handle to the rps service
 * @param ready_cb the callback called when the peers are available
 * @param cls closure given to the callback
 * @return a handle to cancel this request
 */
struct GNUNET_RPS_Request_Handle_Single_Info *
GNUNET_RPS_request_peer_info (struct GNUNET_RPS_Handle *rps_handle,
                              GNUNET_RPS_NotifyReadySingleInfoCB ready_cb,
                              void *cls)
{
  struct GNUNET_RPS_Request_Handle_Single_Info *rhs;
  uint32_t num_req_peers = 1;

  LOG (GNUNET_ERROR_TYPE_INFO,
       "Client requested peer with additional info\n");
  rhs = GNUNET_new (struct GNUNET_RPS_Request_Handle_Single_Info);
  rhs->rps_handle = rps_handle;
  rhs->sampler = RPS_sampler_mod_init (num_req_peers,
                                      GNUNET_TIME_UNIT_SECONDS); // TODO remove this time-stuff
  RPS_sampler_set_desired_probability (rhs->sampler,
                                       rps_handle->desired_probability);
  RPS_sampler_set_deficiency_factor (rhs->sampler,
                                     rps_handle->deficiency_factor);
  rhs->sampler_rh = RPS_sampler_get_rand_peer_info (rhs->sampler,
                                                   peer_info_ready_cb,
                                                   rhs);
  rhs->srh = GNUNET_RPS_stream_request (rps_handle,
                                       collect_peers_info_cb,
                                       rhs); /* cls */
  rhs->ready_cb = ready_cb;
  rhs->ready_cb_cls = cls;
  GNUNET_CONTAINER_DLL_insert (rps_handle->rhs_head,
                               rps_handle->rhs_tail,
                               rhs);

  return rhs;
}


/**
 * Seed rps service with peerIDs.
 *
 * @param h handle to the rps service
 * @param n number of peers to seed
 * @param ids the ids of the peers seeded
 */
void
GNUNET_RPS_seed_ids (struct GNUNET_RPS_Handle *h,
                     uint32_t n,
                     const struct GNUNET_PeerIdentity *ids)
{
  size_t size_needed;
  uint32_t num_peers_max;
  const struct GNUNET_PeerIdentity *tmp_peer_pointer;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_SeedMessage *msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client wants to seed %" PRIu32 " peers:\n",
       n);
  for (unsigned int i = 0 ; i < n ; i++)
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%u. peer: %s\n",
         i,
         GNUNET_i2s (&ids[i]));

  /* The actual size the message occupies */
  size_needed = sizeof (struct GNUNET_RPS_CS_SeedMessage) +
    n * sizeof (struct GNUNET_PeerIdentity);
  /* The number of peers that fits in one message together with
   * the respective header */
  num_peers_max = (GNUNET_MAX_MESSAGE_SIZE -
      sizeof (struct GNUNET_RPS_CS_SeedMessage)) /
    sizeof (struct GNUNET_PeerIdentity);
  tmp_peer_pointer = ids;

  while (GNUNET_MAX_MESSAGE_SIZE < size_needed)
  {
    ev = GNUNET_MQ_msg_extra (msg,
			      num_peers_max * sizeof (struct GNUNET_PeerIdentity),
			      GNUNET_MESSAGE_TYPE_RPS_CS_SEED);
    msg->num_peers = htonl (num_peers_max);
    GNUNET_memcpy (&msg[1],
		   tmp_peer_pointer,
		   num_peers_max * sizeof (struct GNUNET_PeerIdentity));
    GNUNET_MQ_send (h->mq,
		    ev);
    n -= num_peers_max;
    size_needed = sizeof (struct GNUNET_RPS_CS_SeedMessage) +
                  n * sizeof (struct GNUNET_PeerIdentity);
    /* Set pointer to beginning of next block of num_peers_max peers */
    tmp_peer_pointer = &ids[num_peers_max];
  }

  ev = GNUNET_MQ_msg_extra (msg,
			    n * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_RPS_CS_SEED);
  msg->num_peers = htonl (n);
  GNUNET_memcpy (&msg[1],
		 tmp_peer_pointer,
		 n * sizeof (struct GNUNET_PeerIdentity));
  GNUNET_MQ_send (h->mq,
		  ev);
}


#if ENABLE_MALICIOUS
/**
 * Turn RPS service to act malicious.
 *
 * @param h handle to the rps service
 * @param type which type of malicious peer to turn to.
 *             0 Don't act malicious at all
 *             1 Try to maximise representation
 *             2 Try to partition the network
 *               (isolate one peer from the rest)
 * @param n number of @a ids
 * @param ids the ids of the malicious peers
 *            if @type is 2 the last id is the id of the
 *            peer to be isolated from the rest
 */
void
GNUNET_RPS_act_malicious (struct GNUNET_RPS_Handle *h,
                          uint32_t type,
                          uint32_t num_peers,
                          const struct GNUNET_PeerIdentity *peer_ids,
                          const struct GNUNET_PeerIdentity *target_peer)
{
  size_t size_needed;
  uint32_t num_peers_max;
  const struct GNUNET_PeerIdentity *tmp_peer_pointer;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_ActMaliciousMessage *msg;

  unsigned int i;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client turns malicious (type %" PRIu32 ") with %" PRIu32 " other peers:\n",
       type,
       num_peers);
  for (i = 0 ; i < num_peers ; i++)
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%u. peer: %s\n",
         i,
         GNUNET_i2s (&peer_ids[i]));

  /* The actual size the message would occupy */
  size_needed = sizeof (struct GNUNET_RPS_CS_SeedMessage) +
    num_peers * sizeof (struct GNUNET_PeerIdentity);
  /* The number of peers that fit in one message together with
   * the respective header */
  num_peers_max = (GNUNET_MAX_MESSAGE_SIZE -
      sizeof (struct GNUNET_RPS_CS_SeedMessage)) /
    sizeof (struct GNUNET_PeerIdentity);
  tmp_peer_pointer = peer_ids;

  while (GNUNET_MAX_MESSAGE_SIZE < size_needed)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Too many peers to send at once, sending %" PRIu32 " (all we can so far)\n",
         num_peers_max);
    ev = GNUNET_MQ_msg_extra (msg,
                              num_peers_max * sizeof (struct GNUNET_PeerIdentity),
                              GNUNET_MESSAGE_TYPE_RPS_ACT_MALICIOUS);
    msg->type = htonl (type);
    msg->num_peers = htonl (num_peers_max);
    if ( (2 == type) ||
         (3 == type) )
      msg->attacked_peer = peer_ids[num_peers];
    GNUNET_memcpy (&msg[1],
            tmp_peer_pointer,
            num_peers_max * sizeof (struct GNUNET_PeerIdentity));

    GNUNET_MQ_send (h->mq, ev);

    num_peers -= num_peers_max;
    size_needed = sizeof (struct GNUNET_RPS_CS_SeedMessage) +
                  num_peers * sizeof (struct GNUNET_PeerIdentity);
    /* Set pointer to beginning of next block of num_peers_max peers */
    tmp_peer_pointer = &peer_ids[num_peers_max];
  }

  ev = GNUNET_MQ_msg_extra (msg,
                            num_peers * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_RPS_ACT_MALICIOUS);
  msg->type = htonl (type);
  msg->num_peers = htonl (num_peers);
  if ( (2 == type) ||
       (3 == type) )
    msg->attacked_peer = *target_peer;
  GNUNET_memcpy (&msg[1],
		 tmp_peer_pointer,
		 num_peers * sizeof (struct GNUNET_PeerIdentity));

  GNUNET_MQ_send (h->mq, ev);
}
#endif /* ENABLE_MALICIOUS */


/**
 * Cancle an issued request.
 *
 * @param rh request handle of request to cancle
 */
void
GNUNET_RPS_request_cancel (struct GNUNET_RPS_Request_Handle *rh)
{
  struct GNUNET_RPS_Handle *h;

  h = rh->rps_handle;
  GNUNET_assert (NULL != rh);
  GNUNET_assert (NULL != rh->srh);
  GNUNET_assert (h == rh->srh->rps_handle);
  GNUNET_RPS_stream_cancel (rh->srh);
  rh->srh = NULL;
  if (NULL == h->stream_requests_head) cancel_stream(h);
  if (NULL != rh->sampler_rh)
  {
    RPS_sampler_request_cancel (rh->sampler_rh);
  }
  RPS_sampler_destroy (rh->sampler);
  rh->sampler = NULL;
  GNUNET_CONTAINER_DLL_remove (h->rh_head,
                               h->rh_tail,
                               rh);
  GNUNET_free (rh);
}


/**
 * Cancle an issued single info request.
 *
 * @param rhs request handle of request to cancle
 */
void
GNUNET_RPS_request_single_info_cancel (
    struct GNUNET_RPS_Request_Handle_Single_Info *rhs)
{
  struct GNUNET_RPS_Handle *h;

  h = rhs->rps_handle;
  GNUNET_assert (NULL != rhs);
  GNUNET_assert (NULL != rhs->srh);
  GNUNET_assert (h == rhs->srh->rps_handle);
  GNUNET_RPS_stream_cancel (rhs->srh);
  rhs->srh = NULL;
  if (NULL == h->stream_requests_head) cancel_stream(h);
  if (NULL != rhs->sampler_rh)
  {
    RPS_sampler_request_single_info_cancel (rhs->sampler_rh);
  }
  RPS_sampler_destroy (rhs->sampler);
  rhs->sampler = NULL;
  GNUNET_CONTAINER_DLL_remove (h->rhs_head,
                               h->rhs_tail,
                               rhs);
  GNUNET_free (rhs);
}


/**
 * Disconnect from the rps service
 *
 * @param h the handle to the rps service
 */
void
GNUNET_RPS_disconnect (struct GNUNET_RPS_Handle *h)
{
  if (NULL != h->stream_requests_head)
  {
    struct GNUNET_RPS_StreamRequestHandle *srh_next;

    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Still waiting for replies\n");
    for (struct GNUNET_RPS_StreamRequestHandle *srh_iter = h->stream_requests_head;
         NULL != srh_iter;
         srh_iter = srh_next)
    {
      srh_next = srh_iter->next;
      GNUNET_RPS_stream_cancel (srh_iter);
    }
  }
  if (NULL != h->rh_head)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Not all requests were cancelled!\n");
    for (struct GNUNET_RPS_Request_Handle *rh_iter = h->rh_head;
         h->rh_head != NULL;
         rh_iter = h->rh_head)
    {
      GNUNET_RPS_request_cancel (rh_iter);
    }
  }
  if (NULL != h->rhs_head)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Not all requests were cancelled!\n");
    for (struct GNUNET_RPS_Request_Handle_Single_Info *rhs_iter = h->rhs_head;
         h->rhs_head != NULL;
         rhs_iter = h->rhs_head)
    {
      GNUNET_RPS_request_single_info_cancel (rhs_iter);
    }
  }
  if (NULL != srh_callback_peers)
  {
    GNUNET_free (srh_callback_peers);
    srh_callback_peers = NULL;
  }
  if (NULL != h->view_update_cb)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Still waiting for view updates\n");
    GNUNET_RPS_view_request_cancel (h);
  }
  if (NULL != h->nse)
    GNUNET_NSE_disconnect (h->nse);
  GNUNET_MQ_destroy (h->mq);
  GNUNET_free (h);
}


/* end of rps_api.c */
