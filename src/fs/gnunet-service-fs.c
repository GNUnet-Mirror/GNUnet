/*
     This file is part of GNUnet.
     Copyright (C) 2009-2014, 2016 GNUnet e.V.

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
 * @file fs/gnunet-service-fs.c
 * @brief gnunet anonymity protocol implementation
 * @author Christian Grothoff
 */
#include "platform.h"
#include <float.h>
#include "gnunet_constants.h"
#include "gnunet_core_service.h"
#include "gnunet_dht_service.h"
#include "gnunet_datastore_service.h"
#include "gnunet_load_lib.h"
#include "gnunet_peer_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-fs_cp.h"
#include "gnunet-service-fs_indexing.h"
#include "gnunet-service-fs_lc.h"
#include "gnunet-service-fs_pe.h"
#include "gnunet-service-fs_pr.h"
#include "gnunet-service-fs_push.h"
#include "gnunet-service-fs_put.h"
#include "gnunet-service-fs_cadet.h"
#include "fs.h"
#include "fs_api.h"

/**
 * Size for the hash map for DHT requests from the FS
 * service.  Should be about the number of concurrent
 * DHT requests we plan to make.
 */
#define FS_DHT_HT_SIZE 1024


/**
 * How quickly do we age cover traffic?  At the given
 * time interval, remaining cover traffic counters are
 * decremented by 1/16th.
 */
#define COVER_AGE_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Collect an instane number of statistics?  May cause excessive IPC.
 */
#define INSANE_STATISTICS GNUNET_NO



/**
 * Doubly-linked list of requests we are performing
 * on behalf of the same client.
 */
struct ClientRequest
{

  /**
   * This is a doubly-linked list.
   */
  struct ClientRequest *next;

  /**
   * This is a doubly-linked list.
   */
  struct ClientRequest *prev;

  /**
   * Request this entry represents.
   */
  struct GSF_PendingRequest *pr;

  /**
   * Client list this request belongs to.
   */
  struct GSF_LocalClient *lc;

  /**
   * Task scheduled to destroy the request.
   */
  struct GNUNET_SCHEDULER_Task * kill_task;

};


/**
 * Replies to be transmitted to the client.  The actual
 * response message is allocated after this struct.
 */
struct ClientResponse
{
  /**
   * This is a doubly-linked list.
   */
  struct ClientResponse *next;

  /**
   * This is a doubly-linked list.
   */
  struct ClientResponse *prev;

  /**
   * Client list entry this response belongs to.
   */
  struct GSF_LocalClient *lc;

  /**
   * Number of bytes in the response.
   */
  size_t msize;
};


/**
 * Information we track while handling an index
 * start request from a client.
 */
struct IndexStartContext
{

  /**
   * This is a doubly linked list.
   */
  struct IndexStartContext *next;

  /**
   * This is a doubly linked list.
   */
  struct IndexStartContext *prev;

  /**
   * Name of the indexed file.
   */
  char *filename;

  /**
   * Context for transmitting confirmation to client.
   */
  struct GSF_LocalClient *lc;

  /**
   * Context for hashing of the file.
   */
  struct GNUNET_CRYPTO_FileHashContext *fhc;

  /**
   * Hash of the contents of the file.
   */
  struct GNUNET_HashCode file_id;

};


/**
 * A local client.
 */
struct GSF_LocalClient
{

  /**
   * ID of the client.
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Queue for sending replies.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Head of list of requests performed on behalf
   * of this client right now.
   */
  struct ClientRequest *cr_head;

  /**
   * Tail of list of requests performed on behalf
   * of this client right now.
   */
  struct ClientRequest *cr_tail;

  /**
   * This is a doubly linked list.
   */
  struct IndexStartContext *isc_head;

  /**
   * This is a doubly linked list.
   */
  struct IndexStartContext *isc_tail;

  /**
   * Head of linked list of responses.
   */
  struct ClientResponse *res_head;

  /**
   * Tail of linked list of responses.
   */
  struct ClientResponse *res_tail;

};


/* ****************************** globals ****************************** */

/**
 * Our connection to the datastore.
 */
struct GNUNET_DATASTORE_Handle *GSF_dsh;

/**
 * Our configuration.
 */
const struct GNUNET_CONFIGURATION_Handle *GSF_cfg;

/**
 * Handle for reporting statistics.
 */
struct GNUNET_STATISTICS_Handle *GSF_stats;

/**
 * Handle for DHT operations.
 */
struct GNUNET_DHT_Handle *GSF_dht;

/**
 * How long do requests typically stay in the routing table?
 */
struct GNUNET_LOAD_Value *GSF_rt_entry_lifetime;

/**
 * Running average of the observed latency to other peers (round trip).
 * Initialized to 5s as the initial default.
 */
struct GNUNET_TIME_Relative GSF_avg_latency = { 500 };

/**
 * Handle to ATS service.
 */
struct GNUNET_ATS_PerformanceHandle *GSF_ats;


/**
 * Typical priorities we're seeing from other peers right now.  Since
 * most priorities will be zero, this value is the weighted average of
 * non-zero priorities seen "recently".  In order to ensure that new
 * values do not dramatically change the ratio, values are first
 * "capped" to a reasonable range (+N of the current value) and then
 * averaged into the existing value by a ratio of 1:N.  Hence
 * receiving the largest possible priority can still only raise our
 * "current_priorities" by at most 1.
 */
double GSF_current_priorities;

/**
 * Size of the datastore queue we assume for common requests.
 */
unsigned int GSF_datastore_queue_size;

/**
 * How many query messages have we received 'recently' that
 * have not yet been claimed as cover traffic?
 */
unsigned int GSF_cover_query_count;

/**
 * How many content messages have we received 'recently' that
 * have not yet been claimed as cover traffic?
 */
unsigned int GSF_cover_content_count;

/**
 * Our block context.
 */
struct GNUNET_BLOCK_Context *GSF_block_ctx;

/**
 * Pointer to handle to the core service (points to NULL until we've
 * connected to it).
 */
struct GNUNET_CORE_Handle *GSF_core;

/**
 * Are we introducing randomized delays for better anonymity?
 */
int GSF_enable_randomized_delays;

/**
 * Identity of this peer.
 */
struct GNUNET_PeerIdentity GSF_my_id;

/* ***************************** locals ******************************* */

/**
 * Configuration for block library.
 */
static struct GNUNET_CONFIGURATION_Handle *block_cfg;

/**
 * Private key of this peer.  Used to sign LOC URI requests.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *pk;

/**
 * ID of our task that we use to age the cover counters.
 */
static struct GNUNET_SCHEDULER_Task * cover_age_task;

/**
 * Datastore 'GET' load tracking.
 */
static struct GNUNET_LOAD_Value *datastore_get_load;


/**
 * Creates a fresh local client handle.
 *
 * @param cls NULL
 * @param client handle of the client
 * @param mq message queue for @a client
 * @return handle to local client entry
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  struct GSF_LocalClient *pos;

  pos = GNUNET_new (struct GSF_LocalClient);
  pos->client = client;
  pos->mq = mq;
  return pos;
}


/**
 * Free the given client request.
 *
 * @param cls the client request to free
 */
static void
client_request_destroy (void *cls)
{
  struct ClientRequest *cr = cls;
  struct GSF_LocalClient *lc = cr->lc;

  cr->kill_task = NULL;
  GNUNET_CONTAINER_DLL_remove (lc->cr_head,
                               lc->cr_tail,
                               cr);
  GSF_pending_request_cancel_ (cr->pr,
                               GNUNET_YES);
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop ("# client searches active"),
                            -1,
                            GNUNET_NO);
  GNUNET_free (cr);
}


/**
 * Handle a reply to a pending request.  Also called if a request
 * expires (then with data == NULL).  The handler may be called
 * many times (depending on the request type), but will not be
 * called during or after a call to #GSF_pending_request_cancel()
 * and will also not be called anymore after a call signalling
 * expiration.
 *
 * @param cls user-specified closure
 * @param eval evaluation of the result
 * @param pr handle to the original pending request
 * @param reply_anonymity_level anonymity level for the reply, UINT32_MAX for "unknown"
 * @param expiration when does @a data expire?
 * @param last_transmission when was the last time we've tried to download this block? (FOREVER if unknown)
 * @param type type of the block
 * @param data response data, NULL on request expiration
 * @param data_len number of bytes in @a data
 */
static void
client_response_handler (void *cls,
                         enum GNUNET_BLOCK_EvaluationResult eval,
                         struct GSF_PendingRequest *pr,
                         uint32_t reply_anonymity_level,
                         struct GNUNET_TIME_Absolute expiration,
                         struct GNUNET_TIME_Absolute last_transmission,
                         enum GNUNET_BLOCK_Type type,
                         const void *data,
                         size_t data_len)
{
  struct ClientRequest *cr = cls;
  struct GSF_LocalClient *lc;
  struct GNUNET_MQ_Envelope *env;
  struct ClientPutMessage *pm;
  const struct GSF_PendingRequestData *prd;

  if (NULL == data)
  {
    /* local-only request, with no result, clean up. */
    if (NULL == cr->kill_task)
      cr->kill_task = GNUNET_SCHEDULER_add_now (&client_request_destroy,
                                                cr);
    return;
  }
  prd = GSF_pending_request_get_data_ (pr);
  GNUNET_break (type != GNUNET_BLOCK_TYPE_ANY);
  if ((prd->type != type) && (prd->type != GNUNET_BLOCK_TYPE_ANY))
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop
                            ("# replies received for local clients"), 1,
                            GNUNET_NO);
  GNUNET_assert (pr == cr->pr);
  lc = cr->lc;
  env = GNUNET_MQ_msg_extra (pm,
                             data_len,
                             GNUNET_MESSAGE_TYPE_FS_PUT);
  pm->type = htonl (type);
  pm->expiration = GNUNET_TIME_absolute_hton (expiration);
  pm->last_transmission = GNUNET_TIME_absolute_hton (last_transmission);
  pm->num_transmissions = htonl (prd->num_transmissions);
  pm->respect_offered = htonl (prd->respect_offered);
  GNUNET_memcpy (&pm[1],
                 data,
                 data_len);
  GNUNET_MQ_send (lc->mq,
                  env);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Queued reply to query `%s' for local client\n",
              GNUNET_h2s (&prd->query));
  if (GNUNET_BLOCK_EVALUATION_OK_LAST != eval)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Evaluation %d - keeping query alive\n",
		(int) eval);
    return;
  }
  if (NULL == cr->kill_task)
    cr->kill_task = GNUNET_SCHEDULER_add_now (&client_request_destroy,
                                              cr);
}


/**
 * A client disconnected from us.  Tear down the local client
 * record.
 *
 * @param cls unused
 * @param client handle of the client
 * @param app_ctx the `struct GSF_LocalClient`
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *app_ctx)
{
  struct GSF_LocalClient *lc = app_ctx;
  struct IndexStartContext *isc;
  struct ClientRequest *cr;
  struct ClientResponse *res;

  while (NULL != (cr = lc->cr_head))
  {
    if (NULL != cr->kill_task)
      GNUNET_SCHEDULER_cancel (cr->kill_task);
    client_request_destroy (cr);
  }
  while (NULL != (res = lc->res_head))
  {
    GNUNET_CONTAINER_DLL_remove (lc->res_head,
                                 lc->res_tail,
                                 res);
    GNUNET_free (res);
  }
  while (NULL != (isc = lc->isc_head))
  {
    GNUNET_CONTAINER_DLL_remove (lc->isc_head,
                                 lc->isc_tail,
                                 isc);
    GNUNET_CRYPTO_hash_file_cancel (isc->fhc);
    GNUNET_free (isc);
  }
  GNUNET_free (lc);
}





/**
 * Task that periodically ages our cover traffic statistics.
 *
 * @param cls unused closure
 */
static void
age_cover_counters (void *cls)
{
  GSF_cover_content_count = (GSF_cover_content_count * 15) / 16;
  GSF_cover_query_count = (GSF_cover_query_count * 15) / 16;
  cover_age_task =
      GNUNET_SCHEDULER_add_delayed (COVER_AGE_FREQUENCY,
				    &age_cover_counters,
                                    NULL);
}


/**
 * We've just now completed a datastore request.  Update our
 * datastore load calculations.
 *
 * @param start time when the datastore request was issued
 */
void
GSF_update_datastore_delay_ (struct GNUNET_TIME_Absolute start)
{
  struct GNUNET_TIME_Relative delay;

  delay = GNUNET_TIME_absolute_get_duration (start);
  GNUNET_LOAD_update (datastore_get_load, delay.rel_value_us);
}


/**
 * Test if the DATABASE (GET) load on this peer is too high
 * to even consider processing the query at
 * all.
 *
 * @param priority priority of the request (used as a reference point to compare with the load)
 * @return #GNUNET_YES if the load is too high to do anything (load high)
 *         #GNUNET_NO to process normally (load normal)
 *         #GNUNET_SYSERR to process for free (load low)
 */
int
GSF_test_get_load_too_high_ (uint32_t priority)
{
  double ld;

  ld = GNUNET_LOAD_get_load (datastore_get_load);
  if (ld < 1)
    return GNUNET_SYSERR;
  if (ld <= priority)
    return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * We've received peer performance information. Update
 * our running average for the P2P latency.
 *
 * @param cls closure
 * @param address the address
 * @param active is this address in active use
 * @param bandwidth_out assigned outbound bandwidth for the connection
 * @param bandwidth_in assigned inbound bandwidth for the connection
 * @param prop performance data for the address (as far as known)
 */
static void
update_latencies (void *cls,
		  const struct GNUNET_HELLO_Address *address,
		  int active,
		  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
		  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
		  const struct GNUNET_ATS_Properties *prop)
{
  if (NULL == address)
  {
    /* ATS service temporarily disconnected */
    return;
  }

  if (GNUNET_YES != active)
    return;
  GSF_update_peer_latency_ (&address->peer,
                            prop->delay);
  GSF_avg_latency.rel_value_us =
    (GSF_avg_latency.rel_value_us * 31 +
     GNUNET_MIN (5000, prop->delay.rel_value_us)) / 32;
  GNUNET_STATISTICS_set (GSF_stats,
                         gettext_noop ("# running average P2P latency (ms)"),
                         GSF_avg_latency.rel_value_us / 1000LL,
                         GNUNET_NO);
}


/**
 * Check P2P "PUT" message.
 *
 * @param cls closure with the `struct GSF_ConnectedPeer`
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
check_p2p_put (void *cls,
	       const struct PutMessage *put)
{
  enum GNUNET_BLOCK_Type type;

  type = ntohl (put->type);
  if (GNUNET_BLOCK_TYPE_FS_ONDEMAND == type)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * We have a new request, consider forwarding it to the given
 * peer.
 *
 * @param cls the `struct GSF_PendingRequest`
 * @param peer identity of the peer
 * @param cp handle to the connected peer record
 * @param ppd peer performance data
 */
static void
consider_request_for_forwarding (void *cls,
                                 const struct GNUNET_PeerIdentity *peer,
                                 struct GSF_ConnectedPeer *cp,
                                 const struct GSF_PeerPerformanceData *ppd)
{
  struct GSF_PendingRequest *pr = cls;

  if (GNUNET_YES !=
      GSF_pending_request_test_target_ (pr, peer))
  {
#if INSANE_STATISTICS
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop ("# Loopback routes suppressed"), 1,
                              GNUNET_NO);
#endif
    return;
  }
  GSF_plan_add_ (cp,
		 pr);
}


/**
 * Function to be called after we're done processing
 * replies from the local lookup.  If the result status
 * code indicates that there may be more replies, plan
 * forwarding the request.
 *
 * @param cls closure (NULL)
 * @param pr the pending request we were processing
 * @param result final datastore lookup result
 */
void
GSF_consider_forwarding (void *cls,
			 struct GSF_PendingRequest *pr,
			 enum GNUNET_BLOCK_EvaluationResult result)
{
  if (GNUNET_BLOCK_EVALUATION_OK_LAST == result)
    return;                     /* we're done... */
  if (GNUNET_YES !=
      GSF_pending_request_test_active_ (pr))
    return; /* request is not actually active, skip! */
  GSF_iterate_connected_peers_ (&consider_request_for_forwarding,
                                pr);
}


/**
 * Check P2P "GET" request.
 *
 * @param cls closure
 * @param gm the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
check_p2p_get (void *cls,
	       const struct GetMessage *gm)
{
  size_t msize;
  unsigned int bm;
  unsigned int bits;
  size_t bfsize;

  msize = ntohs (gm->header.size);
  bm = ntohl (gm->hash_bitmap);
  bits = 0;
  while (bm > 0)
  {
    if (1 == (bm & 1))
      bits++;
    bm >>= 1;
  }
  if (msize < sizeof (struct GetMessage) + bits * sizeof (struct GNUNET_PeerIdentity))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  bfsize = msize - sizeof (struct GetMessage) - bits * sizeof (struct GNUNET_PeerIdentity);
  /* bfsize must be power of 2, check! */
  if (0 != ((bfsize - 1) & bfsize))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * We're done with the local lookup, now consider
 * P2P processing (depending on request options and
 * result status).  Also signal that we can now
 * receive more request information from the client.
 *
 * @param cls the client doing the request (`struct GSF_LocalClient`)
 * @param pr the pending request we were processing
 * @param result final datastore lookup result
 */
static void
start_p2p_processing (void *cls,
                      struct GSF_PendingRequest *pr,
                      enum GNUNET_BLOCK_EvaluationResult result)
{
  struct GSF_LocalClient *lc = cls;
  struct GSF_PendingRequestData *prd;

  GNUNET_SERVICE_client_continue (lc->client);
  if (GNUNET_BLOCK_EVALUATION_OK_LAST == result)
    return;                     /* we're done, 'pr' was already destroyed... */
  prd = GSF_pending_request_get_data_ (pr);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Finished database lookup for local request `%s' with result %d\n",
              GNUNET_h2s (&prd->query),
	      result);
  if (0 == prd->anonymity_level)
  {
    switch (prd->type)
    {
    case GNUNET_BLOCK_TYPE_FS_DBLOCK:
    case GNUNET_BLOCK_TYPE_FS_IBLOCK:
      /* the above block types MAY be available via 'cadet' */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Considering cadet-based download for block\n");
      GSF_cadet_lookup_ (pr);
      break;
    case GNUNET_BLOCK_TYPE_FS_UBLOCK:
      /* the above block types are in the DHT */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Considering DHT-based search for block\n");
      GSF_dht_lookup_ (pr);
      break;
    default:
      GNUNET_break (0);
      break;
    }
  }
  GSF_consider_forwarding (NULL,
                           pr,
                           result);
}


/**
 * Check #GNUNET_MESSAGE_TYPE_FS_START_SEARCH-message (search request
 * from client).
 *
 * @param cls identification of the client
 * @param sm the actual message
 * @return #GNUNET_OK if @a sm is well-formed
 */
static int
check_client_start_search (void *cls,
                           const struct SearchMessage *sm)
{
  uint16_t msize;

  msize = ntohs (sm->header.size) - sizeof (struct SearchMessage);
  if (0 != msize % sizeof (struct GNUNET_HashCode))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle #GNUNET_MESSAGE_TYPE_FS_START_SEARCH-message (search request
 * from client).
 *
 * Responsible for creating the request entry itself and setting
 * up reply callback and cancellation on client disconnect.
 *
 * @param cls identification of the client
 * @param sm the actual message
 */
static void
handle_client_start_search (void *cls,
                            const struct SearchMessage *sm)
{
  static struct GNUNET_PeerIdentity all_zeros;
  struct GSF_LocalClient *lc = cls;
  struct ClientRequest *cr;
  struct GSF_PendingRequestData *prd;
  uint16_t msize;
  unsigned int sc;
  enum GNUNET_BLOCK_Type type;
  enum GSF_PendingRequestOptions options;

  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop ("# client searches received"),
                            1,
                            GNUNET_NO);
  msize = ntohs (sm->header.size) - sizeof (struct SearchMessage);
  sc = msize / sizeof (struct GNUNET_HashCode);
  type = ntohl (sm->type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received request for `%s' of type %u from local client\n",
              GNUNET_h2s (&sm->query),
              (unsigned int) type);
  cr = NULL;
  /* detect duplicate UBLOCK requests */
  if ((type == GNUNET_BLOCK_TYPE_FS_UBLOCK) ||
      (type == GNUNET_BLOCK_TYPE_ANY))
  {
    cr = lc->cr_head;
    while (NULL != cr)
    {
      prd = GSF_pending_request_get_data_ (cr->pr);
      /* only unify with queries that hae not yet started local processing
	 (SEARCH_MESSAGE_OPTION_CONTINUED was always set) and that have a
	 matching query and type */
      if ((GNUNET_YES != prd->has_started) &&
	  (0 != memcmp (&prd->query,
                        &sm->query,
                        sizeof (struct GNUNET_HashCode))) &&
          (prd->type == type))
        break;
      cr = cr->next;
    }
  }
  if (NULL != cr)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Have existing request, merging content-seen lists.\n");
    GSF_pending_request_update_ (cr->pr,
                                 (const struct GNUNET_HashCode *) &sm[1],
                                 sc);
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop ("# client searches updated (merged content seen list)"),
                              1,
                              GNUNET_NO);
  }
  else
  {
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop ("# client searches active"),
                              1,
                              GNUNET_NO);
    cr = GNUNET_new (struct ClientRequest);
    cr->lc = lc;
    GNUNET_CONTAINER_DLL_insert (lc->cr_head,
                                 lc->cr_tail,
                                 cr);
    options = GSF_PRO_LOCAL_REQUEST;
    if (0 != (SEARCH_MESSAGE_OPTION_LOOPBACK_ONLY & ntohl (sm->options)))
      options |= GSF_PRO_LOCAL_ONLY;
    cr->pr = GSF_pending_request_create_ (options, type,
					  &sm->query,
                                          (0 !=
                                           memcmp (&sm->target,
                                                   &all_zeros,
                                                   sizeof (struct GNUNET_PeerIdentity)))
                                          ? &sm->target : NULL, NULL, 0,
                                          0 /* bf */ ,
                                          ntohl (sm->anonymity_level),
                                          0 /* priority */ ,
                                          0 /* ttl */ ,
                                          0 /* sender PID */ ,
                                          0 /* origin PID */ ,
                                          (const struct GNUNET_HashCode *) &sm[1], sc,
                                          &client_response_handler,
                                          cr);
  }
  if (0 != (SEARCH_MESSAGE_OPTION_CONTINUED & ntohl (sm->options)))
  {
    GNUNET_SERVICE_client_continue (lc->client);
    return;
  }
  GSF_pending_request_get_data_ (cr->pr)->has_started = GNUNET_YES;
  GSF_local_lookup_ (cr->pr,
                     &start_p2p_processing,
                     lc);
}


/**
 * Handle request to sign a LOC URI (from client).
 *
 * @param cls identification of the client
 * @param msg the actual message
 */
static void
handle_client_loc_sign (void *cls,
                        const struct RequestLocSignatureMessage *msg)
{
  struct GSF_LocalClient *lc = cls;
  struct GNUNET_FS_Uri base;
  struct GNUNET_FS_Uri *loc;
  struct GNUNET_MQ_Envelope *env;
  struct ResponseLocSignatureMessage *resp;

  GNUNET_break (GNUNET_SIGNATURE_PURPOSE_PEER_PLACEMENT ==
                ntohl (msg->purpose));
  base.type = GNUNET_FS_URI_CHK;
  base.data.chk.chk = msg->chk;
  base.data.chk.file_length = GNUNET_ntohll (msg->file_length);
  loc = GNUNET_FS_uri_loc_create (&base,
                                  pk,
                                  GNUNET_TIME_absolute_ntoh (msg->expiration_time));
  env = GNUNET_MQ_msg (resp,
                       GNUNET_MESSAGE_TYPE_FS_REQUEST_LOC_SIGNATURE);
  resp->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_PEER_PLACEMENT);
  resp->expiration_time = GNUNET_TIME_absolute_hton (loc->data.loc.expirationTime);
  resp->signature = loc->data.loc.contentSignature;
  resp->peer = loc->data.loc.peer;
  GNUNET_FS_uri_destroy (loc);
  GNUNET_MQ_send (lc->mq,
                  env);
  GNUNET_SERVICE_client_continue (lc->client);
}


/**
 * Check INDEX_START-message.
 *
 * @param cls identification of the client
 * @param ism the actual message
 * @return #GNUNET_OK if @a ism is well-formed
 */
static int
check_client_index_start (void *cls,
                          const struct IndexStartMessage *ism)
{
  uint16_t msize;
  char *fn;

  msize = ntohs (ism->header.size);
  if (((const char *) ism)[msize - 1] != '\0')
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (0 != ism->reserved)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  fn = GNUNET_STRINGS_filename_expand ((const char *) &ism[1]);
  if (NULL == fn)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_free (fn);
  return GNUNET_OK;
}


/**
 * We've validated the hash of the file we're about to index.  Signal
 * success to the client and update our internal data structures.
 *
 * @param isc the data about the index info entry for the request
 */
static void
signal_index_ok (struct IndexStartContext *isc)
{
  struct GSF_LocalClient *lc = isc->lc;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;

  GNUNET_FS_add_to_index (isc->filename,
                          &isc->file_id);
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_FS_INDEX_START_OK);
  GNUNET_MQ_send (lc->mq,
                  env);
  GNUNET_free (isc->filename);
  GNUNET_free (isc);
  GNUNET_SERVICE_client_continue (lc->client);
}


/**
 * Function called once the hash computation over an
 * indexed file has completed.
 *
 * @param cls closure, our publishing context
 * @param res resulting hash, NULL on error
 */
static void
hash_for_index_val (void *cls,
                    const struct GNUNET_HashCode *res)
{
  struct IndexStartContext *isc = cls;
  struct GSF_LocalClient *lc = isc->lc;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;

  GNUNET_CONTAINER_DLL_remove (lc->isc_head,
                               lc->isc_tail,
                               isc);
  isc->fhc = NULL;
  if ( (NULL == res) ||
       (0 != memcmp (res,
                     &isc->file_id,
                     sizeof (struct GNUNET_HashCode))))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Hash mismatch trying to index file `%s' which does not have hash `%s'\n"),
                isc->filename,
                GNUNET_h2s (&isc->file_id));
    env = GNUNET_MQ_msg (msg,
                         GNUNET_MESSAGE_TYPE_FS_INDEX_START_FAILED);
    GNUNET_MQ_send (lc->mq,
                    env);
    GNUNET_SERVICE_client_continue (lc->client);
    GNUNET_free (isc);
    return;
  }
  signal_index_ok (isc);
}


/**
 * Handle INDEX_START-message.
 *
 * @param cls identification of the client
 * @param message the actual message
 */
static void
handle_client_index_start (void *cls,
                           const struct IndexStartMessage *ism)
{
  struct GSF_LocalClient *lc = cls;
  struct IndexStartContext *isc;
  char *fn;
  uint64_t dev;
  uint64_t ino;
  uint64_t mydev;
  uint64_t myino;

  fn = GNUNET_STRINGS_filename_expand ((const char *) &ism[1]);
  GNUNET_assert (NULL != fn);
  dev = GNUNET_ntohll (ism->device);
  ino = GNUNET_ntohll (ism->inode);
  isc = GNUNET_new (struct IndexStartContext);
  isc->filename = fn;
  isc->file_id = ism->file_id;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received START_INDEX message for file `%s'\n",
              isc->filename);
  isc->lc = lc;
  mydev = 0;
  myino = 0;
  if ( ( (dev != 0) ||
         (ino != 0) ) &&
       (GNUNET_OK == GNUNET_DISK_file_get_identifiers (fn,
                                                       &mydev,
                                                       &myino)) &&
       (dev == mydev) &&
       (ino == myino) )
  {
    /* fast validation OK! */
    signal_index_ok (isc);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Mismatch in file identifiers (%llu != %llu or %u != %u), need to hash.\n",
              (unsigned long long) ino,
              (unsigned long long) myino,
              (unsigned int) dev,
              (unsigned int) mydev);
  /* slow validation, need to hash full file (again) */
  GNUNET_CONTAINER_DLL_insert (lc->isc_head,
                               lc->isc_tail,
                               isc);
  isc->fhc = GNUNET_CRYPTO_hash_file (GNUNET_SCHEDULER_PRIORITY_IDLE,
                                      isc->filename,
                                      HASHING_BLOCKSIZE,
                                      &hash_for_index_val,
                                      isc);
  if (NULL == isc->fhc)
    hash_for_index_val (isc,
                        NULL);
}


/**
 * Handle INDEX_LIST_GET-message.
 *
 * @param cls closure
 * @param message the actual message
 */
static void
handle_client_index_list_get (void *cls,
                              const struct GNUNET_MessageHeader *message)
{
  struct GSF_LocalClient *lc = cls;

  GNUNET_FS_indexing_send_list (lc->mq);
  GNUNET_SERVICE_client_continue (lc->client);
}


/**
 * Handle UNINDEX-message.
 *
 * @param cls identification of the client
 * @param message the actual message
 */
static void
handle_client_unindex (void *cls,
                       const struct UnindexMessage *um)
{
  struct GSF_LocalClient *lc = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;
  int found;

  GNUNET_break (0 == um->reserved);
  found = GNUNET_FS_indexing_do_unindex (&um->file_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client requested unindexing of file `%s': %s\n",
              GNUNET_h2s (&um->file_id),
              found ? "found" : "not found");
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_FS_UNINDEX_OK);
  GNUNET_MQ_send (lc->mq,
                  env);
  GNUNET_SERVICE_client_continue (lc->client);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  GSF_cadet_stop_server ();
  if (NULL != GSF_core)
  {
    GNUNET_CORE_disconnect (GSF_core);
    GSF_core = NULL;
  }
  if (NULL != GSF_ats)
  {
    GNUNET_ATS_performance_done (GSF_ats);
    GSF_ats = NULL;
  }
  GSF_put_done_ ();
  GSF_push_done_ ();
  GSF_pending_request_done_ ();
  GSF_plan_done ();
  GSF_connected_peer_done_ ();
  GNUNET_DATASTORE_disconnect (GSF_dsh,
                               GNUNET_NO);
  GSF_dsh = NULL;
  GNUNET_DHT_disconnect (GSF_dht);
  GSF_dht = NULL;
  GNUNET_BLOCK_context_destroy (GSF_block_ctx);
  GSF_block_ctx = NULL;
  GNUNET_CONFIGURATION_destroy (block_cfg);
  block_cfg = NULL;
  GNUNET_STATISTICS_destroy (GSF_stats, GNUNET_NO);
  GSF_stats = NULL;
  if (NULL != cover_age_task)
  {
    GNUNET_SCHEDULER_cancel (cover_age_task);
    cover_age_task = NULL;
  }
  GNUNET_FS_indexing_done ();
  GNUNET_LOAD_value_free (datastore_get_load);
  datastore_get_load = NULL;
  GNUNET_LOAD_value_free (GSF_rt_entry_lifetime);
  GSF_rt_entry_lifetime = NULL;
}


/**
 * Function called after GNUNET_CORE_connect has succeeded
 * (or failed for good).  Note that the private key of the
 * peer is intentionally not exposed here; if you need it,
 * your process should try to read the private key file
 * directly (which should work if you are authorized...).
 *
 * @param cls closure
 * @param my_identity ID of this peer, NULL if we failed
 */
static void
peer_init_handler (void *cls,
                   const struct GNUNET_PeerIdentity *my_identity)
{
  if (0 != GNUNET_CRYPTO_cmp_peer_identity (&GSF_my_id,
                                            my_identity))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Peer identity missmatch, refusing to start!\n");
    GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * Process fs requests.
 *
 * @param c configuration to use
 */
static int
main_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_MQ_MessageHandler no_p2p_handlers[] = {
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_MessageHandler p2p_handlers[] = {
    GNUNET_MQ_hd_var_size (p2p_get,
                           GNUNET_MESSAGE_TYPE_FS_GET,
                           struct GetMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (p2p_put,
                           GNUNET_MESSAGE_TYPE_FS_PUT,
                           struct PutMessage,
                           NULL),
    GNUNET_MQ_hd_fixed_size (p2p_migration_stop,
                             GNUNET_MESSAGE_TYPE_FS_MIGRATION_STOP,
                             struct MigrationStopMessage,
                             NULL),
    GNUNET_MQ_handler_end ()
  };
  int anon_p2p_off;
  char *keyfile;

  /* this option is really only for testcases that need to disable
     _anonymous_ file-sharing for some reason */
  anon_p2p_off = (GNUNET_YES ==
		  GNUNET_CONFIGURATION_get_value_yesno (GSF_cfg,
							"fs",
							"DISABLE_ANON_TRANSFER"));

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (GSF_cfg,
                                               "PEER",
                                               "PRIVATE_KEY",
                                               &keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("FS service is lacking HOSTKEY configuration setting.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return GNUNET_SYSERR;
  }
  pk = GNUNET_CRYPTO_eddsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  GNUNET_assert (NULL != pk);
  GNUNET_CRYPTO_eddsa_key_get_public (pk,
                                      &GSF_my_id.public_key);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "I am peer %s\n",
              GNUNET_i2s (&GSF_my_id));
  GSF_core
    = GNUNET_CORE_connect (GSF_cfg,
			   NULL,
                           &peer_init_handler,
                           &GSF_peer_connect_handler,
                           &GSF_peer_disconnect_handler,
			   (GNUNET_YES == anon_p2p_off)
			   ? no_p2p_handlers
			   : p2p_handlers);
  if (NULL == GSF_core)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to connect to `%s' service.\n"),
		"core");
    return GNUNET_SYSERR;
  }
  cover_age_task =
      GNUNET_SCHEDULER_add_delayed (COVER_AGE_FREQUENCY,
				    &age_cover_counters,
                                    NULL);
  datastore_get_load = GNUNET_LOAD_value_init (DATASTORE_LOAD_AUTODECLINE);
  GSF_cadet_start_server ();
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 NULL);
  return GNUNET_OK;
}


/**
 * Process fs requests.
 *
 * @param cls closure
 * @param cfg configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_SERVICE_Handle *service)
{
  unsigned long long dqs;

  GSF_cfg = cfg;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_size (GSF_cfg,
                                           "fs",
                                           "DATASTORE_QUEUE_SIZE",
                                           &dqs))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_INFO,
			       "fs",
                               "DATASTORE_QUEUE_SIZE");
    dqs = 1024;
  }
  GSF_datastore_queue_size = (unsigned int) dqs;
  GSF_enable_randomized_delays =
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "fs", "DELAY");
  GSF_dsh = GNUNET_DATASTORE_connect (cfg);
  if (NULL == GSF_dsh)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GSF_rt_entry_lifetime = GNUNET_LOAD_value_init (GNUNET_TIME_UNIT_FOREVER_REL);
  GSF_stats = GNUNET_STATISTICS_create ("fs", cfg);
  block_cfg = GNUNET_CONFIGURATION_create ();
  GSF_block_ctx = GNUNET_BLOCK_context_create (block_cfg);
  GNUNET_assert (NULL != GSF_block_ctx);
  GSF_dht = GNUNET_DHT_connect (cfg, FS_DHT_HT_SIZE);
  GSF_plan_init ();
  GSF_pending_request_init_ ();
  GSF_connected_peer_init_ ();
  GSF_ats = GNUNET_ATS_performance_init (GSF_cfg,
                                         &update_latencies,
                                         NULL);
  GSF_push_init_ ();
  GSF_put_init_ ();
  if ( (GNUNET_OK != GNUNET_FS_indexing_init (cfg,
                                              GSF_dsh)) ||
       (GNUNET_OK != main_init (cfg)) )
  {
    GNUNET_SCHEDULER_shutdown ();
    shutdown_task (NULL);
    return;
  }
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("fs",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (client_index_start,
                        GNUNET_MESSAGE_TYPE_FS_INDEX_START,
                        struct IndexStartMessage,
                        NULL),
 GNUNET_MQ_hd_fixed_size (client_index_list_get,
			  GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_GET,
			  struct GNUNET_MessageHeader,
			  NULL),
 GNUNET_MQ_hd_fixed_size (client_unindex,
			  GNUNET_MESSAGE_TYPE_FS_UNINDEX,
			  struct UnindexMessage,
			  NULL),
 GNUNET_MQ_hd_var_size (client_start_search,
                        GNUNET_MESSAGE_TYPE_FS_START_SEARCH,
                        struct SearchMessage,
                        NULL),
 GNUNET_MQ_hd_fixed_size (client_loc_sign,
			  GNUNET_MESSAGE_TYPE_FS_REQUEST_LOC_SIGN,
			  struct RequestLocSignatureMessage,
			  NULL),
 GNUNET_MQ_handler_end ());


/* end of gnunet-service-fs.c */
