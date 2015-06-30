/*
     This file is part of GNUnet.
     Copyright (C) 2009-2014 Christian Grothoff (and other contributing authors)

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
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity my_id;


/**
 * Task that periodically ages our cover traffic statistics.
 *
 * @param cls unused closure
 * @param tc task context
 */
static void
age_cover_counters (void *cls,
                    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GSF_cover_content_count = (GSF_cover_content_count * 15) / 16;
  GSF_cover_query_count = (GSF_cover_query_count * 15) / 16;
  cover_age_task =
      GNUNET_SCHEDULER_add_delayed (COVER_AGE_FREQUENCY, &age_cover_counters,
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
 * Handle P2P "PUT" message.
 *
 * @param cls closure, always NULL
 * @param other the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_p2p_put (void *cls,
                const struct GNUNET_PeerIdentity *other,
                const struct GNUNET_MessageHeader *message)
{
  struct GSF_ConnectedPeer *cp;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received P2P PUT from %s\n",
              GNUNET_i2s (other));
  cp = GSF_peer_get_ (other);
  if (NULL == cp)
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  GSF_cover_content_count++;
  return GSF_handle_p2p_content_ (cp, message);
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

  if (GNUNET_YES != GSF_pending_request_test_target_ (pr, peer))
  {
#if INSANE_STATISTICS
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop ("# Loopback routes suppressed"), 1,
                              GNUNET_NO);
#endif
    return;
  }
  GSF_plan_add_ (cp, pr);
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
static void
consider_forwarding (void *cls,
                     struct GSF_PendingRequest *pr,
                     enum GNUNET_BLOCK_EvaluationResult result)
{
  if (GNUNET_BLOCK_EVALUATION_OK_LAST == result)
    return;                     /* we're done... */
  GSF_iterate_connected_peers_ (&consider_request_for_forwarding, pr);
}


/**
 * Handle P2P "GET" request.
 *
 * @param cls closure, always NULL
 * @param other the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_p2p_get (void *cls,
                const struct GNUNET_PeerIdentity *other,
                const struct GNUNET_MessageHeader *message)
{
  struct GSF_PendingRequest *pr;

  pr = GSF_handle_p2p_query_ (other, message);
  if (NULL == pr)
    return GNUNET_SYSERR;
  GSF_pending_request_get_data_ (pr)->has_started = GNUNET_YES;
  GSF_local_lookup_ (pr,
                     &consider_forwarding, NULL);
  return GNUNET_OK;
}


/**
 * We're done with the local lookup, now consider
 * P2P processing (depending on request options and
 * result status).  Also signal that we can now
 * receive more request information from the client.
 *
 * @param cls the client doing the request (`struct GNUNET_SERVER_Client`)
 * @param pr the pending request we were processing
 * @param result final datastore lookup result
 */
static void
start_p2p_processing (void *cls,
                      struct GSF_PendingRequest *pr,
                      enum GNUNET_BLOCK_EvaluationResult result)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct GSF_PendingRequestData *prd;

  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
  if (GNUNET_BLOCK_EVALUATION_OK_LAST == result)
    return;                     /* we're done, 'pr' was already destroyed... */
  prd = GSF_pending_request_get_data_ (pr);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Finished database lookup for local request `%s' with result %d\n",
              GNUNET_h2s (&prd->query), result);
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
  consider_forwarding (NULL, pr, result);
}


/**
 * Handle START_SEARCH-message (search request from client).
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_start_search (void *cls,
                     struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *message)
{
  struct GSF_PendingRequest *pr;
  int ret;

  pr = NULL;
  ret = GSF_local_client_start_search_handler_ (client,
                                                message,
                                                &pr);
  switch (ret)
  {
  case GNUNET_SYSERR:
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    break;
  case GNUNET_NO:
    GNUNET_SERVER_receive_done (client,
                                GNUNET_OK);
    break;
  case GNUNET_YES:
    GSF_pending_request_get_data_ (pr)->has_started = GNUNET_YES;
    GSF_local_lookup_ (pr,
                       &start_p2p_processing,
                       client);
    break;
  default:
    GNUNET_assert (0);
  }
}


/**
 * Handle request to sign a LOC URI (from client).
 *
 * @param cls closure (NULL)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_loc_sign (void *cls,
                 struct GNUNET_SERVER_Client *client,
                 const struct GNUNET_MessageHeader *message)
{
  const struct RequestLocSignatureMessage *msg;
  struct GNUNET_FS_Uri base;
  struct GNUNET_FS_Uri *loc;
  struct ResponseLocSignatureMessage resp;
  struct GSF_LocalClient *lc;

  msg = (const struct RequestLocSignatureMessage *) message;
  GNUNET_break (GNUNET_SIGNATURE_PURPOSE_PEER_PLACEMENT ==
                ntohl (msg->purpose));
  base.type = GNUNET_FS_URI_CHK;
  base.data.chk.chk = msg->chk;
  base.data.chk.file_length = GNUNET_ntohll (msg->file_length);
  loc = GNUNET_FS_uri_loc_create (&base,
                                  pk,
                                  GNUNET_TIME_absolute_ntoh (msg->expiration_time));
  resp.header.size = htons (sizeof (struct ResponseLocSignatureMessage));
  resp.header.type = htons (GNUNET_MESSAGE_TYPE_FS_REQUEST_LOC_SIGNATURE);
  resp.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_PEER_PLACEMENT);
  resp.expiration_time = GNUNET_TIME_absolute_hton (loc->data.loc.expirationTime);
  resp.signature = loc->data.loc.contentSignature;
  resp.peer = loc->data.loc.peer;
  GNUNET_FS_uri_destroy (loc);
  lc = GSF_local_client_lookup_ (client);
  GSF_local_client_transmit_ (lc,
                              &resp.header);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GSF_cadet_stop_client ();
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
  GNUNET_DATASTORE_disconnect (GSF_dsh, GNUNET_NO);
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
 * Function called for each pending request whenever a new
 * peer connects, giving us a chance to decide about submitting
 * the existing request to the new peer.
 *
 * @param cls the 'struct GSF_ConnectedPeer' of the new peer
 * @param key query for the request
 * @param pr handle to the pending request
 * @return #GNUNET_YES to continue to iterate
 */
static int
consider_peer_for_forwarding (void *cls,
                              const struct GNUNET_HashCode *key,
                              struct GSF_PendingRequest *pr)
{
  struct GSF_ConnectedPeer *cp = cls;
  struct GNUNET_PeerIdentity pid;

  GSF_connected_peer_get_identity_ (cp, &pid);
  if (GNUNET_YES != GSF_pending_request_test_target_ (pr, &pid))
  {
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop ("# Loopback routes suppressed"), 1,
                              GNUNET_NO);
    return GNUNET_YES;
  }
  GSF_plan_add_ (cp, pr);
  return GNUNET_YES;
}


/**
 * Function called after the creation of a connected peer record is complete.
 *
 * @param cls closure (unused)
 * @param cp handle to the newly created connected peer record
 */
static void
connected_peer_cb (void *cls, struct GSF_ConnectedPeer *cp)
{
  if (NULL == cp)
    return;
  GSF_iterate_pending_requests_ (&consider_peer_for_forwarding, cp);
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure, not used
 * @param peer peer identity this notification is about
 */
static void
peer_connect_handler (void *cls,
                      const struct GNUNET_PeerIdentity *peer)
{
  if (0 ==
      GNUNET_CRYPTO_cmp_peer_identity (&my_id,
                                       peer))
    return;
  GSF_peer_connect_handler_ (peer,
                             &connected_peer_cb,
                             NULL);
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
  if (0 != GNUNET_CRYPTO_cmp_peer_identity (&my_id,
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
 * @param server the initialized server
 * @param c configuration to use
 */
static int
main_init (struct GNUNET_SERVER_Handle *server,
           const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_CORE_MessageHandler no_p2p_handlers[] = {
    { NULL, 0, 0 }
  };
  static const struct GNUNET_CORE_MessageHandler p2p_handlers[] = {
    { &handle_p2p_get,
      GNUNET_MESSAGE_TYPE_FS_GET, 0 },
    { &handle_p2p_put,
      GNUNET_MESSAGE_TYPE_FS_PUT, 0 },
    { &GSF_handle_p2p_migration_stop_,
      GNUNET_MESSAGE_TYPE_FS_MIGRATION_STOP,
      sizeof (struct MigrationStopMessage) },
    { NULL, 0, 0 }
  };
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    { &GNUNET_FS_handle_index_start, NULL,
      GNUNET_MESSAGE_TYPE_FS_INDEX_START, 0 },
    { &GNUNET_FS_handle_index_list_get, NULL,
      GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_GET,
      sizeof (struct GNUNET_MessageHeader) },
    { &GNUNET_FS_handle_unindex, NULL,
      GNUNET_MESSAGE_TYPE_FS_UNINDEX,
      sizeof (struct UnindexMessage) },
    { &handle_start_search, NULL,
      GNUNET_MESSAGE_TYPE_FS_START_SEARCH, 0 },
    { &handle_loc_sign, NULL,
      GNUNET_MESSAGE_TYPE_FS_REQUEST_LOC_SIGN,
      sizeof (struct RequestLocSignatureMessage) },
    {NULL, NULL, 0, 0}
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
                                      &my_id.public_key);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "I am peer %s\n",
              GNUNET_i2s (&my_id));
  GSF_core
    = GNUNET_CORE_connect (GSF_cfg, NULL,
                           &peer_init_handler,
                           &peer_connect_handler,
                           &GSF_peer_disconnect_handler_,
                           NULL, GNUNET_NO,
                           NULL, GNUNET_NO,
			   (GNUNET_YES == anon_p2p_off)
			   ? no_p2p_handlers
			   : p2p_handlers);
  if (NULL == GSF_core)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to connect to `%s' service.\n"), "core");
    return GNUNET_SYSERR;
  }
  GNUNET_SERVER_disconnect_notify (server, &GSF_client_disconnect_handler_,
                                   NULL);
  GNUNET_SERVER_add_handlers (server, handlers);
  cover_age_task =
      GNUNET_SCHEDULER_add_delayed (COVER_AGE_FREQUENCY, &age_cover_counters,
                                    NULL);
  datastore_get_load = GNUNET_LOAD_value_init (DATASTORE_LOAD_AUTODECLINE);
  GSF_cadet_start_server ();
  GSF_cadet_start_client ();
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  return GNUNET_OK;
}


/**
 * Process fs requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  unsigned long long dqs;

  GSF_cfg = cfg;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_size (GSF_cfg, "fs", "DATASTORE_QUEUE_SIZE",
                                           &dqs))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_INFO,
			       "fs", "DATASTORE_QUEUE_SIZE");
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
  GSF_ats = GNUNET_ATS_performance_init (GSF_cfg, &update_latencies, NULL);
  GSF_push_init_ ();
  GSF_put_init_ ();
  if ((GNUNET_OK != GNUNET_FS_indexing_init (cfg, GSF_dsh)) ||
      (GNUNET_OK != main_init (server, cfg)))
  {
    GNUNET_SCHEDULER_shutdown ();
    shutdown_task (NULL, NULL);
    return;
  }
}


/**
 * The main function for the fs service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "fs", GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-fs.c */
