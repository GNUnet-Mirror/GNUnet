/*
     This file is part of GNUnet.
     Copyright (C)

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
 * @file rps/gnunet-service-rps.c
 * @brief rps service implementation
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_cadet_service.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_nse_service.h"
#include "rps.h"
#include "rps-test_util.h"
#include "gnunet-service-rps_sampler.h"
#include "gnunet-service-rps_custommap.h"
#include "gnunet-service-rps_peers.h"
#include "gnunet-service-rps_view.h"

#include <math.h>
#include <inttypes.h>

#define LOG(kind, ...) GNUNET_log(kind, __VA_ARGS__)

// TODO modify @brief in every file

// TODO check for overflows

// TODO align message structs

// TODO connect to friends

// TODO store peers somewhere persistent

// TODO blacklist? (-> mal peer detection on top of brahms)

// hist_size_init, hist_size_max

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Our own identity.
 */
static struct GNUNET_PeerIdentity own_identity;


/***********************************************************************
 * Housekeeping with peers
***********************************************************************/

/**
 * Closure used to pass the client and the id to the callback
 * that replies to a client's request
 */
struct ReplyCls
{
  /**
   * DLL
   */
  struct ReplyCls *next;
  struct ReplyCls *prev;

  /**
   * The identifier of the request
   */
  uint32_t id;

  /**
   * The handle to the request
   */
  struct RPS_SamplerRequestHandle *req_handle;

  /**
   * The client handle to send the reply to
   */
  struct GNUNET_SERVER_Client *client;
};


/**
 * Struct used to store the context of a connected client.
 */
struct ClientContext
{
  /**
   * DLL
   */
  struct ClientContext *next;
  struct ClientContext *prev;

  /**
   * The message queue to communicate with the client.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * DLL with handles to single requests from the client
   */
  struct ReplyCls *rep_cls_head;
  struct ReplyCls *rep_cls_tail;
};

/**
 * DLL with all clients currently connected to us
 */
struct ClientContext *cli_ctx_head;
struct ClientContext *cli_ctx_tail;

/***********************************************************************
 * /Housekeeping with peers
***********************************************************************/





/***********************************************************************
 * Globals
***********************************************************************/

/**
 * Sampler used for the Brahms protocol itself.
 */
static struct RPS_Sampler *prot_sampler;

/**
 * Sampler used for the clients.
 */
static struct RPS_Sampler *client_sampler;


/**
 * Name to log view to
 */
static char *file_name_view_log;


/**
 * The size of sampler we need to be able to satisfy the client's need of
 * random peers.
 */
static unsigned int sampler_size_client_need;

/**
 * The size of sampler we need to be able to satisfy the Brahms protocol's
 * need of random peers.
 *
 * This is one minimum size the sampler grows to.
 */
static unsigned int sampler_size_est_need;


/**
 * Percentage of total peer number in the view
 * to send random PUSHes to
 */
static float alpha;

/**
 * Percentage of total peer number in the view
 * to send random PULLs to
 */
static float beta;

/**
 * The percentage gamma of history updates.
 * Simply 1 - alpha - beta
 */


/**
 * Identifier for the main task that runs periodically.
 */
static struct GNUNET_SCHEDULER_Task *do_round_task;

/**
 * Time inverval the do_round task runs in.
 */
static struct GNUNET_TIME_Relative round_interval;



/**
 * List to store peers received through pushes temporary.
 */
static struct CustomPeerMap *push_map;

/**
 * List to store peers received through pulls temporary.
 */
static struct CustomPeerMap *pull_map;


/**
 * Handler to NSE.
 */
static struct GNUNET_NSE_Handle *nse;

/**
 * Handler to CADET.
 */
static struct GNUNET_CADET_Handle *cadet_handle;

/**
 * Handler to PEERINFO.
 */
static struct GNUNET_PEERINFO_Handle *peerinfo_handle;

/**
 * Handle for cancellation of iteration over peers.
 */
struct GNUNET_PEERINFO_NotifyContext *peerinfo_notify_handle;


/**
 * Request counter.
 *
 * Only needed in the beginning to check how many of the 64 deltas
 * we already have
 */
static unsigned int req_counter;

/**
 * Time of the last request we received.
 *
 * Used to compute the expected request rate.
 */
static struct GNUNET_TIME_Absolute last_request;

/**
 * Size of #request_deltas.
 */
#define REQUEST_DELTAS_SIZE 64
static unsigned int request_deltas_size = REQUEST_DELTAS_SIZE;

/**
 * Last 64 deltas between requests
 */
static struct GNUNET_TIME_Relative request_deltas[REQUEST_DELTAS_SIZE];

/**
 * The prediction of the rate of requests
 */
static struct GNUNET_TIME_Relative  request_rate;


/**
 * Number of history update tasks.
 */
uint32_t num_hist_update_tasks;


#ifdef ENABLE_MALICIOUS
/**
 * Type of malicious peer
 *
 * 0 Don't act malicious at all - Default
 * 1 Try to maximise representation
 * 2 Try to partition the network
 * 3 Combined attack
 */
uint32_t mal_type = 0;

/**
 * Other malicious peers
 */
static struct GNUNET_PeerIdentity *mal_peers = NULL;

/**
 * Hashmap of malicious peers used as set.
 * Used to more efficiently check whether we know that peer.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *mal_peer_set = NULL;

/**
 * Number of other malicious peers
 */
static uint32_t num_mal_peers;


/**
 * If type is 2 This struct is used to store the attacked peers in a DLL
 */
struct AttackedPeer
{
  /**
   * DLL
   */
  struct AttackedPeer *next;
  struct AttackedPeer *prev;

  /**
   * PeerID
   */
  struct GNUNET_PeerIdentity peer_id;
};

/**
 * If type is 2 this is the DLL of attacked peers
 */
static struct AttackedPeer *att_peers_head = NULL;
static struct AttackedPeer *att_peers_tail = NULL;

/**
 * This index is used to point to an attacked peer to
 * implement the round-robin-ish way to select attacked peers.
 */
static struct AttackedPeer *att_peer_index = NULL;

/**
 * Hashmap of attacked peers used as set.
 * Used to more efficiently check whether we know that peer.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *att_peer_set = NULL;

/**
 * Number of attacked peers
 */
static uint32_t num_attacked_peers = 0;


/**
 * If type is 1 this is the attacked peer
 */
static struct GNUNET_PeerIdentity attacked_peer;

/**
 * The limit of PUSHes we can send in one round.
 * This is an assumption of the Brahms protocol and either implemented
 * via proof of work
 * or
 * assumend to be the bandwidth limitation.
 */
static uint32_t push_limit = 10000;
#endif /* ENABLE_MALICIOUS */


/***********************************************************************
 * /Globals
***********************************************************************/






/***********************************************************************
 * Util functions
***********************************************************************/


/**
 * Print peerlist to log.
 */
void
print_peer_list (struct GNUNET_PeerIdentity *list, unsigned int len)
{
  unsigned int i;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Printing peer list of length %u at %p:\n",
       len,
       list);
  for (i = 0 ; i < len ; i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%u. peer: %s\n",
         i, GNUNET_i2s (&list[i]));
  }
}


/**
 * Remove peer from list.
 */
  void
rem_from_list (struct GNUNET_PeerIdentity **peer_list,
               unsigned int *list_size,
               const struct GNUNET_PeerIdentity *peer)
{
  unsigned int i;
  struct GNUNET_PeerIdentity *tmp;

  tmp = *peer_list;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Removing peer %s from list at %p\n",
       GNUNET_i2s (peer),
       tmp);

  for ( i = 0 ; i < *list_size ; i++ )
  {
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&tmp[i], peer))
    {
      if (i < *list_size -1)
      { /* Not at the last entry -- shift peers left */
        memcpy (&tmp[i], &tmp[i +1],
                ((*list_size) - i -1) * sizeof (struct GNUNET_PeerIdentity));
      }
      /* Remove last entry (should be now useless PeerID) */
      GNUNET_array_grow (tmp, *list_size, (*list_size) -1);
    }
  }
  *peer_list = tmp;
}


/**
 * Sum all time relatives of an array.
  */
  struct GNUNET_TIME_Relative
T_relative_sum (const struct GNUNET_TIME_Relative *rel_array, uint32_t arr_size)
{
  struct GNUNET_TIME_Relative sum;
  uint32_t i;

  sum = GNUNET_TIME_UNIT_ZERO;
  for ( i = 0 ; i < arr_size ; i++ )
  {
    sum = GNUNET_TIME_relative_add (sum, rel_array[i]);
  }
  return sum;
}


/**
 * Compute the average of given time relatives.
 */
  struct GNUNET_TIME_Relative
T_relative_avg (const struct GNUNET_TIME_Relative *rel_array, uint32_t arr_size)
{
  return GNUNET_TIME_relative_divide (T_relative_sum (rel_array, arr_size), arr_size);
}


/**
 * Put random peer from sampler into the view as history update.
 */
  void
hist_update (void *cls, struct GNUNET_PeerIdentity *ids, uint32_t num_peers)
{
  unsigned int i;

  for (i = 0; i < num_peers; i++)
  {
    View_put (&ids[i]);
    to_file (file_name_view_log,
             "+%s\t(hist)",
             GNUNET_i2s_full (ids));
  }
  if (0 < num_hist_update_tasks)
    num_hist_update_tasks--;
}



/**
 * Wrapper around #RPS_sampler_resize()
 *
 * If we do not have enough sampler elements, double current sampler size
 * If we have more than enough sampler elements, halv current sampler size
 */
static void
resize_wrapper (struct RPS_Sampler *sampler, uint32_t new_size)
{
  unsigned int sampler_size;

  // TODO statistics
  // TODO respect the min, max
  sampler_size = RPS_sampler_get_size (sampler);
  if (sampler_size > new_size * 4)
  { /* Shrinking */
    RPS_sampler_resize (sampler, sampler_size / 2);
  }
  else if (sampler_size < new_size)
  { /* Growing */
    RPS_sampler_resize (sampler, sampler_size * 2);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "sampler_size is now %u\n", sampler_size);
}


/**
 * Wrapper around #RPS_sampler_resize() resizing the client sampler
 */
static void
client_resize_wrapper ()
{
  uint32_t bigger_size;

  // TODO statistics

  bigger_size = GNUNET_MAX (sampler_size_est_need, sampler_size_client_need);

  // TODO respect the min, max
  resize_wrapper (client_sampler, bigger_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "sampler_size_client is now %" PRIu32 "\n",
      bigger_size);
}


/**
 * Estimate request rate
 *
 * Called every time we receive a request from the client.
 */
  void
est_request_rate()
{
  struct GNUNET_TIME_Relative max_round_duration;

  if (request_deltas_size > req_counter)
    req_counter++;
  if ( 1 < req_counter)
  {
    /* Shift last request deltas to the right */
    memcpy (&request_deltas[1],
        request_deltas,
        (req_counter - 1) * sizeof (struct GNUNET_TIME_Relative));

    /* Add current delta to beginning */
    request_deltas[0] =
        GNUNET_TIME_absolute_get_difference (last_request,
                                             GNUNET_TIME_absolute_get ());
    request_rate = T_relative_avg (request_deltas, req_counter);
    request_rate = (request_rate.rel_value_us < 1) ?
      GNUNET_TIME_relative_get_unit_ () : request_rate;

    /* Compute the duration a round will maximally take */
    max_round_duration =
        GNUNET_TIME_relative_add (round_interval,
                                  GNUNET_TIME_relative_divide (round_interval, 2));

    /* Set the estimated size the sampler has to have to
     * satisfy the current client request rate */
    sampler_size_client_need =
        max_round_duration.rel_value_us / request_rate.rel_value_us;

    /* Resize the sampler */
    client_resize_wrapper ();
  }
  last_request = GNUNET_TIME_absolute_get ();
}


/**
 * Add all peers in @a peer_array to @a peer_map used as set.
 *
 * @param peer_array array containing the peers
 * @param num_peers number of peers in @peer_array
 * @param peer_map the peermap to use as set
 */
static void
add_peer_array_to_set (const struct GNUNET_PeerIdentity *peer_array,
                       unsigned int num_peers,
                       struct GNUNET_CONTAINER_MultiPeerMap *peer_map)
{
  unsigned int i;
  if (NULL == peer_map)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Trying to add peers to non-existing peermap.\n");
    return;
  }

  for (i = 0; i < num_peers; i++)
  {
    GNUNET_CONTAINER_multipeermap_put (peer_map,
                                       &peer_array[i],
                                       NULL,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
}


/**
 * Send a PULL REPLY to @a peer_id
 *
 * @param peer_id the peer to send the reply to.
 * @param peer_ids the peers to send to @a peer_id
 * @param num_peer_ids the number of peers to send to @a peer_id
 */
static void
send_pull_reply (const struct GNUNET_PeerIdentity *peer_id,
                 const struct GNUNET_PeerIdentity *peer_ids,
                 unsigned int num_peer_ids)
{
  uint32_t send_size;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_P2P_PullReplyMessage *out_msg;

  /* Compute actual size */
  send_size = sizeof (struct GNUNET_RPS_P2P_PullReplyMessage) +
              num_peer_ids * sizeof (struct GNUNET_PeerIdentity);

  if (GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE < send_size)
    /* Compute number of peers to send
     * If too long, simply truncate */
    // TODO select random ones via permutation
    //      or even better: do good protocol design
    send_size =
      (GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE -
       sizeof (struct GNUNET_RPS_P2P_PullReplyMessage)) /
       sizeof (struct GNUNET_PeerIdentity);
  else
    send_size = num_peer_ids;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Going to send PULL REPLY with %u peers to %s\n",
      send_size, GNUNET_i2s (peer_id));

  ev = GNUNET_MQ_msg_extra (out_msg,
                            send_size * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REPLY);
  out_msg->num_peers = htonl (send_size);
  memcpy (&out_msg[1], peer_ids,
         send_size * sizeof (struct GNUNET_PeerIdentity));

  Peers_send_message (peer_id, ev, "PULL REPLY");
}


/**
 * Insert PeerID in #pull_map
 *
 * Called once we know a peer is live.
 */
  void
insert_in_pull_map (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  CustomPeerMap_put (pull_map, peer);
}

/**
 * Insert PeerID in #view
 *
 * Called once we know a peer is live.
 */
  void
insert_in_view (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  View_put (peer);
}

/**
 * Update sampler with given PeerID.
 */
  void
insert_in_sampler (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Updating samplers with peer %s from insert_in_sampler()\n",
       GNUNET_i2s (peer));
  RPS_sampler_update (prot_sampler,   peer);
  RPS_sampler_update (client_sampler, peer);
  if (0 < RPS_sampler_count_id (prot_sampler, peer))
  {
    /* Make sure we 'know' about this peer */
    (void) Peers_insert_peer (peer);
    /* Establish a channel towards that peer to indicate we are going to send
     * messages to it */
    Peers_indicate_sending_intention (peer);
    //Peers_issue_peer_liveliness_check (peer);
  }
}


/**
 * @brief Checks if there is a sending channel and if it is needed
 *
 * @param peer the peer whose sending channel is checked
 * @return GNUNET_YES if sending channel exists and is still needed
 *         GNUNET_NO  otherwise
 */
static int
check_sending_channel_needed (const struct GNUNET_PeerIdentity *peer)
{
  /* struct GNUNET_CADET_Channel *channel; */
  if (GNUNET_NO == Peers_check_peer_known (peer))
  {
    return GNUNET_NO;
  }
  if (GNUNET_YES == Peers_check_sending_channel_exists (peer))
  {
    if ( (0 < RPS_sampler_count_id (prot_sampler, peer)) ||
         (GNUNET_YES == View_contains_peer (peer)) ||
         (GNUNET_YES == CustomPeerMap_contains_peer (push_map, peer)) ||
         (GNUNET_YES == CustomPeerMap_contains_peer (pull_map, peer)) ||
         (GNUNET_YES == Peers_check_peer_flag (peer, Peers_PULL_REPLY_PENDING)))
    { /* If we want to keep the connection to peer open */
      return GNUNET_YES;
    }
    return GNUNET_NO;
  }
  return GNUNET_NO;
}

/**
 * @brief remove peer from our knowledge, the view, push and pull maps and
 * samplers.
 *
 * @param peer the peer to remove
 */
static void
remove_peer (const struct GNUNET_PeerIdentity *peer)
{
  View_remove_peer (peer);
  CustomPeerMap_remove_peer (pull_map, peer);
  CustomPeerMap_remove_peer (push_map, peer);
  RPS_sampler_reinitialise_by_value (prot_sampler, peer);
  RPS_sampler_reinitialise_by_value (client_sampler, peer);
  Peers_remove_peer (peer);
}


/**
 * @brief Remove data that is not needed anymore.
 *
 * If the sending channel is no longer needed it is destroyed.
 *
 * @param peer the peer whose data is about to be cleaned
 */
static void
clean_peer (const struct GNUNET_PeerIdentity *peer)
{
  if (GNUNET_NO == check_sending_channel_needed (peer))
  {
    #ifdef ENABLE_MALICIOUS
    if (0 != GNUNET_CRYPTO_cmp_peer_identity (&attacked_peer, peer))
      Peers_destroy_sending_channel (peer);
    #else /* ENABLE_MALICIOUS */
    Peers_destroy_sending_channel (peer);
    #endif /* ENABLE_MALICIOUS */
  }

  if ( (GNUNET_NO == Peers_check_peer_send_intention (peer)) &&
       (GNUNET_NO == View_contains_peer (peer)) &&
       (GNUNET_NO == CustomPeerMap_contains_peer (push_map, peer)) &&
       (GNUNET_NO == CustomPeerMap_contains_peer (push_map, peer)) &&
       (0 == RPS_sampler_count_id (prot_sampler,   peer)) &&
       (0 == RPS_sampler_count_id (client_sampler, peer)) )
  { /* We can safely remov this peer */
    remove_peer (peer);
    return;
  }
  Peers_clean_peer (peer);
}

/**
 * @brief This is called when a channel is destroyed.
 *
 * Removes peer completely from our knowledge if the send_channel was destroyed
 * Otherwise simply delete the recv_channel
 *
 * @param cls The closure
 * @param channel The channel being closed
 * @param channel_ctx The context associated with this channel
 */
static void
cleanup_destroyed_channel (void *cls,
                           const struct GNUNET_CADET_Channel *channel,
                           void *channel_ctx)
{
  struct GNUNET_PeerIdentity *peer;

  peer = (struct GNUNET_PeerIdentity *) GNUNET_CADET_channel_get_info (
      (struct GNUNET_CADET_Channel *) channel, GNUNET_CADET_OPTION_PEER);
       // FIXME wait for cadet to change this function

  if (GNUNET_NO == Peers_check_peer_known (peer))
  { /* We don't know a context to that peer */
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "channel (%s) without associated context was destroyed\n",
         GNUNET_i2s (peer));
    return;
  }

  if (GNUNET_YES == Peers_check_peer_flag (peer, Peers_TO_DESTROY))
  { /* We are in the middle of removing that peer from our knowledge. In this
       case simply make sure that the channels are cleaned. */
    Peers_cleanup_destroyed_channel (cls, channel, channel_ctx);
    to_file (file_name_view_log,
             "-%s\t(cleanup channel, ourself)",
             GNUNET_i2s_full (peer));
    return;
  }

  if (GNUNET_YES ==
      Peers_check_channel_role (peer, channel, Peers_CHANNEL_ROLE_SENDING))
  { /* Channel used for sending was destroyed */
    /* Possible causes of channel destruction:
     *  - ourselves  -> cleaning send channel -> clean context
     *  - other peer -> peer probably went down -> remove
     */
    if (GNUNET_YES == Peers_check_channel_flag (channel_ctx, Peers_CHANNEL_CLEAN))
    { /* We are about to clean the sending channel. Clean the respective
       * context */
      Peers_cleanup_destroyed_channel (cls, channel, channel_ctx);
      return;
    }
    else
    { /* Other peer destroyed our sending channel that he is supposed to keep
       * open. It probably went down. Remove it from our knowledge. */
      Peers_cleanup_destroyed_channel (cls, channel, channel_ctx);
      remove_peer (peer);
      return;
    }
  }
  else if (GNUNET_YES ==
      Peers_check_channel_role (peer, channel, Peers_CHANNEL_ROLE_RECEIVING))
  { /* Channel used for receiving was destroyed */
    /* Possible causes of channel destruction:
     *  - ourselves  -> peer tried to establish channel twice -> clean context
     *  - other peer -> peer doesn't want to send us data -> clean
     */
    if (GNUNET_YES ==
        Peers_check_channel_flag (channel_ctx, Peers_CHANNEL_ESTABLISHED_TWICE))
    { /* Other peer tried to establish a channel to us twice. We do not accept
       * that. Clean the context. */
      Peers_cleanup_destroyed_channel (cls, channel, channel_ctx);
      return;
    }
    else
    { /* Other peer doesn't want to send us data anymore. We are free to clean
       * it. */
      Peers_cleanup_destroyed_channel (cls, channel, channel_ctx);
      clean_peer (peer);
      return;
    }
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Destroyed channel is neither sending nor receiving channel\n");
  }
}

/***********************************************************************
 * /Util functions
***********************************************************************/

static void
destroy_reply_cls (struct ReplyCls *rep_cls)
{
  struct ClientContext *cli_ctx;

  cli_ctx = GNUNET_SERVER_client_get_user_context (rep_cls->client,
                                                   struct ClientContext);
  GNUNET_assert (NULL != cli_ctx);
  GNUNET_CONTAINER_DLL_remove (cli_ctx->rep_cls_head,
                               cli_ctx->rep_cls_tail,
                               rep_cls);
  GNUNET_free (rep_cls);
}

static void
destroy_cli_ctx (struct ClientContext *cli_ctx)
{
  GNUNET_assert (NULL != cli_ctx);
  if (NULL != cli_ctx->rep_cls_head)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Trying to destroy the context of a client that still has pending requests. Going to clean those\n");
    while (NULL != cli_ctx->rep_cls_head)
      destroy_reply_cls (cli_ctx->rep_cls_head);
  }
  GNUNET_CONTAINER_DLL_remove (cli_ctx_head,
                               cli_ctx_tail,
                               cli_ctx);
  GNUNET_free (cli_ctx);
}


/**
 * Function called by NSE.
 *
 * Updates sizes of sampler list and view and adapt those lists
 * accordingly.
 */
  void
nse_callback (void *cls, struct GNUNET_TIME_Absolute timestamp,
              double logestimate, double std_dev)
{
  double estimate;
  //double scale; // TODO this might go gloabal/config

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received a ns estimate - logest: %f, std_dev: %f (old_size: %u)\n",
       logestimate, std_dev, RPS_sampler_get_size (prot_sampler));
  //scale = .01;
  estimate = GNUNET_NSE_log_estimate_to_n (logestimate);
  // GNUNET_NSE_log_estimate_to_n (logestimate);
  estimate = pow (estimate, 1.0 / 3);
  // TODO add if std_dev is a number
  // estimate += (std_dev * scale);
  if (2 < ceil (estimate))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Changing estimate to %f\n", estimate);
    sampler_size_est_need = estimate;
  } else
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Not using estimate %f\n", estimate);

  /* If the NSE has changed adapt the lists accordingly */
  resize_wrapper (prot_sampler, sampler_size_est_need);
  client_resize_wrapper ();
}


/**
 * Callback called once the requested PeerIDs are ready.
 *
 * Sends those to the requesting client.
 */
void
client_respond (void *cls,
                struct GNUNET_PeerIdentity *peer_ids,
                uint32_t num_peers)
{
  uint32_t i;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_ReplyMessage *out_msg;
  struct ReplyCls *reply_cls = (struct ReplyCls *) cls;
  uint32_t size_needed;
  struct ClientContext *cli_ctx;

  GNUNET_assert (NULL != reply_cls);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sampler returned %" PRIu32 " peers:\n",
       num_peers);
  for (i = 0; i < num_peers; i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "  %lu: %s\n",
         i,
         GNUNET_i2s (&peer_ids[i]));
  }

  size_needed = sizeof (struct GNUNET_RPS_CS_ReplyMessage) +
                num_peers * sizeof (struct GNUNET_PeerIdentity);

  GNUNET_assert (GNUNET_SERVER_MAX_MESSAGE_SIZE >= size_needed);

  ev = GNUNET_MQ_msg_extra (out_msg,
                            num_peers * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_RPS_CS_REPLY);
  out_msg->num_peers = htonl (num_peers);
  out_msg->id = htonl (reply_cls->id);

  memcpy (&out_msg[1],
          peer_ids,
          num_peers * sizeof (struct GNUNET_PeerIdentity));
  GNUNET_free (peer_ids);

  cli_ctx = GNUNET_SERVER_client_get_user_context (reply_cls->client,
                                                   struct ClientContext);
  GNUNET_assert (NULL != cli_ctx);
  destroy_reply_cls (reply_cls);
  GNUNET_MQ_send (cli_ctx->mq, ev);
}


/**
 * Handle RPS request from the client.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_client_request (void *cls,
                       struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_RPS_CS_RequestMessage *msg;
  uint32_t num_peers;
  uint32_t size_needed;
  struct ReplyCls *reply_cls;
  uint32_t i;
  struct ClientContext *cli_ctx;

  msg = (struct GNUNET_RPS_CS_RequestMessage *) message;

  num_peers = ntohl (msg->num_peers);
  size_needed = sizeof (struct GNUNET_RPS_CS_RequestMessage) +
                num_peers * sizeof (struct GNUNET_PeerIdentity);

  if (GNUNET_SERVER_MAX_MESSAGE_SIZE < size_needed)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Message received from client has size larger than expected\n");
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  for (i = 0 ; i < num_peers ; i++)
    est_request_rate();

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client requested %" PRIu32 " random peer(s).\n",
       num_peers);

  reply_cls = GNUNET_new (struct ReplyCls);
  reply_cls->id = ntohl (msg->id);
  reply_cls->client = client;
  reply_cls->req_handle = RPS_sampler_get_n_rand_peers (client_sampler,
                                                        client_respond,
                                                        reply_cls,
                                                        num_peers);

  cli_ctx = GNUNET_SERVER_client_get_user_context (client, struct ClientContext);
  GNUNET_assert (NULL != cli_ctx);
  GNUNET_CONTAINER_DLL_insert (cli_ctx->rep_cls_head,
                               cli_ctx->rep_cls_tail,
                               reply_cls);
  GNUNET_SERVER_receive_done (client,
			      GNUNET_OK);
}


/**
 * @brief Handle a message that requests the cancellation of a request
 *
 * @param cls unused
 * @param client the client that requests the cancellation
 * @param message the message containing the id of the request
 */
static void
handle_client_request_cancel (void *cls,
                              struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_RPS_CS_RequestCancelMessage *msg =
    (struct GNUNET_RPS_CS_RequestCancelMessage *) message;
  struct ClientContext *cli_ctx;
  struct ReplyCls *rep_cls;

  cli_ctx = GNUNET_SERVER_client_get_user_context (client, struct ClientContext);
  GNUNET_assert (NULL != cli_ctx->rep_cls_head);
  rep_cls = cli_ctx->rep_cls_head;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Client cancels request with id %lu\n",
      ntohl (msg->id));
  while ( (NULL != rep_cls->next) &&
          (rep_cls->id != ntohl (msg->id)) )
    rep_cls = rep_cls->next;
  GNUNET_assert (rep_cls->id == ntohl (msg->id));
  RPS_sampler_request_cancel (rep_cls->req_handle);
  destroy_reply_cls (rep_cls);
  GNUNET_SERVER_receive_done (client,
			      GNUNET_OK);
}


/**
 * Handle seed from the client.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
  static void
handle_client_seed (void *cls,
                    struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_RPS_CS_SeedMessage *in_msg;
  struct GNUNET_PeerIdentity *peers;
  uint32_t num_peers;
  uint32_t i;

  if (sizeof (struct GNUNET_RPS_CS_SeedMessage) > ntohs (message->size))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
  }

  in_msg = (struct GNUNET_RPS_CS_SeedMessage *) message;
  num_peers = ntohl (in_msg->num_peers);
  peers = (struct GNUNET_PeerIdentity *) &in_msg[1];
  //peers = GNUNET_new_array (num_peers, struct GNUNET_PeerIdentity);
  //memcpy (peers, &in_msg[1], num_peers * sizeof (struct GNUNET_PeerIdentity));

  if ((ntohs (message->size) - sizeof (struct GNUNET_RPS_CS_SeedMessage)) /
      sizeof (struct GNUNET_PeerIdentity) != num_peers)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client seeded peers:\n");
  print_peer_list (peers, num_peers);

  for (i = 0; i < num_peers; i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Updating samplers with seed %" PRIu32 ": %s\n",
         i,
         GNUNET_i2s (&peers[i]));

    if (GNUNET_YES == Peers_insert_peer (&peers[i]))
    {
      Peers_schedule_operation (&peers[i], insert_in_sampler);
      Peers_schedule_operation (&peers[i], insert_in_view);
    }

    //RPS_sampler_update (prot_sampler,   &peers[i]);
    //RPS_sampler_update (client_sampler, &peers[i]);
  }

  ////GNUNET_free (peers);

  GNUNET_SERVER_receive_done (client,
			                        GNUNET_OK);
}


/**
 * Handle a PUSH message from another peer.
 *
 * Check the proof of work and store the PeerID
 * in the temporary list for pushed PeerIDs.
 *
 * @param cls Closure
 * @param channel The channel the PUSH was received over
 * @param channel_ctx The context associated with this channel
 * @param msg The message header
 */
static int
handle_peer_push (void *cls,
    struct GNUNET_CADET_Channel *channel,
    void **channel_ctx,
    const struct GNUNET_MessageHeader *msg)
{
  const struct GNUNET_PeerIdentity *peer;

  // (check the proof of work (?))

  peer = (const struct GNUNET_PeerIdentity *)
    GNUNET_CADET_channel_get_info (channel, GNUNET_CADET_OPTION_PEER);
  // FIXME wait for cadet to change this function

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received PUSH (%s)\n", GNUNET_i2s (peer));

  #ifdef ENABLE_MALICIOUS
  struct AttackedPeer *tmp_att_peer;

  tmp_att_peer = GNUNET_new (struct AttackedPeer);
  memcpy (&tmp_att_peer->peer_id, peer, sizeof (struct GNUNET_PeerIdentity));
  if (1 == mal_type
      || 3 == mal_type)
  { /* Try to maximise representation */
    if (NULL == att_peer_set)
      att_peer_set = GNUNET_CONTAINER_multipeermap_create (1, GNUNET_NO);
    if (GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (att_peer_set,
                                                             peer))
    {
      GNUNET_CONTAINER_DLL_insert (att_peers_head,
                                   att_peers_tail,
                                   tmp_att_peer);
      add_peer_array_to_set (peer, 1, att_peer_set);
    }
    return GNUNET_OK;
  }


  else if (2 == mal_type)
  { /* We attack one single well-known peer - simply ignore */
    return GNUNET_OK;
  }
  else
  {
    GNUNET_free (tmp_att_peer);
  }

  #endif /* ENABLE_MALICIOUS */

  /* Add the sending peer to the push_map */
  CustomPeerMap_put (push_map, peer);

  GNUNET_CADET_receive_done (channel);
  return GNUNET_OK;
}


/**
 * Handle PULL REQUEST request message from another peer.
 *
 * Reply with the view of PeerIDs.
 *
 * @param cls Closure
 * @param channel The channel the PULL REQUEST was received over
 * @param channel_ctx The context associated with this channel
 * @param msg The message header
 */
static int
handle_peer_pull_request (void *cls,
    struct GNUNET_CADET_Channel *channel,
    void **channel_ctx,
    const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PeerIdentity *peer;
  const struct GNUNET_PeerIdentity *view_array;

  peer = (struct GNUNET_PeerIdentity *)
    GNUNET_CADET_channel_get_info (channel,
                                   GNUNET_CADET_OPTION_PEER);
  // FIXME wait for cadet to change this function

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received PULL REQUEST (%s)\n", GNUNET_i2s (peer));

  #ifdef ENABLE_MALICIOUS
  if (1 == mal_type
      || 3 == mal_type)
  { /* Try to maximise representation */
    send_pull_reply (peer, mal_peers, num_mal_peers);
    return GNUNET_OK;
  }

  else if (2 == mal_type)
  { /* Try to partition network */
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&attacked_peer, peer))
    {
      send_pull_reply (peer, mal_peers, num_mal_peers);
    }
    return GNUNET_OK;
  }
  #endif /* ENABLE_MALICIOUS */

  view_array = View_get_as_array ();

  send_pull_reply (peer, view_array, View_size ());

  GNUNET_CADET_receive_done (channel);
  return GNUNET_OK;
}


/**
 * Handle PULL REPLY message from another peer.
 *
 * Check whether we sent a corresponding request and
 * whether this reply is the first one.
 *
 * @param cls Closure
 * @param channel The channel the PUSH was received over
 * @param channel_ctx The context associated with this channel
 * @param msg The message header
 */
  static int
handle_peer_pull_reply (void *cls,
                        struct GNUNET_CADET_Channel *channel,
                        void **channel_ctx,
                        const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_RPS_P2P_PullReplyMessage *in_msg;
  struct GNUNET_PeerIdentity *peers;
  struct GNUNET_PeerIdentity *sender;
  uint32_t i;
#ifdef ENABLE_MALICIOUS
  struct AttackedPeer *tmp_att_peer;
#endif /* ENABLE_MALICIOUS */

  /* Check for protocol violation */
  if (sizeof (struct GNUNET_RPS_P2P_PullReplyMessage) > ntohs (msg->size))
  {
    GNUNET_break_op (0);
    GNUNET_CADET_receive_done (channel);
    return GNUNET_SYSERR;
  }

  in_msg = (struct GNUNET_RPS_P2P_PullReplyMessage *) msg;
  if ((ntohs (msg->size) - sizeof (struct GNUNET_RPS_P2P_PullReplyMessage)) /
      sizeof (struct GNUNET_PeerIdentity) != ntohl (in_msg->num_peers))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        "message says it sends %" PRIu32 " peers, have space for %i peers\n",
        ntohl (in_msg->num_peers),
        (ntohs (msg->size) - sizeof (struct GNUNET_RPS_P2P_PullReplyMessage)) /
            sizeof (struct GNUNET_PeerIdentity));
    GNUNET_break_op (0);
    GNUNET_CADET_receive_done (channel);
    return GNUNET_SYSERR;
  }

  // Guess simply casting isn't the nicest way...
  // FIXME wait for cadet to change this function
  sender = (struct GNUNET_PeerIdentity *)
      GNUNET_CADET_channel_get_info (channel, GNUNET_CADET_OPTION_PEER);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received PULL REPLY (%s)\n", GNUNET_i2s (sender));

  if (GNUNET_YES != Peers_check_peer_flag (sender, Peers_PULL_REPLY_PENDING))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Received a pull reply from a peer we didn't request one from!\n");
    GNUNET_break_op (0);
    GNUNET_CADET_receive_done (channel);
    return GNUNET_OK;
  }


  #ifdef ENABLE_MALICIOUS
  // We shouldn't even receive pull replies as we're not sending
  if (2 == mal_type)
    return GNUNET_OK;
  #endif /* ENABLE_MALICIOUS */

  /* Do actual logic */
  peers = (struct GNUNET_PeerIdentity *) &in_msg[1];

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "PULL REPLY received, got following %u peers:\n",
       ntohl (in_msg->num_peers));

  for (i = 0 ; i < ntohl (in_msg->num_peers) ; i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%u. %s\n",
         i,
         GNUNET_i2s (&peers[i]));

    #ifdef ENABLE_MALICIOUS
    if ((NULL != att_peer_set) &&
        (1 == mal_type || 3 == mal_type))
    { /* Add attacked peer to local list */
      // TODO check if we sent a request and this was the first reply
      if (GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (att_peer_set,
                                                               &peers[i])
          && GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (mal_peer_set,
                                                                  &peers[i])
          && 0 != GNUNET_CRYPTO_cmp_peer_identity (&peers[i],
                                                   &own_identity))
      {
        tmp_att_peer = GNUNET_new (struct AttackedPeer);
        tmp_att_peer->peer_id = peers[i];
        GNUNET_CONTAINER_DLL_insert (att_peers_head,
                                     att_peers_tail,
                                     tmp_att_peer);
        add_peer_array_to_set (&peers[i], 1, att_peer_set);
      }
      continue;
    }
    #endif /* ENABLE_MALICIOUS */
    if (0 != GNUNET_CRYPTO_cmp_peer_identity (&own_identity,
                                              &peers[i]))
    {
      /* Make sure we 'know' about this peer */
      (void) Peers_insert_peer (&peers[i]);

      if (GNUNET_YES == Peers_check_peer_flag (&peers[i], Peers_VALID))
      {
        CustomPeerMap_put (pull_map, &peers[i]);
      }
      else
      {
        Peers_schedule_operation (&peers[i], insert_in_pull_map);
        Peers_issue_peer_liveliness_check (&peers[i]);
      }
    }
  }

  Peers_unset_peer_flag (sender, Peers_PULL_REPLY_PENDING);
  clean_peer (sender);

  GNUNET_CADET_receive_done (channel);
  return GNUNET_OK;
}


/**
 * Compute a random delay.
 * A uniformly distributed value between mean + spread and mean - spread.
 *
 * For example for mean 4 min and spread 2 the minimum is (4 min - (1/2 * 4 min))
 * It would return a random value between 2 and 6 min.
 *
 * @param mean the mean
 * @param spread the inverse amount of deviation from the mean
 */
static struct GNUNET_TIME_Relative
compute_rand_delay (struct GNUNET_TIME_Relative mean, unsigned int spread)
{
  struct GNUNET_TIME_Relative half_interval;
  struct GNUNET_TIME_Relative ret;
  unsigned int rand_delay;
  unsigned int max_rand_delay;

  if (0 == spread)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Not accepting spread of 0\n");
    GNUNET_break (0);
  }

  /* Compute random time value between spread * mean and spread * mean */
  half_interval = GNUNET_TIME_relative_divide (mean, spread);

  max_rand_delay = GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us / mean.rel_value_us * (2/spread);
  /**
   * Compute random value between (0 and 1) * round_interval
   * via multiplying round_interval with a 'fraction' (0 to value)/value
   */
  rand_delay = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, max_rand_delay);
  ret = GNUNET_TIME_relative_multiply (mean,  rand_delay);
  ret = GNUNET_TIME_relative_divide   (ret, max_rand_delay);
  ret = GNUNET_TIME_relative_add      (ret, half_interval);

  if (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us == ret.rel_value_us)
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Returning FOREVER_REL\n");

  return ret;
}


/**
 * Send single pull request
 *
 * @param peer_id the peer to send the pull request to.
 */
static void
send_pull_request (const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_MQ_Envelope *ev;

  GNUNET_assert (GNUNET_NO == Peers_check_peer_flag (peer,
                                                     Peers_PULL_REPLY_PENDING));
  Peers_set_peer_flag (peer, Peers_PULL_REPLY_PENDING);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Going to send PULL REQUEST to peer %s.\n",
       GNUNET_i2s (peer));

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST);
  Peers_send_message (peer, ev, "PULL REQUEST");
}


/**
 * Send single push
 *
 * @param peer_id the peer to send the push to.
 */
static void
send_push (const struct GNUNET_PeerIdentity *peer_id)
{
  struct GNUNET_MQ_Envelope *ev;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Going to send PUSH to peer %s.\n",
       GNUNET_i2s (peer_id));

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_RPS_PP_PUSH);
  Peers_send_message (peer_id, ev, "PUSH");
}


static void
do_round (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

static void
do_mal_round (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


#ifdef ENABLE_MALICIOUS
/**
 * Turn RPS service to act malicious.
 *
 * @param cls Closure
 * @param client The client that sent the message
 * @param msg The message header
 */
  static void
handle_client_act_malicious (void *cls,
                             struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_RPS_CS_ActMaliciousMessage *in_msg;
  struct GNUNET_PeerIdentity *peers;
  uint32_t num_mal_peers_sent;
  uint32_t num_mal_peers_old;

  /* Check for protocol violation */
  if (sizeof (struct GNUNET_RPS_CS_ActMaliciousMessage) > ntohs (msg->size))
  {
    GNUNET_break_op (0);
  }

  in_msg = (struct GNUNET_RPS_CS_ActMaliciousMessage *) msg;
  if ((ntohs (msg->size) - sizeof (struct GNUNET_RPS_CS_ActMaliciousMessage)) /
      sizeof (struct GNUNET_PeerIdentity) != ntohl (in_msg->num_peers))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        "message says it sends %" PRIu64 " peers, have space for %i peers\n",
        ntohl (in_msg->num_peers),
        (ntohs (msg->size) - sizeof (struct GNUNET_RPS_CS_ActMaliciousMessage)) /
            sizeof (struct GNUNET_PeerIdentity));
    GNUNET_break_op (0);
  }


  /* Do actual logic */
  peers = (struct GNUNET_PeerIdentity *) &msg[1];
  mal_type = ntohl (in_msg->type);
  if (NULL == mal_peer_set)
    mal_peer_set = GNUNET_CONTAINER_multipeermap_create (1, GNUNET_NO);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Now acting malicious type %" PRIu32 ", got %" PRIu32 " peers.\n",
       mal_type,
       ntohl (in_msg->num_peers));

  if (1 == mal_type)
  { /* Try to maximise representation */
    /* Add other malicious peers to those we already know */

    num_mal_peers_sent = ntohl (in_msg->num_peers);
    num_mal_peers_old = num_mal_peers;
    GNUNET_array_grow (mal_peers,
                       num_mal_peers,
                       num_mal_peers + num_mal_peers_sent);
    memcpy (&mal_peers[num_mal_peers_old],
            peers,
            num_mal_peers_sent * sizeof (struct GNUNET_PeerIdentity));

    /* Add all mal peers to mal_peer_set */
    add_peer_array_to_set (&mal_peers[num_mal_peers_old],
                           num_mal_peers_sent,
                           mal_peer_set);

    /* Substitute do_round () with do_mal_round () */
    GNUNET_SCHEDULER_cancel (do_round_task);
    do_round_task = GNUNET_SCHEDULER_add_now (&do_mal_round, NULL);
  }

  else if ( (2 == mal_type) ||
            (3 == mal_type) )
  { /* Try to partition the network */
    /* Add other malicious peers to those we already know */

    num_mal_peers_sent = ntohl (in_msg->num_peers) - 1;
    num_mal_peers_old = num_mal_peers;
    GNUNET_array_grow (mal_peers,
                       num_mal_peers,
                       num_mal_peers + num_mal_peers_sent);
    if (NULL != mal_peers &&
        0 != num_mal_peers)
    {
      memcpy (&mal_peers[num_mal_peers_old],
              peers,
              num_mal_peers_sent * sizeof (struct GNUNET_PeerIdentity));

      /* Add all mal peers to mal_peer_set */
      add_peer_array_to_set (&mal_peers[num_mal_peers_old],
                             num_mal_peers_sent,
                             mal_peer_set);
    }

    /* Store the one attacked peer */
    memcpy (&attacked_peer,
            &in_msg->attacked_peer,
            sizeof (struct GNUNET_PeerIdentity));
    /* Set the flag of the attacked peer to valid to avoid problems */
    if (GNUNET_NO == Peers_check_peer_known (&attacked_peer))
    {
      Peers_insert_peer (&attacked_peer);
      Peers_issue_peer_liveliness_check (&attacked_peer);
    }

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Attacked peer is %s\n",
         GNUNET_i2s (&attacked_peer));

    /* Substitute do_round () with do_mal_round () */
    GNUNET_SCHEDULER_cancel (do_round_task);
    do_round_task = GNUNET_SCHEDULER_add_now (&do_mal_round, NULL);
  }
  else if (0 == mal_type)
  { /* Stop acting malicious */
    GNUNET_array_grow (mal_peers, num_mal_peers, 0);

    /* Substitute do_mal_round () with do_round () */
    GNUNET_SCHEDULER_cancel (do_round_task);
    do_round_task = GNUNET_SCHEDULER_add_now (&do_round, NULL);
  }
  else
  {
    GNUNET_break (0);
  }

  GNUNET_SERVER_receive_done (client,	GNUNET_OK);
}


/**
 * Send out PUSHes and PULLs maliciously.
 *
 * This is executed regylary.
 */
static void
do_mal_round (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  uint32_t num_pushes;
  uint32_t i;
  struct GNUNET_TIME_Relative time_next_round;
  struct AttackedPeer *tmp_att_peer;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Going to execute next round maliciously type %" PRIu32 ".\n",
      mal_type);
  do_round_task = NULL;
  GNUNET_assert (mal_type <= 3);
  /* Do malicious actions */
  if (1 == mal_type)
  { /* Try to maximise representation */

    /* The maximum of pushes we're going to send this round */
    num_pushes = GNUNET_MIN (GNUNET_MIN (push_limit,
                                         num_attacked_peers),
                             GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE);

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Going to send %" PRIu32 " pushes\n",
         num_pushes);

    /* Send PUSHes to attacked peers */
    for (i = 0 ; i < num_pushes ; i++)
    {
      if (att_peers_tail == att_peer_index)
        att_peer_index = att_peers_head;
      else
        att_peer_index = att_peer_index->next;

      send_push (&att_peer_index->peer_id);
    }

    /* Send PULLs to some peers to learn about additional peers to attack */
    tmp_att_peer = att_peer_index;
    for (i = 0 ; i < num_pushes * alpha ; i++)
    {
      if (att_peers_tail == tmp_att_peer)
        tmp_att_peer = att_peers_head;
      else
        att_peer_index = tmp_att_peer->next;

      send_pull_request (&tmp_att_peer->peer_id);
    }
  }


  else if (2 == mal_type)
  { /**
     * Try to partition the network
     * Send as many pushes to the attacked peer as possible
     * That is one push per round as it will ignore more.
     */
    Peers_insert_peer (&attacked_peer);
    if (GNUNET_YES == Peers_check_peer_flag (&attacked_peer, Peers_VALID))
      send_push (&attacked_peer);
  }


  if (3 == mal_type)
  { /* Combined attack */

    /* Send PUSH to attacked peers */
    if (GNUNET_YES == Peers_check_peer_known (&attacked_peer))
    {
      Peers_insert_peer (&attacked_peer);
      if (GNUNET_YES == Peers_check_peer_flag (&attacked_peer, Peers_VALID))
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
            "Goding to send push to attacked peer (%s)\n",
            GNUNET_i2s (&attacked_peer));
        send_push (&attacked_peer);
      }
      else
        Peers_issue_peer_liveliness_check (&attacked_peer);
    }
    else
      Peers_insert_peer (&attacked_peer);
    Peers_issue_peer_liveliness_check (&attacked_peer);

    /* The maximum of pushes we're going to send this round */
    num_pushes = GNUNET_MIN (GNUNET_MIN (push_limit - 1,
                                         num_attacked_peers),
                             GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE);

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Going to send %" PRIu32 " pushes\n",
         num_pushes);

    for (i = 0; i < num_pushes; i++)
    {
      if (att_peers_tail == att_peer_index)
        att_peer_index = att_peers_head;
      else
        att_peer_index = att_peer_index->next;

      send_push (&att_peer_index->peer_id);
    }

    /* Send PULLs to some peers to learn about additional peers to attack */
    tmp_att_peer = att_peer_index;
    for (i = 0; i < num_pushes * alpha; i++)
    {
      if (att_peers_tail == tmp_att_peer)
        tmp_att_peer = att_peers_head;
      else
        att_peer_index = tmp_att_peer->next;

      send_pull_request (&tmp_att_peer->peer_id);
    }
  }

  /* Schedule next round */
  time_next_round = compute_rand_delay (round_interval, 2);

  //do_round_task = GNUNET_SCHEDULER_add_delayed (round_interval, &do_mal_round,
  //NULL);
  GNUNET_assert (NULL == do_round_task);
  do_round_task = GNUNET_SCHEDULER_add_delayed (time_next_round, &do_mal_round, NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Finished round\n");
}
#endif /* ENABLE_MALICIOUS */


/**
 * Send out PUSHes and PULLs, possibly update #view, samplers.
 *
 * This is executed regylary.
 */
static void
do_round (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Going to execute next round.\n");

  uint32_t i;
  const struct GNUNET_PeerIdentity *view_array;
  unsigned int *permut;
  unsigned int a_peers; /* Number of peers we send pushes to */
  unsigned int b_peers; /* Number of peers we send pull requests to */
  uint32_t first_border;
  uint32_t second_border;
  struct GNUNET_PeerIdentity peer;
  struct GNUNET_PeerIdentity *update_peer;

  do_round_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Printing view:\n");
  to_file (file_name_view_log,
           "___ new round ___");
  view_array = View_get_as_array ();
  for (i = 0; i < View_size (); i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "\t%s\n", GNUNET_i2s (&view_array[i]));
    to_file (file_name_view_log,
             "=%s\t(do round)",
             GNUNET_i2s_full (&view_array[i]));
  }


  /* Send pushes and pull requests */
  if (0 < View_size ())
  {
    permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_STRONG,
                                           View_size ());

    /* Send PUSHes */
    a_peers = ceil (alpha * View_size ());

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Going to send pushes to %u (ceil (%f * %u)) peers.\n",
         a_peers, alpha, View_size ());
    for (i = 0; i < a_peers; i++)
    {
      peer = view_array[permut[i]];
      if (0 != GNUNET_CRYPTO_cmp_peer_identity (&own_identity, &peer)) // TODO
      { // FIXME if this fails schedule/loop this for later
        send_push (&peer);
      }
    }

    /* Send PULL requests */
    b_peers = ceil (beta * View_size ());
    first_border = a_peers;
    second_border = a_peers + b_peers;
    if (second_border > View_size ())
    {
      first_border = View_size () - b_peers;
      second_border = View_size ();
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Going to send pulls to %u (ceil (%f * %u)) peers.\n",
        b_peers, beta, View_size ());
    for (i = first_border; i < second_border; i++)
    {
      peer = view_array[permut[i]];
      if (0 != GNUNET_CRYPTO_cmp_peer_identity (&own_identity, &peer) &&
          GNUNET_NO == Peers_check_peer_flag (&peer, Peers_PULL_REPLY_PENDING)) // TODO
      { // FIXME if this fails schedule/loop this for later
        send_pull_request (&peer);
      }
    }

    GNUNET_free (permut);
    permut = NULL;
  }


  /* Update view */
  /* TODO see how many peers are in push-/pull- list! */

  if ((CustomPeerMap_size (push_map) <= alpha * View_size ()) &&
      (0 < CustomPeerMap_size (push_map)) &&
      (0 < CustomPeerMap_size (pull_map)))
  { /* If conditions for update are fulfilled, update */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Update of the view.\n");

    uint32_t final_size;
    uint32_t peers_to_clean_size;
    struct GNUNET_PeerIdentity *peers_to_clean;

    peers_to_clean = NULL;
    peers_to_clean_size = 0;
    GNUNET_array_grow (peers_to_clean, peers_to_clean_size, View_size ());
    memcpy (peers_to_clean,
            view_array,
            View_size () * sizeof (struct GNUNET_PeerIdentity));

    /* Seems like recreating is the easiest way of emptying the peermap */
    View_clear ();
    to_file (file_name_view_log,
             "--- emptied ---");

    first_border  = GNUNET_MIN (ceil (alpha * sampler_size_est_need),
                                CustomPeerMap_size (push_map));
    second_border = first_border +
                    GNUNET_MIN (floor (beta  * sampler_size_est_need),
                                CustomPeerMap_size (pull_map));
    final_size    = second_border +
      ceil ((1 - (alpha + beta)) * sampler_size_est_need);

    /* Update view with peers received through PUSHes */
    permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_STRONG,
                                           CustomPeerMap_size (push_map));
    for (i = 0; i < first_border; i++)
    {
      View_put (CustomPeerMap_get_peer_by_index (push_map, permut[i]));
      to_file (file_name_view_log,
               "+%s\t(push list)",
               GNUNET_i2s_full (&view_array[i]));
      // TODO change the peer_flags accordingly
    }
    GNUNET_free (permut);
    permut = NULL;

    /* Update view with peers received through PULLs */
    permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_STRONG,
                                           CustomPeerMap_size (pull_map));
    for (i = first_border; i < second_border; i++)
    {
      View_put (CustomPeerMap_get_peer_by_index (pull_map,
                                                 permut[i - first_border]));
      to_file (file_name_view_log,
               "+%s\t(pull list)",
               GNUNET_i2s_full (&view_array[i]));
      // TODO change the peer_flags accordingly
    }
    GNUNET_free (permut);
    permut = NULL;

    /* Update view with peers from history */
    RPS_sampler_get_n_rand_peers (prot_sampler,
                                  hist_update,
                                  NULL,
                                  final_size - second_border);
    num_hist_update_tasks = final_size - second_border;
    // TODO change the peer_flags accordingly

    for (i = 0; i < View_size (); i++)
      rem_from_list (&peers_to_clean, &peers_to_clean_size, &view_array[i]);

    /* Clean peers that were removed from the view */
    for (i = 0; i < peers_to_clean_size; i++)
    {
      to_file (file_name_view_log,
               "-%s",
               GNUNET_i2s_full (&peers_to_clean[i]));
      Peers_clean_peer (&peers_to_clean[i]);
      //peer_destroy_channel_send (sender);
    }

    GNUNET_array_grow (peers_to_clean, peers_to_clean_size, 0);
    peers_to_clean = NULL;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "No update of the view.\n");
  }
  // TODO independent of that also get some peers from CADET_get_peers()?

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received %u pushes and %u pulls last round (alpha (%.2f) * view_size (%u) = %.2f)\n",
       CustomPeerMap_size (push_map),
       CustomPeerMap_size (pull_map),
       alpha,
       View_size (),
       alpha * View_size ());

  /* Update samplers */
  for (i = 0; i < CustomPeerMap_size (push_map); i++)
  {
    update_peer = CustomPeerMap_get_peer_by_index (push_map, i);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Updating with peer %s from push list\n",
         GNUNET_i2s (update_peer));
    insert_in_sampler (NULL, update_peer);
    Peers_clean_peer (update_peer); /* This cleans only if it is not in the view */
    //peer_destroy_channel_send (sender);
  }

  for (i = 0; i < CustomPeerMap_size (pull_map); i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Updating with peer %s from pull list\n",
         GNUNET_i2s (CustomPeerMap_get_peer_by_index (pull_map, i)));
    insert_in_sampler (NULL, CustomPeerMap_get_peer_by_index (pull_map, i));
    /* This cleans only if it is not in the view */
    Peers_clean_peer (CustomPeerMap_get_peer_by_index (pull_map, i));
    //peer_destroy_channel_send (sender);
  }


  /* Empty push/pull lists */
  CustomPeerMap_clear (push_map);
  CustomPeerMap_clear (pull_map);

  struct GNUNET_TIME_Relative time_next_round;

  time_next_round = compute_rand_delay (round_interval, 2);

  /* Schedule next round */
  do_round_task = GNUNET_SCHEDULER_add_delayed (time_next_round, &do_round, NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Finished round\n");
}


static void
rps_start (struct GNUNET_SERVER_Handle *server);


/**
 * This is called from GNUNET_CADET_get_peers().
 *
 * It is called on every peer(ID) that cadet somehow has contact with.
 * We use those to initialise the sampler.
 */
void
init_peer_cb (void *cls,
              const struct GNUNET_PeerIdentity *peer,
              int tunnel, // "Do we have a tunnel towards this peer?"
              unsigned int n_paths, // "Number of known paths towards this peer"
              unsigned int best_path) // "How long is the best path?
                                      // (0 = unknown, 1 = ourselves, 2 = neighbor)"
{
  if (NULL != peer)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Got peer_id %s from cadet\n",
         GNUNET_i2s (peer));
    Peers_insert_peer (peer);
    Peers_schedule_operation (peer, insert_in_sampler);
    Peers_schedule_operation (peer, insert_in_view);
  }
}


/**
 * Iterator over peers from peerinfo.
 *
 * @param cls closure
 * @param peer id of the peer, NULL for last call
 * @param hello hello message for the peer (can be NULL)
 * @param error message
 */
void
process_peerinfo_peers (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
                        const struct GNUNET_HELLO_Message *hello,
                        const char *err_msg)
{
  if (NULL != peer)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Got peer_id %s from peerinfo\n",
         GNUNET_i2s (peer));
    Peers_insert_peer (peer);
    Peers_schedule_operation (peer, insert_in_sampler);
    Peers_schedule_operation (peer, insert_in_view);
  }
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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "RPS is going down\n");

  GNUNET_PEERINFO_notify_cancel (peerinfo_notify_handle);
  GNUNET_PEERINFO_disconnect (peerinfo_handle);

  if (NULL != do_round_task)
  {
    GNUNET_SCHEDULER_cancel (do_round_task);
    do_round_task = NULL;
  }

  Peers_terminate ();

  GNUNET_NSE_disconnect (nse);
  RPS_sampler_destroy (prot_sampler);
  RPS_sampler_destroy (client_sampler);
  GNUNET_CADET_disconnect (cadet_handle);
  View_destroy ();
  CustomPeerMap_destroy (push_map);
  CustomPeerMap_destroy (pull_map);
  #ifdef ENABLE_MALICIOUS
  struct AttackedPeer *tmp_att_peer;
  GNUNET_array_grow (mal_peers, num_mal_peers, 0);
  if (NULL != mal_peer_set)
    GNUNET_CONTAINER_multipeermap_destroy (mal_peer_set);
  if (NULL != att_peer_set)
    GNUNET_CONTAINER_multipeermap_destroy (att_peer_set);
  while (NULL != att_peers_head)
  {
    tmp_att_peer = att_peers_head;
    GNUNET_CONTAINER_DLL_remove (att_peers_head, att_peers_tail, tmp_att_peer);
  }
  #endif /* ENABLE_MALICIOUS */
}


/**
 * @brief Get informed about a connecting client.
 *
 * @param cls unused
 * @param client the client that connects
 */
static void
handle_client_connect (void *cls,
                       struct GNUNET_SERVER_Client *client)
{
  struct ClientContext *cli_ctx;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client connected\n");
  if (NULL == client)
    return; /* Server was destroyed before a client connected. Shutting down */
  cli_ctx = GNUNET_new (struct ClientContext);
  cli_ctx->mq = GNUNET_MQ_queue_for_server_client (client);
  GNUNET_SERVER_client_set_user_context (client, cli_ctx);
  GNUNET_CONTAINER_DLL_insert (cli_ctx_head,
                               cli_ctx_tail,
                               cli_ctx);
}

/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls,
			                    struct GNUNET_SERVER_Client *client)
{
  struct ClientContext *cli_ctx;

  if (NULL == client)
  {/* shutdown task */
    while (NULL != cli_ctx_head)
      destroy_cli_ctx (cli_ctx_head);
  }
  else
  {
    cli_ctx = GNUNET_SERVER_client_get_user_context (client, struct ClientContext);
    destroy_cli_ctx (cli_ctx);
  }
}


/**
 * Actually start the service.
 */
  static void
rps_start (struct GNUNET_SERVER_Handle *server)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_client_request,        NULL, GNUNET_MESSAGE_TYPE_RPS_CS_REQUEST,
      sizeof (struct GNUNET_RPS_CS_RequestMessage)},
    {&handle_client_request_cancel, NULL, GNUNET_MESSAGE_TYPE_RPS_CS_REQUEST_CANCEL,
      sizeof (struct GNUNET_RPS_CS_RequestCancelMessage)},
    {&handle_client_seed,           NULL, GNUNET_MESSAGE_TYPE_RPS_CS_SEED, 0},
    #ifdef ENABLE_MALICIOUS
    {&handle_client_act_malicious,  NULL, GNUNET_MESSAGE_TYPE_RPS_ACT_MALICIOUS , 0},
    #endif /* ENABLE_MALICIOUS */
    {NULL, NULL, 0, 0}
  };

  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_connect_notify (server,
                                &handle_client_connect,
                                NULL);
  GNUNET_SERVER_disconnect_notify (server,
                                   &handle_client_disconnect,
                                   NULL);
  LOG (GNUNET_ERROR_TYPE_INFO, "Ready to receive requests from clients\n");


  do_round_task = GNUNET_SCHEDULER_add_now (&do_round, NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Scheduled first round\n");

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				                        &shutdown_task,
				                        NULL);
}


/**
 * Process statistics requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
  static void
run (void *cls,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  int size;
  int out_size;

  GNUNET_log_setup ("rps", GNUNET_error_type_to_string (GNUNET_ERROR_TYPE_DEBUG), NULL);
  cfg = c;


  /* Get own ID */
  GNUNET_CRYPTO_get_peer_identity (cfg, &own_identity); // TODO check return value
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "STARTING SERVICE (rps) for peer [%s]\n",
              GNUNET_i2s (&own_identity));
  #ifdef ENABLE_MALICIOUS
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Malicious execution compiled in.\n");
  #endif /* ENABLE_MALICIOUS */



  /* Get time interval from the configuration */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_time (cfg, "RPS",
                                                        "ROUNDINTERVAL",
                                                        &round_interval))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "RPS", "ROUNDINTERVAL");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  /* Get initial size of sampler/view from the configuration */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "RPS", "INITSIZE",
        (long long unsigned int *) &sampler_size_est_need))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "RPS", "INITSIZE");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "INITSIZE is %" PRIu64 "\n", sampler_size_est_need);


  View_create (4);

  /* file_name_view_log */
  if (GNUNET_OK != GNUNET_DISK_directory_create ("/tmp/rps/"))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Failed to create directory /tmp/rps/\n");
  }

  size = (14 + strlen (GNUNET_i2s_full (&own_identity)) + 1) * sizeof (char);
  file_name_view_log = GNUNET_malloc (size);
  out_size = GNUNET_snprintf (file_name_view_log,
                              size,
                              "/tmp/rps/view-%s",
                              GNUNET_i2s_full (&own_identity));
  if (size < out_size ||
      0 > out_size)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Failed to write string to buffer (size: %i, out_size: %i)\n",
         size,
         out_size);
  }


  /* connect to NSE */
  nse = GNUNET_NSE_connect (cfg, nse_callback, NULL);


  alpha = 0.45;
  beta  = 0.45;


  /* Initialise cadet */
  static const struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
    {&handle_peer_push        , GNUNET_MESSAGE_TYPE_RPS_PP_PUSH        ,
      sizeof (struct GNUNET_MessageHeader)},
    {&handle_peer_pull_request, GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST,
      sizeof (struct GNUNET_MessageHeader)},
    {&handle_peer_pull_reply  , GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REPLY  , 0},
    {NULL, 0, 0}
  };

  const uint32_t ports[] = {GNUNET_RPS_CADET_PORT, 0}; // _PORT specified in src/rps/rps.h
  cadet_handle = GNUNET_CADET_connect (cfg,
                                       cls,
                                       &Peers_handle_inbound_channel,
                                       &cleanup_destroyed_channel,
                                       cadet_handlers,
                                       ports);
  peerinfo_handle = GNUNET_PEERINFO_connect (cfg);
  Peers_initialise (cadet_handle, &own_identity);

  /* Initialise sampler */
  struct GNUNET_TIME_Relative half_round_interval;
  struct GNUNET_TIME_Relative  max_round_interval;

  half_round_interval = GNUNET_TIME_relative_multiply (round_interval, .5);
  max_round_interval = GNUNET_TIME_relative_add (round_interval, half_round_interval);

  prot_sampler =   RPS_sampler_init     (sampler_size_est_need, max_round_interval);
  client_sampler = RPS_sampler_mod_init (sampler_size_est_need, max_round_interval);

  /* Initialise push and pull maps */
  push_map = CustomPeerMap_create (4);
  pull_map = CustomPeerMap_create (4);


  num_hist_update_tasks = 0;


  LOG (GNUNET_ERROR_TYPE_DEBUG, "Requesting peers from CADET\n");
  GNUNET_CADET_get_peers (cadet_handle, &init_peer_cb, NULL);
  // TODO send push/pull to each of those peers?

  peerinfo_notify_handle = GNUNET_PEERINFO_notify (cfg,
                                                   GNUNET_NO,
                                                   process_peerinfo_peers,
                                                   NULL);

  rps_start (server);
}


/**
 * The main function for the rps service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                              argv,
                              "rps",
			      GNUNET_SERVICE_OPTION_NONE,
			      &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-rps.c */
