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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file rps/gnunet-service-rps.c
 * @brief rps service implementation
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_cadet_service.h"
#include "gnunet_nse_service.h"
#include "rps.h"

#include "gnunet-service-rps_sampler.h"

#include <math.h>
#include <inttypes.h>

#define LOG(kind, ...) GNUNET_log(kind, __VA_ARGS__)

// TODO modify @brief in every file

// TODO check for overflows

// TODO align message structs

// (TODO api -- possibility of getting weak random peer immideately)

// TODO malicious peer

// TODO connect to friends

// TODO store peers somewhere

// TODO ignore list?

// hist_size_init, hist_size_max

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Our own identity.
 */
static struct GNUNET_PeerIdentity own_identity;


  struct GNUNET_PeerIdentity *
get_rand_peer_ignore_list (const struct GNUNET_PeerIdentity *peer_list, unsigned int size,
                           const struct GNUNET_PeerIdentity *ignore_list, unsigned int ignore_size);


/***********************************************************************
 * Housekeeping with peers
***********************************************************************/

/**
 * Struct used to store the context of a connected client.
 */
struct client_ctx
{
  /**
   * The message queue to communicate with the client.
   */
  struct GNUNET_MQ_Handle *mq;
};

/**
 * Used to keep track in what lists single peerIDs are.
 */
enum PeerFlags
{
  PULL_REPLY_PENDING   = 0x01,
  IN_OTHER_GOSSIP_LIST = 0x02, // unneeded?
  IN_OWN_SAMPLER_LIST  = 0x04, // unneeded?
  IN_OWN_GOSSIP_LIST   = 0x08, // unneeded?

  /**
   * We set this bit when we can be sure the other peer is/was live.
   */
  VALID                = 0x10
};


/**
 * Functions of this type can be used to be stored at a peer for later execution.
 */
typedef void (* PeerOp) (void *cls, const struct GNUNET_PeerIdentity *peer);

/**
 * Outstanding operation on peer consisting of callback and closure
 */
struct PeerOutstandingOp
{
  /**
   * Callback
   */
  PeerOp op;

  /**
   * Closure
   */
  void *op_cls;
};


/**
 * Struct used to keep track of other peer's status
 *
 * This is stored in a multipeermap.
 */
struct PeerContext
{
  /**
   * In own gossip/sampler list, in other's gossip/sampler list
   */
  uint32_t peer_flags;

  /**
   * Message queue open to client
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Channel open to client.
   */
  struct GNUNET_CADET_Channel *send_channel;

  /**
   * Channel open from client.
   */
  struct GNUNET_CADET_Channel *recv_channel; // unneeded?

  /**
   * Array of outstanding operations on this peer.
   */
  struct PeerOutstandingOp *outstanding_ops;

  /**
   * Number of outstanding operations.
   */
  unsigned int num_outstanding_ops;
  //size_t num_outstanding_ops;

  /**
   * Handle to the callback given to cadet_ntfy_tmt_rdy()
   *
   * To be canceled on shutdown.
   */
  struct GNUNET_CADET_TransmitHandle *is_live_task;

  /**
   * Identity of the peer
   */
  struct GNUNET_PeerIdentity peer_id;

  /**
   * This is pobably followed by 'statistical' data (when we first saw
   * him, how did we get his ID, how many pushes (in a timeinterval),
   * ...)
   */
};

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
 * Set of all peers to keep track of them.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *peer_map;


/**
 * The gossiped list of peers.
 */
static struct GNUNET_PeerIdentity *gossip_list;

/**
 * Size of the gossiped list
 */
//static unsigned int gossip_list_size;
static uint32_t gossip_list_size;


/**
 * The size of sampler we need to be able to satisfy the client's need of
 * random peers.
 */
static unsigned int sampler_size_client_need;

/**
 * The size of sampler we need to be able to satisfy the Brahms protocol's
 * need of random peers.
 *
 * This is directly taken as the #gossip_list_size on update of the
 * #gossip_list
 *
 * This is one minimum size the sampler grows to.
 */
static unsigned int sampler_size_est_need;


/**
 * Percentage of total peer number in the gossip list
 * to send random PUSHes to
 */
static float alpha;

/**
 * Percentage of total peer number in the gossip list
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
 *
 * TODO -> multipeermap
 */
static struct GNUNET_PeerIdentity *push_list;

/**
 * Size of the push_list;
 */
static unsigned int push_list_size;
//size_t push_list_size;

/**
 * List to store peers received through pulls temporary.
 *
 * TODO -> multipeermap
 */
static struct GNUNET_PeerIdentity *pull_list;

/**
 * Size of the pull_list;
 */
static unsigned int pull_list_size;
//size_t pull_list_size;


/**
 * Handler to NSE.
 */
static struct GNUNET_NSE_Handle *nse;

/**
 * Handler to CADET.
 */
static struct GNUNET_CADET_Handle *cadet_handle;


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
 * List with the peers we sent requests to.
 */
struct GNUNET_PeerIdentity *pending_pull_reply_list;

/**
 * Size of #pending_pull_reply_list.
 */
uint32_t pending_pull_reply_list_size;


/**
 * Number of history update tasks.
 */
uint32_t num_hist_update_tasks;


#if ENABLE_MALICIOUS
/**
 * Type of malicious peer
 *
 * 0 Don't act malicious at all - Default
 * 1 Try to maximise representation
 * 2 Try to partition the network
 */
uint32_t mal_type = 0;

/**
 * Other malicious peers
 */
static struct GNUNET_PeerIdentity *mal_peers;

/**
 * Number of other malicious peers
 */
static uint32_t num_mal_peers;

/**
 * If type is 2 this is the attacked peer
 */
static struct GNUNET_PeerIdentity attacked_peer;
#endif /* ENABLE_MALICIOUS */


/***********************************************************************
 * /Globals
***********************************************************************/






/***********************************************************************
 * Util functions
***********************************************************************/

/**
 * Set a peer flag of given peer context.
 */
#define set_peer_flag(peer_ctx, mask) (peer_ctx->peer_flags |= mask)

/**
 * Get peer flag of given peer context.
 */
#define get_peer_flag(peer_ctx, mask) (peer_ctx->peer_flags & mask ? GNUNET_YES : GNUNET_NO)

/**
 * Unset flag of given peer context.
 */
#define unset_peer_flag(peer_ctx, mask) (peer_ctx->peer_flags &= (~mask))


/**
 * Clean the send channel of a peer
 */
void
peer_clean (const struct GNUNET_PeerIdentity *peer);


/**
 * Check if peer is already in peer array.
 */
  int
in_arr (const struct GNUNET_PeerIdentity *array,
        unsigned int arr_size,
        const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert (NULL != peer);

  if (0 == arr_size)
    return GNUNET_NO;

  GNUNET_assert (NULL != array);

  unsigned int i;

  for (i = 0; i < arr_size ; i++)
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&array[i], peer))
      return GNUNET_YES;
  return GNUNET_NO;
}


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
 * Get random peer from the given list but don't return one from the @a ignore_list.
 */
  struct GNUNET_PeerIdentity *
get_rand_peer_ignore_list (const struct GNUNET_PeerIdentity *peer_list,
                           uint32_t list_size,
                           const struct GNUNET_PeerIdentity *ignore_list,
                           uint32_t ignore_size)
{
  uint32_t r_index;
  uint32_t tmp_size;
  struct GNUNET_PeerIdentity *tmp_peer_list;
  struct GNUNET_PeerIdentity *peer;

  GNUNET_assert (NULL != peer_list);
  if (0 == list_size)
    return NULL;

  tmp_size = 0;
  tmp_peer_list = NULL;
  GNUNET_array_grow (tmp_peer_list, tmp_size, list_size);
  memcpy (tmp_peer_list,
          peer_list,
          list_size * sizeof (struct GNUNET_PeerIdentity));
  peer = GNUNET_new (struct GNUNET_PeerIdentity);

  /**;
   * Choose the r_index of the peer we want to return
   * at random from the interval of the gossip list
   */
  r_index = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
                                      tmp_size);
  *peer = tmp_peer_list[r_index];

  while (in_arr (ignore_list, ignore_size, peer))
  {
    rem_from_list (&tmp_peer_list, &tmp_size, peer);

    print_peer_list (tmp_peer_list, tmp_size);

    if (0 == tmp_size)
    {
      GNUNET_free (peer);
      return NULL;
    }

    /**;
     * Choose the r_index of the peer we want to return
     * at random from the interval of the gossip list
     */
    r_index = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
                                        tmp_size);
    *peer = tmp_peer_list[r_index];
  }


  GNUNET_array_grow (tmp_peer_list, tmp_size, 0);

  return peer;
}


/**
 * Get the context of a peer. If not existing, create.
 */
  struct PeerContext *
get_peer_ctx (struct GNUNET_CONTAINER_MultiPeerMap *peer_map,
              const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *ctx;

  if ( GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (peer_map, peer))
  {
    ctx = GNUNET_CONTAINER_multipeermap_get (peer_map, peer);
  }
  else
  {
    ctx = GNUNET_new (struct PeerContext);
    ctx->peer_flags = 0;
    ctx->mq = NULL;
    ctx->send_channel = NULL;
    ctx->recv_channel = NULL;
    ctx->outstanding_ops = NULL;
    ctx->num_outstanding_ops = 0;
    ctx->is_live_task = NULL;
    ctx->peer_id = *peer;
    (void) GNUNET_CONTAINER_multipeermap_put (peer_map, peer, ctx,
                                              GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  return ctx;
}


/**
 * Put random peer from sampler into the gossip list as history update.
 */
  void
hist_update (void *cls, struct GNUNET_PeerIdentity *ids, uint32_t num_peers)
{
  GNUNET_assert (1 == num_peers);

  if (gossip_list_size < sampler_size_est_need)
    GNUNET_array_append (gossip_list, gossip_list_size, *ids);

  if (0 < num_hist_update_tasks)
    num_hist_update_tasks--;
}


/**
 * Set the peer flag to living and call the outstanding operations on this peer.
 */
static size_t
peer_is_live (struct PeerContext *peer_ctx)
{
  struct GNUNET_PeerIdentity *peer;

  peer = &peer_ctx->peer_id;
  set_peer_flag (peer_ctx, VALID);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Peer %s is live\n", GNUNET_i2s (peer));

  if (0 != peer_ctx->num_outstanding_ops)
  { /* Call outstanding operations */
    unsigned int i;

    for (i = 0 ; i < peer_ctx->num_outstanding_ops ; i++)
      peer_ctx->outstanding_ops[i].op (peer_ctx->outstanding_ops[i].op_cls, peer);
    GNUNET_array_grow (peer_ctx->outstanding_ops, peer_ctx->num_outstanding_ops, 0);
  }

  if (NULL != peer_ctx->is_live_task)
  {
    GNUNET_CADET_notify_transmit_ready_cancel (peer_ctx->is_live_task);
    peer_ctx->is_live_task = NULL;
  }

  return 0;
}


/**
 * Callback that is called when a channel was effectively established.
 * This is given to ntfy_tmt_rdy and called when the channel was
 * successfully established.
 */
static size_t
cadet_ntfy_tmt_rdy_cb (void *cls, size_t size, void *buf)
{
  struct PeerContext *peer_ctx = (struct PeerContext *) cls;

  if (NULL != buf
      && 0 != size)
  {
    peer_ctx->is_live_task = NULL;
    peer_is_live (peer_ctx);
  }

  //if (NULL != peer_ctx->is_live_task)
  //{
  //  LOG (GNUNET_ERROR_TYPE_DEBUG,
  //       "Trying to cancle is_live_task for peer %s\n",
  //       GNUNET_i2s (&peer_ctx->peer_id));
  //  GNUNET_CADET_notify_transmit_ready_cancel (peer_ctx->is_live_task);
  //  peer_ctx->is_live_task = NULL;
  //}

  return 0;
}


/**
 * Get the channel of a peer. If not existing, create.
 */
  struct GNUNET_CADET_Channel *
get_channel (struct GNUNET_CONTAINER_MultiPeerMap *peer_map,
             const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *peer_ctx;

  peer_ctx = get_peer_ctx (peer_map, peer);
  if (NULL == peer_ctx->send_channel)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Trying to establish channel to peer %s\n",
         GNUNET_i2s (peer));

    peer_ctx->send_channel =
      GNUNET_CADET_channel_create (cadet_handle,
                                   NULL,
                                   peer,
                                   GNUNET_RPS_CADET_PORT,
                                   GNUNET_CADET_OPTION_RELIABLE);

    // do I have to explicitly put it in the peer_map?
    (void) GNUNET_CONTAINER_multipeermap_put
      (peer_map,
       peer,
       peer_ctx,
       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }
  return peer_ctx->send_channel;
}


/**
 * Get the message queue of a specific peer.
 *
 * If we already have a message queue open to this client,
 * simply return it, otherways create one.
 */
  struct GNUNET_MQ_Handle *
get_mq (struct GNUNET_CONTAINER_MultiPeerMap *peer_map,
        const struct GNUNET_PeerIdentity *peer_id)
{
  struct PeerContext *peer_ctx;

  peer_ctx = get_peer_ctx (peer_map, peer_id);

  if (NULL == peer_ctx->mq)
  {
    (void) get_channel (peer_map, peer_id);
    peer_ctx->mq = GNUNET_CADET_mq_create (peer_ctx->send_channel);
    //do I have to explicitly put it in the peer_map?
    (void) GNUNET_CONTAINER_multipeermap_put (peer_map, peer_id, peer_ctx,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }
  return peer_ctx->mq;
}


/**
 * Issue check whether peer is live
 *
 * @param peer_ctx the context of the peer
 */
void
check_peer_live (struct PeerContext *peer_ctx)
{
  (void) get_channel (peer_map, &peer_ctx->peer_id);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Get informed about peer %s getting live\n",
       GNUNET_i2s (&peer_ctx->peer_id));
  peer_ctx->is_live_task =
      GNUNET_CADET_notify_transmit_ready (peer_ctx->send_channel,
                                          GNUNET_NO,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          sizeof (struct GNUNET_MessageHeader),
                                          cadet_ntfy_tmt_rdy_cb,
                                          peer_ctx);
  // FIXME check whether this is NULL
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
 * Insert PeerID in #pull_list
 *
 * Called once we know a peer is live.
 */
  void
insert_in_pull_list (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  if (GNUNET_NO == in_arr (pull_list, pull_list_size, peer))
    GNUNET_array_append (pull_list, pull_list_size, *peer);

  peer_clean (peer);
}

/**
 * Check whether #insert_in_pull_list was already scheduled
 */
  int
insert_in_pull_list_scheduled (const struct PeerContext *peer_ctx)
{
  unsigned int i;

  for ( i = 0 ; i < peer_ctx->num_outstanding_ops ; i++ )
    if (insert_in_pull_list == peer_ctx->outstanding_ops[i].op)
      return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Insert PeerID in #gossip_list
 *
 * Called once we know a peer is live.
 */
  void
insert_in_gossip_list (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  if (GNUNET_NO == in_arr (gossip_list, gossip_list_size, peer))
    GNUNET_array_append (gossip_list, gossip_list_size, *peer);

  (void) get_channel (peer_map, peer);
}

/**
 * Check whether #insert_in_gossip_list was already scheduled
 */
  int
insert_in_gossip_list_scheduled (const struct PeerContext *peer_ctx)
{
  unsigned int i;

  for ( i = 0 ; i < peer_ctx->num_outstanding_ops ; i++ )
    if (insert_in_gossip_list == peer_ctx->outstanding_ops[i].op)
      return GNUNET_YES;
  return GNUNET_NO;
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
}


/**
 * Check whether #insert_in_sampler was already scheduled
 */
static int
insert_in_sampler_scheduled (const struct PeerContext *peer_ctx)
{
  unsigned int i;

  for ( i = 0 ; i < peer_ctx->num_outstanding_ops ; i++ )
    if (insert_in_sampler== peer_ctx->outstanding_ops[i].op)
      return GNUNET_YES;
  return GNUNET_NO;
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
  unsigned int sampler_size;

  // TODO statistics

  sampler_size = RPS_sampler_get_size (client_sampler);

  if (sampler_size_est_need > sampler_size_client_need)
    bigger_size = sampler_size_est_need;
  else
    bigger_size = sampler_size_client_need;

  // TODO respect the min, max
  resize_wrapper (client_sampler, bigger_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "sampler_size is now %u\n", sampler_size);
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


/***********************************************************************
 * /Util functions
***********************************************************************/





/**
 * Function called by NSE.
 *
 * Updates sizes of sampler list and gossip list and adapt those lists
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
void client_respond (void *cls,
    struct GNUNET_PeerIdentity *ids, uint32_t num_peers)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "sampler returned %" PRIX32 " peers\n", num_peers);
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_ReplyMessage *out_msg;
  struct GNUNET_SERVER_Client *client;
  uint32_t size_needed;
  struct client_ctx *cli_ctx;

  client = (struct GNUNET_SERVER_Client *) cls;

  size_needed = sizeof (struct GNUNET_RPS_CS_ReplyMessage) +
                num_peers * sizeof (struct GNUNET_PeerIdentity);

  GNUNET_assert (GNUNET_SERVER_MAX_MESSAGE_SIZE >= size_needed);

  ev = GNUNET_MQ_msg_extra (out_msg,
                            num_peers * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_RPS_CS_REPLY);
  out_msg->num_peers = htonl (num_peers);

  memcpy (&out_msg[1],
      ids,
      num_peers * sizeof (struct GNUNET_PeerIdentity));
  GNUNET_free (ids);

  cli_ctx = GNUNET_SERVER_client_get_user_context (client, struct client_ctx);
  if ( NULL == cli_ctx ) {
    cli_ctx = GNUNET_new (struct client_ctx);
    cli_ctx->mq = GNUNET_MQ_queue_for_server_client (client);
    GNUNET_SERVER_client_set_user_context (client, cli_ctx);
  }

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
  uint32_t i;

  msg = (struct GNUNET_RPS_CS_RequestMessage *) message;

  num_peers = ntohl (msg->num_peers);
  size_needed = sizeof (struct GNUNET_RPS_CS_RequestMessage) +
                num_peers * sizeof (struct GNUNET_PeerIdentity);

  if (GNUNET_SERVER_MAX_MESSAGE_SIZE < size_needed)
  {
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  for (i = 0 ; i < num_peers ; i++)
    est_request_rate();

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Client requested %" PRIX32 " random peer(s).\n", num_peers);

  RPS_sampler_get_n_rand_peers (client_sampler, client_respond,
                                client, num_peers, GNUNET_YES);

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
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client seeded peers:\n");
  print_peer_list (peers, num_peers);

  // TODO check for validity of ids

  for (i = 0 ; i < num_peers ; i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Updating samplers with seed %" PRIX32 ": %s\n",
         i,
         GNUNET_i2s (&peers[i]));

    RPS_sampler_update (prot_sampler,   &peers[i]);
    RPS_sampler_update (client_sampler, &peers[i]);
  }

  //GNUNET_free (peers);

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

  // (check the proof of work)

  peer = (const struct GNUNET_PeerIdentity *) GNUNET_CADET_channel_get_info (channel, GNUNET_CADET_OPTION_PEER);
  // FIXME wait for cadet to change this function
  LOG (GNUNET_ERROR_TYPE_DEBUG, "PUSH received (%s)\n", GNUNET_i2s (peer));

  /* Add the sending peer to the push_list */
  if (GNUNET_NO == in_arr (push_list, push_list_size, peer))
    GNUNET_array_append (push_list, push_list_size, *peer);

  return GNUNET_OK;
}

/**
 * Handle PULL REQUEST request message from another peer.
 *
 * Reply with the gossip list of PeerIDs.
 *
 * @param cls Closure
 * @param channel The channel the PUSH was received over
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
  uint32_t send_size;
  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_P2P_PullReplyMessage *out_msg;


  peer = (struct GNUNET_PeerIdentity *) GNUNET_CADET_channel_get_info (channel,
                                                                       GNUNET_CADET_OPTION_PEER);
  // FIXME wait for cadet to change this function

  /* Compute actual size */
  send_size = sizeof (struct GNUNET_RPS_P2P_PullReplyMessage) +
              gossip_list_size * sizeof (struct GNUNET_PeerIdentity);

  if (GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE < send_size)
    /* Compute number of peers to send
     * If too long, simply truncate */
    send_size =
      (GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE -
       sizeof (struct GNUNET_RPS_P2P_PullReplyMessage)) /
       sizeof (struct GNUNET_PeerIdentity);
  else
    send_size = gossip_list_size;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "PULL REQUEST from peer %s received, going to send %u peers\n",
      GNUNET_i2s (peer), send_size);

  mq = get_mq (peer_map, peer);

  ev = GNUNET_MQ_msg_extra (out_msg,
                           send_size * sizeof (struct GNUNET_PeerIdentity),
                           GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REPLY);
  //out_msg->num_peers = htonl (gossip_list_size);
  out_msg->num_peers = htonl (send_size);
  memcpy (&out_msg[1], gossip_list,
         send_size * sizeof (struct GNUNET_PeerIdentity));

  GNUNET_MQ_send (mq, ev);

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
  LOG (GNUNET_ERROR_TYPE_DEBUG, "PULL REPLY received\n");

  struct GNUNET_RPS_P2P_PullReplyMessage *in_msg;
  struct GNUNET_PeerIdentity *peers;
  struct PeerContext *peer_ctx;
  struct GNUNET_PeerIdentity *sender;
  struct PeerContext *sender_ctx;
  struct PeerOutstandingOp out_op;
  uint32_t i;

  /* Check for protocol violation */
  if (sizeof (struct GNUNET_RPS_P2P_PullReplyMessage) > ntohs (msg->size))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  in_msg = (struct GNUNET_RPS_P2P_PullReplyMessage *) msg;
  if ((ntohs (msg->size) - sizeof (struct GNUNET_RPS_P2P_PullReplyMessage)) /
      sizeof (struct GNUNET_PeerIdentity) != ntohl (in_msg->num_peers))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        "message says it sends %" PRIu64 " peers, have space for %i peers\n",
        ntohl (in_msg->num_peers),
        (ntohs (msg->size) - sizeof (struct GNUNET_RPS_P2P_PullReplyMessage)) /
            sizeof (struct GNUNET_PeerIdentity));
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  sender = (struct GNUNET_PeerIdentity *) GNUNET_CADET_channel_get_info (
      (struct GNUNET_CADET_Channel *) channel, GNUNET_CADET_OPTION_PEER);
       // Guess simply casting isn't the nicest way...
       // FIXME wait for cadet to change this function
  sender_ctx = get_peer_ctx (peer_map, sender);

  if (GNUNET_YES == get_peer_flag (sender_ctx, PULL_REPLY_PENDING))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  /* Do actual logic */
  peers = (struct GNUNET_PeerIdentity *) &msg[1];
  for (i = 0 ; i < ntohl (in_msg->num_peers) ; i++)
  {
    peer_ctx = get_peer_ctx (peer_map, &peers[i]);
    if (GNUNET_YES == get_peer_flag (peer_ctx, VALID)
        || NULL != peer_ctx->send_channel
        || NULL != peer_ctx->recv_channel)
    {
      if (GNUNET_NO == in_arr (pull_list, pull_list_size, &peers[i])
          && 0 != GNUNET_CRYPTO_cmp_peer_identity (&own_identity, &peers[i]))
        GNUNET_array_append (pull_list, pull_list_size, peers[i]);
    }
    else if (GNUNET_NO == insert_in_pull_list_scheduled (peer_ctx))
    {
      out_op.op = insert_in_pull_list;
      out_op.op_cls = NULL;
      GNUNET_array_append (peer_ctx->outstanding_ops,
                           peer_ctx->num_outstanding_ops,
                           out_op);
      check_peer_live (peer_ctx);
    }
  }

  unset_peer_flag (sender_ctx, PULL_REPLY_PENDING);
  rem_from_list (&pending_pull_reply_list, &pending_pull_reply_list_size, sender);

  return GNUNET_OK;
}


#if ENABLE_MALICIOUS
/**
 * Turn RPS service to act malicious.
 *
 * @param cls Closure
 * @param channel The channel the PUSH was received over
 * @param channel_ctx The context associated with this channel
 * @param msg The message header
 */
  static int
handle_peer_act_malicious (void *cls,
                           struct GNUNET_CADET_Channel *channel,
                           void **channel_ctx,
                           const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_RPS_CS_ActMaliciousMessage *in_msg;
  struct GNUNET_PeerIdentity *sender;
  struct PeerContext *sender_ctx;
  struct GNUNET_PeerIdentity *peers;

  /* Check for protocol violation */
  if (sizeof (struct GNUNET_RPS_CS_ActMaliciousMessage) > ntohs (msg->size))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
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
    return GNUNET_SYSERR;
  }

  sender = (struct GNUNET_PeerIdentity *) GNUNET_CADET_channel_get_info (
      (struct GNUNET_CADET_Channel *) channel, GNUNET_CADET_OPTION_PEER);
       // Guess simply casting isn't the nicest way...
       // FIXME wait for cadet to change this function
  sender_ctx = get_peer_ctx (peer_map, sender);

  if (GNUNET_YES == get_peer_flag (sender_ctx, PULL_REPLY_PENDING))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }


  /* Do actual logic */
  peers = (struct GNUNET_PeerIdentity *) &msg[1];
  num_mal_peers = ntohl (in_msg->num_peers);
  mal_type = ntohl (in_msg->type);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Now acting malicious type %" PRIX32 "\n",
       mal_type);

  if (1 == mal_type)
  { /* Try to maximise representation */
    num_mal_peers = ntohl (in_msg->num_peers);
    mal_peers = GNUNET_new_array (num_mal_peers,
                                  struct GNUNET_PeerIdentity);
    memcpy (mal_peers, peers, num_mal_peers);

    /* Substitute do_round () with do_mal_round () */
    GNUNET_SCHEDULER_cancel (do_round_task);
    do_round_task = GNUNET_SCHEDULER_add_now (&do_mal_round, NULL);
  }
  else if (2 == mal_type)
  { /* Try to partition the network */
    num_mal_peers = ntohl (in_msg->num_peers) - 1;
    mal_peers = GNUNET_new_array (num_mal_peers,
                                  struct GNUNET_PeerIdentity);
    memcpy (mal_peers, peers, num_mal_peers);
    attacked_peer = peers[num_mal_peers];

    /* Substitute do_round () with do_mal_round () */
    GNUNET_SCHEDULER_cancel (do_round_task);
    do_round_task = GNUNET_SCHEDULER_add_now (&do_mal_round, NULL);
  }
  else if (0 == mal_type)
  { /* Stop acting malicious */
    num_mal_peers = 0;
    GNUNET_free (mal_peers);

    /* Substitute do_mal_round () with do_round () */
    GNUNET_SCHEDULER_cancel (do_round_task);
    do_round_task = GNUNET_SCHEDULER_add_now (&do_round, NULL);
  }
  else
  {
    GNUNET_break (0);
  }

  return GNUNET_OK;
}


/**
 * Send out PUSHes and PULLs maliciously.
 *
 * This is executed regylary.
 */
static void
do_mal_round (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Going to execute next round maliciously.\n");

  /* Do stuff */

  /* Compute random time value between .5 * round_interval and 1.5 *round_interval */
  half_round_interval = GNUNET_TIME_relative_divide (round_interval, 2);
  do
  {
  /*
   * Compute random value between (0 and 1) * round_interval
   * via multiplying round_interval with a 'fraction' (0 to value)/value
   */
  rand_delay = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, UINT_MAX/10);
  time_next_round = GNUNET_TIME_relative_multiply (round_interval,  rand_delay);
  time_next_round = GNUNET_TIME_relative_divide   (time_next_round, UINT_MAX/10);
  time_next_round = GNUNET_TIME_relative_add      (time_next_round, half_round_interval);
  } while (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us == time_next_round.rel_value_us);

  /* Schedule next round */
  do_round_task = GNUNET_SCHEDULER_add_delayed (round_interval, &do_mal_round, NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Finished round\n");
}
#endif /* ENABLE_MALICIOUS */


/**
 * Send out PUSHes and PULLs, possibly update #gossip_list, samplers.
 *
 * This is executed regylary.
 */
static void
do_round (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Going to execute next round.\n");

  uint32_t i;
  unsigned int *permut;
  unsigned int n_peers; /* Number of peers we send pushes/pulls to */
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_PeerIdentity peer;
  struct GNUNET_PeerIdentity *tmp_peer;
  struct GNUNET_MQ_Handle *mq;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Printing gossip list:\n");
  for (i = 0 ; i < gossip_list_size ; i++)
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "\t%s\n", GNUNET_i2s (&gossip_list[i]));
  // TODO log lists, ...

  /* Would it make sense to have one shuffeled gossip list and then
   * to send PUSHes to first alpha peers, PULL requests to next beta peers and
   * use the rest to update sampler?
   * in essence get random peers with consumption */

  /* Send PUSHes */
  if (0 < gossip_list_size)
  {
    permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_STRONG,
                                           (unsigned int) gossip_list_size);
    n_peers = ceil (alpha * gossip_list_size);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Going to send pushes to %u ceil (%f * %u) peers.\n",
         n_peers, alpha, gossip_list_size);
    for (i = 0 ; i < n_peers ; i++)
    {
      peer = gossip_list[permut[i]];
      if (0 != GNUNET_CRYPTO_cmp_peer_identity (&own_identity, &peer)) // TODO
      { // FIXME if this fails schedule/loop this for later
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Sending PUSH to peer %s of gossiped list.\n",
             GNUNET_i2s (&peer));

        ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_RPS_PP_PUSH);
        mq = get_mq (peer_map, &peer);
        GNUNET_MQ_send (mq, ev);
      }
    }
    GNUNET_free (permut);
  }


  /* Send PULL requests */
  //permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_STRONG, (unsigned int) sampler_list->size);
  n_peers = ceil (beta * gossip_list_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Going to send pulls to %u ceil (%f * %u) peers.\n",
       n_peers, beta, gossip_list_size);
  for (i = 0 ; i < n_peers ; i++)
  {
    tmp_peer = get_rand_peer_ignore_list (gossip_list, gossip_list_size,
        pending_pull_reply_list, pending_pull_reply_list_size);
    if (NULL != tmp_peer)
    {
      peer = *tmp_peer;
      GNUNET_free (tmp_peer);

      GNUNET_array_append (pending_pull_reply_list, pending_pull_reply_list_size, peer);

      if (0 != GNUNET_CRYPTO_cmp_peer_identity (&own_identity, &peer))
      { // FIXME if this fails schedule/loop this for later
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Sending PULL request to peer %s of gossiped list.\n",
             GNUNET_i2s (&peer));

        ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST);
        mq = get_mq (peer_map, &peer);
        GNUNET_MQ_send (mq, ev);
      }
    }
  }


  /* Update gossip list */

  if ( push_list_size <= alpha * gossip_list_size &&
       push_list_size != 0 &&
       pull_list_size != 0 )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Update of the gossip list.\n");

    uint32_t first_border;
    uint32_t second_border;
    uint32_t r_index;
    uint32_t peers_to_clean_size;
    struct GNUNET_PeerIdentity *peers_to_clean;

    peers_to_clean = NULL;
    peers_to_clean_size = 0;
    GNUNET_array_grow (peers_to_clean, peers_to_clean_size, gossip_list_size);
    memcpy (peers_to_clean,
            gossip_list,
            gossip_list_size * sizeof (struct GNUNET_PeerIdentity));

    first_border  =                ceil (alpha * sampler_size_est_need);
    second_border = first_border + ceil (beta  * sampler_size_est_need);

    GNUNET_array_grow (gossip_list, gossip_list_size, second_border);

    for (i = 0 ; i < first_border ; i++)
    { // TODO use RPS_sampler_get_n_rand_peers
      /* Update gossip list with peers received through PUSHes */
      r_index = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
                                       push_list_size);
      gossip_list[i] = push_list[r_index];
      // TODO change the peer_flags accordingly
    }

    for (i = first_border ; i < second_border ; i++)
    {
      /* Update gossip list with peers received through PULLs */
      r_index = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
                                       pull_list_size);
      gossip_list[i] = pull_list[r_index];
      // TODO change the peer_flags accordingly
    }

    for (i = second_border ; i < sampler_size_est_need ; i++)
    {
      /* Update gossip list with peers from history */
      RPS_sampler_get_n_rand_peers (prot_sampler, hist_update, NULL, 1, GNUNET_NO);
      num_hist_update_tasks++;
      // TODO change the peer_flags accordingly
    }

    for (i = 0 ; i < gossip_list_size ; i++)
      rem_from_list (&peers_to_clean, &peers_to_clean_size, &gossip_list[i]);

    for (i = 0 ; i < peers_to_clean_size ; i++)
      peer_clean (&peers_to_clean[i]);

    GNUNET_free (peers_to_clean);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "No update of the gossip list.\n");
  }
  // TODO independent of that also get some peers from CADET_get_peers()?


  /* Update samplers */
  for ( i = 0 ; i < push_list_size ; i++ )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Updating with peer %s from push list\n",
         GNUNET_i2s (&push_list[i]));
    RPS_sampler_update (prot_sampler,   &push_list[i]);
    RPS_sampler_update (client_sampler, &push_list[i]);
    // TODO set in_flag?
  }

  for ( i = 0 ; i < pull_list_size ; i++ )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Updating with peer %s from pull list\n",
         GNUNET_i2s (&pull_list[i]));
    RPS_sampler_update (prot_sampler,   &push_list[i]);
    RPS_sampler_update (client_sampler, &push_list[i]);
    // TODO set in_flag?
  }


  /* Empty push/pull lists */
  GNUNET_array_grow (push_list, push_list_size, 0);
  GNUNET_array_grow (pull_list, pull_list_size, 0);

  struct GNUNET_TIME_Relative time_next_round;
  struct GNUNET_TIME_Relative half_round_interval;
  unsigned int rand_delay;


  /* Compute random time value between .5 * round_interval and 1.5 *round_interval */
  half_round_interval = GNUNET_TIME_relative_divide (round_interval, 2);
  do
  {
  /*
   * Compute random value between (0 and 1) * round_interval
   * via multiplying round_interval with a 'fraction' (0 to value)/value
   */
  rand_delay = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, UINT_MAX/10);
  time_next_round = GNUNET_TIME_relative_multiply (round_interval,  rand_delay);
  time_next_round = GNUNET_TIME_relative_divide   (time_next_round, UINT_MAX/10);
  time_next_round = GNUNET_TIME_relative_add      (time_next_round, half_round_interval);
  } while (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us == time_next_round.rel_value_us);

  /* Schedule next round */
  do_round_task = GNUNET_SCHEDULER_add_delayed (round_interval, &do_round, NULL);
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
  struct PeerOutstandingOp out_op;
  struct PeerContext *peer_ctx;

  if (NULL != peer
      && 0 != GNUNET_CRYPTO_cmp_peer_identity (&own_identity, peer))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Got peer %s (at %p) from CADET (gossip_list_size: %u)\n",
        GNUNET_i2s (peer), peer, gossip_list_size);

    // maybe create a function for that
    peer_ctx = get_peer_ctx (peer_map, peer);
    if (GNUNET_YES != get_peer_flag (peer_ctx, VALID))
    {
      if (GNUNET_NO == insert_in_sampler_scheduled (peer_ctx))
      {
        out_op.op = insert_in_sampler;
        out_op.op_cls = NULL;
        GNUNET_array_append (peer_ctx->outstanding_ops,
                             peer_ctx->num_outstanding_ops,
                             out_op);
      }

      if (GNUNET_NO == insert_in_gossip_list_scheduled (peer_ctx))
      {
        out_op.op = insert_in_gossip_list;
        out_op.op_cls = NULL;
        GNUNET_array_append (peer_ctx->outstanding_ops,
                             peer_ctx->num_outstanding_ops,
                             out_op);
      }

      /* Trigger livelyness test on peer */
      check_peer_live (peer_ctx);
    }

    // send push/pull to each of those peers?
  }
}


/**
 * Clean the send channel of a peer
 */
void
peer_clean (const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *peer_ctx;
  struct GNUNET_CADET_Channel *channel;

  if (GNUNET_YES != in_arr (gossip_list, gossip_list_size, peer)
      && GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (peer_map, peer))
  {
    peer_ctx = get_peer_ctx (peer_map, peer);
    if (NULL != peer_ctx->send_channel)
    {
      channel = peer_ctx->send_channel;
      peer_ctx->send_channel = NULL;
      GNUNET_CADET_channel_destroy (channel);
    }
  }
}


/**
 * Callback used to remove peers from the multipeermap.
 */
  int
peer_remove_cb (void *cls, const struct GNUNET_PeerIdentity *key, void *value)
{
  struct PeerContext *peer_ctx;
  const struct GNUNET_CADET_Channel *channel =
    (const struct GNUNET_CADET_Channel *) cls;
  struct GNUNET_CADET_Channel *recv;
  struct GNUNET_CADET_Channel *send;

  if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (peer_map, value))
  {
    peer_ctx = (struct PeerContext *) value;

    if (0 != peer_ctx->num_outstanding_ops)
      GNUNET_array_grow (peer_ctx->outstanding_ops,
                         peer_ctx->num_outstanding_ops,
                         0);

    if (NULL != peer_ctx->mq)
      GNUNET_MQ_destroy (peer_ctx->mq);

    if (NULL != peer_ctx->is_live_task)
    {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Trying to cancle is_live_task for peer %s\n",
         GNUNET_i2s (key));
      GNUNET_CADET_notify_transmit_ready_cancel (peer_ctx->is_live_task);
      peer_ctx->is_live_task = NULL;
    }

    send = peer_ctx->send_channel;
    peer_ctx->send_channel = NULL;
    if (NULL != send
        && channel != send)
    {
      GNUNET_CADET_channel_destroy (send);
    }

    recv = peer_ctx->send_channel;
    peer_ctx->recv_channel = NULL;
    if (NULL != recv
        && channel != recv)
    {
      GNUNET_CADET_channel_destroy (recv);
    }

    if (GNUNET_YES != GNUNET_CONTAINER_multipeermap_remove_all (peer_map, key))
      LOG (GNUNET_ERROR_TYPE_WARNING, "removing peer from peer_map failed\n");
    else
      GNUNET_free (peer_ctx);
  }

  return GNUNET_YES;
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

  if (NULL != do_round_task)
  {
    GNUNET_SCHEDULER_cancel (do_round_task);
    do_round_task = NULL;
  }


  {
  if (GNUNET_SYSERR ==
        GNUNET_CONTAINER_multipeermap_iterate (peer_map, peer_remove_cb, NULL))
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Iterating over peers to disconnect from them was cancelled\n");
  }

  GNUNET_NSE_disconnect (nse);
  GNUNET_CADET_disconnect (cadet_handle);
  RPS_sampler_destroy (prot_sampler);
  RPS_sampler_destroy (client_sampler);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Size of the peermap: %u\n",
       GNUNET_CONTAINER_multipeermap_size (peer_map));
  GNUNET_break (0 == GNUNET_CONTAINER_multipeermap_size (peer_map));
  GNUNET_CONTAINER_multipeermap_destroy (peer_map);
  GNUNET_array_grow (gossip_list, gossip_list_size, 0);
  GNUNET_array_grow (push_list, push_list_size, 0);
  GNUNET_array_grow (pull_list, pull_list_size, 0);
}


/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls,
			  struct GNUNET_SERVER_Client * client)
{
}


/**
 * Handle the channel a peer opens to us.
 *
 * @param cls The closure
 * @param channel The channel the peer wants to establish
 * @param initiator The peer's peer ID
 * @param port The port the channel is being established over
 * @param options Further options
 */
  static void *
handle_inbound_channel (void *cls,
                        struct GNUNET_CADET_Channel *channel,
                        const struct GNUNET_PeerIdentity *initiator,
                        uint32_t port,
                        enum GNUNET_CADET_ChannelOption options)
{
  struct PeerContext *peer_ctx;
  struct GNUNET_PeerIdentity peer;

  peer = *initiator;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "New channel was established to us (Peer %s).\n",
      GNUNET_i2s (&peer));

  GNUNET_assert (NULL != channel);

  // we might not even store the recv_channel

  peer_ctx = get_peer_ctx (peer_map, &peer);
  // FIXME what do we do if a channel is established twice?
  //       overwrite? Clean old channel? ...?
  //if (NULL != peer_ctx->recv_channel)
  //{
  //  peer_ctx->recv_channel = channel;
  //}
  peer_ctx->recv_channel = channel;

  peer_ctx->mq = NULL;

  (void) GNUNET_CONTAINER_multipeermap_put (peer_map, &peer, peer_ctx,
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);

  peer_is_live (peer_ctx);

  return NULL; // TODO
}


/**
 * This is called when a remote peer destroys a channel.
 *
 * @param cls The closure
 * @param channel The channel being closed
 * @param channel_ctx The context associated with this channel
 */
  static void
cleanup_channel (void *cls,
                const struct GNUNET_CADET_Channel *channel,
                void *channel_ctx)
{
  struct GNUNET_PeerIdentity *peer;
  struct PeerContext *peer_ctx;

  peer = (struct GNUNET_PeerIdentity *) GNUNET_CADET_channel_get_info (
      (struct GNUNET_CADET_Channel *) channel, GNUNET_CADET_OPTION_PEER);
       // Guess simply casting isn't the nicest way...
       // FIXME wait for cadet to change this function
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up channel to peer %s\n",
       GNUNET_i2s (peer));

  if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (peer_map, peer))
  {
    peer_ctx = GNUNET_CONTAINER_multipeermap_get (peer_map, peer);

    if (NULL == peer_ctx) /* It could have been removed by shutdown_task */
      return;

    if (channel == peer_ctx->send_channel)
    { /* Peer probably went down */
      rem_from_list (&gossip_list, &gossip_list_size, peer);
      rem_from_list (&pending_pull_reply_list, &pending_pull_reply_list_size, peer);

      /* Somwewhat {ab,re}use the iterator function */
      /* Cast to void is ok, because it's used as void in peer_remove_cb */
      (void) peer_remove_cb ((void *) channel, peer, peer_ctx);
    }
    else /* Other peer doesn't want to send us messages anymore */
      peer_ctx->recv_channel = NULL;
  }
}


/**
 * Actually start the service.
 */
  static void
rps_start (struct GNUNET_SERVER_Handle *server)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_client_request, NULL, GNUNET_MESSAGE_TYPE_RPS_CS_REQUEST,
      sizeof (struct GNUNET_RPS_CS_RequestMessage)},
    {&handle_client_seed,    NULL, GNUNET_MESSAGE_TYPE_RPS_CS_SEED, 0},
    {NULL, NULL, 0, 0}
  };

  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server,
				   &handle_client_disconnect,
				   NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Ready to receive requests from clients\n");


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
  // TODO check what this does -- copied from gnunet-boss
  // - seems to work as expected
  GNUNET_log_setup ("rps", GNUNET_error_type_to_string (GNUNET_ERROR_TYPE_DEBUG), NULL);
  cfg = c;


  /* Get own ID */
  GNUNET_CRYPTO_get_peer_identity (cfg, &own_identity); // TODO check return value
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "STARTING SERVICE (rps) for peer [%s]\n",
              GNUNET_i2s (&own_identity));


  /* Get time interval from the configuration */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_time (cfg, "RPS",
                                                        "ROUNDINTERVAL",
                                                        &round_interval))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Failed to read ROUNDINTERVAL from config\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  /* Get initial size of sampler/gossip list from the configuration */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg, "RPS",
                                                         "INITSIZE",
                                                         (long long unsigned int *) &sampler_size_est_need))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Failed to read INITSIZE from config\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "INITSIZE is %" PRIu64 "\n", sampler_size_est_need);


  gossip_list = NULL;


  /* connect to NSE */
  nse = GNUNET_NSE_connect (cfg, nse_callback, NULL);
  // TODO check whether that was successful
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connected to NSE\n");


  alpha = 0.45;
  beta  = 0.45;

  peer_map = GNUNET_CONTAINER_multipeermap_create (sampler_size_est_need, GNUNET_NO);


  /* Initialise cadet */
  static const struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
    {&handle_peer_push        , GNUNET_MESSAGE_TYPE_RPS_PP_PUSH        ,
      sizeof (struct GNUNET_MessageHeader)},
    {&handle_peer_pull_request, GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST,
      sizeof (struct GNUNET_MessageHeader)},
    {&handle_peer_pull_reply  , GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REPLY  , 0},
    #if ENABLE_MALICIOUS
    {&handle_peer_act_malicious, GNUNET_MESSAGE_TYPE_RPS_ACT_MALICIOUS , 0},
    #endif /* ENABLE_MALICIOUS */
    {NULL, 0, 0}
  };

  const uint32_t ports[] = {GNUNET_RPS_CADET_PORT, 0}; // _PORT specified in src/rps/rps.h
  cadet_handle = GNUNET_CADET_connect (cfg,
                                       cls,
                                       &handle_inbound_channel,
                                       &cleanup_channel,
                                       cadet_handlers,
                                       ports);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connected to CADET\n");


  /* Initialise sampler */
  struct GNUNET_TIME_Relative half_round_interval;
  struct GNUNET_TIME_Relative  max_round_interval;

  half_round_interval = GNUNET_TIME_relative_multiply (round_interval, .5);
  max_round_interval = GNUNET_TIME_relative_add (round_interval, half_round_interval);

  prot_sampler =   RPS_sampler_init (sampler_size_est_need, max_round_interval);
  client_sampler = RPS_sampler_init (sampler_size_est_need, max_round_interval);

  /* Initialise push and pull maps */
  push_list = NULL;
  push_list_size = 0;
  pull_list = NULL;
  pull_list_size = 0;
  pending_pull_reply_list = NULL;
  pending_pull_reply_list_size = 0;


  num_hist_update_tasks = 0;


  LOG (GNUNET_ERROR_TYPE_DEBUG, "Requesting peers from CADET\n");
  GNUNET_CADET_get_peers (cadet_handle, &init_peer_cb, NULL);
  // TODO send push/pull to each of those peers?


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
