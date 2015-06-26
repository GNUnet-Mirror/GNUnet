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
#include "gnunet_peerinfo_service.h"
#include "gnunet_nse_service.h"
#include "rps.h"
#include "rps-test_util.h"

#include "gnunet-service-rps_sampler.h"

#include <math.h>
#include <inttypes.h>

#define LOG(kind, ...) GNUNET_log(kind, __VA_ARGS__)

// TODO modify @brief in every file

// TODO check for overflows

// TODO align message structs

// TODO connect to friends

// TODO store peers somewhere persistent

// TODO blacklist? (-> mal peer detection on top of brahms)

// TODO API request_cancel

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
struct ClientContext
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
  VALID                = 0x10,

  /**
   * We set this bit when we are going to destroy the channel to this peer.
   * When cleanup_channel is called, we know that we wanted to destroy it.
   * Otherwise the channel to the other peer was destroyed.
   */
  TO_DESTROY           = 0x20,
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
   * Flags indicating status of peer
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
 * Name to log view to
 */
static char *file_name_view_log;

/**
 * The "local view" containing peers we learned from gossip and history
 */
static struct GNUNET_CONTAINER_MultiPeerMap *view;

/**
 * An array containing the peers of the local view.
 *
 * This is created every time we send a pull reply if it has changed since the
 * last pull reply we sent.
 */
static struct GNUNET_PeerIdentity *view_array;


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


/**
 * Closure used to pass the client and the id to the callback
 * that replies to a client's request
 */
struct ReplyCls
{
  /**
   * The identifier of the request
   */
  uint32_t id;

  /**
   * The client handle to send the reply to
   */
  struct GNUNET_SERVER_Client *client;
};


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
static uint32_t num_mal_peers = 0;


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
   * at random from the interval of the view
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
     * at random from the interval of the view
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
 * Put random peer from sampler into the view as history update.
 */
  void
hist_update (void *cls, struct GNUNET_PeerIdentity *ids, uint32_t num_peers)
{
  unsigned int i;

  for (i = 0; i < GNUNET_MIN (
       sampler_size_est_need - GNUNET_CONTAINER_multipeermap_size (view),
       num_peers); i++)
  {
    if (GNUNET_OK != GNUNET_CONTAINER_multipeermap_put (view,
          &ids[i],
          NULL,
          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
        {
          LOG (GNUNET_ERROR_TYPE_WARNING,
               "Failed to put peer in peermap. (hist_update)\n");
        }

    /* Might want to check that we really updated the view */
    if (NULL != view_array)
    {
      GNUNET_free (view_array);
      view_array = NULL;
    }

    to_file (file_name_view_log,
             "+%s\t(hist)",
             GNUNET_i2s_full (ids));
  }

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

  /* Cancle is_live_task if still scheduled */
  if (NULL != peer_ctx->is_live_task)
  {
    GNUNET_CADET_notify_transmit_ready_cancel (peer_ctx->is_live_task);
    peer_ctx->is_live_task = NULL;
  }

  peer = &peer_ctx->peer_id;
  set_peer_flag (peer_ctx, VALID);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Peer %s is live\n", GNUNET_i2s (peer));

  if (0 < peer_ctx->num_outstanding_ops)
  { /* Call outstanding operations */
    unsigned int i;

    for (i = 0 ; i < peer_ctx->num_outstanding_ops ; i++)
      peer_ctx->outstanding_ops[i].op (peer_ctx->outstanding_ops[i].op_cls, peer);
    GNUNET_array_grow (peer_ctx->outstanding_ops, peer_ctx->num_outstanding_ops, 0);
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

  peer_ctx->is_live_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Set ->is_live_task = NULL for peer %s\n",
       GNUNET_i2s (&peer_ctx->peer_id));

  if (NULL != buf
      && 0 != size)
  {
    peer_is_live (peer_ctx);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Problems establishing a connection to peer %s in order to check liveliness\n",
         GNUNET_i2s (&peer_ctx->peer_id));
    // TODO reschedule? cleanup?
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

  GNUNET_assert (NULL == peer_ctx->is_live_task);

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
  if (NULL == peer_ctx->is_live_task)
  {
    peer_ctx->is_live_task =
        GNUNET_CADET_notify_transmit_ready (peer_ctx->send_channel,
                                            GNUNET_NO,
                                            GNUNET_TIME_UNIT_FOREVER_REL,
                                            sizeof (struct GNUNET_MessageHeader),
                                            cadet_ntfy_tmt_rdy_cb,
                                            peer_ctx);
    (void) GNUNET_CONTAINER_multipeermap_put (peer_map,
        &peer_ctx->peer_id,
        peer_ctx,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Already waiting for notification\n");
  }
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
 * Insert PeerID in #view
 *
 * Called once we know a peer is live.
 */
  void
insert_in_view (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  if (GNUNET_YES != GNUNET_CONTAINER_multipeermap_put (view,
        peer,
        NULL,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Failed to put peer into view. (insert_in_view)\n");
  }

  /* Might want to check whether we really modified the view */
  if (NULL != view_array)
  {
    GNUNET_free (view_array);
    view_array = NULL;
  }

  (void) get_channel (peer_map, peer);
}

/**
 * Check whether #insert_in_view was already scheduled
 */
  int
insert_in_view_scheduled (const struct PeerContext *peer_ctx)
{
  unsigned int i;

  for ( i = 0 ; i < peer_ctx->num_outstanding_ops ; i++ )
    if (insert_in_view == peer_ctx->outstanding_ops[i].op)
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

  for (i = 0 ; i < peer_ctx->num_outstanding_ops ; i++)
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
         "Trying to add peers to an empty peermap.\n");
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
  struct GNUNET_MQ_Handle *mq;
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
      "PULL REQUEST from peer %s received, going to send %u peers\n",
      GNUNET_i2s (peer_id), send_size);

  mq = get_mq (peer_map, peer_id);

  ev = GNUNET_MQ_msg_extra (out_msg,
                            send_size * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REPLY);
  out_msg->num_peers = htonl (send_size);
  memcpy (&out_msg[1], peer_ids,
         send_size * sizeof (struct GNUNET_PeerIdentity));

  GNUNET_MQ_send (mq, ev);
}


/**
 * This function is called on new peer_ids from 'external' sources
 * (client seed, cadet get_peers(), ...)
 *
 * @param peer_id the new peer_id
 */
static void
new_peer_id (const struct GNUNET_PeerIdentity *peer_id)
{
  struct PeerOutstandingOp out_op;
  struct PeerContext *peer_ctx;

  if (NULL != peer_id &&
      0 != GNUNET_CRYPTO_cmp_peer_identity (&own_identity, peer_id))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Got peer_id %s (at %p, view size: %u)\n",
        GNUNET_i2s (peer_id),
        peer_id,
        GNUNET_CONTAINER_multipeermap_size (view));

    peer_ctx = get_peer_ctx (peer_map, peer_id);
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

      if (GNUNET_NO == insert_in_view_scheduled (peer_ctx))
      {
        out_op.op = insert_in_view;
        out_op.op_cls = NULL;
        GNUNET_array_append (peer_ctx->outstanding_ops,
                             peer_ctx->num_outstanding_ops,
                             out_op);
      }

      /* Trigger livelyness test on peer */
      check_peer_live (peer_ctx);
    }
    // else...?

    // send push/pull to each of those peers?
  }
}


/***********************************************************************
 * /Util functions
***********************************************************************/





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
void client_respond (void *cls,
    struct GNUNET_PeerIdentity *peer_ids, uint32_t num_peers)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_ReplyMessage *out_msg;
  struct ReplyCls *reply_cls = (struct ReplyCls *) cls;
  uint32_t size_needed;
  struct ClientContext *cli_ctx;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sampler returned %" PRIu32 " peers\n",
       num_peers);

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

  cli_ctx = GNUNET_SERVER_client_get_user_context (reply_cls->client, struct ClientContext);
  if (NULL == cli_ctx) {
    cli_ctx = GNUNET_new (struct ClientContext);
    cli_ctx->mq = GNUNET_MQ_queue_for_server_client (reply_cls->client);
    GNUNET_SERVER_client_set_user_context (reply_cls->client, cli_ctx);
  }

  GNUNET_free (reply_cls);

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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client requested %" PRIu32 " random peer(s).\n",
       num_peers);

  reply_cls = GNUNET_new (struct ReplyCls);
  reply_cls->id = ntohl (msg->id);
  reply_cls->client = client;

  RPS_sampler_get_n_rand_peers (client_sampler,
                                client_respond,
                                reply_cls,
                                num_peers);

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

  for (i = 0 ; i < num_peers ; i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Updating samplers with seed %" PRIu32 ": %s\n",
         i,
         GNUNET_i2s (&peers[i]));

    new_peer_id (&peers[i]);

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

  // (check the proof of work)

  peer = (const struct GNUNET_PeerIdentity *)
    GNUNET_CADET_channel_get_info (channel, GNUNET_CADET_OPTION_PEER);
  // FIXME wait for cadet to change this function

  LOG (GNUNET_ERROR_TYPE_DEBUG, "PUSH received (%s)\n", GNUNET_i2s (peer));

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

  /* Add the sending peer to the push_list */
  if (GNUNET_NO == in_arr (push_list, push_list_size, peer))
    GNUNET_array_append (push_list, push_list_size, *peer);

  return GNUNET_OK;
}


/**
 * Iterator over hash map entries.
 * Called from #generate_view_array and writes every peer id into #view_array.
 *
 * @param cls closure - the pointer to the counter
 * @param key current public key
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 * iterate,
 * #GNUNET_NO if not.
 */
static int
dump_id_to_view_array (void *cls,
                       const struct GNUNET_PeerIdentity *key,
                       void *value)
{
  unsigned int *i = (unsigned int *) cls;

  view_array[(*i)++] = *key;
  return GNUNET_YES;
}


/**
 * Makes sure the view_array is filled with the peer ids currently in #view.
 * Called from within #do_round before sending pushes and pulls and from
 * #handle_peer_pull_request when a reply is sent.
 */
static void
generate_view_array (unsigned int view_size)
{
  unsigned int *i;
  int ret;

  if (NULL == view_array)
  {
    view_array = GNUNET_new_array (view_size,
                                   struct GNUNET_PeerIdentity);
    i = GNUNET_new (unsigned int);
    *i = 0;

    ret = GNUNET_CONTAINER_multipeermap_iterate (view,
                                                 dump_id_to_view_array,
                                                 i);
    GNUNET_assert (view_size == ret);
    GNUNET_assert (view_size == *i);

    GNUNET_free (i);
  }
}


/**
 * Handle PULL REQUEST request message from another peer.
 *
 * Reply with the view of PeerIDs.
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
  unsigned int view_size;

  peer = (struct GNUNET_PeerIdentity *)
    GNUNET_CADET_channel_get_info (channel,
                                   GNUNET_CADET_OPTION_PEER);
  // FIXME wait for cadet to change this function

  LOG (GNUNET_ERROR_TYPE_DEBUG, "PULL REQUEST received (%s)\n", GNUNET_i2s (peer));

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

  view_size = GNUNET_CONTAINER_multipeermap_size (view);
  generate_view_array (view_size);

  send_pull_reply (peer, view_array, view_size);

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
  struct PeerContext *peer_ctx;
  struct GNUNET_PeerIdentity *sender;
  struct PeerContext *sender_ctx;
  struct PeerOutstandingOp out_op;
  uint32_t i;
#ifdef ENABLE_MALICIOUS
  struct AttackedPeer *tmp_att_peer;
#endif /* ENABLE_MALICIOUS */

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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "PULL REPLY received (%s)\n", GNUNET_i2s (sender));

  if (GNUNET_YES != get_peer_flag (sender_ctx, PULL_REPLY_PENDING))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Received a pull reply from a peer we didn't request one from!\n");
    GNUNET_break_op (0);
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
    if (1 == mal_type
        || 3 == mal_type)
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
      peer_ctx = get_peer_ctx (peer_map, &peers[i]);
      if (GNUNET_YES == get_peer_flag (peer_ctx, VALID) ||
          NULL != peer_ctx->send_channel ||
          NULL != peer_ctx->recv_channel)
      {
        if (GNUNET_NO == in_arr (pull_list, pull_list_size, &peers[i]))
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
  }

  unset_peer_flag (sender_ctx, PULL_REPLY_PENDING);

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
send_pull_request (struct GNUNET_PeerIdentity *peer_id)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_MQ_Handle *mq;
  struct PeerContext *peer_ctx;

  peer_ctx = get_peer_ctx (peer_map, peer_id);
  GNUNET_assert (GNUNET_NO == get_peer_flag (peer_ctx, PULL_REPLY_PENDING));
  set_peer_flag (peer_ctx, PULL_REPLY_PENDING);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending PULL request to peer %s of view.\n",
       GNUNET_i2s (peer_id));

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST);
  mq = get_mq (peer_map, peer_id);
  GNUNET_MQ_send (mq, ev);
}


/**
 * Send single push
 *
 * @param peer_id the peer to send the push to.
 */
static void
send_push (struct GNUNET_PeerIdentity *peer_id)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_MQ_Handle *mq;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending PUSH to peer %s of view.\n",
       GNUNET_i2s (peer_id));

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_RPS_PP_PUSH);
  mq = get_mq (peer_map, peer_id);
  GNUNET_MQ_send (mq, ev);
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
 * @param channel The channel the PUSH was received over
 * @param channel_ctx The context associated with this channel
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Now acting malicious type %" PRIu32 "\n",
       mal_type);

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

  else if (2 == mal_type
           || 3 == mal_type)
  { /* Try to partition the network */
    /* Add other malicious peers to those we already know */
    num_mal_peers_sent = ntohl (in_msg->num_peers) - 1;
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

    /* Store the one attacked peer */
    memcpy (&attacked_peer,
            &in_msg->attacked_peer,
            sizeof (struct GNUNET_PeerIdentity));

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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Going to execute next round maliciously.\n");

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
      send_push (&attacked_peer);
  }


  if (3 == mal_type)
  { /* Combined attack */

    /* The maximum of pushes we're going to send this round */
    num_pushes = GNUNET_MIN (GNUNET_MIN (push_limit - 1,
                                         num_attacked_peers),
                             GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE);

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Going to send %" PRIu32 " pushes\n",
         num_pushes);

    /* Send PUSHes to attacked peers */
    send_push (&attacked_peer);

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

  /* Schedule next round */
  time_next_round = compute_rand_delay (round_interval, 2);

  //do_round_task = GNUNET_SCHEDULER_add_delayed (round_interval, &do_mal_round, NULL);
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
  unsigned int view_size;
  unsigned int *permut;
  unsigned int a_peers; /* Number of peers we send pushes to */
  unsigned int b_peers; /* Number of peers we send pull requests to */
  uint32_t first_border;
  uint32_t second_border;
  struct GNUNET_PeerIdentity peer;
  struct PeerContext *peer_ctx;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Printing view:\n");
  to_file (file_name_view_log,
           "___ new round ___");
  view_size = GNUNET_CONTAINER_multipeermap_size (view);
  generate_view_array (view_size);
  for (i = 0 ; i < view_size ; i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "\t%s\n", GNUNET_i2s (&view_array[i]));
    to_file (file_name_view_log,
             "=%s\t(do round)",
             GNUNET_i2s_full (&view_array[i]));
  }


  /* Send pushes and pull requests */
  if (0 < view_size)
  {
    permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_STRONG,
                                           (unsigned int) view_size);

    /* Send PUSHes */
    a_peers = ceil (alpha * view_size);

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Going to send pushes to %u (ceil (%f * %u)) peers.\n",
         a_peers, alpha, view_size);
    for (i = 0; i < a_peers; i++)
    {
      peer = view_array[permut[i]];
      if (0 != GNUNET_CRYPTO_cmp_peer_identity (&own_identity, &peer)) // TODO
      { // FIXME if this fails schedule/loop this for later
        send_push (&peer);
      }
    }

    /* Send PULL requests */
    b_peers = ceil (beta * view_size);
    first_border = a_peers;
    second_border = a_peers + b_peers;
    if (second_border > view_size)
    {
      first_border = view_size - b_peers;
      second_border = view_size;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Going to send pulls to %u (ceil (%f * %u)) peers.\n",
        b_peers, beta, view_size);
    for (i = first_border; i < second_border; i++)
    {
      peer = view_array[permut[i]];
      peer_ctx = get_peer_ctx (peer_map, &peer);
      if (0 != GNUNET_CRYPTO_cmp_peer_identity (&own_identity, &peer) &&
          GNUNET_NO == get_peer_flag (peer_ctx, PULL_REPLY_PENDING)) // TODO
      { // FIXME if this fails schedule/loop this for later
        send_pull_request (&peer);
      }
    }

    GNUNET_free (permut);
    permut = NULL;
  }


  /* Update view */
  /* TODO see how many peers are in push-/pull- list! */

  if (push_list_size <= alpha * view_size &&
      0 < push_list_size &&
      0 < pull_list_size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Update of the view.\n");

    uint32_t final_size;
    uint32_t peers_to_clean_size;
    struct GNUNET_PeerIdentity *peers_to_clean;

    peers_to_clean = NULL;
    peers_to_clean_size = 0;
    GNUNET_array_grow (peers_to_clean, peers_to_clean_size, view_size);
    memcpy (peers_to_clean,
            view_array,
            view_size * sizeof (struct GNUNET_PeerIdentity));

    /* Seems like recreating is the easiest way of emptying the peermap */
    GNUNET_CONTAINER_multipeermap_destroy (view);
    view = GNUNET_CONTAINER_multipeermap_create (view_size, GNUNET_NO);
    to_file (file_name_view_log,
             "--- emptied ---");

    first_border  = GNUNET_MIN (ceil (alpha * sampler_size_est_need),
                                push_list_size);
    second_border = first_border +
                    GNUNET_MIN (floor (beta  * sampler_size_est_need),
                                pull_list_size);
    final_size    = second_border +
      ceil ((1 - (alpha + beta)) * sampler_size_est_need);

    GNUNET_array_grow (view_array, view_size, second_border);

    /* Update view with peers received through PUSHes */
    permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_STRONG,
                                           push_list_size);
    for (i = 0; i < first_border; i++)
    {
      view_array[i] = push_list[permut[i]];
      GNUNET_CONTAINER_multipeermap_put (view, &push_list[permut[i]], NULL,
          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

      to_file (file_name_view_log,
               "+%s\t(push list)",
               GNUNET_i2s_full (&view_array[i]));
      // TODO change the peer_flags accordingly
    }
    GNUNET_free (permut);
    permut = NULL;

    /* Update view with peers received through PULLs */
    permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_STRONG,
                                           pull_list_size);
    for (i = first_border; i < second_border; i++)
    {
      view_array[i] = pull_list[permut[i]];
      GNUNET_CONTAINER_multipeermap_put (view, &pull_list[permut[i]], NULL,
          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

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

    for (i = 0; i < view_size; i++)
      rem_from_list (&peers_to_clean, &peers_to_clean_size, &view_array[i]);

    /* Clean peers that were removed from the view */
    for (i = 0; i < peers_to_clean_size; i++)
    {
      peer_clean (&peers_to_clean[i]);
      to_file (file_name_view_log,
               "-%s",
               GNUNET_i2s_full (&peers_to_clean[i]));
    }

    GNUNET_free (peers_to_clean);
    peers_to_clean = NULL;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "No update of the view.\n");
  }
  // TODO independent of that also get some peers from CADET_get_peers()?

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received %u pushes and %u pulls last round (alpha (%.2f) * view_size (%u) = %.2f)\n",
       push_list_size,
       pull_list_size,
       alpha,
       view_size,
       alpha * view_size);

  /* Update samplers */
  for (i = 0; i < push_list_size; i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Updating with peer %s from push list\n",
         GNUNET_i2s (&push_list[i]));
    RPS_sampler_update (prot_sampler,   &push_list[i]);
    RPS_sampler_update (client_sampler, &push_list[i]);
    // TODO set in_flag?
  }

  for (i = 0; i < pull_list_size; i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Updating with peer %s from pull list\n",
         GNUNET_i2s (&pull_list[i]));
    RPS_sampler_update (prot_sampler,   &pull_list[i]);
    RPS_sampler_update (client_sampler, &pull_list[i]);
    // TODO set in_flag?
  }


  /* Empty push/pull lists */
  GNUNET_array_grow (push_list, push_list_size, 0);
  GNUNET_array_grow (pull_list, pull_list_size, 0);

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
    new_peer_id (peer);
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
    new_peer_id (peer);
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

  peer_ctx = (struct PeerContext *) value;
  set_peer_flag (peer_ctx, TO_DESTROY);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Going to clean peer %s\n",
       GNUNET_i2s (&peer_ctx->peer_id));

  /* If operations are still scheduled for this peer cancel those */
  if (0 != peer_ctx->num_outstanding_ops)
  {
    GNUNET_array_grow (peer_ctx->outstanding_ops,
                       peer_ctx->num_outstanding_ops,
                       0);
  }

  /* If we are still waiting for notification whether this peer is live
   * cancel the according task */
  if (NULL != peer_ctx->is_live_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Trying to cancle is_live_task for peer %s\n",
         GNUNET_i2s (key));
    GNUNET_CADET_notify_transmit_ready_cancel (peer_ctx->is_live_task);
    peer_ctx->is_live_task = NULL;
  }

  unset_peer_flag (peer_ctx, PULL_REPLY_PENDING);

  to_file (file_name_view_log,
           "-%s\t(cleanup channel, other peer)",
           GNUNET_i2s_full (key));
  GNUNET_CONTAINER_multipeermap_remove_all (view, key);

  /* If there is still a mq destroy it */
  if (NULL != peer_ctx->mq)
  {
    GNUNET_MQ_destroy (peer_ctx->mq);
    peer_ctx->mq = NULL;
  }


  /* Remove the send_channel
   * This function should be called again from #cleanup_channel (callback
   * called on the destruction of channels) and clean up the rest. */
  if (NULL != peer_ctx->send_channel &&
      channel != peer_ctx->send_channel)
  {
    GNUNET_CADET_channel_destroy (peer_ctx->send_channel);
    peer_ctx->send_channel = NULL;
  }

  /* Remove the recv_channel
   * This function should be called again from #cleanup_channel (callback
   * called on the destruction of channels) and clean up the rest. */
  if (NULL != peer_ctx->recv_channel &&
      channel != peer_ctx->recv_channel)
  {
    GNUNET_CADET_channel_destroy (peer_ctx->recv_channel);
    peer_ctx->recv_channel = NULL;
  }

  /* If there is no channel we have to remove the context now */
  if (GNUNET_YES != GNUNET_CONTAINER_multipeermap_remove_all (peer_map, key))
    LOG (GNUNET_ERROR_TYPE_WARNING, "removing peer from peer_map failed\n");

  GNUNET_free (peer_ctx);

  return GNUNET_YES;
}


/**
 * Clean the send channel of a peer
 * If there is also no channel to receive messages from that peer, remove it
 * from the peermap.
 */
void
peer_clean (const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *peer_ctx;
  /* struct GNUNET_CADET_Channel *channel; */

  if (GNUNET_YES != GNUNET_CONTAINER_multipeermap_contains (view, peer) &&
      GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (peer_map, peer))
  {
    peer_ctx = get_peer_ctx (peer_map, peer);
    GNUNET_CADET_channel_destroy (peer_ctx->send_channel);
    peer_ctx->send_channel = NULL;

    if (NULL == peer_ctx->recv_channel)
    {
      peer_remove_cb (NULL, peer, peer_ctx);
    }
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

  {
  if (GNUNET_SYSERR ==
        GNUNET_CONTAINER_multipeermap_iterate (peer_map, peer_remove_cb, NULL))
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Iterating over peers to disconnect from them was cancelled\n");
  }

  GNUNET_NSE_disconnect (nse);
  RPS_sampler_destroy (prot_sampler);
  RPS_sampler_destroy (client_sampler);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Size of the peermap: %u\n",
       GNUNET_CONTAINER_multipeermap_size (peer_map));
  GNUNET_break (0 == GNUNET_CONTAINER_multipeermap_size (peer_map));
  GNUNET_CADET_disconnect (cadet_handle);
  GNUNET_CONTAINER_multipeermap_destroy (peer_map);
  GNUNET_CONTAINER_multipeermap_destroy (view);
  view = NULL;
  GNUNET_array_grow (push_list, push_list_size, 0);
  GNUNET_array_grow (pull_list, pull_list_size, 0);
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

  (void) GNUNET_CONTAINER_multipeermap_put (peer_map, &peer, peer_ctx,
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);

  /* This would make the push-message unnecessary */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Got peer_id %s from peerinfo\n",
      GNUNET_i2s (&peer));
  new_peer_id (&peer);

  peer_is_live (peer_ctx);

  return NULL; // TODO
}


/**
 * This is called when a channel is destroyed.
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

  if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (peer_map, peer))
  {/* We don't want to implicitly create a context that we're about to kill */
    peer_ctx = GNUNET_CONTAINER_multipeermap_get (peer_map, peer);
    if (NULL == peer_ctx) /* It could have been removed by shutdown_task */
      return;

    if (get_peer_flag (peer_ctx, TO_DESTROY))
    {/* We initiatad the destruction of this particular peer */
      if (channel == peer_ctx->send_channel)
        peer_ctx->send_channel = NULL;
      else if (channel == peer_ctx->recv_channel)
        peer_ctx->recv_channel = NULL;

      to_file (file_name_view_log,
               "-%s\t(cleanup channel, ourself)",
               GNUNET_i2s_full (peer));
    }

    else
    { /* We did not initiate the destruction of this peer */
      if (channel == peer_ctx->send_channel)
      { /* Something (but us) killd the channel - clean up peer */
        LOG (GNUNET_ERROR_TYPE_DEBUG,
            "send channel (%s) was destroyed - cleaning up\n",
            GNUNET_i2s (peer));
        peer_ctx->send_channel = NULL;
        /* Somwewhat {ab,re}use the iterator function */
        /* Cast to void is ok, because it's used as void in peer_remove_cb */
        (void) peer_remove_cb ((void *) channel, peer, peer_ctx);
      }
      else if (channel == peer_ctx->recv_channel)
      { /* Other peer doesn't want to send us messages anymore */
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Peer %s destroyed recv channel - cleaning up channel\n",
             GNUNET_i2s (peer));
        peer_ctx->recv_channel = NULL;
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "unknown channel (%s) was destroyed\n",
             GNUNET_i2s (peer));
      }
    }
  }

  else
  { /* We don't know a context to that peer */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "channel (%s) without associated context was destroyed\n",
         GNUNET_i2s (peer));
  }
}


/**
 * Actually start the service.
 */
  static void
rps_start (struct GNUNET_SERVER_Handle *server)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_client_request,     NULL, GNUNET_MESSAGE_TYPE_RPS_CS_REQUEST,
      sizeof (struct GNUNET_RPS_CS_RequestMessage)},
    {&handle_client_seed,        NULL, GNUNET_MESSAGE_TYPE_RPS_CS_SEED, 0},
    #ifdef ENABLE_MALICIOUS
    {&handle_client_act_malicious, NULL, GNUNET_MESSAGE_TYPE_RPS_ACT_MALICIOUS , 0},
    #endif /* ENABLE_MALICIOUS */
    {NULL, NULL, 0, 0}
  };

  GNUNET_SERVER_add_handlers (server, handlers);
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

  // TODO check what this does -- copied from gnunet-boss
  // - seems to work as expected
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
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Failed to read ROUNDINTERVAL from config\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  /* Get initial size of sampler/view from the configuration */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg, "RPS",
                                                         "INITSIZE",
                                                         (long long unsigned int *) &sampler_size_est_need))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Failed to read INITSIZE from config\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "INITSIZE is %" PRIu64 "\n", sampler_size_est_need);


  view = GNUNET_CONTAINER_multipeermap_create (4, GNUNET_NO);

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

  peer_map = GNUNET_CONTAINER_multipeermap_create (sampler_size_est_need, GNUNET_NO);


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
                                       &handle_inbound_channel,
                                       &cleanup_channel,
                                       cadet_handlers,
                                       ports);

  peerinfo_handle = GNUNET_PEERINFO_connect (cfg);

  /* Initialise sampler */
  struct GNUNET_TIME_Relative half_round_interval;
  struct GNUNET_TIME_Relative  max_round_interval;

  half_round_interval = GNUNET_TIME_relative_multiply (round_interval, .5);
  max_round_interval = GNUNET_TIME_relative_add (round_interval, half_round_interval);

  prot_sampler =   RPS_sampler_init     (sampler_size_est_need, max_round_interval);
  client_sampler = RPS_sampler_mod_init (sampler_size_est_need, max_round_interval);

  /* Initialise push and pull maps */
  push_list = NULL;
  push_list_size = 0;
  pull_list = NULL;
  pull_list_size = 0;


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
