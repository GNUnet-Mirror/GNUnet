/*
     This file is part of GNUnet.
     (C)

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

// TODO take care that messages are not longer than 64k

// TODO check for overflows

// TODO align message structs

// (TODO api -- possibility of getting weak random peer immideately)

// TODO malicious peer

// TODO Change API to accept initialisation peers

// TODO Change API to accept good peers 'friends'

// TODO store peers somewhere

// TODO check that every id we get is valid - is it reachable?

// TODO ignore list

// hist_size_init, hist_size_max

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Our own identity.
 */
static struct GNUNET_PeerIdentity *own_identity;

/**
 * Closure to the callback cadet calls on each peer it passes to us
 */
struct init_peer_cls
{
  /**
   * The server handle to later listen to client requests
   */
  struct GNUNET_SERVER_Handle *server;

  /**
   * Counts how many peers cadet already passed to us
   */
  uint32_t i;
};


  struct GNUNET_PeerIdentity *
get_rand_peer (const struct GNUNET_PeerIdentity *peer_list, unsigned int size);


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
enum in_list_flag // probably unneeded
{
  in_other_sampler_list = 0x1,
  in_other_gossip_list  = 0x2, // unneeded?
  in_own_sampler_list   = 0x4,
  in_own_gossip_list    = 0x8 // unneeded?
};

/**
 * Struct used to keep track of other peer's status
 *
 * This is stored in a multipeermap.
 */
struct peer_context
{
  /**
   * In own gossip/sampler list, in other's gossip/sampler list
   */
  uint32_t in_flags; // unneeded?

  /**
   * Message queue open to client
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Channel open to client.
   */
  struct GNUNET_CADET_Channel *to_channel;

  /**
   * Channel open from client.
   */
  struct GNUNET_CADET_Channel *from_channel; // unneeded

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
static unsigned int gossip_list_size;


/**
 * The size Brahms needs according to the network size.
 *
 * This is directly taken as the #gossip_list_size on update of the
 * #gossip_list
 * This is the minimum size the sampler grows to.
 */
static unsigned int sampler_size;
//size_t sampler_size;

/**
 * The size of sampler we need to be able to satisfy the client's need of
 * random peers.
 */
static unsigned int sampler_size_client_need;


/**
 * Percentage of total peer number in the gossip list
 * to send random PUSHes to
 *
 * TODO do not read from configuration
 */
static float alpha;

/**
 * Percentage of total peer number in the gossip list
 * to send random PULLs to
 *
 * TODO do not read from configuration
 */
static float beta;

/**
 * The percentage gamma of history updates.
 * Simply 1 - alpha - beta
 */


/**
 * Identifier for the main task that runs periodically.
 */
static struct GNUNET_SCHEDULER_Task * do_round_task;

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
 * Global counter
 */
uint64_t g_i = 0;


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


/***********************************************************************
 * /Globals
***********************************************************************/


/***********************************************************************
 * Util functions
***********************************************************************/

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

  i = 0;
  while (0 != GNUNET_CRYPTO_cmp_peer_identity (&array[i], peer) &&
         i < arr_size)
    i++;

  if (i == arr_size)
    return GNUNET_NO;
  else
    return GNUNET_YES;
}


/**
 * Get random peer from the gossip list.
 */
  struct GNUNET_PeerIdentity *
get_rand_peer(const struct GNUNET_PeerIdentity *peer_list, unsigned int list_size)
{
  uint64_t r_index;
  struct GNUNET_PeerIdentity *peer;

  peer = GNUNET_new(struct GNUNET_PeerIdentity);
  // FIXME if we have only NULL in gossip list this will block
  // but then we might have a problem nevertheless

  do
  {

    /**;
     * Choose the r_index of the peer we want to return
     * at random from the interval of the gossip list
     */
    r_index = GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_STRONG,
                                     list_size);

    *peer = peer_list[r_index];
  } while (NULL == peer);

  return peer;
}


/**
 * Get the context of a peer. If not existing, create.
 */
  struct peer_context *
get_peer_ctx (struct GNUNET_CONTAINER_MultiPeerMap *peer_map, const struct GNUNET_PeerIdentity *peer)
{
  struct peer_context *ctx;

  if ( GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (peer_map, peer))
  {
    ctx = GNUNET_CONTAINER_multipeermap_get (peer_map, peer);
  }
  else
  {
    ctx = GNUNET_new (struct peer_context);
    ctx->in_flags = 0;
    ctx->mq = NULL;
    ctx->to_channel = NULL;
    ctx->from_channel = NULL;
    (void) GNUNET_CONTAINER_multipeermap_put (peer_map, peer, ctx, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  return ctx;
}


/**
 * Get the channel of a peer. If not existing, create.
 */
  struct GNUNET_CADET_Channel *
get_channel (struct GNUNET_CONTAINER_MultiPeerMap *peer_map, const struct GNUNET_PeerIdentity *peer)
{
  struct peer_context *ctx;

  ctx = get_peer_ctx (peer_map, peer);
  if (NULL == ctx->to_channel)
  {
    ctx->to_channel = GNUNET_CADET_channel_create (cadet_handle, NULL, peer,
                                                   GNUNET_RPS_CADET_PORT,
                                                   GNUNET_CADET_OPTION_RELIABLE);
    // do I have to explicitly put it in the peer_map?
    (void) GNUNET_CONTAINER_multipeermap_put (peer_map, peer, ctx,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }
  return ctx->to_channel;
}


/**
 * Get the message queue of a specific peer.
 *
 * If we already have a message queue open to this client,
 * simply return it, otherways create one.
 */
  struct GNUNET_MQ_Handle *
get_mq (struct GNUNET_CONTAINER_MultiPeerMap *peer_map, const struct GNUNET_PeerIdentity *peer_id)
{
  struct peer_context *ctx;

  ctx = get_peer_ctx (peer_map, peer_id);
  if (NULL == ctx->mq)
  {
    (void) get_channel (peer_map, peer_id);
    ctx->mq = GNUNET_CADET_mq_create (ctx->to_channel);
    //do I have to explicitly put it in the peer_map?
    (void) GNUNET_CONTAINER_multipeermap_put (peer_map, peer_id, ctx,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }
  return ctx->mq;
}


/**
 * Sum all time relatives of an array.
  */
  struct GNUNET_TIME_Relative
T_relative_sum (const struct GNUNET_TIME_Relative *rel_array, uint64_t arr_size)
{
  struct GNUNET_TIME_Relative sum;
  uint64_t i;

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
T_relative_avg (const struct GNUNET_TIME_Relative *rel_array, uint64_t arr_size)
{
  return GNUNET_TIME_relative_divide (T_relative_sum (rel_array, arr_size), arr_size); // FIXME find a way to devide that by arr_size
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
nse_callback(void *cls, struct GNUNET_TIME_Absolute timestamp, double logestimate, double std_dev)
{
  double estimate;
  unsigned int old_est;
  //double scale; // TODO this might go gloabal/config

  old_est = sampler_size;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Received a ns estimate - logest: %f, std_dev: %f (old_est: %f)\n",
      logestimate, std_dev, old_est);
  //scale = .01;
  estimate = GNUNET_NSE_log_estimate_to_n (logestimate);
  // GNUNET_NSE_log_estimate_to_n (logestimate);
  estimate = pow (estimate, 1./3);
  // TODO add if std_dev is a number
  // estimate += (std_dev * scale);
  if ( 0 < estimate ) {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Changing estimate to %f\n", estimate);
    sampler_size = estimate;
  } else
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Not using estimate %f\n", estimate);

  /* If the NSE has changed adapt the lists accordingly */
  // TODO respect the request rate, min, max
  if (old_est > sampler_size*4)
  { /* Shrinking */
    RPS_sampler_resize (old_est/2);
  }
  else if (old_est < sampler_size)
  { /* Growing */
    if (sampler_size < old_est*2)
      RPS_sampler_resize (old_est*2);
    else
      RPS_sampler_resize (sampler_size);
  }
}

/**
 * Handle RPS request from the client.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
// TODO rename
handle_cs_request (void *cls,
            struct GNUNET_SERVER_Client *client,
            const struct GNUNET_MessageHeader *message)
{
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Client requested (a) random peer(s).\n");

  struct GNUNET_RPS_CS_RequestMessage *msg;
  //unsigned int n_arr[sampler_list->size];// =
    //GNUNET_CRYPTO_random_permute(GNUNET_CRYPTO_QUALITY_STRONG, (unsigned int) sampler_list->size);
  //struct GNUNET_MQ_Handle *mq;
  struct client_ctx *cli_ctx;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_ReplyMessage *out_msg;
  uint64_t num_peers;
  const struct GNUNET_PeerIdentity *peers;
  //uint64_t i;


  /* Estimate request rate */
  if (request_deltas_size > req_counter)
    req_counter++;
  if ( 1 < req_counter)
  {
    /* Shift last request deltas to the right */
    memcpy (&request_deltas[1],
        request_deltas,
        (req_counter - 1) * sizeof (struct GNUNET_TIME_Relative));
    /* Add current delta to beginning */
    request_deltas[0] = GNUNET_TIME_absolute_get_difference (last_request,
        GNUNET_TIME_absolute_get ());
    request_rate = T_relative_avg (request_deltas, req_counter);
  }
  last_request = GNUNET_TIME_absolute_get();
  // TODO resize the size of the extended_samplers


  // TODO check message size
  msg = (struct GNUNET_RPS_CS_RequestMessage *) message;
  cli_ctx = GNUNET_SERVER_client_get_user_context (client, struct client_ctx);
  if ( NULL == cli_ctx ) {
    cli_ctx = GNUNET_new(struct client_ctx);
    cli_ctx->mq = GNUNET_MQ_queue_for_server_client (client);
    GNUNET_SERVER_client_set_user_context (client, cli_ctx);
  }
  
  // How many peers do we give back?
  // Wait until we have enough random peers?

  num_peers = GNUNET_ntohll (msg->num_peers);

  ev = GNUNET_MQ_msg_extra (out_msg,
                            num_peers * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_RPS_CS_REPLY);
  out_msg->num_peers = msg->num_peers; // No conversion between network and network order

  //&out_msg[1] = RPS_sampler_get_n_rand_peers (num_peers);
  peers = RPS_sampler_get_n_rand_peers (num_peers);
  memcpy(&out_msg[1],
      peers,
      num_peers * sizeof (struct GNUNET_PeerIdentity));
  
  GNUNET_MQ_send (cli_ctx->mq, ev);
  //GNUNET_MQ_destroy(mq);

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
  
  // TODO accept empty message
  if (ntohs(msg->size) != sizeof (struct GNUNET_RPS_P2P_PushMessage))
  {
    GNUNET_break_op (0); // At the moment our own implementation seems to break that.
    return GNUNET_SYSERR;
  }

  peer = (const struct GNUNET_PeerIdentity *) GNUNET_CADET_channel_get_info (channel, GNUNET_CADET_OPTION_PEER);
  // FIXME wait for cadet to change this function
  LOG (GNUNET_ERROR_TYPE_DEBUG, "PUSH received (%s)\n", GNUNET_i2s (peer));
  
  /* Add the sending peer to the push_list */
  if (GNUNET_NO == in_arr (push_list, pull_list_size, peer))
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
  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_P2P_PullReplyMessage *out_msg;

  // assert that msg->size is 0

  // TODO accept empty message
  if (ntohs(msg->size) != sizeof (struct GNUNET_RPS_P2P_PullRequestMessage))
  {
    GNUNET_break_op (0); // At the moment our own implementation seems to break that.
    return GNUNET_SYSERR;
  }

  peer = (struct GNUNET_PeerIdentity *) GNUNET_CADET_channel_get_info (channel, GNUNET_CADET_OPTION_PEER);
  // FIXME wait for cadet to change this function
  LOG (GNUNET_ERROR_TYPE_DEBUG, "PULL REQUEST from peer %s received\n", GNUNET_i2s (peer));

  mq = get_mq (peer_map, peer);

  ev = GNUNET_MQ_msg_extra (out_msg,
                           gossip_list_size * sizeof (struct GNUNET_PeerIdentity),
                           GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REPLY);
  out_msg->num_peers = GNUNET_htonll (gossip_list_size);
  memcpy (&out_msg[1], gossip_list,
         gossip_list_size * sizeof (struct GNUNET_PeerIdentity));

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
  uint64_t i;

  if (sizeof (struct GNUNET_RPS_P2P_PullReplyMessage) < ntohs (msg->size))
  {
    GNUNET_break_op (0); // At the moment our own implementation seems to break that.
    return GNUNET_SYSERR;
  }
  in_msg = (struct GNUNET_RPS_P2P_PullReplyMessage *) msg;
  if (ntohs (msg->size) - sizeof (struct GNUNET_RPS_P2P_PullReplyMessage) / sizeof (struct GNUNET_PeerIdentity) != GNUNET_ntohll (in_msg->num_peers))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  // TODO check that we sent a request and that it is the first reply

  peers = (struct GNUNET_PeerIdentity *) &msg[1];
  for ( i = 0 ; i < GNUNET_ntohll (in_msg->num_peers) ; i++ )
  {
    if (GNUNET_NO == in_arr(pull_list, pull_list_size, &peers[i]))
      GNUNET_array_append (pull_list, pull_list_size, peers[i]);
  }

  // TODO check that id is valid - whether it is reachable

  return GNUNET_OK;
}


/**
 * Send out PUSHes and PULLs.
 *
 * This is executed regylary.
 */
static void
do_round (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Going to execute next round\n");

  uint64_t i;
  //unsigned int *n_arr;
  unsigned int n_peers; /* Number of peers we send pushes/pulls to */
  struct GNUNET_RPS_P2P_PushMessage        *push_msg;
  struct GNUNET_RPS_P2P_PullRequestMessage *pull_msg; // FIXME Send empty message
  struct GNUNET_MQ_Envelope *ev;
  const struct GNUNET_PeerIdentity *peer;
  struct GNUNET_MQ_Handle *mq;

  // TODO print lists, ...
  // TODO randomise and spread calls herein over time


  /* Would it make sense to have one shuffeled gossip list and then
   * to send PUSHes to first alpha peers, PULL requests to next beta peers and
   * use the rest to update sampler?
   * in essence get random peers with consumption */

  /* Send PUSHes */
  //n_arr = GNUNET_CRYPTO_random_permute(GNUNET_CRYPTO_QUALITY_STRONG, (unsigned int) gossip_list_size);
  n_peers = round (alpha * gossip_list_size);
  if (0 == n_peers)
    n_peers = 1;
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Going to send pushes to %u (%f * %u) peers.\n",
      n_peers, alpha, gossip_list_size);
  for ( i = 0 ; i < n_peers ; i++ )
  {
    peer = get_rand_peer (gossip_list, gossip_list_size);
    if (own_identity != peer)
    { // FIXME if this fails schedule/loop this for later
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Sending PUSH to peer %s of gossiped list.\n", GNUNET_i2s (peer));

      ev = GNUNET_MQ_msg (push_msg, GNUNET_MESSAGE_TYPE_RPS_PP_PUSH);
      push_msg = NULL;
      // FIXME sometimes it returns a pointer to a freed mq
      mq = get_mq (peer_map, peer);
      GNUNET_MQ_send (mq, ev);
    }
  }


  /* Send PULL requests */
  //n_arr = GNUNET_CRYPTO_random_permute(GNUNET_CRYPTO_QUALITY_STRONG, (unsigned int) sampler_list->size);
  n_peers = round (beta * gossip_list_size);
  if (0 == n_peers)
    n_peers = 1;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Going to send pulls to %u (%f * %u) peers.\n",
      n_peers, beta, gossip_list_size);
  for ( i = 0 ; i < n_peers ; i++ )
  {
    peer = get_rand_peer (gossip_list, gossip_list_size);
    if (own_identity != peer)
    { // FIXME if this fails schedule/loop this for later
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Sending PULL request to peer %s of gossiped list.\n", GNUNET_i2s (peer));

      ev = GNUNET_MQ_msg (pull_msg, GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST);
      pull_msg = NULL;
      mq = get_mq (peer_map, peer);
      GNUNET_MQ_send (mq, ev);
    }
  }


  /* Update gossip list */
  uint64_t r_index;

  if ( push_list_size <= alpha * gossip_list_size &&
       push_list_size != 0 &&
       pull_list_size != 0 )
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Update of the gossip list. ()\n");

    uint64_t first_border;
    uint64_t second_border;
    
    GNUNET_array_grow(gossip_list, gossip_list_size, sampler_size);

    first_border = round(alpha * gossip_list_size);
    for ( i = 0 ; i < first_border ; i++ )
    { // TODO use RPS_sampler_get_n_rand_peers
      /* Update gossip list with peers received through PUSHes */
      r_index = GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_STRONG,
                                       push_list_size);
      gossip_list[i] = push_list[r_index];
      // TODO change the in_flags accordingly
    }

    second_border = first_border + round(beta * gossip_list_size);
    for ( i = first_border ; i < second_border ; i++ )
    {
      /* Update gossip list with peers received through PULLs */
      r_index = GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_STRONG,
                                       pull_list_size);
      gossip_list[i] = pull_list[r_index];
      // TODO change the in_flags accordingly
    }

    for ( i = second_border ; i < gossip_list_size ; i++ )
    {
      /* Update gossip list with peers from history */
      peer = RPS_sampler_get_n_rand_peers (1),
      gossip_list[i] = *peer;
      // TODO change the in_flags accordingly
    }

  }
  else
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "No update of the gossip list. ()\n");
  }
  // TODO independent of that also get some peers from CADET_get_peers()?


  /* Update samplers */

  for ( i = 0 ; i < push_list_size ; i++ )
  {
    RPS_sampler_update_list (&push_list[i]);
    // TODO set in_flag?
  }

  for ( i = 0 ; i < pull_list_size ; i++ )
  {
    RPS_sampler_update_list (&pull_list[i]);
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


/**
 * Open a connection to given peer and store channel and mq.
 */
  void
insertCB (void *cls, const struct GNUNET_PeerIdentity *id)
{
  // We open a channel to be notified when this peer goes down.
  (void) get_channel (peer_map, id);
}


/**
 * Close the connection to given peer and delete channel and mq.
 */
  void
removeCB (void *cls, const struct GNUNET_PeerIdentity *id)
{
  size_t s;
  struct peer_context *ctx;

  s = RPS_sampler_count_id (id);
  if ( 1 >= s )
  {
    if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (peer_map, id))
    {
      ctx = GNUNET_CONTAINER_multipeermap_get (peer_map, id);
      if (NULL != ctx->to_channel)
      {
        if (NULL != ctx->mq)
        {
          GNUNET_MQ_destroy (ctx->mq);
        }
        // may already be freed at shutdown of cadet
        //GNUNET_CADET_channel_destroy (ctx->to_channel);
      }
      // TODO cleanup peer
      (void) GNUNET_CONTAINER_multipeermap_remove_all (peer_map, id);
    }
  }
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
  struct init_peer_cls *ipc;

  ipc = (struct init_peer_cls *) cls;
  if ( NULL != peer )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Got %" PRIX32 ". peer %s (at %p) from CADET (gossip_list_size: %u)\n",
        ipc->i, GNUNET_i2s (peer), peer, gossip_list_size);
    RPS_sampler_update_list (peer);
    (void) get_peer_ctx (peer_map, peer); // unneeded? -> insertCB

    if (ipc->i < gossip_list_size)
    {
      gossip_list[ipc->i] = *peer; // FIXME sometimes we're writing to invalid space here
                                   // not sure whether fixed
      ipc->i++;
    }

    // send push/pull to each of those peers?
  }
  else
  {
    if (ipc->i < gossip_list_size)
    {
      memcpy(&gossip_list[ipc->i],
          RPS_sampler_get_n_rand_peers (1),
          (gossip_list_size - ipc->i) * sizeof(struct GNUNET_PeerIdentity));
    }
    rps_start (ipc->server);
    GNUNET_free (ipc);
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
  LOG(GNUNET_ERROR_TYPE_DEBUG, "RPS is going down\n");

  if ( NULL != do_round_task )
  {
    GNUNET_SCHEDULER_cancel (do_round_task);
    do_round_task = NULL;
  }

  GNUNET_NSE_disconnect (nse);
  GNUNET_CADET_disconnect (cadet_handle);
  GNUNET_free (own_identity);
  RPS_sampler_destroy ();
  GNUNET_array_grow (request_deltas, request_deltas_size, 0);
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
  struct peer_context *ctx;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "New channel was established to us (Peer %s).\n", GNUNET_i2s(initiator));

  GNUNET_assert( NULL != channel );

  // we might not even store the from_channel

  ctx = get_peer_ctx(peer_map, initiator);
  if (NULL != ctx->from_channel)
  {
    ctx->from_channel = channel;
  }

  // FIXME there might already be an established channel

  //ctx->in_flags = in_other_gossip_list;
  ctx->mq = NULL; // TODO create mq?

  (void) GNUNET_CONTAINER_multipeermap_put (peer_map, initiator, ctx,
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
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
cleanup_channel(void *cls,
                const struct GNUNET_CADET_Channel *channel,
                void *channel_ctx)
{
  struct GNUNET_PeerIdentity *peer;
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Channel to remote peer was destroyed.\n");

  peer = (struct GNUNET_PeerIdentity *) GNUNET_CADET_channel_get_info (
      (struct GNUNET_CADET_Channel *) channel, GNUNET_CADET_OPTION_PEER);
       // Guess simply casting isn't the nicest way...
       // FIXME wait for cadet to change this function
  RPS_sampler_reinitialise_by_value (peer);
}

/**
 * Actually start the service.
 */
static void
rps_start (struct GNUNET_SERVER_Handle *server)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_cs_request, NULL, GNUNET_MESSAGE_TYPE_RPS_CS_REQUEST,
      sizeof (struct GNUNET_RPS_CS_RequestMessage)},
    {NULL, NULL, 0, 0}
  };

  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server,
				   &handle_client_disconnect,
				   NULL);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Ready to receive requests from clients\n");


  do_round_task = GNUNET_SCHEDULER_add_now (&do_round, NULL);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Scheduled first round\n");

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

  LOG(GNUNET_ERROR_TYPE_DEBUG, "RPS started\n");

  struct init_peer_cls *ipc;

  cfg = c;


  /* Get own ID */
  own_identity = GNUNET_new (struct GNUNET_PeerIdentity);
  GNUNET_CRYPTO_get_peer_identity (cfg, own_identity); // TODO check return value
  GNUNET_assert (NULL != own_identity);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Own identity is %s (at %p).\n", GNUNET_i2s(own_identity), own_identity);


  /* Get time interval from the configuration */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_time (cfg, "RPS",
                                                        "ROUNDINTERVAL",
                                                        &round_interval))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Failed to read ROUNDINTERVAL from config\n");
    GNUNET_SCHEDULER_shutdown();
    return;
  }

  /* Get initial size of sampler/gossip list from the configuration */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg, "RPS",
                                                         "INITSIZE",
                                                         (long long unsigned int *) &sampler_size))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Failed to read INITSIZE from config\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "INITSIZE is %" PRIu64 "\n", sampler_size);

  //gossip_list_size = sampler_size; // TODO rename sampler_size

  gossip_list = NULL;
  GNUNET_array_grow (gossip_list, gossip_list_size, sampler_size);


  /* connect to NSE */
  nse = GNUNET_NSE_connect(cfg, nse_callback, NULL);
  // TODO check whether that was successful
  // TODO disconnect on shutdown
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Connected to NSE\n");


  alpha = 0.45;
  beta  = 0.45;
  // TODO initialise thresholds - ?

  /* Get alpha from the configuration */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_float (cfg, "RPS",
                                                         "ALPHA",
                                                         &alpha))
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "No ALPHA specified in the config\n");
  }
  LOG(GNUNET_ERROR_TYPE_DEBUG, "ALPHA is %f\n", alpha);
 
  /* Get beta from the configuration */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_float (cfg, "RPS",
                                                         "BETA",
                                                         &beta))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "No BETA specified in the config\n");
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "BETA is %f\n", beta);

  // TODO check that alpha + beta < 1

  peer_map = GNUNET_CONTAINER_multipeermap_create (sampler_size, GNUNET_NO);


  /* Initialise cadet */
  static const struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
    {&handle_peer_push        , GNUNET_MESSAGE_TYPE_RPS_PP_PUSH        , 0},
    {&handle_peer_pull_request, GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST, 0},
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
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connected to CADET\n");


  /* Initialise sampler */
  RPS_sampler_init (sampler_size, own_identity, insertCB, NULL, removeCB, NULL);

  /* Initialise push and pull maps */
  push_list = NULL;
  push_list_size = 0;
  pull_list = NULL;
  pull_list_size = 0;


  ipc = GNUNET_new (struct init_peer_cls);
  ipc->server = server;
  ipc->i = 0;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Requesting peers from CADET\n");
  GNUNET_CADET_get_peers (cadet_handle, &init_peer_cb, ipc);

  // TODO send push/pull to each of those peers?
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
