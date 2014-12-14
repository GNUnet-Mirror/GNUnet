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

#include <math.h>
#include <inttypes.h>

#define LOG(kind, ...) GNUNET_log(kind, __VA_ARGS__)

// TODO modify @brief in every file

// TODO take care that messages are not longer than 64k

// TODO check for overflows

// TODO align message structs

// TODO multipeerlist indep of gossiped list

// (TODO api -- possibility of getting weak random peer immideately)

// TODO malicious peer

// TODO switch Slist -> DLL

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Our own identity.
 */
struct GNUNET_PeerIdentity *own_identity;

/**
 * Compare two peer identities. Taken from secretsharing.
 *
 * @param p1 Some peer identity.
 * @param p2 Some peer identity.
 * @return 1 if p1 > p2, -1 if p1 < p2 and 0 if p1 == p2.
 */
static int
peer_id_cmp (const void *p1, const void *p2)
{
  return memcmp (p1, p2, sizeof (struct GNUNET_PeerIdentity));
}

/***********************************************************************
 * Sampler
 *
 * WARNING: This section needs to be reviewed regarding the use of
 * functions providing (pseudo)randomness!
***********************************************************************/

// TODO care about invalid input of the caller (size 0 or less...)

/**
 * A sampler sampling PeerIDs.
 */
struct Sampler
{
  /**
   * Min-wise linear permutation used by this sampler.
   *
   * This is an key later used by a hmac.
   */
  struct GNUNET_CRYPTO_AuthKey auth_key;

  /**
   * The PeerID this sampler currently samples.
   */
  struct GNUNET_PeerIdentity *peer_id;

  /**
   * The according hash value of this PeerID.
   */
  struct GNUNET_HashCode peer_id_hash;

  /**
   * Samplers are kept in a linked list.
   */
  struct Sampler *next;

  /**
   * Samplers are kept in a linked list.
   */
  struct Sampler *prev;

};

/**
 * A n-tuple of samplers.
 */
struct Samplers
{
  /**
   * Number of samplers we hold.
   */
  size_t size;
  
  /**
   * All PeerIDs in one array.
   */
  struct GNUNET_PeerIdentity peer_ids[];

  /**
   * The head of the DLL.
   */
  struct Sampler *head;

  /**
   * The tail of the DLL.
   */
  struct Sampler *tail;

};


typedef void (* SAMPLER_deleteCB) (void *cls, const struct GNUNET_PeerIdentity *id, struct GNUNET_HashCode hash);

/**
 * (Re)Initialise given Sampler with random min-wise independent function.
 *
 * In this implementation this means choosing an auth_key for later use in
 * a hmac at random.
 *
 * @param id pointer to the place where this sampler will store the PeerID.
 *           This will be overwritten.
 */
  struct Sampler *
SAMPLER_init(struct GNUNET_PeerIdentity *id)
{
  struct Sampler *s;
  
  s = GNUNET_new(struct Sampler);

  // I guess I don't need to call GNUNET_CRYPTO_hmac_derive_key()...
  GNUNET_CRYPTO_random_block(GNUNET_CRYPTO_QUALITY_STRONG,
                             &(s->auth_key.key),
                             GNUNET_CRYPTO_HASH_LENGTH);

  //s->peer_id = GNUNET_new( struct GNUNET_PeerIdentity );
  GNUENT_assert(NULL != id);
  s->peer_id = id;
  memcpy(s->peer_id, own_identity, sizeof(struct GNUNET_PeerIdentity));
  //s->peer_id = own_identity; // Maybe set to own PeerID. So we always have
                     // a valid PeerID in the sampler.
                     // Maybe take a PeerID as second argument.
  LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: initialised with PeerID %s (at %p) \n", GNUNET_i2s(s->peer_id), s->peer_id);

  GNUNET_CRYPTO_hmac(&s->auth_key, s->peer_id,
                     sizeof(struct GNUNET_PeerIdentity),
                     &s->peer_id_hash);

  s->prev = NULL;
  s->next = NULL;

  return s;
}

/**
 * Compare two hashes.
 *
 * Returns if the first one is smaller then the second.
 * Used by SAMPLER_next() to compare hashes.
 */
  int
hash_cmp(struct GNUNET_HashCode hash1, struct GNUNET_HashCode hash2)
{
  return memcmp( (const void *) &hash1, (const void *) & hash2, sizeof(struct GNUNET_HashCode));
}

/**
 * Input an PeerID into the given sampler.
 */
  static void
SAMPLER_next(struct Sampler *s, const struct GNUNET_PeerIdentity *id, SAMPLER_deleteCB del_cb, void *cb_cls)
  // TODO set id in peer_ids
{
  struct GNUNET_HashCode other_hash;

  if ( id == s->peer_id )
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER:          Got PeerID %s\n",
        GNUNET_i2s(id));
    LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Have already PeerID %s\n",
        GNUNET_i2s(s->peer_id));
  }
  else
  {
    GNUNET_CRYPTO_hmac(&s->auth_key,
        id,
        sizeof(struct GNUNET_PeerIdentity),
        &other_hash);

    if ( NULL == s->peer_id )
    { // Or whatever is a valid way to say
      // "we have no PeerID at the moment"
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Got PeerID %s; Simply accepting (got NULL previously).\n",
          GNUNET_i2s(id));
      memcpy(s->peer_id, id, sizeof(struct GNUNET_PeerIdentity));
      //s->peer_id = id;
      s->peer_id_hash = other_hash;
    }
    else if ( 0 > hash_cmp(other_hash, s->peer_id_hash) )
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER:            Got PeerID %s\n",
          GNUNET_i2s(id));
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Discarding old PeerID %s\n",
          GNUNET_i2s(s->peer_id));

      if ( NULL != del_cb )
      {
        LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Removing old PeerID %s with the delete callback.\n",
            GNUNET_i2s(s->peer_id));
        del_cb(cb_cls, s->peer_id, s->peer_id_hash);
      }

      memcpy(s->peer_id, id, sizeof(struct GNUNET_PeerIdentity));
      //s->peer_id = id;
      s->peer_id_hash = other_hash;
    }
    else
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER:         Got PeerID %s\n",
          GNUNET_i2s(id), id);
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Keeping old PeerID %s\n",
          GNUNET_i2s(s->peer_id), s->peer_id);
    }
  }
}


/**
 * Initialise a tuple of samplers.
 */
struct Samplers *
SAMPLER_samplers_init(size_t init_size)
{
  struct Samplers *samplers;
  struct Sampler *s;
  uint64_t i;

  samplers = GNUNET_new(struct Samplers);
  samplers->size = init_size;
  samplers->head = samplers->tail = NULL;
  samplers->peer_ids = GNUNET_new_array(init_size, struct GNUNET_PeerIdentity);

  for ( i = 0 ; i < init_size ; i++ )
  {
    GNUNET_array_append(samplers->peer_ids,
        sizeof(struct GNUNET_PeerIdentity),
        own_identity);
    s = SAMPLER_init(&samplers->peer_ids[i]);
    GNUNET_CONTAINER_DLL_insert_tail(samplers->head,
        samplers->tail,
        );
  }
  return sammplers;
}


/**
 * A fuction to update every sampler in the given list
 */
  static void
SAMPLER_update_list(struct Samplers *samplers, const struct GNUNET_PeerIdentity *id,
                    SAMPLER_deleteCB del_cb, void *cb_cls)
{
  struct Sampler *sampler;

  sampler = samplers->head;
  while ( NULL != sampler->next )
  {
    SAMPLER_next(sampler, id, del_cb, cb_cls);
  }
  
}

/**
 * Get one random peer out of the sampled peers.
 *
 * We might want to reinitialise this sampler after giving the
 * corrsponding peer to the client.
 */
  const struct GNUNET_PeerIdentity* 
SAMPLER_get_rand_peer (struct Samplers *samplers)
{
  LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER_get_rand_peer:\n");

  if ( 0 == samplers->size )
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Sgrp: List empty - Returning own PeerID %s\n", GNUNET_i2s(own_identity));
    return own_identity;
  }
  else
  {
    uint64_t index;
    struct Sampler *iter;
    uint64_t i;
    size_t s;
    const struct GNUNET_PeerIdentity *peer;

    /**
     * Choose the index of the peer we want to give back
     * at random from the interval of the sampler list
     */
    index = GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_STRONG,
                                     list_size);
                                     // TODO check that it does not overflow
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Sgrp: Length of Slist: %" PRIu64 ", index: %" PRIu64 "\n", list_size, index);

    s = sizeof( struct Sampler );
    iter = samplers->head;
    for ( i = 0 ; i < index ; i++ )
    {
      if ( NULL == iter->next )
      { // Maybe unneeded
        iter = samplers->head;
      }
    }
    
    // TODO something missing?

    peer = iter->peer_id;
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Sgrp: Returning PeerID %s\n", GNUNET_i2s(peer));
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Sgrp: (own ID: %s)\n", GNUNET_i2s(own_identity));

    return peer;
  }
}

/**
 * Get n random peers out of the sampled peers.
 *
 * We might want to reinitialise this sampler after giving the
 * corrsponding peer to the client.
 * Random with or without consumption?
 */
  const struct GNUNET_PeerIdentity*  // TODO give back simple array
SAMPLER_get_n_rand_peers (struct Samplers *samplers, uint64_t n)
{
  // TODO check if we have too much (distinct) sampled peers
  // If we are not ready yet maybe schedule for later
  const struct GNUNET_PeerIdentity *peers;
  uint64_t i;
  
  peers = GNUNET_malloc(n * sizeof(struct GNUNET_PeerIdentity));

  for ( i = 0 ; i < n ; i++ ) {
    peers[i] = SAMPLER_get_rand_peer(samplers);
  }

  // TODO something else missing?
  return peers;
}

/**
 * Counts how many Samplers currently hold a given PeerID.
 */
  uint64_t
SAMPLER_count_id ( struct Samplers *samplers, struct GNUNET_PeerIdentity *id )
{
  struct Sampler *iter;
  uint64_t count;

  iter = samplers->head;
  count = 0;
  while ( NULL != iter )
  {
    if ( peer_id_cmp( iter->peer_id, id) )
      count++;
    iter = iter->next;
  }
  return count;
}

/**
 * Gow the size of the tuple of samplers.
 */
  void
SAMPLER_samplers_grow (struct Samplers * samplers, size_t new_size)
{
  uint64_t i;
  struct Sampler;

  if ( new_size > samplers->size )
  {
    GNUNET_array_grow(samplers->peer_ids, samplers->size, new_size);
    for ( i = 0 ; i < new_size - samplers-size ; i++ )
    {
      sampler = SAMPLER_init(&samplers->peer_ids[samplers->size + i]);
      GNUNET_CONTAINER_DLL_insert_tail(samplers->head, samplers->tail, sampler);
    }
  }
  else if ( new_size < samplers->size )
  {
    for ( i = 0 ; i < samplers->size - new_size ; i++)
    {
      // TODO call delCB on elem?
      GNUNET_CONTAINER_DLL_remove(samplers->head, samplers->tail, samplers->tail);
    }
    GNUNET_array_grow(samplers->peer_ids, samplers->size, new_size);
  }

  samplers->size = new_size;
}

/***********************************************************************
 * /Sampler
***********************************************************************/



/***********************************************************************
 * Peer list
***********************************************************************/

/**
 * A struct that just holds the PeerID.
 */
struct PeerEntry
{
  /**
   * The PeerID.
   */
  struct GNUNET_PeerIdentity *id;
};

/**
 * A DLL holding PeerIDs.
 */
struct PeerList
{
  /**
   * The size of the list.
   */
  size_t size;

  /**
   * Array of PeerIDs.
   */
  struct GNUNET_PeerIdentity *peer_ids;

  /**
   * Head of the DLL.
   */
  struct PeerEntry *head;

  /**
   * Tail of the DLL.
   */
  struct PeerEntry *tail;
};

/**
 * Give back an empty PeerList.
 */
  struct PeerList*
PeerList_init()
{
  struct PeerList *peer_list;

  peer_list = GNUNET_new(struct PeerList);
  peer_list->size = 0;
  peer_list->peer_ids = NULL;
  peer_list->head = peer_list->tail = NULL;

  return peer_list;
}

/**
 * Put one PeerID into the given PeerList.
 */
  void
PeerList_put(struct PeerList *peer_list, struct GNUNET_PeerIdentity *id)
{
}

///**
// * Get one random peer out of the gossiped peer list.
// */
//  struct GNUNET_PeerIdentity *
//get_random_peer(struct GNUNET_CONTAINER_MultiPeerMap * lst)
//{
//  size_t n;
//  struct GNUNET_CONTAINER_MultiPeerMapIterator *iter;
//  uint64_t index;
//  uint64_t i;
//  struct GNUNET_PeerIdentity *peer;
//
//  n = (size_t) GNUNET_CONTAINER_multipeermap_size(lst);
//  index = GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_STRONG,
//                                   (uint64_t) n);
//  iter = GNUNET_CONTAINER_multipeermap_iterator_create(lst);
//
//  for ( i = 0 ; i < index ; i++ ) {
//    GNUNET_CONTAINER_multipeermap_iterator_next(iter, NULL, NULL);
//  }
//  
//  peer = GNUNET_malloc(sizeof(struct GNUNET_PeerIdentity));
//  GNUNET_CONTAINER_multipeermap_iterator_next(iter, peer, NULL);
//
//  return peer;
//}


/***********************************************************************
 * /Peer list
***********************************************************************/



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

/**
 * Set of all peers to keep track of them.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *peer_map;


// -- gossip list length --
// Depends on the (estimated) size of the
// network. - Initial size might be the
// number of peers cadet provides.
// TODO other events to grow/shrink size?

/**
 * List of samplers // TODO get rid of that
 */
struct GNUNET_CONTAINER_SList *sampler_list;

/**
 * List of samplers.
 */
struct Samplers *samplers; // TODO rename to sampler_list

/**
 * Sampler list size // TODO get rid of that
 *
 * Adapts to the nse. Size should be in BigTheta(network_size)^(1/3).
 */
size_t sampler_list_size;


/**
 * The gossiped list of peers.
 */
struct GNUNET_PeerIdentity *gossip_list;

/**
 * Size of the gossiped list
 */
unsigned int gossip_list_size;

/**
 * Min size of the gossip list
 */
uint64_t gossip_list_min_size;

///**
// * Max size of the gossip list
// * 
// * This will probably be left to be set by the client.
// */
//uint64_t gossip_list_max_size;


/**
 * The estimated size of the network.
 *
 * Influenced by the stdev.
 */
size_t est_size;



/**
 * Percentage of total peer number in the gossip list
 * to send random PUSHes to
 */
float alpha;

/**
 * Percentage of total peer number in the gossip list
 * to send random PULLs to
 */
float beta;

/**
 * The percentage gamma of history updates.
 * Simply 1 - alpha - beta
 */




/**
 * Identifier for the main task that runs periodically.
 */
GNUNET_SCHEDULER_TaskIdentifier do_round_task;

/**
 * Time inverval the do_round task runs in.
 */
struct GNUNET_TIME_Relative round_interval;



/**
 * List to store peers received through pushes temporary.
 */
struct GNUNET_CONTAINER_SList *push_list;

/**
 * List to store peers received through pulls temporary.
 */
struct GNUNET_CONTAINER_SList *pull_list;


/**
 * Handler to NSE.
 */
struct GNUNET_NSE_Handle *nse;

/**
 * Handler to CADET.
 */
struct GNUNET_CADET_Handle *cadet_handle;


/***********************************************************************
 * Util functions
***********************************************************************/

/**
 * Get random peer from the gossip list.
 */
  struct GNUNET_PeerIdentity *
get_rand_gossip_peer()
{
  uint64_t index;
  struct GNUNET_PeerIdentity *peer;

  // TODO find a better solution.
  // FIXME if we have only own ID in gossip list this will block
  // but then we might have a problem nevertheless ?

  do {

    /**;
     * Choose the index of the peer we want to return
     * at random from the interval of the gossip list
     */
    index = GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_STRONG,
                                     gossip_list_size);

    peer = &(gossip_list[index]);
  } while ( own_identity == peer || NULL == peer );

  return peer;
}

/**
 * Get the message queue of a specific peer.
 *
 * If we already have a message queue open to this client,
 * simply return it, otherways create one.
 */
  struct GNUNET_MQ_Handle *
get_mq (struct GNUNET_CONTAINER_MultiPeerMap *peer_map, struct GNUNET_PeerIdentity *peer_id)
{
  struct peer_context *ctx;
  struct GNUNET_MQ_Handle * mq;
  struct GNUNET_CADET_Channel *channel;

  if ( GNUNET_OK != GNUNET_CONTAINER_multipeermap_contains( peer_map, peer_id ) ) {

    channel = GNUNET_CADET_channel_create(cadet_handle, NULL, peer_id,
                                  GNUNET_RPS_CADET_PORT,
                                  GNUNET_CADET_OPTION_RELIABLE);
    mq = GNUNET_CADET_mq_create(channel);

    ctx = GNUNET_malloc(sizeof(struct peer_context));
    ctx->in_flags = 0;
    ctx->to_channel = channel;
    ctx->mq = mq;

    GNUNET_CONTAINER_multipeermap_put(peer_map, peer_id, ctx,
                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  } else {
    ctx = GNUNET_CONTAINER_multipeermap_get(peer_map, peer_id);
    if ( NULL == ctx->mq ) {
      if ( NULL == ctx->to_channel ) {
        channel = GNUNET_CADET_channel_create(cadet_handle, NULL, peer_id,
                                      GNUNET_RPS_CADET_PORT,
                                      GNUNET_CADET_OPTION_RELIABLE);
        ctx->to_channel = channel;
      }

      mq = GNUNET_CADET_mq_create(ctx->to_channel);
      ctx->mq = mq;
    }
  }

  return ctx->mq;
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
  //double scale; // TODO this might go gloabal/config

  LOG(GNUNET_ERROR_TYPE_DEBUG, "Received a ns estimate - logest: %f, std_dev: %f\n", logestimate, std_dev);
  //scale = .01;
  estimate = 1 << (uint64_t) round(logestimate);
  // GNUNET_NSE_log_estimate_to_n (logestimate);
  estimate = pow(estimate, 1./3);// * (std_dev * scale); // TODO add
  if ( 0 < estimate ) {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Changing estimate to %f\n", estimate);
    est_size = estimate;
  } else {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Not using estimate %f\n", estimate);
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
  //unsigned int n_arr[sampler_list_size];// =
    //GNUNET_CRYPTO_random_permute(GNUNET_CRYPTO_QUALITY_STRONG, (unsigned int) sampler_list_size);
  //struct GNUNET_MQ_Handle *mq;
  struct client_ctx *cli_ctx;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_ReplyMessage *out_msg;
  uint64_t num_peers;
  uint64_t i;

  // TODO
  msg = (struct GNUNET_RPS_CS_RequestMessage *) message;
  // Does not work because the compiler seems not to find it.
  cli_ctx = GNUNET_SERVER_client_get_user_context(client, struct client_ctx);
  if ( NULL == cli_ctx ) {
    cli_ctx = GNUNET_new(struct client_ctx);
    cli_ctx->mq = GNUNET_MQ_queue_for_server_client(client);
    GNUNET_SERVER_client_set_user_context(client, cli_ctx);
  }
  
  //mq = GNUNET_MQ_queue_for_server_client(client);
    
  // TODO How many peers do we give back?
  // Wait until we have enough random peers?

  ev = GNUNET_MQ_msg_extra(out_msg,
                           GNUNET_ntohll(msg->num_peers) * sizeof(struct GNUNET_PeerIdentity),
                           GNUNET_MESSAGE_TYPE_RPS_CS_REPLY);
  out_msg->num_peers = GNUNET_ntohll(msg->num_peers);

  num_peers = GNUNET_ntohll(msg->num_peers);
  //&out_msg[1] = SAMPLER_get_n_rand_peers(sampler_list, num_peers);
  for ( i = 0 ; i < num_peers ; i++ ) {
    memcpy(&out_msg[1] + i * sizeof(struct GNUNET_PeerIdentity),
           SAMPLER_get_rand_peer(sampler_list),
           sizeof(struct GNUNET_PeerIdentity));
  }
  
  GNUNET_MQ_send(cli_ctx->mq, ev);
  //GNUNET_MQ_send(mq, ev);
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
  LOG(GNUNET_ERROR_TYPE_DEBUG, "PUSH received\n");

  struct GNUNET_PeerIdentity *peer;

  // TODO check the proof of work
  // and check limit for PUSHes
  // IF we count per peer PUSHes
  // maybe remove from gossip/sampler list
  
  peer = (struct GNUNET_PeerIdentity *) GNUNET_CADET_channel_get_info( channel, GNUNET_CADET_OPTION_PEER );
  
  /* Add the sending peer to the push_list */
  GNUNET_CONTAINER_slist_add(push_list,
                             GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
                             peer, sizeof(struct GNUNET_PeerIdentity));

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
  //struct GNUNET_RPS_P2P_PullRequestMessage *in_msg;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_P2P_PullReplyMessage *out_msg;

  // TODO find some way to keep one peer from spamming with pull requests
  // allow only one request per time interval ?
  // otherwise remove from peerlist?

  peer = (struct GNUNET_PeerIdentity *) GNUNET_CADET_channel_get_info(channel, GNUNET_CADET_OPTION_PEER);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "PULL REQUEST from peer %s received\n", GNUNET_i2s(peer));

  mq = GNUNET_CADET_mq_create(channel); // TODO without mq?
  //mq = get_mq(peer_map, peer);

  //in_msg = (struct GNUNET_RPS_P2P_PullRequestMessage *) msg;
  // TODO how many peers do we actually send?
  // GNUNET_ntohll(in_msg->num_peers)
  ev = GNUNET_MQ_msg_extra(out_msg,
                           gossip_list_size * sizeof(struct GNUNET_PeerIdentity),
                           GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REPLY);
  out_msg->num_peers = GNUNET_htonll(gossip_list_size);
  memcpy(&out_msg[1], gossip_list,
         gossip_list_size * sizeof(struct GNUNET_PeerIdentity));

  GNUNET_MQ_send(mq, ev);

  GNUNET_MQ_destroy(mq);


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
  LOG(GNUNET_ERROR_TYPE_DEBUG, "PULL REPLY received\n");

  struct GNUNET_RPS_P2P_PullReplyMessage *in_msg;
  uint64_t i;

  // TODO check that we sent a request and that it is the first reply

  in_msg = (struct GNUNET_RPS_P2P_PullReplyMessage *) msg;
  for ( i = 0 ; i < in_msg->num_peers ; i++ ) {
    GNUNET_CONTAINER_slist_add(pull_list,
                               GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
                               &in_msg[1] + i * sizeof(struct GNUNET_PeerIdentity),
                               sizeof(struct GNUNET_PeerIdentity));
  }

  // TODO maybe a disconnect happens here
  
  return GNUNET_OK;
}


/**
 * Callback called when a Sampler is updated.
 */
  void
delete_cb (void *cls, struct GNUNET_PeerIdentity *id, struct GNUNET_HashCode hash)
{
  size_t s;

  //s = SAMPLER_count_id(samplers, id); // TODO
  s = SAMPLER_count_id(sampler_list, id);
  if ( 1 >= s ) {
    // TODO cleanup peer
    GNUNET_CONTAINER_multipeermap_remove_all( peer_map, id);
  }
}


/**
 * Send out PUSHes and PULLs.
 *
 * This is executed regylary.
 */
static void
do_round(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Going to execute next round\n");

  uint64_t i;
  struct Sampler *s;
  struct GNUNET_CONTAINER_SList_Iterator *iter;
  //unsigned int *n_arr;
  struct GNUNET_RPS_P2P_PushMessage        *push_msg;
  struct GNUNET_RPS_P2P_PullRequestMessage *pull_msg; // FIXME Send empty message
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_PeerIdentity *peer;

  // TODO print lists, ...
  // TODO cleanup peer_map

  iter = GNUNET_new(struct GNUNET_CONTAINER_SList_Iterator);


  /* If the NSE has changed adapt the lists accordingly */
  // TODO check nse == 0!
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Checking size estimate.\n");
  SAMPLER_samplers_grow(samplers, est_size);
  //if ( sampler_list_size < est_size ) {
  //  LOG(GNUNET_ERROR_TYPE_DEBUG, "Growing size.\n");
  //  /* Grow the lists. */
  //  for ( i = 0 ; i < est_size - sampler_list_size ; i++ ) {
  //    s = SAMPLER_init();
  //    GNUNET_CONTAINER_slist_add_end(sampler_list,
  //                                   GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT, // DEPRECATED
  //                                   s,
  //                                   sizeof(struct Sampler));

  //    // TODO add peers to gossiped ones?
  //  }
  //} else if ( sampler_list_size > est_size ) {
  //  LOG(GNUNET_ERROR_TYPE_DEBUG, "Shrinking size.\n");
  //  /* Shrink the lists. */
  //  for ( i = 0 ; i < sampler_list_size - est_size ; i++ ) {
  //    *iter = GNUNET_CONTAINER_slist_begin(sampler_list);
  //    GNUNET_CONTAINER_slist_erase(iter);
  //    GNUNET_CONTAINER_slist_iter_destroy(iter); // Maybe unneeded but I don't know whether _erase() also deletes the iter
  //  }
  //}

  GNUNET_array_grow(gossip_list, gossip_list_size, est_size); // FIXME Do conversion correct or change type

  gossip_list_size = sampler_list_size = est_size;

 


  /* Would it make sense to have one shuffeled gossip list and then
   * to send PUSHes to first alpha peers, PULL requests to next beta peers and
   * use the rest to update sampler? */

  /* Send PUSHes */
  //n_arr = GNUNET_CRYPTO_random_permute(GNUNET_CRYPTO_QUALITY_STRONG, (unsigned int) gossip_list_size);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Going to send pushes to %f (%f * %" PRIu64 ") peers.\n",
      alpha * gossip_list_size, alpha, gossip_list_size);
  for ( i = 0 ; i < alpha * gossip_list_size ; i++ ) { // TODO compute length
    peer = get_rand_gossip_peer();
    // TODO check NULL == peer
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Sending PUSH to peer %s of gossiped list.\n", GNUNET_i2s(peer));

    ev = GNUNET_MQ_msg(push_msg, GNUNET_MESSAGE_TYPE_RPS_PP_PUSH);
    //ev = GNUNET_MQ_msg_extra();
    /* TODO Compute proof of work here
    push_msg; */
    push_msg->placeholder = 0;
    GNUNET_MQ_send( get_mq(peer_map, peer), ev );

    // TODO modify in_flags of respective peer?
  }


  /* Send PULL requests */
  // TODO
  //n_arr = GNUNET_CRYPTO_random_permute(GNUNET_CRYPTO_QUALITY_STRONG, (unsigned int) sampler_list_size);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Going to send pulls to %f (%f * %" PRIu64 ") peers.\n",
      beta * gossip_list_size, beta, gossip_list_size);
  for ( i = 0 ; i < beta * gossip_list_size ; i++ ){ // TODO compute length
    peer = get_rand_gossip_peer();
    // TODO check NULL == peer
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Sending PULL request to peer %s of gossiped list.\n", GNUNET_i2s(peer));

    ev = GNUNET_MQ_msg(pull_msg, GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST);
    //ev = GNUNET_MQ_msg_extra();
    pull_msg->placeholder = 0;
    GNUNET_MQ_send( get_mq(peer_map, peer), ev );
    // TODO modify in_flags of respective peer?
  }




  /* Update gossip list */
  uint64_t tmp_index;

  if ( GNUNET_CONTAINER_slist_count(push_list) <= alpha * gossip_list_size &&
       GNUNET_CONTAINER_slist_count(push_list) != 0 &&
       GNUNET_CONTAINER_slist_count(pull_list) != 0 ) {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Update of the gossip list. ()\n");

    for ( i = 0 ; i < alpha * gossip_list_size ; i++ ) { // TODO use SAMPLER_get_n_rand_peers
      /* Update gossip list with peers received through PUSHes */
      gossip_list[i] = *SAMPLER_get_rand_peer(push_list);
      // TODO change the in_flags accordingly
    }

    for ( i = 0 ; i < beta * gossip_list_size ; i++ ) {
      /* Update gossip list with peers received through PULLs */
      tmp_index = i + round(alpha * gossip_list_size);
      gossip_list[tmp_index] = *SAMPLER_get_rand_peer(pull_list);
      // TODO change the in_flags accordingly
    }

    for ( i = 0 ; i < (1 - (alpha + beta)) * gossip_list_size ; i++ ) {
      /* Update gossip list with peers from history */
      tmp_index = i + round((alpha + beta) * gossip_list_size);
      gossip_list[tmp_index] = *SAMPLER_get_rand_peer(sampler_list);
      // TODO change the in_flags accordingly
    }

  } else {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "No update of the gossip list. ()\n");
  }
  // TODO independent of that also get some peers from CADET_get_peers()?



  /* Update samplers */
  size_t size;

  if ( 0 < GNUNET_CONTAINER_slist_count(push_list) ) {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Update of the sampler list from pushes.\n");

    *iter = GNUNET_CONTAINER_slist_begin(push_list);
    size = sizeof(struct GNUNET_PeerIdentity);

    while ( GNUNET_NO != GNUNET_CONTAINER_slist_next(iter) ) {
      peer = (struct GNUNET_PeerIdentity *) GNUNET_CONTAINER_slist_get(iter, &size);
      SAMPLER_update_list(sampler_list, peer, NULL, NULL);
      // TODO set in_flag
    }
    GNUNET_CONTAINER_slist_iter_destroy(iter);

  } else {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "No update of the sampler list - received no pushes.\n");
  }

  if ( 0 < GNUNET_CONTAINER_slist_count(pull_list) ) {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Update of the sampler list - received no pushes.\n");

    *iter = GNUNET_CONTAINER_slist_begin(pull_list);

    while ( GNUNET_NO != GNUNET_CONTAINER_slist_next(iter) ) {
      peer = (struct GNUNET_PeerIdentity *) GNUNET_CONTAINER_slist_get(iter, &size);
      SAMPLER_update_list(sampler_list, peer, NULL, NULL);
      // TODO set in_flag
    }
    GNUNET_CONTAINER_slist_iter_destroy(iter);
  } else {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "No update of the sampler list - received no pulls.\n");
  }


  GNUNET_free(iter);


  // TODO go over whole peer_map and do cleanups
  // delete unneeded peers, set in_flags, check channel/mq



  /* Empty push/pull lists */
  if ( 0 != GNUNET_CONTAINER_slist_count(push_list) ) {
      GNUNET_CONTAINER_slist_clear(push_list);
  }

  if ( 0 != GNUNET_CONTAINER_slist_count(push_list) ) {
    GNUNET_CONTAINER_slist_clear(push_list);
  }


  /* Schedule next round */
  // TODO
  do_round_task = GNUNET_SCHEDULER_add_delayed( round_interval, &do_round, NULL );
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Finished round\n");
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
  // FIXME use the magic 0000 PeerID
  if ( NULL != peer ) {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Got peer %s (at %p) from CADET\n", GNUNET_i2s(peer), peer);
    SAMPLER_update_list(sampler_list, peer, NULL, NULL);
    if ( GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains( peer_map, peer ) ) {
    } else {
      struct peer_context *ctx;

      ctx = GNUNET_malloc(sizeof(struct peer_context));
      ctx->in_flags = 0;
      ctx->mq = NULL;
      ctx->to_channel = NULL;
      ctx->from_channel = NULL;
      GNUNET_CONTAINER_multipeermap_put( peer_map, peer, ctx, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    }

    uint64_t i;
    i = GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_STRONG, gossip_list_size);
    gossip_list[i] = *peer;
    // TODO send push/pull to each of those peers?
  } else {
    rps_start( (struct GNUNET_SERVER_Handle *) cls);
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

  if ( GNUNET_SCHEDULER_NO_TASK != do_round_task )
  {
    GNUNET_SCHEDULER_cancel (do_round_task);
    do_round_task = GNUNET_SCHEDULER_NO_TASK;
  }

  GNUNET_NSE_disconnect(nse);
  GNUNET_CADET_disconnect(cadet_handle);
  GNUNET_free(own_identity);
  //GNUNET_free(round_interval);
  //GNUNET_free(est_size);
  //GNUNET_free(gossip_list_size);
  //GNUNET_free(sampler_list_size);
  GNUNET_free(gossip_list);
  // TODO for i in sampler_list free sampler
  // TODO destroy sampler_list
  // TODO destroy push/pull_list
  // TODO delete global data
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
  // TODO reinitialise that sampler
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
  LOG(GNUNET_ERROR_TYPE_DEBUG, "New channel was established to us.\n");

  GNUNET_assert( NULL != channel );

  // TODO we might even not store the from_channel

  if ( GNUNET_CONTAINER_multipeermap_contains( peer_map, initiator ) ) {
    ((struct peer_context *) GNUNET_CONTAINER_multipeermap_get( peer_map, initiator ))->from_channel = channel;
    // FIXME there might already be an established channel
  } else {
    struct peer_context *ctx;

    ctx = GNUNET_malloc( sizeof(struct peer_context));
    ctx->in_flags = in_other_gossip_list;
    ctx->mq = NULL; // TODO create mq?
    ctx->from_channel = channel;

    GNUNET_CONTAINER_multipeermap_put( peer_map, initiator, ctx, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
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
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Channel was destroyed by remote peer.\n");
}

/**
 * Actually start the service.
 */
static void
rps_start (struct GNUNET_SERVER_Handle *server)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_cs_request, NULL, GNUNET_MESSAGE_TYPE_RPS_CS_REQUEST, 0},
    {NULL, NULL, 0, 0}
  };

  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server,
				   &handle_client_disconnect,
				   NULL);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Ready to receive requests from clients\n");



  do_round_task = GNUNET_SCHEDULER_add_delayed( round_interval, &do_round, NULL);
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
  GNUNET_log_setup("rps", GNUNET_error_type_to_string(GNUNET_ERROR_TYPE_DEBUG), NULL);

  LOG(GNUNET_ERROR_TYPE_DEBUG, "RPS started\n");

  uint32_t i;

  cfg = c;


  own_identity = GNUNET_new(struct GNUNET_PeerIdentity);

  GNUNET_CRYPTO_get_peer_identity(cfg, own_identity); // TODO check return value

  LOG(GNUNET_ERROR_TYPE_DEBUG, "Own identity is %s (at %p).\n", GNUNET_i2s(own_identity), own_identity);



  /* Get time interval from the configuration */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_time (cfg, "RPS",
                                                        "ROUNDINTERVAL",
                                                        &round_interval))
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Failed to read ROUNDINTERVAL from config\n");
    GNUNET_SCHEDULER_shutdown();
    return;
  }

  /* Get initial size of sampler/gossip list from the configuration */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg, "RPS",
                                                         "INITSIZE",
                                                         (long long unsigned int *) &est_size))
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Failed to read INITSIZE from config\n");
    GNUNET_SCHEDULER_shutdown();
    return;
  }
  LOG(GNUNET_ERROR_TYPE_DEBUG, "INITSIZE is %" PRIu64 "\n", est_size);

  gossip_list_size = sampler_list_size = est_size; // TODO rename est_size


  gossip_list = NULL;

  static unsigned int tmp = 0;

  GNUNET_array_grow(gossip_list, tmp, gossip_list_size);



  /* connect to NSE */
  nse = GNUNET_NSE_connect(cfg, nse_callback, NULL);
  // TODO check whether that was successful
  // TODO disconnect on shutdown
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Connected to NSE\n");


  alpha = 0.45;
  beta  = 0.45;
  // TODO initialise thresholds - ?

  ///* Get alpha from the configuration */
  //if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_float (cfg, "RPS",
  //                                                       "ALPHA",
  //                                                       &alpha))
  //{
  //  LOG(GNUNET_ERROR_TYPE_DEBUG, "No ALPHA specified in the config\n");
  //}
  //LOG(GNUNET_ERROR_TYPE_DEBUG, "ALPHA is %f\n", alpha);
 
  ///* Get beta from the configuration */
  //if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_float (cfg, "RPS",
  //                                                       "BETA",
  //                                                       &beta))
  //{
  //  LOG(GNUNET_ERROR_TYPE_DEBUG, "No BETA specified in the config\n");
  //}
  //LOG(GNUNET_ERROR_TYPE_DEBUG, "BETA is %f\n", beta);




  peer_map = GNUNET_CONTAINER_multipeermap_create(est_size, GNUNET_NO);


  /* Initialise sampler and gossip list */
  struct Sampler *s;

  //sampler_list = GNUNET_CONTAINER_slist_create();
  samplers = SAMPLER_samplers_init(est_size);

  //if ( gossip_list_size == sampler_list_size ) {
  //  for ( i = 0 ; i < sampler_list_size ; i++ ) {
  //    /* Init sampler list */
  //    s = SAMPLER_init();
  //    GNUNET_CONTAINER_slist_add(sampler_list,
  //                               GNUNET_CONTAINER_SLIST_DISPOSITION_DYNAMIC, // TODO DEPRECATED
  //                               s,
  //                               sizeof(struct Sampler));
  //    /* Init gossip list */
  //      // TODO init gossip list
  //      // What do we need to do here?
  //  }
  //} else {
  //  for ( i = 0 ; i < gossip_list_size ; i++ ) {
  //    // TODO init gossip list
  //  }
  //  for ( i = 0 ; i < sampler_list_size ; i++ ) {
  //    // TODO init RPF func
  //    // TODO init Sample list
  //    // TODO init Sampled list
  //  }
  //}
  //uint64_t tmp_s = (uint64_t) GNUNET_CONTAINER_slist_count(sampler_list);
  //LOG(GNUNET_ERROR_TYPE_DEBUG, "Initialised sampler list %" PRIu64 "\n", tmp_s);



  push_list = GNUNET_CONTAINER_slist_create();
  pull_list = GNUNET_CONTAINER_slist_create();



  static const struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
    {&handle_peer_push        , GNUNET_MESSAGE_TYPE_RPS_PP_PUSH        , 0},
    {&handle_peer_pull_request, GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST, 0},
    {&handle_peer_pull_reply  , GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REPLY  , 0},
    {NULL, 0, 0}
  };

  const uint32_t ports[] = {GNUNET_RPS_CADET_PORT, 0}; // _PORT specified in src/rps/rps.h
  cadet_handle = GNUNET_CADET_connect(cfg,
                                    cls,
                                    &handle_inbound_channel,
                                    &cleanup_channel,
                                    cadet_handlers,
                                    ports);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Connected to CADET\n");


  LOG(GNUNET_ERROR_TYPE_DEBUG, "Requesting peers from CADET\n");
  GNUNET_CADET_get_peers(cadet_handle, &init_peer_cb, server);
  // FIXME use magic 0000 PeerID to _start_ the service

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
