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

// (TODO api -- possibility of getting weak random peer immideately)

// TODO malicious peer

// TODO Change API to accept initialisation peers

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Our own identity.
 */
static struct GNUNET_PeerIdentity *own_identity;


  struct GNUNET_PeerIdentity *
get_rand_peer(struct GNUNET_PeerIdentity *peer_list, unsigned int size);

/***********************************************************************
 * Sampler
 *
 * WARNING: This section needs to be reviewed regarding the use of
 * functions providing (pseudo)randomness!
***********************************************************************/

// TODO care about invalid input of the caller (size 0 or less...)

// It might be interesting to formulate this independent of PeerIDs.

/**
 * Callback that is called when a new PeerID is inserted into a sampler.
 *
 * @param cls the closure given alongside this function.
 * @param id the PeerID that is inserted
 * @param hash the hash the sampler produced of the PeerID
 */
typedef void (* SAMPLER_insertCB) (void *cls,
    const struct GNUNET_PeerIdentity *id,
    struct GNUNET_HashCode hash);

/**
 * Callback that is called when a new PeerID is removed from a sampler.
 *
 * @param cls the closure given alongside this function.
 * @param id the PeerID that is removed
 * @param hash the hash the sampler produced of the PeerID
 */
typedef void (* SAMPLER_removeCB) (void *cls,
    const struct GNUNET_PeerIdentity *id,
    struct GNUNET_HashCode hash);

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
  unsigned int size;
  //size_t size;
  
  /**
   * All PeerIDs in one array.
   */
  struct GNUNET_PeerIdentity *peer_ids;

  /**
   * Callback to be called when a peer gets inserted into a sampler.
   */
  SAMPLER_insertCB insertCB;

  /**
   * Closure to the insertCB.
   */
  void *insertCLS;

  /**
   * Callback to be called when a peer gets inserted into a sampler.
   */
  SAMPLER_removeCB removeCB;

  /**
   * Closure to the removeCB.
   */
  void *removeCLS;

  /**
   * The head of the DLL.
   */
  struct Sampler *head;

  /**
   * The tail of the DLL.
   */
  struct Sampler *tail;

};

/**
 * Reinitialise a previously initialised sampler.
 *
 * @param sampler the sampler element.
 * @param id pointer to the memory that keeps the value.
 */
  void
SAMPLER_reinitialise_sampler (struct Sampler *sampler, struct GNUNET_PeerIdentity *id)
{
  // I guess I don't need to call GNUNET_CRYPTO_hmac_derive_key()...
  GNUNET_CRYPTO_random_block(GNUNET_CRYPTO_QUALITY_STRONG,
                             &(sampler->auth_key.key),
                             GNUNET_CRYPTO_HASH_LENGTH);

  GNUNET_assert(NULL != id);
  sampler->peer_id = id;
  memcpy(sampler->peer_id, own_identity, sizeof(struct GNUNET_PeerIdentity)); // FIXME this should probably be NULL -- the caller has to handle those.
  // Maybe take a PeerID as second argument.

  GNUNET_CRYPTO_hmac(&sampler->auth_key, sampler->peer_id,
                     sizeof(struct GNUNET_PeerIdentity),
                     &sampler->peer_id_hash);
}


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

  SAMPLER_reinitialise_sampler (s, id);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: initialised with PeerID %s (at %p) \n",
      GNUNET_i2s(s->peer_id), s->peer_id);

  s->prev = NULL;
  s->next = NULL;

  return s;
}

/**
 * Input an PeerID into the given sampler.
 */
  static void
SAMPLER_next(struct Sampler *s, const struct GNUNET_PeerIdentity *other,
    SAMPLER_insertCB insertCB, void *insertCLS,
    SAMPLER_removeCB removeCB, void *removeCLS)
  // TODO call update herein
{
  struct GNUNET_HashCode other_hash;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: New PeerID %s at %p\n",
      GNUNET_i2s(other), other);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Old PeerID %s at %p\n",
      GNUNET_i2s(s->peer_id), s->peer_id);

  if ( 0 == GNUNET_CRYPTO_cmp_peer_identity(other, s->peer_id) )
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER:          Got PeerID %s\n",
        GNUNET_i2s(other));
    LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Have already PeerID %s\n",
        GNUNET_i2s(s->peer_id));
  }
  else
  {
    GNUNET_CRYPTO_hmac(&s->auth_key,
        other,
        sizeof(struct GNUNET_PeerIdentity),
        &other_hash);

    if ( NULL == s->peer_id )
    { // Or whatever is a valid way to say
      // "we have no PeerID at the moment"
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Got PeerID %s; Simply accepting (got NULL previously).\n",
          GNUNET_i2s(other));
      memcpy(s->peer_id, other, sizeof(struct GNUNET_PeerIdentity));
      //s->peer_id = other;
      s->peer_id_hash = other_hash;
      if (NULL != insertCB)
      {
        insertCB(insertCLS, s->peer_id, s->peer_id_hash);
      }
    }
    else if ( 0 > GNUNET_CRYPTO_hash_cmp(&other_hash, &s->peer_id_hash) )
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER:            Got PeerID %s\n",
          GNUNET_i2s(other));
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Discarding old PeerID %s\n",
          GNUNET_i2s(s->peer_id));

      if ( NULL != removeCB )
      {
        LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Removing old PeerID %s with the remove callback.\n",
            GNUNET_i2s(s->peer_id));
        removeCB(removeCLS, s->peer_id, s->peer_id_hash);
      }

      memcpy(s->peer_id, other, sizeof(struct GNUNET_PeerIdentity));
      //s->peer_id = other;
      s->peer_id_hash = other_hash;

      if ( NULL != insertCB )
      {
        LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Inserting new PeerID %s with the insert callback.\n",
            GNUNET_i2s(s->peer_id));
        insertCB(insertCLS, s->peer_id, s->peer_id_hash);
      }
    }
    else
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER:         Got PeerID %s\n",
          GNUNET_i2s(other));
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Keeping old PeerID %s\n",
          GNUNET_i2s(s->peer_id));
    }
  }
}

/**
 * Gow or shrink the size of the tuple of samplers.
 *
 * @param samplers the samplers to grow
 * @param new_size the new size of the samplers
 * @param fill_up_id if growing, that has to point to a
 *                   valid PeerID and will be used
 *                   to initialise newly created samplers
 */
  void
SAMPLER_samplers_resize (struct Samplers * samplers,
    unsigned int new_size,
    struct GNUNET_PeerIdentity *fill_up_id)
{
  if ( samplers->size == new_size )
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Size remains the same -- nothing to do\n");
    return;
  }

  unsigned int old_size;
  struct Sampler *iter;
  uint64_t i;
  struct Sampler *tmp;

  old_size = samplers->size;
  LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Growing/Shrinking samplers %u -> %u\n", old_size, new_size);

  iter = samplers->head;

  if ( new_size < old_size )
  {
    for ( i = new_size ; i < old_size ; i++ )
    {/* Remove unneeded rest */
      tmp = iter->next;
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Removing %" PRIX64 ". sampler\n", i);
      if (NULL != samplers->removeCB)
        samplers->removeCB(samplers->removeCLS, iter->peer_id, iter->peer_id_hash);
        // FIXME When this is called and counts the amount of peer_ids in the samplers
        //       this gets a wrong number.
      GNUNET_CONTAINER_DLL_remove(samplers->head, samplers->tail, iter);
      GNUNET_free(iter);
      iter = tmp;
    }
  }

  GNUNET_array_grow(samplers->peer_ids, samplers->size, new_size);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: samplers->peer_ids now points to %p\n", samplers->peer_ids);

  if ( new_size > old_size )
  { /* Growing */
    GNUNET_assert( NULL != fill_up_id );
    for ( i = 0 ; i < new_size ; i++ )
    { /* All samplers */
      if ( i < old_size )
      { /* Update old samplers */
        iter->peer_id = &samplers->peer_ids[i];
        LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Updated %" PRIX64 ". sampler, now pointing to %p, contains %s\n",
            i, &samplers->peer_ids[i], GNUNET_i2s(iter->peer_id));
        iter = iter->next;
      }
      else
      { /* Add new samplers */
        memcpy(&samplers->peer_ids[i], fill_up_id, sizeof(struct GNUNET_PeerIdentity));
        iter = SAMPLER_init(&samplers->peer_ids[i]);
        if (NULL != samplers->insertCB)
        {
          samplers->insertCB(samplers->insertCLS, iter->peer_id, iter->peer_id_hash);
        }
        GNUNET_CONTAINER_DLL_insert_tail(samplers->head, samplers->tail, iter);
        LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Added %" PRIX64 ". sampler, now pointing to %p, contains %s\n",
            i, &samplers->peer_ids[i], GNUNET_i2s(iter->peer_id));
      }
    }
  }
  else// if ( new_size < old_size )
  { /* Shrinking */
    for ( i = 0 ; i < new_size ; i++)
    { /* All samplers */
      tmp = iter->next;
      /* Update remaining samplers */
      iter->peer_id = &samplers->peer_ids[i];
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Updatied %" PRIX64 ". sampler, now pointing to %p, contains %s\n",
          i, &samplers->peer_ids[i], GNUNET_i2s(iter->peer_id));

      iter = tmp;
    }
  }

  GNUNET_assert(samplers->size == new_size);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Finished growing/shrinking.\n");
}


/**
 * Initialise a tuple of samplers.
 */
struct Samplers *
SAMPLER_samplers_init(size_t init_size, struct GNUNET_PeerIdentity *id,
    SAMPLER_insertCB insertCB, void *insertCLS,
    SAMPLER_removeCB removeCB, void *removeCLS)
{
  struct Samplers *samplers;
  //struct Sampler *s;
  //uint64_t i;

  samplers = GNUNET_new(struct Samplers);
  samplers->size = 0;
  samplers->peer_ids = NULL;
  samplers->insertCB = insertCB;
  samplers->insertCLS = insertCLS;
  samplers->removeCB = removeCB;
  samplers->removeCLS = removeCLS;
  samplers->head = samplers->tail = NULL;
  //samplers->peer_ids = GNUNET_new_array(init_size, struct GNUNET_PeerIdentity);

  SAMPLER_samplers_resize(samplers, init_size, id);

  GNUNET_assert(init_size == samplers->size);
  return samplers;
}


/**
 * A fuction to update every sampler in the given list
 */
  static void
SAMPLER_update_list(struct Samplers *samplers, const struct GNUNET_PeerIdentity *id)
{
  struct Sampler *iter;

  iter = samplers->head;
  while ( NULL != iter->next )
  {
    SAMPLER_next(iter, id,
        samplers->insertCB, samplers->insertCLS,
        samplers->removeCB, samplers->removeCLS);
    iter = iter->next;
  }
  
}

/**
 * Reinitialise all previously initialised sampler with the given value.
 *
 * @param samplers the sampler list.
 * @param id the id of the samplers to update.
 */
  void
SAMPLER_reinitialise_samplers_by_value (struct Samplers *samplers, const struct GNUNET_PeerIdentity *id)
{
  uint64_t i;
  struct Sampler *iter;

  iter = samplers->head;
  for ( i = 0 ; i < samplers->size ; i++ )
  {
    if ( 0 == GNUNET_CRYPTO_cmp_peer_identity(id, &samplers->peer_ids[i]) )
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Reinitialising sampler\n");
      SAMPLER_reinitialise_sampler (iter, &samplers->peer_ids[i]);
    }
    if (NULL != iter->next)
      iter = iter->next;
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
    const struct GNUNET_PeerIdentity *peer;

    peer = get_rand_peer(samplers->peer_ids, samplers->size);
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
  struct GNUNET_PeerIdentity *peers;
  uint64_t i;
  
  peers = GNUNET_malloc(n * sizeof(struct GNUNET_PeerIdentity));

  for ( i = 0 ; i < n ; i++ ) {
    //peers[i] = SAMPLER_get_rand_peer(samplers);
    memcpy(&peers[i], SAMPLER_get_rand_peer(samplers), sizeof(struct GNUNET_PeerIdentity));
  }

  // TODO something else missing?
  return peers;
}

/**
 * Counts how many Samplers currently hold a given PeerID.
 */
  uint64_t
SAMPLER_count_id ( struct Samplers *samplers, const struct GNUNET_PeerIdentity *id )
{
  struct Sampler *iter;
  uint64_t count;

  iter = samplers->head;
  count = 0;
  while ( NULL != iter )
  {
    if ( 0 == GNUNET_CRYPTO_cmp_peer_identity( iter->peer_id, id) )
      count++;
    iter = iter->next;
  }
  return count;
}


/**
 * Cleans the samplers.
 * 
 * @param samplers the samplers to clean up.
 */
  void
SAMPLER_samplers_destroy (struct Samplers *samplers)
{
  SAMPLER_samplers_resize(samplers, 0, NULL);
  GNUNET_free(samplers);
}

/***********************************************************************
 * /Sampler
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


/**
 * The samplers.
 */
static struct Samplers *sampler_list;


/**
 * The gossiped list of peers.
 */
static struct GNUNET_PeerIdentity *gossip_list;

/**
 * Size of the gossiped list
 */
static unsigned int gossip_list_size;


/**
 * The estimated size of the network.
 *
 * Influenced by the stdev.
 */
static unsigned int est_size;
//size_t est_size;


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
static struct GNUNET_SCHEDULER_Task * do_round_task;

/**
 * Time inverval the do_round task runs in.
 */
static struct GNUNET_TIME_Relative round_interval;



/**
 * List to store peers received through pushes temporary.
 */
static struct GNUNET_PeerIdentity *push_list;

/**
 * Size of the push_list;
 */
static unsigned int push_list_size;
//size_t push_list_size;

/**
 * List to store peers received through pulls temporary.
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


/***********************************************************************
 * Util functions
***********************************************************************/

/**
 * Get random peer from the gossip list.
 */
  struct GNUNET_PeerIdentity *
get_rand_peer(struct GNUNET_PeerIdentity *peer_list, unsigned int list_size)
{
  uint64_t r_index;
  struct GNUNET_PeerIdentity *peer;

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

    peer = &(peer_list[r_index]);
  } while (NULL == peer);

  return peer;
}

/**
 * Make sure the context of a given peer exists in the given peer_map.
 */
  void
touch_peer_ctx (struct GNUNET_CONTAINER_MultiPeerMap *peer_map, const struct GNUNET_PeerIdentity *peer)
{
  struct peer_context *ctx;

  if ( GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains( peer_map, peer ) )
  {
    ctx = GNUNET_CONTAINER_multipeermap_get(peer_map, peer);
  }
  else
  {
    ctx = GNUNET_new(struct peer_context);
    ctx->in_flags = 0;
    ctx->mq = NULL;
    ctx->to_channel = NULL;
    ctx->from_channel = NULL;
    GNUNET_CONTAINER_multipeermap_put( peer_map, peer, ctx, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
}

/**
 * Get the context of a peer. If not existing, create.
 */
  struct peer_context *
get_peer_ctx (struct GNUNET_CONTAINER_MultiPeerMap *peer_map, const struct GNUNET_PeerIdentity *peer)
{
  struct peer_context *ctx;

  touch_peer_ctx(peer_map, peer);
  ctx = GNUNET_CONTAINER_multipeermap_get(peer_map, peer);
  return ctx;
}

/**
 * Get the channel of a peer. If not existing, create.
 */
  void
touch_channel (struct GNUNET_CONTAINER_MultiPeerMap *peer_map, const struct GNUNET_PeerIdentity *peer)
{
  struct peer_context *ctx;

  ctx = get_peer_ctx (peer_map, peer);
  if (NULL == ctx->to_channel)
  {
    ctx->to_channel = GNUNET_CADET_channel_create(cadet_handle, NULL, peer,
                                                  GNUNET_RPS_CADET_PORT,
                                                  GNUNET_CADET_OPTION_RELIABLE);
    // do I have to explicitly put it in the peer_map?
    GNUNET_CONTAINER_multipeermap_put(peer_map, peer, ctx,
                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }
}

/**
 * Get the channel of a peer. If not existing, create.
 */
  struct GNUNET_CADET_Channel *
get_channel (struct GNUNET_CONTAINER_MultiPeerMap *peer_map, const struct GNUNET_PeerIdentity *peer)
{
  struct peer_context *ctx;

  ctx = get_peer_ctx (peer_map, peer);
  touch_channel(peer_map, peer);
  return ctx->to_channel;
}

/**
 * Make sure the mq for a given peer exists.
 *
 * If we already have a message queue open to this client,
 * simply return it, otherways create one.
 */
  void
touch_mq (struct GNUNET_CONTAINER_MultiPeerMap *peer_map, const struct GNUNET_PeerIdentity *peer_id)
{
  struct peer_context *ctx;

  ctx = get_peer_ctx(peer_map, peer_id);
  if (NULL == ctx->mq)
  {
    touch_channel(peer_map, peer_id);
    ctx->mq = GNUNET_CADET_mq_create(ctx->to_channel);
    //do I have to explicitly put it in the peer_map?
    GNUNET_CONTAINER_multipeermap_put(peer_map, peer_id, ctx,
                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }
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

  ctx = get_peer_ctx(peer_map, peer_id);
  touch_mq(peer_map, peer_id);

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
  estimate = GNUNET_NSE_log_estimate_to_n(logestimate);
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
  //unsigned int n_arr[sampler_list->size];// =
    //GNUNET_CRYPTO_random_permute(GNUNET_CRYPTO_QUALITY_STRONG, (unsigned int) sampler_list->size);
  //struct GNUNET_MQ_Handle *mq;
  struct client_ctx *cli_ctx;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_ReplyMessage *out_msg;
  uint64_t num_peers;
  //uint64_t i;

  // TODO
  msg = (struct GNUNET_RPS_CS_RequestMessage *) message;
  cli_ctx = GNUNET_SERVER_client_get_user_context(client, struct client_ctx);
  if ( NULL == cli_ctx ) {
    cli_ctx = GNUNET_new(struct client_ctx);
    cli_ctx->mq = GNUNET_MQ_queue_for_server_client(client);
    GNUNET_SERVER_client_set_user_context(client, cli_ctx);
  }
  
  // How many peers do we give back?
  // Wait until we have enough random peers?

  ev = GNUNET_MQ_msg_extra(out_msg,
                           GNUNET_ntohll(msg->num_peers) * sizeof(struct GNUNET_PeerIdentity),
                           GNUNET_MESSAGE_TYPE_RPS_CS_REPLY);
  out_msg->num_peers = msg->num_peers; // No conversion between network and host order

  num_peers = GNUNET_ntohll(msg->num_peers);
  //&out_msg[1] = SAMPLER_get_n_rand_peers(sampler_list, num_peers);
  memcpy(&out_msg[1],
      SAMPLER_get_n_rand_peers(sampler_list, num_peers),
      num_peers * sizeof(struct GNUNET_PeerIdentity));
  
  GNUNET_MQ_send(cli_ctx->mq, ev);
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
  
  peer = (struct GNUNET_PeerIdentity *) GNUNET_CADET_channel_get_info( channel, GNUNET_CADET_OPTION_PEER );
  
  /* Add the sending peer to the push_list */
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Adding peer to push_list of size %u\n", push_list_size);
  GNUNET_array_append(push_list, push_list_size, *peer);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Size of push_list is now %u\n", push_list_size);

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

  // find some way to keep one peer from spamming with pull requests?
  // allow only one request per time interval ?
  // otherwise remove from peerlist?

  peer = (struct GNUNET_PeerIdentity *) GNUNET_CADET_channel_get_info(channel, GNUNET_CADET_OPTION_PEER);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "PULL REQUEST from peer %s received\n", GNUNET_i2s(peer));

  //mq = GNUNET_CADET_mq_create(channel); // without mq?
  mq = get_mq(peer_map, peer);

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
  struct GNUNET_PeerIdentity *peers;
  uint64_t i;

  // TODO check that we sent a request and that it is the first reply

  in_msg = (struct GNUNET_RPS_P2P_PullReplyMessage *) msg;
  peers = (struct GNUNET_PeerIdentity *) &msg[1];
  for ( i = 0 ; i < GNUNET_ntohll(in_msg->num_peers) ; i++ )
  {
    GNUNET_array_append(pull_list, pull_list_size, peers[i]);
  }

  return GNUNET_OK;
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
  //unsigned int *n_arr;
  struct GNUNET_RPS_P2P_PushMessage        *push_msg;
  struct GNUNET_RPS_P2P_PullRequestMessage *pull_msg; // FIXME Send empty message
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_PeerIdentity *peer;

  // TODO print lists, ...
  // TODO cleanup peer_map


  /* If the NSE has changed adapt the lists accordingly */
  if ( sampler_list->size != est_size )
    SAMPLER_samplers_resize(sampler_list, est_size, own_identity);

  GNUNET_array_grow(gossip_list, gossip_list_size, est_size);


  /* Would it make sense to have one shuffeled gossip list and then
   * to send PUSHes to first alpha peers, PULL requests to next beta peers and
   * use the rest to update sampler?
   * in essence get random peers with consumption */

  /* Send PUSHes */
  //n_arr = GNUNET_CRYPTO_random_permute(GNUNET_CRYPTO_QUALITY_STRONG, (unsigned int) gossip_list_size);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Going to send pushes to %f (%f * %u) peers.\n",
      alpha * gossip_list_size, alpha, gossip_list_size);
  for ( i = 0 ; i < alpha * gossip_list_size ; i++ )
  { // TODO compute length
    peer = get_rand_peer(gossip_list, gossip_list_size);
    if (own_identity != peer)
    { // FIXME if this fails schedule/loop this for later
      LOG(GNUNET_ERROR_TYPE_DEBUG, "Sending PUSH to peer %s of gossiped list.\n", GNUNET_i2s(peer));

      ev = GNUNET_MQ_msg (push_msg, GNUNET_MESSAGE_TYPE_RPS_PP_PUSH);
      //ev = GNUNET_MQ_msg_extra();
      /* TODO Compute proof of work here
         push_msg; */
      push_msg->placeholder = 0;
      // FIXME sometimes it returns a pointer to a freed mq
      GNUNET_MQ_send (get_mq (peer_map, peer), ev);

      // modify in_flags of respective peer?
    }
  }


  /* Send PULL requests */
  //n_arr = GNUNET_CRYPTO_random_permute(GNUNET_CRYPTO_QUALITY_STRONG, (unsigned int) sampler_list->size);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Going to send pulls to %f (%f * %u) peers.\n",
      beta * gossip_list_size, beta, gossip_list_size);
  for ( i = 0 ; i < beta * gossip_list_size ; i++ )
  { // TODO compute length
    peer = get_rand_peer(gossip_list, gossip_list_size);
    if (own_identity != peer)
    { // FIXME if this fails schedule/loop this for later
      LOG(GNUNET_ERROR_TYPE_DEBUG, "Sending PULL request to peer %s of gossiped list.\n", GNUNET_i2s(peer));

      ev = GNUNET_MQ_msg(pull_msg, GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST);
      //ev = GNUNET_MQ_msg_extra();
      pull_msg->placeholder = 0;
      GNUNET_MQ_send( get_mq(peer_map, peer), ev );
      // modify in_flags of respective peer?
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

    first_border = round(alpha * gossip_list_size);
    for ( i = 0 ; i < first_border ; i++ )
    { // TODO use SAMPLER_get_n_rand_peers
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
      r_index = GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_STRONG,
                                       sampler_list->size);
      gossip_list[i] = sampler_list->peer_ids[r_index];
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
    SAMPLER_update_list(sampler_list, &push_list[i]);
    // TODO set in_flag?
  }

  for ( i = 0 ; i < pull_list_size ; i++ )
  {
    SAMPLER_update_list(sampler_list, &pull_list[i]);
    // TODO set in_flag?
  }


  /* Empty push/pull lists */
  GNUNET_array_grow(push_list, push_list_size, 0);
  push_list_size = 0; // I guess that's not necessary but doesn't hurt
  GNUNET_array_grow(pull_list, pull_list_size, 0);
  pull_list_size = 0; // I guess that's not necessary but doesn't hurt


  /* Schedule next round */
  do_round_task = GNUNET_SCHEDULER_add_delayed( round_interval, &do_round, NULL );
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Finished round\n");
}

/**
 * Open a connection to given peer and store channel and mq.
 */
  void
insertCB (void *cls, const struct GNUNET_PeerIdentity *id, struct GNUNET_HashCode hash)
{
  // We open a channel to be notified when this peer goes down.
  touch_channel(peer_map, id);
}

/**
 * Close the connection to given peer and delete channel and mq.
 */
  void
removeCB (void *cls, const struct GNUNET_PeerIdentity *id, struct GNUNET_HashCode hash)
{
  size_t s;
  struct peer_context *ctx;

  s = SAMPLER_count_id(sampler_list, id);
  if ( 1 >= s ) {
    if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains(peer_map, id))
    {
      ctx = GNUNET_CONTAINER_multipeermap_get(peer_map, id);
      if (NULL != ctx->to_channel)
      {
        if (NULL != ctx->mq)
        {
          GNUNET_MQ_destroy(ctx->mq);
        }
        GNUNET_CADET_channel_destroy(ctx->to_channel);
      }
      // TODO cleanup peer
      GNUNET_CONTAINER_multipeermap_remove_all(peer_map, id);
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
  if ( NULL != peer )
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Got peer %s (at %p) from CADET\n", GNUNET_i2s(peer), peer);
    SAMPLER_update_list(sampler_list, peer);
    touch_peer_ctx(peer_map, peer);

    uint64_t i;
    i = GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_STRONG, gossip_list_size);
    gossip_list[i] = *peer;
    // TODO send push/pull to each of those peers?
  }
  else
  {
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

  if ( NULL != do_round_task )
  {
    GNUNET_SCHEDULER_cancel (do_round_task);
    do_round_task = NULL;
  }

  GNUNET_NSE_disconnect(nse);
  GNUNET_CADET_disconnect(cadet_handle);
  GNUNET_free(own_identity);
  SAMPLER_samplers_destroy(sampler_list);
  GNUNET_array_grow(gossip_list, gossip_list_size, 0);
  GNUNET_array_grow(push_list, push_list_size, 0);
  GNUNET_array_grow(pull_list, pull_list_size, 0);
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
  LOG(GNUNET_ERROR_TYPE_DEBUG, "New channel was established to us.\n");

  GNUNET_assert( NULL != channel );

  // TODO we might not even store the from_channel

  if ( GNUNET_CONTAINER_multipeermap_contains( peer_map, initiator ) ) {
    ((struct peer_context *) GNUNET_CONTAINER_multipeermap_get( peer_map, initiator ))->from_channel = channel;
    // FIXME there might already be an established channel
  } else {
    struct peer_context *ctx;

    ctx = GNUNET_new(struct peer_context);
    ctx->in_flags = in_other_gossip_list;
    ctx->mq = NULL; // TODO create mq?
    ctx->from_channel = channel;

    GNUNET_CONTAINER_multipeermap_put (peer_map, initiator, ctx,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
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
  struct GNUNET_PeerIdentity *peer;
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Channel to remote peer was destroyed.\n");

  peer = (struct GNUNET_PeerIdentity *) GNUNET_CADET_channel_get_info (
      (struct GNUNET_CADET_Channel *) channel, GNUNET_CADET_OPTION_PEER);
       // Guess simply casting isn't the nicest way...
  SAMPLER_reinitialise_samplers_by_value(sampler_list, peer);
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
  GNUNET_log_setup("rps", GNUNET_error_type_to_string(GNUNET_ERROR_TYPE_DEBUG), NULL);

  LOG(GNUNET_ERROR_TYPE_DEBUG, "RPS started\n");

  cfg = c;


  own_identity = GNUNET_new(struct GNUNET_PeerIdentity); // needed?

  GNUNET_CRYPTO_get_peer_identity(cfg, own_identity); // TODO check return value

  GNUNET_assert(NULL != own_identity);

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

  //gossip_list_size = est_size; // TODO rename est_size

  gossip_list = NULL;

  GNUNET_array_grow(gossip_list, gossip_list_size, est_size);


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
    LOG(GNUNET_ERROR_TYPE_DEBUG, "No BETA specified in the config\n");
  }
  LOG(GNUNET_ERROR_TYPE_DEBUG, "BETA is %f\n", beta);

  // TODO check that alpha + beta < 1

  peer_map = GNUNET_CONTAINER_multipeermap_create(est_size, GNUNET_NO);


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


  /* Initialise sampler and gossip list */

  sampler_list = SAMPLER_samplers_init(est_size, own_identity, insertCB, NULL, removeCB, NULL);

  push_list = NULL;
  push_list_size = 0;
  pull_list = NULL;
  pull_list_size = 0;


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
