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
 * @file rps/gnunet-service-rps_sampler.c
 * @brief sampler implementation
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "rps.h"

#include "gnunet-service-rps_sampler.h"

#include <math.h>
#include <inttypes.h>

#define LOG(kind, ...) GNUNET_log(kind, __VA_ARGS__)

// multiple 'clients'?

// TODO check for overflows

// TODO align message structs

// hist_size_init, hist_size_max

/***********************************************************************
 * WARNING: This section needs to be reviewed regarding the use of
 * functions providing (pseudo)randomness!
***********************************************************************/

// TODO care about invalid input of the caller (size 0 or less...)

enum RPS_SamplerEmpty
{
  NOT_EMPTY = 0x0,
      EMPTY = 0x1
};

/**
 * A sampler element sampling one PeerID at a time.
 */
struct RPS_SamplerElement
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
  struct GNUNET_PeerIdentity peer_id;

  /**
   * The according hash value of this PeerID.
   */
  struct GNUNET_HashCode peer_id_hash;


  /**
   * Time of last request.
   */
  struct GNUNET_TIME_Absolute last_client_request;

  /**
   * Flag that indicates that we are not holding a valid PeerID right now.
   */
  enum RPS_SamplerEmpty is_empty;

  /**
   * 'Birth'
   */
  struct GNUNET_TIME_Absolute birth;

  /**
   * How many times a PeerID was put in this sampler.
   */
  uint32_t num_peers;

  /**
   * How many times this sampler changed the peer_id.
   */
  uint32_t num_change;
};

/**
 * Sampler with its own array of SamplerElements
 */
struct RPS_Sampler
{
  /**
   * Number of sampler elements we hold.
   */
  unsigned int sampler_size;
  //size_t size;

  /**
   * All Samplers in one array.
   */
  struct RPS_SamplerElement **sampler_elements;

  /**
   * Max time a round takes
   *
   * Used in the context of RPS
   */
  struct GNUNET_TIME_Relative max_round_interval;

  /**
   * Callback to be called when a peer gets inserted into a sampler.
   */
  RPS_sampler_insert_cb insert_cb;

  /**
   * Closure to the insert_cb.
   */
  void *insert_cls;

  /**
   * Callback to be called when a peer gets inserted into a sampler.
   */
  RPS_sampler_remove_cb remove_cb;

  /**
   * Closure to the remove_cb.
   */
  void *remove_cls;
};

/**
 * Closure to _get_n_rand_peers_ready_cb()
 */
struct NRandPeersReadyCls
{
  /**
   * Number of peers we are waiting for.
   */
  uint32_t num_peers;

  /**
   * Number of peers we currently have.
   */
  uint32_t cur_num_peers;

  /**
   * Pointer to the array holding the ids.
   */
  struct GNUNET_PeerIdentity *ids;

  /**
   * Callback to be called when all ids are available.
   */
  RPS_sampler_n_rand_peers_ready_cb callback;

  /**
   * Closure given to the callback
   */
  void *cls;
};

/**
 * Callback that is called from _get_rand_peer() when the PeerID is ready.
 *
 * @param cls the closure given alongside this function.
 * @param id the PeerID that was returned
 */
typedef void
(*RPS_sampler_rand_peer_ready_cb) (void *cls,
        const struct GNUNET_PeerIdentity *id);

/**
 * Closure to #RPS_sampler_get_rand_peer()
 */
struct GetPeerCls
{
  /**
   * The task for this function.
   */
  struct GNUNET_SCHEDULER_Task *get_peer_task;

  /**
   * The callback
   */
  RPS_sampler_rand_peer_ready_cb cb;

  /**
   * The closure to the callback
   */
  void *cb_cls;

  /**
   * The address of the id to be stored at
   */
  struct GNUNET_PeerIdentity *id;
};

/**
 * Multihashmap that keeps track of all get_peer_tasks that are still scheduled.
 */
struct GNUNET_CONTAINER_MultiHashMap *get_peer_tasks;


/**
 * Global sampler variable.
 */
struct RPS_Sampler *sampler;


/**
 * The minimal size for the extended sampler elements.
 */
static size_t min_size;

/**
 * The maximal size the extended sampler elements should grow to.
 */
static size_t max_size;

/**
 * The size the extended sampler elements currently have.
 */
//static size_t extra_size;

/**
 * Inedex to the sampler element that is the next to be returned
 */
static uint32_t client_get_index;


/**
 * Callback to _get_rand_peer() used by _get_n_rand_peers().
 *
 * Checks whether all n peers are available. If they are,
 * give those back.
 */
  void
check_n_peers_ready (void *cls,
    const struct GNUNET_PeerIdentity *id)
{
  struct NRandPeersReadyCls *n_peers_cls;

  n_peers_cls = (struct NRandPeersReadyCls *) cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "SAMPLER: Got %" PRIX32 ". of %" PRIX32 " peers\n",
      n_peers_cls->cur_num_peers, n_peers_cls->num_peers);

  if (n_peers_cls->num_peers - 1 == n_peers_cls->cur_num_peers)
  { /* All peers are ready -- return those to the client */
    GNUNET_assert (NULL != n_peers_cls->callback);

    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "SAMPLER: returning %" PRIX32 " peers to the client\n",
        n_peers_cls->num_peers);
    n_peers_cls->callback (n_peers_cls->cls, n_peers_cls->ids, n_peers_cls->num_peers);

    GNUNET_free (n_peers_cls);
  }
}


/**
 * Reinitialise a previously initialised sampler element.
 *
 * @param sampler pointer to the memory that keeps the value.
 */
  static void
RPS_sampler_elem_reinit (struct RPS_SamplerElement *sampler_el)
{
  sampler_el->is_empty = EMPTY;

  // I guess I don't need to call GNUNET_CRYPTO_hmac_derive_key()...
  GNUNET_CRYPTO_random_block(GNUNET_CRYPTO_QUALITY_STRONG,
                             &(sampler_el->auth_key.key),
                             GNUNET_CRYPTO_HASH_LENGTH);

  sampler_el->last_client_request = GNUNET_TIME_UNIT_FOREVER_ABS;

  sampler_el->birth = GNUNET_TIME_absolute_get ();
  sampler_el->num_peers = 0;
  sampler_el->num_change = 0;
}


/**
 * (Re)Initialise given Sampler with random min-wise independent function.
 *
 * In this implementation this means choosing an auth_key for later use in
 * a hmac at random.
 *
 * @return a newly created RPS_SamplerElement which currently holds no id.
 */
  struct RPS_SamplerElement *
RPS_sampler_elem_create (void)
{
  struct RPS_SamplerElement *s;

  s = GNUNET_new (struct RPS_SamplerElement);

  RPS_sampler_elem_reinit (s);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: initialised with empty PeerID\n");

  return s;
}


/**
 * Input an PeerID into the given sampler.
 */
  static void
RPS_sampler_elem_next (struct RPS_SamplerElement *s_elem, const struct GNUNET_PeerIdentity *other,
    RPS_sampler_insert_cb insert_cb, void *insert_cls,
    RPS_sampler_remove_cb remove_cb, void *remove_cls)
{
  struct GNUNET_HashCode other_hash;

  s_elem->num_peers++;

  if ( 0 == GNUNET_CRYPTO_cmp_peer_identity (other, &(s_elem->peer_id)) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER:          Got PeerID %s\n",
        GNUNET_i2s (other));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Have already PeerID %s\n",
        GNUNET_i2s (&(s_elem->peer_id)));
  }
  else
  {
    GNUNET_CRYPTO_hmac(&s_elem->auth_key,
        other,
        sizeof(struct GNUNET_PeerIdentity),
        &other_hash);

    if ( EMPTY == s_elem->is_empty )
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Got PeerID %s; Simply accepting (was empty previously).\n",
          GNUNET_i2s(other));
      s_elem->peer_id = *other;
      s_elem->peer_id_hash = other_hash;

      if (NULL != sampler->insert_cb)
        sampler->insert_cb (sampler->insert_cls, &(s_elem->peer_id));

      s_elem->num_change++;
    }
    else if ( 0 > GNUNET_CRYPTO_hash_cmp (&other_hash, &s_elem->peer_id_hash) )
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER:            Got PeerID %s\n",
          GNUNET_i2s (other));
      LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Discarding old PeerID %s\n",
          GNUNET_i2s (&s_elem->peer_id));

      if ( NULL != sampler->remove_cb )
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Removing old PeerID %s with the remove callback.\n",
            GNUNET_i2s (&s_elem->peer_id));
        sampler->remove_cb (sampler->remove_cls, &s_elem->peer_id);
      }

      s_elem->peer_id = *other;
      s_elem->peer_id_hash = other_hash;

      if ( NULL != sampler->insert_cb )
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Inserting new PeerID %s with the insert callback.\n",
            GNUNET_i2s (&s_elem->peer_id));
        sampler->insert_cb(sampler->insert_cls, &s_elem->peer_id);
      }

      s_elem->num_change++;
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER:         Got PeerID %s\n",
          GNUNET_i2s(other));
      LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Keeping old PeerID %s\n",
          GNUNET_i2s(&s_elem->peer_id));
    }
  }
  s_elem->is_empty = NOT_EMPTY;
}

/**
 * Get the size of the sampler.
 *
 * @return the size of the sampler
 */
unsigned int
RPS_sampler_get_size ()
{
  return sampler->sampler_size;
}


/**
 * Grow or shrink the size of the sampler.
 *
 * @param new_size the new size of the sampler
 */
  void
RPS_sampler_resize (unsigned int new_size)
{
  unsigned int old_size;
  uint32_t i;
  struct RPS_SamplerElement **rem_list;

  // TODO check min and max size

  old_size = sampler->sampler_size;

  if (old_size > new_size)
  { /* Shrinking */
    /* Temporary store those to properly call the removeCB on those later */
    rem_list = GNUNET_malloc ((old_size - new_size) * sizeof (struct RPS_SamplerElement *));
    memcpy (rem_list,
        &sampler->sampler_elements[new_size],
        (old_size - new_size) * sizeof (struct RPS_SamplerElement *));

    LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Shrinking sampler %d -> %d\n", old_size, new_size);
    GNUNET_array_grow (sampler->sampler_elements, sampler->sampler_size, new_size);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "SAMPLER: sampler->sampler_elements now points to %p\n",
        sampler->sampler_elements);

    for (i = 0 ; i < old_size - new_size ; i++)
    {/* Remove unneeded rest */
      LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Removing %" PRIX32 ". sampler\n", i);
      if (NULL != sampler->remove_cb)
        sampler->remove_cb (sampler->remove_cls, &rem_list[i]->peer_id);
      GNUNET_free (rem_list[i]);
    }
    GNUNET_free (rem_list);
  }
  else if (old_size < new_size)
  { /* Growing */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Growing sampler %d -> %d\n", old_size, new_size);
    GNUNET_array_grow (sampler->sampler_elements, sampler->sampler_size, new_size);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "SAMPLER: sampler->sampler_elements now points to %p\n",
        sampler->sampler_elements);

    for ( i = old_size ; i < new_size ; i++ )
    { /* Add new sampler elements */
      sampler->sampler_elements[i] = RPS_sampler_elem_create ();
      if (NULL != sampler->insert_cb)
        sampler->insert_cb (sampler->insert_cls, &sampler->sampler_elements[i]->peer_id);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "SAMPLER: Added %" PRIX32 ". sampler, now pointing to %p, contains %s\n",
          i, &sampler->sampler_elements[i], GNUNET_i2s (&sampler->sampler_elements[i]->peer_id));
    }
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Size remains the same -- nothing to do\n");
    return;
  }

  GNUNET_assert (sampler->sampler_size == new_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Finished growing/shrinking.\n"); // remove
}


/**
 * Initialise a tuple of sampler elements.
 *
 * @param init_size the size the sampler is initialised with
 * @param ins_cb the callback that will be called on every PeerID that is
 *               newly inserted into a sampler element
 * @param ins_cls the closure given to #ins_cb
 * @param rem_cb the callback that will be called on every PeerID that is
 *               removed from a sampler element
 * @param rem_cls the closure given to #rem_cb
 */
  void
RPS_sampler_init (size_t init_size,
    struct GNUNET_TIME_Relative max_round_interval,
    RPS_sampler_insert_cb ins_cb, void *ins_cls,
    RPS_sampler_remove_cb rem_cb, void *rem_cls)
{
  //struct RPS_Sampler *sampler;
  //uint32_t i;

  /* Initialise context around extended sampler */
  min_size = 10; // TODO make input to _samplers_init()
  max_size = 1000; // TODO make input to _samplers_init()

  sampler = GNUNET_new (struct RPS_Sampler);
  sampler->sampler_size = 0;
  sampler->sampler_elements = NULL;
  sampler->max_round_interval = max_round_interval;
  sampler->insert_cb = ins_cb;
  sampler->insert_cls = ins_cls;
  sampler->remove_cb = rem_cb;
  sampler->remove_cls = rem_cls;
  get_peer_tasks = GNUNET_CONTAINER_multihashmap_create (4, GNUNET_NO);
  //sampler->sampler_elements = GNUNET_new_array(init_size, struct GNUNET_PeerIdentity);
  //GNUNET_array_grow (sampler->sampler_elements, sampler->sampler_size, min_size);
  RPS_sampler_resize (init_size);

  client_get_index = 0;

  //GNUNET_assert (init_size == sampler->sampler_size);
}


/**
 * A fuction to update every sampler in the given list
 *
 * @param id the PeerID that is put in the sampler
 */
  void
RPS_sampler_update_list (const struct GNUNET_PeerIdentity *id)
{
  uint32_t i;

  for ( i = 0 ; i < sampler->sampler_size ; i++ )
    RPS_sampler_elem_next (sampler->sampler_elements[i], id,
        sampler->insert_cb, sampler->insert_cls,
        sampler->remove_cb, sampler->remove_cls);
}


/**
 * Reinitialise all previously initialised sampler elements with the given value.
 *
 * Used to get rid of a PeerID.
 *
 * @param id the id of the sampler elements to update.
 */
  void
RPS_sampler_reinitialise_by_value (const struct GNUNET_PeerIdentity *id)
{
  uint32_t i;

  for ( i = 0 ; i < sampler->sampler_size ; i++ )
  {
    if ( 0 == GNUNET_CRYPTO_cmp_peer_identity(id, &(sampler->sampler_elements[i]->peer_id)) )
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Reinitialising sampler\n");
      RPS_sampler_elem_reinit (sampler->sampler_elements[i]);
    }
  }
}


/**
 * Get one random peer out of the sampled peers.
 *
 * We might want to reinitialise this sampler after giving the
 * corrsponding peer to the client.
 * Only used internally
 */
  void
RPS_sampler_get_rand_peer_ (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GetPeerCls *gpc;
  uint32_t r_index;
  struct GNUNET_HashCode *hash;

  gpc = (struct GetPeerCls *) cls;

  /**;
   * Choose the r_index of the peer we want to return
   * at random from the interval of the gossip list
   */
  r_index = GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_STRONG,
      sampler->sampler_size);

  if ( EMPTY == sampler->sampler_elements[r_index]->is_empty )
  {
    gpc->get_peer_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply(
                                                                   GNUNET_TIME_UNIT_SECONDS,
                                                                   .1),
                                                       &RPS_sampler_get_rand_peer_,
                                                       cls);
    return;
  }

  *gpc->id = sampler->sampler_elements[r_index]->peer_id;

  hash = GNUNET_new (struct GNUNET_HashCode);
  GNUNET_CRYPTO_hash (&gpc->get_peer_task, sizeof (struct GNUNET_SCHEDULER_Task *), hash);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_remove (get_peer_tasks, hash, &gpc->get_peer_task))
      LOG (GNUNET_ERROR_TYPE_WARNING, "SAMPLER: Key to remove is not in the hashmap\n");
  GNUNET_free (gpc->get_peer_task);

  gpc->cb (gpc->cb_cls, gpc->id);
}


/**
 * Get one random peer out of the sampled peers.
 *
 * We might want to reinitialise this sampler after giving the
 * corrsponding peer to the client.
 *
 * @return a random PeerID of the PeerIDs previously put into the sampler.
 */
  void
RPS_sampler_get_rand_peer (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GetPeerCls *gpc;
  struct GNUNET_PeerIdentity tmp_id;
  struct RPS_SamplerElement *s_elem;
  struct GNUNET_TIME_Relative last_request_diff;
  struct GNUNET_HashCode *hash;
  uint32_t tmp_client_get_index;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Single peer was requested\n");

  gpc = (struct GetPeerCls *) cls;
  hash = GNUNET_new (struct GNUNET_HashCode);

  /* Store the next #client_get_index to check whether we cycled over the whole list */
  if (0 < client_get_index)
    tmp_client_get_index = client_get_index - 1;
  else
    tmp_client_get_index = sampler->sampler_size - 1;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "SAMPLER: scheduling for later if index reaches %" PRIX32 " (sampler size: %" PRIX32 ").\n",
      tmp_client_get_index, sampler->sampler_size);

  do
  { /* Get first non empty sampler */
    if (tmp_client_get_index == client_get_index)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: reached tmp_index %" PRIX32 ".\n", client_get_index);
      gpc->get_peer_task = GNUNET_SCHEDULER_add_delayed (sampler->max_round_interval,
                                                         &RPS_sampler_get_rand_peer,
                                                         cls);
      return;
    }

    tmp_id = sampler->sampler_elements[client_get_index]->peer_id;
    RPS_sampler_elem_reinit (sampler->sampler_elements[client_get_index]);
    RPS_sampler_elem_next (sampler->sampler_elements[client_get_index], &tmp_id,
                           NULL, NULL, NULL, NULL);

    /* Cycle the #client_get_index one step further */
    if ( client_get_index == sampler->sampler_size - 1 )
      client_get_index = 0;
    else
      client_get_index++;

    LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: incremented index to %" PRIX32 ".\n", client_get_index);
  } while (EMPTY == sampler->sampler_elements[client_get_index]->is_empty);

  s_elem = sampler->sampler_elements[client_get_index];
  *gpc->id = s_elem->peer_id;

  /* Check whether we may use this sampler to give it back to the client */
  if (GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us != s_elem->last_client_request.abs_value_us)
  {
    last_request_diff = GNUNET_TIME_absolute_get_difference (s_elem->last_client_request,
                                                             GNUNET_TIME_absolute_get ());
    /* We're not going to give it back now if it was already requested by a client this round */
    if (last_request_diff.rel_value_us < sampler->max_round_interval.rel_value_us)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "SAMPLER: Last client request on this sampler was less than max round interval ago -- scheduling for later\n");
      ///* How many time remains untile the next round has started? */
      //inv_last_request_diff = GNUNET_TIME_absolute_get_difference (last_request_diff,
      //                                                             sampler->max_round_interval);
      // add a little delay
      /* Schedule it one round later */
      gpc->get_peer_task = GNUNET_SCHEDULER_add_delayed (sampler->max_round_interval,
                                              &RPS_sampler_get_rand_peer,
                                              cls);
      return;
    }
    // TODO add other reasons to wait here
  }

  GNUNET_CRYPTO_hash (&gpc->get_peer_task, sizeof (struct GNUNET_SCHEDULER_Task *), hash);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_remove (get_peer_tasks, hash, &gpc->get_peer_task))
      LOG (GNUNET_ERROR_TYPE_WARNING, "SAMPLER: Key to remove is not in the hashmap\n");
  GNUNET_free (gpc->get_peer_task);

  s_elem->last_client_request = GNUNET_TIME_absolute_get ();

  gpc->cb (gpc->cb_cls, gpc->id);
}


/**
 * Get n random peers out of the sampled peers.
 *
 * We might want to reinitialise this sampler after giving the
 * corrsponding peer to the client.
 * Random with or without consumption?
 *
 * @param cb callback that will be called once the ids are ready.
 * @param cls closure given to @a cb
 * @param for_client #GNUNET_YES if result is used for client,
 *                   #GNUNET_NO if used internally
 * @param num_peers the number of peers requested
 */
  void
RPS_sampler_get_n_rand_peers (RPS_sampler_n_rand_peers_ready_cb cb,
    void *cls, uint32_t num_peers, int for_client)
{
  GNUNET_assert (GNUNET_YES == for_client ||
                 GNUNET_NO  == for_client);
  GNUNET_assert (0 != sampler->sampler_size);

  // TODO check if we have too much (distinct) sampled peers
  uint32_t i;
  struct NRandPeersReadyCls *cb_cls;
  struct GetPeerCls *gpc;
  struct GNUNET_HashCode *hash;

  hash = GNUNET_new (struct GNUNET_HashCode);

  cb_cls = GNUNET_new (struct NRandPeersReadyCls);
  cb_cls->num_peers = num_peers;
  cb_cls->cur_num_peers = 0;
  cb_cls->ids = GNUNET_new_array (num_peers, struct GNUNET_PeerIdentity);
  cb_cls->callback = cb;
  cb_cls->cls = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "SAMPLER: Scheduling requests for %" PRIX32 " peers\n", num_peers);

  for ( i = 0 ; i < num_peers ; i++ )
  {
    gpc = GNUNET_new (struct GetPeerCls);
    gpc->cb = check_n_peers_ready;
    gpc->cb_cls = cb_cls;
    gpc->id = &cb_cls->ids[i];

    // maybe add a little delay
    if (GNUNET_YES == for_client)
      gpc->get_peer_task = GNUNET_SCHEDULER_add_now (&RPS_sampler_get_rand_peer, gpc);
    else if (GNUNET_NO == for_client)
      gpc->get_peer_task = GNUNET_SCHEDULER_add_now (&RPS_sampler_get_rand_peer_, gpc);
    GNUNET_CRYPTO_hash (&gpc->get_peer_task, sizeof (struct GNUNET_SCHEDULER_Task *), hash);
    (void) GNUNET_CONTAINER_multihashmap_put (get_peer_tasks, hash, &gpc->get_peer_task,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  }
}


/**
 * Counts how many Samplers currently hold a given PeerID.
 *
 * @param id the PeerID to count.
 *
 * @return the number of occurrences of id.
 */
  uint32_t
RPS_sampler_count_id (const struct GNUNET_PeerIdentity *id)
{
  uint32_t count;
  uint32_t i;

  count = 0;
  for ( i = 0 ; i < sampler->sampler_size ; i++ )
  {
    if ( 0 == GNUNET_CRYPTO_cmp_peer_identity (&sampler->sampler_elements[i]->peer_id, id)
        && EMPTY != sampler->sampler_elements[i]->is_empty)
      count++;
  }
  return count;
}


/**
 * Callback to iterate over the hashmap to cancle the get_peer_tasks.
 */
  int
clear_get_peer_tasks (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_SCHEDULER_Task *task;

  task = (struct GNUNET_SCHEDULER_Task *) value;
  GNUNET_SCHEDULER_cancel (task);

  GNUNET_CONTAINER_multihashmap_remove (get_peer_tasks, key, value);

  return GNUNET_YES;
}


/**
 * Cleans the sampler.
 */
  void
RPS_sampler_destroy ()
{
  if (GNUNET_SYSERR == GNUNET_CONTAINER_multihashmap_iterate (get_peer_tasks,
                                                              clear_get_peer_tasks,
                                                              NULL))
    LOG (GNUNET_ERROR_TYPE_WARNING, "SAMPLER: iteration over hashmap was cancelled\n");
  GNUNET_CONTAINER_multihashmap_destroy (get_peer_tasks);
  RPS_sampler_resize (0);
  GNUNET_array_grow (sampler->sampler_elements, sampler->sampler_size, 0);
}

/* end of gnunet-service-rps.c */
