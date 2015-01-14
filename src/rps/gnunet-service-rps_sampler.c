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
  struct GNUNET_TIME_Absolute last_request;
  
  /**
   * Flag that indicates that we are not holding a valid PeerID right now.
   */
  enum RPS_SamplerEmpty is_empty;
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
   * Index to a sampler element.
   *
   * Gets cycled on every hist_request.
   */
  uint64_t sampler_elem_index;

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
static uint64_t client_get_index;


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

  sampler_el->last_request = GNUNET_TIME_UNIT_FOREVER_ABS;

  /* We might want to keep the previous peer */

  //GNUNET_CRYPTO_hmac(&sampler_el->auth_key, sampler_el->peer_id,
  //                   sizeof(struct GNUNET_PeerIdentity),
  //                   &sampler_el->peer_id_hash);
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

  if ( 0 == GNUNET_CRYPTO_cmp_peer_identity(other, &(s_elem->peer_id)) )
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER:          Got PeerID %s\n",
        GNUNET_i2s(other));
    LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Have already PeerID %s\n",
        GNUNET_i2s(&(s_elem->peer_id)));
  }
  else
  {
    GNUNET_CRYPTO_hmac(&s_elem->auth_key,
        other,
        sizeof(struct GNUNET_PeerIdentity),
        &other_hash);

    if ( EMPTY == s_elem->is_empty )
    { // Or whatever is a valid way to say
      // "we have no PeerID at the moment"
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Got PeerID %s; Simply accepting (was empty previously).\n",
          GNUNET_i2s(other));
      s_elem->peer_id = *other;
      //s_elem->peer_id = other;
      s_elem->peer_id_hash = other_hash;
      if (NULL != sampler->insert_cb)
      {
        sampler->insert_cb(sampler->insert_cls, &(s_elem->peer_id));
      }
    }
    else if ( 0 > GNUNET_CRYPTO_hash_cmp(&other_hash, &s_elem->peer_id_hash) )
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER:            Got PeerID %s\n",
          GNUNET_i2s(other));
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Discarding old PeerID %s\n",
          GNUNET_i2s(&s_elem->peer_id));

      if ( NULL != sampler->remove_cb )
      {
        LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Removing old PeerID %s with the remove callback.\n",
            GNUNET_i2s(&s_elem->peer_id));
        sampler->remove_cb(sampler->remove_cls, &s_elem->peer_id);
      }

      memcpy(&s_elem->peer_id, other, sizeof(struct GNUNET_PeerIdentity));
      //s_elem->peer_id = other;
      s_elem->peer_id_hash = other_hash;

      if ( NULL != sampler->insert_cb )
      {
        LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Inserting new PeerID %s with the insert callback.\n",
            GNUNET_i2s(&s_elem->peer_id));
        sampler->insert_cb(sampler->insert_cls, &s_elem->peer_id);
      }
    }
    else
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER:         Got PeerID %s\n",
          GNUNET_i2s(other));
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Keeping old PeerID %s\n",
          GNUNET_i2s(&s_elem->peer_id));
    }
  }
  s_elem->is_empty = NOT_EMPTY;
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
  uint64_t i;
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
      LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Removing %" PRIX64 ". sampler\n", i);
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
          "SAMPLER: Added %" PRIX64 ". sampler, now pointing to %p, contains %s\n",
          i, &sampler->sampler_elements[i], GNUNET_i2s (&sampler->sampler_elements[i]->peer_id));
    }
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Size remains the same -- nothing to do\n");
    return;
  }

  GNUNET_assert(sampler->sampler_size == new_size);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Finished growing/shrinking.\n"); // remove
}


/**
 * Initialise a tuple of sampler elements.
 *
 * @param init_size the size the sampler is initialised with
 * @param id with which all newly created sampler elements are initialised
 * @param ins_cb the callback that will be called on every PeerID that is 
 *               newly inserted into a sampler element
 * @param ins_cls the closure given to #ins_cb
 * @param rem_cb the callback that will be called on every PeerID that is
 *               removed from a sampler element
 * @param rem_cls the closure given to #rem_cb
 */
  void
RPS_sampler_init (size_t init_size, const struct GNUNET_PeerIdentity *id,
    RPS_sampler_insert_cb ins_cb, void *ins_cls,
    RPS_sampler_remove_cb rem_cb, void *rem_cls)
{
  //struct RPS_Sampler *sampler;
  //uint64_t i;

  /* Initialise context around extended sampler */
  min_size = 10; // TODO make input to _samplers_init()
  max_size = 1000; // TODO make input to _samplers_init()

  sampler = GNUNET_new (struct RPS_Sampler);
  sampler->sampler_size = 0;
  sampler->sampler_elements = NULL;
  sampler->insert_cb = ins_cb;
  sampler->insert_cls = ins_cls;
  sampler->remove_cb = rem_cb;
  sampler->remove_cls = rem_cls;
  //sampler->sampler_elements = GNUNET_new_array(init_size, struct GNUNET_PeerIdentity);
  //GNUNET_array_grow (sampler->sampler_elements, sampler->sampler_size, min_size);
  RPS_sampler_resize (init_size);
  RPS_sampler_update_list (id); // no super nice desing but ok for the moment

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
  uint64_t i;

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
  uint64_t i;

  for ( i = 0 ; i < sampler->sampler_size ; i++ )
  {
    if ( 0 == GNUNET_CRYPTO_cmp_peer_identity(id, &(sampler->sampler_elements[i]->peer_id)) )
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "SAMPLER: Reinitialising sampler\n");
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
  const struct GNUNET_PeerIdentity * 
RPS_sampler_get_rand_peer_ ()
{
  uint64_t r_index;
  const struct GNUNET_PeerIdentity *peer; // do we have to malloc that?

  // TODO implement extra logic

  /**;
   * Choose the r_index of the peer we want to return
   * at random from the interval of the gossip list
   */
  r_index = GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_STRONG,
      sampler->sampler_size);

  //if ( EMPTY == sampler->sampler_elements[r_index]->is_empty )
  //  // TODO schedule for later
  //  peer = NULL;
  //else
    peer = &(sampler->sampler_elements[r_index]->peer_id);
  sampler->sampler_elements[r_index]->last_request = GNUNET_TIME_absolute_get();
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Sgrp: Returning PeerID %s\n", GNUNET_i2s(peer));

  return peer;
}


/**
 * Get n random peers out of the sampled peers.
 *
 * We might want to reinitialise this sampler after giving the
 * corrsponding peer to the client.
 * Random with or without consumption?
 * Only used internally
 */
  const struct GNUNET_PeerIdentity *
RPS_sampler_get_n_rand_peers_ (uint64_t n)
{
  if ( 0 == sampler->sampler_size )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Sgrp: List empty - Returning NULL\n");
    return NULL;
  }
  else
  {
    // TODO check if we have too much (distinct) sampled peers
    // If we are not ready yet maybe schedule for later
    struct GNUNET_PeerIdentity *peers;
    uint64_t i;

    peers = GNUNET_malloc (n * sizeof(struct GNUNET_PeerIdentity));

    for ( i = 0 ; i < n ; i++ ) {
      //peers[i] = RPS_sampler_get_rand_peer_(sampler->sampler_elements);
      memcpy (&peers[i], RPS_sampler_get_rand_peer_ (), sizeof (struct GNUNET_PeerIdentity));
    }
    return peers;
  }
}


/**
 * Get one random peer out of the sampled peers.
 *
 * We might want to reinitialise this sampler after giving the
 * corrsponding peer to the client.
 *
 * @return a random PeerID of the PeerIDs previously put into the sampler.
 */
  const struct GNUNET_PeerIdentity * 
RPS_sampler_get_rand_peer ()
{
  struct GNUNET_PeerIdentity *peer;

  // use _get_rand_peer_ ?
  peer = GNUNET_new (struct GNUNET_PeerIdentity);
  *peer = sampler->sampler_elements[client_get_index]->peer_id;
  RPS_sampler_elem_reinit (sampler->sampler_elements[client_get_index]);
  if ( client_get_index == sampler->sampler_size )
    client_get_index = 0;
  else
    client_get_index++;
  return peer;
}


/**
 * Get n random peers out of the sampled peers.
 *
 * We might want to reinitialise this sampler after giving the
 * corrsponding peer to the client.
 * Random with or without consumption?
 *
 * @return n random PeerIDs of the PeerIDs previously put into the sampler.
 */
  const struct GNUNET_PeerIdentity *
RPS_sampler_get_n_rand_peers (uint64_t n)
{
  // use _get_rand_peers_ ?
  if ( 0 == sampler->sampler_size )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Sgrp: List empty - Returning NULL\n");
    return NULL;
  }
  else
  {
    // TODO check if we have too much (distinct) sampled peers
    // If we are not ready yet maybe schedule for later
    struct GNUNET_PeerIdentity *peers;
    const struct GNUNET_PeerIdentity *peer;
    uint64_t i;

    peers = GNUNET_malloc (n * sizeof (struct GNUNET_PeerIdentity));

    for ( i = 0 ; i < n ; i++ ) {
      //peers[i] = RPS_sampler_get_rand_peer_(sampler->sampler_elements);
      peer = RPS_sampler_get_rand_peer ();
      memcpy (&peers[i], peer, sizeof (struct GNUNET_PeerIdentity));
      //GNUNET_free (peer);
    }
    return peers;
  }
}


/**
 * Counts how many Samplers currently hold a given PeerID.
 *
 * @param id the PeerID to count.
 *
 * @return the number of occurrences of id.
 */
  uint64_t
RPS_sampler_count_id (const struct GNUNET_PeerIdentity *id)
{
  uint64_t count;
  uint64_t i;

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
 * Cleans the sampler.
 */
  void
RPS_sampler_destroy ()
{
  RPS_sampler_resize (0);
  GNUNET_array_grow (sampler->sampler_elements, sampler->sampler_size, 0);
}

/* end of gnunet-service-rps.c */
