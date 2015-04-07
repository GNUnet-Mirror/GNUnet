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

#define LOG(kind, ...) GNUNET_log_from(kind,"rps-sampler",__VA_ARGS__)

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

  #ifdef TO_FILE
  /**
   * File name to log to
   */
  char *file_name;
  #endif /* TO_FILE */
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
(*RPS_sampler_rand_peer_ready_cont) (void *cls,
        const struct GNUNET_PeerIdentity *id);

/**
 * Closure for #sampler_get_rand_peer()
 */
struct GetPeerCls
{
  /**
   * DLL
   */
  struct GetPeerCls *next;

  /**
   * DLL
   */
  struct GetPeerCls *prev;

  /**
   * The sampler this function operates on.
   */
  struct RPS_Sampler *sampler;

  /**
   * The task for this function.
   */
  struct GNUNET_SCHEDULER_Task *get_peer_task;

  /**
   * The callback
   */
  RPS_sampler_rand_peer_ready_cont cont;

  /**
   * The closure to the callback @e cont
   */
  void *cont_cls;

  /**
   * The address of the id to be stored at
   */
  struct GNUNET_PeerIdentity *id;
};


///**
// * Global sampler variable.
// */
//struct RPS_Sampler *sampler;


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


#ifdef TO_FILE
/**
 * This function is used to facilitate writing important information to disk
 */
#define to_file(file_name, ...) do {char tmp_buf[512];\
  int size;\
  size = GNUNET_snprintf(tmp_buf,sizeof(tmp_buf),__VA_ARGS__);\
  if (0 > size)\
    LOG (GNUNET_ERROR_TYPE_WARNING,\
         "Failed to create tmp_buf\n");\
  else\
    to_file_(file_name,tmp_buf);\
} while (0);

static void
to_file_ (char *file_name, char *line)
{
  struct GNUNET_DISK_FileHandle *f;
  char output_buffer[512];
  //size_t size;
  int size;
  size_t size2;


  if (NULL == (f = GNUNET_DISK_file_open (file_name,
                                          GNUNET_DISK_OPEN_APPEND |
                                          GNUNET_DISK_OPEN_WRITE |
                                          GNUNET_DISK_OPEN_CREATE,
                                          GNUNET_DISK_PERM_USER_WRITE)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Not able to open file %s\n",
         file_name);
    return;
  }
  size = GNUNET_snprintf (output_buffer,
                          sizeof (output_buffer),
                          "%llu %s\n",
                          GNUNET_TIME_absolute_get ().abs_value_us,
                          line);
  if (0 > size)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Failed to write string to buffer (size: %i)\n",
         size);
    return;
  }

  size2 = GNUNET_DISK_file_write (f, output_buffer, size);
  if (size != size2)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Unable to write to file! (Size: %u, size2: %u)\n",
         size,
         size2);
    return;
  }

  if (GNUNET_YES != GNUNET_DISK_file_close (f))
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Unable to close file\n");
}
#endif /* TO_FILE */


/** FIXME document */
static struct GetPeerCls *gpc_head;
static struct GetPeerCls *gpc_tail;


/**
 * Callback to _get_rand_peer() used by _get_n_rand_peers().
 *
 * Checks whether all n peers are available. If they are,
 * give those back.
 */
static void
check_n_peers_ready (void *cls,
    const struct GNUNET_PeerIdentity *id)
{
  struct NRandPeersReadyCls *n_peers_cls = cls;

  n_peers_cls->cur_num_peers++;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Got %" PRIX32 ". of %" PRIX32 " peers\n",
      n_peers_cls->cur_num_peers, n_peers_cls->num_peers);

  if (n_peers_cls->num_peers == n_peers_cls->cur_num_peers)
  { /* All peers are ready -- return those to the client */
    GNUNET_assert (NULL != n_peers_cls->callback);

    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "returning %" PRIX32 " peers to the client\n",
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

  return s;
}


/**
 * Input an PeerID into the given sampler element.
 *
 * @param sampler the sampler the @a s_elem belongs to.
 *                Needed to know the
 */
static void
RPS_sampler_elem_next (struct RPS_SamplerElement *s_elem,
                       struct RPS_Sampler *sampler,
                       const struct GNUNET_PeerIdentity *other)
{
  struct GNUNET_HashCode other_hash;

  s_elem->num_peers++;

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (other, &(s_elem->peer_id)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "         Got PeerID %s\n",
        GNUNET_i2s (other));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Have already PeerID %s\n",
        GNUNET_i2s (&(s_elem->peer_id)));
  }
  else
  {
    GNUNET_CRYPTO_hmac(&s_elem->auth_key,
        other,
        sizeof(struct GNUNET_PeerIdentity),
        &other_hash);

    if (EMPTY == s_elem->is_empty)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Got PeerID %s; Simply accepting (was empty previously).\n",
           GNUNET_i2s(other));
      s_elem->peer_id = *other;
      s_elem->peer_id_hash = other_hash;

      s_elem->num_change++;
    }
    else if (0 > GNUNET_CRYPTO_hash_cmp (&other_hash, &s_elem->peer_id_hash))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "           Got PeerID %s\n",
          GNUNET_i2s (other));
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Discarding old PeerID %s\n",
          GNUNET_i2s (&s_elem->peer_id));
      s_elem->peer_id = *other;
      s_elem->peer_id_hash = other_hash;

      s_elem->num_change++;
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "        Got PeerID %s\n",
          GNUNET_i2s (other));
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Keeping old PeerID %s\n",
          GNUNET_i2s (&s_elem->peer_id));
    }
  }
  s_elem->is_empty = NOT_EMPTY;
}


/**
 * Get the size of the sampler.
 *
 * @param sampler the sampler to return the size of.
 * @return the size of the sampler
 */
unsigned int
RPS_sampler_get_size (struct RPS_Sampler *sampler)
{
  return sampler->sampler_size;
}


/**
 * Grow or shrink the size of the sampler.
 *
 * @param sampler the sampler to resize.
 * @param new_size the new size of the sampler
 */
static void
sampler_resize (struct RPS_Sampler *sampler, unsigned int new_size)
{
  unsigned int old_size;
  uint32_t i;

  // TODO check min and max size

  old_size = sampler->sampler_size;

  if (old_size > new_size)
  { /* Shrinking */
    /* Temporary store those to properly call the removeCB on those later */

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Shrinking sampler %d -> %d\n",
         old_size,
         new_size);
    #ifdef TO_FILE
    to_file (sampler->file_name,
         "Shrinking sampler %d -> %d\n",
         old_size,
         new_size);
    #endif /* TO_FILE */
    GNUNET_array_grow (sampler->sampler_elements,
        sampler->sampler_size,
        new_size);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "sampler->sampler_elements now points to %p\n",
        sampler->sampler_elements);

  }
  else if (old_size < new_size)
  { /* Growing */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Growing sampler %d -> %d\n",
         old_size,
         new_size);
    #ifdef TO_FILE
    to_file (sampler->file_name,
         "Growing sampler %d -> %d\n",
         old_size,
         new_size);
    #endif /* TO_FILE */
    GNUNET_array_grow (sampler->sampler_elements,
        sampler->sampler_size,
        new_size);

    for (i = old_size ; i < new_size ; i++)
    { /* Add new sampler elements */
      sampler->sampler_elements[i] = RPS_sampler_elem_create ();
      #ifdef TO_FILE
      to_file (sampler->file_name,
               "%" PRIu32 ": Initialised empty sampler element\n",
               i);
               //"New sampler with key %s\n",
               //GNUNET_h2s_full (sampler->sampler_elements[i]->auth_key));
      #endif /* TO_FILE */
    }
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Size remains the same -- nothing to do\n");
    return;
  }

  GNUNET_assert (sampler->sampler_size == new_size);
}


/**
 * Grow or shrink the size of the sampler.
 *
 * @param sampler the sampler to resize.
 * @param new_size the new size of the sampler
 */
void
RPS_sampler_resize (struct RPS_Sampler *sampler, unsigned int new_size)
{
  GNUNET_assert (0 < new_size);
  sampler_resize (sampler, new_size);
}


/**
 * Empty the sampler.
 *
 * @param sampler the sampler to empty.
 * @param new_size the new size of the sampler
 */
static void
sampler_empty (struct RPS_Sampler *sampler)
{
  sampler_resize (sampler, 0);
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
 * @return a handle to a sampler that consists of sampler elements.
 */
struct RPS_Sampler *
RPS_sampler_init (size_t init_size,
    struct GNUNET_TIME_Relative max_round_interval)
{
  struct RPS_Sampler *sampler;
  //uint32_t i;

  /* Initialise context around extended sampler */
  min_size = 10; // TODO make input to _samplers_init()
  max_size = 1000; // TODO make input to _samplers_init()

  sampler = GNUNET_new (struct RPS_Sampler);

  #ifdef TO_FILE
  if (NULL == (sampler->file_name = GNUNET_DISK_mktemp ("sampler-")))
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Could not create file\n");
  #endif /* TO_FILE */

  sampler->sampler_size = 0;
  sampler->sampler_elements = NULL;
  sampler->max_round_interval = max_round_interval;
  //sampler->sampler_elements = GNUNET_new_array(init_size, struct GNUNET_PeerIdentity);
  //GNUNET_array_grow (sampler->sampler_elements, sampler->sampler_size, min_size);
  RPS_sampler_resize (sampler, init_size);

  client_get_index = 0;

  //GNUNET_assert (init_size == sampler->sampler_size);
  return sampler;
}


/**
 * A fuction to update every sampler in the given list
 *
 * @param sampler the sampler to update.
 * @param id the PeerID that is put in the sampler
 */
  void
RPS_sampler_update (struct RPS_Sampler *sampler,
                    const struct GNUNET_PeerIdentity *id)
{
  uint32_t i;

  for (i = 0 ; i < sampler->sampler_size ; i++)
  {
    RPS_sampler_elem_next (sampler->sampler_elements[i],
                           sampler,
                           id);
    #ifdef TO_FILE
    to_file (sampler->file_name,
             "%" PRIu32 ": Now contains %s\n",
             i,
             GNUNET_i2s_full (&sampler->sampler_elements[i]->peer_id));
    #endif /* TO_FILE */
  }
}


/**
 * Reinitialise all previously initialised sampler elements with the given value.
 *
 * Used to get rid of a PeerID.
 *
 * @param sampler the sampler to reinitialise a sampler element in.
 * @param id the id of the sampler elements to update.
 */
  void
RPS_sampler_reinitialise_by_value (struct RPS_Sampler *sampler,
                                   const struct GNUNET_PeerIdentity *id)
{
  uint32_t i;

  for ( i = 0 ; i < sampler->sampler_size ; i++ )
  {
    if ( 0 == GNUNET_CRYPTO_cmp_peer_identity(id, &(sampler->sampler_elements[i]->peer_id)) )
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Reinitialising sampler\n");
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
static void
sampler_get_rand_peer2 (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GetPeerCls *gpc = cls;
  uint32_t r_index;

  gpc->get_peer_task = NULL;
  GNUNET_CONTAINER_DLL_remove (gpc_head, gpc_tail, gpc);
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  /**;
   * Choose the r_index of the peer we want to return
   * at random from the interval of the gossip list
   */
  r_index = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
      gpc->sampler->sampler_size);

  if ( EMPTY == gpc->sampler->sampler_elements[r_index]->is_empty )
  {
    gpc->get_peer_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply(
                                                                   GNUNET_TIME_UNIT_SECONDS,
                                                                   .1),
                                                       &sampler_get_rand_peer2,
                                                       cls);
    return;
  }

  *gpc->id = gpc->sampler->sampler_elements[r_index]->peer_id;

  gpc->cont (gpc->cont_cls, gpc->id);
  GNUNET_free (gpc);
}


/**
 * Get one random peer out of the sampled peers.
 *
 * We might want to reinitialise this sampler after giving the
 * corrsponding peer to the client.
 */
static void
sampler_get_rand_peer (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GetPeerCls *gpc = cls;
  struct GNUNET_PeerIdentity tmp_id;
  unsigned int empty_flag;
  struct RPS_SamplerElement *s_elem;
  struct GNUNET_TIME_Relative last_request_diff;
  uint32_t tmp_client_get_index;

  gpc->get_peer_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Single peer was requested\n");


  /* Store the next #client_get_index to check whether we cycled over the whole list */
  if (0 < client_get_index)
    tmp_client_get_index = client_get_index - 1;
  else
    tmp_client_get_index = gpc->sampler->sampler_size - 1;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "sched for later if index reaches %" PRIX32 " (sampler size: %" PRIX32 ").\n",
      tmp_client_get_index, gpc->sampler->sampler_size);

  do
  { /* Get first non empty sampler */
    if (tmp_client_get_index == client_get_index)
    { /* We once cycled over the whole list */
      LOG (GNUNET_ERROR_TYPE_DEBUG, "reached tmp_index %" PRIX32 ".\n",
           client_get_index);
      GNUNET_assert (NULL == gpc->get_peer_task);
      gpc->get_peer_task =
        GNUNET_SCHEDULER_add_delayed (gpc->sampler->max_round_interval,
                                      &sampler_get_rand_peer,
                                      cls);
      return;
    }

    tmp_id = gpc->sampler->sampler_elements[client_get_index]->peer_id;
    empty_flag = gpc->sampler->sampler_elements[client_get_index]->is_empty;
    RPS_sampler_elem_reinit (gpc->sampler->sampler_elements[client_get_index]);
    if (EMPTY != empty_flag)
      RPS_sampler_elem_next (gpc->sampler->sampler_elements[client_get_index],
                             gpc->sampler,
                             &tmp_id);

    /* Cycle the #client_get_index one step further */
    if ( client_get_index == gpc->sampler->sampler_size - 1 )
      client_get_index = 0;
    else
      client_get_index++;

    LOG (GNUNET_ERROR_TYPE_DEBUG, "incremented index to %" PRIX32 ".\n",
         client_get_index);
  } while (EMPTY == gpc->sampler->sampler_elements[client_get_index]->is_empty);

  s_elem = gpc->sampler->sampler_elements[client_get_index];
  *gpc->id = s_elem->peer_id;

  /* Check whether we may use this sampler to give it back to the client */
  if (GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us != s_elem->last_client_request.abs_value_us)
  {
    last_request_diff =
      GNUNET_TIME_absolute_get_difference (s_elem->last_client_request,
                                           GNUNET_TIME_absolute_get ());
    /* We're not going to give it back now if it was
     * already requested by a client this round */
    if (last_request_diff.rel_value_us < gpc->sampler->max_round_interval.rel_value_us)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "Last client request on this sampler was less than max round interval ago -- scheduling for later\n");
      ///* How many time remains untile the next round has started? */
      //inv_last_request_diff =
      //  GNUNET_TIME_absolute_get_difference (last_request_diff,
      //                                       sampler->max_round_interval);
      // add a little delay
      /* Schedule it one round later */
      GNUNET_assert (NULL == gpc->get_peer_task);
      gpc->get_peer_task =
        GNUNET_SCHEDULER_add_delayed (gpc->sampler->max_round_interval,
                                      &sampler_get_rand_peer,
                                      cls);
      return;
    }
    // TODO add other reasons to wait here
  }

  s_elem->last_client_request = GNUNET_TIME_absolute_get ();

  GNUNET_CONTAINER_DLL_remove (gpc_head, gpc_tail, gpc);
  gpc->cont (gpc->cont_cls, gpc->id);
  GNUNET_free (gpc);
}


/**
 * Get n random peers out of the sampled peers.
 *
 * We might want to reinitialise this sampler after giving the
 * corrsponding peer to the client.
 * Random with or without consumption?
 *
 * @param sampler the sampler to get peers from.
 * @param cb callback that will be called once the ids are ready.
 * @param cls closure given to @a cb
 * @param for_client #GNUNET_YES if result is used for client,
 *                   #GNUNET_NO if used internally
 * @param num_peers the number of peers requested
 */
  void
RPS_sampler_get_n_rand_peers (struct RPS_Sampler *sampler,
                              RPS_sampler_n_rand_peers_ready_cb cb,
                              void *cls, uint32_t num_peers, int for_client)
{
  GNUNET_assert (0 != sampler->sampler_size);

  // TODO check if we have too much (distinct) sampled peers
  uint32_t i;
  struct NRandPeersReadyCls *cb_cls;
  struct GetPeerCls *gpc;

  cb_cls = GNUNET_new (struct NRandPeersReadyCls);
  cb_cls->num_peers = num_peers;
  cb_cls->cur_num_peers = 0;
  cb_cls->ids = GNUNET_new_array (num_peers, struct GNUNET_PeerIdentity);
  cb_cls->callback = cb;
  cb_cls->cls = cls;

  #ifdef TO_FILE
  if (GNUNET_NO == for_client)
  {
    to_file (sampler->file_name,
             "This sampler is probably for Brahms itself\n");
  }
  #endif /* TO_FILE */

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Scheduling requests for %" PRIX32 " peers\n", num_peers);

  for (i = 0 ; i < num_peers ; i++)
  {
    gpc = GNUNET_new (struct GetPeerCls);
    gpc->sampler = sampler;
    gpc->cont = check_n_peers_ready;
    gpc->cont_cls = cb_cls;
    gpc->id = &cb_cls->ids[i];

    // maybe add a little delay
    if (GNUNET_YES == for_client)
      gpc->get_peer_task = GNUNET_SCHEDULER_add_now (&sampler_get_rand_peer, gpc);
    else if (GNUNET_NO == for_client)
      gpc->get_peer_task = GNUNET_SCHEDULER_add_now (&sampler_get_rand_peer2, gpc);
    else
      GNUNET_assert (0);

    GNUNET_CONTAINER_DLL_insert (gpc_head, gpc_tail, gpc);
  }
}


/**
 * Counts how many Samplers currently hold a given PeerID.
 *
 * @param sampler the sampler to count ids in.
 * @param id the PeerID to count.
 *
 * @return the number of occurrences of id.
 */
  uint32_t
RPS_sampler_count_id (struct RPS_Sampler *sampler,
                      const struct GNUNET_PeerIdentity *id)
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
 * Cleans the sampler.
 */
  void
RPS_sampler_destroy (struct RPS_Sampler *sampler)
{
  struct GetPeerCls *i;

  for (i = gpc_head; NULL != i; i = gpc_head)
  {
    GNUNET_CONTAINER_DLL_remove (gpc_head, gpc_tail, i);
    GNUNET_SCHEDULER_cancel (i->get_peer_task);
    GNUNET_free (i);
  }

  sampler_empty (sampler);
  GNUNET_free (sampler);
}

/* end of gnunet-service-rps.c */
