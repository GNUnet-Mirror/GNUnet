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
 * @file rps/gnunet-service-rps_sampler.c
 * @brief sampler implementation
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "rps.h"

#include "gnunet-service-rps_sampler.h"
#include "gnunet-service-rps_sampler_elem.h"

#include <math.h>
#include <inttypes.h>

#include "rps-test_util.h"

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
 * Closure for #sampler_mod_get_rand_peer() and #sampler_get_rand_peer
 */
struct GetPeerCls
{
  /**
   * DLL
   */
  struct GetPeerCls *next;
  struct GetPeerCls *prev;

  /**
   * The #RPS_SamplerRequestHandle this single request belongs to.
   */
  struct RPS_SamplerRequestHandle *req_handle;

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


/**
 * Type of function used to differentiate between modified and not modified
 * Sampler.
 */
typedef void
(*RPS_get_peers_type) (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Get one random peer out of the sampled peers.
 *
 * We might want to reinitialise this sampler after giving the
 * corrsponding peer to the client.
 * Only used internally
 */
static void
sampler_get_rand_peer (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Get one random peer out of the sampled peers.
 *
 * We might want to reinitialise this sampler after giving the
 * corrsponding peer to the client.
 */
static void
sampler_mod_get_rand_peer (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext *tc);


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
   * All sampler elements in one array.
   */
  struct RPS_SamplerElement **sampler_elements;

  /**
   * Maximum time a round takes
   *
   * Used in the context of RPS
   */
  struct GNUNET_TIME_Relative max_round_interval;

  /**
   * Stores the function to return peers. Which one it is depends on whether
   * the Sampler is the modified one or not.
   */
  RPS_get_peers_type get_peers;

  /**
   * Head and tail for the DLL to store the #RPS_SamplerRequestHandle
   */
  struct RPS_SamplerRequestHandle *req_handle_head;
  struct RPS_SamplerRequestHandle *req_handle_tail;

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
struct RPS_SamplerRequestHandle
{
  /**
   * DLL
   */
  struct RPS_SamplerRequestHandle *next;
  struct RPS_SamplerRequestHandle *prev;

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
   * Head and tail for the DLL to store the tasks for single requests
   */
  struct GetPeerCls *gpc_head;
  struct GetPeerCls *gpc_tail;

  /**
   * Sampler.
   */
  struct RPS_Sampler *sampler;

  /**
   * Callback to be called when all ids are available.
   */
  RPS_sampler_n_rand_peers_ready_cb callback;

  /**
   * Closure given to the callback
   */
  void *cls;
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
  struct RPS_SamplerRequestHandle *req_handle = cls;

  req_handle->cur_num_peers++;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Got %" PRIX32 ". of %" PRIX32 " peers\n",
      req_handle->cur_num_peers, req_handle->num_peers);

  if (req_handle->num_peers == req_handle->cur_num_peers)
  { /* All peers are ready -- return those to the client */
    GNUNET_assert (NULL != req_handle->callback);

    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "returning %" PRIX32 " peers to the client\n",
        req_handle->num_peers);
    req_handle->callback (req_handle->cls, req_handle->ids, req_handle->num_peers);

    RPS_sampler_request_cancel (req_handle);
  }
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

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Shrinking sampler %d -> %d\n",
         old_size,
         new_size);

    to_file (sampler->file_name,
         "Shrinking sampler %d -> %d",
         old_size,
         new_size);

    for (i = new_size ; i < old_size ; i++)
    {
      to_file (sampler->file_name,
               "-%" PRIu32 ": %s",
               i,
               sampler->sampler_elements[i]->file_name);
    }

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

    to_file (sampler->file_name,
         "Growing sampler %d -> %d",
         old_size,
         new_size);

    GNUNET_array_grow (sampler->sampler_elements,
        sampler->sampler_size,
        new_size);

    for (i = old_size ; i < new_size ; i++)
    { /* Add new sampler elements */
      sampler->sampler_elements[i] = RPS_sampler_elem_create ();

      to_file (sampler->file_name,
               "+%" PRIu32 ": %s",
               i,
               sampler->sampler_elements[i]->file_name);
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
 * @param max_round_interval maximum time a round takes
 * @return a handle to a sampler that consists of sampler elements.
 */
struct RPS_Sampler *
RPS_sampler_init (size_t init_size,
                  struct GNUNET_TIME_Relative max_round_interval)
{
  struct RPS_Sampler *sampler;

  /* Initialise context around extended sampler */
  min_size = 10; // TODO make input to _samplers_init()
  max_size = 1000; // TODO make input to _samplers_init()

  sampler = GNUNET_new (struct RPS_Sampler);

  #ifdef TO_FILE
  sampler->file_name = create_file ("sampler-");

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Initialised sampler %s\n",
       sampler->file_name);
  #endif /* TO_FILE */

  sampler->max_round_interval = max_round_interval;
  sampler->get_peers = sampler_get_rand_peer;
  //sampler->sampler_elements = GNUNET_new_array(init_size, struct GNUNET_PeerIdentity);
  //GNUNET_array_grow (sampler->sampler_elements, sampler->sampler_size, min_size);
  RPS_sampler_resize (sampler, init_size);

  client_get_index = 0;

  //GNUNET_assert (init_size == sampler->sampler_size);
  return sampler;
}

/**
 * Initialise a modified tuple of sampler elements.
 *
 * @param init_size the size the sampler is initialised with
 * @param max_round_interval maximum time a round takes
 * @return a handle to a sampler that consists of sampler elements.
 */
struct RPS_Sampler *
RPS_sampler_mod_init (size_t init_size,
                      struct GNUNET_TIME_Relative max_round_interval)
{
  struct RPS_Sampler *sampler;

  sampler = RPS_sampler_init (init_size, max_round_interval);
  sampler->get_peers = sampler_mod_get_rand_peer;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Initialised modified sampler %s\n",
       sampler->file_name);
  to_file (sampler->file_name,
           "This is a modified sampler");

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

  to_file (sampler->file_name,
           "Got %s",
           GNUNET_i2s_full (id));

  for (i = 0 ; i < sampler->sampler_size ; i++)
  {
    RPS_sampler_elem_next (sampler->sampler_elements[i],
                           id);
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
  struct RPS_SamplerElement *trash_entry;

  for ( i = 0 ; i < sampler->sampler_size ; i++ )
  {
    if ( 0 == GNUNET_CRYPTO_cmp_peer_identity(id, &(sampler->sampler_elements[i]->peer_id)) )
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Reinitialising sampler\n");
      trash_entry = GNUNET_new (struct RPS_SamplerElement);
      *trash_entry = *(sampler->sampler_elements[i]);
      to_file (trash_entry->file_name,
               "--- non-active");
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
sampler_get_rand_peer (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GetPeerCls *gpc = cls;
  uint32_t r_index;
  struct RPS_Sampler *sampler;

  gpc->get_peer_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  sampler = gpc->req_handle->sampler;

  /**;
   * Choose the r_index of the peer we want to return
   * at random from the interval of the gossip list
   */
  r_index = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
      sampler->sampler_size);

  if (EMPTY == sampler->sampler_elements[r_index]->is_empty)
  {
    //LOG (GNUNET_ERROR_TYPE_DEBUG,
    //     "Not returning randomly selected, empty PeerID. - Rescheduling.\n");

    /* FIXME no active wait - get notified, when new id arrives?
     * Might also be a freshly emptied one. Others might still contain ids.
     * Counter?
     */
    gpc->get_peer_task =
      GNUNET_SCHEDULER_add_delayed (
          GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1),
          &sampler_get_rand_peer,
          cls);
    return;
  }

  GNUNET_CONTAINER_DLL_remove (gpc->req_handle->gpc_head,
                               gpc->req_handle->gpc_tail,
                               gpc);
  *gpc->id = sampler->sampler_elements[r_index]->peer_id;
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
sampler_mod_get_rand_peer (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GetPeerCls *gpc = cls;
  struct RPS_SamplerElement *s_elem;
  struct GNUNET_TIME_Relative last_request_diff;
  struct RPS_Sampler *sampler;

  gpc->get_peer_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  sampler = gpc->req_handle->sampler;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Single peer was requested\n");

  /* Cycle the #client_get_index one step further */
  client_get_index = (client_get_index + 1) % sampler->sampler_size;

  s_elem = sampler->sampler_elements[client_get_index];
  *gpc->id = s_elem->peer_id;
  GNUNET_assert (NULL != s_elem);

  if (EMPTY == s_elem->is_empty)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Sampler_mod element empty, rescheduling.\n");
    GNUNET_assert (NULL == gpc->get_peer_task);
    gpc->get_peer_task =
      GNUNET_SCHEDULER_add_delayed (sampler->max_round_interval,
                                    &sampler_mod_get_rand_peer,
                                    cls);
    return;
  }

  /* Check whether we may use this sampler to give it back to the client */
  if (GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us != s_elem->last_client_request.abs_value_us)
  {
    last_request_diff =
      GNUNET_TIME_absolute_get_difference (s_elem->last_client_request,
                                           GNUNET_TIME_absolute_get ());
    /* We're not going to give it back now if it was
     * already requested by a client this round */
    if (last_request_diff.rel_value_us < sampler->max_round_interval.rel_value_us)
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
        GNUNET_SCHEDULER_add_delayed (sampler->max_round_interval,
                                      &sampler_mod_get_rand_peer,
                                      cls);
      return;
    }
    // TODO add other reasons to wait here
  }

  s_elem->last_client_request = GNUNET_TIME_absolute_get ();

  GNUNET_CONTAINER_DLL_remove (gpc->req_handle->gpc_head,
                               gpc->req_handle->gpc_tail,
                               gpc);
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
struct RPS_SamplerRequestHandle *
RPS_sampler_get_n_rand_peers (struct RPS_Sampler *sampler,
                              RPS_sampler_n_rand_peers_ready_cb cb,
                              void *cls, uint32_t num_peers)
{
  GNUNET_assert (0 != sampler->sampler_size);
  if (0 == num_peers)
    return NULL;

  // TODO check if we have too much (distinct) sampled peers
  uint32_t i;
  struct RPS_SamplerRequestHandle *req_handle;
  struct GetPeerCls *gpc;

  req_handle = GNUNET_new (struct RPS_SamplerRequestHandle);
  req_handle->num_peers = num_peers;
  req_handle->cur_num_peers = 0;
  req_handle->ids = GNUNET_new_array (num_peers, struct GNUNET_PeerIdentity);
  req_handle->sampler = sampler;
  req_handle->callback = cb;
  req_handle->cls = cls;
  GNUNET_CONTAINER_DLL_insert (sampler->req_handle_head,
                               sampler->req_handle_tail,
                               req_handle);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Scheduling requests for %" PRIu32 " peers\n", num_peers);

  for (i = 0 ; i < num_peers ; i++)
  {
    gpc = GNUNET_new (struct GetPeerCls);
    gpc->req_handle = req_handle;
    gpc->cont = check_n_peers_ready;
    gpc->cont_cls = req_handle;
    gpc->id = &req_handle->ids[i];

    GNUNET_CONTAINER_DLL_insert (req_handle->gpc_head,
                                 req_handle->gpc_tail,
                                 gpc);
    // maybe add a little delay
    gpc->get_peer_task = GNUNET_SCHEDULER_add_now (sampler->get_peers, gpc);
  }
  return req_handle;
}

/**
 * Cancle a request issued through #RPS_sampler_n_rand_peers_ready_cb.
 *
 * @param req_handle the handle to the request
 */
void
RPS_sampler_request_cancel (struct RPS_SamplerRequestHandle *req_handle)
{
  struct GetPeerCls *i;

  while (NULL != (i = req_handle->gpc_head) )
  {
    GNUNET_CONTAINER_DLL_remove (req_handle->gpc_head,
                                 req_handle->gpc_tail,
                                 i);
    if (NULL != i->get_peer_task)
      GNUNET_SCHEDULER_cancel (i->get_peer_task);
    GNUNET_free (i);
  }
  GNUNET_CONTAINER_DLL_remove (req_handle->sampler->req_handle_head,
                               req_handle->sampler->req_handle_tail,
                               req_handle);
  GNUNET_free (req_handle);
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
  if (NULL != sampler->req_handle_head)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "There are still pending requests. Going to remove them.\n");
    while (NULL != sampler->req_handle_head)
      RPS_sampler_request_cancel (sampler->req_handle_head);
  }
  sampler_empty (sampler);
  GNUNET_free (sampler);
}

/* end of gnunet-service-rps.c */
