/*
     This file is part of GNUnet.
     Copyright (C)

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/

/**
 * @file rps/gnunet-service-rps_sampler.c
 * @brief sampler implementation
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "rps.h"

#include "rps-sampler_common.h"
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
 * @brief Callback called each time a new peer was put into the sampler
 *
 * @param cls A possibly given closure
 */
typedef void
(*SamplerNotifyUpdateCB) (void *cls);

/**
 * @brief Context for a callback. Contains callback and closure.
 *
 * Meant to be an entry in an DLL.
 */
struct SamplerNotifyUpdateCTX
{
  /**
   * @brief The Callback to call on updates
   */
  SamplerNotifyUpdateCB notify_cb;

  /**
   * @brief The according closure.
   */
  void *cls;

  /**
   * @brief Next element in DLL.
   */
  struct SamplerNotifyUpdateCTX *next;

  /**
   * @brief Previous element in DLL.
   */
  struct SamplerNotifyUpdateCTX *prev;
};


/**
 * Type of function used to differentiate between modified and not modified
 * Sampler.
 */
typedef void
(*RPS_get_peers_type) (void *cls);


/**
 * Get one random peer out of the sampled peers.
 *
 * We might want to reinitialise this sampler after giving the
 * corrsponding peer to the client.
 */
static void
sampler_mod_get_rand_peer (void *cls);


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

  /* Initialise context around extended sampler */
  min_size = 10; // TODO make input to _samplers_init()
  max_size = 1000; // TODO make input to _samplers_init()

  sampler = GNUNET_new (struct RPS_Sampler);
  sampler->max_round_interval = max_round_interval;
  sampler->get_peers = sampler_mod_get_rand_peer;
  //sampler->sampler_elements = GNUNET_new_array(init_size, struct GNUNET_PeerIdentity);
  //GNUNET_array_grow (sampler->sampler_elements, sampler->sampler_size, min_size);

  client_get_index = 0;

  //GNUNET_assert (init_size == sampler->sampler_size);

  RPS_sampler_resize (sampler, init_size);

  return sampler;
}


/**
 * @brief Compute the probability that we already observed all peers from a
 * biased stream of peer ids.
 *
 * Deficiency factor:
 * As introduced by Brahms: Factor between the number of unique ids in a
 * truly random stream and number of unique ids in the gossip stream.
 *
 * @param num_peers_estim The estimated number of peers in the network
 * @param num_peers_observed The number of peers the given element has observed
 * @param deficiency_factor A factor that catches the 'bias' of a random stream
 * of peer ids
 *
 * @return The estimated probability
 */
static double
prob_observed_n_peers (uint32_t num_peers_estim,
                       uint32_t num_peers_observed,
                       double deficiency_factor)
{
  uint32_t num_peers = num_peers_estim * (1/deficiency_factor);
  uint64_t sum = 0;

  for (uint32_t i = 0; i < num_peers; i++)
  {
    uint64_t a = pow (-1, num_peers-i);
    uint64_t b = binom (num_peers, i);
    uint64_t c = pow (i, num_peers_observed);
    sum += a * b * c;
  }

  return sum / (double) pow (num_peers, num_peers_observed);
}


/**
 * Get one random peer out of the sampled peers.
 *
 * This reinitialises the queried sampler element.
 */
static void
sampler_mod_get_rand_peer (void *cls)
{
  struct GetPeerCls *gpc = cls;
  struct RPS_SamplerElement *s_elem;
  struct GNUNET_TIME_Relative last_request_diff;
  struct RPS_Sampler *sampler;
  double prob_observed_n;

  gpc->get_peer_task = NULL;
  gpc->notify_ctx = NULL;
  sampler = gpc->req_handle->sampler;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Single peer was requested\n");

  /* Cycle the #client_get_index one step further */
  client_get_index = (client_get_index + 1) % sampler->sampler_size;

  s_elem = sampler->sampler_elements[client_get_index];
  *gpc->id = s_elem->peer_id;
  GNUNET_assert (NULL != s_elem);

  if (EMPTY == s_elem->is_empty)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Sampler_mod element empty, rescheduling.\n");
    GNUNET_assert (NULL == gpc->notify_ctx);
    gpc->notify_ctx =
      sampler_notify_on_update (sampler,
                                &sampler_mod_get_rand_peer,
                                gpc);
    return;
  }

  /* Check whether we may use this sampler to give it back to the client */
  if (GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us != s_elem->last_client_request.abs_value_us)
  {
    // TODO remove this condition at least for the client sampler
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
      GNUNET_assert (NULL == gpc->notify_ctx);
      gpc->notify_ctx =
        sampler_notify_on_update (sampler,
                                  &sampler_mod_get_rand_peer,
                                  gpc);
      return;
    }
  }
  if (2 > s_elem->num_peers)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "This s_elem saw less than two peers -- scheduling for later\n");
    GNUNET_assert (NULL == gpc->notify_ctx);
    gpc->notify_ctx =
      sampler_notify_on_update (sampler,
                                &sampler_mod_get_rand_peer,
                                gpc);
    return;
  }
  /* compute probability */
  prob_observed_n = prob_observed_n_peers (sampler->num_peers_estim,
                                           s_elem->num_peers,
                                           sampler->deficiency_factor);
  /* check if probability is above desired */
  if (prob_observed_n >= sampler->desired_probability)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Probability of having observed all peers (%d) too small ( < %d).\n",
        prob_observed_n,
        sampler->desired_probability);
    GNUNET_assert (NULL == gpc->notify_ctx);
    gpc->notify_ctx =
      sampler_notify_on_update (sampler,
                                &sampler_mod_get_rand_peer,
                                gpc);
    return;
  }
  /* More reasons to wait could be added here */

//  GNUNET_STATISTICS_set (stats,
//                         "# client sampler element input",
//                         s_elem->num_peers,
//                         GNUNET_NO);
//  GNUNET_STATISTICS_set (stats,
//                         "# client sampler element change",
//                         s_elem->num_change,
//                         GNUNET_NO);

  RPS_sampler_elem_reinit (s_elem);
  s_elem->last_client_request = GNUNET_TIME_absolute_get ();

  GNUNET_CONTAINER_DLL_remove (gpc->req_handle->gpc_head,
                               gpc->req_handle->gpc_tail,
                               gpc);
  gpc->cont (gpc->cont_cls, gpc->id);
  GNUNET_free (gpc);
}


/* end of gnunet-service-rps.c */

