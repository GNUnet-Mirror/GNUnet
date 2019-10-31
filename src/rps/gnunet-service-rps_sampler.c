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

#define LOG(kind, ...) GNUNET_log_from (kind, "rps-sampler", __VA_ARGS__)


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
 * Only used internally
 */
static void
sampler_get_rand_peer (void *cls);


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
// struct RPS_Sampler *sampler;


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
// static size_t extra_size;

/**
 * Inedex to the sampler element that is the next to be returned
 */
static uint32_t client_get_index;


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

  sampler->max_round_interval = max_round_interval;
  sampler->get_peers = sampler_get_rand_peer;
  // sampler->sampler_elements = GNUNET_new_array(init_size, struct GNUNET_PeerIdentity);
  // GNUNET_array_grow (sampler->sampler_elements, sampler->sampler_size, min_size);
  RPS_sampler_resize (sampler, init_size);

  client_get_index = 0;

  // GNUNET_assert (init_size == sampler->sampler_size);
  return sampler;
}


/**
 * Get one random peer out of the sampled peers.
 *
 * We might want to reinitialise this sampler after giving the
 * corrsponding peer to the client.
 * Only used internally
 */
static void
sampler_get_rand_peer (void *cls)
{
  struct GetPeerCls *gpc = cls;
  uint32_t r_index;
  struct RPS_Sampler *sampler;

  gpc->get_peer_task = NULL;
  gpc->notify_ctx = NULL;
  sampler = gpc->req_handle->sampler;

  /**;
   * Choose the r_index of the peer we want to return
   * at random from the interval of the gossip list
   */
  r_index = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
                                      sampler->sampler_size);

  if (EMPTY == sampler->sampler_elements[r_index]->is_empty)
  {
    // LOG (GNUNET_ERROR_TYPE_DEBUG,
    //     "Not returning randomly selected, empty PeerID. - Rescheduling.\n");

    gpc->notify_ctx =
      sampler_notify_on_update (sampler,
                                &sampler_get_rand_peer,
                                gpc);
    return;
  }

  GNUNET_CONTAINER_DLL_remove (gpc->req_handle->gpc_head,
                               gpc->req_handle->gpc_tail,
                               gpc);
  *gpc->id = sampler->sampler_elements[r_index]->peer_id;
  gpc->cont (gpc->cont_cls, gpc->id, 0,
             sampler->sampler_elements[r_index]->num_peers);

  GNUNET_free (gpc);
}


/* end of gnunet-service-rps.c */
