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
 * @file rps/rps-sampler_common.h
 * @brief Code common to client and service sampler
 * @author Julius Bünger
 */

#ifndef RPS_SAMPLER_COMMON_H
#define RPS_SAMPLER_COMMON_H

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"

#include "gnunet-service-rps_sampler_elem.h"

#include <math.h>
#include <inttypes.h>

#include "rps-test_util.h"


/**
 * Callback that is called from _get_rand_peer() when the PeerID is ready.
 *
 * @param cls the closure given alongside this function.
 * @param id the PeerID that was returned
 * @param probability The probability with which this sampler has seen all ids
 * @param num_observed How many ids this sampler has observed
 */
typedef void
(*RPS_sampler_rand_peer_ready_cont) (void *cls,
                                     const struct GNUNET_PeerIdentity *id,
                                     double probability,
                                     uint32_t num_observed);


/**
 * Type of function used to differentiate between modified and not modified
 * Sampler.
 */
typedef void
(*RPS_get_peers_type) (void *cls);


/**
 * Callback that is called from _get_n_rand_peers() when the PeerIDs are ready.
 *
 * @param cls the closure given alongside this function.
 * @param ids the PeerIDs that were returned
 *        to be freed
 */
  typedef void
(*RPS_sampler_n_rand_peers_ready_cb) (const struct GNUNET_PeerIdentity *ids,
                                      uint32_t num_peers,
                                      void *cls);


/**
 * Callback that is called from _get_n_rand_peers() when the PeerIDs are ready.
 *
 * @param cls the closure given alongside this function.
 * @param probability Probability with which all IDs have been observed
 * @param num_observed Number of observed IDs
 * @param ids the PeerIDs that were returned
 *        to be freed
 */
  typedef void
(*RPS_sampler_sinlge_info_ready_cb) (const struct GNUNET_PeerIdentity *ids,
                                     void *cls,
                                     double probability,
                                     uint32_t num_observed);


/**
 * @brief Callback called each time a new peer was put into the sampler
 *
 * @param cls A possibly given closure
 */
typedef void
(*SamplerNotifyUpdateCB) (void *cls);


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
   * The #RPS_SamplerRequestHandleSingleInfo this single request belongs to.
   */
  struct RPS_SamplerRequestHandleSingleInfo *req_single_info_handle;

  /**
   * The task for this function.
   */
  struct GNUNET_SCHEDULER_Task *get_peer_task;

  /**
   * @brief Context to the given callback.
   */
  struct SamplerNotifyUpdateCTX *notify_ctx;

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
   * @brief The estimated total number of peers in the network
   */
  uint32_t num_peers_estim;

  /**
   * @brief The desired probability with which we want to have observed all
   * peers.
   */
  double desired_probability;

  /**
   * @brief A factor that catches the 'bias' of a random stream of peer ids.
   *
   * As introduced by Brahms: Factor between the number of unique ids in a
   * truly random stream and number of unique ids in the gossip stream.
   */
  double deficiency_factor;

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

  /**
   * Head and tail for the DLL to store the #RPS_SamplerRequestHandleSingleInfo
   */
  struct RPS_SamplerRequestHandleSingleInfo *req_handle_single_head;
  struct RPS_SamplerRequestHandleSingleInfo *req_handle_single_tail;

  struct SamplerNotifyUpdateCTX *notify_ctx_head;
  struct SamplerNotifyUpdateCTX *notify_ctx_tail;
};


/**
 * @brief Update the current estimate of the network size stored at the sampler
 *
 * Used for computing the condition when to return elements to the client
 *
 * @param sampler The sampler to update
 * @param num_peers The estimated value
 */
void
RPS_sampler_update_with_nw_size (struct RPS_Sampler *sampler,
                                 uint32_t num_peers);


/**
 * @brief Set the probability that is needed at least with what a sampler
 * element has to have observed all elements from the network.
 *
 * Only used/useful with the client sampler
 * (Maybe move to rps-sampler_client.{h|c} ?)
 *
 * @param sampler
 * @param desired_probability
 */
void
RPS_sampler_set_desired_probability (struct RPS_Sampler *sampler,
                                     double desired_probability);


/**
 * @brief Set the deficiency factor.
 *
 * Only used/useful with the client sampler
 * (Maybe move to rps-sampler_client.{h|c} ?)
 *
 * @param sampler
 * @param desired_probability
 */
void
RPS_sampler_set_deficiency_factor (struct RPS_Sampler *sampler,
                                   double deficiency_factor);


/**
 * @brief Add a callback that will be called when the next peer is inserted
 * into the sampler
 *
 * @param sampler The sampler on which update it will be called
 * @param notify_cb The callback
 * @param cls Closure given to the callback
 *
 * @return The context containing callback and closure
 */
struct SamplerNotifyUpdateCTX *
sampler_notify_on_update (struct RPS_Sampler *sampler,
                          SamplerNotifyUpdateCB notify_cb,
                          void *cls);


/**
 * Update every sampler element of this sampler with given peer
 *
 * @param sampler the sampler to update.
 * @param id the PeerID that is put in the sampler
 */
  void
RPS_sampler_update (struct RPS_Sampler *sampler,
                    const struct GNUNET_PeerIdentity *id);


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
                                   const struct GNUNET_PeerIdentity *id);


/**
 * Get the size of the sampler.
 *
 * @param sampler the sampler to return the size of.
 * @return the size of the sampler
 */
unsigned int
RPS_sampler_get_size (struct RPS_Sampler *sampler);


/**
 * Grow or shrink the size of the sampler.
 *
 * @param sampler the sampler to resize.
 * @param new_size the new size of the sampler
 */
void
RPS_sampler_resize (struct RPS_Sampler *sampler, unsigned int new_size);


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
                              uint32_t num_peers,
                              RPS_sampler_n_rand_peers_ready_cb cb,
                              void *cls);


/**
 * Get one random peer with additional information.
 *
 * @param sampler the sampler to get peers from.
 * @param cb callback that will be called once the ids are ready.
 * @param cls closure given to @a cb
 */
struct RPS_SamplerRequestHandleSingleInfo *
RPS_sampler_get_rand_peer_info (struct RPS_Sampler *sampler,
                                RPS_sampler_sinlge_info_ready_cb cb,
                                void *cls);


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
                      const struct GNUNET_PeerIdentity *id);


/**
 * Cancle a request issued through #RPS_sampler_n_rand_peers_ready_cb.
 *
 * @param req_handle the handle to the request
 */
void
RPS_sampler_request_cancel (struct RPS_SamplerRequestHandle *req_handle);


/**
 * Cancle a request issued through #RPS_sampler_n_rand_peers_ready_cb.
 *
 * @param req_handle the handle to the request
 */
void
RPS_sampler_request_single_info_cancel (
    struct RPS_SamplerRequestHandleSingleInfo *req_single_info_handle);


/**
 * Cleans the sampler.
 */
  void
RPS_sampler_destroy (struct RPS_Sampler *sampler);

#endif /* RPS_SAMPLER_COMMON_H */
/* end of rps-sampler_common.h */
