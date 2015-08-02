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
 * @file rps/gnunet-service-rps_sampler.h
 * @brief sampler implementation
 * @author Julius Bünger
 */

#ifndef RPS_SAMPLER_H
#define RPS_SAMPLER_H
#include <inttypes.h>


/**
 * A sampler sampling a stream of PeerIDs.
 */
struct RPS_Sampler;

/**
 * A handle to cancel a request.
 */
struct RPS_SamplerRequestHandle;


/**
 * Callback that is called from _get_n_rand_peers() when the PeerIDs are ready.
 *
 * @param cls the closure given alongside this function.
 * @param ids the PeerIDs that were returned
 *        to be freed
 */
  typedef void
(*RPS_sampler_n_rand_peers_ready_cb) (void *cls,
    struct GNUNET_PeerIdentity *ids, uint32_t num_peers);


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
 * @param new_size the new size of the sampler (not 0)
 */
void
RPS_sampler_resize (struct RPS_Sampler *sampler, unsigned int new_size);


/**
 * Initialise a tuple of samplers.
 *
 * @param init_size the size the sampler is initialised with
 * @param max_round_interval maximum time a round takes
 * @return a handle to a sampler that consists of sampler elements.
 */
struct RPS_Sampler *
RPS_sampler_init (size_t init_size,
    struct GNUNET_TIME_Relative max_round_interval);


/**
 * Initialise a modified tuple of sampler elements.
 *
 * @param init_size the size the sampler is initialised with
 * @param max_round_interval maximum time a round takes
 * @return a handle to a sampler that consists of sampler elements.
 */
struct RPS_Sampler *
RPS_sampler_mod_init (size_t init_size,
                      struct GNUNET_TIME_Relative max_round_interval);


/**
 * A fuction to update every sampler in the given list
 *
 * @param sampler the sampler to update.
 * @param id the PeerID that is put in the sampler
 */
  void
RPS_sampler_update (struct RPS_Sampler *sampler,
                    const struct GNUNET_PeerIdentity *id);


/**
 * Reinitialise all previously initialised sampler elements with the given
 * value.
 *
 * Used to get rid of a PeerID.
 *
 * @param sampler the sampler to reinitialise a sampler in.
 * @param id the id of the samplers to update.
 */
  void
RPS_sampler_reinitialise_by_value (struct RPS_Sampler *sampler,
                                   const struct GNUNET_PeerIdentity *id);


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
                              void *cls, uint32_t num_peers);

/**
 * Cancle a request issued through #RPS_sampler_n_rand_peers_ready_cb.
 *
 * @param req_handle the handle to the request
 */
void
RPS_sampler_request_cancel (struct RPS_SamplerRequestHandle *req_handle);


/**
 * Counts how many Samplers currently hold a given PeerID.
 *
 * @param sampler the sampler to cound ids in.
 * @param id the PeerID to count.
 *
 * @return the number of occurrences of id.
 */
  uint32_t
RPS_sampler_count_id (struct RPS_Sampler *sampler,
                      const struct GNUNET_PeerIdentity *id);


/**
 * Cleans the samplers.
 *
 * @param sampler the sampler to destroy.
 */
  void
RPS_sampler_destroy (struct RPS_Sampler *sampler);

#endif
/* end of gnunet-service-rps.c */
