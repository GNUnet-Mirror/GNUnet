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
 * Callback that is called when a new PeerID is inserted into a sampler.
 *
 * @param cls the closure given alongside this function.
 * @param id the PeerID that is inserted
 */
typedef void
(*RPS_sampler_insert_cb) (void *cls,
    struct RPS_Sampler *sampler,
    const struct GNUNET_PeerIdentity *id);

/**
 * Callback that is called when a new PeerID is removed from a sampler.
 *
 * @param cls the closure given alongside this function.
 * @param id the PeerID that is removed
 */
typedef void
(*RPS_sampler_remove_cb) (void *cls,
    struct RPS_Sampler *sampler,
    const struct GNUNET_PeerIdentity *id);

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
 * @param id with which all newly created sampler elements are initialised
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
    struct GNUNET_TIME_Relative max_round_interval,
    RPS_sampler_insert_cb ins_cb, void *ins_cls,
    RPS_sampler_remove_cb rem_cb, void *rem_cls);


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
    void
RPS_sampler_get_n_rand_peers (struct RPS_Sampler *sampler,
                              RPS_sampler_n_rand_peers_ready_cb cb,
                              void *cls, uint32_t num_peers, int for_client);


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
