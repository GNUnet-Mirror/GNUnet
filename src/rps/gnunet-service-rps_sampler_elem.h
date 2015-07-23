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
 * @file rps/gnunet-service-rps_sampler_elem.h
 * @brief sampler element implementation
 * @author Julius Bünger
 */

#ifndef RPS_SAMPLER_ELEM_H
#define RPS_SAMPLER_ELEM_H
#include <inttypes.h>


/***********************************************************************
 * WARNING: This section needs to be reviewed regarding the use of
 * functions providing (pseudo)randomness!
 ***********************************************************************/

/**
 * Used to indicate whether a sampler element is empty.
 */
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

  /**
   * The file name this sampler element should log to
   */
  char *file_name;
};


/**
 * Reinitialise a previously initialised sampler element.
 *
 * @param sampler pointer to the memory that keeps the value.
 */
void
RPS_sampler_elem_reinit (struct RPS_SamplerElement *sampler_el);


/**
 * (Re)Initialise given Sampler with random min-wise independent function.
 *
 * In this implementation this means choosing an auth_key for later use in
 * a hmac at random.
 *
 * @return a newly created RPS_SamplerElement which currently holds no id.
 */
struct RPS_SamplerElement *
RPS_sampler_elem_create (void);


/**
 * Input an PeerID into the given sampler element.
 *
 * @param sampler the sampler the @a s_elem belongs to.
 *                Needed to know the
 */
void
RPS_sampler_elem_next (struct RPS_SamplerElement *s_elem,
                       const struct GNUNET_PeerIdentity *new_ID);


#endif /* RPS_SAMPLER_ELEM_H */
/* end of gnunet-service-rps.c */
