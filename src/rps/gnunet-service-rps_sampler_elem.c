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

#include "gnunet-service-rps_sampler_elem.h"

#include <inttypes.h>

#include "rps-test_util.h"

#define LOG(kind, ...) GNUNET_log_from(kind,"rps-sampler_elem",__VA_ARGS__)


/***********************************************************************
 * WARNING: This section needs to be reviewed regarding the use of
 * functions providing (pseudo)randomness!
***********************************************************************/


/**
 * Reinitialise a previously initialised sampler element.
 *
 * @param sampler_el The sampler element to (re-) initialise
 */
void
RPS_sampler_elem_reinit (struct RPS_SamplerElement *sampler_elem)
{
  sampler_elem->is_empty = EMPTY;

  // I guess I don't need to call GNUNET_CRYPTO_hmac_derive_key()...
  GNUNET_CRYPTO_random_block(GNUNET_CRYPTO_QUALITY_STRONG,
                             &(sampler_elem->auth_key.key),
                             GNUNET_CRYPTO_HASH_LENGTH);

  sampler_elem->last_client_request = GNUNET_TIME_UNIT_FOREVER_ABS;

  sampler_elem->birth = GNUNET_TIME_absolute_get ();
  sampler_elem->num_peers = 0;
  sampler_elem->num_change = 0;
}


/**
 * Create a sampler element and initialise it.
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
 * Destroy a sampler element.
 *
 * @param sampler_elem the element to destroy
 */
void
RPS_sampler_elem_destroy (struct RPS_SamplerElement *sampler_elem)
{
  GNUNET_free (sampler_elem);
}


/**
 * Update a sampler element with a PeerID
 *
 * @param sampler_elem The sampler element to update
 * @param new_ID The PeerID to update with
 */
void
RPS_sampler_elem_next (struct RPS_SamplerElement *sampler_elem,
                       const struct GNUNET_PeerIdentity *new_ID)
{
  struct GNUNET_HashCode other_hash;

  sampler_elem->num_peers++;

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (new_ID, &(sampler_elem->peer_id)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Have already PeerID %s\n",
        GNUNET_i2s (&(sampler_elem->peer_id)));
  }
  else
  {
    GNUNET_CRYPTO_hmac(&sampler_elem->auth_key,
        new_ID,
        sizeof(struct GNUNET_PeerIdentity),
        &other_hash);

    if (EMPTY == sampler_elem->is_empty)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Got PeerID %s; Simply accepting (was empty previously).\n",
           GNUNET_i2s(new_ID));
      sampler_elem->peer_id = *new_ID;
      sampler_elem->peer_id_hash = other_hash;

      sampler_elem->num_change++;
    }
    else if (0 > GNUNET_CRYPTO_hash_cmp (&other_hash, &sampler_elem->peer_id_hash))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Discarding old PeerID %s\n",
          GNUNET_i2s (&sampler_elem->peer_id));
      sampler_elem->peer_id = *new_ID;
      sampler_elem->peer_id_hash = other_hash;

      sampler_elem->num_change++;
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Keeping old PeerID %s\n",
          GNUNET_i2s (&sampler_elem->peer_id));
    }
  }
  sampler_elem->is_empty = NOT_EMPTY;
}

/**
 * Set the min-wise independent function of the given sampler element.
 *
 * @param sampler_elem the sampler element
 * @param auth_key the key to use
 */
void
RPS_sampler_elem_set (struct RPS_SamplerElement *sampler_elem,
                      struct GNUNET_CRYPTO_AuthKey auth_key)
{
  sampler_elem->auth_key = auth_key;
}

/* end of gnunet-service-rps.c */
