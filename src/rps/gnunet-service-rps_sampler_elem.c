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

#include "gnunet-service-rps_sampler_elem.h"

#include <inttypes.h>

#include "rps-test_util.h"

#define LOG(kind, ...) GNUNET_log_from(kind,"rps-sampler_elem",__VA_ARGS__)


// TODO check for overflows

/***********************************************************************
 * WARNING: This section needs to be reviewed regarding the use of
 * functions providing (pseudo)randomness!
***********************************************************************/

// TODO care about invalid input of the caller (size 0 or less...)


/**
 * Reinitialise a previously initialised sampler element.
 *
 * @param sampler pointer to the memory that keeps the value.
 */
void
RPS_sampler_elem_reinit (struct RPS_SamplerElement *sampler_el)
{
  sampler_el->is_empty = EMPTY;

  // I guess I don't need to call GNUNET_CRYPTO_hmac_derive_key()...
  GNUNET_CRYPTO_random_block(GNUNET_CRYPTO_QUALITY_STRONG,
                             &(sampler_el->auth_key.key),
                             GNUNET_CRYPTO_HASH_LENGTH);

  #ifdef TO_FILE
  /* Create a file(-name) to store internals to */
  char *name_buf;
  name_buf = auth_key_to_string (sampler_el->auth_key);

  sampler_el->file_name = create_file (name_buf);
  GNUNET_free (name_buf);
  #endif /* TO_FILE */

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
void
RPS_sampler_elem_next (struct RPS_SamplerElement *s_elem,
                       const struct GNUNET_PeerIdentity *other)
{
  struct GNUNET_HashCode other_hash;

  s_elem->num_peers++;

  to_file (s_elem->file_name,
           "Got id %s",
           GNUNET_i2s_full (other));

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (other, &(s_elem->peer_id)))
  {
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
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Discarding old PeerID %s\n",
          GNUNET_i2s (&s_elem->peer_id));
      s_elem->peer_id = *other;
      s_elem->peer_id_hash = other_hash;

      s_elem->num_change++;
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Keeping old PeerID %s\n",
          GNUNET_i2s (&s_elem->peer_id));
    }
  }
  s_elem->is_empty = NOT_EMPTY;

  to_file (s_elem->file_name,
           "Now holding %s",
           GNUNET_i2s_full (&s_elem->peer_id));
}

/**
 * Initialise the min-wise independent function of the given sampler element.
 *
 * @param s_elem the sampler element
 * @param auth_key the key to use
 */
void
RPS_sampler_elem_set (struct RPS_SamplerElement *s_elem,
                      struct GNUNET_CRYPTO_AuthKey auth_key)
{
  s_elem->auth_key = auth_key;

  #ifdef TO_FILE
  /* Create a file(-name) to store internals to */
  char *name_buf;
  name_buf = auth_key_to_string (s_elem->auth_key);

  s_elem->file_name = create_file (name_buf);
  GNUNET_free (name_buf);
  #endif /* TO_FILE */
}

/* end of gnunet-service-rps.c */
