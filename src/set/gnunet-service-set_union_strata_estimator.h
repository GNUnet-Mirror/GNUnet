/*
      This file is part of GNUnet
      Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file set/gnunet-service-set_union_strata_estimator.h
 * @brief estimator of set difference
 * @author Florian Dold
 */

#ifndef GNUNET_CONSENSUS_STRATA_ESTIMATOR_H
#define GNUNET_CONSENSUS_STRATA_ESTIMATOR_H

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * A handle to a strata estimator.
 */
struct StrataEstimator
{
  /**
   * The IBFs of this strata estimator.
   */
  struct InvertibleBloomFilter **strata;

  /**
   * Size of the IBF array in @e strata
   */
  unsigned int strata_count;

  /**
   * Size of each IBF stratum (in bytes)
   */
  unsigned int ibf_size;
};


/**
 * Write the given strata estimator to the buffer.
 *
 * @param se strata estimator to serialize
 * @param[out] buf buffer to write to, must be of appropriate size
 * @return number of bytes written to @a buf
 */
size_t
strata_estimator_write (const struct StrataEstimator *se,
                        void *buf);


/**
 * Read strata from the buffer into the given strata
 * estimator.  The strata estimator must already be allocated.
 *
 * @param buf buffer to read from
 * @param buf_len number of bytes in @a buf
 * @param is_compressed is the data compressed?
 * @param[out] se strata estimator to write to
 * @return #GNUNET_OK on success
 */
int
strata_estimator_read (const void *buf,
                       size_t buf_len,
                       int is_compressed,
                       struct StrataEstimator *se);


/**
 * Create a new strata estimator with the given parameters.
 *
 * @param strata_count number of stratas, that is, number of ibfs in the estimator
 * @param ibf_size size of each ibf stratum
 * @param ibf_hashnum hashnum parameter of each ibf
 * @return a freshly allocated, empty strata estimator, NULL on error
 */
struct StrataEstimator *
strata_estimator_create (unsigned int strata_count,
                         uint32_t ibf_size,
                         uint8_t ibf_hashnum);


/**
 * Get an estimation of the symmetric difference of the elements
 * contained in both strata estimators.
 *
 * @param se1 first strata estimator
 * @param se2 second strata estimator
 * @return abs(|se1| - |se2|)
 */
unsigned int
strata_estimator_difference (const struct StrataEstimator *se1,
                             const struct StrataEstimator *se2);


/**
 * Add a key to the strata estimator.
 *
 * @param se strata estimator to add the key to
 * @param key key to add
 */
void
strata_estimator_insert (struct StrataEstimator *se,
                         struct IBF_Key key);


/**
 * Remove a key from the strata estimator.
 *
 * @param se strata estimator to remove the key from
 * @param key key to remove
 */
void
strata_estimator_remove (struct StrataEstimator *se,
                         struct IBF_Key key);


/**
 * Destroy a strata estimator, free all of its resources.
 *
 * @param se strata estimator to destroy.
 */
void
strata_estimator_destroy (struct StrataEstimator *se);


/**
 * Make a copy of a strata estimator.
 *
 * @param se the strata estimator to copy
 * @return the copy
 */
struct StrataEstimator *
strata_estimator_dup (struct StrataEstimator *se);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
