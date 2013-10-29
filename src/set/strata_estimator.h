/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file set/strata_estimator.h
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


struct StrataEstimator
{
  struct InvertibleBloomFilter **strata;
  unsigned int strata_count;
  unsigned int ibf_size;
};


void
strata_estimator_write (const struct StrataEstimator *se, void *buf);


void
strata_estimator_read (const void *buf, struct StrataEstimator *se);


struct StrataEstimator *
strata_estimator_create (unsigned int strata_count, uint32_t ibf_size, uint8_t ibf_hashnum);


unsigned int
strata_estimator_difference (const struct StrataEstimator *se1,
                             const struct StrataEstimator *se2);


void
strata_estimator_insert (struct StrataEstimator *se, struct IBF_Key key);


void
strata_estimator_remove (struct StrataEstimator *se, struct IBF_Key key);


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

