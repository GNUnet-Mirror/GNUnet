
/*
  This file is part of GNUnet
  Copyright (C) 2017 GNUnet e.V.

  GNUnet is free software; you can redistribute it and/or modify it under the
  terms of the GNU General Public License as published by the Free Software
  Foundation; either version 3, or (at your option) any later version.

  GNUnet is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along with
  GNUnet; see the file COPYING.  If not, If not, see <http://www.gnu.org/licenses/>
*/
/**
 * @file sq/sq_result_helper.c
 * @brief helper functions for queries
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_sq_lib.h"


/**
 * Extract fixed-sized binary data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row row to extract data from
 * @param column column to extract data from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static int
extract_fixed_blob (void *cls,
                    sqlite3_stmt *result,
                    int row,
                    unsigned int column,
                    size_t *dst_size,
                    void *dst)
{
}


/**
 * Variable-size result expected.
 *
 * @param[out] dst where to store the result, allocated
 * @param[out] sptr where to store the size of @a dst
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_variable_size (void **dst,
				     size_t *sptr)
{
}


/**
 * Fixed-size result expected.
 *
 * @param[out] dst where to store the result
 * @param dst_size number of bytes in @a dst
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_fixed_size (void *dst,
				  size_t dst_size)
{
}


/**
 * 0-terminated string expected.
 *
 * @param[out] dst where to store the result, allocated
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_string (char **dst)
{
}


/**
 * RSA public key expected.
 *
 * @param[out] rsa where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_rsa_public_key (struct GNUNET_CRYPTO_RsaPublicKey **rsa)
{
}


/**
 * RSA signature expected.
 *
 * @param[out] sig where to store the result;
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_rsa_signature (struct GNUNET_CRYPTO_RsaSignature **sig)
{
}


/**
 * Absolute time expected.
 *
 * @param[out] at where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_absolute_time (struct GNUNET_TIME_Absolute *at)
{
}


/**
 * Absolute time expected.
 *
 * @param[out] at where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_absolute_time_nbo (struct GNUNET_TIME_AbsoluteNBO *at)
{
}


/**
 * uint16_t expected.
 *
 * @param[out] u16 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_uint16 (uint16_t *u16)
{
}


/**
 * uint32_t expected.
 *
 * @param[out] u32 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_uint32 (uint32_t *u32)
{
}


/**
 * uint64_t expected.
 *
 * @param[out] u64 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_uint64 (uint64_t *u64)
{
}


/* end of sq_result_helper.c */
