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
 * @file sq/sq_query_helper.c
 * @brief helper functions for queries
 * @author Christian Grothoff
 */
#include "gnunet_sq_lib.h"


/**
 * Generate query parameter for a buffer @a ptr of
 * @a ptr_size bytes.
 *
 * @param ptr pointer to the query parameter to pass
 * @oaran ptr_size number of bytes in @a ptr
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_fixed_size (const void *ptr,
				  size_t ptr_size)
{
}


/**
 * Generate query parameter for a string.
 *
 * @param ptr pointer to the string query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_string (const char *ptr)
{
}


/**
 * Generate query parameter for an RSA public key.  The
 * database must contain a BLOB type in the respective position.
 *
 * @param x the query parameter to pass.
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_rsa_public_key (const struct GNUNET_CRYPTO_RsaPublicKey *x)
{
}


/**
 * Generate query parameter for an RSA signature.  The
 * database must contain a BLOB type in the respective position.
 *
 * @param x the query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_rsa_signature (const struct GNUNET_CRYPTO_RsaSignature *x)
{
}


/**
 * Generate query parameter for an absolute time value.
 * The database must store a 64-bit integer.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_absolute_time (const struct GNUNET_TIME_Absolute *x)
{
}


/**
 * Generate query parameter for an absolute time value.
 * The database must store a 64-bit integer.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_absolute_time_nbo (const struct GNUNET_TIME_AbsoluteNBO *x)
{
}


/**
 * Generate query parameter for an uint16_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_uint16 (const uint16_t *x)
{
}


/**
 * Generate query parameter for an uint32_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_uint32 (const uint32_t *x)
{
}


/**
 * Generate query parameter for an uint16_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_uint64 (const uint64_t *x)
{
}

/* end of sq_query_helper.c */
