 /*
  This file is part of GNUnet
  Copyright (C) 2014, 2015, 2016 GNUnet e.V.

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
 * @file pq/pq_query_helper.c
 * @brief functions to initialize parameter arrays
 * @author Christian Grothoff
 */
#include "platform.h"
#include <gnunet/gnunet_util_lib.h>
#include "gnunet_pq_lib.h"


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_fixed (void *cls,
	     const void *data,
	     size_t data_len,
	     void *param_values[],
	     int param_lengths[],
	     int param_formats[],
	     unsigned int param_length,
	     void *scratch[],
	     unsigned int scratch_length)
{
  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  param_values[0] = (void *) data;
  param_lengths[0] = data_len;
  param_formats[0] = 1;
  return 0;
}


/**
 * Generate query parameter for a buffer @a ptr of
 * @a ptr_size bytes.
 *
 * @param ptr pointer to the query parameter to pass
 * @oaran ptr_size number of bytes in @a ptr
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_fixed_size (const void *ptr,
				  size_t ptr_size)
{
  struct GNUNET_PQ_QueryParam res =
    { &qconv_fixed, NULL, ptr, ptr_size, 1 };
  return res;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_uint16 (void *cls,
	      const void *data,
	      size_t data_len,
	      void *param_values[],
	      int param_lengths[],
	      int param_formats[],
	      unsigned int param_length,
	      void *scratch[],
	      unsigned int scratch_length)
{
  const uint16_t *u_hbo = data;
  uint16_t *u_nbo;

  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  u_nbo = GNUNET_new (uint16_t);
  scratch[0] = u_nbo;
  *u_nbo = htons (*u_hbo);
  param_values[0] = (void *) u_nbo;
  param_lengths[0] = sizeof (uint16_t);
  param_formats[0] = 1;
  return 1;
}


/**
 * Generate query parameter for an uint16_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_uint16 (const uint16_t *x)
{
  struct GNUNET_PQ_QueryParam res =
    { &qconv_uint16, NULL, x, sizeof (*x), 1 };
  return res;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_uint32 (void *cls,
	      const void *data,
	      size_t data_len,
	      void *param_values[],
	      int param_lengths[],
	      int param_formats[],
	      unsigned int param_length,
	      void *scratch[],
	      unsigned int scratch_length)
{
  const uint32_t *u_hbo = data;
  uint32_t *u_nbo;

  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  u_nbo = GNUNET_new (uint32_t);
  scratch[0] = u_nbo;
  *u_nbo = htonl (*u_hbo);
  param_values[0] = (void *) u_nbo;
  param_lengths[0] = sizeof (uint32_t);
  param_formats[0] = 1;
  return 1;
}


/**
 * Generate query parameter for an uint32_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_uint32 (const uint32_t *x)
{
  struct GNUNET_PQ_QueryParam res =
    { &qconv_uint32, NULL, x, sizeof (*x), 1 };
  return res;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_uint64 (void *cls,
	      const void *data,
	      size_t data_len,
	      void *param_values[],
	      int param_lengths[],
	      int param_formats[],
	      unsigned int param_length,
	      void *scratch[],
	      unsigned int scratch_length)
{
  const uint64_t *u_hbo = data;
  uint64_t *u_nbo;

  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  u_nbo = GNUNET_new (uint64_t);
  scratch[0] = u_nbo;
  *u_nbo = GNUNET_htonll (*u_hbo);
  param_values[0] = (void *) u_nbo;
  param_lengths[0] = sizeof (uint64_t);
  param_formats[0] = 1;
  return 1;
}


/**
 * Generate query parameter for an uint64_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_uint64 (const uint64_t *x)
{
  struct GNUNET_PQ_QueryParam res =
    { &qconv_uint64, NULL, x, sizeof (*x), 1 };
  return res;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int 
qconv_rsa_public_key (void *cls,
		      const void *data,
		      size_t data_len,
		      void *param_values[],
		      int param_lengths[],
		      int param_formats[],
		      unsigned int param_length,
		      void *scratch[],
		      unsigned int scratch_length)
{
  const struct GNUNET_CRYPTO_rsa_PublicKey *rsa = data;
  char *buf;
  size_t buf_size;

  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  buf_size = GNUNET_CRYPTO_rsa_public_key_encode (rsa,
						  &buf);
  scratch[0] = buf;
  param_values[0] = (void *) buf;
  param_lengths[0] = buf_size - 1; /* DB doesn't like the trailing \0 */
  param_formats[0] = 1;
  return 1;
}


/**
 * Generate query parameter for an RSA public key.  The
 * database must contain a BLOB type in the respective position.
 *
 * @param x the query parameter to pass
 * @return array entry for the query parameters to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_rsa_public_key (const struct GNUNET_CRYPTO_rsa_PublicKey *x)
{
  struct GNUNET_PQ_QueryParam res =
    { &qconv_rsa_public_key, NULL, (x), 0, 1 };
  return res;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_rsa_signature (void *cls,
		     const void *data,
		     size_t data_len,
		     void *param_values[],
		     int param_lengths[],
		     int param_formats[],
		     unsigned int param_length,
		     void *scratch[],
		     unsigned int scratch_length)
{
  const struct GNUNET_CRYPTO_rsa_Signature *sig = data;
  char *buf;
  size_t buf_size;

  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  buf_size = GNUNET_CRYPTO_rsa_signature_encode (sig,
						 &buf);
  scratch[0] = buf;
  param_values[0] = (void *) buf;
  param_lengths[0] = buf_size - 1; /* DB doesn't like the trailing \0 */
  param_formats[0] = 1;
  return 1;
}


/**
 * Generate query parameter for an RSA signature.  The
 * database must contain a BLOB type in the respective position.
 *
 * @param x the query parameter to pass
 * @return array entry for the query parameters to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_rsa_signature (const struct GNUNET_CRYPTO_rsa_Signature *x)
{
  struct GNUNET_PQ_QueryParam res =
    { &qconv_rsa_signature, NULL, (x), 0, 1 };
  return res;
}


/**
 * Generate query parameter for an absolute time value.
 * The database must store a 64-bit integer.
 *
 * @param x pointer to the query parameter to pass
 * @return array entry for the query parameters to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_absolute_time (const struct GNUNET_TIME_Absolute *x)
{
  return GNUNET_PQ_query_param_uint64 (&x->abs_value_us);
}


/**
 * Generate query parameter for an absolute time value.
 * The database must store a 64-bit integer.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_absolute_time_nbo(const struct GNUNET_TIME_AbsoluteNBO *x)
{
  return GNUNET_PQ_query_param_auto_from_type (&x->abs_value_us__);
}


/* end of pq_query_helper.c */
