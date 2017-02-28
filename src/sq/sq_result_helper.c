
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
 * Extract variable-sized binary data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param column column to extract data from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result (actually a `void **`)
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static int
extract_var_blob (void *cls,
                  sqlite3_stmt *result,
                  unsigned int column,
                  size_t *dst_size,
                  void *dst)
{
  int have;
  const void *ret;
  void **rdst = (void **) dst;

  if (SQLITE_BLOB !=
      sqlite3_column_type (result,
                           column))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  /* sqlite manual says to invoke 'sqlite3_column_blob()'
     before calling sqlite3_column_bytes() */
  ret = sqlite3_column_blob (result,
                             column);
  have = sqlite3_column_bytes (result,
                               column);
  if (have < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  *dst_size = have;
  if (0 == have)
  {
    *rdst = NULL;
    return GNUNET_OK;
  }
  *rdst = GNUNET_malloc (have);
  GNUNET_memcpy (*rdst,
                 ret,
                 have);
  return GNUNET_OK;
}


/**
 * Cleanup memory allocated by #extract_var_blob().
 *
 * @param cls pointer to pointer of allocation
 */
static void
clean_var_blob (void *cls)
{
  void **dptr = (void **) cls;

  if (NULL != *dptr)
  {
    GNUNET_free (*dptr);
    *dptr = NULL;
  }
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
  struct GNUNET_SQ_ResultSpec rs = {
    .conv = &extract_var_blob,
    .cleaner = &clean_var_blob,
    .cls = dst,
    .result_size = sptr,
    .num_params = 1
  };

  return rs;
}


/**
 * Extract fixed-sized binary data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
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
                    unsigned int column,
                    size_t *dst_size,
                    void *dst)
{
  int have;
  const void *ret;

  if (SQLITE_BLOB !=
      sqlite3_column_type (result,
                           column))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  /* sqlite manual says to invoke 'sqlite3_column_blob()'
     before calling sqlite3_column_bytes() */
  ret = sqlite3_column_blob (result,
                             column);
  have = sqlite3_column_bytes (result,
                               column);
  if (*dst_size != have)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_memcpy (dst,
                 ret,
                 have);
  return GNUNET_OK;
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
  struct GNUNET_SQ_ResultSpec rs = {
    .conv = &extract_fixed_blob,
    .dst = dst,
    .dst_size = dst_size,
    .num_params = 1
  };

  return rs;
}


/**
 * Extract fixed-sized binary data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param column column to extract data from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static int
extract_utf8_string (void *cls,
                     sqlite3_stmt *result,
                     unsigned int column,
                     size_t *dst_size,
                     void *dst)
{
  const char *text;
  char **rdst = dst;

  if (SQLITE_TEXT !=
      sqlite3_column_type (result,
                           column))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  /* sqlite manual guarantees that 'sqlite3_column_text()'
     is 0-terminated */
  text = (const char *) sqlite3_column_text (result,
                                             column);
  if (NULL == text)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  *dst_size = strlen (text) + 1;
  *rdst = GNUNET_strdup (text);
  return GNUNET_OK;
}


/**
 * Cleanup memory allocated by #extract_var_blob().
 *
 * @param cls pointer to pointer of allocation
 */
static void
clean_utf8_string (void *cls)
{
  char **dptr = (char **) cls;

  if (NULL != *dptr)
  {
    GNUNET_free (*dptr);
    *dptr = NULL;
  }
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
  struct GNUNET_SQ_ResultSpec rs = {
    .conv = &extract_utf8_string,
    .cleaner = &clean_utf8_string,
    .cls = dst,
    .dst = dst,
    .num_params = 1
  };

  return rs;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param column column to extract data from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static int
extract_rsa_pub (void *cls,
                 sqlite3_stmt *result,
                 unsigned int column,
                 size_t *dst_size,
                 void *dst)
{
  struct GNUNET_CRYPTO_RsaPublicKey **pk = dst;
  int have;
  const void *ret;

  if (SQLITE_BLOB !=
      sqlite3_column_type (result,
                           column))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  /* sqlite manual says to invoke 'sqlite3_column_blob()'
     before calling sqlite3_column_bytes() */
  ret = sqlite3_column_blob (result,
                             column);
  have = sqlite3_column_bytes (result,
                               column);
  if (have < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  *pk = GNUNET_CRYPTO_rsa_public_key_decode (ret,
					     have);
  if (NULL == *pk)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_PQ_ResultConverter.
 *
 * @param cls closure
 */
static void
clean_rsa_pub (void *cls)
{
  struct GNUNET_CRYPTO_RsaPublicKey **pk = cls;

  if (NULL != *pk)
  {
    GNUNET_CRYPTO_rsa_public_key_free (*pk);
    *pk = NULL;
  }
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
  struct GNUNET_SQ_ResultSpec rs = {
    .conv = &extract_rsa_pub,
    .cleaner = &clean_rsa_pub,
    .dst = rsa,
    .cls = rsa,
    .num_params = 1
  };

  return rs;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param column column to extract data from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static int
extract_rsa_sig (void *cls,
                 sqlite3_stmt *result,
                 unsigned int column,
                 size_t *dst_size,
                 void *dst)
{
  struct GNUNET_CRYPTO_RsaSignature **sig = dst;
  int have;
  const void *ret;

  if (SQLITE_BLOB !=
      sqlite3_column_type (result,
                           column))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  /* sqlite manual says to invoke 'sqlite3_column_blob()'
     before calling sqlite3_column_bytes() */
  ret = sqlite3_column_blob (result,
                             column);
  have = sqlite3_column_bytes (result,
                               column);
  if (have < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  *sig = GNUNET_CRYPTO_rsa_signature_decode (ret,
					     have);
  if (NULL == *sig)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_PQ_ResultConverter.
 *
 * @param cls result data to clean up
 */
static void
clean_rsa_sig (void *cls)
{
  struct GNUNET_CRYPTO_RsaSignature **sig = cls;

  if (NULL != *sig)
  {
    GNUNET_CRYPTO_rsa_signature_free (*sig);
    *sig = NULL;
  }
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
  struct GNUNET_SQ_ResultSpec rs = {
    .conv = &extract_rsa_sig,
    .cleaner = &clean_rsa_sig,
    .dst = sig,
    .cls = sig,
    .num_params = 1
  };

  return rs;
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
  return GNUNET_SQ_result_spec_uint64 (&at->abs_value_us);
}


/**
 * Extract absolute time value in NBO from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param column column to extract data from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static int
extract_abs_time_nbo (void *cls,
                      sqlite3_stmt *result,
                      unsigned int column,
                      size_t *dst_size,
                      void *dst)
{
  struct GNUNET_TIME_AbsoluteNBO *u = dst;
  struct GNUNET_TIME_Absolute t;

  GNUNET_assert (sizeof (uint64_t) == *dst_size);
  if (SQLITE_INTEGER !=
      sqlite3_column_type (result,
                           column))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  t.abs_value_us = (uint64_t) sqlite3_column_int64 (result,
                                                    column);
  *u = GNUNET_TIME_absolute_hton (t);
  return GNUNET_OK;
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
  struct GNUNET_SQ_ResultSpec rs = {
    .conv = &extract_abs_time_nbo,
    .dst = at,
    .dst_size = sizeof (struct GNUNET_TIME_AbsoluteNBO),
    .num_params = 1
  };

  return rs;
}


/**
 * Extract 16-bit integer from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param column column to extract data from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static int
extract_uint16 (void *cls,
                sqlite3_stmt *result,
                unsigned int column,
                size_t *dst_size,
                void *dst)
{
  uint64_t v;
  uint32_t *u = dst;

  GNUNET_assert (sizeof (uint16_t) == *dst_size);
  if (SQLITE_INTEGER !=
      sqlite3_column_type (result,
                           column))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  v = (uint64_t) sqlite3_column_int64 (result,
                                       column);
  if (v > UINT16_MAX)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  *u = (uint16_t) v;
  return GNUNET_OK;
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
  struct GNUNET_SQ_ResultSpec rs = {
    .conv = &extract_uint16,
    .dst = u16,
    .dst_size = sizeof (uint16_t),
    .num_params = 1
  };

  return rs;
}


/**
 * Extract 32-bit integer from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param column column to extract data from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static int
extract_uint32 (void *cls,
                sqlite3_stmt *result,
                unsigned int column,
                size_t *dst_size,
                void *dst)
{
  uint64_t v;
  uint32_t *u = dst;

  GNUNET_assert (sizeof (uint32_t) == *dst_size);
  if (SQLITE_INTEGER !=
      sqlite3_column_type (result,
                           column))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  v = (uint64_t) sqlite3_column_int64 (result,
                                       column);
  if (v > UINT32_MAX)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  *u = (uint32_t) v;
  return GNUNET_OK;
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
  struct GNUNET_SQ_ResultSpec rs = {
    .conv = &extract_uint32,
    .dst = u32,
    .dst_size = sizeof (uint32_t),
    .num_params = 1
  };

  return rs;
}


/**
 * Extract 64-bit integer from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param column column to extract data from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static int
extract_uint64 (void *cls,
                sqlite3_stmt *result,
                unsigned int column,
                size_t *dst_size,
                void *dst)
{
  uint64_t *u = dst;

  GNUNET_assert (sizeof (uint64_t) == *dst_size);
  if (SQLITE_INTEGER !=
      sqlite3_column_type (result,
                           column))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  *u = (uint64_t) sqlite3_column_int64 (result,
                                        column);
  return GNUNET_OK;
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
  struct GNUNET_SQ_ResultSpec rs = {
    .conv = &extract_uint64,
    .dst = u64,
    .dst_size = sizeof (uint64_t),
    .num_params = 1
  };

  return rs;
}


/* end of sq_result_helper.c */
