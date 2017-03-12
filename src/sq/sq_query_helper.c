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
#include "platform.h"
#include "gnunet_sq_lib.h"


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param stmt sqlite statement to bind parameters for
 * @param off offset of the argument to bind in @a stmt, numbered from 1,
 *            so immediately suitable for passing to `sqlite3_bind`-functions.
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
static int
bind_fixed_blob (void *cls,
                 const void *data,
                 size_t data_len,
                 sqlite3_stmt *stmt,
                 unsigned int off)
{
  if (SQLITE_OK !=
      sqlite3_bind_blob64 (stmt,
                           (int) off,
                           data,
                           (sqlite3_uint64) data_len,
                           SQLITE_TRANSIENT))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


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
  struct GNUNET_SQ_QueryParam qp = {
    .conv = &bind_fixed_blob,
    .data = ptr,
    .size = ptr_size,
    .num_params = 1
  };
  return qp;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param stmt sqlite statement to bind parameters for
 * @param off offset of the argument to bind in @a stmt, numbered from 1,
 *            so immediately suitable for passing to `sqlite3_bind`-functions.
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
static int
bind_string (void *cls,
             const void *data,
             size_t data_len,
             sqlite3_stmt *stmt,
             unsigned int off)
{
  if (SQLITE_OK !=
      sqlite3_bind_text (stmt,
                         (int) off,
                         (const char *) data,
                         -1,
                         SQLITE_TRANSIENT))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Generate query parameter for a string.
 *
 * @param ptr pointer to the string query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_string (const char *ptr)
{
  struct GNUNET_SQ_QueryParam qp = {
    .conv = &bind_string,
    .data = ptr,
    .num_params = 1
  };
  return qp;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param stmt sqlite statement to bind parameters for
 * @param off offset of the argument to bind in @a stmt, numbered from 1,
 *            so immediately suitable for passing to `sqlite3_bind`-functions.
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
static int
bind_rsa_pub (void *cls,
              const void *data,
              size_t data_len,
              sqlite3_stmt *stmt,
              unsigned int off)
{
  const struct GNUNET_CRYPTO_RsaPublicKey *rsa = data;
  char *buf;
  size_t buf_size;

  GNUNET_break (NULL == cls);
  buf_size = GNUNET_CRYPTO_rsa_public_key_encode (rsa,
						  &buf);
  if (SQLITE_OK !=
      sqlite3_bind_blob64 (stmt,
                           (int) off,
                           buf,
                           (sqlite3_uint64) buf_size,
                           SQLITE_TRANSIENT))
  {
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  GNUNET_free (buf);
  return GNUNET_OK;
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
 struct GNUNET_SQ_QueryParam qp = {
    .conv = &bind_rsa_pub,
    .data = x,
    .num_params = 1
  };
 return qp;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param stmt sqlite statement to bind parameters for
 * @param off offset of the argument to bind in @a stmt, numbered from 1,
 *            so immediately suitable for passing to `sqlite3_bind`-functions.
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
static int
bind_rsa_sig (void *cls,
              const void *data,
              size_t data_len,
              sqlite3_stmt *stmt,
              unsigned int off)
{
  const struct GNUNET_CRYPTO_RsaSignature *sig = data;
  char *buf;
  size_t buf_size;

  GNUNET_break (NULL == cls);
  buf_size = GNUNET_CRYPTO_rsa_signature_encode (sig,
						 &buf);
  if (SQLITE_OK !=
      sqlite3_bind_blob64 (stmt,
                           (int) off,
                           buf,
                           (sqlite3_uint64) buf_size,
                           SQLITE_TRANSIENT))
  {
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  GNUNET_free (buf);
  return GNUNET_OK;
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
 struct GNUNET_SQ_QueryParam qp = {
    .conv = &bind_rsa_sig,
    .data = x,
    .num_params = 1
  };
 return qp;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param stmt sqlite statement to bind parameters for
 * @param off offset of the argument to bind in @a stmt, numbered from 1,
 *            so immediately suitable for passing to `sqlite3_bind`-functions.
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
static int
bind_abstime (void *cls,
              const void *data,
              size_t data_len,
              sqlite3_stmt *stmt,
              unsigned int off)
{
  const struct GNUNET_TIME_Absolute *u = data;
  struct GNUNET_TIME_Absolute abs;

  abs = *u;
  if (abs.abs_value_us > INT64_MAX)
    abs.abs_value_us = INT64_MAX;
  GNUNET_assert (sizeof (uint64_t) == data_len);
  if (SQLITE_OK !=
      sqlite3_bind_int64 (stmt,
                          (int) off,
                          (sqlite3_int64) abs.abs_value_us))
    return GNUNET_SYSERR;
  return GNUNET_OK;
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
 struct GNUNET_SQ_QueryParam qp = {
    .conv = &bind_abstime,
    .data = x,
    .size = sizeof (struct GNUNET_TIME_Absolute),
    .num_params = 1
  };
  return qp;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param stmt sqlite statement to bind parameters for
 * @param off offset of the argument to bind in @a stmt, numbered from 1,
 *            so immediately suitable for passing to `sqlite3_bind`-functions.
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
static int
bind_nbotime (void *cls,
              const void *data,
              size_t data_len,
              sqlite3_stmt *stmt,
              unsigned int off)
{
  const struct GNUNET_TIME_AbsoluteNBO *u = data;
  struct GNUNET_TIME_Absolute abs;

  abs = GNUNET_TIME_absolute_ntoh (*u);
  if (abs.abs_value_us > INT64_MAX)
    abs.abs_value_us = INT64_MAX;
  GNUNET_assert (sizeof (uint64_t) == data_len);
  if (SQLITE_OK !=
      sqlite3_bind_int64 (stmt,
                          (int) off,
                          (sqlite3_int64) abs.abs_value_us))
    return GNUNET_SYSERR;
  return GNUNET_OK;
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
 struct GNUNET_SQ_QueryParam qp = {
    .conv = &bind_nbotime,
    .data = x,
    .size = sizeof (struct GNUNET_TIME_AbsoluteNBO),
    .num_params = 1
  };
  return qp;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param stmt sqlite statement to bind parameters for
 * @param off offset of the argument to bind in @a stmt, numbered from 1,
 *            so immediately suitable for passing to `sqlite3_bind`-functions.
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
static int
bind_u16 (void *cls,
          const void *data,
          size_t data_len,
          sqlite3_stmt *stmt,
          unsigned int off)
{
  const uint16_t *u = data;

  GNUNET_assert (sizeof (uint16_t) == data_len);
  if (SQLITE_OK !=
      sqlite3_bind_int (stmt,
                        (int) off,
                        (int) *u))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Generate query parameter for an uint16_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_uint16 (const uint16_t *x)
{
 struct GNUNET_SQ_QueryParam qp = {
    .conv = &bind_u16,
    .data = x,
    .size = sizeof (uint16_t),
    .num_params = 1
  };
  return qp;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param stmt sqlite statement to bind parameters for
 * @param off offset of the argument to bind in @a stmt, numbered from 1,
 *            so immediately suitable for passing to `sqlite3_bind`-functions.
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
static int
bind_u32 (void *cls,
          const void *data,
          size_t data_len,
          sqlite3_stmt *stmt,
          unsigned int off)
{
  const uint32_t *u = data;

  GNUNET_assert (sizeof (uint32_t) == data_len);
  if (SQLITE_OK !=
      sqlite3_bind_int64 (stmt,
                          (int) off,
                          (sqlite3_int64) *u))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

/**
 * Generate query parameter for an uint32_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_uint32 (const uint32_t *x)
{
 struct GNUNET_SQ_QueryParam qp = {
    .conv = &bind_u32,
    .data = x,
    .size = sizeof (uint32_t),
    .num_params = 1
  };
  return qp;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param stmt sqlite statement to bind parameters for
 * @param off offset of the argument to bind in @a stmt, numbered from 1,
 *            so immediately suitable for passing to `sqlite3_bind`-functions.
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
static int
bind_u64 (void *cls,
          const void *data,
          size_t data_len,
          sqlite3_stmt *stmt,
          unsigned int off)
{
  const uint64_t *u = data;

  GNUNET_assert (sizeof (uint64_t) == data_len);
  if (SQLITE_OK !=
      sqlite3_bind_int64 (stmt,
                          (int) off,
                          (sqlite3_int64) *u))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Generate query parameter for an uint16_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_uint64 (const uint64_t *x)
{
  struct GNUNET_SQ_QueryParam qp = {
    .conv = &bind_u64,
    .data = x,
    .size = sizeof (uint64_t),
    .num_params = 1
  };
  return qp;
}

/* end of sq_query_helper.c */
