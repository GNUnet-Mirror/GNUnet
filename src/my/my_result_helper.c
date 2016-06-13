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
 * @file my/my_result_helper.c
 * @brief functions to extract result values
 * @author Christophe Genevey
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_my_lib.h"


/**
 * extract data from a Mysql database @a result at row @a row
 *
 * @param cls closure
 * @param[in,out] rs
 * @param stmt the mysql statement that is being run
 * @param column the column that is being processed
 * @param[out] result mysql result
 * @return
 *   #GNUNET_OK if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid
 */
static int
pre_extract_varsize_blob (void *cls,
                          struct GNUNET_MY_ResultSpec *rs,
                          MYSQL_STMT *stmt,
                          unsigned int column,
                          MYSQL_BIND *results)
{
  results[0].buffer = NULL;
  results[0].buffer_length = 0;
  results[0].length = &rs->mysql_bind_output_length;

  return GNUNET_OK;
}


/**
 * extract data from a Mysql database @a result at row @a row
 *
 * @param cls closure
 * @param[in,out] rs
 * @param stmt the mysql statement that is being run
 * @param column the column that is being processed
 * @param[out] results
 * @return
 *   #GNUNET_OK if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid
 */
static int
post_extract_varsize_blob (void *cls,
                           struct GNUNET_MY_ResultSpec *rs,
                           MYSQL_STMT *stmt,
                           unsigned int column,
                           MYSQL_BIND *results)
{
  void *buf;
  size_t size;

  size = (size_t) rs->mysql_bind_output_length;

  if (rs->mysql_bind_output_length != size)
    return GNUNET_SYSERR; /* 'unsigned long' does not fit in size_t!? */

  buf = GNUNET_malloc (size);

  results[0].buffer = buf;
  results[0].buffer_length = size;
  results[0].buffer_type = MYSQL_TYPE_BLOB;

  if (0 !=
      mysql_stmt_fetch_column (stmt,
                               results,
                               column,
                               0))
  {
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }

  *(void **) rs->dst = buf;
  *rs->result_size = size;

  return GNUNET_OK;
}


/**
 * extract data from a Mysql database @a result at row @a row
 *
 * @param cls closure
 * @param[in,out] rs
 */
static void
cleanup_varsize_blob (void *cls,
                      struct GNUNET_MY_ResultSpec *rs)
{
  void **ptr = (void **)rs->dst;

  if (NULL != *ptr)
  {
    GNUNET_free (*ptr);
    *ptr = NULL;  
  }
}


/**
 * Variable-size result expected
 *
 * @param[out] dst where to store the result, allocated
 * @param[out] ptr_size where to store the size of @a dst
 * @return array entru for the result specification to use
 */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_variable_size (void **dst,
                                    size_t *ptr_size)
{
  struct GNUNET_MY_ResultSpec res =
  {
    .pre_conv = &pre_extract_varsize_blob,
    .post_conv = &post_extract_varsize_blob,
    .cleaner = &cleanup_varsize_blob,
    .dst =  (void *)(dst),
    .result_size = ptr_size,
    .num_fields = 1
  };

  return res;
}


/**
 * Extract data from a Mysql database @a result at row @a row
 *
 * @param cls closure
 * @param[in,out] rs
 * @param stmt the mysql statement that is being run
 * @param column the column that is being processed
 * @param[out] results
 * @return
 *  #GNUNET_OK if all results could be extracted
 *  #GNUNET_SYSERR if a result was invalid(non-existing field or NULL)
 */
static int
pre_extract_fixed_blob (void *cls,
                        struct GNUNET_MY_ResultSpec *rs,
                        MYSQL_STMT *stmt,
                        unsigned int column,
                        MYSQL_BIND *results)
{
  results[0].buffer = rs->dst;
  results[0].buffer_length = rs->dst_size;
  results[0].length = &rs->mysql_bind_output_length;
  results[0].buffer_type = MYSQL_TYPE_BLOB;

  return GNUNET_OK;
}


/**
 * Check size of extracted fixed size data from a Mysql database @a
 * result at row @a row
 *
 * @param cls closure
 * @param[in,out] rs
 * @param stmt the mysql statement that is being run
 * @param column the column that is being processed
 * @param[out] results
 * @return
 *  #GNUNET_OK if all results could be extracted
 *  #GNUNET_SYSERR if a result was invalid(non-existing field or NULL)
 */
static int
post_extract_fixed_blob (void *cls,
                         struct GNUNET_MY_ResultSpec *rs,
                         MYSQL_STMT *stmt,
                         unsigned int column,
                         MYSQL_BIND *results)
{
  if (rs->dst_size != rs->mysql_bind_output_length)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Fixed-size result expected.
 *
 * @param name name of the field in the table
 * @param[out] dst where to store the result
 * @param ptr_size number of bytes in @a dst
 * @return array entry for the result specification to use
 */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_fixed_size (void *ptr,
                                  size_t ptr_size)
{
  struct GNUNET_MY_ResultSpec res =
  {
    .pre_conv = &pre_extract_fixed_blob,
    .post_conv = &post_extract_fixed_blob,
    .cleaner = NULL,
    .dst = (void *)(ptr),
    .dst_size = ptr_size,
    .num_fields = 1
  };

  return res;
}


/**
  * Extract data from a Mysql database @a result at row @a row
  *
  * @param cls closure
  * @param[in,out] rs
  * @param stmt the mysql statement that is being run
  * @param column the column that is being processed
  * @param[out] results
  * @return
  *   #GNUNET_OK if all results could be extracted
  *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
  */
static int
pre_extract_rsa_public_key (void *cls,
                            struct GNUNET_MY_ResultSpec *rs,
                            MYSQL_STMT *stmt,
                            unsigned int column,
                            MYSQL_BIND *results)
{
  results[0].buffer = NULL;
  results[0].buffer_length = 0;
  results[0].length = &rs->mysql_bind_output_length;
  results[0].buffer_type = MYSQL_TYPE_BLOB;

  return GNUNET_OK;
}


/**
  * Check size of extracted fixed size data from a Mysql database @a
  * result at row @a row
  *
  * @param cls closure
  * @param[in,out] rs
  * @param stmt the mysql statement that is being run
  * @param column the column that is being processed
  * @param[out] results
  * @return
  *   #GNUNET_OK if all results could be extracted
  *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
  */
static int
post_extract_rsa_public_key  (void *cls,
                              struct GNUNET_MY_ResultSpec *rs,
                              MYSQL_STMT *stmt,
                              unsigned int column,
                              MYSQL_BIND *results)

{
  struct GNUNET_CRYPTO_RsaPublicKey **pk = rs->dst;
  void *buf;
  size_t size;

  size = (size_t) rs->mysql_bind_output_length;

  if (rs->mysql_bind_output_length != size)
    return GNUNET_SYSERR; /* 'unsigned long' does not fit in size_t!? */
  buf = GNUNET_malloc (size);

  results[0].buffer = buf;
  results[0].buffer_length = size;
  results[0].buffer_type = MYSQL_TYPE_BLOB;
  if (0 !=
      mysql_stmt_fetch_column (stmt,
                               results,
                               column,
                               0))
  {
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  
  *pk = GNUNET_CRYPTO_rsa_public_key_decode (buf,
                                             size);
  GNUNET_free (buf);
  if (NULL == *pk)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Results contains bogus public key value (fail to decode)\n");
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_MY_ResultConverter.
 *
 * @param cls closure
 * @param rs result data to clean up
 */
static void
clean_rsa_public_key (void *cls,
                      struct GNUNET_MY_ResultSpec *rs)
{
  struct GNUNET_CRYPTO_RsaPublicKey **pk = rs->dst;

  if (NULL != *pk)
  {
    GNUNET_CRYPTO_rsa_public_key_free (*pk);
    *pk = NULL;
  }
}


/**
  * RSA public key expected
  *
  * @param name name of the field in the table
  * @param[out] rsa where to store the result
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_rsa_public_key (struct GNUNET_CRYPTO_RsaPublicKey **rsa)
{
  struct GNUNET_MY_ResultSpec res = {
    .pre_conv = &pre_extract_rsa_public_key,
    .post_conv = &post_extract_rsa_public_key,
    .cleaner = &clean_rsa_public_key,
    .dst = (void *) rsa,
    .dst_size = 0,
    .num_fields = 1
  };

  return res;
}


/**
  * Extract data from a Mysql database @a result at row @a row.
  *
  * @param cls closure
  * @param[in,out] rs
  * @param stmt the mysql statement that is being run
  * @param column the column that is being processed
  * @param[out] results
  * @return
  *    #GNUNET_OK if all results could be extracted
  *    #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
  */
static int
pre_extract_rsa_signature (void *cls,
                      struct GNUNET_MY_ResultSpec *rs,
                      MYSQL_STMT *stmt,
                      unsigned int column,
                      MYSQL_BIND *results)
{
  results[0].buffer = 0;
  results[0].buffer_length = 0;
  results[0].length = &rs->mysql_bind_output_length;
  results[0].buffer_type = MYSQL_TYPE_BLOB;

  return GNUNET_OK;
}


/**
  * Extract data from a Mysql database @a result at row @a row.
  *
  * @param cls closure
  * @param[in,out] rs
  * @param stmt the mysql statement that is being run
  * @param column the column that is being processed
  * @param[out] results
  * @return
  *    #GNUNET_OK if all results could be extracted
  *    #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
  */
static int
post_extract_rsa_signature (void *cls,
                      struct GNUNET_MY_ResultSpec *rs,
                      MYSQL_STMT *stmt,
                      unsigned int column,
                      MYSQL_BIND *results)
{
  struct GNUNET_CRYPTO_RsaSignature **sig = rs->dst;
  void *buf;
  size_t size;

  size = (size_t) rs->mysql_bind_output_length;

  if (rs->mysql_bind_output_length != size)
    return GNUNET_SYSERR; /* 'unsigned long' does not fit in size_t!? */
  buf = GNUNET_malloc (size);

  results[0].buffer = buf;
  results[0].buffer_length = size;
  results[0].buffer_type = MYSQL_TYPE_BLOB;
  if (0 !=
      mysql_stmt_fetch_column (stmt,
                               results,
                               column,
                               0))
  {
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }

  *sig = GNUNET_CRYPTO_rsa_signature_decode (buf,
                                             size);
  GNUNET_free (buf);
  if (NULL == *sig)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Resuls contains bogus signature value (fails to decode)\n");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_MY_ResultConverter.
 *
 * @param cls closure
 * @param rd result data to clean up
 */
static void
clean_rsa_signature (void *cls,
          struct GNUNET_MY_ResultSpec *rs)
{
  struct GNUNET_CRYPTO_RsaSignature **sig = rs->dst;

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
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_rsa_signature (struct GNUNET_CRYPTO_RsaSignature **sig)
{
  struct GNUNET_MY_ResultSpec res =
  {
    .pre_conv = &pre_extract_rsa_signature,
    .post_conv = &post_extract_rsa_signature,
    .cleaner = &clean_rsa_signature,
    .dst = (void *)sig,
    .dst_size = 0,
    .num_fields = 1
  };
  return res;
}


/**
  * Extract data from a Mysql database @a result at row @a row
  *
  * @param cls closure
  * @param[in,out] rs
  * @param stmt the mysql statement that is being run
  * @param column the column that is being processed
  * @param[out] results
  * @return
  *    #GNUNET_OK if all results could be extracted
  *    #GNUNET_SYSERR if a result was invalid (non existing field or NULL)
  */
static int
pre_extract_string (void * cls,
                struct GNUNET_MY_ResultSpec *rs,
                MYSQL_STMT *stmt,
                unsigned int column,
                MYSQL_BIND *results)
{
  results[0].buffer = NULL;
  results[0].buffer_length = 0;
  results[0].length = &rs->mysql_bind_output_length;
  results[0].buffer_type = MYSQL_TYPE_BLOB;

  return GNUNET_OK;
}


/**
  * Check size of extracted fixed size data from a Mysql database @a
  *
  * @param cls closure
  * @param[in,out] rs
  * @param stmt the mysql statement that is being run
  * @param column the column that is being processed
  * @param[out] results
  * @return
  *    #GNUNET_OK if all results could be extracted
  *    #GNUNET_SYSERR if a result was invalid (non existing field or NULL)
  */
static int
post_extract_string (void * cls,
                struct GNUNET_MY_ResultSpec *rs,
                MYSQL_STMT *stmt,
                unsigned int column,
                MYSQL_BIND *results)
{
  size_t size;

  size = (size_t) rs->mysql_bind_output_length;
  char buf[size];

  if (rs->mysql_bind_output_length != size)
    return GNUNET_SYSERR;

  results[0].buffer = buf;
  results[0].buffer_length = size;
  results[0].buffer_type = MYSQL_TYPE_BLOB;

  if (0 !=
      mysql_stmt_fetch_column (stmt,
                               results,
                               column,
                               0))
  {
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }

  rs->dst = buf;

  return GNUNET_OK;
}


/**
 * 0- terminated string exprected.
 *
 * @param[out] dst where to store the result, allocated
 * @return array entry for the result specification to use
 */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_string (char **dst)
{
  struct GNUNET_MY_ResultSpec res = {
    .pre_conv = &pre_extract_string,
    .post_conv = &post_extract_string,
    .cleaner = NULL,
    .dst = (void *) dst,
    .dst_size = 0,
    .num_fields = 1
  };
  return res;
}


/**
 * Absolute time expected
 *
 * @param name name of the field in the table
 * @param[out] at where to store the result
 * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_absolute_time (struct GNUNET_TIME_Absolute *at)
{
  return GNUNET_MY_result_spec_uint64 (&at->abs_value_us);
}


/**
  * Absolute time in network byte order expected
  *
  * @param[out] at where to store the result
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_absolute_time_nbo (struct GNUNET_TIME_AbsoluteNBO *at)
{
  struct GNUNET_MY_ResultSpec res =
    GNUNET_MY_result_spec_auto_from_type (&at->abs_value_us__);
  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param[in,out] rs
 * @param stmt the mysql statement that is being run
 * @param column the column that is being processed
 * @param[out] results
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static int
pre_extract_uint16 (void *cls,
                struct GNUNET_MY_ResultSpec *rs,
                MYSQL_STMT *stmt,
                unsigned int column,
                MYSQL_BIND *results)
{
  results[0].buffer = (char *)rs->dst;
  results[0].buffer_length = rs->dst_size;
  results[0].length = &rs->mysql_bind_output_length;
  results[0].buffer_type = MYSQL_TYPE_SHORT;

  return GNUNET_OK;
}


/**
 * Check size of extracted fixed size data from a Mysql datbase.
 *
 * @param cls closure
 * @param[in,out] rs
 * @param stmt the mysql statement that is being run
 * @param column the column that is being processed
 * @param[out] results
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static int
post_extract_uint16 (void *cls,
                struct GNUNET_MY_ResultSpec *rs,
                MYSQL_STMT *stmt,
                unsigned int column,
                MYSQL_BIND *results)
{
  if (rs->dst_size != rs->mysql_bind_output_length)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * uint16_t expected
 *
 * @param[out] u16 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_uint16 (uint16_t *u16)
{
  struct GNUNET_MY_ResultSpec res = {
    .pre_conv = &pre_extract_uint16,
    .post_conv = &post_extract_uint16,
    .cleaner = NULL,
    .dst = (void *) u16,
    .dst_size = sizeof (*u16),
    .num_fields = 1
  };
  return res;
}


/**
  * Extrac data from a  MYSQL database @a result at row @a row
  *
  * @param cls closure
  * @param cls closure
  * @param[in,out] rs
  * @param stmt the mysql statement that is being run
  * @param column the column that is being processed
  * @param[out] results
  * @return
  *      #GNUNET_OK if all results could be extracted
  *      #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
  */
static int
pre_extract_uint32 (void *cls,
                struct GNUNET_MY_ResultSpec *rs,
                MYSQL_STMT *stmt,
                unsigned int column,
                MYSQL_BIND *results)
{
  results[0].buffer = (int *)rs->dst;
  results[0].buffer_length = rs->dst_size;
  results[0].length = &rs->mysql_bind_output_length;
  results[0].buffer_type = MYSQL_TYPE_LONG;

  return GNUNET_OK;
}


/**
  * Extrac data from a  MYSQL database @a result at row @a row
  *
  * @param cls closure
  * @param cls closure
  * @param[in,out] rs
  * @param stmt the mysql statement that is being run
  * @param column the column that is being processed
  * @param[out] results
  * @return
  *      #GNUNET_OK if all results could be extracted
  *      #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
  */
static int
post_extract_uint32 (void *cls,
                struct GNUNET_MY_ResultSpec *rs,
                MYSQL_STMT * stmt,
                unsigned int column,
                MYSQL_BIND *results)
{
  if (rs->dst_size != rs->mysql_bind_output_length)
      return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
  * uint32_t expected
  *
  * @param[out] u32 where to store the result
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_uint32 (uint32_t *u32)
{
  struct GNUNET_MY_ResultSpec res = {
    .pre_conv = &pre_extract_uint32,
    .post_conv = &post_extract_uint32,
    .cleaner = NULL,
    .dst = (void *) u32,
    .dst_size = sizeof (*u32),
    .num_fields = 1
  };
  return res;
}


/**
  * Extract data from a MYSQL database @a result at row @a row
  *
  * @param cls closure
  * @param[in,out] rs
  * @param stmt the mysql statement that is being run
  * @param column the column that is being processed
  * @param[out] results
  * @return
  *    #GNUNET_OK if all results could be extracted
  *    #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
  */
static int
pre_extract_uint64 (void *cls,
                struct GNUNET_MY_ResultSpec *rs,
                MYSQL_STMT *stmt,
                unsigned int column,
                MYSQL_BIND *results)
{
  results[0].buffer = rs->dst;
  results[0].buffer_length = rs->dst_size;
  results[0].length = &rs->mysql_bind_output_length;
  results[0].buffer_type = MYSQL_TYPE_LONGLONG;

  return GNUNET_OK;
}


/**
  * Check size of extracted fixe size data from a Mysql database
  *
  * @param cls closure
  * @param[in,out] rs
  * @param stmt the mysql statement that is being run
  * @param column the column that is being processed
  * @param[out] results
  * @return
  *    #GNUNET_OK if all results could be extracted
  *    #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
  */
static int
post_extract_uint64 (void *cls,
                struct GNUNET_MY_ResultSpec *rs,
                MYSQL_STMT *stmt,
                unsigned int column,
                MYSQL_BIND *results)
{
  if (rs->dst_size != rs->mysql_bind_output_length)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
  * uint64_t expected.
  *
  * @param[out] u64 where to store the result
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_uint64 (uint64_t *u64)
{
  struct GNUNET_MY_ResultSpec res = {
    .pre_conv = &pre_extract_uint64,
    .post_conv = &post_extract_uint64,
    .cleaner = NULL,
    .dst = (void *) u64,
    .dst_size = sizeof (*u64),
    .num_fields = 1
  };
  return res;
}


/* end of pq_result_helper.c */
