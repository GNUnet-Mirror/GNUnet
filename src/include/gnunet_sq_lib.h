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
 * @file include/gnunet_sq_lib.h
 * @brief helper functions for Sqlite3 DB interactions
 * @author Christian Grothoff
 */
#ifndef GNUNET_SQ_LIB_H
#define GNUNET_SQ_LIB_H

#include <sqlite3.h>
#include "gnunet_util_lib.h"


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
typedef int
(*GNUNET_SQ_QueryConverter)(void *cls,
			    const void *data,
			    size_t data_len,
			    sqlite3_stmt *stmt,
                            unsigned int off);


/**
 * @brief Description of a DB query parameter.
 */
struct GNUNET_SQ_QueryParam
{

  /**
   * Function for how to handle this type of entry.
   */
  GNUNET_SQ_QueryConverter conv;

  /**
   * Closure for @e conv.
   */
  void *conv_cls;

  /**
   * Data or NULL.
   */
  const void *data;

  /**
   * Size of @e data
   */
  size_t size;

  /**
   * Number of parameters eaten by this operation.
   */
  unsigned int num_params;
};


/**
 * End of query parameter specification.
 */
#define GNUNET_SQ_query_param_end { NULL, NULL, NULL, 0, 0 }


/**
 * Generate query parameter for a buffer @a ptr of
 * @a ptr_size bytes.
 *
 * @param ptr pointer to the query parameter to pass
 * @oaran ptr_size number of bytes in @a ptr
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_fixed_size (const void *ptr,
				  size_t ptr_size);



/**
 * Generate query parameter for a string.
 *
 * @param ptr pointer to the string query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_string (const char *ptr);


/**
 * Generate fixed-size query parameter with size determined
 * by variable type.
 *
 * @param x pointer to the query parameter to pass.
 */
#define GNUNET_SQ_query_param_auto_from_type(x) GNUNET_SQ_query_param_fixed_size ((x), sizeof (*(x)))


/**
 * Generate query parameter for an RSA public key.  The
 * database must contain a BLOB type in the respective position.
 *
 * @param x the query parameter to pass.
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_rsa_public_key (const struct GNUNET_CRYPTO_RsaPublicKey *x);


/**
 * Generate query parameter for an RSA signature.  The
 * database must contain a BLOB type in the respective position.
 *
 * @param x the query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_rsa_signature (const struct GNUNET_CRYPTO_RsaSignature *x);


/**
 * Generate query parameter for an absolute time value.
 * The database must store a 64-bit integer.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_absolute_time (const struct GNUNET_TIME_Absolute *x);


/**
 * Generate query parameter for an absolute time value.
 * The database must store a 64-bit integer.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_absolute_time_nbo (const struct GNUNET_TIME_AbsoluteNBO *x);


/**
 * Generate query parameter for an uint16_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_uint16 (const uint16_t *x);


/**
 * Generate query parameter for an uint32_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_uint32 (const uint32_t *x);


/**
 * Generate query parameter for an uint16_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_SQ_QueryParam
GNUNET_SQ_query_param_uint64 (const uint64_t *x);


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
typedef int
(*GNUNET_SQ_ResultConverter)(void *cls,
			     sqlite3_stmt *result,
                             unsigned int column,
			     size_t *dst_size,
			     void *dst);


/**
 * @brief Description of a DB result cell.
 */
struct GNUNET_SQ_ResultSpec;


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_SQ_ResultConverter.
 *
 * @param cls closure
 */
typedef void
(*GNUNET_SQ_ResultCleanup)(void *cls);


/**
 * @brief Description of a DB result cell.
 */
struct GNUNET_SQ_ResultSpec
{

  /**
   * What is the format of the result?
   */
  GNUNET_SQ_ResultConverter conv;

  /**
   * Function to clean up result data, NULL if cleanup is
   * not necessary.
   */
  GNUNET_SQ_ResultCleanup cleaner;

  /**
   * Closure for @e conv and @e cleaner.
   */
  void *cls;

  /**
   * Destination for the data.
   */
  void *dst;

  /**
   * Allowed size for the data, 0 for variable-size
   * (in this case, the type of @e dst is a `void **`
   * and we need to allocate a buffer of the right size).
   */
  size_t dst_size;

  /**
   * Where to store actual size of the result.
   */
  size_t *result_size;

  /**
   * Number of parameters (columns) eaten by this operation.
   */
  unsigned int num_params;

};


/**
 * End of result parameter specification.
 *
 * @return array last entry for the result specification to use
 */
#define GNUNET_SQ_result_spec_end { NULL, NULL, NULL, NULL, 0, NULL }


/**
 * Variable-size result expected.
 *
 * @param[out] dst where to store the result, allocated
 * @param[out] sptr where to store the size of @a dst
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_variable_size (void **dst,
				     size_t *sptr);


/**
 * Fixed-size result expected.
 *
 * @param[out] dst where to store the result
 * @param dst_size number of bytes in @a dst
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_fixed_size (void *dst,
				  size_t dst_size);


/**
 * We expect a fixed-size result, with size determined by the type of `* dst`
 *
 * @param dst point to where to store the result, type fits expected result size
 * @return array entry for the result specification to use
 */
#define GNUNET_SQ_result_spec_auto_from_type(dst) GNUNET_SQ_result_spec_fixed_size ((dst), sizeof (*(dst)))


/**
 * Variable-size result expected.
 *
 * @param[out] dst where to store the result, allocated
 * @param[out] sptr where to store the size of @a dst
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_variable_size (void **dst,
				     size_t *sptr);


/**
 * 0-terminated string expected.
 *
 * @param[out] dst where to store the result, allocated
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_string (char **dst);


/**
 * RSA public key expected.
 *
 * @param[out] rsa where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_rsa_public_key (struct GNUNET_CRYPTO_RsaPublicKey **rsa);


/**
 * RSA signature expected.
 *
 * @param[out] sig where to store the result;
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_rsa_signature (struct GNUNET_CRYPTO_RsaSignature **sig);


/**
 * Absolute time expected.
 *
 * @param[out] at where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_absolute_time (struct GNUNET_TIME_Absolute *at);


/**
 * Absolute time expected.
 *
 * @param[out] at where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_absolute_time_nbo (struct GNUNET_TIME_AbsoluteNBO *at);


/**
 * uint16_t expected.
 *
 * @param[out] u16 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_uint16 (uint16_t *u16);


/**
 * uint32_t expected.
 *
 * @param[out] u32 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_uint32 (uint32_t *u32);


/**
 * uint64_t expected.
 *
 * @param[out] u64 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_SQ_ResultSpec
GNUNET_SQ_result_spec_uint64 (uint64_t *u64);


/**
 * Execute a prepared statement.
 *
 * @param db_conn database connection
 * @param params parameters to the statement
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_SQ_bind (sqlite3_stmt *stmt,
                const struct GNUNET_SQ_QueryParam *params);


/**
 * Extract results from a query result according to the given specification.
 *
 * @param result result to process
 * @param[in,out] rs result specification to extract for
 * @return
 *   #GNUNET_OK if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 */
int
GNUNET_SQ_extract_result (sqlite3_stmt *result,
			  struct GNUNET_SQ_ResultSpec *rs);


/**
 * Free all memory that was allocated in @a rs during
 * #GNUNET_SQ_extract_result().
 *
 * @param rs reult specification to clean up
 */
void
GNUNET_SQ_cleanup_result (struct GNUNET_SQ_ResultSpec *rs);


#endif  /* GNUNET_SQ_LIB_H_ */

/* end of include/gnunet_sq_lib.h */
