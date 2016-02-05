/*
  This file is part of GNUnet
  Copyright (C) 2016 GNUnet e.V.

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
 * @file include/gnunet_pq_lib.h
 * @brief helper functions for DB interactions
 * @author Christian Grothoff
 */
#ifndef GNUNET_PQ_LIB_H_
#define GNUNET_PQ_LIB_H_

#include <libpq-fe.h>
#include "gnunet_util_lib.h"


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
typedef int
(*GNUNET_PQ_QueryConverter)(void *cls,
			    const void *data,
			    size_t data_len,
			    void *param_values[],
			    int param_lengths[],
			    int param_formats[],
			    unsigned int param_length,
			    void *scratch[],
			    unsigned int scratch_length);


/**
 * @brief Description of a DB query parameter.
 */
struct GNUNET_PQ_QueryParam
{

  /**
   * Format of the rest of the entry, determines the data
   * type that is being added to the query.
   */
  GNUNET_PQ_QueryConverter conv;

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
#define GNUNET_PQ_query_param_end { NULL, NULL, NULL, 0, 0 }


/**
 * Generate query parameter for a buffer @a ptr of
 * @a ptr_size bytes.
 *
 * @param ptr pointer to the query parameter to pass
 * @oaran ptr_size number of bytes in @a ptr
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_fixed_size (const void *ptr,
				  size_t ptr_size);


/**
 * Generate fixed-size query parameter with size determined
 * by variable type.
 *
 * @param x pointer to the query parameter to pass.
 */
#define GNUNET_PQ_query_param_auto_from_type(x) GNUNET_PQ_query_param_fixed_size ((x), sizeof (*(x)))


/**
 * Generate query parameter for an RSA public key.  The
 * database must contain a BLOB type in the respective position.
 *
 * @param x the query parameter to pass.
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_rsa_public_key (const struct GNUNET_CRYPTO_rsa_PublicKey *x);


/**
 * Generate query parameter for an RSA signature.  The
 * database must contain a BLOB type in the respective position.
 *
 * @param x the query parameter to pass
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_rsa_signature (const struct GNUNET_CRYPTO_rsa_Signature *x);


/**
 * Generate query parameter for an absolute time value.
 * The database must store a 64-bit integer.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_absolute_time (const struct GNUNET_TIME_Absolute *x);


/**
 * Generate query parameter for an absolute time value.
 * The database must store a 64-bit integer.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_absolute_time_nbo (const struct GNUNET_TIME_AbsoluteNBO *x);


/**
 * Generate query parameter for an uint16_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_uint16 (const uint16_t *x);


/**
 * Generate query parameter for an uint32_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_uint32 (const uint32_t *x);


/**
 * Generate query parameter for an uint16_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_uint64 (const uint64_t *x);


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param int row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_NO if at least one result was NULL
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 */
typedef int
(*GNUNET_PQ_ResultConverter)(void *cls,
			     PGresult *result,
			     int row,
			     const char *fname,
			     size_t *dst_size,
			     void *dst);


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_PQ_ResultConverter.
 *
 * @param cls closure
 * @param rd result data to clean up
 */
typedef void
(*GNUNET_PQ_ResultCleanup)(void *cls,
			   void *rd);


/**
 * @brief Description of a DB result cell.
 */
struct GNUNET_PQ_ResultSpec
{

  /**
   * What is the format of the result?
   */
  GNUNET_PQ_ResultConverter conv;

  /**
   * Function to clean up result data, NULL if cleanup is
   * not necessary.
   */
  GNUNET_PQ_ResultCleanup cleaner;

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
   * Field name of the desired result.
   */
  const char *fname;

  /**
   * Where to store actual size of the result.
   */
  size_t *result_size;

};


/**
 * End of result parameter specification.
 *
 * @return array last entry for the result specification to use
 */
#define GNUNET_PQ_result_spec_end { NULL, NULL, NULL, NULL, 0, NULL, NULL }


/**
 * Variable-size result expected.
 *
 * @param name name of the field in the table
 * @param[out] dst where to store the result, allocated
 * @param[out] sptr where to store the size of @a dst
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_variable_size (const char *name,
				     void **dst,
				     size_t *sptr);


/**
 * Fixed-size result expected.
 *
 * @param name name of the field in the table
 * @param[out] dst where to store the result
 * @param dst_size number of bytes in @a dst
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_fixed_size (const char *name,
				  void *dst,
				  size_t dst_size);



/**
 * We expect a fixed-size result, with size determined by the type of `* dst`
 *
 * @param name name of the field in the table
 * @param dst point to where to store the result, type fits expected result size
 * @return array entry for the result specification to use
 */
#define GNUNET_PQ_result_spec_auto_from_type(name, dst) GNUNET_PQ_result_spec_fixed_size (name, (dst), sizeof (*(dst)))


/**
 * Variable-size result expected.
 *
 * @param name name of the field in the table
 * @param[out] dst where to store the result, allocated
 * @param[out] sptr where to store the size of @a dst
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_variable_size (const char *name,
				     void **dst,
				     size_t *sptr);


/**
 * RSA public key expected.
 *
 * @param name name of the field in the table
 * @param[out] rsa where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_rsa_public_key (const char *name,
				      struct GNUNET_CRYPTO_rsa_PublicKey **rsa);


/**
 * RSA signature expected.
 *
 * @param name name of the field in the table
 * @param[out] sig where to store the result;
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_rsa_signature (const char *name,
				     struct GNUNET_CRYPTO_rsa_Signature **sig);


/**
 * Absolute time expected.
 *
 * @param name name of the field in the table
 * @param[out] at where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_absolute_time (const char *name,
				     struct GNUNET_TIME_Absolute *at);


/**
 * Absolute time expected.
 *
 * @param name name of the field in the table
 * @param[out] at where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_absolute_time_nbo (const char *name,
					 struct GNUNET_TIME_AbsoluteNBO *at);


/**
 * uint16_t expected.
 *
 * @param name name of the field in the table
 * @param[out] u16 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_uint16 (const char *name,
			      uint16_t *u16);


/**
 * uint32_t expected.
 *
 * @param name name of the field in the table
 * @param[out] u32 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_uint32 (const char *name,
			      uint32_t *u32);


/**
 * uint64_t expected.
 *
 * @param name name of the field in the table
 * @param[out] u64 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_uint64 (const char *name,
			      uint64_t *u64);


/**
 * Execute a prepared statement.
 *
 * @param db_conn database connection
 * @param name name of the prepared statement
 * @param params parameters to the statement
 * @return postgres result
 */
PGresult *
GNUNET_PQ_exec_prepared (PGconn *db_conn,
			 const char *name,
			 const struct GNUNET_PQ_QueryParam *params);


/**
 * Extract results from a query result according to the given specification.
 * If colums are NULL, the destination is not modified, and #GNUNET_NO
 * is returned.
 *
 * @param result result to process
 * @param[in,out] rs result specification to extract for
 * @param row row from the result to extract
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_NO if at least one result was NULL
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 */
int
GNUNET_PQ_extract_result (PGresult *result,
			  struct GNUNET_PQ_ResultSpec *rs,
			  int row);


/**
 * Free all memory that was allocated in @a rs during
 * #GNUNET_PQ_extract_result().
 *
 * @param rs reult specification to clean up
 */
void
GNUNET_PQ_cleanup_result (struct GNUNET_PQ_ResultSpec *rs);


#endif  /* GNUNET_PQ_LIB_H_ */

/* end of include/gnunet_pq_lib.h */
