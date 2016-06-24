/*
     This file is part of GNUnet
     Copyright (C) 2012 GNUnet e.V.

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
 * @author Christian Grothoff
 * @author Christophe Genevey
 *
 * @file
 * Helper library to access a MySQL database
 *
 * @defgroup mysql  MySQL library
 * Helper library to access a MySQL database.
 * @{
 */
#ifndef GNUNET_MY_LIB_H
#define GNUNET_MY_LIB_H

#include "gnunet_util_lib.h"
#include "gnunet_mysql_lib.h"
#include <mysql/mysql.h>

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif



/**
 * Information we pass to #GNUNET_MY_exec_prepared() to
 * initialize the arguments of the prepared statement.
 */
struct GNUNET_MY_QueryParam;


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param pq data about the query
 * @param qbind array of parameters to initialize
 * @return -1 on error
 */
typedef int
(*GNUNET_MY_QueryConverter)(void *cls,
			    const struct GNUNET_MY_QueryParam *qp,
                            MYSQL_BIND *qbind);


/**
 * Function called to cleanup result data.
 *
 * @param cls closure
 * @param rs spec to clean up
 */
typedef void
(*GNUNET_MY_QueryCleanup)(void *cls,
                           MYSQL_BIND *qbind);
/**
 * Information we pass to #GNUNET_MY_exec_prepared() to
 * initialize the arguments of the prepared statement.
 */


struct GNUNET_MY_QueryParam
{

  /**
   * Function to call for the type conversion.
   */
  GNUNET_MY_QueryConverter conv;

   /**
   * Function to call for cleaning up the query. Can be NULL.
   */
  GNUNET_MY_QueryCleanup cleaner;

  /**
   * Closure for @e conv.
   */
  void *conv_cls;

  /**
   * Number of arguments the @a conv converter expects to initialize.
   */
  unsigned int num_params;

  /**
   * Information to pass to @e conv.
   */
  const void *data;

  /**
   * Information to pass to @e conv.  Size of @a data.
   */
  unsigned long data_len;

};

/**
 * End of query parameter specification.
 *
 * @return array last entry for the result specification to use
 */
#define GNUNET_MY_query_param_end { NULL, NULL, NULL, 0, NULL, 0 }


/**
 * Generate query parameter for a buffer @a ptr of
 * @a ptr_size bytes.FG
 *
 * @param ptr pointer to the query parameter to pass
 * @oaran ptr_size number of bytes in @a ptr
 */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_fixed_size (const void *ptr,
				  size_t ptr_size);


/**
 * Run a prepared SELECT statement.
 *
 * @param mc mysql context
 * @param sh handle to SELECT statment
 * @param params parameters to the statement
 * @return TBD
 */
int
GNUNET_MY_exec_prepared (struct GNUNET_MYSQL_Context *mc,
                         struct GNUNET_MYSQL_StatementHandle *sh,
                         struct GNUNET_MY_QueryParam *params);


/**
 * Information we pass to #GNUNET_MY_extract_result() to
 * initialize the arguments of the prepared statement.
 */
struct GNUNET_MY_ResultParam;

/**
 * Information we pass to #GNUNET_MY_extract_result() to
 * initialize the arguments of the prepared statement.
 */
struct GNUNET_MY_ResultSpec;

/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param[in,out] rs
 * @param stmt the mysql statement that is being run
 * @param column the column that is being processed
 * @param[out] results
 * @return -1 on error
 */
typedef int
(*GNUNET_MY_ResultConverter)(void *cls,
                             struct GNUNET_MY_ResultSpec *rs,
                             MYSQL_STMT *stmt,
                             unsigned int column,
                             MYSQL_BIND *results);

/**
 * Function called to cleanup result data.
 *
 * @param cls closure
 * @param rs spec to clean up
 */
typedef void
(*GNUNET_MY_ResultCleanup)(void *cls,
                           struct GNUNET_MY_ResultSpec *rs);


/**
 * Information we pass to #GNUNET_MY_extract_result() to
 * initialize the arguments of the prepared statement.
 */
struct GNUNET_MY_ResultSpec
{

  /**
   * Function to call to initialize the MYSQL_BIND array.
   */
  GNUNET_MY_ResultConverter pre_conv;

  /**
   * Function to call for converting the result. Can be NULL.
   */
  GNUNET_MY_ResultConverter post_conv;

    /**
   * Function to call for cleaning up the result. Can be NULL.
   */
  GNUNET_MY_ResultCleanup cleaner;

  /**
   * Closure for @e conv.
   */
  void *conv_cls;

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
   * How many fields does this result specification occupy
   * in the result returned by MySQL.
   */
  unsigned int num_fields;

  /**
   * Location where we temporarily store the output buffer
   * length from MySQL.  Internal to libgnunetmy.
   */
  unsigned long mysql_bind_output_length;

  /**
   * Memory for MySQL to notify us about NULL values.
   */
  my_bool is_null;

};


/**
 * End of result speceter specification.
 *
 * @return array last entry for the result specification to use
 */
#define GNUNET_MY_result_spec_end { NULL, NULL, NULL, 0, NULL, 0 }



/**
 * Obtain fixed size result of @a ptr_size bytes from
 * MySQL, store in already allocated buffer at @a ptr.
 *
 * @spec ptr where to write the result
 * @oaran ptr_size number of bytes available at @a ptr
 */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_fixed_size (void *ptr,
                                  size_t ptr_size);

/**
  * Generate query parameter for a string
  *
  *@param ptr pointer to the string query parameter to pass
  */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_string (const char *ptr);

/**
  * Generate fixed-size query parameter with size determined
  * by variable type.
  *
  * @param x pointer to the query parameter to pass
  */
#define GNUNET_MY_query_param_auto_from_type(x) GNUNET_MY_query_param_fixed_size ((x), sizeof (*(x)))

/**
  * Generate query parameter for an RSA public key. The
  * database must contain a BLOB type in the respective position.
  *
  * @param x the query parameter to pass
  * @return array entry for the query parameters to use
  */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_rsa_public_key (const struct GNUNET_CRYPTO_RsaPublicKey *x);

/**
  * Generate query parameter for an RSA signature. The
  * database must contain a BLOB type in the respective position
  *
  *@param x the query parameter to pass
  *@return array entry for the query parameters to use
  */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_rsa_signature (const struct GNUNET_CRYPTO_RsaSignature *x);

/**
  * Generate query parameter for an absolute time value.
  * The database must store a 64-bit integer.
  *
  *@param x pointer to the query parameter to pass
  *@return array entry for the query parameters to use
  */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_absolute_time (const struct GNUNET_TIME_Absolute *x);


/**
  * Generate query parameter for an absolute time value.
  * The database must store a 64-bit integer.
  *
  *@param x pointer to the query parameter to pass
  */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_absolute_time_nbo (const struct GNUNET_TIME_AbsoluteNBO *x);

/**
  * Generate query parameter for an uint16_t in host byte order.
  *
  * @param x pointer to the query parameter to pass
  */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_uint16 (const uint16_t *x);

/**
  * Generate query parameter for an uint32_t in host byte order
  *
  *@param x pointer to the query parameter to pass
  */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_uint32 (const uint32_t *x);

/**
  * Generate query parameter for an uint64_t in host byte order
  *
  *@param x pointer to the query parameter to pass
  */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_uint64 (const uint64_t *x);

/**
 * We expect a fixed-size result, with size determined by the type of `* dst`
 *
 * @spec name name of the field in the table
 * @spec dst point to where to store the result, type fits expected result size
 * @return array entry for the result specification to use
 */
#define GNUNET_MY_result_spec_auto_from_type(dst) GNUNET_MY_result_spec_fixed_size ((dst), sizeof (*(dst)))


/**
 * Variable-size result expected
 *
 * @param[out] dst where to store the result, allocated
 * @param[out] sptr where to store the size of @a dst
 * @return array entru for the result specification to use
 */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_variable_size (void **dst,
                                     size_t *ptr_size);

/**
 * RSA public key expected
 *
 * @param name name of the field in the table
 * @param[out] rsa where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_rsa_public_key (struct GNUNET_CRYPTO_RsaPublicKey **rsa);


/**
 * RSA signature expected.
 *
 * @param[out] sig where to store the result;
 * @return array entry for the result specification to use
 */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_rsa_signature (struct GNUNET_CRYPTO_RsaSignature **sig);

/**
  * 0- terminated string exprected.
  *
  * @param[out] dst where to store the result, allocated
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_string (char **dst);

/**
  * Absolute time expected
  *
  * @param name name of the field in the table
  * @param[out] at where to store the result
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_absolute_time (struct GNUNET_TIME_Absolute *at);

/**
  * Absolute time in network byte order expected
  *
  * @param[out] at where to store the result
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_absolute_time_nbo (struct GNUNET_TIME_AbsoluteNBO *at);

/**
  * uint16_t expected
  *
  * @param[out] u16 where to store the result
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_uint16 (uint16_t *u16);

/**
  * uint32_t expected
  *
  * @param[out] u32 where to store the result
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_uint32 (uint32_t *u32);

/**
  * uint64_t expected.
  *
  * @param[out] u64 where to store the result
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_uint64 (uint64_t *u64);


/**
 * Extract results from a query result according to the given
 * specification.  Always fetches the next row.
 *
 * @param sh statement that returned results
 * @param rs specification to extract for
 * @return
 *  #GNUNET_YES if all results could be extracted
 *  #GNUNET_NO if there is no more data in the result set
 *  #GNUNET_SYSERR if a result was invalid
 */
int
GNUNET_MY_extract_result (struct GNUNET_MYSQL_StatementHandle *sh,
                          struct GNUNET_MY_ResultSpec *specs);


/**
 * Free all memory that was allocated in @a qp during
 * #GNUNET_MY_exect_prepared().
 *
 * @param qp query specification to clean up
 * @param qbind mysql query
 */
void
GNUNET_MY_cleanup_query (struct GNUNET_MY_QueryParam *qp,
                        MYSQL_BIND *qbind);


/**
 * Free all memory that was allocated in @a rs during
 * #GNUNET_MY_extract_result().
 *
 * @param rs reult specification to clean up
 */
void
GNUNET_MY_cleanup_result (struct GNUNET_MY_ResultSpec *rs);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */
