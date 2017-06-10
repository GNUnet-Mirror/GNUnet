/*
  This file is part of GNUnet
  Copyright (C) 2016, 2017 GNUnet e.V.

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
 * @brief helper functions for Postgres DB interactions
 * @author Christian Grothoff
 */
#ifndef GNUNET_PQ_LIB_H
#define GNUNET_PQ_LIB_H

#include <libpq-fe.h>
#include "gnunet_util_lib.h"
#include "gnunet_db_lib.h"

/* ************************* pq_query_helper.c functions ************************ */


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
   * Function for how to handle this type of entry.
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
 * Generate query parameter for a string.
 *
 * @param ptr pointer to the string query parameter to pass
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_string (const char *ptr);


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
GNUNET_PQ_query_param_rsa_public_key (const struct GNUNET_CRYPTO_RsaPublicKey *x);


/**
 * Generate query parameter for an RSA signature.  The
 * database must contain a BLOB type in the respective position.
 *
 * @param x the query parameter to pass
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_rsa_signature (const struct GNUNET_CRYPTO_RsaSignature *x);


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


/* ************************* pq_result_helper.c functions ************************ */


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
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
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
 * 0-terminated string expected.
 *
 * @param name name of the field in the table
 * @param[out] dst where to store the result, allocated
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_string (const char *name,
                              char **dst);


/**
 * RSA public key expected.
 *
 * @param name name of the field in the table
 * @param[out] rsa where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_rsa_public_key (const char *name,
				      struct GNUNET_CRYPTO_RsaPublicKey **rsa);


/**
 * RSA signature expected.
 *
 * @param name name of the field in the table
 * @param[out] sig where to store the result;
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_rsa_signature (const char *name,
				     struct GNUNET_CRYPTO_RsaSignature **sig);


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


/* ************************* pq.c functions ************************ */

/**
 * Execute a prepared statement.
 *
 * @param db_conn database connection
 * @param name name of the prepared statement
 * @param params parameters to the statement
 * @return postgres result
 * @deprecated (should become an internal API)
 */
PGresult *
GNUNET_PQ_exec_prepared (PGconn *db_conn,
			 const char *name,
			 const struct GNUNET_PQ_QueryParam *params);


/**
 * Extract results from a query result according to the given specification.
 *
 * @param result result to process
 * @param[in,out] rs result specification to extract for
 * @param row row from the result to extract
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 * @deprecated (should become an internal API)
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


/* ******************** pq_eval.c functions ************** */


/**
 * Check the @a result's error code to see what happened.
 * Also logs errors.
 *
 * @param connection connection to execute the statement in
 * @param statement_name name of the statement that created @a result
 * @param result result to check
 * @return status code from the result, mapping PQ status
 *         codes to `enum GNUNET_DB_QueryStatus`.  Never
 *         returns positive values as this function does
 *         not look at the result set.
 * @deprecated (low level, let's see if we can do with just the high-level functions)
 */
enum GNUNET_DB_QueryStatus
GNUNET_PQ_eval_result (PGconn *connection,
                       const char *statement_name,
                       PGresult *result);


/**
 * Execute a named prepared @a statement that is NOT a SELECT
 * statement in @a connnection using the given @a params.  Returns the
 * resulting session state.
 *
 * @param connection connection to execute the statement in
 * @param statement_name name of the statement
 * @param params parameters to give to the statement (#GNUNET_PQ_query_param_end-terminated)
 * @return status code from the result, mapping PQ status
 *         codes to `enum GNUNET_DB_QueryStatus`.   If the
 *         statement was a DELETE or UPDATE statement, the
 *         number of affected rows is returned; if the
 *         statment was an INSERT statement, and no row
 *         was added due to a UNIQUE violation, we return
 *         zero; if INSERT was successful, we return one.
 */
enum GNUNET_DB_QueryStatus
GNUNET_PQ_eval_prepared_non_select (PGconn *connection,
                                    const char *statement_name,
                                    const struct GNUNET_PQ_QueryParam *params);


/**
 * Function to be called with the results of a SELECT statement
 * that has returned @a num_results results.
 *
 * @param cls closure
 * @param result the postgres result
 * @param num_result the number of results in @a result
 */
typedef void
(*GNUNET_PQ_PostgresResultHandler)(void *cls,
                                   PGresult *result,
                                   unsigned int num_results);


/**
 * Execute a named prepared @a statement that is a SELECT statement
 * which may return multiple results in @a connection using the given
 * @a params.  Call @a rh with the results.  Returns the query
 * status including the number of results given to @a rh (possibly zero).
 * @a rh will not have been called if the return value is negative.
 *
 * @param connection connection to execute the statement in
 * @param statement_name name of the statement
 * @param params parameters to give to the statement (#GNUNET_PQ_query_param_end-terminated)
 * @param rh function to call with the result set, NULL to ignore
 * @param rh_cls closure to pass to @a rh
 * @return status code from the result, mapping PQ status
 *         codes to `enum GNUNET_DB_QueryStatus`.
 */
enum GNUNET_DB_QueryStatus
GNUNET_PQ_eval_prepared_multi_select (PGconn *connection,
                                      const char *statement_name,
                                      const struct GNUNET_PQ_QueryParam *params,
                                      GNUNET_PQ_PostgresResultHandler rh,
                                      void *rh_cls);


/**
 * Execute a named prepared @a statement that is a SELECT statement
 * which must return a single result in @a connection using the given
 * @a params.  Stores the result (if any) in @a rs, which the caller
 * must then clean up using #GNUNET_PQ_cleanup_result() if the return
 * value was #GNUNET_DB_STATUS_SUCCESS_ONE_RESULT.  Returns the
 * resulting session status.
 *
 * @param connection connection to execute the statement in
 * @param statement_name name of the statement
 * @param params parameters to give to the statement (#GNUNET_PQ_query_param_end-terminated)
 * @param[in,out] rs result specification to use for storing the result of the query
 * @return status code from the result, mapping PQ status
 *         codes to `enum GNUNET_DB_QueryStatus`.
 */
enum GNUNET_DB_QueryStatus
GNUNET_PQ_eval_prepared_singleton_select (PGconn *connection,
                                          const char *statement_name,
                                          const struct GNUNET_PQ_QueryParam *params,
                                          struct GNUNET_PQ_ResultSpec *rs);


/* ******************** pq_prepare.c functions ************** */


/**
 * Information needed to prepare a list of SQL statements using
 * #GNUNET_PQ_prepare_statements().
 */
struct GNUNET_PQ_PreparedStatement {

  /**
   * Name of the statement.
   */
  const char *name;

  /**
   * Actual SQL statement.
   */
  const char *sql;

  /**
   * Number of arguments included in @e sql.
   */
  unsigned int num_arguments;

};


/**
 * Terminator for prepared statement list.
 */
#define GNUNET_PQ_PREPARED_STATEMENT_END { NULL, NULL, 0 }


/**
 * Create a `struct GNUNET_PQ_PreparedStatement`.
 *
 * @param name name of the statement
 * @param sql actual SQL statement
 * @param num_args number of arguments in the statement
 * @return initialized struct
 */
struct GNUNET_PQ_PreparedStatement
GNUNET_PQ_make_prepare (const char *name,
                        const char *sql,
                        unsigned int num_args);


/**
 * Request creation of prepared statements @a ps from Postgres.
 *
 * @param connection connection to prepare the statements for
 * @param ps #GNUNET_PQ_PREPARED_STATEMENT_END-terminated array of prepared
 *            statements.
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on error
 */
int
GNUNET_PQ_prepare_statements (PGconn *connection,
                              const struct GNUNET_PQ_PreparedStatement *ps);


/* ******************** pq_exec.c functions ************** */


/**
 * Information needed to run a list of SQL statements using
 * #GNUNET_PQ_exec_statements().
 */
struct GNUNET_PQ_ExecuteStatement {

  /**
   * Actual SQL statement.
   */
  const char *sql;

  /**
   * Should we ignore errors?
   */
  int ignore_errors;

};


/**
 * Terminator for executable statement list.
 */
#define GNUNET_PQ_EXECUTE_STATEMENT_END { NULL, GNUNET_SYSERR }


/**
 * Create a `struct GNUNET_PQ_ExecuteStatement` where errors are fatal.
 *
 * @param sql actual SQL statement
 * @return initialized struct
 */
struct GNUNET_PQ_ExecuteStatement
GNUNET_PQ_make_execute (const char *sql);


/**
 * Create a `struct GNUNET_PQ_ExecuteStatement` where errors should
 * be tolerated.
 *
 * @param sql actual SQL statement
 * @return initialized struct
 */
struct GNUNET_PQ_ExecuteStatement
GNUNET_PQ_make_try_execute (const char *sql);


/**
 * Request execution of an array of statements @a es from Postgres.
 *
 * @param connection connection to execute the statements over
 * @param es #GNUNET_PQ_PREPARED_STATEMENT_END-terminated array of prepared
 *            statements.
 * @return #GNUNET_OK on success (modulo statements where errors can be ignored)
 *         #GNUNET_SYSERR on error
 */
int
GNUNET_PQ_exec_statements (PGconn *connection,
                           const struct GNUNET_PQ_ExecuteStatement *es);


/* ******************** pq_connect.c functions ************** */


/**
 * Create a connection to the Postgres database using @a config_str
 * for the configuration.  Initialize logging via GNUnet's log
 * routines and disable Postgres's logger.
 *
 * @param config_str configuration to use
 * @return NULL on error
 */
PGconn *
GNUNET_PQ_connect (const char *config_str);


/**
 * Connect to a postgres database using the configuration
 * option "CONFIG" in @a section.
 *
 * @param cfg configuration
 * @param section configuration section to use to get Postgres configuration options
 * @return the postgres handle, NULL on error
 */
PGconn *
GNUNET_PQ_connect_with_cfg (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            const char *section);



#endif  /* GNUNET_PQ_LIB_H_ */

/* end of include/gnunet_pq_lib.h */
