/*
  This file is part of GNUnet
  (C) 2015, 2016, 2017 GNUnet e.V.

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
 * @file sq/test_sq.c
 * @brief Tests for sqlite3 convenience API
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_sq_lib.h"


/**
 * @brief Prepare a SQL statement
 *
 * @param dbh handle to the database
 * @param zSql SQL statement, UTF-8 encoded
 * @param[out] ppStmt set to the prepared statement
 * @return 0 on success
 */
static int
sq_prepare (sqlite3 *dbh,
            const char *zSql,
            sqlite3_stmt **ppStmt)
{
  char *dummy;
  int result;

  result = sqlite3_prepare_v2 (dbh,
                               zSql,
                               strlen (zSql),
                               ppStmt,
                               (const char **) &dummy);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Prepared `%s' / %p: %d\n",
              zSql,
              *ppStmt,
              result);
  return result;
}


/**
 * Run actual test queries.
 *
 * @return 0 on success
 */
static int
run_queries (sqlite3 *dbh)
{
  struct GNUNET_CRYPTO_RsaPublicKey *pub;
  struct GNUNET_CRYPTO_RsaPublicKey *pub2 = NULL;
  struct GNUNET_CRYPTO_RsaSignature *sig;
  struct GNUNET_CRYPTO_RsaSignature *sig2 = NULL;
  struct GNUNET_TIME_Absolute abs_time = GNUNET_TIME_absolute_get ();
  struct GNUNET_TIME_Absolute abs_time2;
  struct GNUNET_TIME_Absolute forever = GNUNET_TIME_UNIT_FOREVER_ABS;
  struct GNUNET_TIME_Absolute forever2;
  struct GNUNET_HashCode hc;
  struct GNUNET_HashCode hc2;
  sqlite3_stmt *stmt;
  struct GNUNET_CRYPTO_RsaPrivateKey *priv;
  const char msg[] = "hello";
  void *msg2;
  struct GNUNET_HashCode hmsg;
  size_t msg2_len;
  uint16_t u16;
  uint16_t u162;
  uint32_t u32;
  uint32_t u322;
  uint64_t u64;
  uint64_t u642;

  priv = GNUNET_CRYPTO_rsa_private_key_create (1024);
  pub = GNUNET_CRYPTO_rsa_private_key_get_public (priv);
  memset (&hmsg, 42, sizeof (hmsg));
  sig = GNUNET_CRYPTO_rsa_sign_fdh (priv,
                                    &hmsg);
  u16 = 16;
  u32 = 32;
  u64 = 64;
  /* FIXME: test GNUNET_SQ_result_spec_variable_size */

  sq_prepare (dbh,
              "INSERT INTO test_sq ("
              " pub"
              ",sig"
              ",abs_time"
              ",forever"
              ",hash"
              ",vsize"
              ",u16"
              ",u32"
              ",u64"
              ") VALUES "
              "($1, $2, $3, $4, $5, $6,"
              "$7, $8, $9);",
              &stmt);
  {
    struct GNUNET_SQ_QueryParam params_insert[] = {
      GNUNET_SQ_query_param_rsa_public_key (pub),
      GNUNET_SQ_query_param_rsa_signature (sig),
      GNUNET_SQ_query_param_absolute_time (&abs_time),
      GNUNET_SQ_query_param_absolute_time (&forever),
      GNUNET_SQ_query_param_auto_from_type (&hc),
      GNUNET_SQ_query_param_fixed_size (msg, strlen (msg)),
      GNUNET_SQ_query_param_uint16 (&u16),
      GNUNET_SQ_query_param_uint32 (&u32),
      GNUNET_SQ_query_param_uint64 (&u64),
      GNUNET_SQ_query_param_end
    };

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_SQ_bind (stmt,
                                   params_insert));
    if (SQLITE_DONE !=
        sqlite3_step (stmt))
    {
      GNUNET_CRYPTO_rsa_signature_free (sig);
      GNUNET_CRYPTO_rsa_private_key_free (priv);
      GNUNET_CRYPTO_rsa_public_key_free (pub);
      return 1;
    }
  }
  sqlite3_finalize (stmt);

  sq_prepare (dbh,
              "SELECT"
              " pub"
              ",sig"
              ",abs_time"
              ",forever"
              ",hash"
              ",vsize"
              ",u16"
              ",u32"
              ",u64"
              " FROM test_sq"
              " ORDER BY abs_time DESC "
              " LIMIT 1;",
              &stmt);
  {
    struct GNUNET_SQ_QueryParam params_select[] = {
      GNUNET_SQ_query_param_end
    };
    struct GNUNET_SQ_ResultSpec results_select[] = {
      GNUNET_SQ_result_spec_rsa_public_key (&pub2),
      GNUNET_SQ_result_spec_rsa_signature (&sig2),
      GNUNET_SQ_result_spec_absolute_time (&abs_time2),
      GNUNET_SQ_result_spec_absolute_time (&forever2),
      GNUNET_SQ_result_spec_auto_from_type (&hc2),
      GNUNET_SQ_result_spec_variable_size (&msg2, &msg2_len),
      GNUNET_SQ_result_spec_uint16 (&u162),
      GNUNET_SQ_result_spec_uint32 (&u322),
      GNUNET_SQ_result_spec_uint64 (&u642),
      GNUNET_SQ_result_spec_end
    };

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_SQ_bind (stmt,
                                   params_select));
    if (SQLITE_ROW !=
        sqlite3_step (stmt))
    {
      GNUNET_break (0);
      sqlite3_finalize (stmt);
      GNUNET_CRYPTO_rsa_signature_free (sig);
      GNUNET_CRYPTO_rsa_private_key_free (priv);
      GNUNET_CRYPTO_rsa_public_key_free (pub);
      return 1;
    }
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_SQ_extract_result (stmt,
                                             results_select));
    GNUNET_break (abs_time.abs_value_us == abs_time2.abs_value_us);
    GNUNET_break (forever.abs_value_us == forever2.abs_value_us);
    GNUNET_break (0 ==
		  memcmp (&hc,
			  &hc2,
			  sizeof (struct GNUNET_HashCode)));
    GNUNET_break (0 ==
		  GNUNET_CRYPTO_rsa_signature_cmp (sig,
						   sig2));
    GNUNET_break (0 ==
		  GNUNET_CRYPTO_rsa_public_key_cmp (pub,
						    pub2));
    GNUNET_break (strlen (msg) == msg2_len);
    GNUNET_break (0 ==
		  strncmp (msg,
			   msg2,
			   msg2_len));
    GNUNET_break (16 == u162);
    GNUNET_break (32 == u322);
    GNUNET_break (64 == u642);
    GNUNET_SQ_cleanup_result (results_select);
  }
  sqlite3_finalize (stmt);

  GNUNET_CRYPTO_rsa_signature_free (sig);
  GNUNET_CRYPTO_rsa_private_key_free (priv);
  GNUNET_CRYPTO_rsa_public_key_free (pub);
  return 0;
}


int
main(int argc,
     const char *const argv[])
{
  sqlite3 *dbh;
  int ret;

  GNUNET_log_setup ("test-sq",
		    "WARNING",
		    NULL);
  if (SQLITE_OK !=
      sqlite3_open ("test.db",
                    &dbh))
  {
    fprintf (stderr,
	     "Cannot run test, sqlite3 initialization failed\n");
    GNUNET_break (0);
    return 77; /* Signal test was skipped... */
  }

  if (SQLITE_OK !=
      sqlite3_exec (dbh,
                    "CREATE TEMPORARY TABLE IF NOT EXISTS test_sq ("
                    " pub BYTEA NOT NULL"
                    ",sig BYTEA NOT NULL"
                    ",abs_time INT8 NOT NULL"
                    ",forever INT8 NOT NULL"
                    ",hash BYTEA NOT NULL"
                    ",vsize VARCHAR NOT NULL"
                    ",u16 INT2 NOT NULL"
                    ",u32 INT4 NOT NULL"
                    ",u64 INT8 NOT NULL"
                    ")",
                    NULL, NULL, NULL))
  {
    fprintf (stderr,
	     "Failed to create table\n");
    sqlite3_close (dbh);
    if (0 != unlink ("test.db"))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                "unlink",
                                "test.db");
    return 1;
  }

  ret = run_queries (dbh);
  if (SQLITE_OK !=
      sqlite3_exec (dbh,
                    "DROP TABLE test_sq",
                    NULL, NULL, NULL))
  {
    fprintf (stderr,
	     "Failed to drop table\n");
    ret = 1;
  }
  GNUNET_break (SQLITE_OK ==
                sqlite3_close (dbh));
  if (0 != unlink ("test.db"))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                              "unlink",
                              "test.db");
  return ret;
}


/* end of test_sq.c */
