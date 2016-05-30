/*
     This file is part of GNUnet
     Copyright (C) 2016 GNUnet e.V.

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
 * @file my/test_my.c
 * @brief Tests for convenience MySQL database
 * @author Christophe Genevey
 */
#include "platform.h"
#include <mysql/mysql.h>
#include "gnunet_my_lib.h"
#include "gnunet_mysql_lib.h"
#include "gnunet_util_lib.h"

/**
  * Run actual test queries.
  *
  * @param contexte the current context of mysql
  * @return 0 on succes
  */
static int
run_queries (struct GNUNET_MYSQL_Context *context)
{
     const struct GNUNET_CRYPTO_RsaPublicKey *pub;
     struct GNUNET_CRYPTO_RsaSignature *sig;
     struct GNUNET_TIME_Absolute abs_time = GNUNET_TIME_absolute_get ();
     struct GNUNET_TIME_Absolute forever = GNUNET_TIME_UNIT_FOREVER_ABS;
     struct GNUNET_HashCode hc;
     const char msg[] = "hello";
     uint16_t u16;
     uint32_t u32;
     uint64_t u64;

//     struct GNUNET_MYSQL_StatementHandle *statements_handle_insert;
     struct GNUNET_MYSQL_StatementHandle *statements_handle_select;

     struct GNUNET_CRYPTO_RsaPrivateKey *priv;
     struct GNUNET_HashCode hmsg;

     priv = GNUNET_CRYPTO_rsa_private_key_create (1024);
     pub =  GNUNET_CRYPTO_rsa_private_key_get_public (priv);
     memset (&hmsg, 42, sizeof(hmsg));
     sig = GNUNET_CRYPTO_rsa_sign_fdh (priv,
                                        &hmsg);
     u16 = 16;
     u32 = 32;
     u64 = 64;

/*   FIXE THE INSERT QUERY  
     statements_handle_insert = GNUNET_MYSQL_statement_prepare (context,
                                        "INSERT INTO test_my ("
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
                                        "(@1, @2, @3, @4, @5, @6,"
                                        "@7, @8, @9);");

     if (NULL == statements_handle_insert)
     {
          fprintf(stderr, "Failed to prepared statement INSERT\n");
          return 1;
     }

     struct GNUNET_MY_QueryParam params_insert[] = {
          GNUNET_MY_query_param_rsa_public_key (pub),
          GNUNET_MY_query_param_rsa_signature (sig),
          GNUNET_MY_query_param_absolute_time (&abs_time),
          GNUNET_MY_query_param_absolute_time (&forever),
          GNUNET_MY_query_param_auto_from_type (&hc),
          GNUNET_MY_query_param_fixed_size (msg, strlen (msg)),
          GNUNET_MY_query_param_uint16 (&u16),
          GNUNET_MY_query_param_uint32 (&u32),
          GNUNET_MY_query_param_uint64 (&u64),
          GNUNET_MY_query_param_end
     };

      //FAIL HERE
     if (GNUNET_OK != GNUNET_MY_exec_prepared (context,
                                             statements_handle_insert,
                                             params_insert))
     {
          fprintf (stderr, 
                    "Failed to execute prepared statement\n");
          return 22;
     }
*/
     statements_handle_select = GNUNET_MYSQL_statement_prepare (context,
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
                                                                 " FROM test_my"
                                                                 " ORDER BY abs_time DESC "
                                                                 " LIMIT 1;");

     if (NULL == statements_handle_select)
     {
          fprintf(stderr, "Failed to prepared statement SELECT\n");
          return 1;
     }

     struct GNUNET_MY_QueryParam params_select[] = {
          GNUNET_MY_query_param_end
     };

     if (GNUNET_OK != GNUNET_MY_exec_prepared (context,
                                             statements_handle_select,
                                             params_select))
     {
          fprintf (stderr, "Failed to execute prepared statement\n");
          return 22;
     }

     return 0;
}


int 
main (int argc, const char * const argv[])
{
     struct GNUNET_CONFIGURATION_Handle *config;
     struct GNUNET_MYSQL_Context *context;

     int ret;

     GNUNET_log_setup (  "test-my",
                         "WARNING",
                         NULL);

     config = GNUNET_CONFIGURATION_create ();
     if (NULL == config)
     {
          fprintf (stderr, "Failed to create a configuration\n");
          return 1;
     }

     if (GNUNET_OK != GNUNET_CONFIGURATION_parse (config, "test_my.conf"))
     {
          fprintf (stderr, "Failed to parse configuaration\n");
          return 1;
     }

     context = GNUNET_MYSQL_context_create (config, 
                                             "datastore-mysql");
     if (NULL == context)
     {
          fprintf(stderr, "Failed to connect to database\n");
          return 77;
     }

     if (GNUNET_OK != GNUNET_MYSQL_statement_run (context,
                                                  "CREATE TABLE test_my("
                                                  "pub INT NOT NULL"
                                                  ", sig INT NOT NULL"
                                                  ", abs_time BIGINT NOT NULL"
                                                  ", forever BIGINT NOT NULL"
                                                  ", hash INT NOT NULL CHECK(LENGTH(hash)=64)"
                                                  ", vsize VARCHAR(32) NOT NULL"
                                                  ", u16 SMALLINT NOT NULL"
                                                  ", u32 INT NOT NULL"
                                                  ", u64 BIGINT NOT NULL"
                                                  ")"))
     {
          fprintf (stderr, 
                    "Failed to create table \n"); 
          GNUNET_MYSQL_statements_invalidate (context);    
          GNUNET_MYSQL_context_destroy (context);
          
          return 1;
     }

     ret = run_queries (context);

     if(GNUNET_OK != GNUNET_MYSQL_statement_run (context,
                                                  "DROP TABLE test_my"))
     {
          fprintf (stderr, "Failed to drop table test_my\n");
          GNUNET_MYSQL_statements_invalidate (context);
     }

     GNUNET_MYSQL_context_destroy (context);

     return ret;
}
