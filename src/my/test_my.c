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

/**
  * Setup prepared statements.
  *
  * @param mysql connection handle to initialize
  * @return 
          #GNUNET_OK on success
          #GNUNET_SYSERR on failure
  */

/** OK **/
static int
mysql_prepare (MYSQL * mysql)
{
     MYSQL_STMT *stmt;
     stmt = mysql_stmt_init (mysql);
#define PREPARE(name, sql, size)                                      \
     do {                                                             \
          int ret = mysql_stmt_prepare (stmt, sql, size);             \
          if (ret )                                                   \
          {                                                           \
               GNUNET_break (0);                                      \
               mysql_stmt_free_result (stmt);                         \
               return GNUNET_SYSERR;                                  \
          }                                                           \
          mysql_stmt_free_result (stmt);                              \
     } while (0);

     char *query1 =  "INSERT INTO test_my ("
               "pub"
               ",sig"
               ",abs_time"
               ",forever"
               ",hash"
               ",vsize"
               ",u16"
               ",u32"
               ",u64"
               ") VALUES "
               "(1, 2, 3, 4, 5, 6,"
               "7, 8, 9);";
     PREPARE("test_insert",
              query1,
               strlen (query1));

     char *query2 = "SELECT"
               "pub"
               ",sig"
               ",abs_time"
               ",forever"
               ",hash"
               ",vsize"
               ",u16"
               ",u32"
               ",u64"
               " FROM test_my"
               " ORDER BY abs_time DESC"
               " LIMIT 1;";

     PREPARE("test_select",
             query2,
             strlen (query2));

     return GNUNET_OK;
#undef PREPARE
}

/**
  * Run actual test queries.
  *
  * @param mysql coonection handle to initialize
  * @return 0 on succes
  */

/*** FIXE THIS FUNCTION ***/
static int
run_queries (MYSQL * mysql)
{
     struct GNUNET_CRYPTO_RsaPublicKey *pub;
//     struct GNUNET_CRYPTO_RsaPublicKey *pub2 = NULL;
     struct GNUNET_CRYPTO_RsaSignature *sig;
//     struct GNUNET_CRYPTO_RsaSignature *sig2 = NULL;
     struct GNUNET_TIME_Absolute abs_time = GNUNET_TIME_absolute_get () ;
//     struct GNUNET_TIME_Absolute abs_time2;
     struct GNUNET_TIME_Absolute forever = GNUNET_TIME_UNIT_FOREVER_ABS;
 //    struct GNUNET_TIME_Absolute forever2;
     struct GNUNET_HashCode hc;
//   struct GNUNET_HashCode hc2;
//     MYSQL_RES * result;
//     int ret;
     struct GNUNET_CRYPTO_RsaPrivateKey *priv;
     const char msg[] = "hello";
//     void *msg2;
     struct GNUNET_HashCode hmsg;
//     size_t msg2_len;
     uint16_t u16;
 //    uint16_t u162;
     uint32_t u32;
  //   uint32_t u322;
     uint64_t u64;
  //   uint64_t u642;

     priv = GNUNET_CRYPTO_rsa_private_key_create (1024);
     pub =  GNUNET_CRYPTO_rsa_private_key_get_public (priv);
     memset (&hmsg, 42, sizeof (hmsg));
     sig = GNUNET_CRYPTO_rsa_sign_fdh (priv,
                                       &hmsg);
     u16 = 16;
     u32 = 32;
     u64 = 64;

     struct GNUNET_CONFIGURATION_Handle * configuration_handle;
     configuration_handle = GNUNET_CONFIGURATION_create();

     char *query1 =  "INSERT INTO test_my ("
               "pub"
               ",sig"
               ",abs_time"
               ",forever"
               ",hash"
               ",vsize"
               ",u16"
               ",u32"
               ",u64"
               ") VALUES "
               "(1, 2, 3, 4, 5, 6,"
               "7, 8, 9);";

/*     char *query2 = "SELECT"
               "pub"
               ",sig"
               ",abs_time"
               ",forever"
               ",hash"
               ",vsize"
               ",u16"
               ",u32"
               ",u64"
               " FROM test_my"
               " ORDER BY abs_time DESC"
               " LIMIT 1;";
*/
       struct GNUNET_MYSQL_Context *context_insert = NULL;
 //    context_insert = GNUNET_MYSQL_context_create (configuration_handle,
 //                                                 NULL);

     struct GNUNET_MYSQL_StatementHandle *statements_handle = NULL;
 //    statements_handle = GNUNET_MYSQL_statement_prepare(context_insert, query1);


 //    {
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

/*          struct GNUNET_MY_QueryParam params_select[] = {
               GNUNET_MY_query_param_end
          };

          struct GNUNET_MY_Context *context_insert[] = {

          };

          struct GNUNET_MY_StatementHandle *statement_insert[] = {

          };
*/
/*          struct GNUNET_MY_ResultSpec results_select[] = {
               GNUNET_MY_result_spec_rsa_public_key (&pub2),
               GNUNET_MY_result_spec_rsa_signature (&sig2),
               GNUNET_MY_result_spec_absolute_time (&abs_time2),
               GNUNET_MY_result_spec_absolute_time (&forever2),
               GNUNET_MY_result_spec_auto_from_type (&hc2),
               GNUNET_MY_result_spec_variable_size (&msg2, &msg2_len),
               GNUNET_MY_result_spec_uint16 (&u162),
               GNUNET_MY_result_spec_uint32 (&u322),
               GNUNET_MY_result_spec_uint64 (&u642),
               GNUNET_MY_result_spec_end
          };
*/
          if(GNUNET_MY_exec_prepared ( context_insert,
                                        statements_handle,
                                        params_insert));
          {
               GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                         "Database failure: \n");
               
               //free result

               GNUNET_CRYPTO_rsa_signature_free (sig);
               GNUNET_CRYPTO_rsa_private_key_free (priv);
               GNUNET_CRYPTO_rsa_public_key_free (pub);
               return 1;
          }

          //free result

/*        result = GNUNET_MY_exec_prepared (mysql, "test_select", params_select);
          if(1 != mysql_fetch_length (result))
          {
               GNUNET_break (0);
               GNUNET_CRYPTO_rsa_signature_free (sig);
               GNUNET_CRYPTO_rsa_private_key_free (priv);
               GNUNET_CRYPTO_rsa_public_key_free (pub);

               return 1;
          }

          if (GNUNET_MY_exec_prepared (mysql
                                        , "test_select"
                                        , params_select))
          {
               GNUNET_break (0);
               GNUNET_CRYPTO_rsa_signature_free (sig);
               GNUNET_CRYPTO_rsa_private_key_free (priv);
               GNUNET_CRYPTO_rsa_public_key_free (pub);

               return 1;
          }


/*          ret = GNUNET_MY_extract_result (result,
                                        results_select,
                                        0);
          GNUNET_break (GNUNET_YES == ret);
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
     }
     
     GNUNET_CRYPTO_rsa_signature_free (sig);
     GNUNET_CRYPTO_rsa_private_key_free (priv);
     GNUNET_CRYPTO_rsa_public_key_free (pub);

     if (GNUNET_OK != ret)
          return 1;
 */    return 0;
}


/** OK **/
int 
main (int argc, const char * const argv[])
{
     
     MYSQL mysql ;
//     MYSQL_RES *result;

     int ret;

     char *hote = "";
     char *pseudo = "";
     char *mdp = "";
     char *database = "";

     mysql_init (&mysql);

     mysql_options (&mysql, 
                    MYSQL_READ_DEFAULT_GROUP,
                    NULL);

     GNUNET_log_setup (  "test-my",
                         "WARNING",
                         NULL);

     if ( mysql_real_connect (&mysql
                              ,hote
                              ,pseudo
                              ,mdp,database
                              ,0
                              ,NULL
                              ,0
                              )) 
     {
          fprintf(  stderr,
                    "Cannot run test, database connection failed : %s\n",
                    mysql_error (&mysql));
          GNUNET_break (0);

          return 0;
     }

     if (mysql_query (&mysql,  "CREATE TABLE test_my("
                              "pub INT"
                              ", sig INT"
                              ", abs_time BIGINT"
                              ", forever BIGINT"
                              ", hash INT"
                              ", vsize VARCHAR"
                              ", u16 SMALLINT"
                              ", u32 INT"
                              ", u64 BIGINT"
                              ")"))
     {
          fprintf (stderr, 
                    "Failed to create table : %s\n",
                    mysql_error (&mysql));

          mysql_close (&mysql);
          return 1;
     }

     if (GNUNET_OK != 
          mysql_prepare (&mysql))
     {
          GNUNET_break (0) ;
          mysql_close (&mysql);
          return 1;
     }

     ret = run_queries (&mysql);

     if (mysql_query (&mysql, 
                    "DROP TABLE test_my;"))
     {
          fprintf (stderr, "Failed to drop table : %s\n",
                         mysql_error (&mysql));
          mysql_close (&mysql);
          return 1;
     }

     mysql_close (&mysql);

     return ret;
}
