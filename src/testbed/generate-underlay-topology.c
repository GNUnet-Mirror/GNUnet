/*
      This file is part of GNUnet
      Copyright (C) 2008--2014 Christian Grothoff (and other contributing authors)

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
      Free Software Foundation, Inc., 59 Temple Place - Suite 330,
      Boston, MA 02111-1307, USA.
*/

/**
 * @file testbed/generate-underlay-topology.c
 * @brief Program to generate a database file containing given underlay topology
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "testbed_api_topology.h"
#include "sqlite3.h"

#define LOG(type, ...)                          \
  GNUNET_log (type, __VA_ARGS__)


#define LOG_ERROR(...)                          \
  LOG (GNUNET_ERROR_TYPE_ERROR, __VA_ARGS__)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(db, msg, level, cmd)                                 \
  do {                                                                  \
    GNUNET_log_from (level, "sqlite", _("`%s' failed at %s:%d with error: %s\n"), \
                     cmd, __FILE__,__LINE__, sqlite3_errmsg(db));  \
    if (msg != NULL)                                                    \
      GNUNET_asprintf(msg, _("`%s' failed at %s:%u with error: %s"), cmd, \
                      __FILE__, __LINE__, sqlite3_errmsg(db));     \
  } while(0)


/**
 * Handle to the sqlite3 database
 */
static struct sqlite3 *db;

/**
 * Prepared statement for inserting link values into db
 */
struct sqlite3_stmt *stmt_insert;

/**
 * The topology to generate
 */
enum GNUNET_TESTBED_TopologyOption topology;

/**
 * The number of peers to include in the topology
 */
static int num_peers;

/**
 * program result
 */
static int exit_result;


/**
 * Functions of this type are called to process underlay link
 *
 * @param cls closure
 * @param A offset of first peer
 * @param B offset of second peer
 * @param bandwidth the bandwidth of the link in bytes per second
 * @param latency the latency of link in milliseconds
 * @param loss the percentage of messages dropped on the link
 * @return GNUNET_OK to continue processing; GNUNET_SYSERR to abort
 */
static int
link_processor (void *cls,
                unsigned int A,
                unsigned int B,
                unsigned int bandwidth,
                unsigned int latency,
                unsigned int loss)
{
  if ( (SQLITE_OK != sqlite3_bind_int (stmt_insert, 1, A)) ||
       (SQLITE_OK != sqlite3_bind_int (stmt_insert, 2, B)) ||
       (SQLITE_OK != sqlite3_bind_int (stmt_insert, 3, bandwidth)) ||
       (SQLITE_OK != sqlite3_bind_int (stmt_insert, 4, latency)) ||
       (SQLITE_OK != sqlite3_bind_int (stmt_insert, 5, loss)) )
  {
    LOG_SQLITE (db, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_bind_int");
    return GNUNET_SYSERR;
  }
  if (SQLITE_DONE != sqlite3_step (stmt_insert))
  {
    LOG_SQLITE (db, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_step");
    return GNUNET_SYSERR;
  }
  FPRINTF (stdout, "%u -> %u\n", A, B);
  GNUNET_break (SQLITE_OK == sqlite3_reset (stmt_insert));
  //GNUNET_break (SQLITE_OK == sqlite3_clear_bindings (stmt_insert));
  if ( (SQLITE_OK != sqlite3_bind_int (stmt_insert, 1, B)) ||
       (SQLITE_OK != sqlite3_bind_int (stmt_insert, 2, A)) )
  {
    LOG_SQLITE (db, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_bind_int");
    return GNUNET_SYSERR;
  }
  if (SQLITE_DONE != sqlite3_step (stmt_insert))
  {
    LOG_SQLITE (db, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_step");
    return GNUNET_SYSERR;
  }
  FPRINTF (stdout, "%u -> %u\n", B, A);
  GNUNET_break (SQLITE_OK == sqlite3_reset (stmt_insert));
  return GNUNET_OK;
}


/**
 * Open the database file, creating a new database if not existing and setup the
 * whitelist table
 *
 * @param dbfile the database filename
 * @return GNUNET_OK upon success; GNUNET_SYSERR upon failure (error message has
 * to be printed)
 */
static int
setup_db (const char *dbfile)
{
  const char *query_create =
      "CREATE TABLE whitelist ("
      "id INTEGER,"
      "oid INTEGER,"
      "bandwidth INTEGER DEFAULT NULL,"
      "latency INTEGER DEFAULT NULL,"
      "loss INTEGER DEFAULT NULL,"
      " UNIQUE ("
      "  id,"
      "  oid"
      " ) ON CONFLICT IGNORE"
      ");";
  const char *query_insert =
      "INSERT INTO whitelist("
      " id,"
      " oid,"
      " bandwidth,"
      " latency,"
      " loss"
      ") VALUES ("
      " ?1,"
      " ?2,"
      " ?3,"
      " ?4,"
      " ?5);";
  int ret;

  ret = GNUNET_SYSERR;
  if (SQLITE_OK != sqlite3_open (dbfile, &db))
  {
    LOG_SQLITE (db, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_open");
    goto err_ret;
  }
  if (0 != sqlite3_exec (db, query_create, NULL, NULL, NULL))
  {
    LOG_SQLITE (db, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_exec");
    FPRINTF (stderr, "Error: %d.  Perhaps the database `%s' already exits.\n",
             sqlite3_errcode (db),
             dbfile);
    goto err_ret;
  }
  GNUNET_break (0 == sqlite3_exec (db, "PRAGMA synchronous = 0;", NULL, NULL, NULL));
  if (SQLITE_OK != sqlite3_prepare_v2 (db, query_insert, -1,
                                       &stmt_insert, NULL))
  {
    LOG_SQLITE (db, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_prepare_v2");
    goto err_ret;
  }
  ret = GNUNET_OK;

 err_ret:
  return ret;
}


/**
 * Main run function.
 *
 * @param cls NULL
 * @param args arguments passed to GNUNET_PROGRAM_run
 * @param cfgfile the path to configuration file
 * @param cfg the configuration file handle
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  const char *dbfile;
  const char *topology_string;
  unsigned int arg_uint1;
  unsigned int arg_uint2;
  const char *arg_str1;
  const char *value;
  unsigned int argc;

  argc = 0;
  arg_uint1 = 0; /* make compilers happy */
  arg_uint2 = 0; /* make compilers happy */
  if (NULL == args)
  {
    LOG_ERROR (_("Need at least 2 arguments\n"));
    return;
  }
  if (NULL == (dbfile = args[argc++]))
  {
    LOG_ERROR (_("Database filename missing\n"));
    return;
  }
  if (GNUNET_OK != setup_db (dbfile))
    return;
  if (NULL == (topology_string = args[argc++]))
  {
    LOG_ERROR (_("Topology string missing\n"));
    return;
  }
  if (GNUNET_YES != GNUNET_TESTBED_topology_get_ (&topology, topology_string))
  {
    LOG_ERROR (_("Invalid topology: %s\n"), topology_string);
    return;
  }
  arg_str1 = NULL;
  /* parse for first TOPOOPT.  This can either be arg_uint1 or arg_str1 */
  switch (topology)
  {
  case GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI:
  case GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD_RING:
  case GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD:
  case GNUNET_TESTBED_TOPOLOGY_SCALE_FREE:
    if (NULL == (value = args[argc++]))
    {
      LOG_ERROR (_("An argument is missing for given topology `%s'\n"),
                 topology_string);
      return;
    }
    if (-1 == SSCANF (value, "%u", &arg_uint1))
    {
      LOG_ERROR (_("Invalid argument `%s' given as topology argument\n"),
                 value);
      return;
    }
    break;
  case GNUNET_TESTBED_TOPOLOGY_FROM_FILE:
    if (NULL == (arg_str1 = args[argc++]))
    {
      LOG_ERROR (_("Filename argument missing for topology `%s'\n"),
                 topology_string);
      return;
    }
    break;
  default:
    break;
  }
  /* parse for second TOPOOPT.  Only required for SCALE_FREE topology */
  switch (topology)
  {
  case GNUNET_TESTBED_TOPOLOGY_SCALE_FREE:
    if (NULL == (value = args[argc++]))
    {
      LOG_ERROR (_("Second argument for topology `%s' is missing\n"),
                 topology_string);
      return;
    }
    if (-1 == SSCANF (value, "%u", &arg_uint2))
    {
      LOG_ERROR (_("Invalid argument `%s'; expecting unsigned int\n"), value);
      return;
    }
    break;
  default:
    break;
  }
  /* contruct topologies */
  switch (topology)
  {
  case GNUNET_TESTBED_TOPOLOGY_LINE:
  case GNUNET_TESTBED_TOPOLOGY_RING:
  case GNUNET_TESTBED_TOPOLOGY_CLIQUE:
  case GNUNET_TESTBED_TOPOLOGY_2D_TORUS:
    GNUNET_TESTBED_underlay_construct_ (num_peers, link_processor, NULL,
                                        topology);
    break;
  case GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI:
  case GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD_RING:
  case GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD:
    GNUNET_TESTBED_underlay_construct_ (num_peers, link_processor, NULL,
                                        topology,
                                        arg_uint1);
    break;
  case GNUNET_TESTBED_TOPOLOGY_FROM_FILE:
    GNUNET_TESTBED_underlay_construct_ (num_peers, link_processor, NULL,
                                        topology,
                                        arg_str1);
    break;
  case GNUNET_TESTBED_TOPOLOGY_SCALE_FREE:
    GNUNET_TESTBED_underlay_construct_ (num_peers, link_processor, NULL,
                                        topology,
                                        arg_uint1,
                                        arg_uint2);
    break;
  default:
    GNUNET_assert (0);
  }
}


/**
 * Main
 */
int
main (int argc, char *const argv[])
{
  struct GNUNET_GETOPT_CommandLineOption option[] = {
    {'p', "num-peers", "COUNT",
     gettext_noop ("create COUNT number of peers"),
     GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_peers},
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  exit_result = GNUNET_SYSERR;
  ret =
      GNUNET_PROGRAM_run (argc, argv, "gnunet-underlay-topology",
                          _("Generates SQLite3 database representing a given underlay topology.\n"
                            "Usage: gnunet-underlay-topology [OPTIONS] db-filename TOPO [TOPOOPTS]\n"
                            "The following options are available for TOPO followed by TOPOOPTS if applicable:\n"
                            "\t LINE\n"
                            "\t RING\n"
                            "\t RANDOM <num_rnd_links>\n"
                            "\t SMALL_WORLD <num_rnd_links>\n"
                            "\t SMALL_WORLD_RING <num_rnd_links>\n"
                            "\t CLIQUE\n"
                            "\t 2D_TORUS\n"
                            "\t SCALE_FREE <cap> <m>\n"
                            "\t FROM_FILE <filename>\n"
                            "TOPOOPTS:\n"
                            "\t num_rnd_links: The number of random links\n"
                            "\t cap: the maximum number of links a node can have\n"
                            "\t m: the number of links a node should have while joining the network\n"
                            "\t filename: the path of the file which contains topology information\n"
                            "NOTE: the format of the above file is descibed here: https://www.gnunet.org/content/topology-file-format\n"),
                          option, &run, NULL);
  if (NULL != stmt_insert)
    sqlite3_finalize (stmt_insert);
  if (NULL != db)
    GNUNET_break (SQLITE_OK == sqlite3_close (db));
  if ((GNUNET_OK != ret) || (GNUNET_OK != exit_result))
    return 1;
  return 0;
}
