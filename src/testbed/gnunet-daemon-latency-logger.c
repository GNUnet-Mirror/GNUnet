/*
      This file is part of GNUnet
      (C) 2008--2014 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-daemon-latency-logger.c
 * @brief log latency values from neighbour connections into an SQLite database
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include <sqlite3.h>


/**
 * Logging shorthand
 */
#define LOG(type,...)                           \
  GNUNET_log (type, __VA_ARGS__)

/**
 * Debug logging shorthand
 */
#define DEBUG(...)                              \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

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
 * Entry type to be used in the map to store old latency values
 */
struct Entry
{
  /**
   *  The peer's identity
   */
  struct GNUNET_PeerIdentity id;

  /**
   * The last known value for latency
   */
  unsigned int latency;

};


/**
 * Handle to the map used to store old latency values for peers
 */
static struct GNUNET_CONTAINER_MultiPeerMap *map;

/**
 * The SQLite database handle
 */
static struct sqlite3 *db;

/**
 * Handle to the ATS performance subsystem
 */
struct GNUNET_ATS_PerformanceHandle *ats;

/**
 * Prepared statement for inserting values into the database table
 */
struct sqlite3_stmt *stmt_insert;

/**
 * Shutdown task identifier
 */
GNUNET_SCHEDULER_TaskIdentifier shutdown_task;


/**
 * @ingroup hashmap
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current public key
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
free_iterator (void *cls,
               const struct GNUNET_PeerIdentity *key,
               void *value)
{
  struct Entry *e = cls;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (map, key, e));
  GNUNET_free (e);
  return GNUNET_YES;
}


/**
 * Shutdown
 *
 * @param cls NULL
 * @param tc task context from scheduler
 * @return
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  shutdown_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_ATS_performance_done (ats);
  ats = NULL;
  if (NULL != stmt_insert)
  {
    sqlite3_finalize (stmt_insert);
    stmt_insert = NULL;
  }
  GNUNET_break (SQLITE_OK == sqlite3_close (db));
  db = NULL;
  if (NULL != map)
  {
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_CONTAINER_multipeermap_iterate (map, free_iterator, NULL));
    GNUNET_CONTAINER_multipeermap_destroy (map);
    map = NULL;
  }
}

/**
 * Signature of a function that is called with QoS information about an address.
 *
 * @param cls closure
 * @param address the address
 * @param address_active #GNUNET_YES if this address is actively used
 *        to maintain a connection to a peer;
 *        #GNUNET_NO if the address is not actively used;
 *        #GNUNET_SYSERR if this address is no longer available for ATS
 * @param bandwidth_out assigned outbound bandwidth for the connection
 * @param bandwidth_in assigned inbound bandwidth for the connection
 * @param ats performance data for the address (as far as known)
 * @param ats_count number of performance records in 'ats'
 */
static void
addr_info_cb (void *cls,
              const struct GNUNET_HELLO_Address *address,
              int address_active,
              struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
              struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
              const struct GNUNET_ATS_Information *ats,
              uint32_t ats_count)
{
  static const char *query_insert =
      "INSERT INTO ats_info("
      " id,"
      " val,"
      " timestamp"
      ") VALUES ("
      " ?1,"
      " ?2,"
      " datetime('now')"
      ");";
  struct Entry *entry;
  int latency;
  unsigned int cnt;

  if (NULL == address)
  {
    /* ATS service temporarily disconnected */
    return;
  }

  GNUNET_assert (NULL != db);
  if (GNUNET_YES != address_active)
    return;
  for (cnt = 0; cnt < ats_count; cnt++)
  {
    if (GNUNET_ATS_QUALITY_NET_DELAY == ntohl (ats[cnt].type))
      goto insert;
  }
  return;

 insert:
  latency = (int) ntohl (ats[cnt].value);
  entry = NULL;
  if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (map,
                                                            &address->peer))
  {
    entry = GNUNET_CONTAINER_multipeermap_get (map, &address->peer);
    GNUNET_assert (NULL != entry);
    if (latency == entry->latency)
      return;
  }
  if (NULL == stmt_insert)
  {
    if (SQLITE_OK != sqlite3_prepare_v2 (db, query_insert, -1, &stmt_insert,
                                         NULL))
    {
      LOG_SQLITE (db, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_prepare_v2");
      goto err_shutdown;
    }
  }
  if ( (SQLITE_OK != sqlite3_bind_text (stmt_insert, 1,
                                        GNUNET_i2s (&address->peer), -1,
                                        SQLITE_STATIC)) ||
        (SQLITE_OK != sqlite3_bind_int (stmt_insert, 2, latency)) )
  {
     LOG_SQLITE (db, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_bind_text");
     goto err_shutdown;
  }
  if (SQLITE_DONE != sqlite3_step (stmt_insert))
  {
    LOG_SQLITE (db, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_step");
    goto err_shutdown;
  }
  if (SQLITE_OK != sqlite3_reset (stmt_insert))
  {
    LOG_SQLITE (db, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_insert");
    goto err_shutdown;
  }
  if (NULL == entry)
  {
    entry = GNUNET_new (struct Entry);
    entry->id = address->peer;
    GNUNET_CONTAINER_multipeermap_put (map,
                                       &entry->id, entry,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  entry->latency = latency;
  return;

 err_shutdown:
      GNUNET_SCHEDULER_shutdown ();
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  const char *query_create =
      "CREATE TABLE ats_info ("
      "id TEXT,"
      "val INTEGER,"
      "timestamp NUMERIC"
      ");";
  char *dbfile;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (c, "LATENCY-LOGGER",
                                                            "DBFILE",
                                                            &dbfile))
  {
    GNUNET_break (0);
    return;
  }
  if (SQLITE_OK != sqlite3_open (dbfile, &db))
  {
    if (NULL != db)
    {
      LOG_SQLITE (db, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite_open_v2");
      sqlite3_close (db);
    }
    else
      LOG (GNUNET_ERROR_TYPE_ERROR, "Cannot open sqlite file %s\n", dbfile);
    GNUNET_free (dbfile);
    return;
  }
  if (0 != sqlite3_exec (db, query_create, NULL, NULL, NULL))
    DEBUG ("SQLite Error: %d.  Perhaps the database `%s' already exits.\n",
           sqlite3_errcode (db), dbfile);
  DEBUG ("Opened database %s\n", dbfile);
  GNUNET_free (dbfile);
  dbfile = NULL;
  ats = GNUNET_ATS_performance_init (c, &addr_info_cb, NULL);
  map = GNUNET_CONTAINER_multipeermap_create (30, GNUNET_YES);
  shutdown_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                                &do_shutdown, NULL);
}


/**
 * Execution entry point
 */
int
main (int argc, char * const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv, "gnunet-daemon-latency-logger",
                           _("Daemon to log latency values of connections to neighbours"),
                           options, &run, NULL)) ? 0 : 1;
  GNUNET_free ((void*) argv);
  return ret;
}
