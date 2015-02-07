/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-daemon-testbed-blacklist.c
 * @brief daemon to restrict incoming connections from other peers at the
 *          transport layer of a peer
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_ats_service.h"
#include "gnunet_testing_lib.h"
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
 * The map to store the peer identities to allow/deny
 */
static struct GNUNET_CONTAINER_MultiPeerMap *map;

/**
 * The database connection
 */
static struct sqlite3 *db;

/**
 * The blacklist handle we obtain from transport when we register ourselves for
 * access control
 */
struct GNUNET_TRANSPORT_Blacklist *bh;

/**
 * The hostkeys file
 */
struct GNUNET_DISK_FileHandle *hostkeys_fd;

/**
 * The hostkeys map
 */
static struct GNUNET_DISK_MapHandle *hostkeys_map;

/**
 * The hostkeys data
 */
static void *hostkeys_data;

/**
 * Handle to the transport service.  This is used for setting link metrics
 */
static struct GNUNET_TRANSPORT_Handle *transport;

/**
 * The number of hostkeys in the hostkeys array
 */
static unsigned int num_hostkeys;

/**
 * Task for shutdown
 */
static struct GNUNET_SCHEDULER_Task * shutdown_task;


/**
 * @ingroup hashmap
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
iterator (void *cls, const struct GNUNET_PeerIdentity *key, void *value)
{
  GNUNET_assert (GNUNET_YES == GNUNET_CONTAINER_multipeermap_remove (map, key,
                                                                     value));
  return GNUNET_YES;
}


/**
 * Cleaup and destroy the map
 */
static void
cleanup_map ()
{
  if (NULL != map)
  {
    GNUNET_assert (GNUNET_SYSERR != GNUNET_CONTAINER_multipeermap_iterate (map,
                                                                           &iterator,
                                                                           NULL));
    GNUNET_CONTAINER_multipeermap_destroy (map);
    map = NULL;
  }
}


/**
 * Function that decides if a connection is acceptable or not.
 *
 * @param cls closure
 * @param pid peer to approve or disapproave
 * @return GNUNET_OK if the connection is allowed, GNUNET_SYSERR if not
 */
static int
check_access (void *cls, const struct GNUNET_PeerIdentity * pid)
{
  int contains;

  GNUNET_assert (NULL != map);
  contains = GNUNET_CONTAINER_multipeermap_contains (map, pid);
  if (GNUNET_YES == contains)
  {
    DEBUG ("Permitting `%s'\n", GNUNET_i2s (pid));
    return GNUNET_OK;
  }
  DEBUG ("Not permitting `%s'\n", GNUNET_i2s (pid));
  return GNUNET_SYSERR;
}


static int
get_identity (unsigned int offset, struct GNUNET_PeerIdentity *id)
{
  struct GNUNET_CRYPTO_EddsaPrivateKey private_key;

  if (offset >= num_hostkeys)
    return GNUNET_SYSERR;
  (void) memcpy (&private_key,
                 hostkeys_data + (offset * GNUNET_TESTING_HOSTKEYFILESIZE),
                 GNUNET_TESTING_HOSTKEYFILESIZE);
  GNUNET_CRYPTO_eddsa_key_get_public (&private_key, &id->public_key);
  return GNUNET_OK;
}


/**
 * Whilelist entry
 */
struct WhiteListRow
{
  /**
   * Next ptr
   */
  struct WhiteListRow *next;

  /**
   * The offset where to find the hostkey for the peer
   */
  unsigned int id;

  /**
   * Latency to be assigned to the link
   */
  int latency;

};


/**
 * Function to load keys
 */
static int
load_keys (const struct GNUNET_CONFIGURATION_Handle *c)
{
  char *data_dir;
  char *idfile;
  uint64_t fsize;

  data_dir = NULL;
  idfile = NULL;
  fsize = 0;
  data_dir = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_DATADIR);
  GNUNET_asprintf (&idfile, "%s/testing_hostkeys.ecc", data_dir);
  GNUNET_free (data_dir);
  data_dir = NULL;
  if (GNUNET_OK !=
      GNUNET_DISK_file_size (idfile, &fsize, GNUNET_YES, GNUNET_YES))
  {
    GNUNET_free (idfile);
    return GNUNET_SYSERR;
  }
  if (0 != (fsize % GNUNET_TESTING_HOSTKEYFILESIZE))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Incorrect hostkey file format: %s\n"), idfile);
    GNUNET_free (idfile);
    return GNUNET_SYSERR;
  }
  hostkeys_fd = GNUNET_DISK_file_open (idfile, GNUNET_DISK_OPEN_READ,
                                       GNUNET_DISK_PERM_NONE);
  if (NULL == hostkeys_fd)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", idfile);
    GNUNET_free (idfile);
    return GNUNET_SYSERR;
  }
  GNUNET_free (idfile);
  idfile = NULL;
  hostkeys_data = GNUNET_DISK_file_map (hostkeys_fd,
                                        &hostkeys_map,
                                        GNUNET_DISK_MAP_TYPE_READ,
                                        fsize);
  if (NULL == hostkeys_data)
  {

    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "mmap");
    return GNUNET_SYSERR;
  }
  num_hostkeys = fsize / GNUNET_TESTING_HOSTKEYFILESIZE;
  return GNUNET_OK;
}


/**
 * Function to unload keys
 */
static void
unload_keys ()
{
  if (NULL != hostkeys_map)
  {
    GNUNET_assert (NULL != hostkeys_data);
    GNUNET_DISK_file_unmap (hostkeys_map);
    hostkeys_map = NULL;
    hostkeys_data = NULL;
  }
  if (NULL != hostkeys_fd)
  {
    GNUNET_DISK_file_close (hostkeys_fd);
    hostkeys_fd = NULL;
  }
}


/**
 * Shutdown task to cleanup our resources and exit.
 *
 * @param cls NULL
 * @param tc scheduler task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != transport)
  {
    GNUNET_TRANSPORT_disconnect (transport);
    transport = NULL;
  }
  cleanup_map ();
  unload_keys ();
  if (NULL != bh)
    GNUNET_TRANSPORT_blacklist_cancel (bh);
}


/**
 * Function to read whitelist rows from the database
 *
 * @param db the database connection
 * @param pid the identity of this peer
 * @param wl_rows where to store the retrieved whitelist rows
 * @return GNUNET_SYSERR upon error OR the number of rows retrieved
 */
static int
db_read_whitelist (struct sqlite3 *db, int pid, struct WhiteListRow **wl_rows)
{
  static const char *query_wl = "SELECT oid, latency FROM whitelist WHERE (id == ?);";
  struct sqlite3_stmt *stmt_wl;
  struct WhiteListRow *lr;
  int nrows;
  int ret;

  if (SQLITE_OK != (ret = sqlite3_prepare_v2 (db, query_wl, -1, &stmt_wl, NULL)))
  {
    LOG_SQLITE (db, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_prepare_v2");
    return GNUNET_SYSERR;
  }
  if (SQLITE_OK != (ret = sqlite3_bind_int (stmt_wl, 1, pid)))
  {
    LOG_SQLITE (db, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_bind_int");
    sqlite3_finalize (stmt_wl);
    return GNUNET_SYSERR;
  }
  nrows = 0;
  do
  {
    ret = sqlite3_step (stmt_wl);
    if (SQLITE_ROW != ret)
      break;
    nrows++;
    lr = GNUNET_new (struct WhiteListRow);
    lr->id = sqlite3_column_int (stmt_wl, 0);
    lr->latency = sqlite3_column_int (stmt_wl, 1);
    lr->next = *wl_rows;
    *wl_rows = lr;
  } while (1);
  sqlite3_finalize (stmt_wl);
  return nrows;
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
  char *dbfile;
  struct WhiteListRow *wl_head;
  struct WhiteListRow *wl_entry;
  struct GNUNET_PeerIdentity identity;
  struct GNUNET_ATS_Information params[1];
  unsigned long long pid;
  unsigned int nrows;
  int ret;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (c, "TESTBED",
                                                            "PEERID", &pid))
  {
    GNUNET_break (0);
    return;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (c, "TESTBED-UNDERLAY",
                                                            "DBFILE",
                                                            &dbfile))
  {
    GNUNET_break (0);
    return;
  }
  if (SQLITE_OK != (ret = sqlite3_open_v2 (dbfile, &db, SQLITE_OPEN_READONLY, NULL)))
  {
    if (NULL != db)
    {
      LOG_SQLITE (db, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite_open_v2");
      GNUNET_break (SQLITE_OK == sqlite3_close (db));
    }
    else
      LOG (GNUNET_ERROR_TYPE_ERROR, "Cannot open sqlite file %s\n", dbfile);
    GNUNET_free (dbfile);
    return;
  }
  DEBUG ("Opened database %s\n", dbfile);
  GNUNET_free (dbfile);
  dbfile = NULL;
  wl_head = NULL;
  if (GNUNET_OK != load_keys (c))
      goto close_db;

  transport = GNUNET_TRANSPORT_connect (c, NULL, NULL, NULL, NULL, NULL);
  if (NULL == transport)
  {
    GNUNET_break (0);
    return;
  }
  /* read and process whitelist */
  nrows = 0;
  wl_head = NULL;
  nrows = db_read_whitelist (db, pid, &wl_head);
  if ((GNUNET_SYSERR == nrows) || (0 == nrows))
  {
    GNUNET_TRANSPORT_disconnect (transport);
    goto close_db;
  }
  map = GNUNET_CONTAINER_multipeermap_create (nrows, GNUNET_NO);
  params[0].type = GNUNET_ATS_QUALITY_NET_DELAY;
  while (NULL != (wl_entry = wl_head))
  {
    wl_head = wl_entry->next;
    params[0].value = wl_entry->latency;
    GNUNET_assert (GNUNET_OK == get_identity (wl_entry->id, &identity));
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONTAINER_multipeermap_put (map, &identity, &identity,
                                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
    DEBUG ("Setting %u ms latency to peer `%s'\n",
           wl_entry->latency,
           GNUNET_i2s (&identity));
    GNUNET_TRANSPORT_set_traffic_metric (transport,
                                         &identity,
                                         GNUNET_YES,
                                         GNUNET_YES, /* FIXME: Separate inbound, outboud metrics */
                                         params, 1);
    GNUNET_free (wl_entry);
  }
  bh = GNUNET_TRANSPORT_blacklist (c, &check_access, NULL);
  shutdown_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                                &do_shutdown, NULL);

 close_db:
  GNUNET_break (SQLITE_OK == sqlite3_close (db));
  return;
}


/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
#ifdef SQLITE_CONFIG_MMAP_SIZE
  (void) sqlite3_config (SQLITE_CONFIG_MMAP_SIZE, 512000, 256000000);
#endif
  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv, "testbed-underlay",
                           _
                           ("Daemon to restrict underlay network in testbed deployments"),
                           options, &run, NULL)) ? 0 : 1;
  GNUNET_free ((void*) argv);
  return ret;
}
