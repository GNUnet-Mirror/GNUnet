/*
      This file is part of GNUnet
      (C) 2008--2013 Christian Grothoff (and other contributing authors)

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


#define LOG_SQLITE_ERROR(ret)                                           \
  LOG (GNUNET_ERROR_TYPE_ERROR, "sqlite error: %s", sqlite3_errstr (ret))


/**
 * Allow access from the peers read from the whitelist
 */
#define ACCESS_ALLOW 1

/**
 * Deny access from the peers read from the blacklist
 */
#define ACCESS_DENY 0

/**
 * The map to store the peer identities to allow/deny
 */
static struct GNUNET_CONTAINER_MultiPeerMap *map;


/**
 * The map to store the peer identities to allow/deny
 */
static struct GNUNET_CONTAINER_MultiPeerMap *blacklist_map;

/**
 * The database connection
 */
static struct sqlite3 *db;

/**
 * The array of peer identities we read from whitelist/blacklist
 */
static struct GNUNET_PeerIdentity *ilist;

/**
 * The blacklist handle we obtain from transport when we register ourselves for
 * access control
 */
struct GNUNET_TRANSPORT_Blacklist *bh;

/**
 * The peer ID map
 */
static struct GNUNET_DISK_MapHandle *idmap;

/**
 * The hostkeys data
 */
static struct GNUNET_PeerIdentity *hostkeys;

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
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

/**
 * Are we allowing or denying access from peers
 */
static int mode;


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
 * Shutdown task to cleanup our resources and exit.
 *
 * @param cls NULL
 * @param tc scheduler task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  cleanup_map ();
  if (NULL != bh)
    GNUNET_TRANSPORT_blacklist_cancel (bh);
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

  if (NULL != map)
    contains = GNUNET_CONTAINER_multipeermap_contains (map, pid);
  else
    contains = GNUNET_NO;
  if (ACCESS_DENY == mode)
    return (contains) ? GNUNET_SYSERR : GNUNET_OK;
  return (contains) ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Setup the access control by reading the given file containing peer identities
 * and then establishing blacklist handler with the peer's transport service
 *
 * @param fname the filename to read the list of peer identities
 * @param cfg the configuration for connecting to the peer's transport service
 */
static void
setup_ac (const char *fname, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  uint64_t fsize;
  unsigned int npeers;
  unsigned int cnt;

  GNUNET_assert (GNUNET_OK != GNUNET_DISK_file_size (fname, &fsize, GNUNET_NO,
                                                     GNUNET_YES));
  if (0 != (fsize % sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break (0);
    return;
  }
  npeers = fsize / sizeof (struct GNUNET_PeerIdentity);
  if (0 != npeers)
  {
    map = GNUNET_CONTAINER_multipeermap_create (npeers, GNUNET_YES);
    ilist = GNUNET_malloc_large (fsize);
    GNUNET_assert (fsize == GNUNET_DISK_fn_read (fname, ilist, fsize));
  }
  for (cnt = 0; cnt < npeers; cnt++)
  {
    if (GNUNET_SYSERR == GNUNET_CONTAINER_multipeermap_put (map, &ilist[cnt],
                                                            &ilist[cnt],
                                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      cleanup_map ();
      GNUNET_free (ilist);
      return;
    }
  }
  shutdown_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                                &do_shutdown, NULL);
  bh = GNUNET_TRANSPORT_blacklist (cfg, &check_access, NULL);
}


/**
 * Function to blacklist a peer
 *
 * @param offset the offset where to find the peer's hostkey in the array of hostkeys
 */
static void
blacklist_peer (unsigned int offset)
{
  struct GNUNET_CRYPTO_EddsaPrivateKey private_key;
  struct GNUNET_PeerIdentity id;

  (void) memcpy (&private_key, &hostkeys[offset], sizeof (private_key));
  GNUNET_CRYPTO_eddsa_key_get_public (&private_key, &id.public_key);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multipeermap_put (map, &id, &id,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

}

/**
 * Blacklist peer
 */
struct BlackListRow
{
  /**
   * Next ptr
   */
  struct BlackListRow *next;

  /**
   * The offset where to find the hostkey for the peer
   */
  unsigned int id;
};


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
   * Bandwidth to be assigned to the link
   */
  int bandwidth;

  /**
   * Latency to be assigned to the link
   */
  int latency;

  /**
   * Loss to be assigned to the link
   */
  int loss;
};


/**
 * Add peers in the blacklist to the blacklist map
 */
static int
map_populate (struct BlackListRow *head,
              struct GNUNET_CONTAINER_MultiPeerMap *map,
              const struct GNUNET_PeerIdentity *hostkeys)
{
  struct BlackListRow *row;
  int ret;

  while (NULL != (row = head))
  {
    if (head->id >= num_hostkeys)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Hostkey index %u out of max range %u\n",
           row->id, num_hostkeys);
    }
    head = row->next;
    ret = GNUNET_CONTAINER_multipeermap_put (blacklist_map, &hostkeys[row->id],
                                       (void *) &hostkeys[row->id],
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    if (GNUNET_OK != ret)
      return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function to load keys
 */
static int
load_keys (const struct GNUNET_CONFIGURATION_Handle *c)
{
  char *data_dir;
  char *idfile;
  struct GNUNET_DISK_FileHandle *fd;
  uint64_t fsize;

  data_dir = NULL;
  idfile = NULL;
  fd = NULL;
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
  fd = GNUNET_DISK_file_open (idfile, GNUNET_DISK_OPEN_READ,
                              GNUNET_DISK_PERM_NONE);
  if (NULL == fd)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", idfile);
    GNUNET_free (idfile);
    return GNUNET_SYSERR;
  }
  GNUNET_free (idfile);
  idfile = NULL;
  hostkeys = (struct GNUNET_PeerIdentity *)
      GNUNET_DISK_file_map (fd, &idmap, GNUNET_DISK_MAP_TYPE_READ, fsize);
  if (NULL == hostkeys)
    num_hostkeys = fsize / GNUNET_TESTING_HOSTKEYFILESIZE;
  return GNUNET_OK;
}


/**
 * Function to read blacklist rows from the database
 *
 * @param db the database connection
 * @param pid the identity of this peer
 * @param bl_rows where to store the retrieved blacklist rows
 * @return GNUNET_SYSERR upon error OR the number of rows retrieved
 */
static int
db_read_blacklist (struct sqlite3 *db, unsigned int pid, struct BlackListRow **bl_rows)
{
  static const char *query_bl = "SELECT (oid) FROM blacklist WHERE (id == ?);";
  struct sqlite3_stmt *stmt_bl;
  struct BlackListRow *lr;
  int nrows;
  int peer_id;
  int ret;

  if (SQLITE_OK != (ret = sqlite3_prepare_v2 (db, query_bl, -1, &stmt_bl, NULL)))
  {
    LOG_SQLITE_ERROR (ret);
    return GNUNET_SYSERR;
  }
  if (SQLITE_OK != (ret = sqlite3_bind_int (stmt_bl, 1, pid)))
  {
    LOG_SQLITE_ERROR (ret);
    sqlite3_finalize (stmt_bl);
    return GNUNET_SYSERR;
  }
  nrows = 0;
  do
  {
    ret = sqlite3_step (stmt_bl);
    if (SQLITE_ROW != ret)
      break;
    peer_id = sqlite3_column_int (stmt_bl, 1);
    lr = GNUNET_new (struct BlackListRow);
    lr->id = peer_id;
    lr->next = *bl_rows;
    *bl_rows = lr;
    nrows++;
  } while (1);
  sqlite3_finalize (stmt_bl);
  stmt_bl = NULL;
  return nrows;
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
db_read_whitelist (struct sqlite3 *db, unsigned int pid, struct WhiteListRow **wl_rows)
{
  static const char *query_wl = "SELECT (oid, bandwidth, latency, loss) FROM whitelist WHERE (id == ?);";
  struct sqlite3_stmt *stmt_wl;
  struct WhiteListRow *lr;
  int nrows;
  int ret;
  
  if (SQLITE_OK != (ret = sqlite3_prepare_v2 (db, query_wl, -1, &stmt_wl, NULL)))
  {
    LOG_SQLITE_ERROR (ret);
    return GNUNET_SYSERR;
  }
  if (SQLITE_OK != (ret = sqlite3_bind_int (stmt_wl, 1, pid)))
  {
    LOG_SQLITE_ERROR (ret);
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
    lr->id = sqlite3_column_int (stmt_wl, 1);
    lr->bandwidth = sqlite3_column_int (stmt_wl, 2);
    lr->latency = sqlite3_column_int (stmt_wl, 3);
    lr->loss = sqlite3_column_int (stmt_wl, 4);
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
  struct BlackListRow *bl_head;
  struct BlackListRow *bl_entry;
  struct WhiteListRow *wl_head;
  struct WhiteListRow *wl_entry;
  struct GNUNET_ATS_Information triplet[3];
  unsigned long long pid;
  unsigned int nrows;
  int ret;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (c, "TESTBED",
                                                            "PEERID", &pid))
  {
    GNUNET_break (0);
    return;
  }
  transport = GNUNET_TRANSPORT_connect (c, NULL, NULL, NULL, NULL, NULL);
  if (NULL == transport)
  {
    GNUNET_break (0);
    return;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (c, "TESTBED",
                                                            "UNDERLAY_DB",
                                                            &dbfile))
  {
    GNUNET_break (0);
    return;
  }
  if (SQLITE_OK != (ret = sqlite3_open_v2 (dbfile, &db, SQLITE_OPEN_READONLY, NULL)))
  {
    LOG_SQLITE_ERROR (ret);
    GNUNET_free (dbfile);
    return;
  }
  DEBUG ("Opened database %s\n", dbfile);
  GNUNET_free (dbfile);
  dbfile = NULL;
  bl_head = NULL;
  wl_head = NULL;
  nrows = db_read_blacklist (db, pid, &bl_head);
  if (GNUNET_SYSERR == nrows)
    goto close_db;
  if (nrows > 0)
  {
    blacklist_map = GNUNET_CONTAINER_multipeermap_create (nrows, GNUNET_YES);
    if (GNUNET_OK != load_keys (c))
      goto close_db;
  }
  /* process whitelist */
  nrows = 0;
  wl_head = NULL;
  nrows = db_read_whitelist (db, pid, &wl_head);
  if ((GNUNET_SYSERR == nrows) || (0 == nrows))
    goto close_db;
  triplet[0].type = 0; //FIXME: not implemented: GNUNET_ATS_QUALITY_NET_THROUGHPUT
  triplet[1].type = GNUNET_ATS_QUALITY_NET_DELAY;
  triplet[2].type =  0; //FIXME: not implemented: GNUNET_ATS_QUALITY_NET_LOSSRATE;
  while (NULL != (wl_entry = wl_head))
  {
    wl_head = wl_entry->next;
    triplet[0].value = wl_entry->bandwidth; //FIXME: bandwidth != throughput !!
    triplet[1].value = wl_entry->latency;
    triplet[2].value = wl_entry->loss;
    GNUNET_TRANSPORT_set_traffic_metric (transport,
                                         &hostkeys[wl_entry->id],
                                         GNUNET_YES,
                                         GNUNET_YES, /* FIXME: Separate inbound, outboud metrics */
                                         triplet, 3);
  }

 close_db:
  while (NULL != (bl_entry = bl_head))
  {
    bl_head = bl_entry->next;
    GNUNET_free (bl_entry);
  }
  GNUNET_break (GNUNET_OK == sqlite3_close (db));
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
       GNUNET_PROGRAM_run (argc, argv, "gnunet-daemon-testbed-underlay",
                           _
                           ("Daemon to restrict underlay network in testbed deployments"),
                           options, &run, NULL)) ? 0 : 1;
  GNUNET_free ((void*) argv);
  return ret;
}
