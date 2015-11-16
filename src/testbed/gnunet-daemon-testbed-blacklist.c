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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
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
 * The array of peer identities we read from whitelist/blacklist
 */
static struct GNUNET_PeerIdentity *ilist;

/**
 * The blacklist handle we obtain from transport when we register ourselves for
 * access control
 */
struct GNUNET_TRANSPORT_Blacklist *bh;

/**
 * Task for shutdown
 */
static struct GNUNET_SCHEDULER_Task * shutdown_task;

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
  char *shome;
  char *fname;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (c, "PATHS",
                                                            "GNUNET_HOME",
                                                            &shome))
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_asprintf (&fname,
                   "%s/whitelist",
                   shome);
  if (GNUNET_YES == GNUNET_DISK_file_test (fname))
  {
    mode = ACCESS_ALLOW;
    setup_ac (fname, c);
    GNUNET_free (shome);
    GNUNET_free (fname);
    return;
  }
  GNUNET_asprintf (&fname,
                   "%s/blacklist",
                   shome);
  GNUNET_free (fname);
  if (GNUNET_YES == GNUNET_DISK_file_test (fname))
  {
    mode = ACCESS_DENY;
    setup_ac (shome, c);
  }
  GNUNET_free (shome);
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
  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv, "gnunet-daemon-testbed-blacklist",
                           _
                           ("Daemon to restrict incoming transport layer connections during testbed deployments"),
                           options, &run, NULL)) ? 0 : 1;
  GNUNET_free ((void*) argv);
  return ret;
}
