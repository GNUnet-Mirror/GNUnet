/*
      This file is part of GNUnet
      (C) 2008, 2009 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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
 * @file testing/testing_group.c
 * @brief convenience API for writing testcases for GNUnet
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_testing_lib.h"

#define VERBOSE_TESTING GNUNET_YES

/**
 * Lowest port used for GNUnet testing.  Should be high enough to not
 * conflict with other applications running on the hosts but be low
 * enough to not conflict with client-ports (typically starting around
 * 32k).
 */
#define LOW_PORT 10000

/**
 * Highest port used for GNUnet testing.  Should be low enough to not
 * conflict with the port range for "local" ports (client apps; see
 * /proc/sys/net/ipv4/ip_local_port_range on Linux for example).
 */
#define HIGH_PORT 32000

#define CONNECT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

struct PeerConnection
{
  /*
   * Linked list
   */
  struct PeerConnection *next;

  /*
   * Pointer to daemon handle
   */
  struct GNUNET_TESTING_Daemon *daemon;

};

/**
 * Data we keep per peer.
 */
struct PeerData
{
  /**
   * (Initial) configuration of the host.
   * (initial because clients could change
   *  it and we would not know about those
   *  updates).
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Handle for controlling the daemon.
   */
  struct GNUNET_TESTING_Daemon *daemon;

  /*
   * Linked list of peer connections (simply indexes of PeerGroup)
   * FIXME: Question, store pointer or integer?  Pointer for now...
   */
  struct PeerConnection *connected_peers;
};


/**
 * Data we keep per host.
 */
struct HostData
{
  /**
   * Name of the host.
   */
  char *hostname;

  /**
   * Lowest port that we have not yet used
   * for GNUnet.
   */
  uint16_t minport;
};


/**
 * Handle to a group of GNUnet peers.
 */
struct GNUNET_TESTING_PeerGroup
{
  /**
   * Our scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Configuration template.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Function to call on each started daemon.
   */
  GNUNET_TESTING_NotifyDaemonRunning cb;

  /**
   * Closure for cb.
   */
  void *cb_cls;

  /*
   * Function to call on each topology connection created
   */
  GNUNET_TESTING_NotifyConnection notify_connection;

  /*
   * Callback for notify_connection
   */
  void *notify_connection_cls;

  /**
   * NULL-terminated array of information about
   * hosts.
   */
  struct HostData *hosts;

  /**
   * Array of "total" peers.
   */
  struct PeerData *peers;

  /**
   * Number of peers in this group.
   */
  unsigned int total;

};


struct UpdateContext
{
  struct GNUNET_CONFIGURATION_Handle *ret;
  unsigned int nport;
};

/**
 * Function to iterate over options.  Copies
 * the options to the target configuration,
 * updating PORT values as needed.
 *
 * @param cls closure
 * @param section name of the section
 * @param option name of the option
 * @param value value of the option
 */
static void
update_config (void *cls,
               const char *section, const char *option, const char *value)
{
  struct UpdateContext *ctx = cls;
  unsigned int ival;
  char cval[12];

  if ((0 == strcmp (option, "PORT")) && (1 == sscanf (value, "%u", &ival)))
    {
      GNUNET_snprintf (cval, sizeof (cval), "%u", ctx->nport++);
      value = cval;
    }
  GNUNET_CONFIGURATION_set_value_string (ctx->ret, section, option, value);
}


/**
 * Create a new configuration using the given configuration
 * as a template; however, each PORT in the existing cfg
 * must be renumbered by incrementing "*port".  If we run
 * out of "*port" numbers, return NULL. 
 * 
 * @param cfg template configuration
 * @param port port numbers to use, update to reflect
 *             port numbers that were used
 * @return new configuration, NULL on error
 */
static struct GNUNET_CONFIGURATION_Handle *
make_config (const struct GNUNET_CONFIGURATION_Handle *cfg, uint16_t * port)
{
  struct UpdateContext uc;
  uint16_t orig;

  orig = *port;
  uc.nport = *port;
  uc.ret = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_iterate (cfg, &update_config, &uc);
  if (uc.nport >= HIGH_PORT)
    {
      *port = orig;
      GNUNET_CONFIGURATION_destroy (uc.ret);
      return NULL;
    }
  *port = (uint16_t) uc.nport;
  return uc.ret;
}

/*
 * Add entries to the peers connected list
 *
 * @param pg the peer group we are working with
 * @param first index of the first peer
 * @param second index of the second peer
 *
 * @return the number of connections added (can be 0 1 or 2)
 *
 * FIXME: add both, or only add one?
 *      - if both are added, then we have to keep track
 *        when connecting so we don't double connect
 *      - if only one is added, we need to iterate over
 *        both lists to find out if connection already exists
 *      - having both allows the whitelisting/friend file
 *        creation to be easier
 *
 *      -- For now, add both, we have to iterate over each to
 *         check for duplicates anyways, so we'll take the performance
 *         hit assuming we don't have __too__ many connections
 *
 */
static int
add_connections(struct GNUNET_TESTING_PeerGroup *pg, unsigned int first, unsigned int second)
{
  int added;
  struct PeerConnection *first_iter;
  struct PeerConnection *second_iter;
  int add_first;
  int add_second;
  struct PeerConnection *new_first;
  struct PeerConnection *new_second;

  first_iter = pg->peers[first].connected_peers;
  add_first = GNUNET_YES;
  while (first_iter != NULL)
    {
      if (first_iter->daemon == pg->peers[second].daemon)
        add_first = GNUNET_NO;
      first_iter = first_iter->next;
    }

  second_iter = pg->peers[second].connected_peers;
  add_second = GNUNET_YES;
  while (second_iter != NULL)
    {
      if (second_iter->daemon == pg->peers[first].daemon)
        add_second = GNUNET_NO;
      second_iter = second_iter->next;
    }

  added = 0;
  if (add_first)
    {
      new_first = GNUNET_malloc(sizeof(struct PeerConnection));
      new_first->daemon = pg->peers[second].daemon;
      new_first->next = pg->peers[first].connected_peers;
      pg->peers[first].connected_peers = new_first;
      added++;
    }

  if (add_second)
    {
      new_second = GNUNET_malloc(sizeof(struct PeerConnection));
      new_second->daemon = pg->peers[first].daemon;
      new_second->next = pg->peers[second].connected_peers;
      pg->peers[second].connected_peers = new_second;
      added++;
    }

  return added;
}

static int
create_clique (struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int outer_count;
  unsigned int inner_count;
  int connect_attempts;

  connect_attempts = 0;

  for (outer_count = 0; outer_count < pg->total - 1; outer_count++)
    {
      for (inner_count = outer_count + 1; inner_count < pg->total;
           inner_count++)
        {
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Connecting peer %d to peer %d\n",
                      outer_count, inner_count);
#endif
          connect_attempts += add_connections(pg, outer_count, inner_count);
          /*GNUNET_TESTING_daemons_connect (pg->peers[outer_count].daemon,
                                          pg->peers[inner_count].daemon,
                                          CONNECT_TIMEOUT,
                                          pg->notify_connection,
                                          pg->notify_connection_cls);*/
        }
    }

  return connect_attempts;
}


/*
 * Create the friend files based on the PeerConnection's
 * of each peer in the peer group, and copy the files
 * to the appropriate place
 *
 * @param pg the peer group we are dealing with
 */
static void
create_and_copy_friend_files (struct GNUNET_TESTING_PeerGroup *pg)
{
  FILE *temp_friend_handle;
  unsigned int pg_iter;
  struct PeerConnection *connection_iter;
  struct GNUNET_CRYPTO_HashAsciiEncoded peer_enc;
  char *temp_service_path;
  pid_t pid;
  char *arg;
  struct GNUNET_PeerIdentity *temppeer;
  const char * mytemp;

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      mytemp = GNUNET_DISK_mktemp("friends");
      temp_friend_handle = fopen (mytemp, "wt");
      connection_iter = pg->peers[pg_iter].connected_peers;
      while (connection_iter != NULL)
        {
          temppeer = &connection_iter->daemon->id;
          GNUNET_CRYPTO_hash_to_enc(&temppeer->hashPubKey, &peer_enc);
          fprintf(temp_friend_handle, "%s\n", (char *)&peer_enc);
          connection_iter = connection_iter->next;
        }

      fclose(temp_friend_handle);

      GNUNET_CONFIGURATION_get_value_string(pg->peers[pg_iter].daemon->cfg, "PATHS", "SERVICEHOME", &temp_service_path);

      if (temp_service_path == NULL)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _("No SERVICEHOME specified in peer configuration, can't copy friends file!\n"));
          fclose(temp_friend_handle);
          unlink(mytemp);
          break;
        }

      if (pg->peers[pg_iter].daemon->hostname == NULL) /* Local, just copy the file */
        {
          GNUNET_asprintf (&arg, "%s/friends", temp_service_path);
          pid = GNUNET_OS_start_process ("mv",
                                         "mv", mytemp, arg, NULL);
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Copying file with command cp %s %s\n"), mytemp, arg);
#endif
          GNUNET_free(arg);
        }
      else /* Remote, scp the file to the correct place */
        {
          if (NULL != pg->peers[pg_iter].daemon->username)
            GNUNET_asprintf (&arg, "%s@%s:%s/friends", pg->peers[pg_iter].daemon->username, pg->peers[pg_iter].daemon->hostname, temp_service_path);
          else
            GNUNET_asprintf (&arg, "%s:%s/friends", pg->peers[pg_iter].daemon->hostname, temp_service_path);
          pid = GNUNET_OS_start_process ("scp",
                                         "scp", mytemp, arg, NULL);
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Copying file with command scp %s %s\n"), mytemp, arg);
#endif
          GNUNET_free(arg);
        }

    }
}



/*
 * Connect the topology as specified by the PeerConnection's
 * of each peer in the peer group
 *
 * @param pg the peer group we are dealing with
 */
static void
connect_topology (struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int pg_iter;
  struct PeerConnection *connection_iter;

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      connection_iter = pg->peers[pg_iter].connected_peers;
      while (connection_iter != NULL)
        {
          GNUNET_TESTING_daemons_connect (pg->peers[pg_iter].daemon,
                                          connection_iter->daemon,
                                          CONNECT_TIMEOUT,
                                          pg->notify_connection,
                                          pg->notify_connection_cls);
          connection_iter = connection_iter->next;
        }
    }
}


/*
 * Takes a peer group and attempts to create a topology based on the
 * one specified in the configuration file.  Returns the number of connections
 * that will attempt to be created, but this will happen asynchronously(?) so
 * the caller will have to keep track (via the callback) of whether or not
 * the connection actually happened.
 *
 * @param pg the peer group struct representing the running peers
 *
 */
int
GNUNET_TESTING_create_topology (struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned long long topology_num;
  int ret;

  GNUNET_assert (pg->notify_connection != NULL);
  ret = 0;
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_number (pg->cfg, "testing", "topology",
                                             &topology_num))
    {
      switch (topology_num)
        {
        case GNUNET_TESTING_TOPOLOGY_CLIQUE:
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating clique topology (may take a bit!)\n"));
          ret = create_clique (pg);
          break;
        case GNUNET_TESTING_TOPOLOGY_SMALL_WORLD:
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating small world topology (may take a bit!)\n"));
#endif
          ret = GNUNET_SYSERR;
/*        ret =
          GNUNET_REMOTE_connect_small_world_ring (&totalConnections,
                                                  number_of_daemons,
                                                  list_as_array, dotOutFile,
                                                  percentage, logNModifier);
                                                  */
          break;
        case GNUNET_TESTING_TOPOLOGY_RING:
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating ring topology (may take a bit!)\n"));
#endif
          /*
             ret = GNUNET_REMOTE_connect_ring (&totalConnections, head, dotOutFile);
           */
          ret = GNUNET_SYSERR;
          break;
        case GNUNET_TESTING_TOPOLOGY_2D_TORUS:
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating 2d torus topology (may take a bit!)\n"));
#endif
          /*
             ret =
             GNUNET_REMOTE_connect_2d_torus (&totalConnections, number_of_daemons,
             list_as_array, dotOutFile);
           */
          ret = GNUNET_SYSERR;
          break;
        case GNUNET_TESTING_TOPOLOGY_ERDOS_RENYI:
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating Erdos-Renyi topology (may take a bit!)\n"));
#endif
          /* ret =
             GNUNET_REMOTE_connect_erdos_renyi (&totalConnections, percentage,
             head, dotOutFile);
           */
          ret = GNUNET_SYSERR;
          break;
        case GNUNET_TESTING_TOPOLOGY_INTERNAT:
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating InterNAT topology (may take a bit!)\n"));
#endif
          /*
             ret =
             GNUNET_REMOTE_connect_nated_internet (&totalConnections, percentage,
             number_of_daemons, head,
             dotOutFile);
           */
          ret = GNUNET_SYSERR;
          break;
        case GNUNET_TESTING_TOPOLOGY_NONE:
          ret = 0;
          break;
        default:
          ret = GNUNET_SYSERR;
          break;
        }

      if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno (pg->cfg, "TESTING", "F2F"))
        create_and_copy_friend_files(pg);

      connect_topology(pg);
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("No topology specified, was one intended?\n"));
    }

  return ret;
}

/**
 * Start count gnunetd processes with the same set of transports and
 * applications.  The port numbers (any option called "PORT") will be
 * adjusted to ensure that no two peers running on the same system
 * have the same port(s) in their respective configurations.
 *
 * @param sched scheduler to use 
 * @param cfg configuration template to use
 * @param total number of daemons to start
 * @param cb function to call on each daemon that was started
 * @param cb_cls closure for cb
 * @param connect_callback function to call each time two hosts are connected
 * @param connect_callback_cls closure for connect_callback
 * @param hostnames space-separated list of hostnames to use; can be NULL (to run
 *        everything on localhost).
 * @return NULL on error, otherwise handle to control peer group
 */
struct GNUNET_TESTING_PeerGroup *
GNUNET_TESTING_daemons_start (struct GNUNET_SCHEDULER_Handle *sched,
                              const struct GNUNET_CONFIGURATION_Handle *cfg,
                              unsigned int total,
                              GNUNET_TESTING_NotifyDaemonRunning cb,
                              void *cb_cls,
                              GNUNET_TESTING_NotifyConnection
                              connect_callback, void *connect_callback_cls,
                              const char *hostnames)
{
  struct GNUNET_TESTING_PeerGroup *pg;
  const char *rpos;
  char *pos;
  char *start;
  const char *hostname;
  char *baseservicehome;
  char *newservicehome;
  char *tmpdir;
  struct GNUNET_CONFIGURATION_Handle *pcfg;
  unsigned int off;
  unsigned int hostcnt;
  uint16_t minport;
  int tempsize;

  if (0 == total)
    {
      GNUNET_break (0);
      return NULL;
    }
  pg = GNUNET_malloc (sizeof (struct GNUNET_TESTING_PeerGroup));
  pg->sched = sched;
  pg->cfg = cfg;
  pg->cb = cb;
  pg->cb_cls = cb_cls;
  pg->notify_connection = connect_callback;
  pg->notify_connection_cls = connect_callback_cls;
  pg->total = total;
  pg->peers = GNUNET_malloc (total * sizeof (struct PeerData));
  if (NULL != hostnames)
    {
      off = 2;
      /* skip leading spaces */
      while ((0 != *hostnames) && (isspace (*hostnames)))
        hostnames++;
      rpos = hostnames;
      while ('\0' != *rpos)
        {
          if (isspace (*rpos))
            off++;
          rpos++;
        }
      pg->hosts = GNUNET_malloc (off * sizeof (struct HostData));
      off = 0;
      start = GNUNET_strdup (hostnames);
      pos = start;
      while ('\0' != *pos)
        {
          if (isspace (*pos))
            {
              *pos = '\0';
              if (strlen (start) > 0)
                {
                  pg->hosts[off].minport = LOW_PORT;
                  pg->hosts[off++].hostname = start;
                }
              start = pos + 1;
            }
          pos++;
        }
      if (strlen (start) > 0)
        {
          pg->hosts[off].minport = LOW_PORT;
          pg->hosts[off++].hostname = start;
        }
      if (off == 0)
        {
          GNUNET_free (start);
          GNUNET_free (pg->hosts);
          pg->hosts = NULL;
        }
      hostcnt = off;
      minport = 0;              /* make gcc happy */
    }
  else
    {
      hostcnt = 0;
      minport = LOW_PORT;
    }
  for (off = 0; off < total; off++)
    {
      if (hostcnt > 0)
        {
          hostname = pg->hosts[off % hostcnt].hostname;
          pcfg = make_config (cfg, &pg->hosts[off % hostcnt].minport);
        }
      else
        {
          hostname = NULL;
          pcfg = make_config (cfg, &minport);
        }
      if (NULL == pcfg)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      _
                      ("Could not create configuration for peer number %u on `%s'!\n"),
                      off, hostname == NULL ? "localhost" : hostname);
          continue;
        }

      if (GNUNET_YES ==
          GNUNET_CONFIGURATION_get_value_string (pcfg, "PATHS", "SERVICEHOME",
                                                 &baseservicehome))
        {
          tempsize = snprintf (NULL, 0, "%s/%d/", baseservicehome, off) + 1;
          newservicehome = GNUNET_malloc (tempsize);
          snprintf (newservicehome, tempsize, "%s/%d/", baseservicehome, off);
        }
      else
        {
          tmpdir = getenv ("TMPDIR");
          tmpdir = tmpdir ? tmpdir : "/tmp";
          tempsize = snprintf (NULL, 0, "%s/%s/%d/", tmpdir, "gnunet-testing-test-test", off) + 1;
          newservicehome = GNUNET_malloc (tempsize);
          snprintf (newservicehome, tempsize, "%s/%d/",
                    "/tmp/gnunet-testing-test-test", off);
        }
      GNUNET_CONFIGURATION_set_value_string (pcfg,
                                             "PATHS",
                                             "SERVICEHOME", newservicehome);

      pg->peers[off].cfg = pcfg;
      pg->peers[off].daemon = GNUNET_TESTING_daemon_start (sched,
                                                           pcfg,
                                                           hostname,
                                                           cb, cb_cls);
      if (NULL == pg->peers[off].daemon)
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _("Could not start peer number %u!\n"), off);
    }
  return pg;
}

/*
 * Get a daemon by number, so callers don't have to do nasty
 * offsetting operation.
 */
struct GNUNET_TESTING_Daemon *
GNUNET_TESTING_daemon_get (struct GNUNET_TESTING_PeerGroup *pg, unsigned int position)
{
  if (position < pg->total)
    return pg->peers[position].daemon;
  else
    return NULL;
}

/**
 * Shutdown all peers started in the given group.
 * 
 * @param pg handle to the peer group
 */
void
GNUNET_TESTING_daemons_stop (struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int off;

  for (off = 0; off < pg->total; off++)
    {
      /* FIXME: should we wait for our
         continuations to be called here? This
         would require us to take a continuation
         as well... */

      if (NULL != pg->peers[off].daemon)
        GNUNET_TESTING_daemon_stop (pg->peers[off].daemon, NULL, NULL);
      if (NULL != pg->peers[off].cfg)
        GNUNET_CONFIGURATION_destroy (pg->peers[off].cfg);
    }
  GNUNET_free (pg->peers);
  if (NULL != pg->hosts)
    {
      GNUNET_free (pg->hosts[0].hostname);
      GNUNET_free (pg->hosts);
    }
  GNUNET_free (pg);
}


/* end of testing_group.c */
