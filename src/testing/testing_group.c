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

#define MAX_OUTSTANDING_CONNECTIONS 50

#define CONNECT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 180)

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


struct ConnectContext
{
  struct GNUNET_TESTING_Daemon *first;

  struct GNUNET_TESTING_Daemon *second;

  struct GNUNET_TESTING_PeerGroup *pg;
};

/**
 * Number of connects we are waiting on, allows us to rate limit
 * connect attempts.
 */
static int outstanding_connects;

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
  char *control_host;
  char *allowed_hosts;

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

  if (GNUNET_CONFIGURATION_get_value_string(cfg, "testing", "control_host", &control_host) == GNUNET_OK)
    {
      GNUNET_asprintf(&allowed_hosts, "%s; 127.0.0.1;", control_host);
      fprintf(stderr, "FOUND CONTROL_HOST OPTION %s, setting to %s\n", control_host, allowed_hosts);
      GNUNET_CONFIGURATION_set_value_string(uc.ret, "core", "ACCEPT_FROM", allowed_hosts);
      GNUNET_free(allowed_hosts);
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
 * @return the number of connections added (can be 0, 1 or 2)
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

int
create_small_world_ring(struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int i, j;
  int nodeToConnect;
  unsigned int natLog;
  unsigned int randomPeer;
  double random, logNModifier, percentage;
  unsigned int smallWorldConnections;
  int connsPerPeer;
  char *p_string;
  int max;
  int min;
  unsigned int useAnd;
  int connect_attempts;

  logNModifier = 0.5; /* FIXME: default value? */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(pg->cfg,
							 "TESTING",
							 "LOGNMODIFIER",
							 &p_string))
    {
      if (sscanf(p_string, "%lf", &logNModifier) != 1)
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
		    p_string,
		    "LOGNMODIFIER",
		    "TESTING");
      GNUNET_free (p_string);
    }
  percentage = 0.5; /* FIXME: default percentage? */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(pg->cfg,
							 "TESTING",
							 "PERCENTAGE",
							 &p_string))
    {
      if (sscanf(p_string, "%lf", &percentage) != 1)
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
		    p_string,
		    "PERCENTAGE",
		    "TESTING");
      GNUNET_free (p_string);
    }
  natLog = log (pg->total);
  connsPerPeer = ceil (natLog * logNModifier);

  if (connsPerPeer % 2 == 1)
    connsPerPeer += 1;

  smallWorldConnections = 0;
  connect_attempts = 0;
  for (i = 0; i < pg->total; i++)
    {
      useAnd = 0;
      max = i + connsPerPeer / 2;
      min = i - connsPerPeer / 2;

      if (max > pg->total - 1)
        {
          max = max - pg->total;
          useAnd = 1;
        }

      if (min < 0)
        {
          min = pg->total - 1 + min;
          useAnd = 1;
        }

      for (j = 0; j < connsPerPeer / 2; j++)
        {
          random = ((double) GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_WEAK,
						      (uint64_t)-1LL)) / ( (double) (uint64_t) -1LL);
          if (random < percentage)
            {
              /* Connect to uniformly selected random peer */
              randomPeer =
                GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                   pg->total);
              while ((((randomPeer < max) && (randomPeer > min))
                      && (useAnd == 0)) || (((randomPeer > min)
                                             || (randomPeer < max))
                                            && (useAnd == 1)))
                {
                  randomPeer =
                      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                                         pg->total);
                }
              smallWorldConnections +=
                add_connections (pg, i, randomPeer);
            }
          else
            {
              nodeToConnect = i + j + 1;
              if (nodeToConnect > pg->total - 1)
                {
                  nodeToConnect = nodeToConnect - pg->total;
                }
              connect_attempts +=
                add_connections (pg, i, nodeToConnect);
            }
        }

    }

  connect_attempts += smallWorldConnections;

  return connect_attempts;
}


static int
create_nated_internet (struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int outer_count, inner_count;
  unsigned int cutoff;
  int connect_attempts;
  double nat_percentage;
  char *p_string;

  nat_percentage = 0.6; /* FIXME: default percentage? */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(pg->cfg,
							 "TESTING",
							 "NATPERCENTAGE",
							 &p_string))
    {
      if (sscanf(p_string, "%lf", &nat_percentage) != 1)
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
		    p_string,
		    "NATPERCENTAGE",
		    "TESTING");
      GNUNET_free (p_string);
    }



  cutoff = (unsigned int) (nat_percentage * pg->total);

  connect_attempts = 0;

  for (outer_count = 0; outer_count < pg->total - 1; outer_count++)
    {
      for (inner_count = outer_count + 1; inner_count < pg->total;
           inner_count++)
        {
          if ((outer_count > cutoff) || (inner_count > cutoff))
            {
#if VERBOSE_TESTING
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          "Connecting peer %d to peer %d\n",
                          outer_count, inner_count);
#endif
              connect_attempts += add_connections(pg, outer_count, inner_count);
            }
        }
    }

  return connect_attempts;

}



static int
create_small_world (struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int i, j, k;
  unsigned int square;
  unsigned int rows;
  unsigned int cols;
  unsigned int toggle = 1;
  unsigned int nodeToConnect;
  unsigned int natLog;
  unsigned int node1Row;
  unsigned int node1Col;
  unsigned int node2Row;
  unsigned int node2Col;
  unsigned int distance;
  double probability, random, percentage;
  unsigned int smallWorldConnections;
  char *p_string;
  int connect_attempts;
  square = floor (sqrt (pg->total));
  rows = square;
  cols = square;

  percentage = 0.5; /* FIXME: default percentage? */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(pg->cfg,
							 "TESTING",
							 "PERCENTAGE",
							 &p_string))
    {
      if (sscanf(p_string, "%lf", &percentage) != 1)
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
		    p_string,
		    "PERCENTAGE",
		    "TESTING");
      GNUNET_free (p_string);
    }
  probability = 0.5; /* FIXME: default percentage? */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(pg->cfg,
							 "TESTING",
							 "PROBABILITY",
							 &p_string))
    {
      if (sscanf(p_string, "%lf", &probability) != 1)
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
		    p_string,
		    "PROBABILITY",
		    "TESTING");
      GNUNET_free (p_string);
    }
  if (square * square != pg->total)
    {
      while (rows * cols < pg->total)
        {
          if (toggle % 2 == 0)
            rows++;
          else
            cols++;

          toggle++;
        }
    }
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Connecting nodes in 2d torus topology: %u rows %u columns\n"),
                  rows, cols);
#endif

  connect_attempts = 0;
  /* Rows and columns are all sorted out, now iterate over all nodes and connect each
   * to the node to its right and above.  Once this is over, we'll have our torus!
   * Special case for the last node (if the rows and columns are not equal), connect
   * to the first in the row to maintain topology.
   */
  for (i = 0; i < pg->total; i++)
    {
      /* First connect to the node to the right */
      if (((i + 1) % cols != 0) && (i + 1 != pg->total))
        nodeToConnect = i + 1;
      else if (i + 1 == pg->total)
        nodeToConnect = rows * cols - cols;
      else
        nodeToConnect = i - cols + 1;

      connect_attempts += add_connections (pg, i, nodeToConnect);

      if (i < cols)
        nodeToConnect = (rows * cols) - cols + i;
      else
        nodeToConnect = i - cols;

      if (nodeToConnect < pg->total)
        connect_attempts += add_connections (pg, i, nodeToConnect);
    }
  natLog = log (pg->total);
#if VERBOSE_TESTING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("natural log of %d is %d, will run %d iterations\n"),
             pg->total, natLog, (int) (natLog * percentage));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Total connections added thus far: %u!\n"), connect_attempts);
#endif
  smallWorldConnections = 0;
  for (i = 0; i < (int) (natLog * percentage); i++)
    {
      for (j = 0; j < pg->total; j++)
        {
          /* Determine the row and column of node at position j on the 2d torus */
          node1Row = j / cols;
          node1Col = j - (node1Row * cols);
          for (k = 0; k < pg->total; k++)
            {
              /* Determine the row and column of node at position k on the 2d torus */
              node2Row = k / cols;
              node2Col = k - (node2Row * cols);
              /* Simple Cartesian distance */
              distance = abs (node1Row - node2Row) + abs (node1Col - node2Col);
              if (distance > 1)
                {
                  /* Calculate probability as 1 over the square of the distance */
                  probability = 1.0 / (distance * distance);
                  /* Choose a random value between 0 and 1 */
		  random = ((double) GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_WEAK,
							      (uint64_t)-1LL)) / ( (double) (uint64_t) -1LL);
                  /* If random < probability, then connect the two nodes */
                  if (random < probability)
                    smallWorldConnections += add_connections (pg, j, k);

                }
            }
        }
    }
  connect_attempts += smallWorldConnections;
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Total connections added for small world: %d!\n"),
                      smallWorldConnections);
#endif
  return connect_attempts;
}



static int
create_erdos_renyi (struct GNUNET_TESTING_PeerGroup *pg)
{
  double temp_rand;
  unsigned int outer_count;
  unsigned int inner_count;
  int connect_attempts;
  double probability;
  char *p_string;

  probability = 0.5; /* FIXME: default percentage? */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(pg->cfg,
							 "TESTING",
							 "PROBABILITY",
							 &p_string))
    {
      if (sscanf(p_string, "%lf", &probability) != 1)
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
		    p_string,
		    "PROBABILITY",
		    "TESTING");
      GNUNET_free (p_string);
    }
  connect_attempts = 0;
  for (outer_count = 0; outer_count < pg->total - 1; outer_count++)
    {
      for (inner_count = outer_count + 1; inner_count < pg->total;
           inner_count++)
        {
          temp_rand = ((double) GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_WEAK,
							 (uint64_t)-1LL)) / ( (double) (uint64_t) -1LL);
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("rand is %f probability is %f\n"), temp_rand,
                      probability);
#endif
          if (temp_rand < probability)
            {
              connect_attempts += add_connections (pg, outer_count, inner_count);
            }
        }
    }

  return connect_attempts;
}

static int
create_2d_torus (struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int i;
  unsigned int square;
  unsigned int rows;
  unsigned int cols;
  unsigned int toggle = 1;
  unsigned int nodeToConnect;
  int connect_attempts;

  connect_attempts = 0;

  square = floor (sqrt (pg->total));
  rows = square;
  cols = square;

  if (square * square != pg->total)
    {
      while (rows * cols < pg->total)
        {
          if (toggle % 2 == 0)
            rows++;
          else
            cols++;

          toggle++;
        }
    }
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Connecting nodes in 2d torus topology: %u rows %u columns\n"),
                  rows, cols);
#endif
  /* Rows and columns are all sorted out, now iterate over all nodes and connect each
   * to the node to its right and above.  Once this is over, we'll have our torus!
   * Special case for the last node (if the rows and columns are not equal), connect
   * to the first in the row to maintain topology.
   */
  for (i = 0; i < pg->total; i++)
    {
      /* First connect to the node to the right */
      if (((i + 1) % cols != 0) && (i + 1 != pg->total))
        nodeToConnect = i + 1;
      else if (i + 1 == pg->total)
        nodeToConnect = rows * cols - cols;
      else
        nodeToConnect = i - cols + 1;
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Connecting peer %d to peer %d\n",
                      i, nodeToConnect);
#endif
      connect_attempts += add_connections(pg, i, nodeToConnect);

      /* Second connect to the node immediately above */
      if (i < cols)
        nodeToConnect = (rows * cols) - cols + i;
      else
        nodeToConnect = i - cols;

      if (nodeToConnect < pg->total)
        {
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Connecting peer %d to peer %d\n",
                      i, nodeToConnect);
#endif
          connect_attempts += add_connections(pg, i, nodeToConnect);
        }

    }

  return connect_attempts;
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
        }
    }

  return connect_attempts;
}


static int
create_ring (struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int count;
  int connect_attempts;

  connect_attempts = 0;

  /* Connect each peer to the next highest numbered peer */
  for (count = 0; count < pg->total - 1; count++)
    {
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Connecting peer %d to peer %d\n",
                      count, count + 1);
#endif
      connect_attempts += add_connections(pg, count, count + 1);
    }

  /* Connect the last peer to the first peer */
  connect_attempts += add_connections(pg, pg->total - 1, 0);

  return connect_attempts;
}


/*
 * Create the friend files based on the PeerConnection's
 * of each peer in the peer group, and copy the files
 * to the appropriate place
 *
 * @param pg the peer group we are dealing with
 */
static int
create_and_copy_friend_files (struct GNUNET_TESTING_PeerGroup *pg)
{
  FILE *temp_friend_handle;
  unsigned int pg_iter;
  struct PeerConnection *connection_iter;
  struct GNUNET_CRYPTO_HashAsciiEncoded peer_enc;
  char *temp_service_path;
  pid_t *pidarr;
  char *arg;
  struct GNUNET_PeerIdentity *temppeer;
  char * mytemp;
  enum GNUNET_OS_ProcessStatusType type;
  unsigned long return_code;
  int count;
  int ret;
  int max_wait = 10;

  pidarr = GNUNET_malloc(sizeof(pid_t) * pg->total);
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

      if (GNUNET_OK !=
	  GNUNET_CONFIGURATION_get_value_string(pg->peers[pg_iter].daemon->cfg, "PATHS", "SERVICEHOME", &temp_service_path))
	{
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		      _("No `%s' specified in peer configuration in section `%s', cannot copy friends file!\n"),
		      "SERVICEHOME",
		      "PATHS");
          if (UNLINK (mytemp) != 0)
            GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", mytemp);
	  GNUNET_free (mytemp);
          break;
        }

      if (pg->peers[pg_iter].daemon->hostname == NULL) /* Local, just copy the file */
        {
          GNUNET_asprintf (&arg, "%s/friends", temp_service_path);
          pidarr[pg_iter] = GNUNET_OS_start_process (NULL, NULL, "mv",
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
          pidarr[pg_iter] = GNUNET_OS_start_process (NULL, NULL, "scp",
                                         "scp", mytemp, arg, NULL);

#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Copying file with command scp %s %s\n"), mytemp, arg);
#endif
          GNUNET_free(arg);
        }
      GNUNET_free (temp_service_path);
      GNUNET_free (mytemp);
    }

  count = 0;
  ret = GNUNET_SYSERR;
  while ((count < max_wait) && (ret != GNUNET_OK))
    {
      ret = GNUNET_OK;
      for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
        {
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Checking copy status of file %d\n"), pg_iter);
#endif
          if (pidarr[pg_iter] != 0) /* Check for already completed! */
            {
              if (GNUNET_OS_process_status(pidarr[pg_iter], &type, &return_code) != GNUNET_OK)
                {
                  ret = GNUNET_SYSERR;
                }
              else if ((type != GNUNET_OS_PROCESS_EXITED) || (return_code != 0))
                {
                  ret = GNUNET_SYSERR;
                }
              else
                {
                  pidarr[pg_iter] = 0;
#if VERBOSE_TESTING
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("File %d copied\n"), pg_iter);
#endif
                }
            }
        }
      count++;
      if (ret == GNUNET_SYSERR)
        {
          sleep(1);
        }
    }

  GNUNET_free(pidarr);
  return ret;
}

/**
 * Internal notification of a connection, kept so that we can ensure some connections
 * happen instead of flooding all testing daemons with requests to connect.
 */
static void internal_connect_notify (void *cls,
                                     const struct GNUNET_PeerIdentity *first,
                                     const struct GNUNET_PeerIdentity *second,
                                     const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                                     const struct GNUNET_CONFIGURATION_Handle *second_cfg,
                                     struct GNUNET_TESTING_Daemon *first_daemon,
                                     struct GNUNET_TESTING_Daemon *second_daemon,
                                     const char *emsg)
{
  struct GNUNET_TESTING_PeerGroup *pg = cls;
  outstanding_connects--;

  pg->notify_connection(pg->notify_connection_cls, first, second, first_cfg, second_cfg, first_daemon, second_daemon, emsg);

}

static void schedule_connect(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ConnectContext *connect_context = cls;

  if (outstanding_connects > MAX_OUTSTANDING_CONNECTIONS)
    {
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Delaying connect, we have too many outstanding connections!\n"));
#endif
      GNUNET_SCHEDULER_add_delayed(connect_context->pg->sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 3), &schedule_connect, connect_context);
    }
  else
    {
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating connection, outstanding_connections is %d\n"), outstanding_connects);
#endif
      outstanding_connects++;
      GNUNET_TESTING_daemons_connect (connect_context->first,
                                      connect_context->second,
                                      CONNECT_TIMEOUT,
                                      &internal_connect_notify,
                                      connect_context->pg);
      GNUNET_free(connect_context);
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
  struct ConnectContext *connect_context;

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      connection_iter = pg->peers[pg_iter].connected_peers;
      while (connection_iter != NULL)
        {
          connect_context = GNUNET_malloc(sizeof(struct ConnectContext));
          connect_context->pg = pg;
          connect_context->first = pg->peers[pg_iter].daemon;
          connect_context->second = connection_iter->daemon;

          GNUNET_SCHEDULER_add_now(pg->sched, &schedule_connect, connect_context);
          /*GNUNET_TESTING_daemons_connect (pg->peers[pg_iter].daemon,
                                          connection_iter->daemon,
                                          CONNECT_TIMEOUT,
                                          pg->notify_connection,
                                          pg->notify_connection_cls);*/
          connection_iter = connection_iter->next;

          /*if (outstanding_connects > MAX_OUTSTANDING_CONNECTS)
            {
#if VERBOSE_TESTING
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          _("Sleeping to give peers a chance to connect!\n"));
#endif
              sleep(2);
            } */
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
 * @return the number of connections should be created by the topology, so the
 * caller knows how many to wait for (if it so chooses)
 *
 */
int
GNUNET_TESTING_create_topology (struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned long long topology_num;
  int ret;
  int num_connections;

  GNUNET_assert (pg->notify_connection != NULL);
  ret = GNUNET_OK;
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
#endif
          num_connections = create_clique (pg);
          break;
        case GNUNET_TESTING_TOPOLOGY_SMALL_WORLD_RING:
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating small world (ring) topology (may take a bit!)\n"));
#endif
          num_connections = create_small_world_ring (pg);
          break;
        case GNUNET_TESTING_TOPOLOGY_SMALL_WORLD:
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating small world (2d-torus) topology (may take a bit!)\n"));
#endif
          num_connections = create_small_world (pg);
          break;
        case GNUNET_TESTING_TOPOLOGY_RING:
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating ring topology (may take a bit!)\n"));
#endif
          num_connections = create_ring (pg);
          break;
        case GNUNET_TESTING_TOPOLOGY_2D_TORUS:
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating 2d torus topology (may take a bit!)\n"));
#endif
          num_connections = create_2d_torus (pg);
          break;
        case GNUNET_TESTING_TOPOLOGY_ERDOS_RENYI:
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating Erdos-Renyi topology (may take a bit!)\n"));
#endif
          num_connections = create_erdos_renyi (pg);
          break;
        case GNUNET_TESTING_TOPOLOGY_INTERNAT:
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating InterNAT topology (may take a bit!)\n"));
#endif
          num_connections = create_nated_internet (pg);
          break;
        case GNUNET_TESTING_TOPOLOGY_NONE:
          num_connections = 0;
          break;
        default:
	  num_connections = 0;
          break;
        }
      if (num_connections < 1)
        return GNUNET_SYSERR;

      if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno (pg->cfg, "TESTING", "F2F"))
        ret = create_and_copy_friend_files(pg);
      if (ret == GNUNET_OK)
        connect_topology(pg);
      else
        {
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Failed during friend file copying!\n"));
#endif
          return GNUNET_SYSERR;
        }
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("No topology specified, was one intended?\n"));
      return GNUNET_SYSERR;
    }

  return num_connections;
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
	  GNUNET_asprintf (&newservicehome,
			   "%s/%d/", baseservicehome, off);
	  GNUNET_free (baseservicehome);
        }
      else
        {
          tmpdir = getenv ("TMPDIR");
          tmpdir = tmpdir ? tmpdir : "/tmp";
	  GNUNET_asprintf (&newservicehome,
			   "%s/%s/%d/",
			   tmpdir,
			   "gnunet-testing-test-test", off);
        }
      GNUNET_CONFIGURATION_set_value_string (pcfg,
                                             "PATHS",
                                             "SERVICEHOME", newservicehome);
      GNUNET_free (newservicehome);
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
  struct PeerConnection *pos;
  struct PeerConnection *next;

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

      pos = pg->peers[off].connected_peers;
      while (pos != NULL)
        {
          next = pos->next;
          GNUNET_free(pos);
          pos = next;
        }

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
