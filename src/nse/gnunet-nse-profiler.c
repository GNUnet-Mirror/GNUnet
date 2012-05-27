/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file nse/gnunet-nse-profiler.c
 *
 * @brief Profiling driver for the network size estimation service.
 *        Generally, the profiler starts a given number of peers,
 *        then churns some off, waits a certain amount of time, then
 *        churns again, and repeats.
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_nse_service.h"

#define VERBOSE 3

struct NSEPeer
{
  struct NSEPeer *prev;

  struct NSEPeer *next;

  struct GNUNET_TESTING_Daemon *daemon;

  struct GNUNET_NSE_Handle *nse_handle;

  struct GNUNET_STATISTICS_Handle *stats;
  
  GNUNET_SCHEDULER_TaskIdentifier stats_task;
};


struct StatsContext
{
  /**
   * Whether or not shoutdown after finishing.
   */
  int shutdown;

  /**
   * How many messages have peers received during the test.
   */
  unsigned long long total_nse_received_messages;

  /**
   * How many messages have peers send during the test (should be == received).
   */
  unsigned long long total_nse_transmitted_messages;

  /**
   * How many messages have travelled an edge in both directions.
   */
  unsigned long long total_nse_cross;

  /**
   * How many extra messages per edge (corrections) have been received.
   */
  unsigned long long total_nse_extra;

  /**
   * How many messages have been discarded.
   */
  unsigned long long total_discarded;
};


static struct NSEPeer *peer_head;

static struct NSEPeer *peer_tail;

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1500)

static int ok;

/**
 * Be verbose
 */
static int verbose;

/**
 * Total number of peers in the test.
 */
static unsigned long long num_peers;

/**
 * Global configuration file
 */
static struct GNUNET_CONFIGURATION_Handle *testing_cfg;

/**
 * Total number of currently running peers.
 */
static unsigned long long peers_running;

/**
 * Current round we are in.
 */
static unsigned long long current_round;

/**
 * Peers desired in the next round.
 */
static unsigned long long peers_next_round;

/**
 * Maximum number of connections to NSE services.
 */
static unsigned long long connection_limit;

/**
 * Total number of connections in the whole network.
 */
static unsigned int total_connections;

/**
 * The currently running peer group.
 */
static struct GNUNET_TESTING_PeerGroup *pg;

/**
 * File to report results to.
 */
static struct GNUNET_DISK_FileHandle *output_file;

/**
 * File to log connection info, statistics to.
 */
static struct GNUNET_DISK_FileHandle *data_file;

/**
 * How many data points to capture before triggering next round?
 */
static struct GNUNET_TIME_Relative wait_time;

/**
 * NSE interval.
 */
static struct GNUNET_TIME_Relative interval;

/**
 * Task called to disconnect peers.
 */
static GNUNET_SCHEDULER_TaskIdentifier disconnect_task;

/**
 * Task called to shutdown test.
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_handle;

/**
 * Task used to churn the network.
 */
static GNUNET_SCHEDULER_TaskIdentifier churn_task;

static char *topology_file;

/**
 * Check whether peers successfully shut down.
 */
static void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown of peers failed!\n");
#endif
    if (ok == 0)
      ok = 666;
  }
  else
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All peers successfully shut down!\n");
#endif
    ok = 0;
  }
}


static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NSEPeer *pos;

#if VERBOSE
  FPRINTF (stderr, "%s",  "Ending test.\n");
#endif

  if (disconnect_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }
  while (NULL != (pos = peer_head))
  {
    if (pos->nse_handle != NULL)
      GNUNET_NSE_disconnect (pos->nse_handle);
    GNUNET_CONTAINER_DLL_remove (peer_head, peer_tail, pos);
    if (GNUNET_SCHEDULER_NO_TASK != pos->stats_task)
    {
      GNUNET_SCHEDULER_cancel (pos->stats_task);
      if (NULL != pos->stats)
        GNUNET_STATISTICS_destroy(pos->stats, GNUNET_NO);
    }
    GNUNET_free (pos);
  }

  if (data_file != NULL)
    GNUNET_DISK_file_close (data_file);
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
}


/**
 * Callback to call when network size estimate is updated.
 *
 * @param cls closure
 * @param timestamp server timestamp
 * @param estimate the value of the current network size estimate
 * @param std_dev standard deviation (rounded down to nearest integer)
 *                of the size estimation values seen
 *
 */
static void
handle_estimate (void *cls, struct GNUNET_TIME_Absolute timestamp,
                 double estimate, double std_dev)
{
  struct NSEPeer *peer = cls;
  char *output_buffer;
  size_t size;

  if (output_file != NULL)
  {
    size =
        GNUNET_asprintf (&output_buffer, "%s %llu %llu %f %f %f\n",
                         GNUNET_i2s (&peer->daemon->id), peers_running,
                         timestamp.abs_value,
                         GNUNET_NSE_log_estimate_to_n (estimate), estimate,
                         std_dev);
    if (size != GNUNET_DISK_file_write (output_file, output_buffer, size))
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Unable to write to file!\n");
    GNUNET_free (output_buffer);
  }
  else
    FPRINTF (stderr,
             "Received network size estimate from peer %s. Size: %f std.dev. %f\n",
             GNUNET_i2s (&peer->daemon->id), estimate, std_dev);

}

/**
 * Process core statistic values.
 *
 * @param cls closure
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
core_stats_iterator (void *cls, const char *subsystem, const char *name,
                     uint64_t value, int is_persistent)
{
  struct NSEPeer *peer = cls;
  char *output_buffer;
  size_t size;

  if (output_file != NULL)
  {
    size =
        GNUNET_asprintf (&output_buffer, "%s [%s] %s %llu\n",
                          GNUNET_i2s (&peer->daemon->id),
                         subsystem, name, value);
    if (size != GNUNET_DISK_file_write (output_file, output_buffer, size))
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Unable to write to file!\n");
    GNUNET_free (output_buffer);
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "%s -> %s [%s]: %llu\n",
                GNUNET_i2s (&peer->daemon->id), subsystem, name, value);

  return GNUNET_OK;
}

/**
 * Continuation called by "get_stats" function.
 *
 * @param cls closure
 * @param success GNUNET_OK if statistics were
 *        successfully obtained, GNUNET_SYSERR if not.
 */
static void
core_stats_cont (void *cls, int success);

static void
core_get_stats (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NSEPeer *peer = cls;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
  {
    GNUNET_STATISTICS_destroy(peer->stats, GNUNET_NO);
    peer->stats = NULL;
    return;
  }
  else
  {
    GNUNET_STATISTICS_get(peer->stats, "core", NULL,
                          GNUNET_TIME_UNIT_FOREVER_REL,
                          &core_stats_cont, &core_stats_iterator, peer);
    GNUNET_STATISTICS_get(peer->stats, "transport", NULL,
                          GNUNET_TIME_UNIT_FOREVER_REL,
                          NULL, &core_stats_iterator, peer);
    GNUNET_STATISTICS_get(peer->stats, "nse", NULL,
                          GNUNET_TIME_UNIT_FOREVER_REL,
                          NULL, &core_stats_iterator, peer);
  }
  peer->stats_task = GNUNET_SCHEDULER_NO_TASK;
}

/**
 * Continuation called by "get_stats" function.
 *
 * @param cls closure
 * @param success GNUNET_OK if statistics were
 *        successfully obtained, GNUNET_SYSERR if not.
 */
static void
core_stats_cont (void *cls, int success)
{
  struct NSEPeer *peer = cls;
  peer->stats_task = GNUNET_SCHEDULER_add_delayed (interval, &core_get_stats,
                                                   peer);
}


/**
 *
 */
static void
connect_nse_service (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NSEPeer *current_peer;
  unsigned int i;

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting to nse service of peers\n");
#endif
  for (i = 0; i < num_peers; i++)
  {
    if ((connection_limit > 0) &&
	(num_peers > connection_limit) && 
	(i % (num_peers / connection_limit) != 0))
      continue;
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "nse-profiler: connecting to nse service of peer %d\n", i);
#endif
    current_peer = GNUNET_malloc (sizeof (struct NSEPeer));
    current_peer->daemon = GNUNET_TESTING_daemon_get (pg, i);
    if (GNUNET_YES ==
        GNUNET_TESTING_test_daemon_running (GNUNET_TESTING_daemon_get (pg, i)))
    {
      current_peer->nse_handle =
          GNUNET_NSE_connect (current_peer->daemon->cfg, &handle_estimate,
                              current_peer);
      GNUNET_assert (current_peer->nse_handle != NULL);
    }
    current_peer->stats = GNUNET_STATISTICS_create("profiler", current_peer->daemon->cfg);
    GNUNET_STATISTICS_get(current_peer->stats, "core", NULL,
                          GNUNET_TIME_UNIT_FOREVER_REL,
                          &core_stats_cont, &core_stats_iterator, current_peer);
    GNUNET_STATISTICS_get(current_peer->stats, "transport", NULL,
                          GNUNET_TIME_UNIT_FOREVER_REL,
                          NULL, &core_stats_iterator, current_peer);
    GNUNET_STATISTICS_get(current_peer->stats, "nse", NULL,
                          GNUNET_TIME_UNIT_FOREVER_REL,
                          NULL, &core_stats_iterator, current_peer);
    GNUNET_CONTAINER_DLL_insert (peer_head, peer_tail, current_peer);
  }
}


static void
churn_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Continuation called by the "get_all" and "get" functions.
 *
 * @param cls struct StatsContext
 * @param success GNUNET_OK if statistics were
 *        successfully obtained, GNUNET_SYSERR if not.
 */
static void
stats_finished_callback (void *cls, int success)
{
  struct StatsContext *stats_context = cls;
  char *buf;
  int buf_len;

  if ((GNUNET_OK == success) && (data_file != NULL))
  {
    /* Stats lookup successful, write out data */
    buf = NULL;
    buf_len =
        GNUNET_asprintf (&buf, "TOTAL_NSE_RECEIVED_MESSAGES_%d: %u \n",
                         stats_context->shutdown, 
                         stats_context->total_nse_received_messages);
    if (buf_len > 0)
    {
      GNUNET_DISK_file_write (data_file, buf, buf_len);
    }
    GNUNET_free_non_null (buf);

    buf = NULL;
    buf_len =
        GNUNET_asprintf (&buf, "TOTAL_NSE_TRANSMITTED_MESSAGES_%d: %u\n",
                         stats_context->shutdown, 
                         stats_context->total_nse_transmitted_messages);
    if (buf_len > 0)
    {
      GNUNET_DISK_file_write (data_file, buf, buf_len);
    }
    GNUNET_free_non_null (buf);

    buf = NULL;
    buf_len =
        GNUNET_asprintf (&buf, "TOTAL_NSE_CROSS_%d: %u \n",
                         stats_context->shutdown, 
                         stats_context->total_nse_cross);
    if (buf_len > 0)
    {
      GNUNET_DISK_file_write (data_file, buf, buf_len);
    }
    GNUNET_free_non_null (buf);

    buf = NULL;
    buf_len =
        GNUNET_asprintf (&buf, "TOTAL_NSE_EXTRA_%d: %u \n",
                         stats_context->shutdown, 
                         stats_context->total_nse_extra);
    if (buf_len > 0)
    {
      GNUNET_DISK_file_write (data_file, buf, buf_len);
    }
    GNUNET_free_non_null (buf);

    buf = NULL;
    buf_len =
        GNUNET_asprintf (&buf, "TOTAL_NSE_DISCARDED_%d: %u \n",
                         stats_context->shutdown, 
                         stats_context->total_discarded);
    if (buf_len > 0)
    {
      GNUNET_DISK_file_write (data_file, buf, buf_len);
    }
    GNUNET_free_non_null (buf);

  }

  if (GNUNET_YES == stats_context->shutdown)
  {
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == shutdown_handle);
    shutdown_handle = GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
  }
  else
  {
    GNUNET_assert (churn_task == GNUNET_SCHEDULER_NO_TASK);
    churn_task = GNUNET_SCHEDULER_add_now (&churn_peers, NULL);
  }
  GNUNET_free (stats_context);
}


/**
 * Callback function to process statistic values.
 *
 * @param cls struct StatsContext
 * @param peer the peer the statistics belong to
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
statistics_iterator (void *cls, const struct GNUNET_PeerIdentity *peer,
                     const char *subsystem, const char *name, uint64_t value,
                     int is_persistent)
{
  struct StatsContext *stats_context = cls;

  if (0 == strcmp (subsystem, "nse"))
  {
    if (0 == strcmp (name, "# flood messages received"))
    {
      stats_context->total_nse_received_messages += value;
#if VERBOSE
      if (data_file != NULL)
      {
        char *buf;
        int buf_len;

        buf = NULL;
        buf_len =
            GNUNET_asprintf (&buf, "%s %u RECEIVED\n", GNUNET_i2s(peer), value);
        if (buf_len > 0)
        {
          GNUNET_DISK_file_write (data_file, buf, buf_len);
        }
        GNUNET_free_non_null (buf);
      }
#endif
    }
    if (0 == strcmp (name, "# flood messages transmitted"))
    {
      stats_context->total_nse_transmitted_messages += value;
#if VERBOSE
      if (data_file != NULL)
      {
        char *buf;
        int buf_len;

        buf = NULL;
        buf_len =
            GNUNET_asprintf (&buf, "%s %u TRANSMITTED\n", 
                             GNUNET_i2s(peer), value);
        if (buf_len > 0)
        {
          GNUNET_DISK_file_write (data_file, buf, buf_len);
        }
        GNUNET_free_non_null (buf);
      }
#endif
    }
    if (0 == strcmp (name, "# cross messages"))
    {
      stats_context->total_nse_cross += value;
    }
    if (0 == strcmp (name, "# extra messages"))
    {
      stats_context->total_nse_extra += value;
    }
    if (0 == strcmp (name, "# flood messages discarded (clock skew too large)"))
    {
      stats_context->total_discarded += value;
    }
  }
  return GNUNET_OK;
}


static void
disconnect_nse_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NSEPeer *pos;
  char *buf;
  struct StatsContext *stats_context;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "disconnecting nse service of peers\n");
  disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  while (NULL != (pos = peer_head))
  {
    if (pos->nse_handle != NULL)
    {
      GNUNET_NSE_disconnect (pos->nse_handle);
      pos->nse_handle = NULL;
    }
    GNUNET_CONTAINER_DLL_remove (peer_head, peer_tail, pos);
    if (NULL != pos->stats)
      GNUNET_STATISTICS_destroy(pos->stats, GNUNET_NO);
    if (GNUNET_SCHEDULER_NO_TASK != pos->stats_task)
      GNUNET_SCHEDULER_cancel (pos->stats_task);
    GNUNET_free (pos);
  }

  GNUNET_asprintf (&buf, "round%llu", current_round);
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (testing_cfg, "nse-profiler", buf,
                                             &peers_next_round))
  {
    current_round++;
    if (current_round == 1)
    {
      stats_context = GNUNET_malloc (sizeof (struct StatsContext));
      stats_context->shutdown = GNUNET_NO;
      GNUNET_TESTING_get_statistics (pg, &stats_finished_callback,
                                    &statistics_iterator, stats_context);
    }
    else
    {
      GNUNET_assert (churn_task == GNUNET_SCHEDULER_NO_TASK);
      churn_task = GNUNET_SCHEDULER_add_now (&churn_peers, NULL);
    }
  }
  else                          /* No more rounds, let's shut it down! */
  {
    stats_context = GNUNET_malloc (sizeof (struct StatsContext));
    stats_context->shutdown = GNUNET_YES;
    GNUNET_SCHEDULER_cancel (shutdown_handle);
    shutdown_handle = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_TESTING_get_statistics (pg, &stats_finished_callback,
                                   &statistics_iterator, stats_context);
  }
  GNUNET_free (buf);
}


/**
 * FIXME.
 *
 * @param cls unused
 * @param emsg NULL on success
 */
static void
topology_output_callback (void *cls, const char *emsg)
{
  disconnect_task =
      GNUNET_SCHEDULER_add_delayed (wait_time, &disconnect_nse_peers, NULL);
  GNUNET_SCHEDULER_add_now (&connect_nse_service, NULL);
}


/**
 * FIXME.
 *
 * @param cls closure
 * @param emsg NULL on success
 */
static void
churn_callback (void *cls, const char *emsg)
{
  char *temp_output_file;

  if (emsg == NULL)             /* Everything is okay! */
  {
    peers_running = peers_next_round;
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Round %llu, churn finished successfully.\n", current_round);
    GNUNET_assert (disconnect_task == GNUNET_SCHEDULER_NO_TASK);
    GNUNET_asprintf (&temp_output_file, "%s_%llu.dot", topology_file,
                     current_round);
    GNUNET_TESTING_peergroup_topology_to_file (pg, temp_output_file,
                                               &topology_output_callback, NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Writing topology to file %s\n",
                temp_output_file);
    GNUNET_free (temp_output_file);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Round %llu, churn FAILED!!\n",
                current_round);
    GNUNET_SCHEDULER_cancel (shutdown_handle);
    shutdown_handle = GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
  }
}


static void
churn_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  /* peers_running = GNUNET_TESTING_daemons_running(pg); */
  churn_task = GNUNET_SCHEDULER_NO_TASK;
  if (peers_next_round == peers_running)
  {
    /* Nothing to do... */
    GNUNET_SCHEDULER_add_now (&connect_nse_service, NULL);
    GNUNET_assert (disconnect_task == GNUNET_SCHEDULER_NO_TASK);
    disconnect_task =
        GNUNET_SCHEDULER_add_delayed (wait_time, &disconnect_nse_peers, NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Round %lu, doing nothing!\n",
                current_round);
  }
  else
  {
    if (peers_next_round > num_peers)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Asked to turn on more peers than we have!!\n");
      GNUNET_SCHEDULER_cancel (shutdown_handle);
      GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
    }
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Round %llu, turning off %llu peers, turning on %llu peers!\n",
                current_round,
                (peers_running >
                 peers_next_round) ? peers_running - peers_next_round : 0,
                (peers_next_round >
                 peers_running) ? peers_next_round - peers_running : 0);
    GNUNET_TESTING_daemons_churn (pg, "nse",
                                  (peers_running >
                                   peers_next_round) ? peers_running -
                                  peers_next_round : 0,
                                  (peers_next_round >
                                   peers_running) ? peers_next_round -
                                  peers_running : 0, wait_time, &churn_callback,
                                  NULL);
  }
}


static void
nse_started_cb (void *cls, const char *emsg)
{
  GNUNET_SCHEDULER_add_now (&connect_nse_service, NULL);
  disconnect_task =
      GNUNET_SCHEDULER_add_delayed (wait_time, &disconnect_nse_peers, NULL);
}


static void
my_cb (void *cls, const char *emsg)
{
  char *buf;
  int buf_len;

  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peergroup callback called with error, aborting test!\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Error from testing: `%s'\n");
    ok = 1;
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
    return;
  }
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer Group started successfully, connecting to NSE service for each peer!\n");
#endif
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Have %u connections\n",
              total_connections);
  if (data_file != NULL)
  {
    buf = NULL;
    buf_len = GNUNET_asprintf (&buf, "CONNECTIONS_0: %u\n", total_connections);
    if (buf_len > 0)
      GNUNET_DISK_file_write (data_file, buf, buf_len);
    GNUNET_free (buf);
  }
  peers_running = GNUNET_TESTING_daemons_running (pg);
  GNUNET_TESTING_daemons_start_service (pg, "nse", wait_time, &nse_started_cb,
                                        NULL);

}


/**
 * Function that will be called whenever two daemons are connected by
 * the testing library.
 *
 * @param cls closure
 * @param first peer id for first daemon
 * @param second peer id for the second daemon
 * @param distance distance between the connected peers
 * @param first_cfg config for the first daemon
 * @param second_cfg config for the second daemon
 * @param first_daemon handle for the first daemon
 * @param second_daemon handle for the second daemon
 * @param emsg error message (NULL on success)
 */
static void
connect_cb (void *cls, const struct GNUNET_PeerIdentity *first,
            const struct GNUNET_PeerIdentity *second, uint32_t distance,
            const struct GNUNET_CONFIGURATION_Handle *first_cfg,
            const struct GNUNET_CONFIGURATION_Handle *second_cfg,
            struct GNUNET_TESTING_Daemon *first_daemon,
            struct GNUNET_TESTING_Daemon *second_daemon, const char *emsg)
{
  if (emsg == NULL)
    total_connections++;
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *temp_str;
  struct GNUNET_TESTING_Host *hosts;
  char *data_filename;

  ok = 1;
  //testing_cfg = GNUNET_CONFIGURATION_create ();
  testing_cfg = GNUNET_CONFIGURATION_dup (cfg);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting daemons.\n");
  GNUNET_CONFIGURATION_set_value_string (testing_cfg, "testing",
                                         "use_progressbars", "YES");
#endif
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (testing_cfg, "testing",
                                             "num_peers", &num_peers))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Option TESTING:NUM_PEERS is required!\n");
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (testing_cfg, "nse-profiler",
                                           "WAIT_TIME", &wait_time))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Option nse-profiler:wait_time is required!\n");
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (testing_cfg, "nse",
                                           "INTERVAL", &interval))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Option nse:interval is required!\n");
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (testing_cfg, "nse-profiler",
                                             "connection_limit",
                                             &connection_limit))
  {
    connection_limit = 0;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (testing_cfg, "nse-profiler",
                                             "topology_output_file",
                                             &topology_file))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Option nse-profiler:topology_output_file is required!\n");
    return;
  }

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (testing_cfg, "nse-profiler",
                                             "data_output_file",
                                             &data_filename))
  {
    data_file =
        GNUNET_DISK_file_open (data_filename,
                               GNUNET_DISK_OPEN_READWRITE |
                               GNUNET_DISK_OPEN_TRUNCATE |
                               GNUNET_DISK_OPEN_CREATE,
                               GNUNET_DISK_PERM_USER_READ |
                               GNUNET_DISK_PERM_USER_WRITE);
    if (data_file == NULL)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Failed to open %s for output!\n",
                  data_filename);
    GNUNET_free (data_filename);
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "nse-profiler", "output_file",
                                             &temp_str))
  {
    output_file =
        GNUNET_DISK_file_open (temp_str,
                               GNUNET_DISK_OPEN_READWRITE |
                               GNUNET_DISK_OPEN_CREATE,
                               GNUNET_DISK_PERM_USER_READ |
                               GNUNET_DISK_PERM_USER_WRITE);
    if (output_file == NULL)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Failed to open %s for output!\n",
                  temp_str);
  }
  GNUNET_free_non_null (temp_str);

  hosts = GNUNET_TESTING_hosts_load (testing_cfg);

  pg = GNUNET_TESTING_peergroup_start (testing_cfg, num_peers, TIMEOUT,
                                       &connect_cb, &my_cb, NULL, hosts);
  GNUNET_assert (pg != NULL);
  shutdown_handle =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                    &shutdown_task, NULL);
}



/**
 * nse-profiler command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'V', "verbose", NULL,
   gettext_noop ("be verbose (print progress information)"),
   0, &GNUNET_GETOPT_set_one, &verbose},
  GNUNET_GETOPT_OPTION_END
};


int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("nse-profiler",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  GNUNET_PROGRAM_run (argc, argv, "nse-profiler",
                      gettext_noop
                      ("Measure quality and performance of the NSE service."),
                      options, &run, NULL);
#if REMOVE_DIR
  GNUNET_DISK_directory_remove ("/tmp/nse-profiler");
#endif
  return ok;
}

/* end of nse-profiler.c */
