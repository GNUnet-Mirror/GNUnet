/*
 This file is part of GNUnet
 (C) 2008-2011 Christian Grothoff (and other contributing authors)

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
 * @file testing/testing_peergroup.c
 * @brief API implementation for easy peer group creation
 * @author Nathan Evans
 * @author Christian Grothoff
 *
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_disk_lib.h"

/** Globals **/
#define DEFAULT_CONNECT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

#define DEFAULT_CONNECT_ATTEMPTS 2

/** Struct definitions **/

struct PeerGroupStartupContext
{
  struct GNUNET_TESTING_PeerGroup *pg;
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  unsigned int total;
  unsigned int peers_left;
  unsigned long long max_concurrent_connections;

  /**
   * Maximum attemps to connect two daemons.
   */
  unsigned long long connect_attempts;

  /**
   * How long to spend trying to establish all the connections?
   */
  struct GNUNET_TIME_Relative connect_timeout;

  unsigned long long max_concurrent_ssh;
  struct GNUNET_TIME_Absolute timeout;
  GNUNET_TESTING_NotifyConnection connect_cb;
  GNUNET_TESTING_NotifyCompletion peergroup_cb;

  /**
   * Closure for all peergroup callbacks.
   */
  void *cls;

  const struct GNUNET_TESTING_Host *hostnames;
  
  /**
   * FIXME document
   */
  enum GNUNET_TESTING_Topology topology;

  float topology_percentage;

  float topology_probability;

  /**
   * FIXME document
   */
  enum GNUNET_TESTING_Topology restrict_topology;
  
  /**
   * FIXME document
   */
  char *restrict_transports;
  
  /**
   * Initial connections
   */
  enum GNUNET_TESTING_Topology connect_topology;
  enum GNUNET_TESTING_TopologyOption connect_topology_option;
  double connect_topology_option_modifier;
  int verbose;

  struct ProgressMeter *hostkey_meter;
  struct ProgressMeter *peer_start_meter;
  struct ProgressMeter *connect_meter;

  /**
   * Task used to kill the peergroup.
   */
  GNUNET_SCHEDULER_TaskIdentifier die_task;

  char *fail_reason;

  /**
   * Variable used to store the number of connections we should wait for.
   */
  unsigned int expected_connections;

  /**
   * Time when the connecting peers was started.
   */
  struct GNUNET_TIME_Absolute connect_start_time;

  /**
   * The total number of connections that have been created so far.
   */
  unsigned int total_connections;

  /**
   * The total number of connections that have failed so far.
   */
  unsigned int failed_connections;

  /**
   * File handle to write out topology in dot format.
   */
  struct GNUNET_DISK_FileHandle *topology_output_file;
};

struct TopologyOutputContext
{
  struct GNUNET_DISK_FileHandle *file;
  GNUNET_TESTING_NotifyCompletion notify_cb;
  void *notify_cb_cls;
};

/**
 * Simple struct to keep track of progress, and print a
 * percentage meter for long running tasks.
 */
struct ProgressMeter
{
  /**
   * Total number of tasks to complete.
   */
  unsigned int total;

  /**
   * Print percentage done after modnum tasks.
   */
  unsigned int modnum;

  /**
   * Print a . each dotnum tasks.
   */
  unsigned int dotnum;

  /**
   * Total number completed thus far.
   */
  unsigned int completed;

  /**
   * Whether or not to print.
   */
  int print;

  /**
   * Startup string for progress meter.
   */
  char *startup_string;
};


/** Utility functions **/

/**
 * Create a meter to keep track of the progress of some task.
 *
 * @param total the total number of items to complete
 * @param start_string a string to prefix the meter with (if printing)
 * @param print GNUNET_YES to print the meter, GNUNET_NO to count
 *              internally only
 *
 * @return the progress meter
 */
static struct ProgressMeter *
create_meter (unsigned int total, char *start_string, int print)
{
  struct ProgressMeter *ret;

  ret = GNUNET_malloc (sizeof (struct ProgressMeter));
  ret->print = print;
  ret->total = total;
  ret->modnum = (total / 4 == 0) ? 1 : (total / 4);
  ret->dotnum = (total / 50) + 1;
  if (start_string != NULL)
    ret->startup_string = GNUNET_strdup (start_string);
  else
    ret->startup_string = GNUNET_strdup ("");

  return ret;
}

/**
 * Update progress meter (increment by one).
 *
 * @param meter the meter to update and print info for
 *
 * @return GNUNET_YES if called the total requested,
 *         GNUNET_NO if more items expected
 */
static int
update_meter (struct ProgressMeter *meter)
{
  if (meter->print == GNUNET_YES)
  {
    if (meter->completed % meter->modnum == 0)
    {
      if (meter->completed == 0)
      {
        FPRINTF (stdout, "%sProgress: [0%%", meter->startup_string);
      }
      else
        FPRINTF (stdout, "%d%%",
                 (int) (((float) meter->completed / meter->total) * 100));
    }
    else if (meter->completed % meter->dotnum == 0)
      FPRINTF (stdout, "%s",  ".");

    if (meter->completed + 1 == meter->total)
      FPRINTF (stdout, "%d%%]\n", 100);
    fflush (stdout);
  }
  meter->completed++;

  if (meter->completed == meter->total)
    return GNUNET_YES;
  return GNUNET_NO;
}

/**
 * Reset progress meter.
 *
 * @param meter the meter to reset
 *
 * @return GNUNET_YES if meter reset,
 *         GNUNET_SYSERR on error
 */
static int
reset_meter (struct ProgressMeter *meter)
{
  if (meter == NULL)
    return GNUNET_SYSERR;

  meter->completed = 0;
  return GNUNET_YES;
}

/**
 * Release resources for meter
 *
 * @param meter the meter to free
 */
static void
free_meter (struct ProgressMeter *meter)
{
  GNUNET_free_non_null (meter->startup_string);
  GNUNET_free (meter);
}


/** Functions for creating, starting and connecting the peergroup **/

/**
 * Check whether peers successfully shut down.
 */
static void
internal_shutdown_callback (void *cls, const char *emsg)
{
  struct PeerGroupStartupContext *pg_start_ctx = cls;

  if (emsg != NULL)
    pg_start_ctx->peergroup_cb (pg_start_ctx->cls, emsg);
  else
    pg_start_ctx->peergroup_cb (pg_start_ctx->cls, pg_start_ctx->fail_reason);
}

/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerGroupStartupContext *pg_start_ctx = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Failing peer group startup with error: `%s'!\n",
              pg_start_ctx->fail_reason);

  GNUNET_TESTING_daemons_stop (pg_start_ctx->pg,
                               GNUNET_TIME_absolute_get_remaining
                               (pg_start_ctx->timeout),
                               &internal_shutdown_callback, pg_start_ctx);

  if (pg_start_ctx->hostkey_meter != NULL)
  {
    free_meter (pg_start_ctx->hostkey_meter);
    pg_start_ctx->hostkey_meter = NULL;
  }
  if (pg_start_ctx->peer_start_meter != NULL)
  {
    free_meter (pg_start_ctx->peer_start_meter);
    pg_start_ctx->peer_start_meter = NULL;
  }
  if (pg_start_ctx->connect_meter != NULL)
  {
    free_meter (pg_start_ctx->connect_meter);
    pg_start_ctx->connect_meter = NULL;
  }
}

/**
 * This function is called whenever a connection attempt is finished between two of
 * the started peers (started with GNUNET_TESTING_daemons_start).  The total
 * number of times this function is called should equal the number returned
 * from the GNUNET_TESTING_connect_topology call.
 *
 * The emsg variable is NULL on success (peers connected), and non-NULL on
 * failure (peers failed to connect).
 */
static void
internal_topology_callback (void *cls, const struct GNUNET_PeerIdentity *first,
                            const struct GNUNET_PeerIdentity *second,
                            uint32_t distance,
                            const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                            const struct GNUNET_CONFIGURATION_Handle
                            *second_cfg,
                            struct GNUNET_TESTING_Daemon *first_daemon,
                            struct GNUNET_TESTING_Daemon *second_daemon,
                            const char *emsg)
{
  struct PeerGroupStartupContext *pg_start_ctx = cls;
  char *temp_str;
  char *second_str;
  int temp;

#if TIMING
  unsigned long long duration;
  unsigned long long total_duration;
  unsigned int new_connections;
  unsigned int new_failed_connections;
  double conns_per_sec_recent;
  double conns_per_sec_total;
  double failed_conns_per_sec_recent;
  double failed_conns_per_sec_total;
#endif

#if TIMING
  if (GNUNET_TIME_absolute_get_difference
      (connect_last_time,
       GNUNET_TIME_absolute_get ()).rel_value >
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                     CONN_UPDATE_DURATION).rel_value)
  {
    /* Get number of new connections */
    new_connections = total_connections - previous_connections;

    /* Get number of new FAILED connections */
    new_failed_connections = failed_connections - previous_failed_connections;

    /* Get duration in seconds */
    duration =
        GNUNET_TIME_absolute_get_difference (connect_last_time,
                                             GNUNET_TIME_absolute_get
                                             ()).rel_value / 1000;
    total_duration =
        GNUNET_TIME_absolute_get_difference (connect_start_time,
                                             GNUNET_TIME_absolute_get
                                             ()).rel_value / 1000;

    failed_conns_per_sec_recent = (double) new_failed_connections / duration;
    failed_conns_per_sec_total = (double) failed_connections / total_duration;
    conns_per_sec_recent = (double) new_connections / duration;
    conns_per_sec_total = (double) total_connections / total_duration;
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Recent: %.2f/s, Total: %.2f/s, Recent failed: %.2f/s, total failed %.2f/s\n",
                conns_per_sec_recent, CONN_UPDATE_DURATION, conns_per_sec_total,
                failed_conns_per_sec_recent, failed_conns_per_sec_total);
    connect_last_time = GNUNET_TIME_absolute_get ();
    previous_connections = total_connections;
    previous_failed_connections = failed_connections;
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "have %u total_connections, %u failed\n", total_connections,
                failed_connections);
  }
#endif


  if (emsg == NULL)
  {
    pg_start_ctx->total_connections++;
#if VERBOSE > 1
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "connected peer %s to peer %s, distance %u\n",
                first_daemon->shortname, second_daemon->shortname, distance);
#endif
    if (pg_start_ctx->topology_output_file != NULL)
    {
      second_str = GNUNET_strdup (GNUNET_i2s (second));
      temp =
          GNUNET_asprintf (&temp_str, "\t\"%s\" -- \"%s\"\n",
                           GNUNET_i2s (first), second_str);
      GNUNET_free (second_str);
      if (temp > 0)
        GNUNET_DISK_file_write (pg_start_ctx->topology_output_file, temp_str,
                                temp);
      GNUNET_free (temp_str);
    }
  }
  else
  {
    pg_start_ctx->failed_connections++;
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to connect peer %s to peer %s with error :\n%s\n",
                first_daemon->shortname, second_daemon->shortname, emsg);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to connect peer %s to peer %s with error :\n%s\n",
                first_daemon->shortname, second_daemon->shortname, emsg);
#endif
  }

  GNUNET_assert (pg_start_ctx->connect_meter != NULL);
  if (pg_start_ctx->connect_cb != NULL)
    pg_start_ctx->connect_cb (pg_start_ctx->cls, first, second, distance,
                              first_cfg, second_cfg, first_daemon,
                              second_daemon, emsg);
  if (GNUNET_YES != update_meter (pg_start_ctx->connect_meter))
  {
    /* No finished yet */
    return;
  }
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Created %d total connections, which is our target number!  Starting next phase of testing.\n",
              pg_start_ctx->total_connections);
#endif

#if TIMING
  total_duration =
      GNUNET_TIME_absolute_get_difference (connect_start_time,
                                            GNUNET_TIME_absolute_get
                                            ()).rel_value / 1000;
  failed_conns_per_sec_total = (double) failed_connections / total_duration;
  conns_per_sec_total = (double) total_connections / total_duration;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Overall connection info --- Total: %u, Total Failed %u/s\n",
              total_connections, failed_connections);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Overall connection info --- Total: %.2f/s, Total Failed %.2f/s\n",
              conns_per_sec_total, failed_conns_per_sec_total);
#endif

  GNUNET_assert (pg_start_ctx->die_task != GNUNET_SCHEDULER_NO_TASK);
  GNUNET_SCHEDULER_cancel (pg_start_ctx->die_task);

  /* Call final callback, signifying that the peer group has been started and connected */
  if (pg_start_ctx->peergroup_cb != NULL)
    pg_start_ctx->peergroup_cb (pg_start_ctx->cls, NULL);

  if (pg_start_ctx->topology_output_file != NULL)
  {
    temp = GNUNET_asprintf (&temp_str, "}\n");
    if (temp > 0)
      GNUNET_DISK_file_write (pg_start_ctx->topology_output_file, temp_str,
                              temp);
    GNUNET_free (temp_str);
    GNUNET_DISK_file_close (pg_start_ctx->topology_output_file);
  }
  GNUNET_free_non_null (pg_start_ctx->fail_reason);
  if (NULL != pg_start_ctx->hostkey_meter)
    free_meter(pg_start_ctx->hostkey_meter);
  if (NULL != pg_start_ctx->peer_start_meter)
    free_meter(pg_start_ctx->peer_start_meter);
  if (NULL != pg_start_ctx->connect_meter)
    free_meter(pg_start_ctx->connect_meter);
  GNUNET_free (pg_start_ctx);
}


/**
 * Callback called for each started daemon.
 *
 * @param cls Clause (PG Context).
 * @param id PeerIdentidy of started daemon.
 * @param cfg Configuration used by the daemon.
 * @param d Handle for the daemon.
 * @param emsg Error message, NULL on success.
 */
static void
internal_peers_started_callback (void *cls,
                                 const struct GNUNET_PeerIdentity *id,
                                 const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 struct GNUNET_TESTING_Daemon *d,
                                 const char *emsg)
{
  struct PeerGroupStartupContext *pg_start_ctx = cls;

  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to start daemon with error: `%s'\n", emsg);
    return;
  }
  GNUNET_assert (id != NULL);

#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Started daemon %llu out of %llu\n",
              (pg_start_ctx->total - pg_start_ctx->peers_left) + 1,
              pg_start_ctx->total);
#endif

  pg_start_ctx->peers_left--;

  if (NULL == pg_start_ctx->peer_start_meter)
  {
    /* Cancelled Ctrl-C or error */
    return;
  }
  if (GNUNET_YES == update_meter (pg_start_ctx->peer_start_meter))
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All %d daemons started, now connecting peers!\n",
                pg_start_ctx->total);
#endif
    GNUNET_assert (pg_start_ctx->die_task != GNUNET_SCHEDULER_NO_TASK);
    GNUNET_SCHEDULER_cancel (pg_start_ctx->die_task);

    pg_start_ctx->expected_connections = UINT_MAX;
    // FIXME: why whould peers_left be != 0?? Or pg NULL?
    if ((pg_start_ctx->pg != NULL) && (pg_start_ctx->peers_left == 0))
    {
      pg_start_ctx->connect_start_time = GNUNET_TIME_absolute_get ();
      pg_start_ctx->expected_connections =
          GNUNET_TESTING_connect_topology (pg_start_ctx->pg,
                                           pg_start_ctx->connect_topology,
                                           pg_start_ctx->connect_topology_option,
                                           pg_start_ctx->connect_topology_option_modifier,
                                           pg_start_ctx->connect_timeout,
                                           pg_start_ctx->connect_attempts, NULL,
                                           NULL);

      pg_start_ctx->connect_meter =
          create_meter (pg_start_ctx->expected_connections, "Peer connection ",
                        pg_start_ctx->verbose);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Have %d expected connections\n",
                  pg_start_ctx->expected_connections);
    }

    if (pg_start_ctx->expected_connections == 0)
    {
      GNUNET_free_non_null (pg_start_ctx->fail_reason);
      pg_start_ctx->fail_reason =
          GNUNET_strdup ("from connect topology (bad return)");
      pg_start_ctx->die_task =
          GNUNET_SCHEDULER_add_now (&end_badly, pg_start_ctx);
      return;
    }

    GNUNET_free_non_null (pg_start_ctx->fail_reason);
    pg_start_ctx->fail_reason =
        GNUNET_strdup ("from connect topology (timeout)");
    pg_start_ctx->die_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                      (pg_start_ctx->timeout), &end_badly,
                                      pg_start_ctx);
  }
}

/**
 * Callback indicating that the hostkey was created for a peer.
 *
 * @param cls NULL
 * @param id the peer identity
 * @param d the daemon handle (pretty useless at this point, remove?)
 * @param emsg non-null on failure
 */
static void
internal_hostkey_callback (void *cls, const struct GNUNET_PeerIdentity *id,
                           struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  struct PeerGroupStartupContext *pg_start_ctx = cls;
  unsigned int create_expected_connections;

  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Hostkey callback received error: %s\n", emsg);
  }

#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Hostkey (%d/%d) created for peer `%s'\n",
              pg_start_ctx->total - pg_start_ctx->peers_left + 1,
              pg_start_ctx->total, GNUNET_i2s (id));
#endif

  pg_start_ctx->peers_left--;
  if (GNUNET_YES == update_meter (pg_start_ctx->hostkey_meter))
  {
    GNUNET_SCHEDULER_cancel (pg_start_ctx->die_task);
    GNUNET_free_non_null (pg_start_ctx->fail_reason);
    /* Set up task in case topology creation doesn't finish
     * within a reasonable amount of time */
    pg_start_ctx->fail_reason = GNUNET_strdup ("from create_topology");
    pg_start_ctx->die_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                      (pg_start_ctx->timeout), &end_badly,
                                      pg_start_ctx);
    pg_start_ctx->peers_left = pg_start_ctx->total;     /* Reset counter */
    create_expected_connections =
        GNUNET_TESTING_create_topology (pg_start_ctx->pg,
                                        pg_start_ctx->topology,
                                        pg_start_ctx->restrict_topology,
                                        pg_start_ctx->restrict_transports);
    if (create_expected_connections > 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Topology set up, have %u expected connections, now starting peers!\n",
                  create_expected_connections);
      GNUNET_TESTING_daemons_continue_startup (pg_start_ctx->pg);
    }
    else
    {
      GNUNET_SCHEDULER_cancel (pg_start_ctx->die_task);
      GNUNET_free_non_null (pg_start_ctx->fail_reason);
      pg_start_ctx->fail_reason =
          GNUNET_strdup ("from create topology (bad return)");
      pg_start_ctx->die_task =
          GNUNET_SCHEDULER_add_now (&end_badly, pg_start_ctx);
      return;
    }

    GNUNET_SCHEDULER_cancel (pg_start_ctx->die_task);
    GNUNET_free_non_null (pg_start_ctx->fail_reason);
    pg_start_ctx->fail_reason =
        GNUNET_strdup ("from continue startup (timeout)");
    pg_start_ctx->die_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                      (pg_start_ctx->timeout), &end_badly,
                                      pg_start_ctx);
  }
}


/**
 * Prototype of a callback function indicating that two peers
 * are currently connected.
 *
 * @param cls closure
 * @param first peer id for first daemon
 * @param second peer id for the second daemon
 * @param emsg error message (NULL on success)
 */
void
write_topology_cb (void *cls, const struct GNUNET_PeerIdentity *first,
                   const struct GNUNET_PeerIdentity *second, const char *emsg)
{
  struct TopologyOutputContext *topo_ctx;
  int temp;
  char *temp_str;
  char *temp_pid2;

  topo_ctx = (struct TopologyOutputContext *) cls;
  GNUNET_assert (topo_ctx->file != NULL);
  if ((emsg == NULL) && (first != NULL) && (second != NULL))
  {
    GNUNET_assert (first != NULL);
    GNUNET_assert (second != NULL);
    temp_pid2 = GNUNET_strdup (GNUNET_i2s (second));
    temp =
        GNUNET_asprintf (&temp_str, "\t\"%s\" -- \"%s\"\n", GNUNET_i2s (first),
                         temp_pid2);
    GNUNET_free (temp_pid2);
    GNUNET_DISK_file_write (topo_ctx->file, temp_str, temp);
  }
  else if ((emsg == NULL) && (first == NULL) && (second == NULL))
  {
    temp = GNUNET_asprintf (&temp_str, "}\n");
    GNUNET_DISK_file_write (topo_ctx->file, temp_str, temp);
    GNUNET_DISK_file_close (topo_ctx->file);
    topo_ctx->notify_cb (topo_ctx->notify_cb_cls, NULL);
    GNUNET_free (topo_ctx);
  }
  else
  {
    temp = GNUNET_asprintf (&temp_str, "}\n");
    GNUNET_DISK_file_write (topo_ctx->file, temp_str, temp);
    GNUNET_DISK_file_close (topo_ctx->file);
    topo_ctx->notify_cb (topo_ctx->notify_cb_cls, emsg);
    GNUNET_free (topo_ctx);
  }
}

/**
 * Print current topology to a graphviz readable file.
 *
 * @param pg a currently running peergroup to print to file
 * @param output_filename the file to write the topology to
 * @param notify_cb callback to call upon completion or failure
 * @param notify_cb_cls closure for notify_cb
 *
 */
void
GNUNET_TESTING_peergroup_topology_to_file (struct GNUNET_TESTING_PeerGroup *pg,
                                           const char *output_filename,
                                           GNUNET_TESTING_NotifyCompletion
                                           notify_cb, void *notify_cb_cls)
{
  struct TopologyOutputContext *topo_ctx;
  int temp;
  char *temp_str;

  topo_ctx = GNUNET_malloc (sizeof (struct TopologyOutputContext));

  topo_ctx->notify_cb = notify_cb;
  topo_ctx->notify_cb_cls = notify_cb_cls;
  topo_ctx->file =
      GNUNET_DISK_file_open (output_filename,
                             GNUNET_DISK_OPEN_READWRITE |
                             GNUNET_DISK_OPEN_CREATE,
                             GNUNET_DISK_PERM_USER_READ |
                             GNUNET_DISK_PERM_USER_WRITE);
  if (topo_ctx->file == NULL)
  {
    notify_cb (notify_cb_cls, "Failed to open output file!");
    GNUNET_free (topo_ctx);
    return;
  }

  temp = GNUNET_asprintf (&temp_str, "strict graph G {\n");
  if (temp > 0)
    GNUNET_DISK_file_write (topo_ctx->file, temp_str, temp);
  GNUNET_free_non_null (temp_str);
  GNUNET_TESTING_get_topology (pg, &write_topology_cb, topo_ctx);
}

/**
 * Start a peer group with a given number of peers.  Notify
 * on completion of peer startup and connection based on given
 * topological constraints.  Optionally notify on each
 * established connection.
 *
 * @param cfg configuration template to use
 * @param total number of daemons to start
 * @param timeout total time allowed for peers to start
 * @param connect_cb function to call each time two daemons are connected
 * @param peergroup_cb function to call once all peers are up and connected
 * @param peergroup_cls closure for peergroup callbacks
 * @param hostnames linked list of host structs to use to start peers on
 *                  (NULL to run on localhost only)
 *
 * @return NULL on error, otherwise handle to control peer group
 */
struct GNUNET_TESTING_PeerGroup *
GNUNET_TESTING_peergroup_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                unsigned int total,
                                struct GNUNET_TIME_Relative timeout,
                                GNUNET_TESTING_NotifyConnection connect_cb,
                                GNUNET_TESTING_NotifyCompletion peergroup_cb,
                                void *peergroup_cls,
                                const struct GNUNET_TESTING_Host *hostnames)
{
  struct PeerGroupStartupContext *pg_start_ctx;
  char *temp_str;
  int temp;
  struct GNUNET_TIME_Relative rtimeout;

  GNUNET_assert (total > 0);
  GNUNET_assert (cfg != NULL);

  pg_start_ctx = GNUNET_malloc (sizeof (struct PeerGroupStartupContext));

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "connect_attempts",
                                             &pg_start_ctx->connect_attempts))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Must provide option %s:%s!\n",
                "testing", "connect_attempts");
    GNUNET_free (pg_start_ctx);
    return NULL;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg, "testing", "CONNECT_TIMEOUT",
                                           &pg_start_ctx->connect_timeout))
  {
    pg_start_ctx->connect_timeout = DEFAULT_CONNECT_TIMEOUT;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing",
                                             "max_outstanding_connections",
                                             &pg_start_ctx->max_concurrent_connections))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Must provide option %s:%s!\n",
                "testing", "max_outstanding_connections");
    GNUNET_free (pg_start_ctx);
    return NULL;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing",
                                             "max_concurrent_ssh",
                                             &pg_start_ctx->max_concurrent_ssh))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Must provide option %s:%s!\n",
                "testing", "max_concurrent_ssh");
    GNUNET_free (pg_start_ctx);
    return NULL;
  }

  if (GNUNET_SYSERR ==
      (pg_start_ctx->verbose =
       GNUNET_CONFIGURATION_get_value_yesno (cfg, "testing",
                                             "use_progressbars")))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Must provide option %s:%s!\n",
                "testing", "use_progressbars");
    GNUNET_free (pg_start_ctx);
    return NULL;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg, "testing", "PEERGROUP_TIMEOUT",
                                           &rtimeout))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Must provide option %s:%s!\n",
                "testing", "PEERGROUP_TIMEOUT");
    GNUNET_free (pg_start_ctx);
    return NULL;
  }
  pg_start_ctx->timeout = GNUNET_TIME_relative_to_absolute (rtimeout);


  /* Read topology related options from the configuration file */
  temp_str = NULL;
  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "topology",
                                              &temp_str)) &&
      (GNUNET_NO ==
       GNUNET_TESTING_topology_get (&pg_start_ctx->topology, temp_str)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid topology `%s' given for section %s option %s\n",
                temp_str, "TESTING", "TOPOLOGY");
    pg_start_ctx->topology = GNUNET_TESTING_TOPOLOGY_CLIQUE;    /* Defaults to NONE, so set better default here */
  }
  GNUNET_free_non_null (temp_str);

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                             "topology_output_file", &temp_str))
  {
    pg_start_ctx->topology_output_file =
        GNUNET_DISK_file_open (temp_str,
                               GNUNET_DISK_OPEN_READWRITE |
                               GNUNET_DISK_OPEN_CREATE,
                               GNUNET_DISK_PERM_USER_READ |
                               GNUNET_DISK_PERM_USER_WRITE);
    if (pg_start_ctx->topology_output_file != NULL)
    {
      GNUNET_free (temp_str);
      temp = GNUNET_asprintf (&temp_str, "strict graph G {\n");
      if (temp > 0)
        GNUNET_DISK_file_write (pg_start_ctx->topology_output_file, temp_str,
                                temp);
    }
    GNUNET_free (temp_str);
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "percentage",
                                             &temp_str))
    pg_start_ctx->topology_percentage = 0.5;
  else
  {
    pg_start_ctx->topology_percentage = atof (temp_str);
    GNUNET_free (temp_str);
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "probability",
                                             &temp_str))
    pg_start_ctx->topology_probability = 0.5;
  else
  {
    pg_start_ctx->topology_probability = atof (temp_str);
    GNUNET_free (temp_str);
  }

  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                              "connect_topology", &temp_str)) &&
      (GNUNET_NO ==
       GNUNET_TESTING_topology_get (&pg_start_ctx->connect_topology, temp_str)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid connect topology `%s' given for section %s option %s\n",
                temp_str, "TESTING", "CONNECT_TOPOLOGY");
  }
  GNUNET_free_non_null (temp_str);

  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                              "connect_topology_option",
                                              &temp_str)) &&
      (GNUNET_NO ==
       GNUNET_TESTING_topology_option_get
       (&pg_start_ctx->connect_topology_option, temp_str)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid connect topology option `%s' given for section %s option %s\n",
                temp_str, "TESTING", "CONNECT_TOPOLOGY_OPTION");
    pg_start_ctx->connect_topology_option = GNUNET_TESTING_TOPOLOGY_OPTION_ALL; /* Defaults to NONE, set to ALL */
  }
  GNUNET_free_non_null (temp_str);

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                             "connect_topology_option_modifier",
                                             &temp_str))
  {
    if (SSCANF
        (temp_str, "%lf", &pg_start_ctx->connect_topology_option_modifier) != 1)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
                  temp_str, "connect_topology_option_modifier", "TESTING");
      GNUNET_free (temp_str);
      GNUNET_free (pg_start_ctx);
      return NULL;
    }
    GNUNET_free (temp_str);
  }

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                             "blacklist_transports",
                                             &pg_start_ctx->restrict_transports))
    pg_start_ctx->restrict_transports = NULL;

  pg_start_ctx->restrict_topology = GNUNET_TESTING_TOPOLOGY_NONE;
  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                              "blacklist_topology", &temp_str))
      && (GNUNET_NO ==
          GNUNET_TESTING_topology_get (&pg_start_ctx->restrict_topology,
                                       temp_str)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid topology `%s' given for section %s option %s\n",
                temp_str, "TESTING", "BLACKLIST_TOPOLOGY");
  }

  GNUNET_free_non_null (temp_str);

  pg_start_ctx->cfg = cfg;
  pg_start_ctx->total = total;
  pg_start_ctx->peers_left = total;
  pg_start_ctx->connect_cb = connect_cb;
  pg_start_ctx->peergroup_cb = peergroup_cb;
  pg_start_ctx->cls = peergroup_cls;
  pg_start_ctx->hostnames = hostnames;
  pg_start_ctx->hostkey_meter =
      create_meter (pg_start_ctx->peers_left, "Hostkeys created ",
                    pg_start_ctx->verbose);
  pg_start_ctx->peer_start_meter =
      create_meter (pg_start_ctx->peers_left, "Peers started ",
                    pg_start_ctx->verbose);
  /* Make compilers happy */
  reset_meter (pg_start_ctx->peer_start_meter);
  pg_start_ctx->fail_reason =
      GNUNET_strdup
      ("didn't generate all hostkeys within allowed startup time!");
  pg_start_ctx->die_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                    (pg_start_ctx->timeout), &end_badly,
                                    pg_start_ctx);

  pg_start_ctx->pg =
      GNUNET_TESTING_daemons_start (pg_start_ctx->cfg, pg_start_ctx->peers_left,
                                    pg_start_ctx->max_concurrent_connections,
                                    pg_start_ctx->max_concurrent_ssh,
                                    GNUNET_TIME_absolute_get_remaining
                                    (pg_start_ctx->timeout),
                                    &internal_hostkey_callback, pg_start_ctx,
                                    &internal_peers_started_callback,
                                    pg_start_ctx, &internal_topology_callback,
                                    pg_start_ctx, pg_start_ctx->hostnames);

  return pg_start_ctx->pg;
}

/* end of testing_peergroup.c */
