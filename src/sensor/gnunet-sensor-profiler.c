/*
     This file is part of GNUnet.
     Copyright (C)

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
 * @file sensor/gnunet-sensor-profiler.c
 * @brief Profiler for the sensor service
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_peerstore_service.h"
#include "gnunet_sensor_service.h"
#include "gnunet_sensor_util_lib.h"
#include "gnunet_transport_service.h"

/**
 * Time to wait for the peer to startup completely
 */
#define PEER_STARTUP_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * Information about a single peer
 */
struct PeerInfo
{

  /**
   * Peer Identity
   */
  struct GNUNET_PeerIdentity peer_id;

  /**
   * Testbed peer handle
   */
  struct GNUNET_TESTBED_Peer *testbed_peer;

  /**
   * Index of this peer within our list
   */
  int index;

  /**
   * TESTBED operation used to connect to statistics service
   */
  struct GNUNET_TESTBED_Operation *statistics_op;

  /**
   * Handle to the peer's statistics service
   */
  struct GNUNET_STATISTICS_Handle *statistics;

};

/**
 * Name of the configuration file used
 */
static const char *cfg_filename = "gnunet-sensor-profiler.conf";

/**
 * Directory to read sensor definitions from
 */
static const char *sensor_src_dir = "sensors";

/**
 * Directory to write new sensor definitions to
 */
static const char *sensor_dst_dir = "/tmp/gnunet-sensor-profiler";

/**
 * Scheduled task to shutdown
 */
static struct GNUNET_SCHEDULER_Task * shutdown_task = NULL;

/**
 * GNUnet configuration
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Number of peers to run (Option -p)
 */
static unsigned int num_peers = 0;

/**
 * Set sensors running interval to this value (Option -i)
 */
static unsigned int sensors_interval = 0;

/**
 * Path to topology file (Option -t)
 */
static char *topology_file;

/**
 * Number of peers to simulate anomalies on (Option -a)
 */
static unsigned int anomalous_peers = 0;

/**
 * Array of peer info for all peers
 */
static struct PeerInfo *all_peers_info;

/**
 * Number of peers that we already collected and start their info
 */
static int peers_known = 0;

/**
 * TESTBED operation connecting us to peerstore service on collection point
 */
static struct GNUNET_TESTBED_Operation *peerstore_op;

/**
 * Handle to peerstore service on collection point
 */
static struct GNUNET_PEERSTORE_Handle *peerstore;

/**
 * Dashboard service on collection point started?
 */
static int dashboard_service_started = GNUNET_NO;

/**
 * Number of peers started the sensor service successfully
 */
static int sensor_services_started = 0;

/**
 * Array of sensor names to be used for watching peerstore records
 */
static char **sensor_names;

/**
 * Size of 'sensor_names' array
 */
static unsigned int sensor_names_size = 0;

/**
 * Task run after any waiting period
 */
static struct GNUNET_SCHEDULER_Task * delayed_task = NULL;


/**
 * Copy directory recursively
 *
 * @param src Path to source directory
 * @param dst Destination directory, will be created if it does not exist
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
copy_dir (const char *src, const char *dst);


/**
 * Do clean up and shutdown scheduler
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutting down.\n");
  if (NULL != delayed_task)
  {
    GNUNET_SCHEDULER_cancel (delayed_task);
    delayed_task = NULL;
  }
  for (i = 0; i < num_peers; i++)
  {
    if (NULL != all_peers_info[i].statistics_op)
    {
      GNUNET_TESTBED_operation_done (all_peers_info[i].statistics_op);
      all_peers_info[i].statistics_op = NULL;
    }
  }
  if (NULL != peerstore_op)
  {
    GNUNET_TESTBED_operation_done (peerstore_op);
    peerstore_op = NULL;
  }
  if (NULL != all_peers_info)
  {
    GNUNET_free (all_peers_info);
    all_peers_info = NULL;
  }
  if (NULL != cfg)
  {
    GNUNET_CONFIGURATION_destroy (cfg);
    cfg = NULL;
  }
  if (NULL != sensor_names)
  {
    for (i = 0; i < sensor_names_size; i++)
      GNUNET_free (sensor_names[i]);
    GNUNET_array_grow (sensor_names, sensor_names_size, 0);
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Function called with each file/folder inside a directory that is being copied.
 *
 * @param cls closure, destination directory
 * @param filename complete filename (absolute path)
 * @return #GNUNET_OK to continue to iterate.
 *         #GNUNET_SYSERR to abort iteration with error
 */
static int
copy_dir_scanner (void *cls, const char *filename)
{
  char *dst_dir = cls;
  char *dst;
  int copy_result;

  GNUNET_asprintf (&dst, "%s%s%s", dst_dir, DIR_SEPARATOR_STR,
                   GNUNET_STRINGS_get_short_name (filename));
  if (GNUNET_YES == GNUNET_DISK_directory_test (filename, GNUNET_YES))
    copy_result = copy_dir (filename, dst);
  else
  {
    if (GNUNET_YES == GNUNET_DISK_file_test (dst))
      GNUNET_DISK_directory_remove (dst);
    copy_result = GNUNET_DISK_file_copy (filename, dst);
    if (GNUNET_OK == copy_result)
      GNUNET_DISK_fix_permissions (dst, GNUNET_NO, GNUNET_NO);
  }
  GNUNET_free (dst);
  return copy_result;
}


/**
 * Copy directory recursively
 *
 * @param src Path to source directory
 * @param dst Destination directory, will be created if it does not exist
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
copy_dir (const char *src, const char *dst)
{
  if (GNUNET_YES != GNUNET_DISK_directory_test (src, GNUNET_YES))
    return GNUNET_SYSERR;
  if (GNUNET_OK != GNUNET_DISK_directory_create (dst))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      GNUNET_DISK_directory_scan (src, &copy_dir_scanner, (char *) dst))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Function called with each file/folder inside source sensor directory.
 *
 * @param cls closure (unused)
 * @param filename complete filename (absolute path)
 * @return #GNUNET_OK to continue to iterate.
 */
static int
sensor_dir_scanner (void *cls, const char *filename)
{
  const char *file_basename;
  char *dst_path;
  struct GNUNET_CONFIGURATION_Handle *sensor_cfg;
  char *sensor_name;

  file_basename = GNUNET_STRINGS_get_short_name (filename);
  GNUNET_asprintf (&dst_path, "%s%s%s", sensor_dst_dir, DIR_SEPARATOR_STR,
                   file_basename);
  if (GNUNET_YES == GNUNET_DISK_directory_test (filename, GNUNET_NO))
  {
    GNUNET_assert (GNUNET_OK == copy_dir (filename, dst_path));
  }
  else
  {
    sensor_name = GNUNET_strdup (file_basename);
    GNUNET_array_append (sensor_names, sensor_names_size, sensor_name);
    sensor_cfg = GNUNET_CONFIGURATION_create ();
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONFIGURATION_parse (sensor_cfg, filename));
    GNUNET_CONFIGURATION_set_value_string (sensor_cfg, file_basename,
                                           "COLLECTION_POINT",
                                           GNUNET_i2s_full (&all_peers_info
                                                            [0].peer_id));
    if (sensors_interval > 0)
    {
      GNUNET_CONFIGURATION_set_value_number (sensor_cfg, file_basename,
                                             "INTERVAL",
                                             (unsigned long long int)
                                             sensors_interval);
    }
    GNUNET_CONFIGURATION_write (sensor_cfg, dst_path);
    GNUNET_CONFIGURATION_destroy (sensor_cfg);
  }
  GNUNET_free (dst_path);
  return GNUNET_OK;
}


/**
 * Load sensor definitions and rewrite them to tmp location.
 * Add collection point peer id and change running interval if needed.
 */
static void
rewrite_sensors ()
{
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_DISK_directory_test (sensor_src_dir, GNUNET_YES));
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_create (sensor_dst_dir));
  GNUNET_DISK_directory_scan (sensor_src_dir, &sensor_dir_scanner, NULL);
}


/**
 * Callback to be called when dashboard service is started
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
dashboard_started (void *cls, struct GNUNET_TESTBED_Operation *op,
                   const char *emsg)
{
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "ERROR: %s.\n", emsg);
    GNUNET_assert (0);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Dashboard service started.\n");
  GNUNET_TESTBED_operation_done (op);
  dashboard_service_started = GNUNET_YES;
}


/**
 * Function called by PEERSTORE for each matching record.
 *
 * @param cls closure
 * @param record peerstore record information
 * @param emsg error message, or NULL if no errors
 * @return #GNUNET_YES to continue iterating, #GNUNET_NO to stop
 */
static int
peerstore_watch_cb (void *cls,
                    const struct GNUNET_PEERSTORE_Record *record,
                    const char *emsg)
{
  struct PeerInfo *peer = cls;
  struct GNUNET_SENSOR_DashboardAnomalyEntry *anomaly;

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "ERROR: %s.\n", emsg);
    GNUNET_assert (0);
  }
  GNUNET_assert (record->value_size ==
                 sizeof (struct GNUNET_SENSOR_DashboardAnomalyEntry));
  anomaly = record->value;
  GNUNET_assert (0 ==
                 GNUNET_CRYPTO_cmp_peer_identity (&peer->peer_id,
                                                  record->peer));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Anomaly report:{'peerid': '%s'," "'peer': %d," "'sensor': '%s',"
              "'anomalous': %d," "'neighbors': %f}\n",
              GNUNET_i2s (&peer->peer_id), peer->index, record->key,
              anomaly->anomalous, anomaly->anomalous_neighbors);
  return GNUNET_YES;
}


/**
 * Callback to be called when peerstore service connect operation is completed
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param ca_result the service handle returned from GNUNET_TESTBED_ConnectAdapter()
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
peerstore_connect_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
                      void *ca_result, const char *emsg)
{
  int i;
  int j;
  struct PeerInfo *peer;

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "ERROR: %s.\n", emsg);
    GNUNET_assert (0);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected to peerstore service.\n");
  /* Watch for anomaly reports from other peers */
  for (i = 0; i < num_peers; i++)
  {
    peer = &all_peers_info[i];
    for (j = 0; j < sensor_names_size; j++)
    {
      GNUNET_PEERSTORE_watch (peerstore, "sensordashboard-anomalies",
                              &peer->peer_id, sensor_names[j],
                              &peerstore_watch_cb, peer);
    }
  }
}


/**
 * Adapter function called to establish a connection to peerstore service.
 *
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
peerstore_connect_adapter (void *cls,
                           const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  peerstore = GNUNET_PEERSTORE_connect (cfg);
  GNUNET_assert (NULL != peerstore);
  return peerstore;
}


/**
 * Adapter function called to destroy a connection to peerstore service.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
peerstore_disconnect_adapter (void *cls, void *op_result)
{
  GNUNET_PEERSTORE_disconnect (peerstore, GNUNET_NO);
  peerstore = NULL;
  peerstore_op = NULL;
}


/**
 * Callback to be called when statistics service connect operation is completed
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param ca_result the service handle returned from GNUNET_TESTBED_ConnectAdapter()
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
statistics_connect_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
                      void *ca_result, const char *emsg)
{
  struct PeerInfo *peer = cls;

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "ERROR: %s.\n", emsg);
    GNUNET_assert (0);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Connected to statistics service on peer `%s'.\n", GNUNET_i2s (&peer->peer_id));
  GNUNET_STATISTICS_set (peer->statistics, "# peers connected", 0, GNUNET_NO);
}


/**
 * Adapter function called to establish a connection to statistics service.
 *
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
statistics_connect_adapter (void *cls,
                           const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct PeerInfo *peer = cls;

  peer->statistics = GNUNET_STATISTICS_create ("core", cfg);
  GNUNET_assert (NULL != peer->statistics);
  return peer->statistics;
}


/**
 * Adapter function called to destroy a connection to statistics service.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
statistics_disconnect_adapter (void *cls, void *op_result)
{
  struct PeerInfo *peer = cls;

  GNUNET_STATISTICS_destroy (peer->statistics, GNUNET_NO);
  peer->statistics = NULL;
}


/**
 * This function is called after the estimated training period is over.
 */
static void
simulate_anomalies (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int i;
  uint32_t an_peer;
  struct GNUNET_TIME_Relative shutdown_delay;

  delayed_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Training period over, simulating anomalies now.\n");
  GNUNET_assert (anomalous_peers <= num_peers);
  for (i = 0; i < anomalous_peers; i++)
  {
    an_peer = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
    if (NULL != all_peers_info[an_peer].statistics_op)
    {
      i--;
      continue;
    }
    all_peers_info[an_peer].statistics_op =
    GNUNET_TESTBED_service_connect (NULL, all_peers_info[an_peer].testbed_peer,
                                    "statistics", &statistics_connect_cb,
                                    &all_peers_info[an_peer], &statistics_connect_adapter,
                                    &statistics_disconnect_adapter, &all_peers_info[an_peer]);
  }
  shutdown_delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, num_peers * 6);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutting down in %s\n",
      GNUNET_STRINGS_relative_time_to_string (shutdown_delay, GNUNET_NO));
  GNUNET_SCHEDULER_cancel (shutdown_task);
  shutdown_task = GNUNET_SCHEDULER_add_delayed (shutdown_delay, &do_shutdown, NULL);
}


/**
 * This function is called after a delay which ensures that all peers are
 * properly initialized
 */
static void
peers_ready (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned long long int training_points;
  struct GNUNET_TIME_Relative training_period;

  delayed_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All peers are ready.\n");
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_number (cfg,
                                                        "sensor-model-gaussian",
                                                        "TRAINING_WINDOW",
                                                        &training_points));
  training_period =
      GNUNET_TIME_relative_multiply (GNUNET_TIME_relative_multiply
                                     (GNUNET_TIME_UNIT_SECONDS,
                                      (sensors_interval ==
                                       0) ? 60 : sensors_interval),
                                     training_points);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sleeping for a training period of %s.\n",
              GNUNET_STRINGS_relative_time_to_string (training_period,
                                                      GNUNET_NO));
  delayed_task =
      GNUNET_SCHEDULER_add_delayed (training_period, &simulate_anomalies, NULL);
}


/**
 * Callback to be called when sensor service is started
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
sensor_service_started (void *cls, struct GNUNET_TESTBED_Operation *op,
                        const char *emsg)
{
  struct PeerInfo *peer = cls;

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "ERROR: %s.\n", emsg);
    GNUNET_assert (0);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sensor service started on peer `%s'.\n",
              GNUNET_i2s (&peer->peer_id));
  GNUNET_TESTBED_operation_done (op);
  sensor_services_started++;
  if (sensor_services_started == num_peers)
  {
    delayed_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (PEER_STARTUP_TIME, num_peers),
                                      &peers_ready, NULL);
  }
}


/**
 * Callback to be called when the requested peer information is available
 *
 * @param cb_cls the closure from GNUNET_TETSBED_peer_get_information()
 * @param op the operation this callback corresponds to
 * @param pinfo the result; will be NULL if the operation has failed
 * @param emsg error message if the operation has failed; will be NULL if the
 *          operation is successfull
 */
static void
peer_info_cb (void *cb_cls, struct GNUNET_TESTBED_Operation *op,
              const struct GNUNET_TESTBED_PeerInformation *pinfo,
              const char *emsg)
{
  struct GNUNET_TESTBED_Peer *testbed_peer = cb_cls;
  struct PeerInfo *peer = &all_peers_info[peers_known];

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "ERROR: %s.\n", emsg);
    GNUNET_assert (0);
  }
  peer->testbed_peer = testbed_peer;
  GNUNET_CRYPTO_get_peer_identity (pinfo->result.cfg, &peer->peer_id);
  peer->index = peers_known;
  peers_known++;
  if (1 == peers_known)         /* First peer is collection point */
  {
    /* Rewrite sensors */
    rewrite_sensors ();
    /* Start dashboard */
    GNUNET_TESTBED_peer_manage_service (NULL, testbed_peer, "sensordashboard",
                                        &dashboard_started, NULL, 1);
  }
  /* Start sensor service on every peer */
  GNUNET_TESTBED_peer_manage_service (NULL, testbed_peer, "sensor",
                                      &sensor_service_started, peer, 1);
  if (num_peers == peers_known) /* Last peer */
  {
    /* Connect to peerstore on first peer (collection point) */
    peerstore_op =
        GNUNET_TESTBED_service_connect (NULL, all_peers_info[0].testbed_peer,
                                        "peerstore", &peerstore_connect_cb,
                                        NULL, &peerstore_connect_adapter,
                                        &peerstore_disconnect_adapter, NULL);
  }
  GNUNET_TESTBED_operation_done (op);
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param h the run handle
 * @param num number of peers in 'peers'
 * @param peers handle to peers run in the testbed.  NULL upon timeout (see
 *          GNUNET_TESTBED_test_run()).
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 * @see GNUNET_TESTBED_test_run()
 */
static void
test_master (void *cls, struct GNUNET_TESTBED_RunHandle *h, unsigned int num,
             struct GNUNET_TESTBED_Peer **peers, unsigned int links_succeeded,
             unsigned int links_failed)
{
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%d peers started. %d links succeeded. %d links failed.\n",
              num_peers, links_succeeded, links_failed);
  GNUNET_assert (num == num_peers);
  /* Collect peer information */
  all_peers_info = GNUNET_new_array (num_peers, struct PeerInfo);

  for (i = 0; i < num_peers; i++)
  {
    GNUNET_TESTBED_peer_get_information (peers[i],
                                         GNUNET_TESTBED_PIT_CONFIGURATION,
                                         &peer_info_cb, peers[i]);
  }
}


/**
 * Verify that the user passed correct CL args
 *
 * @return #GNUNET_OK if arguments are valid, #GNUNET_SYSERR otherwise
 */
static int
verify_args ()
{
  if (num_peers < 2)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Invalid or missing number of peers. Set at least 2 peers.\n"));
    return GNUNET_SYSERR;
  }
  if (NULL == topology_file ||
      GNUNET_YES != GNUNET_DISK_file_test (topology_file))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Missing or invalid topology file.\n"));
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Actual main function.
 *
 * @param cls unused
 * @param args remaining args, unused
 * @param cfgfile name of the configuration
 * @param cfg configuration handle
 */
static void
run (void *cls, char *const *args, const char *cf,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  if (GNUNET_OK != verify_args ())
  {
    do_shutdown (NULL, NULL);
    return;
  }
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (cfg, cfg_filename));
  GNUNET_CONFIGURATION_set_value_string ((struct GNUNET_CONFIGURATION_Handle *)
                                         cfg, "TESTBED",
                                         "OVERLAY_TOPOLOGY_FILE",
                                         topology_file);
  shutdown_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &do_shutdown,
                                    NULL);
  GNUNET_TESTBED_run (NULL, cfg, num_peers, 0, NULL, NULL, &test_master, NULL);
}


/**
 * Main function.
 *
 * @return 0 on success
 */
int
main (int argc, char *const *argv)
{
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'p', "peers", "COUNT", gettext_noop ("Number of peers to run"), GNUNET_YES,
     &GNUNET_GETOPT_set_uint, &num_peers},
    {'t', "topology-file", "FILEPATH", gettext_noop ("Path to topology file"),
     GNUNET_YES, &GNUNET_GETOPT_set_filename, &topology_file},
    {'i', "sensors-interval", "INTERVAL",
     gettext_noop ("Change the interval of running sensors to given value"),
     GNUNET_YES, &GNUNET_GETOPT_set_uint, &sensors_interval},
    {'a', "anomalous-peers", "COUNT",
     gettext_noop ("Number of peers to simulate anomalies on"), GNUNET_YES,
     &GNUNET_GETOPT_set_uint, &anomalous_peers},
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-sensor-profiler",
                              gettext_noop ("Profiler for sensor service"),
                              options, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-sensor-profiler.c */
