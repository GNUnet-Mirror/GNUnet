/*
     This file is part of GNUnet.
     (C)

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
 * TODO:
 * - Run X peers
 * - Rewrite interval time (optional)
 * - Run 1 dashboard
 * - Monitor dashboard records
 * - Prompt for anomalies when ready:
 *  -- Cut Y peers (remove their connections to other X-Y peers but not the connections among themselves)
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
 * Return value of the program
 */
static int ok = 1;

/**
 * Number of peers to run (Option -p)
 */
static unsigned int num_peers = 0;

/**
 * Set sensors running interval to this value (Option -i)
 */
static unsigned int sensors_interval = 0;

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
do_shutdown ()                  // TODO: schedule timeout shutdown
{
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutting down.\n");
  if (NULL != sensor_names)
  {
    for (i = 0; i < sensor_names_size; i++)
      GNUNET_free (sensor_names[i]);
    GNUNET_array_grow (sensor_names, sensor_names_size, 0);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Copying `%s' to `%s'.\n", filename,
              dst);
  if (GNUNET_YES == GNUNET_DISK_directory_test (filename, GNUNET_YES))
    copy_result = copy_dir (filename, dst);
  else
  {
    if (GNUNET_YES == GNUNET_DISK_file_test (dst))
      GNUNET_DISK_directory_remove (dst);
    copy_result = GNUNET_DISK_file_copy (filename, dst);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Copying directory `%s' to `%s'.\n", src,
              dst);
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
    sensor_name = GNUNET_strdup(file_basename);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Saving sensor name `%s'.\n", sensor_name);
    GNUNET_array_append(sensor_names, sensor_names_size, sensor_name);
    sensor_cfg = GNUNET_CONFIGURATION_create ();
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONFIGURATION_parse (sensor_cfg, filename));
    GNUNET_CONFIGURATION_set_value_string (sensor_cfg, file_basename,
                                           "COLLECTION_POINT",
                                           GNUNET_i2s_full (&all_peers_info[0].
                                                            peer_id));
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
  //TODO:
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
peerstore_watch_cb (void *cls, struct GNUNET_PEERSTORE_Record *record,
                      char *emsg)
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
  printf ("Anomaly report:\n"
           "  Peer: `%s'\n"
           "  Sensor: `%s'\n"
           "  Anomalous: `%d'\n"
           "  Anomalous neighbors: %f.\n\n",
           GNUNET_i2s (&peer->peer_id),
           record->key, anomaly->anomalous, anomaly->anomalous_neighbors);
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
      GNUNET_PEERSTORE_watch (peerstore, "sensordashboard-anomalies", &peer->peer_id,
          sensor_names[j], &peerstore_watch_cb, peer);
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
  sensor_services_started ++;
  //TODO
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
  GNUNET_assert (0 == links_failed);
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
  if (num_peers < 3)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Invalid or missing number of peers. Set at least 3 peers.\n"));
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
  struct GNUNET_CONFIGURATION_Handle *cfg;
  double links;

  if (GNUNET_OK != verify_args ())
  {
    do_shutdown ();
    return;
  }
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (cfg, cfg_filename));
  links = log (num_peers) * log (num_peers) * num_peers / 2;
  GNUNET_CONFIGURATION_set_value_number ((struct GNUNET_CONFIGURATION_Handle *)
                                         cfg, "TESTBED", "OVERLAY_RANDOM_LINKS",
                                         (unsigned long long int) links);
  GNUNET_TESTBED_run (NULL, cfg, num_peers, 0, NULL, NULL, &test_master, NULL);
  GNUNET_CONFIGURATION_destroy (cfg);
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
    {'i', "sensors-interval", "INTERVAL",
     gettext_noop ("Change the interval or running sensors to given value"),
     GNUNET_YES, &GNUNET_GETOPT_set_uint, &sensors_interval},
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-sensor-profiler",
                              gettext_noop ("Profiler for sensor service"),
                              options, &run, NULL)) ? ok : 1;
}

/* end of gnunet-sensor-profiler.c */
