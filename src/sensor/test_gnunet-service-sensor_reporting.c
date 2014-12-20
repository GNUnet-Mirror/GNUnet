  /*
   * This file is part of GNUnet.
   * (C)
   *
   * GNUnet is free software; you can redistribute it and/or modify
   * it under the terms of the GNU General Public License as published
   * by the Free Software Foundation; either version 3, or (at your
   * option) any later version.
   *
   * GNUnet is distributed in the hope that it will be useful, but
   * WITHOUT ANY WARRANTY; without even the implied warranty of
   * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   * General Public License for more details.
   *
   * You should have received a copy of the GNU General Public License
   * along with GNUnet; see the file COPYING.  If not, write to the
   * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   * Boston, MA 02111-1307, USA.
   */
/**
 * @file sensor/test_gnunet-service-sensor_reporting.c
 * @brief testcase for gnunet-service-sensor_reporting.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_sensor_util_lib.h"
#include "sensor.h"
#include "gnunet_peerstore_service.h"
#include "gnunet_sensor_service.h"

/**
 * Number of peers to start for the test
 */
#define NUM_PEERS 2

/**
 * Test timeout
 */
#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 1)

/**
 * How long to wait between starting everything and forcing anomalies to give
 * the peer enough time to stabilize.
 */
#define ANOMALY_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)

/**
 * Information about a test peer
 */
struct TestPeer
{

  /**
   * DLL
   */
  struct TestPeer *prev;

  /**
   * DLL
   */
  struct TestPeer *next;

  /**
   * TESTBED information about the peer
   */
  struct GNUNET_TESTBED_Peer *testbed_peer;

  /**
   * Peer indentity
   */
  struct GNUNET_PeerIdentity peer_id;

  /**
   * Peerstore watch context for this peer's anomaly reports
   */
  struct GNUNET_PEERSTORE_WatchContext *wc;

  /**
   * TESTBED operation connecting us to sensor service
   */
  struct GNUNET_TESTBED_Operation *sensor_op;

  /**
   * Sensor service handle
   */
  struct GNUNET_SENSOR_Handle *sensor;

  /**
   * GNUNET scheduler task that forces the anomaly after a stabilization delay
   */
  GNUNET_SCHEDULER_TaskIdentifier delay_task;

};

/**
 * Test name
 */
static const char *testname = "test_gnunet-service-sensor_reporting";

/**
 * Name of GNUNET config file used in this test
 */
static const char *cfg_filename = "test_gnunet-service-sensor_reporting.conf";

/**
 * Test sensor name
 */
static const char *sensor_name = "test-sensor-statistics";

/**
 * Path to read test sensor from
 */
static const char *sensor_path_src = "test_sensors/test-sensor-statistics";

/**
 * Path to write new test sensor to
 */
static const char *sensor_path_dest =
    "/tmp/test-gnunet-service-sensor-reporting/test-sensor-statistics";

/**
 * Head of DLL of peers
 */
static struct TestPeer *peer_head;

/**
 * Tail of DLL of peers
 */
static struct TestPeer *peer_tail;

/**
 * Number of peers started and got information for
 */
static int started_peers = 0;

/**
 * Number of peers reported anomalies with full list of anomalous neighbors
 */
static int reported_peers = 0;

/**
 * TESTBED operation connecting us to peerstore service
 */
static struct GNUNET_TESTBED_Operation *peerstore_op;

/**
 * Handle to the peerstore service
 */
static struct GNUNET_PEERSTORE_Handle *peerstore;

/**
 * Task used to shutdown / expire the test
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

/**
 * Status of the test to be returned by main()
 */
static int ok = 1;


static void
destroy_peer (struct TestPeer *peer)
{
  if (GNUNET_SCHEDULER_NO_TASK != peer->delay_task)
  {
    GNUNET_SCHEDULER_cancel (peer->delay_task);
    peer->delay_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != peer->sensor_op)
  {
    GNUNET_TESTBED_operation_done (peer->sensor_op);
    peer->sensor_op = NULL;
  }
  if (NULL != peer->wc)
  {
    GNUNET_PEERSTORE_watch_cancel (peer->wc);
    peer->wc = NULL;
  }
  GNUNET_free (peer);
}


/**
 * Shutdown task
 *
 * @param cls Closure (unused)
 * @param tc Task context (unused)
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestPeer *peer;

  peer = peer_head;
  while (NULL != peer)
  {
    GNUNET_CONTAINER_DLL_remove (peer_head, peer_tail, peer);
    destroy_peer (peer);
    peer = peer_head;
  }
  if (NULL != peerstore_op)
  {
    GNUNET_TESTBED_operation_done (peerstore_op);
    peerstore_op = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Write new temp sensor directory with a sensor updated with collection point
 * peer id
 */
static void
write_new_sensor_dir (struct TestPeer *cp_peer)
{
  struct GNUNET_CONFIGURATION_Handle *sensorcfg;

  GNUNET_assert (GNUNET_YES == GNUNET_DISK_file_test (sensor_path_src));
  sensorcfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CONFIGURATION_parse (sensorcfg, sensor_path_src));
  GNUNET_CONFIGURATION_set_value_string (sensorcfg, sensor_name,
                                         "COLLECTION_POINT",
                                         GNUNET_i2s_full (&cp_peer->peer_id));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_DISK_directory_create_for_file (sensor_path_dest));
  GNUNET_CONFIGURATION_write (sensorcfg, sensor_path_dest);
  GNUNET_CONFIGURATION_destroy (sensorcfg);
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
  struct TestPeer *peer = cls;
  struct GNUNET_SENSOR_DashboardAnomalyEntry *anomaly;

  GNUNET_assert (NULL != record);
  GNUNET_assert (record->value_size ==
                 sizeof (struct GNUNET_SENSOR_DashboardAnomalyEntry));
  anomaly = record->value;
  GNUNET_assert (0 ==
                 GNUNET_CRYPTO_cmp_peer_identity (&peer->peer_id,
                                                  record->peer));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peerstore watch got an anomaly report from peer `%s':\n"
              "Anomalous: %d\n" "Anomalous neigbors: %f.\n",
              GNUNET_i2s (&peer->peer_id), anomaly->anomalous,
              anomaly->anomalous_neighbors);
  if (1 == anomaly->anomalous_neighbors)
    reported_peers++;
  if (reported_peers == NUM_PEERS)
  {
    ok = 0;
    GNUNET_SCHEDULER_cancel (shutdown_task);
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
  }
  return GNUNET_YES;
}


/**
 * Task that pushes fake anomalies to running peers
 */
static void
force_anomaly_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestPeer *peer = cls;

  peer->delay_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_SENSOR_force_anomaly (peer->sensor, (char *) sensor_name, GNUNET_YES,
                               NULL, NULL);
}


/**
 * Callback to be called when sensor service connect operation is completed
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param ca_result the service handle returned from GNUNET_TESTBED_ConnectAdapter()
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
sensor_connect_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
                   void *ca_result, const char *emsg)
{
  struct TestPeer *peer = cls;
  struct GNUNET_SENSOR_Handle *sensor = ca_result;

  peer->sensor = sensor;
  peer->delay_task =
      GNUNET_SCHEDULER_add_delayed (ANOMALY_DELAY, &force_anomaly_task, peer);
}


/**
 * Adapter function called to establish a connection to sensor service.
 *
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
sensor_connect_adapter (void *cls,
                        const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_SENSOR_Handle *sensor;

  sensor = GNUNET_SENSOR_connect (cfg);
  return sensor;
}


/**
 * Adapter function called to destroy a connection to sensor service.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
sensor_disconnect_adapter (void *cls, void *op_result)
{
  struct GNUNET_SENSOR_Handle *sensor = op_result;

  GNUNET_SENSOR_disconnect (sensor);
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
  struct TestPeer *peer = cls;

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "ERROR: %s.\n", emsg);
    GNUNET_assert (0);
  }
  peer->sensor_op =
      GNUNET_TESTBED_service_connect (NULL, peer->testbed_peer, "sensor",
                                      &sensor_connect_cb, peer,
                                      &sensor_connect_adapter,
                                      &sensor_disconnect_adapter, NULL);
  GNUNET_TESTBED_operation_done (op);
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
  struct TestPeer *peer;

  peer = peer_head;
  while (NULL != peer)
  {
    GNUNET_PEERSTORE_watch (peerstore, "sensordashboard-anomalies",
                            &peer->peer_id, sensor_name, &peerstore_watch_cb,
                            peer);
    /* Start sensor service */
    GNUNET_TESTBED_peer_manage_service (NULL, peer->testbed_peer, "sensor",
                                        &sensor_service_started, peer, 1);
    peer = peer->next;
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
  GNUNET_TESTBED_operation_done (op);
  /* Connect to peerstore service on first peer */
  peerstore_op =
      GNUNET_TESTBED_service_connect (NULL, peer_head->testbed_peer,
                                      "peerstore", &peerstore_connect_cb, NULL,
                                      &peerstore_connect_adapter,
                                      &peerstore_disconnect_adapter, NULL);
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
  struct TestPeer *peer;

  peer = GNUNET_new (struct TestPeer);

  peer->testbed_peer = testbed_peer;
  peer->delay_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_CRYPTO_get_peer_identity (pinfo->result.cfg, &peer->peer_id);
  if (NULL == peer_head)        /* First peer (collection point) */
  {
    /* Rewrite sensor with collection point peer id */
    write_new_sensor_dir (peer);
  }
  GNUNET_CONTAINER_DLL_insert_tail (peer_head, peer_tail, peer);
  started_peers++;
  if (NUM_PEERS == started_peers)
  {
    /* Start dashboard service on first peer */
    GNUNET_TESTBED_peer_manage_service (NULL, peer_head->testbed_peer,
                                        "sensordashboard", &dashboard_started,
                                        NULL, 1);
  }
  GNUNET_TESTBED_operation_done (op);
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param h the run handle
 * @param num_peers number of peers in 'peers'
 * @param peers handle to peers run in the testbed.  NULL upon timeout (see
 *          GNUNET_TESTBED_test_run()).
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 * @see GNUNET_TESTBED_test_run()
 */
static void
test_master (void *cls, struct GNUNET_TESTBED_RunHandle *h,
             unsigned int num_peers, struct GNUNET_TESTBED_Peer **peers,
             unsigned int links_succeeded, unsigned int links_failed)
{
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%d peers started. %d links succeeded. %d links failed.\n",
              num_peers, links_succeeded, links_failed);
  GNUNET_assert (NUM_PEERS == num_peers);
  GNUNET_assert (0 == links_failed);
  /* Schedule test timeout */
  shutdown_task =
      GNUNET_SCHEDULER_add_delayed (TEST_TIMEOUT, &do_shutdown, NULL);
  /* Collect peer information */
  for (i = 0; i < num_peers; i++)
  {
    GNUNET_TESTBED_peer_get_information (peers[i],
                                         GNUNET_TESTBED_PIT_CONFIGURATION,
                                         &peer_info_cb, peers[i]);
  }
}


int
main (int argc, char *argv[])
{
  GNUNET_log_setup (testname, "INFO", NULL);
  if (GNUNET_OK ==
      GNUNET_TESTBED_test_run (testname, cfg_filename, NUM_PEERS, 0, NULL, NULL,
                               &test_master, NULL))
    return ok;
  return 1;
}
