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
 * @file sensor/gnunet-service-sensor_reporting_anomaly.c
 * @brief sensor service anomaly reporting functionality
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "sensor.h"
#include "gnunet_peerstore_service.h"
#include "gnunet_core_service.h"

#define LOG(kind,...) GNUNET_log_from (kind, "sensor-reporting-anomaly",__VA_ARGS__)

struct AnomalyInfo
{

  /**
   * DLL
   */
  struct AnomalyInfo *prev;

  /**
   * DLL
   */
  struct AnomalyInfo *next;

  /**
   * Sensor information
   */
  struct GNUNET_SENSOR_SensorInfo *sensor;

  /**
   * Current anomalous status of sensor
   */
  int anomalous;

  /**
   * List of peers that reported an anomaly for this sensor
   */
  struct GNUNET_CONTAINER_MultiPeerMap *anomalous_neighbors;

};

/**
 * Information about a connected CORE peer.
 * Note that we only know about a connected peer if it is running the same
 * application (sensor anomaly reporting) as us.
 */
struct CorePeer
{

  /**
   * DLL
   */
  struct CorePeer *prev;

  /**
   * DLL
   */
  struct CorePeer *next;

  /**
   * Peer identity of connected peer
   */
  struct GNUNET_PeerIdentity *peerid;

  /**
   * Message queue for messages to be sent to this peer
   */
  struct GNUNET_MQ_Handle *mq;

};


/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Multihashmap of loaded sensors
 */
static struct GNUNET_CONTAINER_MultiHashMap *sensors;

/**
 * Handle to core service
 */
static struct GNUNET_CORE_Handle *core;

/**
 * My peer id
 */
static struct GNUNET_PeerIdentity mypeerid;

/**
 * Head of DLL of anomaly info structs
 */
static struct AnomalyInfo *ai_head;

/**
 * Tail of DLL of anomaly info structs
 */
static struct AnomalyInfo *ai_tail;

/**
 * Head of DLL of CORE peers
 */
static struct CorePeer *cp_head;

/**
 * Tail of DLL of CORE peers
 */
static struct CorePeer *cp_tail;

/**
 * Is the module started?
 */
static int module_running = GNUNET_NO;

/**
 * Number of known neighborhood peers
 */
static int neighborhood;


/**
 * Destroy anomaly info struct
 *
 * @param ai struct to destroy
 */
static void
destroy_anomaly_info (struct AnomalyInfo *ai)
{
  if (NULL != ai->anomalous_neighbors)
    GNUNET_CONTAINER_multipeermap_destroy (ai->anomalous_neighbors);
  GNUNET_free (ai);
}


/**
 * Destroy core peer struct
 *
 * @param cp struct to destroy
 */
static void
destroy_core_peer (struct CorePeer *cp)
{
  struct AnomalyInfo *ai;

  if (NULL != cp->mq)
  {
    GNUNET_MQ_destroy (cp->mq);
    cp->mq = NULL;
  }
  ai = ai_head;
  while (NULL != ai)
  {
    GNUNET_assert (NULL != ai->anomalous_neighbors);
    GNUNET_CONTAINER_multipeermap_remove_all (ai->anomalous_neighbors,
                                              cp->peerid);
    ai = ai->next;
  }
  GNUNET_free (cp);
}


/**
 * Stop sensor anomaly reporting module
 */
void
SENSOR_reporting_anomaly_stop ()
{
  struct AnomalyInfo *ai;
  struct CorePeer *cp;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Stopping sensor anomaly reporting module.\n");
  module_running = GNUNET_NO;
  ai = ai_head;
  while (NULL != ai)
  {
    GNUNET_CONTAINER_DLL_remove (ai_head, ai_tail, ai);
    destroy_anomaly_info (ai);
    ai = ai_head;
  }
  cp = cp_head;
  while (NULL != cp)
  {
    GNUNET_CONTAINER_DLL_remove (cp_head, cp_tail, cp);
    destroy_core_peer (cp);
    cp = cp_head;
  }
  neighborhood = 0;
  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
}


/**
 * Gets the anomaly info struct related to the given sensor
 *
 * @param sensor Sensor to search by
 */
static struct AnomalyInfo *
get_anomaly_info_by_sensor (struct GNUNET_SENSOR_SensorInfo *sensor)
{
  struct AnomalyInfo *ai;

  ai = ai_head;
  while (NULL != ai)
  {
    if (ai->sensor == sensor)
    {
      return ai;
    }
    ai = ai->next;
  }
  return NULL;
}


/**
 * Create an anomaly report message from a given anomaly info structb inside an
 * MQ envelope.
 *
 * @param ai Anomaly info struct to use
 * @return
 */
static struct GNUNET_MQ_Envelope *
create_anomaly_report_message (struct AnomalyInfo *ai)
{
  struct AnomalyReportMessage *arm;
  struct GNUNET_MQ_Envelope *ev;

  ev = GNUNET_MQ_msg (arm, GNUNET_MESSAGE_TYPE_SENSOR_ANOMALY_REPORT);
  GNUNET_CRYPTO_hash (ai->sensor->name, strlen (ai->sensor->name) + 1,
                      &arm->sensorname_hash);
  arm->sensorversion_major = ai->sensor->version_major;
  arm->sensorversion_minor = ai->sensor->version_minor;
  arm->anomalous = ai->anomalous;
  arm->anomalous_neighbors =
      ((float) GNUNET_CONTAINER_multipeermap_size (ai->anomalous_neighbors)) /
      neighborhood;
  return ev;
}


/**
 * Send given anomaly info report to given core peer.
 *
 * @param cp Core peer to send the report to
 * @param ai Anomaly info to report
 */
static void
send_anomaly_report (struct CorePeer *cp, struct AnomalyInfo *ai)
{
  struct GNUNET_MQ_Envelope *ev;

  GNUNET_assert (NULL != cp->mq);
  ev = create_anomaly_report_message (ai);
  GNUNET_MQ_send (cp->mq, ev);
}


/**
 * An inbound anomaly report is received from a peer through CORE.
 *
 * @param cls closure (unused)
 * @param peer the other peer involved
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close connection to the peer (signal serious error)
 */
static int
handle_anomaly_report (void *cls, const struct GNUNET_PeerIdentity *other,
                       const struct GNUNET_MessageHeader *message)
{
  struct AnomalyReportMessage *arm;
  struct GNUNET_SENSOR_SensorInfo *sensor;
  struct AnomalyInfo *ai;
  int peer_in_list;

  arm = (struct AnomalyReportMessage *) message;
  sensor = GNUNET_CONTAINER_multihashmap_get (sensors, &arm->sensorname_hash);
  if (NULL == sensor || sensor->version_major != arm->sensorversion_major ||
      sensor->version_minor != arm->sensorversion_minor)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "I don't have the sensor reported by the peer `%s'.\n",
         GNUNET_i2s (other));
    return GNUNET_OK;
  }
  ai = get_anomaly_info_by_sensor (sensor);
  GNUNET_assert (NULL != ai);
  peer_in_list =
      GNUNET_CONTAINER_multipeermap_contains (ai->anomalous_neighbors, other);
  if (GNUNET_YES == ai->anomalous)
  {
    if (GNUNET_YES == peer_in_list)
      GNUNET_break_op (0);
    else
      GNUNET_CONTAINER_multipeermap_put (ai->anomalous_neighbors, other, NULL,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  else
  {
    if (GNUNET_NO == peer_in_list)
      GNUNET_break_op (0);
    else
      GNUNET_CONTAINER_multipeermap_remove_all (ai->anomalous_neighbors, other);
  }
  //TODO: report to collection point if anomalous neigbors jump up or down
  // by a configurable percentage or is now 0% or 100%
  return GNUNET_OK;
}


/**
 * Method called whenever a CORE peer disconnects.
 *
 * @param cls closure (unused)
 * @param peer peer identity this notification is about
 */
static void
core_disconnect_cb (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct CorePeer *cp;

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&mypeerid, peer))
    return;
  neighborhood--;
  cp = cp_head;
  while (NULL != cp)
  {
    if (peer == cp->peerid)
    {
      GNUNET_CONTAINER_DLL_remove (cp_head, cp_tail, cp);
      destroy_core_peer (cp);
      return;
    }
    cp = cp->next;
  }
  LOG (GNUNET_ERROR_TYPE_ERROR,
       _("Received disconnect notification from CORE"
         " for a peer we didn't know about.\n"));
}


/**
 * Method called whenever a given peer connects through CORE.
 *
 * @param cls closure (unused)
 * @param peer peer identity this notification is about
 */
static void
core_connect_cb (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct CorePeer *cp;
  struct AnomalyInfo *ai;

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&mypeerid, peer))
    return;
  neighborhood++;
  cp = GNUNET_new (struct CorePeer);
  cp->peerid = (struct GNUNET_PeerIdentity *) peer;
  cp->mq = GNUNET_CORE_mq_create (core, peer);
  GNUNET_CONTAINER_DLL_insert (cp_head, cp_tail, cp);
  /* Send any locally anomalous sensors to the new peer */
  ai = ai_head;
  while (NULL != ai)
  {
    if (GNUNET_YES == ai->anomalous)
      send_anomaly_report (cp, ai);
    ai = ai->next;
  }
}


/**
 * Function called after #GNUNET_CORE_connect has succeeded (or failed
 * for good).  Note that the private key of the peer is intentionally
 * not exposed here; if you need it, your process should try to read
 * the private key file directly (which should work if you are
 * authorized...).  Implementations of this function must not call
 * #GNUNET_CORE_disconnect (other than by scheduling a new task to
 * do this later).
 *
 * @param cls closure (unused)
 * @param my_identity ID of this peer, NULL if we failed
 */
static void
core_startup_cb (void *cls, const struct GNUNET_PeerIdentity *my_identity)
{
  if (NULL == my_identity)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Failed to connect to CORE service.\n"));
    SENSOR_reporting_anomaly_stop ();
    return;
  }
  if (0 != GNUNET_CRYPTO_cmp_peer_identity (&mypeerid, my_identity))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Peer identity received from CORE init doesn't match ours.\n"));
    SENSOR_reporting_anomaly_stop ();
    return;
  }
}


/**
 * Used by the analysis module to tell the reporting module about a change in
 * the anomaly status of a sensor.
 *
 * @param sensor Related sensor
 * @param anomalous The new sensor anomalous status
 */
void
SENSOR_reporting_anomaly_update (struct GNUNET_SENSOR_SensorInfo *sensor,
                                 int anomalous)
{
  struct AnomalyInfo *ai;
  struct CorePeer *cp;

  if (GNUNET_NO == module_running)
    return;
  ai = get_anomaly_info_by_sensor (sensor);
  GNUNET_assert (NULL != ai);
  ai->anomalous = anomalous;
  /* Report change to all neighbors */
  cp = cp_head;
  while (NULL != cp)
  {
    send_anomaly_report (cp, ai);
    cp = cp->next;
  }
  //TODO: report change to collection point if report_anomalies
}


/**
 * Iterator for defined sensors and creates anomaly info context
 *
 * @param cls unused
 * @param key unused
 * @param value a `struct GNUNET_SENSOR_SensorInfo *` with sensor information
 * @return #GNUNET_YES to continue iterations
 */
static int
init_sensor_reporting (void *cls, const struct GNUNET_HashCode *key,
                       void *value)
{
  struct GNUNET_SENSOR_SensorInfo *sensor = value;
  struct AnomalyInfo *ai;

  ai = GNUNET_new (struct AnomalyInfo);

  ai->sensor = sensor;
  ai->anomalous = GNUNET_NO;
  ai->anomalous_neighbors =
      GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
  GNUNET_CONTAINER_DLL_insert (ai_head, ai_tail, ai);
  return GNUNET_YES;
}


/**
 * Start the sensor anomaly reporting module
 *
 * @param c our service configuration
 * @param s multihashmap of loaded sensors
 * @return #GNUNET_OK if started successfully, #GNUNET_SYSERR otherwise
 */
int
SENSOR_reporting_anomaly_start (const struct GNUNET_CONFIGURATION_Handle *c,
                                struct GNUNET_CONTAINER_MultiHashMap *s)
{
  static struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {&handle_anomaly_report, GNUNET_MESSAGE_TYPE_SENSOR_ANOMALY_REPORT,
     sizeof (struct AnomalyReportMessage)},
    {NULL, 0, 0}
  };

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Starting sensor anomaly reporting module.\n");
  GNUNET_assert (NULL != s);
  sensors = s;
  cfg = c;
  core =
      GNUNET_CORE_connect (cfg, NULL, &core_startup_cb, core_connect_cb,
                           &core_disconnect_cb, NULL, GNUNET_YES, NULL,
                           GNUNET_YES, core_handlers);
  if (NULL == core)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Failed to connect to CORE service.\n"));
    SENSOR_reporting_anomaly_stop ();
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_get_peer_identity (cfg, &mypeerid);
  GNUNET_CONTAINER_multihashmap_iterate (sensors, &init_sensor_reporting, NULL);
  neighborhood = 0;
  module_running = GNUNET_YES;
  return GNUNET_OK;
}

/* end of gnunet-service-sensor_reporting_anomaly.c */
