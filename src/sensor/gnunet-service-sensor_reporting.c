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
 * @file sensor/gnunet-service-sensor_reporting.c
 * @brief sensor service reporting functionality
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "sensor.h"
#include "gnunet_peerstore_service.h"
#include "gnunet_core_service.h"
#include "gnunet_cadet_service.h"
#include "gnunet_applications.h"

#define LOG(kind,...) GNUNET_log_from (kind, "sensor-reporting",__VA_ARGS__)


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

struct ValueInfo
{

  /**
   * DLL
   */
  struct ValueInfo *prev;

  /**
   * DLL
   */
  struct ValueInfo *next;

  /**
   * Sensor information
   */
  struct GNUNET_SENSOR_SensorInfo *sensor;

  /**
   * Last value read from sensor
   */
  void *last_value;

  /**
   * Size of @e last_value
   */
  size_t last_value_size;

  /**
   * Timestamp of last value reading
   */
  struct GNUNET_TIME_Absolute last_value_timestamp;

  /**
   * Has the last value seen already been reported to collection point?
   */
  int last_value_reported;

  /**
   * Watcher of sensor values
   */
  struct GNUNET_PEERSTORE_WatchContext *wc;

  /**
   * Collection point reporting task (or #GNUNET_SCHEDULER_NO_TASK)
   */
  GNUNET_SCHEDULER_TaskIdentifier reporting_task;

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
  struct GNUNET_PeerIdentity *peer_id;

  /**
   * Message queue for messages to be sent to this peer
   */
  struct GNUNET_MQ_Handle *mq;

};

/**
 * Information about a connected CADET peer (collection point).
 */
struct CadetPeer
{

  /**
   * DLL
   */
  struct CadetPeer *prev;

  /**
   * DLL
   */
  struct CadetPeer *next;

  /**
   * Peer Identity
   */
  struct GNUNET_PeerIdentity peer_id;

  /**
   * CADET channel handle
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * Message queue for messages to be sent to this peer
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Are we currently destroying the channel and its context?
   */
  int destroying;

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
 * Handle to peerstore service
 */
static struct GNUNET_PEERSTORE_Handle *peerstore;

/**
 * Handle to core service
 */
static struct GNUNET_CORE_Handle *core;

/**
 * Handle to CADET service
 */
static struct GNUNET_CADET_Handle *cadet;

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
 * Head of DLL of value info structs
 */
static struct ValueInfo *vi_head;

/**
 * Tail of DLL of value info structs
 */
static struct ValueInfo *vi_tail;

/**
 * Head of DLL of CORE peers
 */
static struct CorePeer *corep_head;

/**
 * Tail of DLL of CORE peers
 */
static struct CorePeer *corep_tail;

/**
 * Head of DLL of CADET peers
 */
static struct CadetPeer *cadetp_head;

/**
 * Tail of DLL of CADET peers
 */
static struct CadetPeer *cadetp_tail;

/**
 * Is the module started?
 */
static int module_running = GNUNET_NO;

/**
 * Number of known neighborhood peers
 */
static int neighborhood;



/******************************************************************************/
/******************************      CLEANUP     ******************************/
/******************************************************************************/

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
 * Destroy value info struct
 *
 * @param vi struct to destroy
 */
static void
destroy_value_info (struct ValueInfo *vi)
{
  if (NULL != vi->wc)
  {
    GNUNET_PEERSTORE_watch_cancel (vi->wc);
    vi->wc = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != vi->reporting_task)
  {
    GNUNET_SCHEDULER_cancel (vi->reporting_task);
    vi->reporting_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != vi->last_value)
  {
    GNUNET_free (vi->last_value);
    vi->last_value = NULL;
  }
  GNUNET_free (vi);
}


/**
 * Destroy core peer struct
 *
 * @param corep struct to destroy
 */
static void
destroy_core_peer (struct CorePeer *corep)
{
  struct AnomalyInfo *ai;

  if (NULL != corep->mq)
  {
    GNUNET_MQ_destroy (corep->mq);
    corep->mq = NULL;
  }
  ai = ai_head;
  while (NULL != ai)
  {
    GNUNET_assert (NULL != ai->anomalous_neighbors);
    GNUNET_CONTAINER_multipeermap_remove_all (ai->anomalous_neighbors,
                                              corep->peer_id);
    ai = ai->next;
  }
  GNUNET_free (corep);
}


/**
 * Destroy cadet peer struct
 *
 * @param cadetp struct to destroy
 */
static void
destroy_cadet_peer (struct CadetPeer *cadetp)
{
  cadetp->destroying = GNUNET_YES;
  if (NULL != cadetp->mq)
  {
    GNUNET_MQ_destroy (cadetp->mq);
    cadetp->mq = NULL;
  }
  if (NULL != cadetp->channel)
  {
    GNUNET_CADET_channel_destroy (cadetp->channel);
    cadetp->channel = NULL;
  }
  GNUNET_free (cadetp);
}


/**
 * Stop sensor reporting module
 */
void
SENSOR_reporting_stop ()
{
  struct ValueInfo *vi;
  struct CorePeer *corep;
  struct AnomalyInfo *ai;
  struct CadetPeer *cadetp;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Stopping sensor anomaly reporting module.\n");
  module_running = GNUNET_NO;
  neighborhood = 0;
  /* Destroy value info's */
  vi = vi_head;
  while (NULL != vi)
  {
    GNUNET_CONTAINER_DLL_remove (vi_head, vi_tail, vi);
    destroy_value_info (vi);
    vi = vi_head;
  }
  /* Destroy core peers */
  corep = corep_head;
  while (NULL != corep)
  {
    GNUNET_CONTAINER_DLL_remove (corep_head, corep_tail, corep);
    destroy_core_peer (corep);
    corep = corep_head;
  }
  /* Destroy anomaly info's */
  ai = ai_head;
  while (NULL != ai)
  {
    GNUNET_CONTAINER_DLL_remove (ai_head, ai_tail, ai);
    destroy_anomaly_info (ai);
    ai = ai_head;
  }
  /* Destroy cadet peers */
  cadetp = cadetp_head;
  while (NULL != cadetp)
  {
    GNUNET_CONTAINER_DLL_remove (cadetp_head, cadetp_tail, cadetp);
    destroy_cadet_peer (cadetp);
    cadetp = cadetp_head;
  }
  /* Disconnect from other services */
  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
  if (NULL != peerstore)
  {
    GNUNET_PEERSTORE_disconnect (peerstore, GNUNET_NO);
    peerstore = NULL;
  }
  if (NULL != cadet)
  {
    GNUNET_CADET_disconnect (cadet);
    cadet = NULL;
  }
}


/******************************************************************************/
/******************************      HELPERS     ******************************/
/******************************************************************************/


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
 * Returns context of a connected CADET peer.
 * Creates it first if didn't exist before.
 *
 * @param pid Peer Identity
 * @return Context of connected CADET peer
 */
static struct CadetPeer *
get_cadet_peer (struct GNUNET_PeerIdentity pid)
{
  struct CadetPeer *cadetp;

  cadetp = cadetp_head;
  while (NULL != cadetp)
  {
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&pid, &cadetp->peer_id))
      return cadetp;
    cadetp = cadetp->next;
  }
  /* Not found, create struct and channel */
  cadetp = GNUNET_new (struct CadetPeer);
  cadetp->peer_id = pid;
  cadetp->channel =
      GNUNET_CADET_channel_create (cadet, cadetp, &pid,
                                   GNUNET_APPLICATION_TYPE_SENSORDASHBOARD,
                                   GNUNET_CADET_OPTION_DEFAULT);
  cadetp->mq = GNUNET_CADET_mq_create (cadetp->channel);
  GNUNET_CONTAINER_DLL_insert (cadetp_head, cadetp_tail, cadetp);
  return cadetp;
}


/**
 * Create an anomaly report message from a given anomaly info struct inside a
 * MQ envelope.
 *
 * @param ai Anomaly info struct to use
 * @return Envelope with message
 */
static struct GNUNET_MQ_Envelope *
create_anomaly_report_message (struct AnomalyInfo *ai)
{
  struct GNUNET_SENSOR_AnomalyReportMessage *arm;
  struct GNUNET_MQ_Envelope *ev;

  ev = GNUNET_MQ_msg (arm, GNUNET_MESSAGE_TYPE_SENSOR_ANOMALY_REPORT);
  GNUNET_CRYPTO_hash (ai->sensor->name, strlen (ai->sensor->name) + 1,
                      &arm->sensorname_hash);
  arm->sensorversion_major = htons (ai->sensor->version_major);
  arm->sensorversion_minor = htons (ai->sensor->version_minor);
  arm->anomalous = htons (ai->anomalous);
  arm->anomalous_neighbors =
      ((float) GNUNET_CONTAINER_multipeermap_size (ai->anomalous_neighbors)) /
      neighborhood;
  return ev;
}


/**
 * Create a sensor value message from a given value info struct inside a MQ
 * envelope.
 *
 * @param vi Value info struct to use
 * @return Envelope with message
 */
static struct GNUNET_MQ_Envelope *
create_value_message (struct ValueInfo *vi)
{
  struct GNUNET_SENSOR_ValueMessage *vm;
  struct GNUNET_MQ_Envelope *ev;

  ev = GNUNET_MQ_msg_extra (vm, vi->last_value_size,
                            GNUNET_MESSAGE_TYPE_SENSOR_READING);
  GNUNET_CRYPTO_hash (vi->sensor->name, strlen (vi->sensor->name) + 1,
                      &vm->sensorname_hash);
  vm->sensorversion_major = htons (vi->sensor->version_major);
  vm->sensorversion_minor = htons (vi->sensor->version_minor);
  vm->timestamp = vi->last_value_timestamp;
  vm->value_size = htons (vi->last_value_size);
  memcpy (&vm[1], vi->last_value, vi->last_value_size);
  return ev;
}


/**
 * Send given anomaly info report by putting it in the given message queue.
 *
 * @param mq Message queue to put the message in
 * @param ai Anomaly info to report
 */
static void
send_anomaly_report (struct GNUNET_MQ_Handle *mq, struct AnomalyInfo *ai)
{
  struct GNUNET_MQ_Envelope *ev;

  ev = create_anomaly_report_message (ai);
  GNUNET_MQ_send (mq, ev);
}


/******************************************************************************/
/***************************      CORE Handlers     ***************************/
/******************************************************************************/


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
  struct GNUNET_SENSOR_AnomalyReportMessage *arm;
  struct GNUNET_SENSOR_SensorInfo *sensor;
  struct AnomalyInfo *ai;
  struct CadetPeer *cadetp;
  int peer_in_list;

  arm = (struct GNUNET_SENSOR_AnomalyReportMessage *) message;
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
  /* Send anomaly update to collection point */
  if (NULL != ai->sensor->collection_point &&
      GNUNET_YES == ai->sensor->report_anomalies)
  {
    cadetp = get_cadet_peer (*ai->sensor->collection_point);
    send_anomaly_report (cadetp->mq, ai);
  }
  return GNUNET_OK;
}


/******************************************************************************/
/************************      PEERSTORE callbacks     ************************/
/******************************************************************************/


/**
 * Sensor value watch callback
 *
 * @param cls Closure, ValueInfo struct related to the sensor we are watching
 * @param record PEERSTORE new record, NULL if error
 * @param emsg Error message, NULL if no error
 * @return GNUNET_YES to continue watching
 */
static int
value_watch_cb (void *cls, struct GNUNET_PEERSTORE_Record *record, char *emsg)
{
  struct ValueInfo *vi = cls;

  if (NULL != emsg)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("PEERSTORE error: %s.\n"), emsg);
    return GNUNET_YES;
  }
  if (NULL != vi->last_value)
  {
    GNUNET_free (vi->last_value);
    vi->last_value_size = 0;
  }
  vi->last_value = GNUNET_memdup (record->value, record->value_size);
  vi->last_value_size = record->value_size;
  vi->last_value_timestamp = GNUNET_TIME_absolute_get ();
  vi->last_value_reported = GNUNET_NO;
  return GNUNET_YES;
}


/******************************************************************************/
/**************************      CORE callbacks     ***************************/
/******************************************************************************/


/**
 * Method called whenever a CORE peer disconnects.
 *
 * @param cls closure (unused)
 * @param peer peer identity this notification is about
 */
static void
core_disconnect_cb (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct CorePeer *corep;

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&mypeerid, peer))
    return;
  neighborhood--;
  corep = corep_head;
  while (NULL != corep)
  {
    if (peer == corep->peer_id)
    {
      GNUNET_CONTAINER_DLL_remove (corep_head, corep_tail, corep);
      destroy_core_peer (corep);
      return;
    }
    corep = corep->next;
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
  struct CorePeer *corep;
  struct AnomalyInfo *ai;

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&mypeerid, peer))
    return;
  neighborhood++;
  corep = GNUNET_new (struct CorePeer);
  corep->peer_id = (struct GNUNET_PeerIdentity *) peer;
  corep->mq = GNUNET_CORE_mq_create (core, peer);
  GNUNET_CONTAINER_DLL_insert (corep_head, corep_tail, corep);
  /* Send any locally anomalous sensors to the new peer */
  ai = ai_head;
  while (NULL != ai)
  {
    if (GNUNET_YES == ai->anomalous)
      send_anomaly_report (corep->mq, ai);
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
    SENSOR_reporting_stop ();
    return;
  }
  if (0 != GNUNET_CRYPTO_cmp_peer_identity (&mypeerid, my_identity))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Peer identity received from CORE init doesn't match ours.\n"));
    SENSOR_reporting_stop ();
    return;
  }
}


/******************************************************************************/
/*************************      CADET callbacks     ***************************/
/******************************************************************************/

/**
 * Function called whenever a channel is destroyed.  Should clean up
 * any associated state.
 *
 * It must NOT call #GNUNET_CADET_channel_destroy on the channel.
 *
 * @param cls closure (set from #GNUNET_CADET_connect)
 * @param channel connection to the other end (henceforth invalid)
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 */
static void
cadet_channel_destroyed (void *cls, const struct GNUNET_CADET_Channel *channel,
                         void *channel_ctx)
{
  struct CadetPeer *cadetp = channel_ctx;

  if (GNUNET_YES == cadetp->destroying)
    return;
  GNUNET_CONTAINER_DLL_remove (cadetp_head, cadetp_tail, cadetp);
  cadetp->channel = NULL;
  destroy_cadet_peer (cadetp);
}


/******************************************************************************/
/**********************      Local anomaly receiver     ***********************/
/******************************************************************************/


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
  struct CorePeer *corep;
  struct CadetPeer *cadetp;

  if (GNUNET_NO == module_running)
    return;
  ai = get_anomaly_info_by_sensor (sensor);
  GNUNET_assert (NULL != ai);
  ai->anomalous = anomalous;
  /* Report change to all neighbors */
  corep = corep_head;
  while (NULL != corep)
  {
    send_anomaly_report (corep->mq, ai);
    corep = corep->next;
  }
  if (NULL != ai->sensor->collection_point &&
      GNUNET_YES == ai->sensor->report_anomalies)
  {
    cadetp = get_cadet_peer (*ai->sensor->collection_point);
    send_anomaly_report (cadetp->mq, ai);
  }
}


/******************************************************************************/
/*******************      Reporting values (periodic)     *********************/
/******************************************************************************/


/**
 * Task scheduled to send values to collection point
 *
 * @param cls closure, a `struct ValueReportingContext *`
 * @param tc unused
 */
static void
report_value (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ValueInfo *vi = cls;
  struct GNUNET_SENSOR_SensorInfo *sensor = vi->sensor;
  struct CadetPeer *cadetp;
  struct GNUNET_MQ_Envelope *ev;

  vi->reporting_task =
      GNUNET_SCHEDULER_add_delayed (sensor->value_reporting_interval,
                                    &report_value, vi);
  if (0 == vi->last_value_size || GNUNET_YES == vi->last_value_reported)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Did not receive a fresh value from `%s' to report.\n", sensor->name);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Now trying to report last seen value of `%s' to collection point.\n",
       sensor->name);
  cadetp = get_cadet_peer (*sensor->collection_point);
  ev = create_value_message (vi);
  GNUNET_MQ_send (cadetp->mq, ev);
  vi->last_value_reported = GNUNET_YES;
}


/******************************************************************************/
/********************************      INIT     *******************************/
/******************************************************************************/


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
  struct ValueInfo *vi;

  /* Create sensor anomaly info context */
  ai = GNUNET_new (struct AnomalyInfo);

  ai->sensor = sensor;
  ai->anomalous = GNUNET_NO;
  ai->anomalous_neighbors =
      GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
  GNUNET_CONTAINER_DLL_insert (ai_head, ai_tail, ai);
  /* Create sensor value info context (if needed to be reported) */
  if (NULL == sensor->collection_point || GNUNET_NO == sensor->report_values)
    return GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Reporting sensor `%s' values to collection point `%s' every %s.\n",
       sensor->name, GNUNET_i2s_full (sensor->collection_point),
       GNUNET_STRINGS_relative_time_to_string (sensor->value_reporting_interval,
                                               GNUNET_YES));
  vi = GNUNET_new (struct ValueInfo);
  vi->sensor = sensor;
  vi->last_value = NULL;
  vi->last_value_size = 0;
  vi->last_value_reported = GNUNET_NO;
  vi->wc =
      GNUNET_PEERSTORE_watch (peerstore, "sensor", &mypeerid, sensor->name,
                              &value_watch_cb, vi);
  vi->reporting_task =
      GNUNET_SCHEDULER_add_delayed (sensor->value_reporting_interval,
                                    &report_value, vi);
  GNUNET_CONTAINER_DLL_insert (vi_head, vi_tail, vi);
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
SENSOR_reporting_start (const struct GNUNET_CONFIGURATION_Handle *c,
                        struct GNUNET_CONTAINER_MultiHashMap *s)
{
  static struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {&handle_anomaly_report, GNUNET_MESSAGE_TYPE_SENSOR_ANOMALY_REPORT,
     sizeof (struct GNUNET_SENSOR_AnomalyReportMessage)},
    {NULL, 0, 0}
  };
  static struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
    {NULL, 0, 0}
  };

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Starting sensor reporting module.\n");
  GNUNET_assert (NULL != s);
  sensors = s;
  cfg = c;
  /* Connect to PEERSTORE */
  peerstore = GNUNET_PEERSTORE_connect (cfg);
  if (NULL == peerstore)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Failed to connect to peerstore service.\n"));
    SENSOR_reporting_stop ();
    return GNUNET_SYSERR;
  }
  /* Connect to CORE */
  core =
      GNUNET_CORE_connect (cfg, NULL, &core_startup_cb, core_connect_cb,
                           &core_disconnect_cb, NULL, GNUNET_YES, NULL,
                           GNUNET_YES, core_handlers);
  if (NULL == core)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Failed to connect to CORE service.\n"));
    SENSOR_reporting_stop ();
    return GNUNET_SYSERR;
  }
  /* Connect to CADET */
  cadet =
      GNUNET_CADET_connect (cfg, NULL, NULL, &cadet_channel_destroyed,
                            cadet_handlers, NULL);
  if (NULL == cadet)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Failed to connect to CADET service.\n"));
    SENSOR_reporting_stop ();
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_get_peer_identity (cfg, &mypeerid);
  GNUNET_CONTAINER_multihashmap_iterate (sensors, &init_sensor_reporting, NULL);
  neighborhood = 0;
  module_running = GNUNET_YES;
  return GNUNET_OK;
}

/* end of gnunet-service-sensor_reporting.c */
