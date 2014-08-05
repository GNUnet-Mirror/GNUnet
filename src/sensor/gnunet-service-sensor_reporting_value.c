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
 * @file sensor/gnunet-service-sensor_reporting_value.c
 * @brief sensor service value reporting functionality
 * @author Omar Tarabai
 */
#include <inttypes.h>
#include "platform.h"
#include "gnunet_util_lib.h"
#include "sensor.h"
#include "gnunet_peerstore_service.h"
#include "gnunet_cadet_service.h"
#include "gnunet_applications.h"

#define LOG(kind,...) GNUNET_log_from (kind, "sensor-reporting-value",__VA_ARGS__)

/**
 * Retry interval (seconds) in case channel to collection point is busy
 */
#define COLLECTION_RETRY 1

/**
 * Context of reporting sensor values
 */
struct ValueReportingContext
{

  /**
   * DLL
   */
  struct ValueReportingContext *prev;

  /**
   * DLL
   */
  struct ValueReportingContext *next;

  /**
   * Sensor information
   */
  struct GNUNET_SENSOR_SensorInfo *sensor;

  /**
   * Collection point reporting task
   * (or #GNUNET_SCHEDULER_NO_TASK)
   */
  GNUNET_SCHEDULER_TaskIdentifier cp_task;

  /**
   * Watcher of sensor values
   */
  struct GNUNET_PEERSTORE_WatchContext *wc;

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
  uint64_t timestamp;

};

/**
 * Context of a created CADET channel
 */
struct CadetChannelContext
{

  /**
   * DLL
   */
  struct CadetChannelContext *prev;

  /**
   * DLL
   */
  struct CadetChannelContext *next;

  /**
   * Peer Id of
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * CADET channel handle
   */
  struct GNUNET_CADET_Channel *c;

  /**
   * Are we sending data on this channel?
   * #GNUNET_YES / #GNUNET_NO
   */
  int sending;

  /**
   * Pointer to a pending message to be sent over the channel
   */
  void *pending_msg;

  /**
   * Size of @e pending_msg
   */
  size_t pending_msg_size;

  /**
   * Handle to CADET tranmission request in case we are sending
   * (sending == #GNUNET_YES)
   */
  struct GNUNET_CADET_TransmitHandle *th;

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
 * Handle to peerstore service
 */
static struct GNUNET_PEERSTORE_Handle *peerstore;

/**
 * My peer id
 */
static struct GNUNET_PeerIdentity mypeerid;

/**
 * Handle to CADET service
 */
static struct GNUNET_CADET_Handle *cadet;

/**
 * Head of DLL of all reporting contexts
 */
struct ValueReportingContext *vrc_head;

/**
 * Tail of DLL of all reporting contexts
 */
struct ValueReportingContext *vrc_tail;

/**
 * Head of DLL of all cadet channels
 */
struct CadetChannelContext *cc_head;

/**
 * Tail of DLL of all cadet channels
 */
struct CadetChannelContext *cc_tail;

/**
 * Destroy a reporting context structure
 */
static void
destroy_value_reporting_context (struct ValueReportingContext *vrc)
{
  if (NULL != vrc->wc)
  {
    GNUNET_PEERSTORE_watch_cancel (vrc->wc);
    vrc->wc = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != vrc->cp_task)
  {
    GNUNET_SCHEDULER_cancel (vrc->cp_task);
    vrc->cp_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != vrc->last_value)
  {
    GNUNET_free (vrc->last_value);
    vrc->last_value_size = 0;
  }
  GNUNET_free (vrc);
}


/**
 * Destroy a CADET channel context struct
 */
static void
destroy_cadet_channel_context (struct CadetChannelContext *cc)
{
  cc->destroying = GNUNET_YES;
  if (NULL != cc->th)
  {
    GNUNET_CADET_notify_transmit_ready_cancel (cc->th);
    cc->th = NULL;
  }
  if (NULL != cc->pending_msg)
  {
    GNUNET_free (cc->pending_msg);
    cc->pending_msg = NULL;
  }
  if (NULL != cc->c)
  {
    GNUNET_CADET_channel_destroy (cc->c);
    cc->c = NULL;
  }
  GNUNET_free (cc);
}


/**
 * Stop sensor value reporting module
 */
void
SENSOR_reporting_value_stop ()
{
  struct ValueReportingContext *vrc;
  struct CadetChannelContext *cc;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Stopping sensor value reporting module.\n");
  while (NULL != cc_head)
  {
    cc = cc_head;
    GNUNET_CONTAINER_DLL_remove (cc_head, cc_tail, cc);
    destroy_cadet_channel_context (cc);
  }
  while (NULL != vrc_head)
  {
    vrc = vrc_head;
    GNUNET_CONTAINER_DLL_remove (vrc_head, vrc_tail, vrc);
    destroy_value_reporting_context (vrc);
  }
  if (NULL != peerstore)
  {
    GNUNET_PEERSTORE_disconnect (peerstore, GNUNET_YES);
    peerstore = NULL;
  }
  if (NULL != cadet)
  {
    GNUNET_CADET_disconnect (cadet);
    cadet = NULL;
  }
}


/**
 * Returns CADET channel established to given peer or creates a new one.
 *
 * @param pid Peer Identity
 * @return Context of established cadet channel
 */
static struct CadetChannelContext *
get_cadet_channel (struct GNUNET_PeerIdentity pid)
{
  struct CadetChannelContext *cc;

  cc = cc_head;
  while (NULL != cc)
  {
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&pid, &cc->pid))
      return cc;
    cc = cc->next;
  }
  cc = GNUNET_new (struct CadetChannelContext);
  cc->c =
      GNUNET_CADET_channel_create (cadet, cc, &pid,
                                   GNUNET_APPLICATION_TYPE_SENSORDASHBOARD,
                                   GNUNET_CADET_OPTION_DEFAULT);
  cc->pid = pid;
  cc->sending = GNUNET_NO;
  cc->destroying = GNUNET_NO;
  GNUNET_CONTAINER_DLL_insert (cc_head, cc_tail, cc);
  return cc;
}


/**
 * Construct a reading message ready to be sent over CADET channel
 *
 * @param rc reporting context to read data from
 * @param msg used to return the created message structure
 * @return size of created message
 */
static size_t
construct_reading_message (struct ValueReportingContext *vrc,
                           struct GNUNET_SENSOR_ReadingMessage **msg)
{
  struct GNUNET_SENSOR_ReadingMessage *ret;
  uint16_t sensorname_size;
  uint16_t total_size;
  void *dummy;

  sensorname_size = strlen (vrc->sensor->name) + 1;
  total_size =
      sizeof (struct GNUNET_SENSOR_ReadingMessage) + sensorname_size +
      vrc->last_value_size;
  ret = GNUNET_malloc (total_size);
  ret->header.size = htons (total_size);
  ret->header.type = htons (GNUNET_MESSAGE_TYPE_SENSOR_READING);
  ret->sensorname_size = htons (sensorname_size);
  ret->sensorversion_major = htons (vrc->sensor->version_major);
  ret->sensorversion_minor = htons (vrc->sensor->version_minor);
  ret->timestamp = GNUNET_htobe64 (vrc->timestamp);
  ret->value_size = htons (vrc->last_value_size);
  dummy = &ret[1];
  memcpy (dummy, vrc->sensor->name, sensorname_size);
  dummy += sensorname_size;
  memcpy (dummy, vrc->last_value, vrc->last_value_size);
  *msg = ret;
  return total_size;
}


/**
 * Function called to notify a client about the connection begin ready
 * to queue more data.  @a buf will be NULL and @a size zero if the
 * connection was closed for writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in @a buf
 * @param buf where the callee should write the message
 * @return number of bytes written to @a buf
 */
static size_t
do_report_value (void *cls, size_t size, void *buf)
{
  struct CadetChannelContext *cc = cls;
  size_t written = 0;

  cc->th = NULL;
  cc->sending = GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Copying to CADET transmit buffer.\n");
  if (NULL == buf)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "CADET failed to transmit message (NULL buf), discarding.\n");
  }
  else if (size < cc->pending_msg_size)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "CADET failed to transmit message (small size, expected: %u, got: %u)"
         ", discarding.\n", cc->pending_msg_size, size);
  }
  else
  {
    memcpy (buf, cc->pending_msg, cc->pending_msg_size);
    written = cc->pending_msg_size;
  }
  GNUNET_free (cc->pending_msg);
  cc->pending_msg = NULL;
  cc->pending_msg_size = 0;
  return written;
}


/**
 * Task scheduled to send values to collection point
 *
 * @param cls closure, a `struct ValueReportingContext *`
 * @param tc unused
 */
static void
report_value (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ValueReportingContext *vrc = cls;
  struct GNUNET_SENSOR_SensorInfo *sensor = vrc->sensor;
  struct CadetChannelContext *cc;
  struct GNUNET_SENSOR_ReadingMessage *msg;
  size_t msg_size;

  vrc->cp_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 == vrc->last_value_size)        /* Did not receive a sensor value yet */
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Did not receive a value from `%s' to report yet.\n",
         vrc->sensor->name);
    vrc->cp_task =
        GNUNET_SCHEDULER_add_delayed (sensor->value_reporting_interval,
                                      &report_value, vrc);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Now trying to report last seen value of `%s' " "to collection point.\n",
       vrc->sensor->name);
  GNUNET_assert (NULL != sensor->collection_point);
  cc = get_cadet_channel (*sensor->collection_point);
  if (GNUNET_YES == cc->sending)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Cadet channel to collection point busy, "
         "trying again for sensor `%s' after %d seconds.\n", vrc->sensor->name,
         COLLECTION_RETRY);
    vrc->cp_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_SECONDS,
                                       COLLECTION_RETRY), &report_value, vrc);
    return;
  }
  msg_size = construct_reading_message (vrc, &msg);
  cc->sending = GNUNET_YES;
  cc->pending_msg = msg;
  cc->pending_msg_size = msg_size;
  cc->th =
      GNUNET_CADET_notify_transmit_ready (cc->c, GNUNET_YES,
                                          sensor->value_reporting_interval,
                                          msg_size, &do_report_value, cc);
  vrc->cp_task =
      GNUNET_SCHEDULER_add_delayed (sensor->value_reporting_interval,
                                    &report_value, vrc);
}


/**
 * Sensor value watch callback
 */
static int
value_watch_cb (void *cls, struct GNUNET_PEERSTORE_Record *record, char *emsg)
{
  struct ValueReportingContext *vrc = cls;

  if (NULL != emsg)
    return GNUNET_YES;
  if (NULL != vrc->last_value)
  {
    GNUNET_free (vrc->last_value);
    vrc->last_value_size = 0;
  }
  vrc->last_value = GNUNET_malloc (record->value_size);
  memcpy (vrc->last_value, record->value, record->value_size);
  vrc->last_value_size = record->value_size;
  vrc->timestamp = GNUNET_TIME_absolute_get ().abs_value_us;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received a sensor `%s' watch value at " "timestamp %" PRIu64
       ", updating notification last_value.\n", vrc->sensor->name,
       vrc->timestamp);
  return GNUNET_YES;
}


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
  struct CadetChannelContext *cc = channel_ctx;

  if (GNUNET_YES == cc->destroying)
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received a `channel destroyed' notification from CADET, "
       "cleaning up.\n");
  GNUNET_CONTAINER_DLL_remove (cc_head, cc_tail, cc);
  cc->c = NULL;
  destroy_cadet_channel_context (cc);
}


/**
 * Iterator for defined sensors
 * Watches sensors for readings to report
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
  struct ValueReportingContext *vrc;

  if (NULL == sensor->collection_point || GNUNET_NO == sensor->report_values)
    return GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Reporting sensor `%s' values to collection point `%s' every %s.\n",
       sensor->name, GNUNET_i2s_full (sensor->collection_point),
       GNUNET_STRINGS_relative_time_to_string (sensor->value_reporting_interval,
                                               GNUNET_YES));
  vrc = GNUNET_new (struct ValueReportingContext);
  vrc->sensor = sensor;
  vrc->last_value = NULL;
  vrc->last_value_size = 0;
  vrc->wc =
      GNUNET_PEERSTORE_watch (peerstore, "sensor", &mypeerid, sensor->name,
                              &value_watch_cb, vrc);
  vrc->cp_task =
      GNUNET_SCHEDULER_add_delayed (sensor->value_reporting_interval,
                                    &report_value, vrc);
  GNUNET_CONTAINER_DLL_insert (vrc_head, vrc_tail, vrc);
  return GNUNET_YES;
}


/**
 * Start the sensor value reporting module
 *
 * @param c our service configuration
 * @param sensors multihashmap of loaded sensors
 * @return #GNUNET_OK if started successfully, #GNUNET_SYSERR otherwise
 */
int
SENSOR_reporting_value_start (const struct GNUNET_CONFIGURATION_Handle *c,
                              struct GNUNET_CONTAINER_MultiHashMap *sensors)
{
  static struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
    {NULL, 0, 0}
  };

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Starting sensor value reporting module.\n");
  GNUNET_assert (NULL != sensors);
  cfg = c;
  peerstore = GNUNET_PEERSTORE_connect (cfg);
  if (NULL == peerstore)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Failed to connect to peerstore service.\n"));
    SENSOR_reporting_value_stop ();
    return GNUNET_SYSERR;
  }
  cadet =
      GNUNET_CADET_connect (cfg, NULL, NULL, &cadet_channel_destroyed,
                            cadet_handlers, NULL);
  if (NULL == cadet)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Failed to connect to CADET service.\n"));
    SENSOR_reporting_value_stop ();
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_get_peer_identity (cfg, &mypeerid);
  GNUNET_CONTAINER_multihashmap_iterate (sensors, &init_sensor_reporting, NULL);
  return GNUNET_OK;
}

/* end of gnunet-service-sensor_reporting_value.c */
