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
 * @file sensor/sensor_api.c
 * @brief API for sensor service
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "sensor.h"

#define LOG(kind,...) GNUNET_log_from (kind, "sensor-api",__VA_ARGS__)

/**
 * Handle to the sensor service.
 */
struct GNUNET_SENSOR_Handle
{

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Connection to the service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Head of iterator DLL.
   */
  struct GNUNET_SENSOR_IterateContext *ic_head;

  /**
   * Tail of iterator DLL.
   */
  struct GNUNET_SENSOR_IterateContext *ic_tail;

  /**
   * Message queue used to send data to service
   */
  struct GNUNET_MQ_Handle *mq;

};

/**
 * Context for an iteration request.
 */
struct GNUNET_SENSOR_IterateContext
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_SENSOR_IterateContext *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_SENSOR_IterateContext *prev;

  /**
   * Handle to the SENSOR service.
   */
  struct GNUNET_SENSOR_Handle *h;

  /**
   * Function to call with the results.
   */
  GNUNET_SENSOR_SensorIterateCB callback;

  /**
   * Closure for 'callback'.
   */
  void *callback_cls;

  /**
   * Envelope containing iterate request.
   */
  struct GNUNET_MQ_Envelope *ev;

  /**
   * Is the request already sent? If yes, cannot be canceled.
   */
  int request_sent;

  /**
   * Are we expecting records from service?
   */
  int receiving;

  /**
   * Task responsible for timeout.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

};


/**
 * Notifier of an error encountered by MQ.
 *
 * @param cls Closure, service handle
 * @param error MQ error type
 */
static void
mq_error_handler (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_SENSOR_Handle *h = cls;

  LOG (GNUNET_ERROR_TYPE_ERROR,
       _("Received an error notification from MQ of type: %d\n"), error);
  GNUNET_SENSOR_disconnect (h); //TODO: try to reconnect
}


/**
 * Handler to a message of type: #GNUNET_MESSAGE_TYPE_SENSOR_END
 *
 * @param cls Closure, service handle
 * @param msg Message received
 */
static void
handle_end (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SENSOR_Handle *h = cls;
  struct GNUNET_SENSOR_IterateContext *ic;
  GNUNET_SENSOR_SensorIterateCB cb;
  void *cb_cls;

  if (NULL == h->ic_head)
  {
    GNUNET_break_op (0);
    //TODO: reconnect
    return;
  }
  ic = h->ic_head;
  cb = ic->callback;
  cb_cls = ic->callback_cls;
  ic->receiving = GNUNET_NO;
  GNUNET_SENSOR_iterate_cancel (ic);
  if (NULL != cb)
    cb (cb_cls, NULL, NULL);
}


/**
 * Handler to a message of type: #GNUNET_MESSAGE_TYPE_SENSOR_INFO
 *
 * @param cls Closure, service handle
 * @param msg Message received
 */
static void
handle_sensor_info (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SENSOR_Handle *h = cls;
  struct GNUNET_SENSOR_IterateContext *ic;
  uint16_t msg_size;
  struct SensorInfoMessage *sensor_msg;
  uint16_t sensor_name_len;
  uint16_t sensor_desc_len;
  struct SensorInfoShort *sensor;
  void *dummy;

  if (NULL == h->ic_head)
  {
    GNUNET_break_op (0);
    //TODO: reconnect
    return;
  }
  ic = h->ic_head;
  if (NULL == ic->callback)     /* no need to parse message */
    return;
  msg_size = ntohs (msg->size);
  if (msg_size < sizeof (struct SensorInfoMessage))
  {
    GNUNET_break_op (0);
    //TODO: reconnect
    return;
  }
  sensor_msg = (struct SensorInfoMessage *) msg;
  sensor_name_len = ntohs (sensor_msg->name_len);
  sensor_desc_len = ntohs (sensor_msg->description_len);
  if (msg_size !=
      sizeof (struct SensorInfoMessage) + sensor_name_len + sensor_desc_len)
  {
    GNUNET_break_op (0);
    //TODO: reconnect
    return;
  }
  sensor = GNUNET_new (struct SensorInfoShort);
  sensor->version_major = ntohs (sensor_msg->version_major);
  sensor->version_minor = ntohs (sensor_msg->version_minor);
  dummy = &sensor_msg[1];
  sensor->name = GNUNET_strndup (dummy, sensor_name_len);
  dummy += sensor_name_len;
  sensor->description = GNUNET_strndup (dummy, sensor_desc_len);
  ic->callback (ic->callback_cls, sensor, NULL);
  GNUNET_free (sensor->name);
  GNUNET_free (sensor->description);
  GNUNET_free (sensor);
}


/**
 * Disconnect from the sensor service
 *
 * @param h handle to disconnect
 */
void
GNUNET_SENSOR_disconnect (struct GNUNET_SENSOR_Handle *h)
{
  struct GNUNET_SENSOR_IterateContext *ic;

  ic = h->ic_head;
  while (NULL != ic)
  {
    if (NULL != ic->callback)
      ic->callback (ic->callback_cls, NULL,
                    _("Iterate request canceled due to disconnection.\n"));
    GNUNET_SENSOR_iterate_cancel (ic);
    ic = h->ic_head;
  }
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  GNUNET_free (h);
}


/**
 * Connect to the sensor service.
 *
 * @return NULL on error
 */
struct GNUNET_SENSOR_Handle *
GNUNET_SENSOR_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_SENSOR_Handle *h;

  static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    {&handle_sensor_info, GNUNET_MESSAGE_TYPE_SENSOR_INFO, 0},
    {&handle_end, GNUNET_MESSAGE_TYPE_SENSOR_END, 0},
    GNUNET_MQ_HANDLERS_END
  };

  client = GNUNET_CLIENT_connect ("sensor", cfg);
  if (NULL == client)
    return NULL;
  h = GNUNET_new (struct GNUNET_SENSOR_Handle);
  h->client = client;
  h->cfg = cfg;
  h->mq =
      GNUNET_MQ_queue_for_connection_client (h->client, mq_handlers,
                                             &mq_error_handler, h);
  return h;
}


/**
 * Iteration request has timed out.
 *
 * @param cls the 'struct GNUNET_SENSOR_SensorIteratorContext*'
 * @param tc scheduler context
 */
static void
signal_sensor_iteration_timeout (void *cls,
                                 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SENSOR_IterateContext *ic = cls;
  GNUNET_SENSOR_SensorIterateCB cb;
  void *cb_cls;

  ic->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  cb = ic->callback;
  cb_cls = ic->callback_cls;
  GNUNET_SENSOR_iterate_cancel (ic);
  if (NULL != cb)
    cb (cb_cls, NULL,
        _("Timeout transmitting iteration request to `SENSOR' service."));
}


/**
 * Callback from MQ when the request has already been sent to the service.
 * Now it can not be canelled.
 *
 * @param cls closure
 */
static void
iterate_request_sent (void *cls)
{
  struct GNUNET_SENSOR_IterateContext *ic = cls;

  ic->request_sent = GNUNET_YES;
  ic->ev = NULL;
  ic->receiving = GNUNET_YES;
}


/**
 * Cancel an iteration request.
 * This should be called before the iterate callback is called with a NULL value.
 *
 * @param ic context of the iterator to cancel
 */
void
GNUNET_SENSOR_iterate_cancel (struct GNUNET_SENSOR_IterateContext *ic)
{
  struct GNUNET_SENSOR_Handle *h;

  h = ic->h;
  if (GNUNET_NO == ic->request_sent)
  {
    GNUNET_MQ_send_cancel (ic->ev);
    ic->ev = NULL;
    ic->request_sent = GNUNET_YES;
  }
  if (GNUNET_YES == ic->receiving)
  {
    /* don't remove since we are still expecting records */
    ic->callback = NULL;
    ic->callback_cls = NULL;
    return;
  }
  if (GNUNET_SCHEDULER_NO_TASK != ic->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (ic->timeout_task);
    ic->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_CONTAINER_DLL_remove (h->ic_head, h->ic_tail, ic);
  GNUNET_free (ic);
}


/**
 * Get one or all sensors loaded by the sensor service.
 * The callback will be called with each sensor received and once with a NULL
 * value to signal end of iteration.
 *
 * @param h Handle to SENSOR service
 * @param timeout how long to wait until timing out
 * @param sensorname Name of the required sensor, NULL to get all
 * @param callback the function to call for each sensor
 * @param callback_cls closure for callback
 * @return iterator context
 */
struct GNUNET_SENSOR_IterateContext *
GNUNET_SENSOR_iterate (struct GNUNET_SENSOR_Handle *h,
                       struct GNUNET_TIME_Relative timeout,
                       const char *sensor_name,
                       GNUNET_SENSOR_SensorIterateCB callback,
                       void *callback_cls)
{
  struct GNUNET_SENSOR_IterateContext *ic;
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_Envelope *ev;
  size_t sensor_name_len;

  if (NULL == sensor_name)
  {
    ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SENSOR_GETALL);
  }
  else
  {
    sensor_name_len = strlen (sensor_name) + 1;
    ev = GNUNET_MQ_msg_extra (msg, sensor_name_len,
                              GNUNET_MESSAGE_TYPE_SENSOR_GET);
    memcpy (&msg[1], sensor_name, sensor_name_len);
  }
  GNUNET_MQ_send (h->mq, ev);
  ic = GNUNET_new (struct GNUNET_SENSOR_IterateContext);

  ic->h = h;
  ic->ev = ev;
  ic->request_sent = GNUNET_NO;
  ic->receiving = GNUNET_NO;
  ic->callback = callback;
  ic->callback_cls = callback_cls;
  ic->timeout_task =
      GNUNET_SCHEDULER_add_delayed (timeout, &signal_sensor_iteration_timeout,
                                    ic);
  GNUNET_MQ_notify_sent (ev, &iterate_request_sent, ic);
  GNUNET_CONTAINER_DLL_insert_tail (h->ic_head, h->ic_tail, ic);
  return ic;
}


/**
 * Force an anomaly status change on a given sensor. If the sensor reporting
 * module is running, this will trigger the usual reporting logic, therefore,
 * please only use this in a test environment.
 *
 * Also, if the sensor analysis module is running, it might conflict and cause
 * undefined behaviour if it detects a real anomaly.
 *
 * @param h Service handle
 * @param sensor_name Sensor name to set the anomaly status
 * @param anomalous The desired status: #GNUNET_YES / #GNUNET_NO
 */
void
GNUNET_SENSOR_force_anomaly (struct GNUNET_SENSOR_Handle *h,
    char *sensor_name, int anomalous)
{
  struct ForceAnomalyMessage *msg;
  struct GNUNET_MQ_Envelope *ev;

  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SENSOR_ANOMALY_REPORT);
  GNUNET_MQ_send (h->mq, ev);
}


/* end of sensor_api.c */
