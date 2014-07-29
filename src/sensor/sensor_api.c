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
 * @brief API for sensor
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "sensor.h"

#define LOG(kind,...) GNUNET_log_from (kind, "sensor-api",__VA_ARGS__)

/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

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
   * Head of transmission queue.
   */
  struct GNUNET_SENSOR_RequestContext *rc_head;

  /**
   * Tail of transmission queue.
   */
  struct GNUNET_SENSOR_RequestContext *rc_tail;

  /**
   * Handle for the current transmission request, or NULL if none is pending.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Head of iterator DLL.
   */
  struct GNUNET_SENSOR_SensorIteratorContext *ic_head;

  /**
   * Tail of iterator DLL.
   */
  struct GNUNET_SENSOR_SensorIteratorContext *ic_tail;

  /**
   * ID for a reconnect task.
   */
  GNUNET_SCHEDULER_TaskIdentifier r_task;

  /**
   * Are we now receiving?
   */
  int in_receive;

};

/**
 * Entry in the transmission queue to SENSOR service.
 *
 */
struct GNUNET_SENSOR_RequestContext
{
  /**
   * This is a linked list.
   */
  struct GNUNET_SENSOR_RequestContext *next;

  /**
   * This is a linked list.
   */
  struct GNUNET_SENSOR_RequestContext *prev;

  /**
   * Handle to the SENSOR service.
   */
  struct GNUNET_SENSOR_Handle *h;

  /**
   * Function to call after request has been transmitted, or NULL.
   */
  GNUNET_SENSOR_Continuation cont;

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * Number of bytes of the request message (follows after this struct).
   */
  size_t size;

};

/**
 * Context for an iteration request.
 */
struct GNUNET_SENSOR_SensorIteratorContext
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_SENSOR_SensorIteratorContext *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_SENSOR_SensorIteratorContext *prev;

  /**
   * Handle to the SENSOR service.
   */
  struct GNUNET_SENSOR_Handle *h;

  /**
   * Function to call with the results.
   */
  GNUNET_SENSOR_SensorIteratorCB callback;

  /**
   * Closure for 'callback'.
   */
  void *callback_cls;

  /**
   * Our entry in the transmission queue.
   */
  struct GNUNET_SENSOR_RequestContext *rc;

  /**
   * Task responsible for timeout.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Timeout for the operation.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Set to GNUNET_YES if we are currently receiving replies from the
   * service.
   */
  int request_transmitted;

};

/******************************************************************************/
/***********************         DECLARATIONS         *************************/
/******************************************************************************/

/**
 * Close the existing connection to SENSOR and reconnect.
 *
 * @param h handle to the service
 */
static void
reconnect (struct GNUNET_SENSOR_Handle *h);


/**
 * Check if we have a request pending in the transmission queue and are
 * able to transmit it right now.  If so, schedule transmission.
 *
 * @param h handle to the service
 */
static void
trigger_transmit (struct GNUNET_SENSOR_Handle *h);

/******************************************************************************/
/*******************         CONNECTION FUNCTIONS         *********************/
/******************************************************************************/

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

  client = GNUNET_CLIENT_connect ("sensor", cfg);
  if (NULL == client)
    return NULL;
  h = GNUNET_new (struct GNUNET_SENSOR_Handle);
  h->client = client;
  h->cfg = cfg;
  return h;
}


/**
 * Disconnect from the sensor service
 *
 * @param h handle to disconnect
 */
void
GNUNET_SENSOR_disconnect (struct GNUNET_SENSOR_Handle *h)
{
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  GNUNET_free (h);
}


/**
 * Task scheduled to re-try connecting to the sensor service.
 *
 * @param cls the 'struct GNUNET_SENSOR_Handle'
 * @param tc scheduler context
 */
static void
reconnect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SENSOR_Handle *h = cls;

  h->r_task = GNUNET_SCHEDULER_NO_TASK;
  reconnect (h);
}


/**
 * Close the existing connection to SENSOR and reconnect.
 *
 * @param h handle to the service
 */
static void
reconnect (struct GNUNET_SENSOR_Handle *h)
{
  if (GNUNET_SCHEDULER_NO_TASK != h->r_task)
  {
    GNUNET_SCHEDULER_cancel (h->r_task);
    h->r_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  h->in_receive = GNUNET_NO;
  h->client = GNUNET_CLIENT_connect ("sensor", h->cfg);
  if (NULL == h->client)
  {
    h->r_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &reconnect_task,
                                      h);
    return;
  }
  trigger_transmit (h);
}

/******************************************************************************/
/******************         SENSOR DATA FUNCTIONS         *********************/
/******************************************************************************/

/**
 * Cancel an iteration over sensor information.
 *
 * @param ic context of the iterator to cancel
 */
void
GNUNET_SENSOR_iterate_sensor_cancel (struct GNUNET_SENSOR_SensorIteratorContext
                                     *ic)
{
  struct GNUNET_SENSOR_Handle *h;

  h = ic->h;
  if (GNUNET_SCHEDULER_NO_TASK != ic->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (ic->timeout_task);
    ic->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  ic->callback = NULL;
  if (GNUNET_YES == ic->request_transmitted)
    return;                     /* need to finish processing */
  GNUNET_CONTAINER_DLL_remove (h->ic_head, h->ic_tail, ic);
  if (NULL != ic->rc)
  {
    GNUNET_CONTAINER_DLL_remove (h->rc_head, h->rc_tail, ic->rc);
    GNUNET_free (ic->rc);
  }
  GNUNET_free (ic);
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
  struct GNUNET_SENSOR_SensorIteratorContext *ic = cls;
  GNUNET_SENSOR_SensorIteratorCB cb;
  void *cb_cls;

  ic->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  cb = ic->callback;
  cb_cls = ic->callback_cls;
  GNUNET_SENSOR_iterate_sensor_cancel (ic);
  if (NULL != cb)
    cb (cb_cls, NULL,
        _("Timeout transmitting iteration request to `SENSOR' service."));
}


/**
 * Type of a function to call when we receive a message from the
 * service.  Call the iterator with the result and (if applicable)
 * continue to receive more messages or trigger processing the next
 * event (if applicable).
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
sensor_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SENSOR_Handle *h = cls;
  struct GNUNET_SENSOR_SensorIteratorContext *ic = h->ic_head;
  GNUNET_SENSOR_SensorIteratorCB cb;
  void *cb_cls;
  uint16_t ms;
  const struct SensorInfoMessage *im;
  struct SensorInfoShort *sensor;
  size_t name_len;
  size_t desc_len;
  char *str_ptr;

  h->in_receive = GNUNET_NO;
  if (NULL == msg)
  {
    /* sensor service died, signal error */
    if (NULL != ic)
    {
      cb = ic->callback;
      cb_cls = ic->callback_cls;
      GNUNET_SENSOR_iterate_sensor_cancel (ic);
    }
    else
    {
      cb = NULL;
    }
    reconnect (h);
    if (NULL != cb)
      cb (cb_cls, NULL, _("Failed to receive response from `SENSOR' service."));
    return;
  }
  if (NULL == ic)
  {
    /* didn't expect a response, reconnect */
    reconnect (h);
    return;
  }
  ic->request_transmitted = GNUNET_NO;
  cb = ic->callback;
  cb_cls = ic->callback_cls;
  if (GNUNET_MESSAGE_TYPE_SENSOR_END == ntohs (msg->type))
  {
    /* normal end of list of sensors, signal end, process next pending request */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received end of list of sensors from `%s' service\n", "SENSOR");
    GNUNET_SENSOR_iterate_sensor_cancel (ic);
    trigger_transmit (h);
    if ((GNUNET_NO == h->in_receive) && (NULL != h->ic_head))
    {
      h->in_receive = GNUNET_YES;
      GNUNET_CLIENT_receive (h->client, &sensor_handler, h,
                             GNUNET_TIME_absolute_get_remaining (h->
                                                                 ic_head->timeout));
    }
    if (NULL != cb)
      cb (cb_cls, NULL, NULL);
    return;
  }
  ms = ntohs (msg->size);
  im = (const struct SensorInfoMessage *) msg;
  name_len = ntohs (im->name_len);
  desc_len = ntohs (im->description_len);
  if ((ms != sizeof (struct SensorInfoMessage) + name_len + desc_len) ||
      (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_SENSOR_INFO))
  {
    /* malformed message */
    GNUNET_break (0);
    GNUNET_SENSOR_iterate_sensor_cancel (ic);
    reconnect (h);
    if (NULL != cb)
      cb (cb_cls, NULL, _("Received invalid message from `SENSOR' service."));
    return;
  }
  sensor = GNUNET_new (struct SensorInfoShort);
  str_ptr = (char *) &im[1];
  sensor->name = GNUNET_strndup (str_ptr, name_len);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received sensor name (%d): %.*s\n", name_len,
       name_len, str_ptr);
  str_ptr += name_len;
  if (desc_len > 0)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Received sensor description (%d): %.*s\n",
         desc_len, desc_len, str_ptr);
    sensor->description = GNUNET_strndup (str_ptr, desc_len);
  }
  sensor->version_major = ntohs (im->version_major);
  sensor->version_minor = ntohs (im->version_minor);
  h->in_receive = GNUNET_YES;
  GNUNET_CLIENT_receive (h->client, &sensor_handler, h,
                         GNUNET_TIME_absolute_get_remaining (ic->timeout));
  if (NULL != cb)
    cb (cb_cls, sensor, NULL);
}


/**
 * We've transmitted the iteration request.  Now get ready to process
 * the results (or handle transmission error).
 *
 * @param cls the 'struct GNUNET_SENSOR_SensorIteratorContext'
 * @param emsg error message, NULL if transmission worked
 */
static void
sensor_iterator_start_receive (void *cls, const char *emsg)
{
  struct GNUNET_SENSOR_SensorIteratorContext *ic = cls;
  struct GNUNET_SENSOR_Handle *h = ic->h;
  GNUNET_SENSOR_SensorIteratorCB cb;
  void *cb_cls;

  ic->rc = NULL;
  if (NULL != emsg)
  {
    cb = ic->callback;
    cb_cls = ic->callback_cls;
    GNUNET_SENSOR_iterate_sensor_cancel (ic);
    reconnect (h);
    if (NULL != cb)
      cb (cb_cls, NULL, emsg);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Waiting for response from `%s' service.\n",
       "SENSOR");
  ic->request_transmitted = GNUNET_YES;
  if (GNUNET_NO == h->in_receive)
  {
    h->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (h->client, &sensor_handler, h,
                           GNUNET_TIME_absolute_get_remaining (ic->timeout));
  }
}


/**
 * Transmit the request at the head of the transmission queue
 * and trigger continuation (if any).
 *
 * @param cls the 'struct GNUNET_SENSOR_Handle' (with the queue)
 * @param size size of the buffer (0 on error)
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
do_transmit (void *cls, size_t size, void *buf)
{
  struct GNUNET_SENSOR_Handle *h = cls;
  struct GNUNET_SENSOR_RequestContext *rc = h->rc_head;
  size_t ret;

  h->th = NULL;
  if (NULL == rc)
    return 0;                   /* request was cancelled in the meantime */
  if (NULL == buf)
  {
    /* sensor service died */
    LOG (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
         "Failed to transmit message to `%s' service.\n", "SENSOR");
    GNUNET_CONTAINER_DLL_remove (h->rc_head, h->rc_tail, rc);
    reconnect (h);
    if (NULL != rc->cont)
      rc->cont (rc->cont_cls, _("failed to transmit request (service down?)"));
    GNUNET_free (rc);
    return 0;
  }
  ret = rc->size;
  if (size < ret)
  {
    /* change in head of queue (i.e. cancel + add), try again */
    trigger_transmit (h);
    return 0;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting request of size %u to `%s' service.\n", ret, "SENSOR");
  memcpy (buf, &rc[1], ret);
  GNUNET_CONTAINER_DLL_remove (h->rc_head, h->rc_tail, rc);
  trigger_transmit (h);
  if (NULL != rc->cont)
    rc->cont (rc->cont_cls, NULL);
  GNUNET_free (rc);
  return ret;
}


/**
 * Check if we have a request pending in the transmission queue and are
 * able to transmit it right now.  If so, schedule transmission.
 *
 * @param h handle to the service
 */
static void
trigger_transmit (struct GNUNET_SENSOR_Handle *h)
{
  struct GNUNET_SENSOR_RequestContext *rc;

  if (NULL == (rc = h->rc_head))
    return;                     /* no requests queued */
  if (NULL != h->th)
    return;                     /* request already pending */
  if (NULL == h->client)
  {
    /* disconnected, try to reconnect */
    reconnect (h);
    return;
  }
  h->th =
      GNUNET_CLIENT_notify_transmit_ready (h->client, rc->size,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_YES, &do_transmit, h);
}


/**
 * Client asking to iterate all available sensors
 *
 * @param h Handle to SENSOR service
 * @param timeout how long to wait until timing out
 * @param sensorname information on one sensor only, can be NULL to get all
 * @param sensorname_len length of the sensorname parameter
 * @param callback the method to call for each sensor
 * @param callback_cls closure for callback
 * @return iterator context
 */
struct GNUNET_SENSOR_SensorIteratorContext *
GNUNET_SENSOR_iterate_sensors (struct GNUNET_SENSOR_Handle *h,
                               struct GNUNET_TIME_Relative timeout,
                               const char *sensorname, size_t sensorname_len,
                               GNUNET_SENSOR_SensorIteratorCB callback,
                               void *callback_cls)
{
  struct GNUNET_SENSOR_SensorIteratorContext *ic;
  struct GNUNET_SENSOR_RequestContext *rc;
  struct GNUNET_MessageHeader *mh;

  ic = GNUNET_new (struct GNUNET_SENSOR_SensorIteratorContext);

  if (NULL == sensorname)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Requesting list of sensors from SENSOR service\n");
    rc = GNUNET_malloc (sizeof (struct GNUNET_SENSOR_RequestContext) +
                        sizeof (struct GNUNET_MessageHeader));
    rc->size = sizeof (struct GNUNET_MessageHeader);
    mh = (struct GNUNET_MessageHeader *) &rc[1];
    mh->size = htons (sizeof (struct GNUNET_MessageHeader));
    mh->type = htons (GNUNET_MESSAGE_TYPE_SENSOR_GETALL);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Requesting information on sensor `%s' from SENSOR service\n",
         sensorname);
    rc = GNUNET_malloc (sizeof (struct GNUNET_SENSOR_RequestContext) +
                        sizeof (struct GNUNET_MessageHeader) + sensorname_len);
    rc->size = sizeof (struct GNUNET_MessageHeader) + sensorname_len;
    mh = (struct GNUNET_MessageHeader *) &rc[1];
    mh->size = htons (rc->size);
    mh->type = htons (GNUNET_MESSAGE_TYPE_SENSOR_GET);
    memcpy (&mh[1], sensorname, sensorname_len);
  }
  ic->h = h;
  ic->rc = rc;
  ic->callback = callback;
  ic->callback_cls = callback_cls;
  ic->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  ic->timeout_task =
      GNUNET_SCHEDULER_add_delayed (timeout, &signal_sensor_iteration_timeout,
                                    ic);
  rc->cont = &sensor_iterator_start_receive;
  rc->cont_cls = ic;
  GNUNET_CONTAINER_DLL_insert_tail (h->rc_head, h->rc_tail, rc);
  GNUNET_CONTAINER_DLL_insert_tail (h->ic_head, h->ic_tail, ic);
  trigger_transmit (h);
  return ic;
}

/* end of sensor_api.c */
