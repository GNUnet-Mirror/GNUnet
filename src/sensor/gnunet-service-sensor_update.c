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
 * @file sensor/gnunet-service-sensor_update.c
 * @brief sensor service update functionality
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "sensor.h"
#include "gnunet_cadet_service.h"
#include "gnunet_sensor_model_plugin.h"
#include "gnunet_applications.h"

#define LOG(kind,...) GNUNET_log_from (kind, "sensor-update",__VA_ARGS__)

/**
 * Interval at which to contact update points for new sensor updates.
 */
#define SENSOR_UPDATE_CHECK_INTERVAL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_DAYS, 1)

/**
 * Interval at which to retry contacting update point if we were busy.
 */
#define SENSOR_UPDATE_CHECK_RETRY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 1)


/**
 * Message queued to be sent to an update point stored in a DLL
 */
struct PendingMessage
{

  /**
   * DLL
   */
  struct PendingMessage *prev;

  /**
   * DLL
   */
  struct PendingMessage *next;

  /**
   * Actual queued message
   */
  struct GNUNET_MessageHeader *msg;

};

/**
 * Sensors update point
 */
struct UpdatePoint
{

  /**
   * DLL
   */
  struct UpdatePoint *prev;

  /**
   * DLL
   */
  struct UpdatePoint *next;

  /**
   * Identity of peer running update point
   */
  struct GNUNET_PeerIdentity peer_id;

  /**
   * CADET channel to update point
   */
  struct GNUNET_CADET_Channel *ch;

  /**
   * CADET transmit handle for a message to be sent to update point.
   */
  struct GNUNET_CADET_TransmitHandle *th;

  /**
   * Head of DLL of pending requests to be sent to update point.
   */
  struct PendingMessage *pm_head;

  /**
   * Tail of DLL of pending requests to be sent to update point.
   */
  struct PendingMessage *pm_tail;

  /**
   * Are we waiting for a sensor list?
   */
  int expecting_sensor_list;

  /**
   * How many sensor updates did we request and are waiting for.
   */
  int expected_sensor_updates;

  /**
   * Did a failure occur while dealing with this update point before?
   */
  int failed;

};


/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Path to sensor definition directory
 */
static char *sensor_dir;

/**
 * Hashmap of known sensors
 */
static struct GNUNET_CONTAINER_MultiHashMap *sensors;

/**
 * Head of update points DLL.
 */
static struct UpdatePoint *up_head;

/**
 * Tail of update points DLL.
 */
static struct UpdatePoint *up_tail;

/**
 * The current default update point to use.
 */
static struct UpdatePoint *up_default;

/**
 * Handle to CADET service
 */
static struct GNUNET_CADET_Handle *cadet;

/**
 * Are we in the process of checking and updating sensors?
 */
static int updating;

/**
 * GNUnet scheduler task that starts the update check process.
 */
static GNUNET_SCHEDULER_TaskIdentifier update_task;

/**
 * Pointer to service reset function called when we have new sensor updates.
 */
static void (*reset_cb) ();


/**
 * Contact update points to check for new updates
 *
 * @param cls unused
 * @param tc GNUnet scheduler task context
 */
static void
check_for_updates (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Trigger sending next pending message to the default update point if any.
 *
 */
static void
trigger_send_next_msg ();


/**
 * Cleanup update point context. This does not destroy the struct itself.
 *
 * @param up UpdatePoint struct
 */
static void
cleanup_updatepoint (struct UpdatePoint *up)
{
  struct PendingMessage *pm;

  up->expecting_sensor_list = GNUNET_NO;
  up->expected_sensor_updates = 0;
  if (NULL != up->th)
  {
    GNUNET_CADET_notify_transmit_ready_cancel (up->th);
    up->th = NULL;
  }
  pm = up->pm_head;
  while (NULL != pm)
  {
    GNUNET_CONTAINER_DLL_remove (up->pm_head, up->pm_tail, pm);
    GNUNET_free (pm->msg);
    GNUNET_free (pm);
    pm = up->pm_head;
  }
  if (NULL != up->ch)
  {
    GNUNET_CADET_channel_destroy (up->ch);
    up->ch = NULL;
  }
}


/**
 * Stop the sensor update module.
 */
void
SENSOR_update_stop ()
{
  struct UpdatePoint *up;

  up_default = NULL;
  up = up_head;
  if (GNUNET_SCHEDULER_NO_TASK != update_task)
  {
    GNUNET_SCHEDULER_cancel (update_task);
    update_task = GNUNET_SCHEDULER_NO_TASK;
  }
  while (NULL != up)
  {
    GNUNET_CONTAINER_DLL_remove (up_head, up_tail, up);
    cleanup_updatepoint (up);
    GNUNET_free (up);
    up = up_head;
  }
  if (NULL != cadet)
  {
    GNUNET_CADET_disconnect (cadet);
    cadet = NULL;
  }
  if (NULL != sensor_dir)
  {
    GNUNET_free (sensor_dir);
    sensor_dir = NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sensor update module stopped.\n");
}


/**
 * A failure occured in connecting/retrieval/verification with current default
 * update point. This method will try to find another update point, do cleanup
 * and reschedule update check.
 */
static void
fail ()
{
  struct UpdatePoint *up;

  cleanup_updatepoint (up_default);
  if (up_default == up_tail)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "All defined update points failed. Will retry again in %s.\n",
         GNUNET_STRINGS_relative_time_to_string (SENSOR_UPDATE_CHECK_INTERVAL,
                                                 GNUNET_NO));
    up = up_head;
    while (NULL != up)
    {
      up->failed = GNUNET_NO;
      up = up->next;
    }
    update_task =
        GNUNET_SCHEDULER_add_delayed (SENSOR_UPDATE_CHECK_INTERVAL,
                                      &check_for_updates, NULL);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_WARNING,
       "Update point `%s' failed, trying next one now.\n",
       GNUNET_i2s (&up_default->peer_id));
  up_default = up_default->next;
  update_task = GNUNET_SCHEDULER_add_now (&check_for_updates, NULL);
}


/**
 * Function called to notify a client about the connection begin ready
 * to queue more data.  @a buf will be NULL and @a size zero if the
 * connection was closed for writing in the meantime.
 *
 * Perform the actual sending of the message to update point.
 *
 * @param cls closure (unused)
 * @param size number of bytes available in @a buf
 * @param buf where the callee should write the message
 * @return number of bytes written to @a buf
 */
static size_t
do_send_msg (void *cls, size_t size, void *buf)
{
  struct PendingMessage *pm;
  size_t msg_size;

  up_default->th = NULL;
  pm = up_default->pm_head;
  msg_size = ntohs (pm->msg->size);
  GNUNET_CONTAINER_DLL_remove (up_default->pm_head, up_default->pm_tail, pm);
  if (NULL == buf || size < msg_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Error trying to send a message to update point `%s'.\n"),
                GNUNET_i2s (&up_default->peer_id));
    fail ();
    return 0;
  }
  memcpy (buf, pm->msg, msg_size);
  GNUNET_free (pm->msg);
  GNUNET_free (pm);
  trigger_send_next_msg ();
  return msg_size;
}


/**
 * Trigger sending next pending message to the default update point if any.
 *
 */
static void
trigger_send_next_msg ()
{
  struct PendingMessage *pm;

  if (NULL == up_default->pm_head)
    return;
  if (NULL != up_default->th)
    return;
  pm = up_default->pm_head;
  up_default->th =
      GNUNET_CADET_notify_transmit_ready (up_default->ch, GNUNET_YES,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          ntohs (pm->msg->size), &do_send_msg,
                                          NULL);
}


/**
 * Add a message to the queue to be sent to the current default update point.
 *
 * @param msg Message to be queued
 */
static void
queue_msg (struct GNUNET_MessageHeader *msg)
{
  struct PendingMessage *pm;

  pm = GNUNET_new (struct PendingMessage);

  pm->msg = msg;
  GNUNET_CONTAINER_DLL_insert_tail (up_default->pm_head, up_default->pm_tail,
                                    pm);
  trigger_send_next_msg ();
}


/**
 * Contact update points to check for new updates
 *
 * @param cls unused
 * @param tc GNUnet scheduler task context
 */
static void
check_for_updates (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_MessageHeader *msg;
  size_t msg_size;

  update_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  if (GNUNET_YES == updating)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Update process still running and update interval already exhausted."
         "Retrying in %s.\n",
         GNUNET_STRINGS_relative_time_to_string (SENSOR_UPDATE_CHECK_RETRY,
                                                 GNUNET_NO));
    update_task =
        GNUNET_SCHEDULER_add_delayed (SENSOR_UPDATE_CHECK_RETRY,
                                      &check_for_updates, NULL);
    return;
  }
  updating = GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Checking for sensor updates.\n");
  GNUNET_assert (NULL != up_default);
  up_default->ch =
      GNUNET_CADET_channel_create (cadet, up_default, &up_default->peer_id,
                                   GNUNET_APPLICATION_TYPE_SENSORUPDATE,
                                   GNUNET_CADET_OPTION_DEFAULT);
  if (NULL == up_default->ch)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Failed to connect to update point `%s'.\n"),
         GNUNET_i2s (&up_default->peer_id));
    fail ();
    return;
  }
  /* Start by requesting list of sensors available from update point */
  up_default->expecting_sensor_list = GNUNET_YES;
  msg = GNUNET_new (struct GNUNET_MessageHeader);
  msg_size = sizeof (struct GNUNET_MessageHeader);
  msg->size = htons (msg_size);
  msg->type = htons (GNUNET_MESSAGE_TYPE_SENSOR_LIST_REQ);
  queue_msg (msg);
  update_task =
      GNUNET_SCHEDULER_add_delayed (SENSOR_UPDATE_CHECK_INTERVAL,
                                    &check_for_updates, NULL);
}


/**
 * Function that reads and validates (correctness not connectivity) of available
 * sensor update points.
 *
 * @return number of update points loaded successfully
 */
static int
load_update_points ()
{
  char *points_list;
  int points_list_len;
  int i;
  int start;
  int len;
  struct GNUNET_CRYPTO_EddsaPublicKey public_key;
  struct UpdatePoint *up;
  int count = 0;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "sensor", "UPDATE_POINTS",
                                             &points_list))
  {
    return 0;
  }
  points_list_len = strlen (points_list) + 1;
  for (i = 0; i < points_list_len; i++)
  {
    if (' ' == points_list[i])
      continue;
    start = i;
    len = 0;
    while (' ' != points_list[i] && '\0' != points_list[i])
    {
      len++;
      i++;
    }
    if (GNUNET_OK !=
        GNUNET_CRYPTO_eddsa_public_key_from_string (points_list + start, len,
                                                    &public_key))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Invalid EDDSA public key `%.*s' for update point.\n", len,
           points_list + len);
      continue;
    }
    up = GNUNET_new (struct UpdatePoint);

    up->peer_id.public_key = public_key;
    up->ch = NULL;
    up->th = NULL;
    up->expecting_sensor_list = GNUNET_NO;
    up->expected_sensor_updates = 0;
    up->failed = GNUNET_NO;
    GNUNET_CONTAINER_DLL_insert (up_head, up_tail, up);
    count++;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Loaded update point `%s'.\n",
         GNUNET_i2s_full (&up->peer_id));
  }
  GNUNET_free (points_list);
  return count;
}


/**
 * Checks if the given sensor name and version (retrieved from an update point)
 * is new for us and we would like to install it. This is the case if we don't
 * have this sensor or we have an old version of it.
 *
 * @param sensorname Sensor name
 * @param sensorversion_major First part of version number
 * @param sensorversion_minor Second part of version number
 * @return #GNUNET_YES if we don't have this sensor
 *         #GNUNET_NO if we have it
 */
static int
update_required (char *sensorname, uint16_t sensorversion_major,
                 uint16_t sensorversion_minor)
{
  struct GNUNET_HashCode key;
  struct GNUNET_SENSOR_SensorInfo *local_sensor;

  GNUNET_CRYPTO_hash (sensorname, strlen (sensorname) + 1, &key);
  local_sensor = GNUNET_CONTAINER_multihashmap_get (sensors, &key);
  if (NULL == local_sensor)
    return GNUNET_YES;
  if (GNUNET_SENSOR_version_compare
      (local_sensor->version_major, local_sensor->version_minor,
       sensorversion_major, sensorversion_minor) < 0)
    return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Handler of a sensor list message received from an update point.
 *
 * @param cls Closure (unused).
 * @param channel Connection to the other end.
 * @param channel_ctx Place to store local state associated with the channel.
 * @param message The actual message.
 * @return #GNUNET_OK to keep the channel open,
 *         #GNUNET_SYSERR to close it (signal serious error).
 */
static int
handle_sensor_brief (void *cls, struct GNUNET_CADET_Channel *channel,
                     void **channel_ctx,
                     const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SENSOR_SensorBriefMessage *sbm;
  struct GNUNET_MessageHeader *pull_req;
  uint16_t version_major;
  uint16_t version_minor;
  uint16_t msg_size;

  GNUNET_assert (*channel_ctx == up_default);
  if (GNUNET_YES != up_default->expecting_sensor_list)
  {
    GNUNET_break_op (0);
    fail ();
    return GNUNET_OK;
  }
  if (GNUNET_MESSAGE_TYPE_SENSOR_END == ntohs (message->type))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received end of sensor list msg. We already requested %d updates.\n",
         up_default->expected_sensor_updates);
    up_default->expecting_sensor_list = GNUNET_NO;
    if (0 == up_default->expected_sensor_updates)
    {
      updating = GNUNET_NO;
      cleanup_updatepoint (up_default);
      return GNUNET_OK;
    }
  }
  else
  {
    sbm = (struct GNUNET_SENSOR_SensorBriefMessage *) message;
    version_major = ntohs (sbm->version_major);
    version_minor = ntohs (sbm->version_minor);
    if (GNUNET_YES ==
        update_required ((char *) &sbm[1], version_major, version_minor))
    {
      LOG (GNUNET_ERROR_TYPE_INFO,
           "Requesting sensor %s %d.%d from update point.\n", &sbm[1],
           version_major, version_minor);
      /* We duplicate the same msg received but change the type and send it
       * back to update point to ask for full sensor information. */
      msg_size = ntohs (message->size);
      pull_req = GNUNET_malloc (msg_size);
      memcpy (pull_req, message, msg_size);
      pull_req->type = htons (GNUNET_MESSAGE_TYPE_SENSOR_FULL_REQ);
      queue_msg (pull_req);
      up_default->expected_sensor_updates++;
    }
  }
  GNUNET_CADET_receive_done (channel);
  return GNUNET_OK;
}


/**
 * Update local sensor definitions with a sensor retrieved from an update point.
 *
 * @param sensorname Sensor name
 * @param sensorfile Buffer containing the sensor definition file
 * @param sensorfile_size Size of @e sensorfile
 * @param scriptname Name of associated script file, NULL if no script
 * @param scriptfile Buffer containing the script file, NULL if no script
 * @param scriptfile_size Size of @e scriptfile, 0 if no script
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
update_sensor (char *sensorname, void *sensorfile, uint16_t sensorfile_size,
               char *scriptname, void *scriptfile, uint16_t scriptfile_size)
{
  char *sensor_path;
  char *script_path;

  LOG (GNUNET_ERROR_TYPE_INFO,
       "Received new sensor information:\n" "Name: %s\n"
       "Sensor file size: %d\n" "Script name: %s\n" "Script file size: %d.\n",
       sensorname, sensorfile_size, (NULL == scriptname) ? "None" : scriptname,
       scriptfile_size);
  GNUNET_asprintf (&sensor_path, "%s%s", sensor_dir, sensorname);
  GNUNET_DISK_fn_write (sensor_path, sensorfile, sensorfile_size,
                        GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_GROUP_READ
                        | GNUNET_DISK_PERM_OTHER_READ |
                        GNUNET_DISK_PERM_USER_WRITE);
  if (NULL != scriptname)
  {
    GNUNET_asprintf (&script_path, "%s-files%s%s", sensor_path,
                     DIR_SEPARATOR_STR, scriptname);
    GNUNET_DISK_fn_write (script_path, scriptfile, scriptfile_size,
                          GNUNET_DISK_PERM_USER_READ |
                          GNUNET_DISK_PERM_GROUP_READ |
                          GNUNET_DISK_PERM_OTHER_READ |
                          GNUNET_DISK_PERM_USER_WRITE |
                          GNUNET_DISK_PERM_GROUP_WRITE |
                          GNUNET_DISK_PERM_USER_EXEC |
                          GNUNET_DISK_PERM_GROUP_EXEC);
    GNUNET_free (script_path);
  }
  GNUNET_free (sensor_path);
  return GNUNET_OK;
}


/**
 * Resets the service after we are done with an update.
 *
 * @param cls unused
 * @param tc unused
 */
static void
reset (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  reset_cb ();
}


/**
 * Handler of a sensor list message received from an update point.
 *
 * @param cls Closure (unused).
 * @param channel Connection to the other end.
 * @param channel_ctx Place to store local state associated with the channel.
 * @param message The actual message.
 * @return #GNUNET_OK to keep the channel open,
 *         #GNUNET_SYSERR to close it (signal serious error).
 */
static int
handle_sensor_full (void *cls, struct GNUNET_CADET_Channel *channel,
                    void **channel_ctx,
                    const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SENSOR_SensorFullMessage *sfm;
  uint16_t msg_size;
  uint16_t sensorfile_size;
  uint16_t scriptfile_size;
  char *sensorname_ptr;
  void *sensorfile_ptr;
  char *scriptname_ptr;
  void *scriptfile_ptr;

  /* error check */
  GNUNET_assert (*channel_ctx == up_default);
  msg_size = ntohs (message->size);
  if (up_default->expected_sensor_updates <= 0 ||
      msg_size < sizeof (struct GNUNET_SENSOR_SensorFullMessage))
  {
    GNUNET_break_op (0);
    fail ();
    return GNUNET_OK;
  }
  /* parse received msg */
  sfm = (struct GNUNET_SENSOR_SensorFullMessage *) message;
  sensorname_ptr = (char *) &sfm[1];
  sensorfile_ptr = sensorname_ptr + ntohs (sfm->sensorname_size);
  sensorfile_size = ntohs (sfm->sensorfile_size);
  scriptfile_size = ntohs (sfm->scriptfile_size);
  if (scriptfile_size > 0)
  {
    scriptname_ptr = sensorfile_ptr + sensorfile_size;
    scriptfile_ptr = scriptname_ptr + ntohs (sfm->scriptname_size);
  }
  else
  {
    scriptname_ptr = NULL;
    scriptfile_ptr = NULL;
  }
  update_sensor ((char *) &sfm[1], sensorfile_ptr, sensorfile_size,
                 scriptname_ptr, scriptfile_ptr, scriptfile_size);
  up_default->expected_sensor_updates--;
  if (0 == up_default->expected_sensor_updates)
  {
    updating = GNUNET_NO;
    cleanup_updatepoint (up_default);
    GNUNET_SCHEDULER_add_continuation (&reset, NULL, 0);
  }
  else
    GNUNET_CADET_receive_done (channel);
  return GNUNET_OK;
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
  struct UpdatePoint *up = channel_ctx;

  up->ch = NULL;
  if (GNUNET_YES == updating)
  {
    fail ();
    return;
  }
  cleanup_updatepoint (up);
}


/**
 * Start the sensor update module
 *
 * @param c our service configuration
 * @param s multihashmap of loaded sensors
 * @param cb callback to reset service components when we have new updates
 * @return #GNUNET_OK if started successfully, #GNUNET_SYSERR otherwise
 */
int
SENSOR_update_start (const struct GNUNET_CONFIGURATION_Handle *c,
                     struct GNUNET_CONTAINER_MultiHashMap *s, void (*cb) ())
{
  static struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
    {&handle_sensor_brief, GNUNET_MESSAGE_TYPE_SENSOR_BRIEF, 0},
    {&handle_sensor_brief, GNUNET_MESSAGE_TYPE_SENSOR_END, 0},
    {&handle_sensor_full, GNUNET_MESSAGE_TYPE_SENSOR_FULL, 0},
    {NULL, 0, 0}
  };
  int up_count;

  GNUNET_assert (NULL != s);
  cfg = c;
  sensors = s;
  reset_cb = cb;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "SENSOR", "SENSOR_DIR",
                                               &sensor_dir))
    sensor_dir = GNUNET_SENSOR_get_default_sensor_dir ();
  cadet =
      GNUNET_CADET_connect (cfg, NULL, NULL, &cadet_channel_destroyed,
                            cadet_handlers, NULL);
  if (NULL == cadet)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Failed to connect to CADET service.\n"));
    SENSOR_update_stop ();
    return GNUNET_SYSERR;
  }
  up_count = load_update_points ();
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Loaded %d update points.\n", up_count);
  if (0 == up_count)
  {
    SENSOR_update_stop ();
    return GNUNET_SYSERR;
  }
  up_default = up_head;
  updating = GNUNET_NO;
  update_task =
      GNUNET_SCHEDULER_add_delayed (SENSOR_UPDATE_CHECK_INTERVAL,
                                    &check_for_updates, NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sensor update module started.\n");
  return GNUNET_OK;
}

/* end of gnunet-service-sensor_update.c */
