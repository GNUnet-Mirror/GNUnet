/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file sensordashboard/gnunet-service-sensordashboard.c
 * @brief Service collecting sensor readings from peers
 * @author Omar Tarabai
 */
#include <inttypes.h>
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_applications.h"
#include "sensordashboard.h"
#include "gnunet_cadet_service.h"
#include "gnunet_sensor_util_lib.h"
#include "gnunet_peerstore_service.h"


/**
 * Context of a connected client peer
 */
struct ClientPeerContext
{

  /**
   * DLL
   */
  struct ClientPeerContext *prev;

  /*
   * DLL
   */
  struct ClientPeerContext *next;

  /**
   * GNUnet Peer identity
   */
  struct GNUNET_PeerIdentity peerid;

  /**
   * Handle to the cadet channel
   */
  struct GNUNET_CADET_Channel *ch;

  /**
   * CADET transmit handle if we requested a transmission
   */
  struct GNUNET_CADET_TransmitHandle *th;

  /**
   * Head of DLL of pending messages to be sent to client
   */
  struct PendingMessage *pm_head;

  /**
   * Tail of DLL of pending messages to be sent to client
   */
  struct PendingMessage *pm_tail;

  /**
   * Are we in the process of destroying this context?
   */
  int destroying;

};

/**
 * Message queued to be sent to a client stored in a DLL
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
 * Carries a single reading from a sensor
 */
struct ClientSensorReading
{

  /**
   * Sensor this reading is related to
   */
  struct GNUNET_SENSOR_SensorInfo *sensor;

  /**
   * Timestamp of taking the reading
   */
  struct GNUNET_TIME_Absolute timestamp;

  /**
   * Reading value
   */
  void *value;

  /**
   * Size of @e value
   */
  uint16_t value_size;

};


/**
 * Path to sensor definition directory
 */
static char *sensor_dir;

/**
 * Global hashmap of defined sensors
 */
static struct GNUNET_CONTAINER_MultiHashMap *sensors;

/**
 * Handle to CADET service
 */
static struct GNUNET_CADET_Handle *cadet;

/**
 * Handle to the peerstore service connection
 */
static struct GNUNET_PEERSTORE_Handle *peerstore;

/**
 * Name of the subsystem used to store sensor values received from remote peers
 * in PEERSTORE
 */
static char *values_subsystem = "sensordashboard-values";

/**
 * Name of the subsystem used to store anomaly reports received from remote
 * peers in PEERSTORE
 */
static char *anomalies_subsystem = "sensordashboard-anomalies";

/**
 * Head of a DLL of all connected client peers
 */
static struct ClientPeerContext *cp_head;

/**
 * Tail of a DLL of all connected client peers
 */
static struct ClientPeerContext *cp_tail;


/**
 * Trigger sending next pending message to the given client peer if any.
 *
 * @param cp client peer context struct
 */
static void
trigger_send_next_msg (struct ClientPeerContext *cp);


/**
 * Destroy a given client peer context
 *
 * @param cp client peer context
 */
static void
destroy_clientpeer (struct ClientPeerContext *cp)
{
  struct PendingMessage *pm;

  cp->destroying = GNUNET_YES;
  if (NULL != cp->th)
  {
    GNUNET_CADET_notify_transmit_ready_cancel (cp->th);
    cp->th = NULL;
  }
  pm = cp->pm_head;
  while (NULL != pm)
  {
    GNUNET_CONTAINER_DLL_remove (cp->pm_head, cp->pm_tail, pm);
    GNUNET_free (pm->msg);
    GNUNET_free (pm);
    pm = cp->pm_head;
  }
  if (NULL != cp->ch)
  {
    GNUNET_CADET_channel_destroy (cp->ch);
    cp->ch = NULL;
  }
  GNUNET_free (cp);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ClientPeerContext *cp;

  cp = cp_head;
  while (NULL != cp)
  {
    GNUNET_CONTAINER_DLL_remove (cp_head, cp_tail, cp);
    destroy_clientpeer (cp);
    cp = cp_head;
  }
  if (NULL != cadet)
  {
    GNUNET_CADET_disconnect (cadet);
    cadet = NULL;
  }
  if (NULL != peerstore)
  {
    GNUNET_PEERSTORE_disconnect (peerstore, GNUNET_YES);
    peerstore = NULL;
  }
  GNUNET_SENSOR_destroy_sensors (sensors);
  if (NULL != sensor_dir)
  {
    GNUNET_free (sensor_dir);
    sensor_dir = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
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
  struct ClientPeerContext *cp = channel_ctx;

  if (GNUNET_YES == cp->destroying)
    return;
  cp->ch = NULL;
  GNUNET_CONTAINER_DLL_remove (cp_head, cp_tail, cp);
  destroy_clientpeer (cp);
}


/**
 * Method called whenever another peer has added us to a channel
 * the other peer initiated.
 * Only called (once) upon reception of data with a message type which was
 * subscribed to in #GNUNET_CADET_connect.
 *
 * A call to #GNUNET_CADET_channel_destroy causes the channel to be ignored. In
 * this case the handler MUST return NULL.
 *
 * @param cls closure
 * @param channel new handle to the channel
 * @param initiator peer that started the channel
 * @param port Port this channel is for.
 * @param options CadetOption flag field, with all active option bits set to 1.
 *
 * @return initial channel context for the channel
 *         (can be NULL -- that's not an error)
 */
static void *
cadet_channel_created (void *cls, struct GNUNET_CADET_Channel *channel,
                       const struct GNUNET_PeerIdentity *initiator,
                       uint32_t port, enum GNUNET_CADET_ChannelOption options)
{
  struct ClientPeerContext *cp;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received a channel connection from peer `%s'.\n",
              GNUNET_i2s (initiator));
  cp = GNUNET_new (struct ClientPeerContext);

  cp->peerid = *initiator;
  cp->ch = channel;
  cp->destroying = GNUNET_NO;
  GNUNET_CONTAINER_DLL_insert (cp_head, cp_tail, cp);
  return cp;
}


/**
 * Function called to notify a client about the connection begin ready
 * to queue more data.  @a buf will be NULL and @a size zero if the
 * connection was closed for writing in the meantime.
 *
 * Perform the actual sending of the message to client peer.
 *
 * @param cls closure, a `struct ClientPeerContext *`
 * @param size number of bytes available in @a buf
 * @param buf where the callee should write the message
 * @return number of bytes written to @a buf
 */
static size_t
do_send_msg (void *cls, size_t size, void *buf)
{
  struct ClientPeerContext *cp = cls;
  struct PendingMessage *pm;
  size_t msg_size;

  cp->th = NULL;
  pm = cp->pm_head;
  msg_size = ntohs (pm->msg->size);
  GNUNET_CONTAINER_DLL_remove (cp->pm_head, cp->pm_tail, pm);
  if (NULL == buf || size < msg_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Error trying to send a message to peer `%s'.\n"),
                GNUNET_i2s (&cp->peerid));
    return 0;
  }
  memcpy (buf, pm->msg, msg_size);
  GNUNET_free (pm->msg);
  GNUNET_free (pm);
  trigger_send_next_msg (cp);
  return msg_size;
}


/**
 * Trigger sending next pending message to the given client peer if any.
 *
 * @param cp client peer context struct
 */
static void
trigger_send_next_msg (struct ClientPeerContext *cp)
{
  struct PendingMessage *pm;

  if (NULL == cp->pm_head)
    return;
  if (NULL != cp->th)
    return;
  pm = cp->pm_head;
  cp->th =
      GNUNET_CADET_notify_transmit_ready (cp->ch, GNUNET_YES,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          ntohs (pm->msg->size), &do_send_msg,
                                          cp);
}


/**
 * Add a new message to the queue to be sent to the given client peer.
 *
 * @param msg Message to be queued
 * @param cp Client peer context
 */
static void
queue_msg (struct GNUNET_MessageHeader *msg, struct ClientPeerContext *cp)
{
  struct PendingMessage *pm;

  pm = GNUNET_new (struct PendingMessage);

  pm->msg = msg;
  GNUNET_CONTAINER_DLL_insert_tail (cp->pm_head, cp->pm_tail, pm);
  trigger_send_next_msg (cp);
}


/**
 * Called with any anomaly report received from a peer.
 *
 * Each time the function must call #GNUNET_CADET_receive_done on the channel
 * in order to receive the next message. This doesn't need to be immediate:
 * can be delayed if some processing is done on the message.
 *
 * @param cls Closure (set from #GNUNET_CADET_connect).
 * @param channel Connection to the other end.
 * @param channel_ctx Place to store local state associated with the channel.
 * @param message The actual message.
 * @return #GNUNET_OK to keep the channel open,
 *         #GNUNET_SYSERR to close it (signal serious error).
 */
static int
handle_anomaly_report (void *cls, struct GNUNET_CADET_Channel *channel,
                       void **channel_ctx,
                       const struct GNUNET_MessageHeader *message)
{
  struct ClientPeerContext *cp = *channel_ctx;
  struct GNUNET_SENSOR_AnomalyReportMessage *anomaly_msg;
  struct GNUNET_SENSOR_SensorInfo *sensor;
  struct GNUNET_SENSOR_DashboardAnomalyEntry *anomaly_entry;
  struct GNUNET_TIME_Absolute expiry;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received an anomaly report message from peer `%s'.\n",
              GNUNET_i2s (&cp->peerid));
  anomaly_msg = (struct GNUNET_SENSOR_AnomalyReportMessage *) message;
  sensor =
      GNUNET_CONTAINER_multihashmap_get (sensors,
                                         &anomaly_msg->sensorname_hash);
  if (NULL == sensor)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  anomaly_entry = GNUNET_new (struct GNUNET_SENSOR_DashboardAnomalyEntry);
  anomaly_entry->anomalous = ntohs (anomaly_msg->anomalous);
  anomaly_entry->anomalous_neighbors = anomaly_msg->anomalous_neighbors;
  expiry =
      (GNUNET_YES ==
       anomaly_entry->anomalous) ? GNUNET_TIME_UNIT_FOREVER_ABS :
      GNUNET_TIME_absolute_get ();
  GNUNET_PEERSTORE_store (peerstore, anomalies_subsystem, &cp->peerid,
                          sensor->name, anomaly_entry,
                          sizeof (struct GNUNET_SENSOR_DashboardAnomalyEntry),
                          expiry, GNUNET_PEERSTORE_STOREOPTION_REPLACE, NULL,
                          NULL);
  GNUNET_free (anomaly_entry);
  GNUNET_CADET_receive_done (channel);
  return GNUNET_OK;
}


/**
 * Iterate over defined sensors, creates and sends brief sensor information to
 * given client peer over CADET.
 *
 * @param cls closure, the client peer
 * @param key sensor key
 * @param value sensor value
 * @return #GNUNET_YES to continue iteration
 */
static int
send_sensor_brief (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct ClientPeerContext *cp = cls;
  struct GNUNET_SENSOR_SensorInfo *sensor = value;
  struct GNUNET_SENSOR_SensorBriefMessage *msg;
  uint16_t sensorname_size;
  uint16_t total_size;

  /* Create message struct */
  sensorname_size = strlen (sensor->name) + 1;
  total_size =
      sizeof (struct GNUNET_SENSOR_SensorBriefMessage) + sensorname_size;
  msg = GNUNET_malloc (total_size);
  msg->header.size = htons (total_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SENSOR_BRIEF);
  msg->name_size = htons (sensorname_size);
  msg->version_major = htons (sensor->version_major);
  msg->version_minor = htons (sensor->version_minor);
  memcpy (&msg[1], sensor->name, sensorname_size);
  /* Queue the msg */
  queue_msg ((struct GNUNET_MessageHeader *) msg, cp);
  return GNUNET_YES;
}


/**
 * Called with any sensor list request received.
 *
 * Each time the function must call #GNUNET_CADET_receive_done on the channel
 * in order to receive the next message. This doesn't need to be immediate:
 * can be delayed if some processing is done on the message.
 *
 * @param cls Closure (set from #GNUNET_CADET_connect).
 * @param channel Connection to the other end.
 * @param channel_ctx Place to store local state associated with the channel.
 * @param message The actual message.
 * @return #GNUNET_OK to keep the channel open,
 *         #GNUNET_SYSERR to close it (signal serious error).
 */
static int
handle_sensor_list_req (void *cls, struct GNUNET_CADET_Channel *channel,
                        void **channel_ctx,
                        const struct GNUNET_MessageHeader *message)
{
  struct ClientPeerContext *cp = *channel_ctx;
  struct GNUNET_MessageHeader *end_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received a sensor list request from peer `%s'.\n",
              GNUNET_i2s (&cp->peerid));
  GNUNET_CONTAINER_multihashmap_iterate (sensors, &send_sensor_brief, cp);
  end_msg = GNUNET_new (struct GNUNET_MessageHeader);

  end_msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  end_msg->type = htons (GNUNET_MESSAGE_TYPE_SENSOR_END);
  queue_msg (end_msg, cp);
  GNUNET_CADET_receive_done (channel);
  return GNUNET_OK;
}


/**
 * Parses a sensor reading message struct
 *
 * @param msg message header received
 * @param sensors multihashmap of loaded sensors
 * @return sensor reading struct or NULL if error
 */
static struct ClientSensorReading *
parse_reading_message (const struct GNUNET_MessageHeader *msg,
                       struct GNUNET_CONTAINER_MultiHashMap *sensors)
{
  uint16_t msg_size;
  uint16_t value_size;
  struct GNUNET_SENSOR_ValueMessage *vm;
  struct GNUNET_SENSOR_SensorInfo *sensor;
  struct ClientSensorReading *reading;

  msg_size = ntohs (msg->size);
  if (msg_size < sizeof (struct GNUNET_SENSOR_ValueMessage))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  vm = (struct GNUNET_SENSOR_ValueMessage *) msg;
  value_size = ntohs (vm->value_size);
  if ((sizeof (struct GNUNET_SENSOR_ValueMessage) + value_size) != msg_size)
  {
    GNUNET_break_op (0);
    return NULL;
  }
  sensor = GNUNET_CONTAINER_multihashmap_get (sensors, &vm->sensorname_hash);
  if (NULL == sensor)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Unknown sensor name in reading message.\n");
    return NULL;
  }
  if ((sensor->version_minor != ntohs (vm->sensorversion_minor)) ||
      (sensor->version_major != ntohs (vm->sensorversion_major)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Sensor version mismatch in reading message.\n");
    return NULL;
  }
  if (0 == strcmp (sensor->expected_datatype, "numeric") &&
      sizeof (double) != value_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid value size for a numerical sensor.\n");
    return NULL;
  }
  reading = GNUNET_new (struct ClientSensorReading);
  reading->sensor = sensor;
  reading->timestamp = vm->timestamp;
  reading->value_size = value_size;
  reading->value = GNUNET_memdup (&vm[1], value_size);
  return reading;
}


/**
 * Called with any sensor reading messages received from CADET.
 *
 * Each time the function must call #GNUNET_CADET_receive_done on the channel
 * in order to receive the next message. This doesn't need to be immediate:
 * can be delayed if some processing is done on the message.
 *
 * @param cls Closure (set from #GNUNET_CADET_connect).
 * @param channel Connection to the other end.
 * @param channel_ctx Place to store local state associated with the channel.
 * @param message The actual message.
 * @return #GNUNET_OK to keep the channel open,
 *         #GNUNET_SYSERR to close it (signal serious error).
 */
static int
handle_sensor_reading (void *cls, struct GNUNET_CADET_Channel *channel,
                       void **channel_ctx,
                       const struct GNUNET_MessageHeader *message)
{
  struct ClientPeerContext *cp = *channel_ctx;
  struct ClientSensorReading *reading;

  reading = parse_reading_message (message, sensors);
  if (NULL == reading)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Received an invalid sensor reading from peer `%s'.\n",
                GNUNET_i2s (&cp->peerid));
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Received a sensor reading from peer `%s':\n"
              "# Sensor name: `%s'\n" "# Timestamp: %" PRIu64 "\n"
              "# Value size: %" PRIu64 ".\n", GNUNET_i2s (&cp->peerid),
              reading->sensor->name, reading->timestamp, reading->value_size);
  GNUNET_PEERSTORE_store (peerstore, values_subsystem, &cp->peerid,
                          reading->sensor->name, reading->value,
                          reading->value_size, GNUNET_TIME_UNIT_FOREVER_ABS,
                          GNUNET_PEERSTORE_STOREOPTION_MULTIPLE, NULL, NULL);
  GNUNET_free (reading->value);
  GNUNET_free (reading);
  GNUNET_CADET_receive_done (channel);
  return GNUNET_OK;
}


/**
 * Create a message with full information about sensor
 *
 * @param sensorname Name of sensor requested
 * @return Message ready to be sent to client or NULL on error
 */
static struct GNUNET_SENSOR_SensorFullMessage *
create_full_sensor_msg (char *sensorname)
{
  struct GNUNET_HashCode key;
  struct GNUNET_SENSOR_SensorInfo *sensor;
  struct GNUNET_SENSOR_SensorFullMessage *msg;
  char *sensor_path;
  char *sensorscript_path;
  uint64_t sensorname_size;
  uint64_t sensorfile_size;
  uint64_t sensorscriptname_size;
  uint64_t sensorscript_size;
  uint64_t total_size;
  void *dummy;

  GNUNET_CRYPTO_hash (sensorname, strlen (sensorname) + 1, &key);
  sensor = GNUNET_CONTAINER_multihashmap_get (sensors, &key);
  if (NULL == sensor)
    return NULL;
  GNUNET_asprintf (&sensor_path, "%s%s", sensor_dir, sensorname);
  if (GNUNET_OK !=
      GNUNET_DISK_file_size (sensor_path, &sensorfile_size, GNUNET_NO,
                             GNUNET_YES))
  {
    GNUNET_free (sensor_dir);
    GNUNET_free (sensor_path);
    return NULL;
  }
  sensorname_size = strlen (sensorname) + 1;
  sensorscript_size = 0;
  sensorscriptname_size = 0;
  /* Test if there is an associated script */
  if (NULL != sensor->ext_process)
  {
    GNUNET_asprintf (&sensorscript_path, "%s%s-files%s%s", sensor_dir,
                     sensor->name, DIR_SEPARATOR_STR, sensor->ext_process);
    if (GNUNET_OK ==
        GNUNET_DISK_file_size (sensorscript_path, &sensorscript_size, GNUNET_NO,
                               GNUNET_YES))
    {
      sensorscriptname_size = strlen (sensor->ext_process) + 1;
    }
  }
  /* Construct the msg */
  total_size =
      sizeof (struct GNUNET_SENSOR_SensorFullMessage) + sensorname_size +
      sensorfile_size + sensorscriptname_size + sensorscript_size;
  msg = GNUNET_malloc (total_size);
  msg->header.size = htons (total_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SENSOR_FULL);
  msg->sensorname_size = htons (sensorname_size);
  msg->sensorfile_size = htons (sensorfile_size);
  msg->scriptname_size = htons (sensorscriptname_size);
  msg->scriptfile_size = htons (sensorscript_size);
  dummy = &msg[1];
  memcpy (dummy, sensorname, sensorname_size);
  dummy += sensorname_size;
  GNUNET_DISK_fn_read (sensor_path, dummy, sensorfile_size);
  dummy += sensorfile_size;
  if (sensorscriptname_size > 0)
  {
    memcpy (dummy, sensor->ext_process, sensorscriptname_size);
    dummy += sensorscriptname_size;
    GNUNET_DISK_fn_read (sensorscript_path, dummy, sensorscript_size);
    GNUNET_free (sensorscript_path);
  }
  GNUNET_free (sensor_path);
  return msg;
}


/**
 * Called with any request for full sensor information.
 *
 * Each time the function must call #GNUNET_CADET_receive_done on the channel
 * in order to receive the next message. This doesn't need to be immediate:
 * can be delayed if some processing is done on the message.
 *
 * @param cls Closure (set from #GNUNET_CADET_connect).
 * @param channel Connection to the other end.
 * @param channel_ctx Place to store local state associated with the channel.
 * @param message The actual message.
 * @return #GNUNET_OK to keep the channel open,
 *         #GNUNET_SYSERR to close it (signal serious error).
 */
static int
handle_sensor_full_req (void *cls, struct GNUNET_CADET_Channel *channel,
                        void **channel_ctx,
                        const struct GNUNET_MessageHeader *message)
{
  struct ClientPeerContext *cp = *channel_ctx;
  struct GNUNET_SENSOR_SensorBriefMessage *sbm = NULL;
  struct GNUNET_SENSOR_SensorFullMessage *sfm;
  uint16_t msg_size;
  uint16_t sensorname_size;

  msg_size = ntohs (message->size);
  /* parse & error check */
  if (msg_size > sizeof (struct GNUNET_SENSOR_SensorBriefMessage))
  {
    sbm = (struct GNUNET_SENSOR_SensorBriefMessage *) message;
    sensorname_size = ntohs (sbm->name_size);
    if (msg_size !=
        sizeof (struct GNUNET_SENSOR_SensorBriefMessage) + sensorname_size)
      sbm = NULL;
  }
  if (NULL == sbm)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Received an invalid full sensor request from peer `%s'.\n",
                GNUNET_i2s (&cp->peerid));
    return GNUNET_SYSERR;
  }
  /* Create and send msg with full sensor info */
  sfm = create_full_sensor_msg ((char *) &sbm[1]);
  if (NULL == sfm)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error creating full sensor info msg for sensor `%s'.\n",
                (char *) &sbm[1]);
    return GNUNET_SYSERR;
  }
  queue_msg ((struct GNUNET_MessageHeader *) sfm, cp);
  GNUNET_CADET_receive_done (channel);
  return GNUNET_OK;
}


/**
 * Process sensordashboard requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {NULL, NULL, 0, 0}
  };
  static struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
    {&handle_sensor_reading,
     GNUNET_MESSAGE_TYPE_SENSOR_READING, 0},
    {&handle_sensor_list_req,
     GNUNET_MESSAGE_TYPE_SENSOR_LIST_REQ,
     sizeof (struct GNUNET_MessageHeader)},
    {&handle_sensor_full_req,
     GNUNET_MESSAGE_TYPE_SENSOR_FULL_REQ,
     sizeof (struct GNUNET_MessageHeader)},
    {&handle_anomaly_report,
     GNUNET_MESSAGE_TYPE_SENSOR_ANOMALY_REPORT,
     sizeof (struct GNUNET_SENSOR_AnomalyReportMessage)},
    {NULL, 0, 0}
  };
  static uint32_t cadet_ports[] = {
    GNUNET_APPLICATION_TYPE_SENSORDASHBOARD,
    GNUNET_APPLICATION_TYPE_SENSORUPDATE,
    GNUNET_APPLICATION_TYPE_END
  };

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "SENSOR", "SENSOR_DIR",
                                               &sensor_dir))
    sensor_dir = GNUNET_SENSOR_get_default_sensor_dir ();
  sensors = GNUNET_SENSOR_load_all_sensors (sensor_dir);
  GNUNET_assert (NULL != sensors);
  cadet =
      GNUNET_CADET_connect (cfg, NULL, &cadet_channel_created,
                            &cadet_channel_destroyed, cadet_handlers,
                            cadet_ports);
  if (NULL == cadet)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to connect to `%s' service.\n"), "CADET");
    GNUNET_SCHEDULER_add_now (&cleanup_task, NULL);
    return;
  }
  peerstore = GNUNET_PEERSTORE_connect (cfg);
  if (NULL == peerstore)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to connect to `%s' service.\n"), "PEERSTORE");
    GNUNET_SCHEDULER_add_now (&cleanup_task, NULL);
    return;
  }
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                NULL);
}


/**
 * The main function for the sensordashboard service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "sensordashboard",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-sensordashboard.c */
