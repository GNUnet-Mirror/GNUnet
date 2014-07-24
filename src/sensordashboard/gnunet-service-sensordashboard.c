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
   * Are we in the process of destroying this context?
   */
  int destroying;

};


/**
 * Handle to CADET service
 */
static struct GNUNET_CADET_Handle *cadet;

/**
 * Global hashmap of defined sensors
 */
static struct GNUNET_CONTAINER_MultiHashMap *sensors;

/**
 * Handle to the peerstore service connection
 */
static struct GNUNET_PEERSTORE_Handle *peerstore;

/**
 * Name of this subsystem to be used for peerstore operations
 */
static char *subsystem = "sensordashboard";

/**
 * Head of a DLL of all connected client peers
 */
static struct ClientPeerContext *cp_head;

/**
 * Tail of a DLL of all connected client peers
 */
static struct ClientPeerContext *cp_tail;


/**
 * Destroy a given client peer context
 *
 * @param cp client peer context
 */
static void
destroy_clientpeer (struct ClientPeerContext *cp)
{
  cp->destroying = GNUNET_YES;
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
cadet_channel_destroyed (void *cls,
                         const struct GNUNET_CADET_Channel *channel,
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
cadet_channel_created (void *cls,
                       struct GNUNET_CADET_Channel *channel,
                       const struct GNUNET_PeerIdentity *initiator,
                       uint32_t port, enum GNUNET_CADET_ChannelOption options)
{
  struct ClientPeerContext *cp;

  cp = GNUNET_new (struct ClientPeerContext);
  cp->peerid = *initiator;
  cp->ch = channel;
  cp->destroying = GNUNET_NO;
  GNUNET_CONTAINER_DLL_insert (cp_head, cp_tail, cp);
  return cp;
}


/**
 * Parses a sensor reading message struct
 *
 * @param msg message header received
 * @param sensors multihashmap of loaded sensors
 * @return sensor reading struct or NULL if error
 */
static struct GNUNET_SENSOR_Reading *
parse_reading_message (const struct GNUNET_MessageHeader *msg,
                       struct GNUNET_CONTAINER_MultiHashMap *sensors)
{
  uint16_t msg_size;
  struct GNUNET_SENSOR_ReadingMessage *rm;
  uint16_t sensorname_size;
  uint16_t value_size;
  void *dummy;
  char *sensorname;
  struct GNUNET_HashCode key;
  struct GNUNET_SENSOR_SensorInfo *sensor;
  struct GNUNET_SENSOR_Reading *reading;

  msg_size = ntohs (msg->size);
  if (msg_size < sizeof (struct GNUNET_SENSOR_ReadingMessage))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Invalid reading message size.\n");
    return NULL;
  }
  rm = (struct GNUNET_SENSOR_ReadingMessage *)msg;
  sensorname_size = ntohs (rm->sensorname_size);
  value_size = ntohs (rm->value_size);
  if ((sizeof (struct GNUNET_SENSOR_ReadingMessage)
      + sensorname_size + value_size) != msg_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Invalid reading message size.\n");
    return NULL;
  }
  dummy = &rm[1];
  sensorname = GNUNET_malloc (sensorname_size);
  memcpy (sensorname, dummy, sensorname_size);
  GNUNET_CRYPTO_hash(sensorname, sensorname_size, &key);
  GNUNET_free (sensorname);
  sensor = GNUNET_CONTAINER_multihashmap_get (sensors, &key);
  if (NULL == sensor)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
        "Unknown sensor name in reading message.\n");
    return NULL;
  }
  if ((sensor->version_minor != ntohs (rm->sensorversion_minor)) ||
      (sensor->version_major != ntohs (rm->sensorversion_major)))
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
  reading = GNUNET_new (struct GNUNET_SENSOR_Reading);
  reading->sensor = sensor;
  reading->timestamp = GNUNET_be64toh (rm->timestamp);
  reading->value_size = value_size;
  reading->value = GNUNET_malloc (value_size);
  dummy += sensorname_size;
  memcpy (reading->value, dummy, value_size);
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
handle_sensor_reading (void *cls,
                       struct GNUNET_CADET_Channel *channel,
                       void **channel_ctx,
                       const struct GNUNET_MessageHeader *message)
{
  struct ClientPeerContext *cp = *channel_ctx;
  struct GNUNET_SENSOR_Reading *reading;

  reading = parse_reading_message (message, sensors);
  if (NULL == reading)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Received an invalid sensor reading from peer `%s'\n",
                GNUNET_i2s (&cp->peerid));
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Received a sensor reading from peer `%s':\n"
              "# Sensor name: `%s'\n"
              "# Timestamp: %" PRIu64 "\n"
              "# Value size: %" PRIu64 ".\n",
              GNUNET_i2s (&cp->peerid),
              reading->sensor->name,
              reading->timestamp,
              reading->value_size);
  GNUNET_PEERSTORE_store (peerstore, subsystem, &cp->peerid,
                          reading->sensor->name, reading->value,
                          reading->value_size, GNUNET_TIME_UNIT_FOREVER_ABS,
                          GNUNET_PEERSTORE_STOREOPTION_MULTIPLE, NULL, NULL);
  GNUNET_free (reading->value);
  GNUNET_free (reading);
  GNUNET_CADET_receive_done (channel);
  return GNUNET_OK;
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
handle_sensor_list_req (void *cls,
                        struct GNUNET_CADET_Channel *channel,
                        void **channel_ctx,
                        const struct GNUNET_MessageHeader *message)
{
  //TODO
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
      {NULL, 0, 0}
  };
  static uint32_t cadet_ports[] = {
      GNUNET_APPLICATION_TYPE_SENSORDASHBOARD,
      GNUNET_APPLICATION_TYPE_SENSORUPDATE,
      GNUNET_APPLICATION_TYPE_END
  };
  sensors = GNUNET_SENSOR_load_all_sensors ();
  GNUNET_assert (NULL != sensors);
  cadet = GNUNET_CADET_connect(cfg,
                               NULL,
                               &cadet_channel_created,
                               &cadet_channel_destroyed,
                               cadet_handlers,
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
