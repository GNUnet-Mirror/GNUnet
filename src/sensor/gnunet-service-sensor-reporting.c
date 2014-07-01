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
 * @file sensor/gnunet-service-sensor-reporting.c
 * @brief sensor service reporting functionality
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "sensor.h"
#include "gnunet_peerstore_service.h"
#include "gnunet_cadet_service.h"

#define LOG(kind,...) GNUNET_log_from (kind, "sensor-reporting",__VA_ARGS__)

/**
 * Context of reporting to collection
 * point
 */
struct CollectionReportingContext
{

  /**
   * Sensor information
   */
  struct SensorInfo *sensor;

  /**
   * Reporting task (OR GNUNET_SCHEDULER_NO_TASK)
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

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
static struct GNUNET_PeerIdentity peerid;

/**
 * Handle to CADET service
 */
static struct GNUNET_CADET_Handle *cadet;


/**
 * Stop sensor reporting module
 */
void SENSOR_reporting_stop ()
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Stopping sensor reporting module.\n");
  if (NULL != peerstore)
  {
    GNUNET_PEERSTORE_disconnect (peerstore);
    peerstore = NULL;
  }
}

/**
 * Task scheduled to send values to collection point
 *
 * @param cls closure, a 'struct CollectionReportingContext *'
 * @param tc unused
 */
void report_collection_point
(void *cls, const struct GNUNET_SCHEDULER_TaskContext* tc)
{
  struct CollectionReportingContext *crc = cls;

  crc->task = GNUNET_SCHEDULER_NO_TASK;
}

/**
 * Iterator for defined sensors
 * Watches sensors for readings to report
 *
 * @param cls unused
 * @param key unused
 * @param value a 'struct SensorInfo *' with sensor information
 * @return #GNUNET_YES to continue iterations
 */
static int
init_sensor_reporting (void *cls,
    const struct GNUNET_HashCode *key,
    void *value)
{
  struct SensorInfo *sensor = value;
  struct CollectionReportingContext *crc;

  if (NULL != sensor->collection_point)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
        "Will start reporting sensor `%s' values to collection point `%s' every %s.\n",
        sensor->name, GNUNET_i2s_full(sensor->collection_point),
        GNUNET_STRINGS_relative_time_to_string(sensor->collection_interval, GNUNET_YES));
    crc = GNUNET_new (struct CollectionReportingContext);
    crc->sensor = sensor;
    crc->task =
        GNUNET_SCHEDULER_add_delayed (sensor->collection_interval,
            &report_collection_point,
            crc);
  }
  if (GNUNET_YES == sensor->p2p_report)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
        "Will start reporting sensor `%s' values to p2p network every %s.\n",
        sensor->name,
        GNUNET_STRINGS_relative_time_to_string(sensor->p2p_interval, GNUNET_YES));
  }
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
static void cadet_channel_destroyed (void *cls,
    const struct GNUNET_CADET_Channel *channel,
    void *channel_ctx)
{

}

/**
 * Start the sensor reporting module
 *
 * @param c our service configuration
 * @param sensors multihashmap of loaded sensors
 * @return #GNUNET_OK if started successfully, #GNUNET_SYSERR otherwise
 */
int
SENSOR_reporting_start (const struct GNUNET_CONFIGURATION_Handle *c,
    struct GNUNET_CONTAINER_MultiHashMap *sensors)
{
  static struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
      {NULL, 0, 0}
  };

  GNUNET_assert(NULL != sensors);
  cfg = c;
  GNUNET_CRYPTO_get_peer_identity(cfg, &peerid);
  GNUNET_CONTAINER_multihashmap_iterate(sensors, &init_sensor_reporting, NULL);
  peerstore = GNUNET_PEERSTORE_connect(cfg);
  if (NULL == peerstore)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        _("Failed to connect to peerstore service.\n"));
    SENSOR_reporting_stop ();
    return GNUNET_SYSERR;
  }
  cadet = GNUNET_CADET_connect(cfg,
      NULL,
      NULL,
      &cadet_channel_destroyed,
      cadet_handlers,
      NULL);
  if (NULL == cadet)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        _("Failed to connect to CADET service.\n"));
    SENSOR_reporting_stop ();
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}

/* end of gnunet-service-sensor-reporting.c */
