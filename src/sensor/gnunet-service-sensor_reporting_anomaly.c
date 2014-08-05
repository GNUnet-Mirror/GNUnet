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

struct AnomalyReportingContext
{

  /**
   * DLL
   */
  struct AnomalyReportingContext *prev;

  /**
   * DLL
   */
  struct AnomalyReportingContext *next;

  /**
   * Sensor information
   */
  struct GNUNET_SENSOR_SensorInfo *sensor;

};

/**
 * Context of a connection to a peer through CORE
 */
struct CorePeerContext
{

  /**
   * DLL
   */
  struct CorePeerContext *prev;

  /**
   * DLL
   */
  struct CorePeerContext *next;

  /**
   * Peer identity of connected peer
   */
  struct GNUNET_PeerIdentity *peerid;

};


/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to core service
 */
static struct GNUNET_CORE_Handle *core;

/**
 * My peer id
 */
static struct GNUNET_PeerIdentity mypeerid;

/**
 * Head of DLL of anomaly reporting contexts
 */
static struct AnomalyReportingContext *arc_head;

/**
 * Tail of DLL of anomaly reporting contexts
 */
static struct AnomalyReportingContext *arc_tail;

/**
 * Head of DLL of CORE peer contexts
 */
static struct CorePeerContext *cp_head;

/**
 * Tail of DLL of CORE peer contexts
 */
static struct CorePeerContext *cp_tail;


/**
 * Destroy anomaly reporting context struct
 *
 * @param arc struct to destroy
 */
static void
destroy_anomaly_reporting_context (struct AnomalyReportingContext *arc)
{
  GNUNET_free (arc);
}


/**
 * Stop sensor anomaly reporting module
 */
void
SENSOR_reporting_anomaly_stop ()
{
  struct AnomalyReportingContext *arc;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Stopping sensor anomaly reporting module.\n");
  //TODO: destroy core peer contexts
  //TODO: destroy core connection
  arc = arc_head;
  while (NULL != arc)
  {
    GNUNET_CONTAINER_DLL_remove (arc_head, arc_tail, arc);
    destroy_anomaly_reporting_context (arc);
    arc = arc_head;
  }
}


/**
 * Iterator for defined sensors
 * Watches sensors for anomaly status change to report
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
  struct AnomalyReportingContext *arc;

  if (NULL == sensor->collection_point)
    return GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Reporting sensor `%s' anomalies to collection point `%s'.\n",
       sensor->name, GNUNET_i2s_full (sensor->collection_point));
  arc = GNUNET_new (struct AnomalyReportingContext);
  arc->sensor = sensor;
  GNUNET_CONTAINER_DLL_insert (arc_head, arc_tail, arc);
  //TODO
  return GNUNET_YES;
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
         _("Peer identity received from CORE doesn't match ours.\n"));
    SENSOR_reporting_anomaly_stop ();
    return;
  }
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
  struct CorePeerContext *cp;

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&mypeerid, peer))
    return;
  cp = GNUNET_new (struct CorePeerContext);
  cp->peerid = (struct GNUNET_PeerIdentity *)peer;
  GNUNET_CONTAINER_DLL_insert (cp_head, cp_tail, cp);
  //TODO: report to peer your anomaly status
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
  struct CorePeerContext *cp;

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&mypeerid, peer))
    return;
  cp = cp_head;
  while (NULL != cp)
  {
    if (peer == cp->peerid)
    {
      GNUNET_CONTAINER_DLL_remove (cp_head, cp_tail, cp);
      //TODO: call peer context destroy function
      return;
    }
  }
  LOG (GNUNET_ERROR_TYPE_ERROR,
       _("Received disconnect notification from CORE"
         " for a peer we didn't know about.\n"));
}


/**
 * An inbound message is received from a peer through CORE.
 *
 * @param cls closure (unused)
 * @param peer the other peer involved
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close connection to the peer (signal serious error)
 */
static int
core_inbound_cb (void *cls,
    const struct GNUNET_PeerIdentity *other,
    const struct GNUNET_MessageHeader *message)
{
  //TODO
  return GNUNET_OK;
}


/**
 * Start the sensor anomaly reporting module
 *
 * @param c our service configuration
 * @param sensors multihashmap of loaded sensors
 * @return #GNUNET_OK if started successfully, #GNUNET_SYSERR otherwise
 */
int
SENSOR_reporting_anomaly_start (const struct GNUNET_CONFIGURATION_Handle *c,
                                struct GNUNET_CONTAINER_MultiHashMap *sensors)
{
  static struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {NULL, 0, 0}                //TODO
  };

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Starting sensor anomaly reporting module.\n");
  GNUNET_assert (NULL != sensors);
  cfg = c;
  core =
      GNUNET_CORE_connect (cfg, NULL, &core_startup_cb, core_connect_cb,
                           &core_disconnect_cb, core_inbound_cb, GNUNET_NO,
                           NULL, GNUNET_YES, core_handlers);
  GNUNET_CRYPTO_get_peer_identity (cfg, &mypeerid);
  GNUNET_CONTAINER_multihashmap_iterate (sensors, &init_sensor_reporting, NULL);
  return GNUNET_OK;
}

/* end of gnunet-service-sensor_reporting_anomaly.c */
