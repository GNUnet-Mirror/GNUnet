/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file namestore/namestore_api_monitor.c
 * @brief API to monitor changes in the NAMESTORE
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_constants.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_signatures.h"
#include "gnunet_namestore_service.h"
#include "namestore.h"


/**
 * Handle for a monitoring activity.
 */
struct GNUNET_NAMESTORE_ZoneMonitor
{
  /**
   * Configuration (to reconnect).
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Handle to namestore service.
   */
  struct GNUNET_CLIENT_Connection *h;

  /**
   * Function to call on events.
   */
  GNUNET_NAMESTORE_RecordMonitor monitor;

  /**
   * Closure for 'monitor'.
   */
  void *monitor_cls;

  /**
   * Transmission handle to client.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Monitored zone.
   */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /**
   * GNUNET_YES if we monitor all zones, GNUNET_NO if we only monitor 'zone'.
   */
  int all_zones;
};


/**
 * Send our request to start monitoring to the service.
 *
 * @param cls the monitor handle
 * @param size number of bytes available in buf
 * @param buf where to copy the message to the service
 * @return number of bytes copied to buf
 */
static size_t
transmit_monitor_message (void *cls,
			  size_t size,
			  void *buf);


/**
 * Reconnect to the namestore service.
 *
 * @param zm monitor to reconnect
 */
static void
reconnect (struct GNUNET_NAMESTORE_ZoneMonitor *zm)
{
  if (NULL != zm->h)
    GNUNET_CLIENT_disconnect (zm->h);
  zm->monitor (zm->monitor_cls,
	       NULL,
	       GNUNET_TIME_UNIT_ZERO_ABS,
	       NULL, 0, NULL, NULL);
  GNUNET_assert (NULL != (zm->h = GNUNET_CLIENT_connect ("namestore", zm->cfg)));
  zm->th = GNUNET_CLIENT_notify_transmit_ready (zm->h,
						sizeof (struct ZoneMonitorStartMessage),
						GNUNET_TIME_UNIT_FOREVER_REL,
						GNUNET_YES,
						&transmit_monitor_message,
						zm);
}


/**
 * We've received a notification about a change to our zone.
 * Forward to monitor callback.
 *
 * @param cls the zone monitor handle
 * @param msg the message from the service.
 */
static void
handle_updates (void *cls,
		const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_NAMESTORE_ZoneMonitor *zm = cls;

  if (NULL == msg)
  {
    reconnect (zm);
    return;
  }
  // FIXME: parse, validate

  GNUNET_CLIENT_receive (zm->h,
			 &handle_updates,
			 zm,
			 GNUNET_TIME_UNIT_FOREVER_REL);
  // FIXME: call 'monitor'.
  // zm->monitor (zm->monitor_cls, ...);
}


/**
 * Send our request to start monitoring to the service.
 *
 * @param cls the monitor handle
 * @param size number of bytes available in buf
 * @param buf where to copy the message to the service
 * @return number of bytes copied to buf
 */
static size_t
transmit_monitor_message (void *cls,
			  size_t size,
			  void *buf)
{
  struct GNUNET_NAMESTORE_ZoneMonitor *zm = cls;
  struct ZoneMonitorStartMessage sm;

  if (size < sizeof (struct ZoneMonitorStartMessage))
  {    
    reconnect (zm);
    return 0;
  }
 
  sm.zone = zm->zone;
  sm.all_zones = htonl (zm->all_zones);
  memcpy (buf, &sm, sizeof (sm));
  GNUNET_CLIENT_receive (zm->h,
			 &handle_updates,
			 zm,
			 GNUNET_TIME_UNIT_FOREVER_REL);
  return sizeof (sm);
}


/**
 * Begin monitoring a zone for changes.  Will first call the 'monitor' function
 * on all existing records in the selected zone(s) and then call it whenever
 * a record changes.
 *
 * @param cfg configuration to use to connect to namestore
 * @param zone zone to monitor, NULL for all zones
 * @param monitor function to call on zone changes
 * @param monitor_cls closure for 'monitor'
 * @return handle to stop monitoring
 */
struct GNUNET_NAMESTORE_ZoneMonitor *
GNUNET_NAMESTORE_zone_monitor_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
				     const struct GNUNET_CRYPTO_ShortHashCode *zone,
				     GNUNET_NAMESTORE_RecordMonitor monitor,
				     void *monitor_cls)
{
  struct GNUNET_NAMESTORE_ZoneMonitor *zm;
  struct GNUNET_CLIENT_Connection *client;

  if (NULL == (client = GNUNET_CLIENT_connect ("namestore", cfg)))
    return NULL; 
  zm = GNUNET_new (struct GNUNET_NAMESTORE_ZoneMonitor);
  zm->cfg = cfg;
  zm->h = client;
  if (NULL == zone)
    zm->all_zones = GNUNET_YES;
  else
    zm->zone = *zone;
  zm->monitor = monitor;
  zm->monitor_cls = monitor_cls;
  zm->th = GNUNET_CLIENT_notify_transmit_ready (zm->h,
						sizeof (struct ZoneMonitorStartMessage),
						GNUNET_TIME_UNIT_FOREVER_REL,
						GNUNET_YES,
						&transmit_monitor_message,
						zm);
  return zm;
}


/**
 * Stop monitoring a zone for changes.
 *
 * @param zm handle to the monitor activity to stop
 */
void
GNUNET_NAMESTORE_zone_monitor_stop (struct GNUNET_NAMESTORE_ZoneMonitor *zm)
{
  if (NULL != zm->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (zm->th);
    zm->th = NULL;
  }
  GNUNET_CLIENT_disconnect (zm->h);
  GNUNET_free (zm);
}

/* end of namestore_api_monitor.c */
