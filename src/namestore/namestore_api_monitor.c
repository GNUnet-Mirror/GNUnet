/*
     This file is part of GNUnet.
     Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
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
   * Function called when we've synchronized.
   */
  GNUNET_NAMESTORE_RecordsSynchronizedCallback sync_cb;

  /**
   * Closure for 'monitor' and 'sync_cb'.
   */
  void *cls;

  /**
   * Transmission handle to client.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Monitored zone.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey zone;

  /**
   * Do we first iterate over all existing records?
   */
  int iterate_first;

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
  zm->monitor (zm->cls,
	       NULL,
	       NULL, 0, NULL);
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
  const struct RecordResultMessage *lrm;
  size_t lrm_len;
  size_t exp_lrm_len;
  size_t name_len;
  size_t rd_len;
  unsigned rd_count;
  const char *name_tmp;
  const char *rd_ser_tmp;

  if (NULL == msg)
  {
    reconnect (zm);
    return;
  }
  if ( (ntohs (msg->size) == sizeof (struct GNUNET_MessageHeader)) &&
       (GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_SYNC == ntohs (msg->type) ) )
  {
    GNUNET_CLIENT_receive (zm->h,
			   &handle_updates,
			   zm,
			   GNUNET_TIME_UNIT_FOREVER_REL);
    if (NULL != zm->sync_cb)
      zm->sync_cb (zm->cls);
    return;
  }
  if ( (ntohs (msg->size) < sizeof (struct RecordResultMessage)) ||
       (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT != ntohs (msg->type) ) )
  {
    GNUNET_break (0);
    reconnect (zm);
    return;
  }
  lrm = (const struct RecordResultMessage *) msg;
  lrm_len = ntohs (lrm->gns_header.header.size);
  rd_len = ntohs (lrm->rd_len);
  rd_count = ntohs (lrm->rd_count);
  name_len = ntohs (lrm->name_len);
  exp_lrm_len = sizeof (struct RecordResultMessage) + name_len + rd_len;
  if (lrm_len != exp_lrm_len)
  {
    GNUNET_break (0);
    reconnect (zm);
    return;
  }
  if (0 == name_len)
  {
    GNUNET_break (0);
    reconnect (zm);
    return;
  }
  name_tmp = (const char *) &lrm[1];
  if ((name_tmp[name_len -1] != '\0') || (name_len > MAX_NAME_LEN))
  {
    GNUNET_break (0);
    reconnect (zm);
    return;
  }
  rd_ser_tmp = (const char *) &name_tmp[name_len];
  {
    struct GNUNET_GNSRECORD_Data rd[rd_count];

    if (GNUNET_OK != GNUNET_GNSRECORD_records_deserialize (rd_len, rd_ser_tmp, rd_count, rd))
    {
      GNUNET_break (0);
      reconnect (zm);
      return;
    }
    GNUNET_CLIENT_receive (zm->h,
			   &handle_updates,
			   zm,
			   GNUNET_TIME_UNIT_FOREVER_REL);
    zm->monitor (zm->cls,
		 &lrm->private_key,
		 name_tmp,
		 rd_count, rd);
  }
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

  zm->th = NULL;
  if (size < sizeof (struct ZoneMonitorStartMessage))
  {
    reconnect (zm);
    return 0;
  }
  sm.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_START);
  sm.header.size = htons (sizeof (struct ZoneMonitorStartMessage));
  sm.iterate_first = htonl (zm->iterate_first);
  sm.zone = zm->zone;
  memcpy (buf, &sm, sizeof (sm));
  GNUNET_CLIENT_receive (zm->h,
			 &handle_updates,
			 zm,
			 GNUNET_TIME_UNIT_FOREVER_REL);
  return sizeof (sm);
}


/**
 * Begin monitoring a zone for changes.  If @a iterate_first is set,
 * we Will first call the @a monitor function on all existing records
 * in the selected zone(s).  In any case, we will call @a sync and
 * afterwards call @a monitor whenever a record changes.
 *
 * @param cfg configuration to use to connect to namestore
 * @param zone zone to monitor
 * @param iterate_first #GNUNET_YES to first iterate over all existing records,
 *                      #GNUNET_NO to only return changes that happen from now on
 * @param monitor function to call on zone changes
 * @param sync_cb function called when we're in sync with the namestore
 * @param cls closure for @a monitor and @a sync_cb
 * @return handle to stop monitoring
 */
struct GNUNET_NAMESTORE_ZoneMonitor *
GNUNET_NAMESTORE_zone_monitor_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
				     const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                                     int iterate_first,
				     GNUNET_NAMESTORE_RecordMonitor monitor,
				     GNUNET_NAMESTORE_RecordsSynchronizedCallback sync_cb,
				     void *cls)
{
  struct GNUNET_NAMESTORE_ZoneMonitor *zm;
  struct GNUNET_CLIENT_Connection *client;

  if (NULL == (client = GNUNET_CLIENT_connect ("namestore", cfg)))
    return NULL;
  zm = GNUNET_new (struct GNUNET_NAMESTORE_ZoneMonitor);
  zm->cfg = cfg;
  zm->h = client;
  if (NULL != zone)
    zm->zone = *zone;
  zm->iterate_first = iterate_first;
  zm->monitor = monitor;
  zm->sync_cb = sync_cb;
  zm->cls = cls;
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
