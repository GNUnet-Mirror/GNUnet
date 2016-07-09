/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2016 GNUnet e.V.

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
  struct GNUNET_MQ_Handle *mq;

  /**
   * Function to call on errors.
   */
  GNUNET_SCHEDULER_TaskCallback error_cb;

  /**
   * Closure for @e error_cb.
   */
  void *error_cb_cls;

  /**
   * Function to call on events.
   */
  GNUNET_NAMESTORE_RecordMonitor monitor;

  /**
   * Closure for @e monitor.
   */
  void *monitor_cls;

  /**
   * Function called when we've synchronized.
   */
  GNUNET_SCHEDULER_TaskCallback sync_cb;

  /**
   * Closure for @e sync_cb.
   */
  void *sync_cb_cls;

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
 * Reconnect to the namestore service.
 *
 * @param zm monitor to reconnect
 */
static void
reconnect (struct GNUNET_NAMESTORE_ZoneMonitor *zm);


/**
 * Handle SYNC message from the namestore service.
 *
 * @param cls the monitor
 * @param msg the sync message
 */
static void
handle_sync (void *cls,
             const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_NAMESTORE_ZoneMonitor *zm = cls;

  if (NULL != zm->sync_cb)
    zm->sync_cb (zm->sync_cb_cls);
}


/**
 * We've received a notification about a change to our zone.
 * Check that it is well-formed.
 *
 * @param cls the zone monitor handle
 * @param lrm the message from the service.
 */
static int
check_result (void *cls,
              const struct RecordResultMessage *lrm)
{
  size_t lrm_len;
  size_t exp_lrm_len;
  size_t name_len;
  size_t rd_len;
  unsigned rd_count;
  const char *name_tmp;
  const char *rd_ser_tmp;

  lrm_len = ntohs (lrm->gns_header.header.size);
  rd_len = ntohs (lrm->rd_len);
  rd_count = ntohs (lrm->rd_count);
  name_len = ntohs (lrm->name_len);
  exp_lrm_len = sizeof (struct RecordResultMessage) + name_len + rd_len;
  if (lrm_len != exp_lrm_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (0 == name_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  name_tmp = (const char *) &lrm[1];
  if ((name_tmp[name_len -1] != '\0') || (name_len > MAX_NAME_LEN))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  rd_ser_tmp = (const char *) &name_tmp[name_len];
  {
    struct GNUNET_GNSRECORD_Data rd[rd_count];

    if (GNUNET_OK !=
        GNUNET_GNSRECORD_records_deserialize (rd_len,
                                              rd_ser_tmp,
                                              rd_count,
                                              rd))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  }
  return GNUNET_OK;
}


/**
 * We've received a notification about a change to our zone.
 * Forward to monitor callback.
 *
 * @param cls the zone monitor handle
 * @param lrm the message from the service.
 */
static void
handle_result (void *cls,
               const struct RecordResultMessage *lrm)
{
  struct GNUNET_NAMESTORE_ZoneMonitor *zm = cls;
  size_t name_len;
  size_t rd_len;
  unsigned rd_count;
  const char *name_tmp;
  const char *rd_ser_tmp;

  rd_len = ntohs (lrm->rd_len);
  rd_count = ntohs (lrm->rd_count);
  name_len = ntohs (lrm->name_len);
  name_tmp = (const char *) &lrm[1];
  rd_ser_tmp = (const char *) &name_tmp[name_len];
  {
    struct GNUNET_GNSRECORD_Data rd[rd_count];

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_GNSRECORD_records_deserialize (rd_len,
                                                         rd_ser_tmp,
                                                         rd_count,
                                                         rd));
    zm->monitor (zm->monitor_cls,
		 &lrm->private_key,
		 name_tmp,
		 rd_count,
                 rd);
  }
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_NAMESTORE_ZoneMonitor *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_NAMESTORE_ZoneMonitor *zm = cls;

  reconnect (zm);
}


/**
 * Reconnect to the namestore service.
 *
 * @param zm monitor to reconnect
 */
static void
reconnect (struct GNUNET_NAMESTORE_ZoneMonitor *zm)
{
  GNUNET_MQ_hd_fixed_size (sync,
                           GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_SYNC,
                           struct GNUNET_MessageHeader);
  GNUNET_MQ_hd_var_size (result,
                         GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT,
                         struct RecordResultMessage);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    make_sync_handler (zm),
    make_result_handler (zm),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct ZoneMonitorStartMessage *sm;

  if (NULL != zm->mq)
  {
    GNUNET_MQ_destroy (zm->mq);
    zm->error_cb (zm->error_cb_cls);
  }
  zm->mq = GNUNET_CLIENT_connecT (zm->cfg,
                                  "namestore",
                                  handlers,
                                  &mq_error_handler,
                                  zm);
  if (NULL == zm->mq)
    return;
  env = GNUNET_MQ_msg (sm,
                       GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_START);
  sm->iterate_first = htonl (zm->iterate_first);
  sm->zone = zm->zone;
  GNUNET_MQ_send (zm->mq,
                  env);
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
 * @param error_cb function to call on error (i.e. disconnect); note that
 *         unlike the other error callbacks in this API, a call to this
 *         function does NOT destroy the monitor handle, it merely signals
 *         that monitoring is down. You need to still explicitly call
 *         #GNUNET_NAMESTORE_zone_monitor_stop().
 * @param error_cb_cls closure for @a error_cb
 * @param monitor function to call on zone changes
 * @param monitor_cls closure for @a monitor
 * @param sync_cb function called when we're in sync with the namestore
 * @param cls closure for @a sync_cb
 * @return handle to stop monitoring
 */
struct GNUNET_NAMESTORE_ZoneMonitor *
GNUNET_NAMESTORE_zone_monitor_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
				     const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                                     int iterate_first,
                                     GNUNET_SCHEDULER_TaskCallback error_cb,
                                     void *error_cb_cls,
				     GNUNET_NAMESTORE_RecordMonitor monitor,
                                     void *monitor_cls,
				     GNUNET_SCHEDULER_TaskCallback sync_cb,
				     void *sync_cb_cls)
{
  struct GNUNET_NAMESTORE_ZoneMonitor *zm;

  zm = GNUNET_new (struct GNUNET_NAMESTORE_ZoneMonitor);
  if (NULL != zone)
    zm->zone = *zone;
  zm->iterate_first = iterate_first;
  zm->error_cb = error_cb;
  zm->error_cb_cls = error_cb_cls;
  zm->monitor = monitor;
  zm->monitor_cls = monitor_cls;
  zm->sync_cb = sync_cb;
  zm->sync_cb_cls = sync_cb_cls;
  zm->cfg = cfg;
  reconnect (zm);
  if (NULL == zm->mq)
  {
    GNUNET_free (zm);
    return NULL;
  }
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
  if (NULL != zm->mq)
  {
    GNUNET_MQ_destroy (zm->mq);
    zm->mq = NULL;
  }
  GNUNET_free (zm);
}

/* end of namestore_api_monitor.c */
