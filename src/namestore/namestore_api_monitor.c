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
};


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
  GNUNET_break (0);
  return NULL;
}


/**
 * Stop monitoring a zone for changes.
 *
 * @param zm handle to the monitor activity to stop
 */
void
GNUNET_NAMESTORE_zone_monitor_stop (struct GNUNET_NAMESTORE_ZoneMonitor *zm)
{
}

/* end of namestore_api_monitor.c */
