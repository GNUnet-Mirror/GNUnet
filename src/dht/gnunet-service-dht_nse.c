/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file dht/gnunet-service-dht_nse.c
 * @brief GNUnet DHT integration with NSE
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_nse_service.h"
#include "gnunet-service-dht.h"
#include "gnunet-service-dht_nse.h"

/**
 * log of the current network size estimate, used as the point where
 * we switch between random and deterministic routing.  Default
 * value of 4.0 is used if NSE module is not available (i.e. not
 * configured).
 */
static double log_of_network_size_estimate = 4.0;

/**
 * Network size estimation handle.
 */
static struct GNUNET_NSE_Handle *nse;


/**
 * Callback that is called when network size estimate is updated.
 *
 * @param cls closure
 * @param timestamp time when the estimate was received from the server (or created by the server)
 * @param logestimate the log(Base 2) value of the current network size estimate
 * @param std_dev standard deviation for the estimate
 *
 */
static void
update_network_size_estimate (void *cls, struct GNUNET_TIME_Absolute timestamp,
                              double logestimate, double std_dev)
{
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# Network size estimates received"),
                            1, GNUNET_NO);
  /* do not allow estimates < 0.5 */
  log_of_network_size_estimate = GNUNET_MAX (0.5, logestimate);
}


/**
 * Return the log of the current network size estimate.
 *
 * @return log of NSE
 */
double
GDS_NSE_get ()
{
  return log_of_network_size_estimate;
}


/**
 * Initialize NSE subsystem.
 */
void
GDS_NSE_init ()
{
  nse = GNUNET_NSE_connect (GDS_cfg, &update_network_size_estimate, NULL);
}


/**
 * Shutdown NSE subsystem.
 */
void
GDS_NSE_done ()
{
  if (NULL != nse)
  {
    GNUNET_NSE_disconnect (nse);
    nse = NULL;
  }
}

/* end of gnunet-service-dht_nse.c */
