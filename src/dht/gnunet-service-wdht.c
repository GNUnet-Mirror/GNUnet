/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011 GNUnet e.V.

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
 * @file dht/gnunet-service-wdht.c
 * @brief GNUnet DHT service
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_block_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-wdht.h"
#include "gnunet-service-dht_datacache.h"
#include "gnunet-service-dht_neighbours.h"
#include "gnunet-service-dht_nse.h"


/* Code shared between different DHT implementations */
#include "gnunet-service-dht_clients.c"


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  GDS_NEIGHBOURS_done ();
  GDS_DATACACHE_done ();
  GDS_NSE_done ();
  if (NULL != GDS_block_context)
  {
    GNUNET_BLOCK_context_destroy (GDS_block_context);
    GDS_block_context = NULL;
  }
  if (NULL != GDS_stats)
  {
    GNUNET_STATISTICS_destroy (GDS_stats, GNUNET_YES);
    GDS_stats = NULL;
  }
  GDS_CLIENTS_stop ();
}


/**
 * Process dht requests.
 *
 * @param cls closure
 * @param c configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  GDS_cfg = c;
  GDS_service = service;
  GDS_block_context = GNUNET_BLOCK_context_create (GDS_cfg);
  GDS_stats = GNUNET_STATISTICS_create ("dht",
                                        GDS_cfg);
  GDS_NSE_init ();
  GDS_DATACACHE_init ();
  GDS_CLIENTS_init ();
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 NULL);
  if (GNUNET_OK != GDS_NEIGHBOURS_init ())
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/* Finally, define the main method */
GDS_DHT_SERVICE_INIT("wdht", &run);


/* end of gnunet-service-wdht.c */
