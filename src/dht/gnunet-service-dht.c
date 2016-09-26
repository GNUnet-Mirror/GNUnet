/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2016 GNUnet e.V.

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
 * @file dht/gnunet-service-dht.c
 * @brief GNUnet DHT service
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_block_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_hello_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-dht.h"
#include "gnunet-service-dht_datacache.h"
#include "gnunet-service-dht_hello.h"
#include "gnunet-service-dht_neighbours.h"
#include "gnunet-service-dht_nse.h"
#include "gnunet-service-dht_routing.h"

/**
 * Our HELLO
 */
struct GNUNET_MessageHeader *GDS_my_hello;

/**
 * Handle to get our current HELLO.
 */
static struct GNUNET_TRANSPORT_HelloGetHandle *ghh;

/**
 * Hello address expiration
 */
struct GNUNET_TIME_Relative hello_expiration;


/* Code shared between different DHT implementations */
#include "gnunet-service-dht_clients.c"


/**
 * Receive the HELLO from transport service, free current and replace
 * if necessary.
 *
 * @param cls NULL
 * @param message HELLO message of peer
 */
static void
process_hello (void *cls,
	       const struct GNUNET_MessageHeader *message)
{
  GNUNET_free_non_null (GDS_my_hello);
  GDS_my_hello = GNUNET_malloc (ntohs (message->size));
  GNUNET_memcpy (GDS_my_hello,
                 message,
                 ntohs (message->size));
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  if (NULL != ghh)
  {
    GNUNET_TRANSPORT_hello_get_cancel (ghh);
    ghh = NULL;
  }
  GDS_NEIGHBOURS_done ();
  GDS_DATACACHE_done ();
  GDS_ROUTING_done ();
  GDS_HELLO_done ();
  GDS_NSE_done ();
  if (NULL != GDS_block_context)
  {
    GNUNET_BLOCK_context_destroy (GDS_block_context);
    GDS_block_context = NULL;
  }
  if (NULL != GDS_stats)
  {
    GNUNET_STATISTICS_destroy (GDS_stats,
			       GNUNET_YES);
    GDS_stats = NULL;
  }
  GNUNET_free_non_null (GDS_my_hello);
  GDS_my_hello = NULL;
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
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c,
					   "transport",
					   "HELLO_EXPIRATION",
					   &hello_expiration))
  {
    hello_expiration = GNUNET_CONSTANTS_HELLO_ADDRESS_EXPIRATION;
  }
  GDS_block_context = GNUNET_BLOCK_context_create (GDS_cfg);
  GDS_stats = GNUNET_STATISTICS_create ("dht",
                                        GDS_cfg);
  GNUNET_SERVICE_suspend (GDS_service);
  GDS_CLIENTS_init ();
  GDS_ROUTING_init ();
  GDS_NSE_init ();
  GDS_DATACACHE_init ();
  GDS_HELLO_init ();
  if (GNUNET_OK != GDS_NEIGHBOURS_init ())
  {
    shutdown_task (NULL);
    return;
  }
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 NULL);
  ghh = GNUNET_TRANSPORT_hello_get (GDS_cfg,
				    GNUNET_TRANSPORT_AC_GLOBAL,
                                    &process_hello,
                                    NULL);
}


/* Finally, define the main method */
GDS_DHT_SERVICE_INIT("dht", &run);




/* end of gnunet-service-dht.c */
