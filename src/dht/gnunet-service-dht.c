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
 * @file dht/gnunet-service-dht.c
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
#include "gnunet-service-dht.h"
#include "gnunet-service-dht_clients.h"
#include "gnunet-service-dht_datacache.h"
#include "gnunet-service-dht_hello.h"
#include "gnunet-service-dht_neighbours.h"
#include "gnunet-service-dht_nse.h"
#include "gnunet-service-dht_routing.h"



/**
 * Handle for the statistics service.
 */
struct GNUNET_STATISTICS_Handle *GDS_stats;

/**
 * Our handle to the BLOCK library.
 */
struct GNUNET_BLOCK_Context *GDS_block_context;

/**
 * The configuration the DHT service is running with
 */
const struct GNUNET_CONFIGURATION_Handle *GDS_cfg;

/**
 * Our HELLO
 */
struct GNUNET_MessageHeader *GDS_my_hello;

/**
 * Handle to the transport service, for getting our hello
 */
struct GNUNET_TRANSPORT_Handle *GDS_transport_handle;


/**
 * Handle to get our current HELLO.
 */
static struct GNUNET_TRANSPORT_GetHelloHandle *ghh;


/**
 * Receive the HELLO from transport service, free current and replace
 * if necessary.
 *
 * @param cls NULL
 * @param message HELLO message of peer
 */
static void
process_hello (void *cls, const struct GNUNET_MessageHeader *message)
{
  GNUNET_assert (message != NULL);
  GNUNET_free_non_null (GDS_my_hello);
  GDS_my_hello = GNUNET_malloc (ntohs (message->size));
  memcpy (GDS_my_hello, message, ntohs (message->size));
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != ghh)
  {
    GNUNET_TRANSPORT_get_hello_cancel (ghh);
    ghh = NULL;
  }
  if (GDS_transport_handle != NULL)
  {
    GNUNET_TRANSPORT_disconnect (GDS_transport_handle);
    GDS_transport_handle = NULL;
  }
  GDS_NEIGHBOURS_done ();
  GDS_DATACACHE_done ();
  GDS_ROUTING_done ();
  GDS_HELLO_done ();
  GDS_NSE_done ();
  if (GDS_block_context != NULL)
  {
    GNUNET_BLOCK_context_destroy (GDS_block_context);
    GDS_block_context = NULL;
  }
  if (GDS_stats != NULL)
  {
    GNUNET_STATISTICS_destroy (GDS_stats, GNUNET_YES);
    GDS_stats = NULL;
  }
  GNUNET_free_non_null (GDS_my_hello);
  GDS_my_hello = NULL;
}


/**
 * Process dht requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  GDS_cfg = c;
  GDS_block_context = GNUNET_BLOCK_context_create (GDS_cfg);
  GDS_stats = GNUNET_STATISTICS_create ("dht", GDS_cfg);
  GDS_ROUTING_init ();
  GDS_NSE_init ();
  GDS_DATACACHE_init ();
  GDS_HELLO_init ();
  GDS_CLIENTS_init (server);
  if (GNUNET_OK != GDS_NEIGHBOURS_init ())
  {
    shutdown_task (NULL, NULL);
    return;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  GDS_transport_handle =
      GNUNET_TRANSPORT_connect (GDS_cfg, NULL, NULL, NULL, NULL, NULL);
  if (GDS_transport_handle == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to connect to transport service!\n"));
    return;
  }
  ghh = GNUNET_TRANSPORT_get_hello (GDS_transport_handle, &process_hello, NULL);
}


/**
 * The main function for the dht service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int ret;

  ret =
      (GNUNET_OK ==
       GNUNET_SERVICE_run (argc, argv, "dht", GNUNET_SERVICE_OPTION_NONE, &run,
                           NULL)) ? 0 : 1;
  GDS_CLIENTS_done ();
  return ret;
}

/* end of gnunet-service-dht.c */
