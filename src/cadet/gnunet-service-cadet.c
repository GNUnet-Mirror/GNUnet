/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013 Christian Grothoff (and other contributing authors)

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
 * @file cadet/gnunet-service-cadet.c
 * @brief GNUnet CADET service with encryption
 * @author Bartlomiej Polot
 *
 *  FIXME in progress:
 * - rekey - reliability interaction
 * - channel retransmit timing
 *
 * TODO:
 * - relay corking down to core
 * - set ttl relative to path length
 * TODO END
 *
 * Dictionary:
 * - peer: other cadet instance. If there is direct connection it's a neighbor.
 * - tunnel: encrypted connection to a peer, neighbor or not.
 * - channel: connection between two clients, on the same or different peers.
 *            have properties like reliability.
 * - path: series of directly connected peer from one peer to another.
 * - connection: path which is being used in a tunnel.
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "cadet.h"
#include "gnunet_statistics_service.h"

#include "gnunet-service-cadet_local.h"
#include "gnunet-service-cadet_channel.h"
#include "gnunet-service-cadet_connection.h"
#include "gnunet-service-cadet_tunnel.h"
#include "gnunet-service-cadet_dht.h"
#include "gnunet-service-cadet_peer.h"
#include "gnunet-service-cadet_hello.h"


/******************************************************************************/
/***********************      GLOBAL VARIABLES     ****************************/
/******************************************************************************/

/****************************** Global variables ******************************/

/**
 * Handle to the statistics service.
 */
struct GNUNET_STATISTICS_Handle *stats;

/**
 * Local peer own ID (memory efficient handle).
 */
GNUNET_PEER_Id myid;

/**
 * Local peer own ID (full value).
 */
struct GNUNET_PeerIdentity my_full_id;


/**
 * Signal that shutdown is happening: prevent recover measures.
 */
int shutting_down;

/*************************** Static global variables **************************/

/**
 * Own private key.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;


/******************************************************************************/
/************************      MAIN FUNCTIONS      ****************************/
/******************************************************************************/

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shutting down\n");

  shutting_down = GNUNET_YES;

  GML_shutdown ();
  GCH_shutdown ();
  GCC_shutdown ();
  GCT_shutdown ();
  GCD_shutdown ();
  GCP_shutdown ();

  GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
  stats = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shut down\n");
}


/**
 * Process cadet requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "starting to run\n");

  stats = GNUNET_STATISTICS_create ("cadet", c);

  /* Scheduled the task to clean up when shutdown is called */
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "reading key\n");
  my_private_key = GNUNET_CRYPTO_eddsa_key_create_from_configuration (c);
  GNUNET_assert (NULL != my_private_key);
  GNUNET_CRYPTO_eddsa_key_get_public (my_private_key, &my_full_id.public_key);
  myid = GNUNET_PEER_intern (&my_full_id);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "STARTING SERVICE (cadet) for peer [%s]\n",
              GNUNET_i2s (&my_full_id));

  GML_init (server);    /* Local clients */
  GCH_init (c);         /* Hellos */
  GCC_init (c);         /* Connections */
  GCP_init (c);         /* Peers */
  GCD_init (c);         /* DHT */
  GCT_init (c, my_private_key); /* Tunnels */

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cadet service running\n");
}


/**
 * The main function for the cadet service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int r;

  shutting_down = GNUNET_NO;
  r = GNUNET_SERVICE_run (argc, argv, "cadet", GNUNET_SERVICE_OPTION_NONE, &run,
                          NULL);
  GNUNET_free (my_private_key);

  if (GNUNET_OK != r)
  {
    FPRINTF (stderr, "GNUNET_SERVICE_run for CADET has failed!\n");
    return 1;
  }

  return 0;
}
