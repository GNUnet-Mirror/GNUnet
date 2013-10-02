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


#include "platform.h"
#include "gnunet_util_lib.h"

#include "gnunet_dht_service.h"

#include "gnunet-service-mesh_dht.h"
#include "gnunet-service-mesh_peer.h"

#define MESH_DEBUG_DHT          GNUNET_NO

#if MESH_DEBUG_DHT
#define DEBUG_DHT(...) GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)
#else
#define DEBUG_DHT(...)
#endif

/******************************************************************************/
/********************************   STRUCTS  **********************************/
/******************************************************************************/




/******************************************************************************/
/*******************************   GLOBALS  ***********************************/
/******************************************************************************/

/**
 * Handle to use DHT.
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * How often to PUT own ID in the DHT.
 */
static struct GNUNET_TIME_Relative id_announce_time;

/**
 * DHT replication level, see DHT API: GNUNET_DHT_get_start, GNUNET_DHT_put.
 */
static unsigned long long dht_replication_level;

/**
 * Task to periodically announce itself in the network.
 */
static GNUNET_SCHEDULER_TaskIdentifier announce_id_task;

/**
 * Own ID (full value).
 */
static struct GNUNET_PeerIdentity *id;

/**
 * Own private key.
 */
static struct GNUNET_CRYPTO_EccPrivateKey *private_key;


/******************************************************************************/
/********************************   STATIC  ***********************************/
/******************************************************************************/


/**
 * Periodically announce self id in the DHT
 *
 * @param cls closure
 * @param tc task context
 */
static void
announce_id (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PBlock block;
  struct GNUNET_HashCode phash;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    announce_id_task = GNUNET_SCHEDULER_NO_TASK;
    return;
  }
  /* TODO
   * - Set data expiration in function of X
   * - Adapt X to churn
   */
  DEBUG_DHT ("DHT_put for ID %s started.\n", GNUNET_i2s (&my_full_id));

  block.id = my_full_id;
  GNUNET_CRYPTO_hash (&my_full_id, sizeof (struct GNUNET_PeerIdentity), &phash);
  GNUNET_DHT_put (dht_handle,   /* DHT handle */
                  &phash,       /* Key to use */
                  dht_replication_level,     /* Replication level */
                  GNUNET_DHT_RO_RECORD_ROUTE | GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,    /* DHT options */
                  GNUNET_BLOCK_TYPE_MESH_PEER,       /* Block type */
                  sizeof (block),  /* Size of the data */
                  (const char *) &block, /* Data itself */
                  GNUNET_TIME_UNIT_FOREVER_ABS,  /* Data expiration */
                  GNUNET_TIME_UNIT_FOREVER_REL, /* Retry time */
                  NULL,         /* Continuation */
                  NULL);        /* Continuation closure */
  announce_id_task =
      GNUNET_SCHEDULER_add_delayed (id_announce_time, &announce_id, cls);
}


/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Initialize the DHT subsystem.
 *
 * @param c Configuration.
 */
void
GMD_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "DHT_REPLICATION_LEVEL",
                                             &dht_replication_level))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_WARNING,
                               "MESH", "DHT_REPLICATION_LEVEL", "USING DEFAULT");
    dht_replication_level = 3;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c, "MESH", "ID_ANNOUNCE_TIME",
                                           &id_announce_time))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "MESH", "ID_ANNOUNCE_TIME", "MISSING");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  dht_handle = GNUNET_DHT_connect (c, 64);
  if (NULL == dht_handle)
  {
    GNUNET_break (0);
  }

  announce_id_task = GNUNET_SCHEDULER_add_now (&announce_id, cls);
}


/**
 * Shut down the DHT subsystem.
 */
void
GMD_shutdown(void )
{
  if (dht_handle != NULL)
  {
    GNUNET_DHT_disconnect (dht_handle);
    dht_handle = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != announce_id_task)
  {
    GNUNET_SCHEDULER_cancel (announce_id_task);
    announce_id_task = GNUNET_SCHEDULER_NO_TASK;
  }
}
