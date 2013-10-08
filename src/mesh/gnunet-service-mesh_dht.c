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

#include "mesh_path.h"
#include "gnunet-service-mesh_dht.h"
#include "gnunet-service-mesh_peer.h"

#define MESH_DEBUG_DHT          GNUNET_NO

#if MESH_DEBUG_DHT
#define DEBUG_DHT(...) GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)
#else
#define DEBUG_DHT(...)
#endif

#define LOG (level, ...) GNUNET_log_from ("mesh-dht", level, __VA_ARGS__)


/******************************************************************************/
/********************************   STRUCTS  **********************************/
/******************************************************************************/

/**
 * Handle for DHT searches.
 */
struct GMD_search_handle
{
  /** DHT_GET handle. */
  struct GNUNET_DHT_GetHandle *dhtget;

  /** Provided callback to call when a path is found. */
  GMD_search_callback callback;

  /** Provided closure. */
  void *cls;
};


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
 * Own ID (short value).
 */
static GNUNET_PEER_Id short_id;

/**
 * Own ID (full value).
 */
static struct GNUNET_PeerIdentity *full_id;

/**
 * Own private key.
 */
static struct GNUNET_CRYPTO_EccPrivateKey *private_key;


/******************************************************************************/
/********************************   STATIC  ***********************************/
/******************************************************************************/


/**
 * Build a PeerPath from the paths returned from the DHT, reversing the paths
 * to obtain a local peer -> destination path and interning the peer ids.
 *
 * @return Newly allocated and created path
 */
static struct MeshPeerPath *
path_build_from_dht (const struct GNUNET_PeerIdentity *get_path,
                     unsigned int get_path_length,
                     const struct GNUNET_PeerIdentity *put_path,
                     unsigned int put_path_length)
{
  struct MeshPeerPath *p;
  GNUNET_PEER_Id id;
  int i;

  p = path_new (1);
  p->peers[0] = myid;
  GNUNET_PEER_change_rc (myid, 1);
  i = get_path_length;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   GET has %d hops.\n", i);
  for (i--; i >= 0; i--)
  {
    id = GNUNET_PEER_intern (&get_path[i]);
    if (p->length > 0 && id == p->peers[p->length - 1])
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   Optimizing 1 hop out.\n");
      GNUNET_PEER_change_rc (id, -1);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   Adding from GET: %s.\n",
                  GNUNET_i2s (&get_path[i]));
      p->length++;
      p->peers = GNUNET_realloc (p->peers, sizeof (GNUNET_PEER_Id) * p->length);
      p->peers[p->length - 1] = id;
    }
  }
  i = put_path_length;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   PUT has %d hops.\n", i);
  for (i--; i >= 0; i--)
  {
    id = GNUNET_PEER_intern (&put_path[i]);
    if (id == myid)
    {
      /* PUT path went through us, so discard the path up until now and start
       * from here to get a much shorter (and loop-free) path.
       */
      path_destroy (p);
      p = path_new (0);
    }
    if (p->length > 0 && id == p->peers[p->length - 1])
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   Optimizing 1 hop out.\n");
      GNUNET_PEER_change_rc (id, -1);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   Adding from PUT: %s.\n",
                  GNUNET_i2s (&put_path[i]));
      p->length++;
      p->peers = GNUNET_realloc (p->peers, sizeof (GNUNET_PEER_Id) * p->length);
      p->peers[p->length - 1] = id;
    }
  }
#if MESH_DEBUG
  if (get_path_length > 0)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   (first of GET: %s)\n",
                GNUNET_i2s (&get_path[0]));
  if (put_path_length > 0)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   (first of PUT: %s)\n",
                GNUNET_i2s (&put_path[0]));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   In total: %d hops\n",
              p->length);
  for (i = 0; i < p->length; i++)
  {
    struct GNUNET_PeerIdentity peer_id;

    GNUNET_PEER_resolve (p->peers[i], &peer_id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "       %u: %s\n", p->peers[i],
                GNUNET_i2s (&peer_id));
  }
#endif
  return p;
}


/**
 * Function to process paths received for a new peer addition. The recorded
 * paths form the initial tunnel, which can be optimized later.
 * Called on each result obtained for the DHT search.
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path path of the get request
 * @param get_path_length lenght of get_path
 * @param put_path path of the put request
 * @param put_path_length length of the put_path
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
static void
dht_get_id_handler (void *cls, struct GNUNET_TIME_Absolute exp,
                    const struct GNUNET_HashCode * key,
                    const struct GNUNET_PeerIdentity *get_path,
                    unsigned int get_path_length,
                    const struct GNUNET_PeerIdentity *put_path,
                    unsigned int put_path_length, enum GNUNET_BLOCK_Type type,
                    size_t size, const void *data)
{
  struct GMD_search_handle *h = cls;
  struct MeshPeerPath *p;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Got results!\n");
  p = path_build_from_dht (get_path, get_path_length,
                           put_path, put_path_length);
  h->callback (h->cls, p);
  path_destroy (p);
  return;
}


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
  DEBUG_DHT ("DHT_put for ID %s started.\n", GNUNET_i2s (id));

  block.id = *full_id;
  GNUNET_CRYPTO_hash (full_id, sizeof (struct GNUNET_PeerIdentity), &phash);
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
 * @param peer_id Local peer ID (must remain valid during all execution time).
 */
void
GMD_init (const struct GNUNET_CONFIGURATION_Handle *c,
          struct GNUNET_PeerIdentity *peer_id)
{
  full_id = peer_id;
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

  announce_id_task = GNUNET_SCHEDULER_add_now (&announce_id, NULL);
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

struct GMD_search_handle *
GMD_search (const struct GNUNET_PeerIdentity *peer_id,
            GMD_search_callback callback, void *cls)
{
  struct GNUNET_HashCode phash;
  struct GMD_search_handle *h;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "  Starting DHT GET for peer %s\n", GNUNET_i2s (peer_id));
  GNUNET_CRYPTO_hash (peer_id, sizeof (struct GNUNET_PeerIdentity), &phash);
  h = GNUNET_new (struct GMD_search_handle);
  h->cls = cls;
  h->dhtget = GNUNET_DHT_get_start (dht_handle,    /* handle */
                                    GNUNET_BLOCK_TYPE_MESH_PEER, /* type */
                                    &phash,     /* key to search */
                                    dht_replication_level, /* replication level */
                                    GNUNET_DHT_RO_RECORD_ROUTE |
                                    GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                                    NULL,       /* xquery */
                                    0,     /* xquery bits */
                                    &dht_get_id_handler, h);
  return h;
}

void
GMD_search_stop (struct GMD_search_handle *h)
{
  GNUNET_DHT_get_stop (h->dhtget);
  GNUNET_free (h);
}