/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet-new_dht.c
 * @brief Information we track per peer.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-cadet-new.h"
#include "gnunet-service-cadet-new_dht.h"
#include "gnunet-service-cadet-new_hello.h"
#include "gnunet-service-cadet-new_peer.h"
#include "gnunet-service-cadet-new_paths.h"

#define LOG(level, ...) GNUNET_log_from (level,"cadet-dht",__VA_ARGS__)


/**
 * Handle for DHT searches.
 */
struct GCD_search_handle
{
  /**
   * DHT_GET handle.
   */
  struct GNUNET_DHT_GetHandle *dhtget;

  /**
   * Provided callback to call when a path is found.
   */
  GCD_search_callback callback;

  /**
   * Provided closure.
   */
  void *cls;

};


/**
 * Handle to use DHT.
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * How often to PUT own ID in the DHT.
 */
static struct GNUNET_TIME_Relative id_announce_time;

/**
 * DHT replication level, see DHT API: #GNUNET_DHT_get_start(), #GNUNET_DHT_put().
 */
static unsigned long long dht_replication_level;

/**
 * Task to periodically announce itself in the network.
 */
static struct GNUNET_SCHEDULER_Task *announce_id_task;

/**
 * Delay for the next ID announce.
 */
static struct GNUNET_TIME_Relative announce_delay;



/**
 * Function to process paths received for a new peer addition. The recorded
 * paths form the initial tunnel, which can be optimized later.
 * Called on each result obtained for the DHT search.
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path path of the get request
 * @param get_path_length lenght of @a get_path
 * @param put_path path of the put request
 * @param put_path_length length of the @a put_path
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
static void
dht_get_id_handler (void *cls, struct GNUNET_TIME_Absolute exp,
                    const struct GNUNET_HashCode *key,
                    const struct GNUNET_PeerIdentity *get_path,
                    unsigned int get_path_length,
                    const struct GNUNET_PeerIdentity *put_path,
                    unsigned int put_path_length,
                    enum GNUNET_BLOCK_Type type,
                    size_t size,
                    const void *data)
{
  struct GCD_search_handle *h = cls;
  const struct GNUNET_HELLO_Message *hello = data;
  struct CadetPeerPath *p;
  struct CadetPeer *peer;

  p = GCPP_path_from_dht (get_path,
                          get_path_length,
                          put_path,
                          put_path_length);
  h->callback (h->cls,
               p);
  GCPP_path_destroy (p);

  if ( (size >= sizeof (struct GNUNET_HELLO_Message)) &&
       (ntohs (hello->header.size) == size) &&
       (size == GNUNET_HELLO_size (hello)) )
  {
    peer = GCP_get (&put_path[0],
                    GNUNET_YES);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Got HELLO for %s\n",
         GCP_2s (peer));
    GCP_set_hello (peer,
                   hello);
  }
}


/**
 * Periodically announce self id in the DHT
 *
 * @param cls closure
 */
static void
announce_id (void *cls)
{
  struct GNUNET_HashCode phash;
  const struct GNUNET_HELLO_Message *hello;
  size_t size;
  struct GNUNET_TIME_Absolute expiration;
  struct GNUNET_TIME_Relative next_put;

  hello = GCH_get_mine ();
  size = (NULL != hello) ? GNUNET_HELLO_size (hello) : 0;
  if (0 == size)
  {
    expiration = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (),
                                           announce_delay);
    announce_delay = GNUNET_TIME_STD_BACKOFF (announce_delay);
  }
  else
  {
    expiration = GNUNET_HELLO_get_last_expiration (hello);
    announce_delay = GNUNET_TIME_UNIT_SECONDS;
  }

  /* Call again in id_announce_time, unless HELLO expires first,
   * but wait at least 1s. */
  next_put
    = GNUNET_TIME_absolute_get_remaining (expiration);
  next_put
    = GNUNET_TIME_relative_min (next_put,
                                id_announce_time);
  next_put
    = GNUNET_TIME_relative_max (next_put,
                                GNUNET_TIME_UNIT_SECONDS);
  announce_id_task
    = GNUNET_SCHEDULER_add_delayed (next_put,
                                    &announce_id,
                                    cls);
  GNUNET_STATISTICS_update (stats,
                            "# DHT announce",
                            1,
                            GNUNET_NO);
  memset (&phash,
          0,
          sizeof (phash));
  GNUNET_memcpy (&phash,
                 &my_full_id,
                 sizeof (my_full_id));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Announcing my HELLO (%u bytes) in the DHT\n",
       size);
  GNUNET_DHT_put (dht_handle,   /* DHT handle */
                  &phash,       /* Key to use */
                  dht_replication_level,     /* Replication level */
                  GNUNET_DHT_RO_RECORD_ROUTE
                  | GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,    /* DHT options */
                  GNUNET_BLOCK_TYPE_DHT_HELLO,       /* Block type */
                  size,  /* Size of the data */
                  (const char *) hello, /* Data itself */
                  expiration,  /* Data expiration */
                  NULL,         /* Continuation */
                  NULL);        /* Continuation closure */
}


/**
 * Initialize the DHT subsystem.
 *
 * @param c Configuration.
 */
void
GCD_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "init\n");
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c,
                                             "CADET",
                                             "DHT_REPLICATION_LEVEL",
                                             &dht_replication_level))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_WARNING,
                               "CADET",
                               "DHT_REPLICATION_LEVEL",
                               "USING DEFAULT");
    dht_replication_level = 3;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c,
                                           "CADET",
                                           "ID_ANNOUNCE_TIME",
                                           &id_announce_time))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "CADET",
                               "ID_ANNOUNCE_TIME",
                               "MISSING");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  dht_handle = GNUNET_DHT_connect (c,
                                   64);
  GNUNET_break (NULL != dht_handle);
  announce_delay = GNUNET_TIME_UNIT_SECONDS;
  announce_id_task = GNUNET_SCHEDULER_add_now (&announce_id,
                                               NULL);
}


/**
 * Shut down the DHT subsystem.
 */
void
GCD_shutdown (void)
{
  if (NULL != dht_handle)
  {
    GNUNET_DHT_disconnect (dht_handle);
    dht_handle = NULL;
  }
  if (NULL != announce_id_task)
  {
    GNUNET_SCHEDULER_cancel (announce_id_task);
    announce_id_task = NULL;
  }
}


/**
 * Search DHT for paths to @a peeR_id
 *
 * @param peer_id peer to search for
 * @param callback function to call with results
 * @param callback_cls closure for @a callback
 * @return handle to abort search
 */
struct GCD_search_handle *
GCD_search (const struct GNUNET_PeerIdentity *peer_id,
            GCD_search_callback callback,
            void *callback_cls)
{
  struct GNUNET_HashCode phash;
  struct GCD_search_handle *h;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Starting DHT GET for peer %s\n",
       GNUNET_i2s (peer_id));
  GNUNET_STATISTICS_update (stats,
                            "# DHT search",
                            1,
                            GNUNET_NO);
  memset (&phash,
          0,
          sizeof (phash));
  GNUNET_memcpy (&phash,
                 peer_id,
                 sizeof (*peer_id));

  h = GNUNET_new (struct GCD_search_handle);
  h->callback = callback;
  h->cls = callback_cls;
  h->dhtget = GNUNET_DHT_get_start (dht_handle,    /* handle */
                                    GNUNET_BLOCK_TYPE_DHT_HELLO, /* type */
                                    &phash,     /* key to search */
                                    dht_replication_level, /* replication level */
                                    GNUNET_DHT_RO_RECORD_ROUTE |
                                    GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                                    NULL,       /* xquery */
                                    0,     /* xquery bits */
                                    &dht_get_id_handler,
				    h);
  return h;
}


/**
 * Stop DHT search started with #GCD_search().
 *
 * @param h handle to search to stop
 */
void
GCD_search_stop (struct GCD_search_handle *h)
{
  GNUNET_DHT_get_stop (h->dhtget);
  GNUNET_free (h);
}

/* end of gnunet-service-cadet_dht.c */
