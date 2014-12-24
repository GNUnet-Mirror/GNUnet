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
#include "gnunet_statistics_service.h"

#include "cadet_path.h"
#include "gnunet-service-cadet_dht.h"
#include "gnunet-service-cadet_peer.h"
#include "gnunet-service-cadet_hello.h"

#define LOG(level, ...) GNUNET_log_from (level,"cadet-dht",__VA_ARGS__)


/******************************************************************************/
/********************************   STRUCTS  **********************************/
/******************************************************************************/

/**
 * Handle for DHT searches.
 */
struct GCD_search_handle
{
  /** DHT_GET handle. */
  struct GNUNET_DHT_GetHandle *dhtget;

  /** Provided callback to call when a path is found. */
  GCD_search_callback callback;

  /** Provided closure. */
  void *cls;

  /** Peer ID searched for */
  GNUNET_PEER_Id peer_id;
};


/******************************************************************************/
/*******************************   GLOBALS  ***********************************/
/******************************************************************************/

/**
 * Global handle to the statistics service.
 */
extern struct GNUNET_STATISTICS_Handle *stats;

/**
 * Own ID (short value).
 */
extern GNUNET_PEER_Id myid;

/**
 * Own ID (full value).
 */
extern struct GNUNET_PeerIdentity my_full_id;

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
static struct GNUNET_SCHEDULER_Task * announce_id_task;

/**
 * GET requests to stop on shutdown.
 */
static struct GNUNET_CONTAINER_MultiHashMap32 *get_requests;

/******************************************************************************/
/********************************   STATIC  ***********************************/
/******************************************************************************/


/**
 * Build a PeerPath from the paths returned from the DHT, reversing the paths
 * to obtain a local peer -> destination path and interning the peer ids.
 *
 * @return Newly allocated and created path
 *
 * FIXME refactor and use build_path_from_peer_ids
 */
static struct CadetPeerPath *
path_build_from_dht (const struct GNUNET_PeerIdentity *get_path,
                     unsigned int get_path_length,
                     const struct GNUNET_PeerIdentity *put_path,
                     unsigned int put_path_length)
{
  size_t size = get_path_length + put_path_length + 1;
  struct GNUNET_PeerIdentity peers[size];
  const struct GNUNET_PeerIdentity *peer;
  struct CadetPeerPath *p;
  unsigned int own_pos;
  int i;

  peers[0] = my_full_id;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "   GET has %d hops.\n", get_path_length);
  for (i = 0 ; i < get_path_length; i++)
  {
    peer = &get_path[get_path_length - i - 1];
    LOG (GNUNET_ERROR_TYPE_DEBUG, "   From GET: %s\n", GNUNET_i2s (peer));
    peers[i + 1] = *peer;
  }
  for (i = 0 ; i < put_path_length; i++)
  {
    peer = &put_path[put_path_length - i - 1];
    LOG (GNUNET_ERROR_TYPE_DEBUG, "   From PUT: %s\n", GNUNET_i2s (peer));
    peers[i + get_path_length + 1] = *peer;
  }
  p = path_build_from_peer_ids (peers, size, myid, &own_pos);
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
  struct GCD_search_handle *h = cls;
  struct GNUNET_HELLO_Message *hello;
  struct CadetPeerPath *p;
  struct CadetPeer *peer;
  char *s;

  p = path_build_from_dht (get_path, get_path_length,
                           put_path, put_path_length);
  if (NULL == p)
  {
    GNUNET_break_op (0);
    return;
  }

  s = path_2s (p);
  LOG (GNUNET_ERROR_TYPE_INFO, "Got path from DHT: %s\n", s);
  GNUNET_free_non_null (s);
  peer = GCP_get_short (p->peers[p->length - 1]);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Got HELLO for %s\n", GCP_2s (peer));
  h->callback (h->cls, p);
  path_destroy (p);
  hello = (struct GNUNET_HELLO_Message *) data;
  GCP_set_hello (peer, hello);
  GCP_try_connect (peer);
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
  struct GNUNET_HashCode phash;
  const struct GNUNET_HELLO_Message *hello;
  size_t size;
  struct GNUNET_TIME_Absolute expiration;
  struct GNUNET_TIME_Relative retry_time;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    announce_id_task = NULL;
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Announce ID\n");

  /* TODO
   * - Set data expiration in function of X
   * - Adapt X to churn
   */
  hello = GCH_get_mine ();
  if (NULL == hello || (size = GNUNET_HELLO_size (hello)) == 0)
  {
    /* Peerinfo gave us no hello yet, try again in a second. */
    announce_id_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                                     &announce_id, cls);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  no hello, waiting!\n");
    return;
  }
  expiration = GNUNET_HELLO_get_last_expiration (hello);
  retry_time = GNUNET_TIME_absolute_get_remaining (expiration);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Hello %p size: %u\n", hello, size);
  memset (&phash, 0, sizeof (phash));
  memcpy (&phash, &my_full_id, sizeof (my_full_id));
  GNUNET_DHT_put (dht_handle,   /* DHT handle */
                  &phash,       /* Key to use */
                  dht_replication_level,     /* Replication level */
                  GNUNET_DHT_RO_RECORD_ROUTE
                  | GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,    /* DHT options */
                  GNUNET_BLOCK_TYPE_DHT_HELLO,       /* Block type */
                  size,  /* Size of the data */
                  (const char *) hello, /* Data itself */
                  expiration,  /* Data expiration */
                  retry_time, /* Retry time */
                  NULL,         /* Continuation */
                  NULL);        /* Continuation closure */
  announce_id_task =
      GNUNET_SCHEDULER_add_delayed (id_announce_time, &announce_id, cls);
}

/**
 * Iterator over hash map entries and stop GET requests before disconnecting
 * from the DHT.
 *
 * @param cls Closure (unused)
 * @param key Current peer ID.
 * @param value Value in the hash map (GCD_search_handle).
 *
 * @return #GNUNET_YES, we should continue to iterate,
 */
int
stop_get (void *cls,
          uint32_t key,
          void *value)
{
  struct GCD_search_handle *h = value;

  GCD_search_stop (h);
  return GNUNET_YES;
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
GCD_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "init\n");
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "CADET", "DHT_REPLICATION_LEVEL",
                                             &dht_replication_level))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_WARNING,
                               "CADET", "DHT_REPLICATION_LEVEL", "USING DEFAULT");
    dht_replication_level = 3;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c, "CADET", "ID_ANNOUNCE_TIME",
                                           &id_announce_time))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "CADET", "ID_ANNOUNCE_TIME", "MISSING");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  dht_handle = GNUNET_DHT_connect (c, 64);
  if (NULL == dht_handle)
  {
    GNUNET_break (0);
  }

  announce_id_task = GNUNET_SCHEDULER_add_now (&announce_id, NULL);
  get_requests = GNUNET_CONTAINER_multihashmap32_create (32);
}


/**
 * Shut down the DHT subsystem.
 */
void
GCD_shutdown (void)
{
  GNUNET_CONTAINER_multihashmap32_iterate (get_requests, &stop_get, NULL);
  GNUNET_CONTAINER_multihashmap32_destroy (get_requests);
  if (dht_handle != NULL)
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

struct GCD_search_handle *
GCD_search (const struct GNUNET_PeerIdentity *peer_id,
            GCD_search_callback callback, void *cls)
{
  struct GNUNET_HashCode phash;
  struct GCD_search_handle *h;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "  Starting DHT GET for peer %s\n", GNUNET_i2s (peer_id));
  memset (&phash, 0, sizeof (phash));
  memcpy (&phash, peer_id, sizeof (*peer_id));
  h = GNUNET_new (struct GCD_search_handle);
  h->peer_id = GNUNET_PEER_intern (peer_id);
  h->callback = callback;
  h->cls = cls;
  h->dhtget = GNUNET_DHT_get_start (dht_handle,    /* handle */
                                    GNUNET_BLOCK_TYPE_DHT_HELLO, /* type */
                                    &phash,     /* key to search */
                                    dht_replication_level, /* replication level */
                                    GNUNET_DHT_RO_RECORD_ROUTE |
                                    GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                                    NULL,       /* xquery */
                                    0,     /* xquery bits */
                                    &dht_get_id_handler, h);
  GNUNET_CONTAINER_multihashmap32_put (get_requests, h->peer_id, h,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  return h;
}

void
GCD_search_stop (struct GCD_search_handle *h)
{
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multihashmap32_remove (get_requests,
                                                        h->peer_id, h));
  GNUNET_DHT_get_stop (h->dhtget);
  GNUNET_free (h);
}
