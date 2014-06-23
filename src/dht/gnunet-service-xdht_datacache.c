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
 * @file dht/gnunet-service-dht_datacache.c
 * @brief GNUnet DHT service's datacache integration
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_datacache_lib.h"
#include "gnunet-service-xdht_clients.h"
#include "gnunet-service-xdht_datacache.h"
#include "gnunet-service-xdht_routing.h"
#include "gnunet-service-xdht_neighbours.h"
#include "gnunet-service-dht.h"

#define LOG(kind,...) GNUNET_log_from (kind, "dht-dtcache",__VA_ARGS__)


/**
 * Handle to the datacache service (for inserting/retrieving data)
 */
static struct GNUNET_DATACACHE_Handle *datacache;


/**
 * Handle a datum we've received from another peer.  Cache if
 * possible.
 *
 * @param expiration when will the reply expire
 * @param key the query this reply is for
 * @param put_path_length number of peers in 'put_path'
 * @param put_path path the reply took on put
 * @param type type of the reply
 * @param data_size number of bytes in 'data'
 * @param data application payload data
 */
void
GDS_DATACACHE_handle_put (struct GNUNET_TIME_Absolute expiration,
                          const struct GNUNET_HashCode * key,
                          unsigned int put_path_length,
                          const struct GNUNET_PeerIdentity *put_path,
                          enum GNUNET_BLOCK_Type type, size_t data_size,
                          const void *data)
{
  int r;

  if (NULL == datacache)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("%s request received, but have no datacache!\n"), "PUT");
    return;
  }
  if (data_size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  /* Put size is actual data size plus struct overhead plus path length (if any) */
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# ITEMS stored in datacache"), 1,
                            GNUNET_NO);
  r = GNUNET_DATACACHE_put (datacache, key, data_size, data, type, expiration,
                            put_path_length, put_path);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "DATACACHE PUT for key %s [%u] completed (%d) after %u hops\n",
       GNUNET_h2s (key), data_size, r, put_path_length);
}

/**
 * List of peers in the get path.
 */
struct GetPath
{
  /**
   * Pointer to next item in the list
   */
  struct GetPath *next;

  /**
   * Pointer to previous item in the list
   */
  struct GetPath *prev;

  /**
   *  An element in the get path.
   */
  struct GNUNET_PeerIdentity peer;
};


/**
 * Context containing information about a GET request.
 */
struct GetRequestContext
{
  /**
   * extended query (see gnunet_block_lib.h).
   */
  const void *xquery;

  /**
   * Bloomfilter to filter out duplicate replies (updated)
   */
  struct GNUNET_CONTAINER_BloomFilter **reply_bf;

  /**
   * The key this request was about
   */
  struct GNUNET_HashCode key;

  /**
   * Number of bytes in xquery.
   */
  size_t xquery_size;

  /**
   * Mutator value for the reply_bf, see gnunet_block_lib.h
   */
  uint32_t reply_bf_mutator;

  /**
   * Total number of peers in get path.
   */
  unsigned int get_path_length;

  /**
   * Return value to give back.
   */
  enum GNUNET_BLOCK_EvaluationResult eval;

  /**
   * Peeer which has the data for the key.
   */
  struct GNUNET_PeerIdentity source_peer;

  /**
   * Next hop to forward the get result to.
   */
  struct GNUNET_PeerIdentity next_hop;

  /**
   * Head of get path.
   */
  struct GetPath *head;

  /**
   * Tail of get path.
   */
  struct GetPath *tail;

  /* get_path */
};


/**
 * Iterator for local get request results,
 *
 * @param cls closure for iterator, a DatacacheGetContext
 * @param exp when does this value expire?
 * @param key the key this data is stored under
 * @param size the size of the data identified by key
 * @param data the actual data
 * @param type the type of the data
 * @param put_path_length number of peers in 'put_path'
 * @param put_path path the reply took on put
 * @return GNUNET_OK to continue iteration, anything else
 * to stop iteration.
 */
static int
datacache_get_iterator (void *cls,
                        const struct GNUNET_HashCode * key, size_t size,
                        const char *data, enum GNUNET_BLOCK_Type type,
			                  struct GNUNET_TIME_Absolute exp,
			                  unsigned int put_path_length,
			                  const struct GNUNET_PeerIdentity *put_path)
{
  struct GetRequestContext *ctx = cls;
  enum GNUNET_BLOCK_EvaluationResult eval;

  eval =
      GNUNET_BLOCK_evaluate (GDS_block_context, type, key, ctx->reply_bf,
                             ctx->reply_bf_mutator, ctx->xquery,
                             ctx->xquery_size, data, size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Found reply for query %s in datacache, evaluation result is %d\n",
       GNUNET_h2s (key), (int) eval);
  ctx->eval = eval;
  switch (eval)
  {
  case GNUNET_BLOCK_EVALUATION_OK_MORE:
  case GNUNET_BLOCK_EVALUATION_OK_LAST:
    /* forward to local clients */
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# Good RESULTS found in datacache"), 1,
                              GNUNET_NO);
    struct GNUNET_PeerIdentity *get_path;
    get_path = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * 
                              ctx->get_path_length);
    struct GetPath *iterator;
    iterator = ctx->head;
    int i = 0;
    while (i < ctx->get_path_length)
    {
      get_path[i] = iterator->peer;
      i++;
      iterator = iterator->next;
    }
    GDS_NEIGHBOURS_send_get_result (key,type, &(ctx->next_hop),&(ctx->source_peer),
                                    put_path_length, put_path, ctx->get_path_length,
                                    get_path, exp, data, size );
    GNUNET_free_non_null (get_path);

    break;
  case GNUNET_BLOCK_EVALUATION_OK_DUPLICATE:
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# Duplicate RESULTS found in datacache"), 1,
                              GNUNET_NO);
    break;
  case GNUNET_BLOCK_EVALUATION_RESULT_INVALID:
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# Invalid RESULTS found in datacache"), 1,
                              GNUNET_NO);
    break;
  case GNUNET_BLOCK_EVALUATION_RESULT_IRRELEVANT:
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# Irrelevant RESULTS found in datacache"), 1,
                              GNUNET_NO);
    break;
  case GNUNET_BLOCK_EVALUATION_REQUEST_VALID:
    GNUNET_break (0);
    break;
  case GNUNET_BLOCK_EVALUATION_REQUEST_INVALID:
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  case GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED:
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# Unsupported RESULTS found in datacache"), 1,
                              GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Unsupported block type (%u) in local response!\n"), type);
    break;
  }
  return (eval == GNUNET_BLOCK_EVALUATION_OK_LAST) ? GNUNET_NO : GNUNET_OK;
}


/**
 * Handle a GET request we've received from another peer.
 *
 * @param key the query
 * @param type requested data type
 * @param xquery extended query
 * @param xquery_size number of bytes in xquery
 * @param reply_bf where the reply bf is (to be) stored, possibly updated, can be NULL
 * @param reply_bf_mutator mutation value for reply_bf
 * @return evaluation result for the local replies
 * @get_path_length Total number of peers in get path
 * @get_path Peers in get path.
 */
enum GNUNET_BLOCK_EvaluationResult
GDS_DATACACHE_handle_get (const struct GNUNET_HashCode * key,
                          enum GNUNET_BLOCK_Type type, const void *xquery,
                          size_t xquery_size,
                          struct GNUNET_CONTAINER_BloomFilter **reply_bf,
                          uint32_t reply_bf_mutator,
                          uint32_t get_path_length,
                          struct GNUNET_PeerIdentity *get_path,
                          struct GNUNET_PeerIdentity *next_hop,
                          struct GNUNET_PeerIdentity *source_peer)
{
  struct GetRequestContext ctx;
  unsigned int r;

  if (datacache == NULL)
    return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# GET requests given to datacache"),
                            1, GNUNET_NO);
  ctx.eval = GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
  ctx.key = *key;
  ctx.xquery = xquery;
  ctx.xquery_size = xquery_size;
  ctx.reply_bf = reply_bf;
  ctx.reply_bf_mutator = reply_bf_mutator;
  ctx.get_path_length = get_path_length;
  
  if (next_hop != NULL)
  {
    memcpy (&(ctx.next_hop), next_hop, sizeof (struct GNUNET_PeerIdentity));
  }
  unsigned int i = 0;
  ctx.head = NULL;
  ctx.tail = NULL;
  if (get_path != NULL)
  {
    while (i < get_path_length)
    {
      struct GetPath *element;
      element = GNUNET_new (struct GetPath);
      element->next = NULL;
      element->prev = NULL;
      element->peer = get_path[i];
      GNUNET_CONTAINER_DLL_insert (ctx.head, ctx.tail, element);
      i++;
    }
  }

  r = GNUNET_DATACACHE_get (datacache, key, type, &datacache_get_iterator,
                            &ctx);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "DATACACHE GET for key %s completed (%d). %u results found.\n",
       GNUNET_h2s (key), ctx.eval, r);
  return ctx.eval;
}


/**
 * Initialize datacache subsystem.
 */
void
GDS_DATACACHE_init ()
{
  datacache = GNUNET_DATACACHE_create (GDS_cfg, "dhtcache");
}


/**
 * Shutdown datacache subsystem.
 */
void
GDS_DATACACHE_done ()
{
  if (datacache != NULL)
  {
    GNUNET_DATACACHE_destroy (datacache);
    datacache = NULL;
  }
}


/* end of gnunet-service-dht_datacache.c */
