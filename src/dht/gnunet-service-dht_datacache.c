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
#include "gnunet-service-dht_datacache.h"


/**
 * Handle to the datacache service (for inserting/retrieving data)
 */
static struct GNUNET_DATACACHE_Handle *datacache;


/**
 * Entry for inserting data into datacache from the DHT.
 */
struct DHTPutEntry
{
  /**
   * Size of data.
   */
  uint16_t data_size;

  /**
   * Length of recorded path.
   */
  uint16_t path_length;

  /* PATH ENTRIES */

  /* PUT DATA */

};


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
			  const GNUNET_HashCode *key,
			  unsigned int put_path_length,
			  const struct GNUNET_PeerIdentity *put_path,
			  uint32_t type,
			  size_t data_size,
			  const void *data)
{
  size_t plen = data_size + put_path_length * sizeof(struct GNUNET_PeerIdentity) + sizeof(struct DHTPutEntry);
  char buf[plen];
  struct DHTPutEntry *pe;
  struct GNUNET_PeerIdentity *pp;
  char *path_offset;

  if (datacache == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  "%s request received, but have no datacache!\n",
		  "PUT");      
      return;
    }
  if (data_size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      return;
    }
  /* Put size is actual data size plus struct overhead plus path length (if any) */
  pe = (struct DHTPutEntry *) buf;
  pe->data_size = htons (data_size);
  pe->path_length = htons ((uint16_t) put_path_length);
  pp = (struct GNUNET_PeerIdentity *) &pe[1];
  memcpy (pp, put_path, put_path_length * sizeof (struct GNUNET_PeerIdentity));
  memcpy (&pp[put_path_length],
	  data, data_size);
  (void) GNUNET_DATACACHE_put (datacache, key, 
			       plen, (const char *) pe, type,
			       expiration);
}


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
  GNUNET_HashCode key;

  /**
   * Number of bytes in xquery.
   */
  size_t xquery_size;

  /**
   * Mutator value for the reply_bf, see gnunet_block_lib.h
   */
  uint32_t reply_bf_mutator;

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
 *
 * @return GNUNET_OK to continue iteration, anything else
 * to stop iteration.
 */
static int
datacache_get_iterator (void *cls, struct GNUNET_TIME_Absolute exp,
                        const GNUNET_HashCode * key, size_t size,
                        const char *data, enum GNUNET_BLOCK_Type type)
{
  struct GetRequestContext *ctx = cls;
  const struct DHTPutEntry *pe;
  const struct GNUNET_PeerIdentity *pp;
  const char *data;
  size_t data_size;
  uint16_t put_path_length;
  enum GNUNET_BLOCK_EvaluationResult eval;

  pe = (const struct DHTPutEntry *) data;
  put_path_length = ntohs (pe->path_length);
  data_size = ntohs (pe->data_size);

  if (size !=
      sizeof (struct DHTPutEntry) + data_size +
      (put_path_length * sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  pp = (const struct GNUNET_PeerIdentity *) &pe[1];
  data = (const char*) &pp[put_path_length];
  eval =
      GNUNET_BLOCK_evaluate (block_context, type, key, 
			     ctx->reply_bf,
                             ctx->reply_bf_mutator,
			     ctx->xquery,
                             ctx->xquery_size, 
			     data,
                             data_size);
  switch (eval)
  {
  case GNUNET_BLOCK_EVALUATION_OK_LAST:
  case GNUNET_BLOCK_EVALUATION_OK_MORE:
    /* forward to local clients */
    GDS_CLIENT_handle_reply (exp,
			     key,
			     0, NULL,
			     put_path_length, pp,
			     type, data_size, data);
    /* forward to other peers */
    GDS_NEIGHBOURS_handle_reply (type, exp,
				 key, put_path_length, pp, 
				 0, NULL, data, data_size);
    break;
  case GNUNET_BLOCK_EVALUATION_OK_DUPLICATE:
    break;
  case GNUNET_BLOCK_EVALUATION_RESULT_INVALID:
    break;
  case GNUNET_BLOCK_EVALUATION_REQUEST_VALID:
    GNUNET_break (0);
    break;
  case GNUNET_BLOCK_EVALUATION_REQUEST_INVALID:
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  case GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Unsupported block type (%u) in local response!\n",
                type);
    break;
  }
  return GNUNET_OK;
}


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
  GNUNET_HashCode key;

  /**
   * Number of bytes in xquery.
   */
  size_t xquery_size;

  /**
   * Mutator value for the reply_bf, see gnunet_block_lib.h
   */
  uint32_t reply_bf_mutator;

};


/**
 * Handle a GET request we've received from another peer.
 *
 * @param key the query 
 * @param type requested data type
 * @param xquery extended query
 * @param xquery_size number of bytes in xquery
 * @param reply_bf where the reply bf is (to be) stored, possibly updated, can be NULL
 * @param reply_bf_mutator mutation value for reply_bf
 */
void
GDS_DATACACHE_handle_get (const GNUNET_HashCode *key,
			  uint32_t type,
			  const void *xquery,
			  size_t xquery_size,
			  struct GNUNET_CONTAINER_BloomFilter **reply_bf,
			  uint32_t reply_bf_mutator)
{
  struct GetRequestContext ctx;

  if (datacache == NULL)
    return;
  ctx.key = *key;
  ctx.xquery = xquery;
  ctx.xquery_size = xquery_size;
  ctx.reply_bf = reply_bf;
  ctx.reply_bf_mutator = reply_bf_mutator;
  (void) GNUNET_DATACACHE_get (datacache, &msg_ctx->key, type,
			       &datacache_get_iterator, &ctx);
}


/**
 * Initialize datacache subsystem.
 */
void 
GDS_DATACACHE_init ()
{
  datacache = GNUNET_DATACACHE_create (cfg, "dhtcache");
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
