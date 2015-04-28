/*
     This file is part of GNUnet
     Copyright (C) 2012, 2015 Christian Grothoff (and other contributing authors)

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
 * @file datacache/plugin_datacache_heap.c
 * @brief heap-only implementation of a database backend for the datacache
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_datacache_plugin.h"

#define LOG(kind,...) GNUNET_log_from (kind, "datacache-heap", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind,op,fn) GNUNET_log_from_strerror_file (kind, "datacache-heap", op, fn)



/**
 * Context for all functions in this plugin.
 */
struct Plugin
{
  /**
   * Our execution environment.
   */
  struct GNUNET_DATACACHE_PluginEnvironment *env;

  /**
   * Our hash map.
   */
  struct GNUNET_CONTAINER_MultiHashMap *map;

  /**
   * Heap for expirations.
   */
  struct GNUNET_CONTAINER_Heap *heap;

};


/**
 * Entry in the hash map.
 */
struct Value
{
  /**
   * Key for the entry.
   */
  struct GNUNET_HashCode key;

  /**
   * Expiration time.
   */
  struct GNUNET_TIME_Absolute discard_time;

  /**
   * Corresponding node in the heap.
   */
  struct GNUNET_CONTAINER_HeapNode *hn;

  /**
   * Path information.
   */
  struct GNUNET_PeerIdentity *path_info;

  /**
   * Payload (actual payload follows this struct)
   */
  size_t size;

  /**
   * Number of entries in @e path_info.
   */
  unsigned int path_info_len;

  /**
   * Type of the block.
   */
  enum GNUNET_BLOCK_Type type;

};


#define OVERHEAD (sizeof (struct Value) + 64)


/**
 * Closure for #put_cb().
 */
struct PutContext
{
  /**
   * Expiration time for the new value.
   */
  struct GNUNET_TIME_Absolute discard_time;

  /**
   * Data for the new value.
   */
  const char *data;

  /**
   * Heap from the plugin.
   */
  struct GNUNET_CONTAINER_Heap *heap;

  /**
   * Path information.
   */
  const struct GNUNET_PeerIdentity *path_info;

  /**
   * Number of bytes in @e data.
   */
  size_t size;

  /**
   * Type of the node.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Number of entries in @e path_info.
   */
  unsigned int path_info_len;

  /**
   * Value to set to #GNUNET_YES if an equivalent block was found.
   */
  int found;
};


/**
 * Function called during PUT to detect if an equivalent block
 * already exists.
 *
 * @param cls the `struct PutContext`
 * @param key the key for the value(s)
 * @param value an existing value
 * @return #GNUNET_YES if not found (to continue to iterate)
 */
static int
put_cb (void *cls,
	const struct GNUNET_HashCode *key,
	void *value)
{
  struct PutContext *put_ctx = cls;
  struct Value *val = value;

  if ( (val->size == put_ctx->size) &&
       (val->type == put_ctx->type) &&
       (0 == memcmp (&val[1], put_ctx->data, put_ctx->size)) )
  {
    put_ctx->found = GNUNET_YES;
    val->discard_time = GNUNET_TIME_absolute_max (val->discard_time,
						  put_ctx->discard_time);
    /* replace old path with new path */
    GNUNET_array_grow (val->path_info,
		       val->path_info_len,
		       put_ctx->path_info_len);
    memcpy (val->path_info,
	    put_ctx->path_info,
	    put_ctx->path_info_len * sizeof (struct GNUNET_PeerIdentity));
    GNUNET_CONTAINER_heap_update_cost (put_ctx->heap,
				       val->hn,
				       val->discard_time.abs_value_us);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Got same value for key %s and type %d (size %u vs %u)\n",
		GNUNET_h2s (key),
		val->type,
		(unsigned int) val->size,
		(unsigned int) put_ctx->size);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure (our `struct Plugin`)
 * @param key key to store data under
 * @param size number of bytes in @a data
 * @param data data to store
 * @param type type of the value
 * @param discard_time when to discard the value in any case
 * @param path_info_len number of entries in @a path_info
 * @param path_info a path through the network
 * @return 0 if duplicate, -1 on error, number of bytes used otherwise
 */
static ssize_t
heap_plugin_put (void *cls,
                 const struct GNUNET_HashCode *key,
                 size_t size,
		 const char *data,
                 enum GNUNET_BLOCK_Type type,
		 struct GNUNET_TIME_Absolute discard_time,
		 unsigned int path_info_len,
		 const struct GNUNET_PeerIdentity *path_info)
{
  struct Plugin *plugin = cls;
  struct Value *val;
  struct PutContext put_ctx;

  put_ctx.found = GNUNET_NO;
  put_ctx.heap = plugin->heap;
  put_ctx.data = data;
  put_ctx.size = size;
  put_ctx.path_info = path_info;
  put_ctx.path_info_len = path_info_len;
  put_ctx.discard_time = discard_time;
  put_ctx.type = type;
  GNUNET_CONTAINER_multihashmap_get_multiple (plugin->map,
					      key,
					      &put_cb,
					      &put_ctx);
  if (GNUNET_YES == put_ctx.found)
    return 0;
  val = GNUNET_malloc (sizeof (struct Value) + size);
  memcpy (&val[1], data, size);
  val->key = *key;
  val->type = type;
  val->discard_time = discard_time;
  val->size = size;
  GNUNET_array_grow (val->path_info,
		     val->path_info_len,
		     path_info_len);
  memcpy (val->path_info, path_info,
	  path_info_len * sizeof (struct GNUNET_PeerIdentity));
  (void) GNUNET_CONTAINER_multihashmap_put (plugin->map,
					    &val->key,
					    val,
					    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  val->hn = GNUNET_CONTAINER_heap_insert (plugin->heap,
					  val,
					  val->discard_time.abs_value_us);
  return size + OVERHEAD;
}


/**
 * Closure for #get_cb().
 */
struct GetContext
{
  /**
   * Function to call for each result.
   */
  GNUNET_DATACACHE_Iterator iter;

  /**
   * Closure for @e iter.
   */
  void *iter_cls;

  /**
   * Number of results found.
   */
  unsigned int cnt;

  /**
   * Block type requested.
   */
  enum GNUNET_BLOCK_Type type;
};



/**
 * Function called during GET to find matching blocks.
 * Only matches by type.
 *
 * @param cls the `struct GetContext`
 * @param key the key for the value(s)
 * @param value an existing value
 * @return #GNUNET_YES to continue to iterate
 */
static int
get_cb (void *cls,
	const struct GNUNET_HashCode *key,
	void *value)
{
  struct GetContext *get_ctx = cls;
  struct Value *val = value;
  int ret;

  if ( (get_ctx->type != val->type) &&
       (GNUNET_BLOCK_TYPE_ANY != get_ctx->type) )
    return GNUNET_OK;
  if (NULL != get_ctx->iter)
    ret = get_ctx->iter (get_ctx->iter_cls,
			 key,
			 val->size,
			 (const char *) &val[1],
			 val->type,
                         val->discard_time,
			 val->path_info_len,
			 val->path_info);
  else
    ret = GNUNET_YES;
  get_ctx->cnt++;
  return ret;
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param cls closure (our `struct Plugin`)
 * @param key
 * @param type entries of which type are relevant?
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for @a iter
 * @return the number of results found
 */
static unsigned int
heap_plugin_get (void *cls,
                 const struct GNUNET_HashCode *key,
                 enum GNUNET_BLOCK_Type type,
                 GNUNET_DATACACHE_Iterator iter,
                 void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct GetContext get_ctx;

  get_ctx.type = type;
  get_ctx.iter = iter;
  get_ctx.iter_cls = iter_cls;
  get_ctx.cnt = 0;
  GNUNET_CONTAINER_multihashmap_get_multiple (plugin->map,
					      key,
					      &get_cb,
					      &get_ctx);
  return get_ctx.cnt;
}


/**
 * Delete the entry with the lowest expiration value
 * from the datacache right now.
 *
 * @param cls closure (our `struct Plugin`)
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
heap_plugin_del (void *cls)
{
  struct Plugin *plugin = cls;
  struct Value *val;

  val = GNUNET_CONTAINER_heap_remove_root (plugin->heap);
  if (NULL == val)
    return GNUNET_SYSERR;
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (plugin->map,
						       &val->key,
						       val));
  plugin->env->delete_notify (plugin->env->cls,
			      &val->key,
			      val->size + OVERHEAD);
  GNUNET_free_non_null (val->path_info);
  GNUNET_free (val);
  return GNUNET_OK;
}


/**
 * Return a random value from the datastore.
 *
 * @param cls closure (our `struct Plugin`)
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for @a iter
 * @return the number of results found
 */
static unsigned int
heap_plugin_get_random (void *cls,
                        GNUNET_DATACACHE_Iterator iter,
                        void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct GetContext get_ctx;

  get_ctx.type = GNUNET_BLOCK_TYPE_ANY;
  get_ctx.iter = iter;
  get_ctx.iter_cls = iter_cls;
  get_ctx.cnt = 0;
  GNUNET_CONTAINER_multihashmap_get_random (plugin->map,
                                            &get_cb,
                                            &get_ctx);
  return get_ctx.cnt;
}


/**
 * Entry point for the plugin.
 *
 * @param cls closure (the `struct GNUNET_DATACACHE_PluginEnvironmnet`)
 * @return the plugin's closure (our `struct Plugin`)
 */
void *
libgnunet_plugin_datacache_heap_init (void *cls)
{
  struct GNUNET_DATACACHE_PluginEnvironment *env = cls;
  struct GNUNET_DATACACHE_PluginFunctions *api;
  struct Plugin *plugin;

  plugin = GNUNET_new (struct Plugin);
  plugin->map = GNUNET_CONTAINER_multihashmap_create (1024,  /* FIXME: base on quota! */
						      GNUNET_YES);
  plugin->heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  plugin->env = env;
  api = GNUNET_new (struct GNUNET_DATACACHE_PluginFunctions);
  api->cls = plugin;
  api->get = &heap_plugin_get;
  api->put = &heap_plugin_put;
  api->del = &heap_plugin_del;
  api->get_random = &heap_plugin_get_random;
  LOG (GNUNET_ERROR_TYPE_INFO,
       _("Heap datacache running\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls closure (our "struct Plugin")
 * @return NULL
 */
void *
libgnunet_plugin_datacache_heap_done (void *cls)
{
  struct GNUNET_DATACACHE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  struct Value *val;

  while (NULL != (val = GNUNET_CONTAINER_heap_remove_root (plugin->heap)))
  {
    GNUNET_assert (GNUNET_YES ==
		   GNUNET_CONTAINER_multihashmap_remove (plugin->map,
							 &val->key,
							 val));
    GNUNET_free_non_null (val->path_info);
    GNUNET_free (val);
  }
  GNUNET_CONTAINER_heap_destroy (plugin->heap);
  GNUNET_CONTAINER_multihashmap_destroy (plugin->map);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}



/* end of plugin_datacache_heap.c */
