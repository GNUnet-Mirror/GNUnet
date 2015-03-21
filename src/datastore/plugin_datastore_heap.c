/*
     This file is part of GNUnet
     Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file datastore/plugin_datastore_heap.c
 * @brief heap-based datastore backend; usually we want the datastore
 *        to be persistent, and storing data in the heap is obviously
 *        NOT going to be persistent; still, this plugin is useful for
 *        testing/benchmarking --- but never for production!
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_datastore_plugin.h"


/**
 * A value that we are storing.
 */
struct Value
{

  /**
   * Key for the value.
   */
  struct GNUNET_HashCode key;

  /**
   * Pointer to the value's data (allocated at the end of this struct).
   */
  const void *data;

  /**
   * Entry for this value in the 'expire' heap.
   */
  struct GNUNET_CONTAINER_HeapNode *expire_heap;

  /**
   * Entry for this value in the 'replication' heap.
   */
  struct GNUNET_CONTAINER_HeapNode *replication_heap;

  /**
   * Expiration time for this value.
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * Offset of this value in the array of the 'struct ZeroAnonByType';
   * only used if anonymity is zero.
   */
  unsigned int zero_anon_offset;

  /**
   * Number of bytes in 'data'.
   */
  uint32_t size;

  /**
   * Priority of the value.
   */
  uint32_t priority;

  /**
   * Anonymity level for the value.
   */
  uint32_t anonymity;

  /**
   * Replication level for the value.
   */
  uint32_t replication;

  /**
   * Type of 'data'.
   */
  enum GNUNET_BLOCK_Type type;

};


/**
 * We organize 0-anonymity values in arrays "by type".
 */
struct ZeroAnonByType
{

  /**
   * We keep these in a DLL.
   */
  struct ZeroAnonByType *next;

  /**
   * We keep these in a DLL.
   */
  struct ZeroAnonByType *prev;

  /**
   * Array of 0-anonymity items of the given type.
   */
  struct Value **array;

  /**
   * Allocated size of the array.
   */
  unsigned int array_size;

  /**
   * First unused offset in 'array'.
   */
  unsigned int array_pos;

  /**
   * Type of all of the values in 'array'.
   */
  enum GNUNET_BLOCK_Type type;
};


/**
 * Context for all functions in this plugin.
 */
struct Plugin
{
  /**
   * Our execution environment.
   */
  struct GNUNET_DATASTORE_PluginEnvironment *env;

  /**
   * Mapping from keys to 'struct Value's.
   */
  struct GNUNET_CONTAINER_MultiHashMap *keyvalue;

  /**
   * Heap organized by minimum expiration time.
   */
  struct GNUNET_CONTAINER_Heap *by_expiration;

  /**
   * Heap organized by maximum replication value.
   */
  struct GNUNET_CONTAINER_Heap *by_replication;

  /**
   * Head of list of arrays containing zero-anonymity values by type.
   */
  struct ZeroAnonByType *zero_head;

  /**
   * Tail of list of arrays containing zero-anonymity values by type.
   */
  struct ZeroAnonByType *zero_tail;

  /**
   * Size of all values we're storing.
   */
  unsigned long long size;

};


/**
 * Get an estimate of how much space the database is
 * currently using.
 *
 * @param cls our "struct Plugin*"
 * @return number of bytes used on disk
 */
static void
heap_plugin_estimate_size (void *cls, unsigned long long *estimate)
{
  struct Plugin *plugin = cls;

  if (NULL != estimate)
    *estimate = plugin->size;
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure
 * @param key key for the item
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param cont continuation called with success or failure status
 * @param cont_cls continuation closure
 */
static void
heap_plugin_put (void *cls,
		 const struct GNUNET_HashCode * key,
		 uint32_t size,
		 const void *data,
		 enum GNUNET_BLOCK_Type type,
		 uint32_t priority, uint32_t anonymity,
		 uint32_t replication,
		 struct GNUNET_TIME_Absolute expiration,
		 PluginPutCont cont,
		 void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct Value *value;

  value = GNUNET_malloc (sizeof (struct Value) + size);
  value->key = *key;
  value->data = &value[1];
  value->expire_heap = GNUNET_CONTAINER_heap_insert (plugin->by_expiration,
						     value,
						     expiration.abs_value_us);
  value->replication_heap = GNUNET_CONTAINER_heap_insert (plugin->by_replication,
							  value,
							  replication);
  value->expiration = expiration;
  if (0 == anonymity)
  {
    struct ZeroAnonByType *zabt;

    for (zabt = plugin->zero_head; NULL != zabt; zabt = zabt->next)
      if (zabt->type == type)
	break;
    if (NULL == zabt)
    {
      zabt = GNUNET_new (struct ZeroAnonByType);
      zabt->type = type;
      GNUNET_CONTAINER_DLL_insert (plugin->zero_head,
				   plugin->zero_tail,
				   zabt);
    }
    if (zabt->array_size == zabt->array_pos)
    {
      GNUNET_array_grow (zabt->array,
			 zabt->array_size,
			 zabt->array_size * 2 + 4);
    }
    value->zero_anon_offset = zabt->array_pos;
    zabt->array[zabt->array_pos++] = value;
  }
  value->size = size;
  value->priority = priority;
  value->anonymity = anonymity;
  value->replication = replication;
  value->type = type;
  memcpy (&value[1], data, size);
  GNUNET_CONTAINER_multihashmap_put (plugin->keyvalue,
				     &value->key,
				     value,
				     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  plugin->size += size;
  cont (cont_cls, key, size, GNUNET_OK, NULL);
}


/**
 * Delete the given value, removing it from the plugin's data
 * structures.
 *
 * @param plugin the plugin
 * @param value value to delete
 */
static void
delete_value (struct Plugin *plugin,
	      struct Value *value)
{
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (plugin->keyvalue,
						       &value->key,
						       value));
  GNUNET_assert (value == GNUNET_CONTAINER_heap_remove_node (value->expire_heap));
  GNUNET_assert (value == GNUNET_CONTAINER_heap_remove_node (value->replication_heap));
  if (0 == value->anonymity)
  {
    struct ZeroAnonByType *zabt;

    for (zabt = plugin->zero_head; NULL != zabt; zabt = zabt->next)
      if (zabt->type == value->type)
	break;
    GNUNET_assert (NULL != zabt);
    zabt->array[value->zero_anon_offset] = zabt->array[--zabt->array_pos];
    zabt->array[value->zero_anon_offset]->zero_anon_offset = value->zero_anon_offset;
    if (0 == zabt->array_pos)
    {
      GNUNET_array_grow (zabt->array,
			 zabt->array_size,
			 0);
      GNUNET_CONTAINER_DLL_remove (plugin->zero_head,
				   plugin->zero_tail,
				   zabt);
      GNUNET_free (zabt);
    }
  }
  plugin->size -= value->size;
  GNUNET_free (value);
}


/**
 * Closure for iterator called during 'get_key'.
 */
struct GetContext
{

  /**
   * Desired result offset / number of results.
   */
  uint64_t offset;

  /**
   * The plugin.
   */
  struct Plugin *plugin;
		
  /**
   * Requested value hash.
   */
  const struct GNUNET_HashCode * vhash;

  /**
   * Requested type.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Function to call with the result.
   */
  PluginDatumProcessor proc;

  /**
   * Closure for 'proc'.
   */
  void *proc_cls;
};


/**
 * Test if a value matches the specification from the 'get' context
 *
 * @param gc query
 * @param value the value to check against the query
 * @return GNUNET_YES if the value matches
 */
static int
match (const struct GetContext *gc,
       struct Value *value)
{
  struct GNUNET_HashCode vh;

  if ( (gc->type != GNUNET_BLOCK_TYPE_ANY) &&
       (gc->type != value->type) )
    return GNUNET_NO;
  if (NULL != gc->vhash)
  {
    GNUNET_CRYPTO_hash (&value[1], value->size, &vh);
    if (0 != memcmp (&vh, gc->vhash, sizeof (struct GNUNET_HashCode)))
      return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Count number of matching values.
 *
 * @param cls the 'struct GetContext'
 * @param key unused
 * @param val the 'struct Value'
 * @return GNUNET_YES (continue iteration)
 */
static int
count_iterator (void *cls,
		const struct GNUNET_HashCode *key,
		void *val)
{
  struct GetContext *gc = cls;
  struct Value *value = val;

  if (GNUNET_NO == match (gc, value))
    return GNUNET_OK;
  gc->offset++;
  return GNUNET_OK;
}


/**
 * Obtain matching value at 'offset'.
 *
 * @param cls the 'struct GetContext'
 * @param key unused
 * @param val the 'struct Value'
 * @return GNUNET_YES (continue iteration), GNUNET_NO if result was found
 */
static int
get_iterator (void *cls,
	      const struct GNUNET_HashCode *key,
	      void *val)
{
  struct GetContext *gc = cls;
  struct Value *value = val;

  if (GNUNET_NO == match (gc, value))
    return GNUNET_OK;
  if (0 != gc->offset--)
    return GNUNET_OK;
  if (GNUNET_NO ==
      gc->proc (gc->proc_cls,
		key,
		value->size,
		&value[1],
		value->type,
		value->priority,
		value->anonymity,
	    value->expiration,
		(uint64_t) (long) value))
    delete_value (gc->plugin, value);
  return GNUNET_NO;
}


/**
 * Get one of the results for a particular key in the datastore.
 *
 * @param cls closure
 * @param offset offset of the result (modulo num-results);
 *               specific ordering does not matter for the offset
 * @param key maybe NULL (to match all entries)
 * @param vhash hash of the value, maybe NULL (to
 *        match all values that have the right key).
 *        Note that for DBlocks there is no difference
 *        betwen key and vhash, but for other blocks
 *        there may be!
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param proc function to call on each matching value;
 *        will be called with NULL if nothing matches
 * @param proc_cls closure for proc
 */
static void
heap_plugin_get_key (void *cls, uint64_t offset,
		     const struct GNUNET_HashCode *key,
		     const struct GNUNET_HashCode *vhash,
		     enum GNUNET_BLOCK_Type type, PluginDatumProcessor proc,
		     void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct GetContext gc;

  gc.plugin = plugin;
  gc.offset = 0;
  gc.vhash = vhash;
  gc.type = type;
  gc.proc = proc;
  gc.proc_cls = proc_cls;
  if (NULL == key)
  {
    GNUNET_CONTAINER_multihashmap_iterate (plugin->keyvalue,
					   &count_iterator,
					   &gc);
    if (0 == gc.offset)
    {
      proc (proc_cls,
	    NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
    gc.offset = offset % gc.offset;
    GNUNET_CONTAINER_multihashmap_iterate (plugin->keyvalue,
					   &get_iterator,
					   &gc);
  }
  else
  {
    GNUNET_CONTAINER_multihashmap_get_multiple (plugin->keyvalue,
						key,
						&count_iterator,
						&gc);
    if (0 == gc.offset)
    {
      proc (proc_cls,
	    NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
    gc.offset = offset % gc.offset;
    GNUNET_CONTAINER_multihashmap_get_multiple (plugin->keyvalue,
						key,
						&get_iterator,
						&gc);
  }
}


/**
 * Get a random item for replication.  Returns a single, not expired,
 * random item from those with the highest replication counters.  The
 * item's replication counter is decremented by one IF it was positive
 * before.  Call 'proc' with all values ZERO or NULL if the datastore
 * is empty.
 *
 * @param cls closure
 * @param proc function to call the value (once only).
 * @param proc_cls closure for proc
 */
static void
heap_plugin_get_replication (void *cls,
			     PluginDatumProcessor proc,
			     void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct Value *value;

  value = GNUNET_CONTAINER_heap_remove_root (plugin->by_replication);
  if (NULL == value)
  {
    proc (proc_cls,
	  NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  if (value->replication > 0)
  {
    value->replication--;
    value->replication_heap = GNUNET_CONTAINER_heap_insert (plugin->by_replication,
							    value,
							    value->replication);
  }
  else
  {
    /* need a better way to pick a random item, replication level is always 0 */
    value->replication_heap = GNUNET_CONTAINER_heap_insert (plugin->by_replication,
							    value,
							    value->replication);
    value = GNUNET_CONTAINER_heap_walk_get_next (plugin->by_replication);
  }
  if (GNUNET_NO ==
      proc (proc_cls,
	    &value->key,
	    value->size,
	    &value[1],
	    value->type,
	    value->priority,
	    value->anonymity,
	    value->expiration,
	    (uint64_t) (long) value))
    delete_value (plugin, value);
}


/**
 * Get a random item for expiration.  Call 'proc' with all values ZERO
 * or NULL if the datastore is empty.
 *
 * @param cls closure
 * @param proc function to call the value (once only).
 * @param proc_cls closure for proc
 */
static void
heap_plugin_get_expiration (void *cls, PluginDatumProcessor proc,
			    void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct Value *value;

  value = GNUNET_CONTAINER_heap_peek (plugin->by_expiration);
  if (NULL == value)
  {
    proc (proc_cls,
	  NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  if (GNUNET_NO ==
      proc (proc_cls,
	    &value->key,
	    value->size,
	    &value[1],
	    value->type,
	    value->priority,
	    value->anonymity,
	    value->expiration,
	    (uint64_t) (long) value))
    delete_value (plugin, value);
}


/**
 * Update the priority for a particular key in the datastore.  If
 * the expiration time in value is different than the time found in
 * the datastore, the higher value should be kept.  For the
 * anonymity level, the lower value is to be used.  The specified
 * priority should be added to the existing priority, ignoring the
 * priority in value.
 *
 * @param cls our "struct Plugin*"
 * @param uid unique identifier of the datum
 * @param delta by how much should the priority
 *     change?  If priority + delta < 0 the
 *     priority should be set to 0 (never go
 *     negative).
 * @param expire new expiration time should be the
 *     MAX of any existing expiration time and
 *     this value
 * @param cont continuation called with success or failure status
 * @param cons_cls continuation closure
 */
static void
heap_plugin_update (void *cls,
		    uint64_t uid,
		    int delta,
		    struct GNUNET_TIME_Absolute expire,
		    PluginUpdateCont cont,
		    void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct Value *value;

  value = (struct Value*) (long) uid;
  GNUNET_assert (NULL != value);
  if (value->expiration.abs_value_us != expire.abs_value_us)
  {
    value->expiration = expire;
    GNUNET_CONTAINER_heap_update_cost (plugin->by_expiration,
				       value->expire_heap,
				       expire.abs_value_us);
  }
  if ( (delta < 0) && (value->priority < - delta) )
    value->priority = 0;
  else
    value->priority += delta;
  cont (cont_cls, GNUNET_OK, NULL);
}


/**
 * Call the given processor on an item with zero anonymity.
 *
 * @param cls our "struct Plugin*"
 * @param offset offset of the result (modulo num-results);
 *               specific ordering does not matter for the offset
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param proc function to call on each matching value;
 *        will be called  with NULL if no value matches
 * @param proc_cls closure for proc
 */
static void
heap_plugin_get_zero_anonymity (void *cls, uint64_t offset,
				enum GNUNET_BLOCK_Type type,
				PluginDatumProcessor proc, void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct ZeroAnonByType *zabt;
  struct Value *value;
  uint64_t count;

  count = 0;
  for (zabt = plugin->zero_head; NULL != zabt; zabt = zabt->next)
  {
    if ( (type != GNUNET_BLOCK_TYPE_ANY) &&
	 (type != zabt->type) )
      continue;
    count += zabt->array_pos;
  }
  if (0 == count)
  {
    proc (proc_cls,
	  NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  offset = offset % count;
  for (zabt = plugin->zero_head; NULL != zabt; zabt = zabt->next)
  {
    if ( (type != GNUNET_BLOCK_TYPE_ANY) &&
	 (type != zabt->type) )
      continue;
    if (offset >= zabt->array_pos)
    {
      offset -= zabt->array_pos;
      continue;
    }
    break;
  }
  GNUNET_assert (NULL != zabt);
  value = zabt->array[offset];
  if (GNUNET_NO ==
      proc (proc_cls,
	    &value->key,
	    value->size,
	    &value[1],
	    value->type,
	    value->priority,
	    value->anonymity,
	    value->expiration,
	    (uint64_t) (long) value))
    delete_value (plugin, value);
}


/**
 * Drop database.
 */
static void
heap_plugin_drop (void *cls)
{
  /* nothing needs to be done */
}


/**
 * Closure for the 'return_value' function.
 */
struct GetAllContext
{
  /**
   * Function to call.
   */
  PluginKeyProcessor proc;

  /**
   * Closure for 'proc'.
   */
  void *proc_cls;
};


/**
 * Callback invoked to call callback on each value.
 *
 * @param cls the plugin
 * @param key unused
 * @param val the value
 * @return GNUNET_OK (continue to iterate)
 */
static int
return_value (void *cls,
	      const struct GNUNET_HashCode *key,
	      void *val)
{
  struct GetAllContext *gac = cls;

  gac->proc (gac->proc_cls,
	     key,
	     1);
  return GNUNET_OK;
}


/**
 * Get all of the keys in the datastore.
 *
 * @param cls closure
 * @param proc function to call on each key
 * @param proc_cls closure for proc
 */
static void
heap_get_keys (void *cls,
	       PluginKeyProcessor proc,
	       void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct GetAllContext gac;

  gac.proc = proc;
  gac.proc_cls = proc_cls;
  GNUNET_CONTAINER_multihashmap_iterate (plugin->keyvalue,
					 &return_value,
					 &gac);
  proc (proc_cls, NULL, 0);
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_DATASTORE_PluginEnvironment*"
 * @return our "struct Plugin*"
 */
void *
libgnunet_plugin_datastore_heap_init (void *cls)
{
  struct GNUNET_DATASTORE_PluginEnvironment *env = cls;
  struct GNUNET_DATASTORE_PluginFunctions *api;
  struct Plugin *plugin;
  unsigned long long esize;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg,
					     "datastore-heap",
					     "HASHMAPSIZE",
					     &esize))
    esize = 128 * 1024;
  plugin = GNUNET_new (struct Plugin);
  plugin->env = env;
  plugin->keyvalue = GNUNET_CONTAINER_multihashmap_create (esize, GNUNET_YES);
  plugin->by_expiration = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  plugin->by_replication = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MAX);
  api = GNUNET_new (struct GNUNET_DATASTORE_PluginFunctions);
  api->cls = plugin;
  api->estimate_size = &heap_plugin_estimate_size;
  api->put = &heap_plugin_put;
  api->update = &heap_plugin_update;
  api->get_key = &heap_plugin_get_key;
  api->get_replication = &heap_plugin_get_replication;
  api->get_expiration = &heap_plugin_get_expiration;
  api->get_zero_anonymity = &heap_plugin_get_zero_anonymity;
  api->drop = &heap_plugin_drop;
  api->get_keys = &heap_get_keys;
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "heap",
                   _("Heap database running\n"));
  return api;
}


/**
 * Callback invoked to free all value.
 *
 * @param cls the plugin
 * @param key unused
 * @param val the value
 * @return GNUNET_OK (continue to iterate)
 */
static int
free_value (void *cls,
	    const struct GNUNET_HashCode *key,
	    void *val)
{
  struct Plugin *plugin = cls;
  struct Value *value = val;

  delete_value (plugin, value);
  return GNUNET_OK;
}


/**
 * Exit point from the plugin.
 * @param cls our "struct Plugin*"
 * @return always NULL
 */
void *
libgnunet_plugin_datastore_heap_done (void *cls)
{
  struct GNUNET_DATASTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  GNUNET_CONTAINER_multihashmap_iterate (plugin->keyvalue,
					 &free_value,
					 plugin);
  GNUNET_CONTAINER_multihashmap_destroy (plugin->keyvalue);
  GNUNET_CONTAINER_heap_destroy (plugin->by_expiration);
  GNUNET_CONTAINER_heap_destroy (plugin->by_replication);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_datastore_heap.c */
