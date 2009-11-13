/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file include/gnunet_container_lib.h
 * @brief container classes for GNUnet
 *
 * @author Christian Grothoff
 * @author Nils Durner
 */

#ifndef GNUNET_CONTAINER_LIB_H
#define GNUNET_CONTAINER_LIB_H

/* add error and config prototypes */
#include "gnunet_crypto_lib.h"
#include <extractor.h>

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/* ******************* bloomfilter ***************** */

/**
 * @brief bloomfilter representation (opaque)
 */
struct GNUNET_CONTAINER_BloomFilter;

/**
 * Iterator over HashCodes.
 *
 * @param cls closure
 * @param next set to the next hash code
 * @return GNUNET_YES if next was updated
 *         GNUNET_NO if there are no more entries
 */
typedef int (*GNUNET_HashCodeIterator) (void *cls,
					GNUNET_HashCode * next);

/**
 * Load a bloom-filter from a file.
 *
 * @param filename the name of the file (or the prefix)
 * @param size the size of the bloom-filter (number of
 *        bytes of storage space to use)
 * @param k the number of GNUNET_CRYPTO_hash-functions to apply per
 *        element (number of bits set per element in the set)
 * @return the bloomfilter
 */
struct GNUNET_CONTAINER_BloomFilter *
GNUNET_CONTAINER_bloomfilter_load (const
				   char
				   *filename,
				   size_t
				   size,
				   unsigned
				   int
				   k);

/**
 * Create a bloom filter from raw bits.
 *
 * @param data the raw bits in memory (maybe NULL,
 *        in which case all bits should be considered
 *        to be zero).
 * @param size the size of the bloom-filter (number of
 *        bytes of storage space to use); also size of data
 *        -- unless data is NULL.  Must be a power of 2.
 * @param k the number of GNUNET_CRYPTO_hash-functions to apply per
 *        element (number of bits set per element in the set)
 * @return the bloomfilter
 */
struct GNUNET_CONTAINER_BloomFilter *
GNUNET_CONTAINER_bloomfilter_init (const
				   char
				   *data,
				   size_t
				   size,
				   unsigned
				   int
				   k);

/**
 * Copy the raw data of this bloomfilter into
 * the given data array.
 *
 * @param data where to write the data
 * @param size the size of the given data array
 * @return GNUNET_SYSERR if the data array of the wrong size
 */
int GNUNET_CONTAINER_bloomfilter_get_raw_data (struct
                                               GNUNET_CONTAINER_BloomFilter
                                               *bf, char *data,
                                               size_t size);

/**
 * Test if an element is in the filter.
 * @param e the element
 * @param bf the filter
 * @return GNUNET_YES if the element is in the filter, GNUNET_NO if not
 */
int GNUNET_CONTAINER_bloomfilter_test (struct GNUNET_CONTAINER_BloomFilter
                                       *bf, const GNUNET_HashCode * e);

/**
 * Add an element to the filter
 * @param bf the filter
 * @param e the element
 */
void GNUNET_CONTAINER_bloomfilter_add (struct GNUNET_CONTAINER_BloomFilter
                                       *bf, const GNUNET_HashCode * e);

/**
 * Remove an element from the filter.
 * @param bf the filter
 * @param e the element to remove
 */
void GNUNET_CONTAINER_bloomfilter_remove (struct GNUNET_CONTAINER_BloomFilter
                                          *bf, const GNUNET_HashCode * e);

/**
 * Free the space associcated with a filter
 * in memory, flush to drive if needed (do not
 * free the space on the drive)
 * @param bf the filter
 */
void GNUNET_CONTAINER_bloomfilter_free (struct GNUNET_CONTAINER_BloomFilter
                                        *bf);

/**
 * Reset a bloom filter to empty.
 * @param bf the filter
 */
void GNUNET_CONTAINER_bloomfilter_clear (struct GNUNET_CONTAINER_BloomFilter
                                         *bf);

/**
 * Or the entries of the given raw data array with the
 * data of the given bloom filter.  Assumes that
 * the size of the data array and the current filter
 * match.
 *
 * @param bf the filter
 * @param data data to OR-in
 * @param size size of data
 * @return GNUNET_OK on success
 */
int GNUNET_CONTAINER_bloomfilter_or (struct GNUNET_CONTAINER_BloomFilter *bf,
                                     const char *data, size_t size);

/**
 * Resize a bloom filter.  Note that this operation
 * is pretty costly.  Essentially, the bloom filter
 * needs to be completely re-build.
 *
 * @param bf the filter
 * @param iterator an iterator over all elements stored in the BF
 * @param iterator_cls closure for iterator
 * @param size the new size for the filter
 * @param k the new number of GNUNET_CRYPTO_hash-function to apply per element
 */
void GNUNET_CONTAINER_bloomfilter_resize (struct GNUNET_CONTAINER_BloomFilter
                                          *bf,
                                          GNUNET_HashCodeIterator iterator,
                                          void *iterator_cls,
                                          size_t size, unsigned int k);

/* ****************** metadata ******************* */

/**
 * Meta data to associate with a file, directory or namespace.
 */
struct GNUNET_CONTAINER_MetaData;

/**
 * Iterator over meta data.
 *
 * @param cls closure
 * @param type type of the meta data
 * @param data value of the meta data
 * @return GNUNET_OK to continue to iterate, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_CONTAINER_MetaDataProcessor) (void *cls,
						   EXTRACTOR_KeywordType type,
                                                   const char *data);

/**
 * Create a fresh MetaData token.
 * 
 * @return empty meta-data container
 */
struct GNUNET_CONTAINER_MetaData *GNUNET_CONTAINER_meta_data_create (void);

/**
 * Duplicate a MetaData token.
 * 
 * @param md what to duplicate
 * @return duplicate meta-data container
 */
struct GNUNET_CONTAINER_MetaData *GNUNET_CONTAINER_meta_data_duplicate (const
                                                                        struct
                                                                        GNUNET_CONTAINER_MetaData
                                                                        *md);

/**
 * Free meta data.
 *
 * @param md what to free
 */
void GNUNET_CONTAINER_meta_data_destroy (struct GNUNET_CONTAINER_MetaData
                                         *md);

/**
 * Test if two MDs are equal.
 *
 * @param md1 first value to check
 * @param md2 other value to check
 * @return GNUNET_YES if they are equal
 */
int GNUNET_CONTAINER_meta_data_test_equal (const struct
                                           GNUNET_CONTAINER_MetaData *md1,
                                           const struct
                                           GNUNET_CONTAINER_MetaData *md2);


/**
 * Extend metadata.
 *
 * @param md metadata to extend
 * @param type type of the new entry
 * @param data value for the entry
 * @return GNUNET_OK on success, GNUNET_SYSERR if this entry already exists
 */
int GNUNET_CONTAINER_meta_data_insert (struct GNUNET_CONTAINER_MetaData *md,
                                       EXTRACTOR_KeywordType type,
                                       const char *data);

/**
 * Remove an item.
 *
 * @param md metadata to manipulate
 * @param type type of the item to remove
 * @param data specific value to remove, NULL to remove all
 *        entries of the given type
 * @return GNUNET_OK on success, GNUNET_SYSERR if the item does not exist in md
 */
int GNUNET_CONTAINER_meta_data_delete (struct GNUNET_CONTAINER_MetaData *md,
                                       EXTRACTOR_KeywordType type,
                                       const char *data);

/**
 * Add the current time as the publication date
 * to the meta-data.
 *
 * @param md metadata to modify
 */
void GNUNET_CONTAINER_meta_data_add_publication_date (struct
                                                      GNUNET_CONTAINER_MetaData
                                                      *md);

/**
 * Iterate over MD entries, excluding thumbnails.
 *
 * @param md metadata to inspect
 * @param iter function to call on each entry
 * @param iter_cls closure for iterator
 * @return number of entries
 */
int GNUNET_CONTAINER_meta_data_get_contents (const struct
                                             GNUNET_CONTAINER_MetaData *md,
                                             GNUNET_CONTAINER_MetaDataProcessor
                                             iter, void *iter_cls);

/**
 * Get the first MD entry of the given type.
 *
 * @param md metadata to inspect
 * @param type type to look for
 * @return NULL if we do not have any such entry,
 *  otherwise client is responsible for freeing the value!
 */
char *GNUNET_CONTAINER_meta_data_get_by_type (const struct
                                             GNUNET_CONTAINER_MetaData *md,
                                              EXTRACTOR_KeywordType type);

/**
 * Get the first matching MD entry of the given types.
 *
 * @param md metadata to inspect
 * @param ... -1-terminated list of types
 * @return NULL if we do not have any such entry,
 *  otherwise client is responsible for freeing the value!
 */
char *GNUNET_CONTAINER_meta_data_get_first_by_types (const struct
                                                     GNUNET_CONTAINER_MetaData
                                                     *md, ...);

/**
 * Get a thumbnail from the meta-data (if present).
 *
 * @param md metadata to inspect
 * @param thumb will be set to the thumbnail data.  Must be
 *        freed by the caller!
 * @return number of bytes in thumbnail, 0 if not available
 */
size_t GNUNET_CONTAINER_meta_data_get_thumbnail (const struct
                                                 GNUNET_CONTAINER_MetaData
                                                 *md, unsigned char **thumb);

/**
 * Extract meta-data from a file.
 *
 * @param md metadata to set
 * @param filename name of file to inspect
 * @param extractors plugins to use
 * @return GNUNET_SYSERR on error, otherwise the number
 *   of meta-data items obtained
 */
int GNUNET_CONTAINER_meta_data_extract_from_file (struct
                                                  GNUNET_CONTAINER_MetaData
                                                  *md, const char *filename,
                                                  EXTRACTOR_ExtractorList *
                                                  extractors);


/**
 * Options for metadata serialization.
 */
enum GNUNET_CONTAINER_MetaDataSerializationOptions
{
  /**
   * Serialize all of the data.
   */
  GNUNET_CONTAINER_META_DATA_SERIALIZE_FULL = 0,

  /**
   * If not enough space is available, it is acceptable
   * to only serialize some of the metadata.
   */
  GNUNET_CONTAINER_META_DATA_SERIALIZE_PART = 1,

  /**
   * Speed is of the essence, do not allow compression.
   */
  GNUNET_CONTAINER_META_DATA_SERIALIZE_NO_COMPRESS = 2
};


/**
 * Serialize meta-data to target.
 *
 * @param md metadata to serialize
 * @param target where to write the serialized metadata
 * @param max maximum number of bytes available
 * @param opt is it ok to just write SOME of the
 *        meta-data to match the size constraint,
 *        possibly discarding some data?
 * @return number of bytes written on success,
 *         -1 on error (typically: not enough
 *         space)
 */
ssize_t GNUNET_CONTAINER_meta_data_serialize (const struct
					      GNUNET_CONTAINER_MetaData *md,
					      char *target, 
					      size_t max,
					      enum
                                          GNUNET_CONTAINER_MetaDataSerializationOptions
                                          opt);


/**
 * Estimate (!) the size of the meta-data in
 * serialized form.  The estimate MAY be higher
 * than what is strictly needed.
 *
 * @param md metadata to inspect
 * @param opt is it ok to just write SOME of the
 *        meta-data to match the size constraint,
 *        possibly discarding some data?
 * @return number of bytes needed for serialization, -1 on error
 */
ssize_t GNUNET_CONTAINER_meta_data_get_serialized_size (const struct
							GNUNET_CONTAINER_MetaData
							*md,
							enum
							GNUNET_CONTAINER_MetaDataSerializationOptions
							opt);

/**
 * Deserialize meta-data.  Initializes md.
 *
 * @param input serialized meta-data.
 * @param size number of bytes available
 * @return MD on success, NULL on error (i.e.
 *         bad format)
 */
struct GNUNET_CONTAINER_MetaData
  *GNUNET_CONTAINER_meta_data_deserialize (const char *input,
                                           size_t size);

/**
 * Does the meta-data claim that this is a directory?
 * Checks if the mime-type is that of a GNUnet directory.
 *
 * @param md metadata to inspect
 * @return GNUNET_YES if it is, GNUNET_NO if it is not, GNUNET_SYSERR if
 *  we have no mime-type information (treat as 'GNUNET_NO')
 */
int GNUNET_CONTAINER_meta_data_test_for_directory (const struct
                                                   GNUNET_CONTAINER_MetaData
                                                   *md);


/* ******************************* HashMap **************************** */

/**
 * Opaque handle for a HashMap.
 */
struct GNUNET_CONTAINER_MultiHashMap;

/**
 * Options for storing values in the HashMap.
 */
enum GNUNET_CONTAINER_MultiHashMapOption
{

  /**
   * If a value with the given key exists, replace it.  Note that the
   * old value would NOT be freed by replace (the application has to
   * make sure that this happens if required).
   */
  GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE,

  /**
   * Allow multiple values with the same key.
   */
  GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE,

  /**
   * There must only be one value per key; storing a value should fail
   * if a value under the same key already exists.
   */
  GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY,

  /**
   * There must only be one value per key, but don't bother checking
   * if a value already exists (faster than UNIQUE_ONLY; implemented
   * just like MULTIPLE but this option documents better what is
   * intended if UNIQUE is what is desired).
   */
  GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST
};


/**
 * Iterator over HashCodes.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
typedef int (*GNUNET_CONTAINER_HashMapIterator) (void *cls,
						 const GNUNET_HashCode * key,
                                                 void *value);


/**
 * Create a multi hash map.
 *
 * @param len initial size (map will grow as needed)
 * @return NULL on error
 */
struct GNUNET_CONTAINER_MultiHashMap
  *GNUNET_CONTAINER_multihashmap_create (unsigned int len);


/**
 * Destroy a hash map.  Will not free any values
 * stored in the hash map!
 *
 * @param map the map
 */
void GNUNET_CONTAINER_multihashmap_destroy (struct
                                            GNUNET_CONTAINER_MultiHashMap
                                            *map);


/**
 * Given a key find a value in the map matching the key.
 *
 * @param map the map
 * @param key what to look for
 * @return NULL if no value was found; note that
 *   this is indistinguishable from values that just
 *   happen to be NULL; use "contains" to test for
 *   key-value pairs with value NULL
 */
void *GNUNET_CONTAINER_multihashmap_get (const struct
                                         GNUNET_CONTAINER_MultiHashMap *map,
                                         const GNUNET_HashCode * key);


/**
 * Remove the given key-value pair from the map.  Note that if the
 * key-value pair is in the map multiple times, only one of the pairs
 * will be removed.
 *
 * @param map the map
 * @param key key of the key-value pair
 * @param value value of the key-value pair
 * @return GNUNET_YES on success, GNUNET_NO if the key-value pair
 *  is not in the map
 */
int GNUNET_CONTAINER_multihashmap_remove (struct GNUNET_CONTAINER_MultiHashMap
                                          *map, const GNUNET_HashCode * key,
                                          void *value);

/**
 * Remove all entries for the given key from the map.
 * Note that the values would not be "freed".
 *
 * @param map the map
 * @param key identifies values to be removed
 * @return number of values removed
 */
int GNUNET_CONTAINER_multihashmap_remove_all (struct
                                              GNUNET_CONTAINER_MultiHashMap
                                              *map,
                                              const GNUNET_HashCode * key);


/**
 * Check if the map contains any value under the given
 * key (including values that are NULL).
 *
 * @param map the map
 * @param key the key to test if a value exists for it
 * @return GNUNET_YES if such a value exists,
 *         GNUNET_NO if not
 */
int GNUNET_CONTAINER_multihashmap_contains (const struct
                                            GNUNET_CONTAINER_MultiHashMap
                                            *map,
                                            const GNUNET_HashCode * key);


/**
 * Store a key-value pair in the map.
 *
 * @param map the map
 * @param key key to use
 * @param value value to use
 * @param opt options for put
 * @return GNUNET_OK on success,
 *         GNUNET_NO if a value was replaced (with REPLACE)
 *         GNUNET_SYSERR if UNIQUE_ONLY was the option and the
 *                       value already exists
 */
int GNUNET_CONTAINER_multihashmap_put (struct GNUNET_CONTAINER_MultiHashMap
                                       *map, const GNUNET_HashCode * key,
                                       void *value,
                                       enum
                                       GNUNET_CONTAINER_MultiHashMapOption
                                       opt);

/**
 * Get the number of key-value pairs in the map.
 *
 * @param map the map
 * @return the number of key value pairs
 */
unsigned int GNUNET_CONTAINER_multihashmap_size (const struct
                                                 GNUNET_CONTAINER_MultiHashMap
                                                 *map);


/**
 * Iterate over all entries in the map.
 *
 * @param map the map
 * @param it function to call on each entry
 * @param it_cls extra argument to it
 * @return the number of key value pairs processed,
 *         GNUNET_SYSERR if it aborted iteration
 */
int GNUNET_CONTAINER_multihashmap_iterate (const struct
                                           GNUNET_CONTAINER_MultiHashMap *map,
                                           GNUNET_CONTAINER_HashMapIterator
                                           it, void *it_cls);


/**
 * Iterate over all entries in the map that match a particular key.
 *
 * @param map the map
 * @param key key that the entries must correspond to
 * @param it function to call on each entry
 * @param it_cls extra argument to it
 * @return the number of key value pairs processed,
 *         GNUNET_SYSERR if it aborted iteration
 */
int GNUNET_CONTAINER_multihashmap_get_multiple (const struct
                                                GNUNET_CONTAINER_MultiHashMap
                                                *map,
                                                const GNUNET_HashCode * key,
                                                GNUNET_CONTAINER_HashMapIterator
                                                it, void *it_cls);


/* ******************** doubly-linked list *************** */

/**
 * Insert an element into a DLL. Assumes
 * that head, tail and element are structs
 * with prev and next fields.
 *
 * @param head pointer to the head of the DLL
 * @param tail pointer to the tail of the DLL
 * @param element element to insert
 */
#define GNUNET_CONTAINER_DLL_insert(head,tail,element) \
  (element)->next = (head); \
  (element)->prev = NULL; \
  if ((tail) == NULL) \
    (tail) = element; \
  else \
    (head)->prev = element; \
  (head) = (element);

/**
 * Insert an element into a DLL after the given other
 * element.  Insert at the head if the other
 * element is NULL.
 *
 * @param head pointer to the head of the DLL
 * @param tail pointer to the tail of the DLL
 * @param other prior element, NULL for insertion at head of DLL
 * @param element element to insert
 */
#define GNUNET_CONTAINER_DLL_insert_after(head,tail,other,element) \
  (element)->prev = (other); \
  if (NULL == other) \
    { \
      (element)->next = (head); \
      (head) = (element); \
    } \
  else \
    { \
      (element)->next = (other)->next; \
      (other)->next = (element); \
    } \
  if (NULL == (element)->next) \
    (tail) = (element); \
  else \
    (element)->next->prev = (element);




/**
 * Remove an element from a DLL. Assumes
 * that head, tail and element are structs
 * with prev and next fields.
 *
 * @param head pointer to the head of the DLL
 * @param tail pointer to the tail of the DLL
 * @param element element to remove
 */
#define GNUNET_CONTAINER_DLL_remove(head,tail,element) \
  if ((element)->prev == NULL) \
    (head) = (element)->next;  \
  else \
    (element)->prev->next = (element)->next; \
  if ((element)->next == NULL) \
    (tail) = (element)->prev;  \
  else \
    (element)->next->prev = (element)->prev;



/* ******************** Heap *************** */


/**
 * Cost by which elements in a heap can be ordered.
 */
typedef uint64_t GNUNET_CONTAINER_HeapCost;


/*
 * Heap type, either max or min.  Hopefully makes the
 * implementation more useful.
 */
enum GNUNET_CONTAINER_HeapOrder
{
  /**
   * Heap with the maximum cost at the root.
   */
  GNUNET_CONTAINER_HEAP_ORDER_MAX,

  /**
   * Heap with the minimum cost at the root.
   */
  GNUNET_CONTAINER_HEAP_ORDER_MIN
};


/**
 * Handle to a Heap.
 */
struct GNUNET_CONTAINER_Heap;

/**
 * Create a new heap.
 *
 * @param type should the minimum or the maximum element be the root
 * @return NULL on error, otherwise a fresh heap
 */
struct GNUNET_CONTAINER_Heap *GNUNET_CONTAINER_heap_create (enum
                                                            GNUNET_CONTAINER_HeapOrder
                                                            type);


/**
 * Free a heap
 *
 * @param h heap to free.
 */
void GNUNET_CONTAINER_heap_destroy (struct GNUNET_CONTAINER_Heap *h);


/**
 * Function called on elements of a heap.
 *
 * @param cls closure
 * @param element obj stored in heap
 * @param cost cost of the element
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not.
 */
typedef int (*GNUNET_CONTAINER_HeapIterator) (void *cls,
                                              void *element,
                                              GNUNET_CONTAINER_HeapCost cost);


/**
 * Iterate over all entries in the map.
 *
 * @param heap the heap
 * @param iterator function to call on each entry
 * @param iterator_cls closure for iterator
 * @return number of items handled
 *         GNUNET_SYSERR if iteration was aborted by iterator
 */
int GNUNET_CONTAINER_heap_iterate (struct GNUNET_CONTAINER_Heap *heap,
                                   GNUNET_CONTAINER_HeapIterator iterator,
                                   void *iterator_cls);



/**
 * Inserts a new item into the heap, item is always neighbor now.
 * @param heap the heap
 * @param element element to insert
 * @param cost cost of the element
 * @return FIXME
 */
int
GNUNET_CONTAINER_heap_insert (struct GNUNET_CONTAINER_Heap *heap,
                              void *element, GNUNET_CONTAINER_HeapCost cost);


/**
 * Removes root of the tree, is remove max if a max heap and remove min
 * if a min heap, returns the data stored at the node.
 *
 * @param heap the heap
 * @return NULL if the heap is empty
 */
void *GNUNET_CONTAINER_heap_remove_root (struct GNUNET_CONTAINER_Heap *heap);


/**
 * Returns element stored at root of tree, doesn't effect anything
 *
 * @param heap the heap
 * @return NULL if the heap is empty
 */
void *GNUNET_CONTAINER_heap_peek (struct GNUNET_CONTAINER_Heap *heap);


/**
 * Removes any node from the tree based on the neighbor given, does
 * not traverse the tree (backpointers) but may take more time due to
 * percolation of nodes.
 *
 * @param heap the heap
 * @param element the element to remove
 * @return NULL if "element" was not found in the heap, otherwise element
 */
void *GNUNET_CONTAINER_heap_remove_node (struct GNUNET_CONTAINER_Heap *heap,
                                         void *element);


/**
 * Updates the cost of any node in the tree
 *
 * @param heap the heap
 * @param element the element for which the cost is updated
 * @param new_cost new cost for the element
 * @return FIXME
 */
int
GNUNET_CONTAINER_heap_update_cost (struct GNUNET_CONTAINER_Heap *heap,
                                   void *element,
                                   GNUNET_CONTAINER_HeapCost new_cost);


/**
 * Random walk of the tree, returns the data stored at the next random node
 * in the walk.  Calls callee with the data, or NULL if the tree is empty
 * or some other problem crops up.
 *
 * @param heap the heap
 * @return the next element from the random walk
 */
void *GNUNET_CONTAINER_heap_walk_get_next (struct GNUNET_CONTAINER_Heap
                                           *heap);


/**
 * Returns the current size of the heap
 *
 * @param heap the heap to get the size of
 * @return number of elements in the heap
 */
unsigned int
GNUNET_CONTAINER_heap_get_size (struct GNUNET_CONTAINER_Heap *heap);

/* ******************** Singly linked list *************** */

/**
 * Possible ways for how data stored in the linked list
 * might be allocated.
 */ 
enum GNUNET_CONTAINER_SListDisposition
  {
    /**
     * Single-linked list must copy the buffer.
     */
    GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT = 0,

    /**
     * Data is static, no need to copy or free.
     */
    GNUNET_CONTAINER_SLIST_DISPOSITION_STATIC = 2,

    /**
     * Data is dynamic, do not copy but free when done.
     */
    GNUNET_CONTAINER_SLIST_DISPOSITION_DYNAMIC = 4
  };



/**
 * Handle to a singly linked list  
 */
struct GNUNET_CONTAINER_SList;

/**
 * Handle to a singly linked list iterator 
 */
struct GNUNET_CONTAINER_SList_Iterator;


/**
 * Add a new element to the list
 * @param l list
 * @param disp memory disposition
 * @param buf payload buffer
 * @param len length of the buffer
 */
void GNUNET_CONTAINER_slist_add (struct GNUNET_CONTAINER_SList *l, 
				 enum GNUNET_CONTAINER_SListDisposition disp,
				 const void *buf, size_t len);


/**
 * Append a singly linked list to another
 * @param dst list to append to
 * @param src source
 */
void
GNUNET_CONTAINER_slist_append (struct GNUNET_CONTAINER_SList *dst, struct GNUNET_CONTAINER_SList *src);


/**
 * Create a new singly linked list
 * @return the new list
 */
struct GNUNET_CONTAINER_SList *GNUNET_CONTAINER_slist_create (void);


/**
 * Destroy a singly linked list
 * @param l the list to be destroyed
 */
void GNUNET_CONTAINER_slist_destroy (struct GNUNET_CONTAINER_SList *l);


/**
 * Return the beginning of a list
 *
 * @param l list
 * @return iterator pointing to the beginning, free using "GNUNET_free"
 */
struct GNUNET_CONTAINER_SList_Iterator *
GNUNET_CONTAINER_slist_begin(struct GNUNET_CONTAINER_SList *l);


/**
 * Clear a list
 *
 * @param l list
 */
void GNUNET_CONTAINER_slist_clear (struct GNUNET_CONTAINER_SList *l);


/**
 * Check if a list contains a certain element
 * @param l list
 * @param buf payload buffer to find
 * @param len length of the payload (number of bytes in buf)
 */
int GNUNET_CONTAINER_slist_contains (const struct GNUNET_CONTAINER_SList *l, const void *buf, size_t len);


/**
 * Count the elements of a list
 * @param l list
 * @return number of elements in the list
 */
int GNUNET_CONTAINER_slist_count (const struct GNUNET_CONTAINER_SList *l);


/**
 * Remove an element from the list
 * @param i iterator that points to the element to be removed
 */
void GNUNET_CONTAINER_slist_erase (struct GNUNET_CONTAINER_SList_Iterator *i);


/**
 * Insert an element into a list at a specific position
 * @param before where to insert the new element
 * @param disp memory disposition
 * @param buf payload buffer
 * @param len length of the payload
 */
void GNUNET_CONTAINER_slist_insert (struct GNUNET_CONTAINER_SList_Iterator *before,
				    enum GNUNET_CONTAINER_SListDisposition disp,
				    const void *buf, 
				    size_t len);


/**
 * Advance an iterator to the next element
 * @param i iterator
 * @return GNUNET_YES on success, GNUNET_NO if the end has been reached
 */
int GNUNET_CONTAINER_slist_next (struct GNUNET_CONTAINER_SList_Iterator *i);


/**
 * Check if an iterator points beyond the end of a list
 * @param i iterator
 * @return GNUNET_YES if the end has been reached, GNUNET_NO if the iterator
 *         points to a valid element
 */
int GNUNET_CONTAINER_slist_end (struct GNUNET_CONTAINER_SList_Iterator *i);


/**
 * Retrieve the element at a specific position in a list
 *
 * @param i iterator
 * @param len set to the payload length
 * @return payload
 */
const void *
GNUNET_CONTAINER_slist_get (const struct GNUNET_CONTAINER_SList_Iterator *i, 
			    size_t *len);


/**
 * Release an iterator
 * @param i iterator
 */
void GNUNET_CONTAINER_slist_iter_destroy (struct GNUNET_CONTAINER_SList_Iterator *i);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_CONTAINER_LIB_H */
#endif
/* end of gnunet_container_lib.h */
