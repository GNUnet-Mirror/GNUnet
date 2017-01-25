/*
     This file is part of GNUnet.
     Copyright (C) 2001-2015 GNUnet e.V.

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
 * @author Christian Grothoff
 * @author Nils Durner
 *
 * @file
 * Container classes for GNUnet
 *
 * @defgroup hashmap  Container library: MultiHashMap
 * Hash map with multiple values per key.
 *
 * @see [Documentation](https://gnunet.org/util_multihashmap)
 *
 * @defgroup heap  Container library: Heap
 * Min- or max-heap with arbitrary element removal
 *
 * @defgroup bloomfilter  Container library: Bloom filter
 * Probabilistic set tests
 *
 * @defgroup dll  Container library: Doubly-linked list
 *
 * @see [Documentation](https://gnunet.org/mdll-api)
 *
 * @defgroup metadata  Container library: Metadata
 * GNU libextractor key-value pairs
 */

#ifndef GNUNET_CONTAINER_LIB_H
#define GNUNET_CONTAINER_LIB_H

/* add error and config prototypes */
#include "gnunet_crypto_lib.h"


/**
 * Try to compress the given block of data using libz.  Only returns
 * the compressed block if compression worked and the new block is
 * actually smaller.  Decompress using #GNUNET_decompress().
 *
 * @param data block to compress; if compression
 *        resulted in a smaller block, the first
 *        bytes of data are updated to the compressed
 *        data
 * @param old_size number of bytes in data
 * @param[out] result set to the compressed data, if compression worked
 * @param[out] new_size set to size of result, if compression worked
 * @return #GNUNET_YES if compression reduce the size,
 *         #GNUNET_NO if compression did not help
 */
int
GNUNET_try_compression (const char *data,
                        size_t old_size,
                        char **result,
                        size_t *new_size);


/**
 * Decompress input, return the decompressed data as output.  Dual to
 * #GNUNET_try_compression(). Caller must set @a output_size to the
 * number of bytes that were originally compressed.
 *
 * @param input compressed data
 * @param input_size number of bytes in input
 * @param output_size expected size of the output
 * @return NULL on error, buffer of @a output_size decompressed bytes otherwise
 */
char *
GNUNET_decompress (const char *input,
                   size_t input_size,
                   size_t output_size);


#if HAVE_EXTRACTOR_H

#include <extractor.h>

#else

/* definitions from extractor.h we need for the build */

/**
 * Enumeration defining various sources of keywords.  See also
 * http://dublincore.org/documents/1998/09/dces/
 */
enum EXTRACTOR_MetaType {
  EXTRACTOR_METATYPE_RESERVED = 0,
  EXTRACTOR_METATYPE_MIMETYPE = 1,
  EXTRACTOR_METATYPE_FILENAME = 2,
  EXTRACTOR_METATYPE_COMMENT = 3,
  EXTRACTOR_METATYPE_TITLE = 4,
  EXTRACTOR_METATYPE_BOOK_TITLE = 5,
  EXTRACTOR_METATYPE_JOURNAL_NAME = 8,
  EXTRACTOR_METATYPE_AUTHOR_NAME = 13,
  EXTRACTOR_METATYPE_PUBLICATION_DATE = 24,
  EXTRACTOR_METATYPE_URL = 29,
  EXTRACTOR_METATYPE_URI = 30,
  EXTRACTOR_METATYPE_ISRC = 31,
  EXTRACTOR_METATYPE_UNKNOWN = 45,
  EXTRACTOR_METATYPE_DESCRIPTION = 46,
  EXTRACTOR_METATYPE_KEYWORDS = 49,
  EXTRACTOR_METATYPE_SUBJECT = 52,
  EXTRACTOR_METATYPE_PACKAGE_NAME = 69,
  EXTRACTOR_METATYPE_THUMBNAIL = 114,
  EXTRACTOR_METATYPE_ALBUM = 129,
  EXTRACTOR_METATYPE_ARTIST = 130,
  EXTRACTOR_METATYPE_ORIGINAL_TITLE = 162,
  EXTRACTOR_METATYPE_GNUNET_FULL_DATA = 174,
  EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME = 180,

};

/**
 * Format in which the extracted meta data is presented.
 */
enum EXTRACTOR_MetaFormat {
  /**
   * Format is unknown.
   */
  EXTRACTOR_METAFORMAT_UNKNOWN = 0,

  /**
   * 0-terminated, UTF-8 encoded string.  "data_len"
   * is strlen(data)+1.
   */
  EXTRACTOR_METAFORMAT_UTF8 = 1,

  /**
   * Some kind of binary format, see given Mime type.
   */
  EXTRACTOR_METAFORMAT_BINARY = 2,

  /**
   * 0-terminated string.  The specific encoding is unknown.
   * "data_len" is strlen (data)+1.
   */
  EXTRACTOR_METAFORMAT_C_STRING = 3
};


/**
 * Type of a function that libextractor calls for each
 * meta data item found.
 *
 * @param cls closure (user-defined)
 * @param plugin_name name of the plugin that produced this value;
 *        special values can be used (i.e. '&lt;zlib&gt;' for zlib being
 *        used in the main libextractor library and yielding
 *        meta data).
 * @param type libextractor-type describing the meta data
 * @param format basic format information about @a data
 * @param data_mime_type mime-type of @a data (not of the original file);
 *        can be NULL (if mime-type is not known)
 * @param data actual meta-data found
 * @param data_len number of bytes in @a data
 * @return 0 to continue extracting, 1 to abort
 */
typedef int
(*EXTRACTOR_MetaDataProcessor) (void *cls,
                                const char *plugin_name,
                                enum EXTRACTOR_MetaType type,
                                enum EXTRACTOR_MetaFormat format,
                                const char *data_mime_type,
                                const char *data,
                                size_t data_len);

#endif

#ifndef EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME
/* hack for LE < 0.6.3 */
#define EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME 180
#endif

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
 * @ingroup bloomfilter
 */
struct GNUNET_CONTAINER_BloomFilter;


/**
 * @ingroup bloomfilter
 * Iterator over `struct GNUNET_HashCode`.
 *
 * @param cls closure
 * @param next set to the next hash code
 * @return #GNUNET_YES if next was updated
 *         #GNUNET_NO if there are no more entries
 */
typedef int
(*GNUNET_CONTAINER_HashCodeIterator) (void *cls,
                                      struct GNUNET_HashCode *next);


/**
 * @ingroup bloomfilter
 * Load a Bloom filter from a file.
 *
 * @param filename the name of the file (or the prefix)
 * @param size the size of the bloom-filter (number of
 *        bytes of storage space to use); will be rounded up
 *        to next power of 2
 * @param k the number of #GNUNET_CRYPTO_hash-functions to apply per
 *        element (number of bits set per element in the set)
 * @return the bloomfilter
 */
struct GNUNET_CONTAINER_BloomFilter *
GNUNET_CONTAINER_bloomfilter_load (const char *filename,
                                   size_t size,
                                   unsigned int k);


/**
 * @ingroup bloomfilter
 * Create a Bloom filter from raw bits.
 *
 * @param data the raw bits in memory (maybe NULL,
 *        in which case all bits should be considered
 *        to be zero).
 * @param size the size of the bloom-filter (number of
 *        bytes of storage space to use); also size of @a data
 *        -- unless data is NULL.  Must be a power of 2.
 * @param k the number of #GNUNET_CRYPTO_hash-functions to apply per
 *        element (number of bits set per element in the set)
 * @return the bloomfilter
 */
struct GNUNET_CONTAINER_BloomFilter *
GNUNET_CONTAINER_bloomfilter_init (const char *data,
                                   size_t size,
                                   unsigned int k);


/**
 * @ingroup bloomfilter
 * Copy the raw data of this Bloom filter into
 * the given data array.
 *
 * @param data where to write the data
 * @param size the size of the given @a data array
 * @return #GNUNET_SYSERR if the data array of the wrong size
 */
int
GNUNET_CONTAINER_bloomfilter_get_raw_data (const struct GNUNET_CONTAINER_BloomFilter *bf,
                                           char *data,
                                           size_t size);


/**
 * @ingroup bloomfilter
 * Test if an element is in the filter.
 *
 * @param e the element
 * @param bf the filter
 * @return #GNUNET_YES if the element is in the filter, #GNUNET_NO if not
 */
int
GNUNET_CONTAINER_bloomfilter_test (const struct GNUNET_CONTAINER_BloomFilter *bf,
                                   const struct GNUNET_HashCode *e);


/**
 * @ingroup bloomfilter
 * Add an element to the filter.
 *
 * @param bf the filter
 * @param e the element
 */
void
GNUNET_CONTAINER_bloomfilter_add (struct GNUNET_CONTAINER_BloomFilter *bf,
                                  const struct GNUNET_HashCode *e);


/**
 * @ingroup bloomfilter
 * Remove an element from the filter.
 *
 * @param bf the filter
 * @param e the element to remove
 */
void
GNUNET_CONTAINER_bloomfilter_remove (struct GNUNET_CONTAINER_BloomFilter *bf,
                                     const struct GNUNET_HashCode *e);


/**
 * @ingroup bloomfilter
 * Create a copy of a bloomfilter.
 *
 * @param bf the filter
 * @return copy of bf
 */
struct GNUNET_CONTAINER_BloomFilter *
GNUNET_CONTAINER_bloomfilter_copy (const struct GNUNET_CONTAINER_BloomFilter *bf);



/**
 * @ingroup bloomfilter
 * Free the space associcated with a filter
 * in memory, flush to drive if needed (do not
 * free the space on the drive).
 *
 * @param bf the filter
 */
void
GNUNET_CONTAINER_bloomfilter_free (struct GNUNET_CONTAINER_BloomFilter *bf);


/**
 * Get the number of the addresses set per element in the bloom filter.
 *
 * @param bf the filter
 * @return addresses set per element in the bf
 */
size_t
GNUNET_CONTAINER_bloomfilter_get_element_addresses (const struct GNUNET_CONTAINER_BloomFilter *bf);


/**
 * @ingroup bloomfilter
 * Get size of the bloom filter.
 *
 * @param bf the filter
 * @return number of bytes used for the data of the bloom filter
 */
size_t
GNUNET_CONTAINER_bloomfilter_get_size (const struct GNUNET_CONTAINER_BloomFilter *bf);


/**
 * @ingroup bloomfilter
 * Reset a Bloom filter to empty.
 *
 * @param bf the filter
 */
void
GNUNET_CONTAINER_bloomfilter_clear (struct GNUNET_CONTAINER_BloomFilter *bf);


/**
 * @ingroup bloomfilter
 * "or" the entries of the given raw data array with the
 * data of the given Bloom filter.  Assumes that
 * the @a size of the @a data array and the current filter
 * match.
 *
 * @param bf the filter
 * @param data data to OR-in
 * @param size size of @a data
 * @return #GNUNET_OK on success
 */
int
GNUNET_CONTAINER_bloomfilter_or (struct GNUNET_CONTAINER_BloomFilter *bf,
                                 const char *data, size_t size);


/**
 * @ingroup bloomfilter
 * "or" the entries of the given raw data array with the
 * data of the given Bloom filter.  Assumes that
 * the size of the two filters matches.
 *
 * @param bf the filter
 * @param to_or the bloomfilter to or-in
 * @return #GNUNET_OK on success
 */
int
GNUNET_CONTAINER_bloomfilter_or2 (struct GNUNET_CONTAINER_BloomFilter *bf,
                                  const struct GNUNET_CONTAINER_BloomFilter *to_or);


/**
 * @ingroup bloomfilter
 * Resize a bloom filter.  Note that this operation
 * is pretty costly.  Essentially, the Bloom filter
 * needs to be completely re-build.
 *
 * @param bf the filter
 * @param iterator an iterator over all elements stored in the BF
 * @param iterator_cls closure for @a iterator
 * @param size the new size for the filter
 * @param k the new number of #GNUNET_CRYPTO_hash-function to apply per element
 */
void
GNUNET_CONTAINER_bloomfilter_resize (struct GNUNET_CONTAINER_BloomFilter *bf,
                                     GNUNET_CONTAINER_HashCodeIterator iterator,
                                     void *iterator_cls,
                                     size_t size,
                                     unsigned int k);


/* ****************** metadata ******************* */

/**
 * @ingroup metadata
 * Meta data to associate with a file, directory or namespace.
 */
struct GNUNET_CONTAINER_MetaData;


/**
 * @ingroup metadata
 * Create a fresh meta data container.
 *
 * @return empty meta-data container
 */
struct GNUNET_CONTAINER_MetaData *
GNUNET_CONTAINER_meta_data_create (void);


/**
 * @ingroup metadata
 * Duplicate a MetaData token.
 *
 * @param md what to duplicate
 * @return duplicate meta-data container
 */
struct GNUNET_CONTAINER_MetaData *
GNUNET_CONTAINER_meta_data_duplicate (const struct GNUNET_CONTAINER_MetaData *md);


/**
 * @ingroup metadata
 * Free meta data.
 *
 * @param md what to free
 */
void
GNUNET_CONTAINER_meta_data_destroy (struct GNUNET_CONTAINER_MetaData *md);


/**
 * @ingroup metadata
 * Test if two MDs are equal. We consider them equal if
 * the meta types, formats and content match (we do not
 * include the mime types and plugins names in this
 * consideration).
 *
 * @param md1 first value to check
 * @param md2 other value to check
 * @return #GNUNET_YES if they are equal
 */
int
GNUNET_CONTAINER_meta_data_test_equal (const struct GNUNET_CONTAINER_MetaData *md1,
                                       const struct GNUNET_CONTAINER_MetaData *md2);


/**
 * @ingroup metadata
 * Extend metadata.
 *
 * @param md metadata to extend
 * @param plugin_name name of the plugin that produced this value;
 *        special values can be used (i.e. '&lt;zlib&gt;' for zlib being
 *        used in the main libextractor library and yielding
 *        meta data).
 * @param type libextractor-type describing the meta data
 * @param format basic format information about data
 * @param data_mime_type mime-type of data (not of the original file);
 *        can be NULL (if mime-type is not known)
 * @param data actual meta-data found
 * @param data_size number of bytes in data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if this entry already exists
 *         data_mime_type and plugin_name are not considered for "exists" checks
 */
int
GNUNET_CONTAINER_meta_data_insert (struct GNUNET_CONTAINER_MetaData *md,
                                   const char *plugin_name,
                                   enum EXTRACTOR_MetaType type,
                                   enum EXTRACTOR_MetaFormat format,
                                   const char *data_mime_type,
                                   const char *data,
                                   size_t data_size);


/**
 * @ingroup metadata
 * Extend metadata.  Merges the meta data from the second argument
 * into the first, discarding duplicate key-value pairs.
 *
 * @param md metadata to extend
 * @param in metadata to merge
 */
void
GNUNET_CONTAINER_meta_data_merge (struct GNUNET_CONTAINER_MetaData *md,
                                  const struct GNUNET_CONTAINER_MetaData *in);


/**
 * @ingroup metadata
 * Remove an item.
 *
 * @param md metadata to manipulate
 * @param type type of the item to remove
 * @param data specific value to remove, NULL to remove all
 *        entries of the given type
 * @param data_size number of bytes in data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the item does not exist in md
 */
int
GNUNET_CONTAINER_meta_data_delete (struct GNUNET_CONTAINER_MetaData *md,
                                   enum EXTRACTOR_MetaType type,
                                   const char *data,
                                   size_t data_size);


/**
 * @ingroup metadata
 * Remove all items in the container.
 *
 * @param md metadata to manipulate
 */
void
GNUNET_CONTAINER_meta_data_clear (struct GNUNET_CONTAINER_MetaData *md);


/**
 * @ingroup metadata
 * Add the current time as the publication date
 * to the meta-data.
 *
 * @param md metadata to modify
 */
void
GNUNET_CONTAINER_meta_data_add_publication_date (struct GNUNET_CONTAINER_MetaData *md);


/**
 * @ingroup metadata
 * Iterate over MD entries.
 *
 * @param md metadata to inspect
 * @param iter function to call on each entry, return 0 to continue to iterate
 *             and 1 to abort iteration in this function (GNU libextractor API!)
 * @param iter_cls closure for @a iter
 * @return number of entries
 */
int
GNUNET_CONTAINER_meta_data_iterate (const struct GNUNET_CONTAINER_MetaData *md,
                                    EXTRACTOR_MetaDataProcessor iter,
                                    void *iter_cls);


/**
 * @ingroup metadata
 * Get the first MD entry of the given type.  Caller
 * is responsible for freeing the return value.
 * Also, only meta data items that are strings (0-terminated)
 * are returned by this function.
 *
 * @param md metadata to inspect
 * @param type type to look for
 * @return NULL if no entry was found
 */
char *
GNUNET_CONTAINER_meta_data_get_by_type (const struct GNUNET_CONTAINER_MetaData *md,
                                        enum EXTRACTOR_MetaType type);


/**
 * @ingroup metadata
 * Get the first matching MD entry of the given types. Caller is
 * responsible for freeing the return value.  Also, only meta data
 * items that are strings (0-terminated) are returned by this
 * function.
 *
 * @param md metadata to inspect
 * @param ... -1-terminated list of types
 * @return NULL if we do not have any such entry,
 *  otherwise client is responsible for freeing the value!
 */
char *
GNUNET_CONTAINER_meta_data_get_first_by_types (const struct GNUNET_CONTAINER_MetaData *md,
                                               ...);

/**
 * @ingroup metadata
 * Get a thumbnail from the meta-data (if present).  Only matches meta
 * data with mime type "image" and binary format.
 *
 * @param md metadata to inspect
 * @param thumb will be set to the thumbnail data.  Must be
 *        freed by the caller!
 * @return number of bytes in thumbnail, 0 if not available
 */
size_t
GNUNET_CONTAINER_meta_data_get_thumbnail (const struct GNUNET_CONTAINER_MetaData *md,
                                          unsigned char **thumb);



/**
 * @ingroup metadata
 * Options for metadata serialization.
 */
enum GNUNET_CONTAINER_MetaDataSerializationOptions
{
  /**
   * @ingroup metadata
   * Serialize all of the data.
   */
  GNUNET_CONTAINER_META_DATA_SERIALIZE_FULL = 0,

  /**
   * @ingroup metadata
   * If not enough space is available, it is acceptable
   * to only serialize some of the metadata.
   */
  GNUNET_CONTAINER_META_DATA_SERIALIZE_PART = 1,

  /**
   * @ingroup metadata
   * Speed is of the essence, do not allow compression.
   */
  GNUNET_CONTAINER_META_DATA_SERIALIZE_NO_COMPRESS = 2
};


/**
 * @ingroup metadata
 * Serialize meta-data to target.
 *
 * @param md metadata to serialize
 * @param target where to write the serialized metadata;
 *         *target can be NULL, in which case memory is allocated
 * @param max maximum number of bytes available
 * @param opt is it ok to just write SOME of the
 *        meta-data to match the size constraint,
 *        possibly discarding some data?
 * @return number of bytes written on success,
 *         -1 on error (typically: not enough
 *         space)
 */
ssize_t
GNUNET_CONTAINER_meta_data_serialize (const struct GNUNET_CONTAINER_MetaData *md,
                                      char **target,
                                      size_t max,
                                      enum GNUNET_CONTAINER_MetaDataSerializationOptions opt);


/**
 * @ingroup metadata
 * Get the size of the full meta-data in serialized form.
 *
 * @param md metadata to inspect
 * @return number of bytes needed for serialization, -1 on error
 */
ssize_t
GNUNET_CONTAINER_meta_data_get_serialized_size (const struct GNUNET_CONTAINER_MetaData *md);


/**
 * @ingroup metadata
 * Deserialize meta-data.  Initializes md.
 *
 * @param input serialized meta-data.
 * @param size number of bytes available
 * @return MD on success, NULL on error (i.e.
 *         bad format)
 */
struct GNUNET_CONTAINER_MetaData *
GNUNET_CONTAINER_meta_data_deserialize (const char *input,
                                        size_t size);


/* ******************************* HashMap **************************** */

/**
 * @ingroup hashmap
 * Opaque handle for a HashMap.
 */
struct GNUNET_CONTAINER_MultiHashMap;

/**
 * @ingroup hashmap
 * Opaque handle to an iterator over
 * a multihashmap.
 */
struct GNUNET_CONTAINER_MultiHashMapIterator;

/**
 * @ingroup hashmap
 * Options for storing values in the HashMap.
 */
enum GNUNET_CONTAINER_MultiHashMapOption
{

  /**
   * @ingroup hashmap
   * If a value with the given key exists, replace it.  Note that the
   * old value would NOT be freed by replace (the application has to
   * make sure that this happens if required).
   */
  GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE,

  /**
   * @ingroup hashmap
   * Allow multiple values with the same key.
   */
  GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE,

  /**
   * @ingroup hashmap
   * There must only be one value per key; storing a value should fail
   * if a value under the same key already exists.
   */
  GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY,

  /**
   * @ingroup hashmap There must only be one value per key, but don't
   * bother checking if a value already exists (faster than
   * #GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY; implemented
   * just like #GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE but this
   * option documents better what is intended if
   * #GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY is what is
   * desired).
   */
  GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST
};


/**
 * @ingroup hashmap
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
typedef int
(*GNUNET_CONTAINER_HashMapIterator) (void *cls,
                                     const struct GNUNET_HashCode *key,
                                     void *value);


/**
 * @ingroup hashmap
 * Create a multi hash map.
 *
 * @param len initial size (map will grow as needed)
 * @param do_not_copy_keys #GNUNET_NO is always safe and should be used by default;
 *                         #GNUNET_YES means that on 'put', the 'key' does not have
 *                         to be copied as the destination of the pointer is
 *                         guaranteed to be life as long as the value is stored in
 *                         the hashmap.  This can significantly reduce memory
 *                         consumption, but of course is also a recipie for
 *                         heap corruption if the assumption is not true.  Only
 *                         use this if (1) memory use is important in this case and
 *                         (2) you have triple-checked that the invariant holds
 * @return NULL on error
 */
struct GNUNET_CONTAINER_MultiHashMap *
GNUNET_CONTAINER_multihashmap_create (unsigned int len,
				      int do_not_copy_keys);


/**
 * @ingroup hashmap
 * Destroy a hash map.  Will not free any values
 * stored in the hash map!
 *
 * @param map the map
 */
void
GNUNET_CONTAINER_multihashmap_destroy (struct GNUNET_CONTAINER_MultiHashMap *map);


/**
 * @ingroup hashmap
 * Given a key find a value in the map matching the key.
 *
 * @param map the map
 * @param key what to look for
 * @return NULL if no value was found; note that
 *   this is indistinguishable from values that just
 *   happen to be NULL; use "contains" to test for
 *   key-value pairs with value NULL
 */
void *
GNUNET_CONTAINER_multihashmap_get (const struct GNUNET_CONTAINER_MultiHashMap *map,
                                   const struct GNUNET_HashCode *key);


/**
 * @ingroup hashmap
 * Remove the given key-value pair from the map.  Note that if the
 * key-value pair is in the map multiple times, only one of the pairs
 * will be removed.
 *
 * @param map the map
 * @param key key of the key-value pair
 * @param value value of the key-value pair
 * @return #GNUNET_YES on success, #GNUNET_NO if the key-value pair
 *  is not in the map
 */
int
GNUNET_CONTAINER_multihashmap_remove (struct GNUNET_CONTAINER_MultiHashMap *map,
                                      const struct GNUNET_HashCode *key,
				      const void *value);

/**
 * @ingroup hashmap
 * Remove all entries for the given key from the map.
 * Note that the values would not be "freed".
 *
 * @param map the map
 * @param key identifies values to be removed
 * @return number of values removed
 */
int
GNUNET_CONTAINER_multihashmap_remove_all (struct GNUNET_CONTAINER_MultiHashMap *map,
                                          const struct GNUNET_HashCode *key);


/**
 * @ingroup hashmap
 * Remove all entries from the map.
 * Note that the values would not be "freed".
 *
 * @param map the map
 * @return number of values removed
 */
unsigned int
GNUNET_CONTAINER_multihashmap_clear (struct GNUNET_CONTAINER_MultiHashMap *map);


/**
 * @ingroup hashmap
 * Check if the map contains any value under the given
 * key (including values that are NULL).
 *
 * @param map the map
 * @param key the key to test if a value exists for it
 * @return #GNUNET_YES if such a value exists,
 *         #GNUNET_NO if not
 */
int
GNUNET_CONTAINER_multihashmap_contains (const struct GNUNET_CONTAINER_MultiHashMap *map,
                                        const struct GNUNET_HashCode * key);


/**
 * @ingroup hashmap
 * Check if the map contains the given value under the given
 * key.
 *
 * @param map the map
 * @param key the key to test if a value exists for it
 * @param value value to test for
 * @return #GNUNET_YES if such a value exists,
 *         #GNUNET_NO if not
 */
int
GNUNET_CONTAINER_multihashmap_contains_value (const struct GNUNET_CONTAINER_MultiHashMap *map,
                                              const struct GNUNET_HashCode *key,
                                              const void *value);


/**
 * @ingroup hashmap
 * Store a key-value pair in the map.
 *
 * @param map the map
 * @param key key to use
 * @param value value to use
 * @param opt options for put
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if a value was replaced (with REPLACE)
 *         #GNUNET_SYSERR if #GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY was the option and the
 *                       value already exists
 */
int
GNUNET_CONTAINER_multihashmap_put (struct GNUNET_CONTAINER_MultiHashMap *map,
                                   const struct GNUNET_HashCode *key,
                                   void *value,
                                   enum GNUNET_CONTAINER_MultiHashMapOption
                                   opt);

/**
 * @ingroup hashmap
 * Get the number of key-value pairs in the map.
 *
 * @param map the map
 * @return the number of key value pairs
 */
unsigned int
GNUNET_CONTAINER_multihashmap_size (const struct GNUNET_CONTAINER_MultiHashMap *map);


/**
 * @ingroup hashmap
 * Iterate over all entries in the map.
 *
 * @param map the map
 * @param it function to call on each entry
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed,
 *         #GNUNET_SYSERR if it aborted iteration
 */
int
GNUNET_CONTAINER_multihashmap_iterate (const struct GNUNET_CONTAINER_MultiHashMap *map,
                                       GNUNET_CONTAINER_HashMapIterator it,
                                       void *it_cls);


/**
 * @ingroup hashmap
 * Create an iterator for a multihashmap.
 * The iterator can be used to retrieve all the elements in the multihashmap
 * one by one, without having to handle all elements at once (in contrast to
 * #GNUNET_CONTAINER_multihashmap_iterate).  Note that the iterator can not be
 * used anymore if elements have been removed from 'map' after the creation of
 * the iterator, or 'map' has been destroyed.  Adding elements to 'map' may
 * result in skipped or repeated elements.
 *
 * @param map the map to create an iterator for
 * @return an iterator over the given multihashmap @a map
 */
struct GNUNET_CONTAINER_MultiHashMapIterator *
GNUNET_CONTAINER_multihashmap_iterator_create (const struct GNUNET_CONTAINER_MultiHashMap *map);


/**
 * @ingroup hashmap
 * Retrieve the next element from the hash map at the iterator's
 * position.  If there are no elements left, #GNUNET_NO is returned,
 * and @a key and @a value are not modified.  This operation is only
 * allowed if no elements have been removed from the multihashmap
 * since the creation of @a iter, and the map has not been destroyed.
 * Adding elements may result in repeating or skipping elements.
 *
 * @param iter the iterator to get the next element from
 * @param key pointer to store the key in, can be NULL
 * @param value pointer to store the value in, can be NULL
 * @return #GNUNET_YES we returned an element,
 *         #GNUNET_NO if we are out of elements
 */
int
GNUNET_CONTAINER_multihashmap_iterator_next (struct GNUNET_CONTAINER_MultiHashMapIterator *iter,
                                             struct GNUNET_HashCode *key,
                                             const void **value);


/**
 * @ingroup hashmap
 * Destroy a multihashmap iterator.
 *
 * @param iter the iterator to destroy
 */
void
GNUNET_CONTAINER_multihashmap_iterator_destroy (struct GNUNET_CONTAINER_MultiHashMapIterator *iter);


/**
 * @ingroup hashmap
 * Iterate over all entries in the map that match a particular key.
 *
 * @param map the map
 * @param key key that the entries must correspond to
 * @param it function to call on each entry
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed,
 *         #GNUNET_SYSERR if it aborted iteration
 */
int
GNUNET_CONTAINER_multihashmap_get_multiple (const struct GNUNET_CONTAINER_MultiHashMap *map,
                                            const struct GNUNET_HashCode *key,
                                            GNUNET_CONTAINER_HashMapIterator it,
                                            void *it_cls);


/**
 * @ingroup hashmap
 * Call @a it on a random value from the map, or not at all
 * if the map is empty.  Note that this function has linear
 * complexity (in the size of the map).
 *
 * @param map the map
 * @param it function to call on a random entry
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed, zero or one.
 */
unsigned int
GNUNET_CONTAINER_multihashmap_get_random (const struct GNUNET_CONTAINER_MultiHashMap *map,
                                          GNUNET_CONTAINER_HashMapIterator it,
                                          void *it_cls);


/* ***************** Version of Multihashmap for peer identities ****************** */

/**
 * @ingroup hashmap
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current public key
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
typedef int
(*GNUNET_CONTAINER_PeerMapIterator) (void *cls,
                                     const struct GNUNET_PeerIdentity *key,
                                     void *value);


/**
 * Hash map from peer identities to values.
 */
struct GNUNET_CONTAINER_MultiPeerMap;


/**
 * @ingroup hashmap
 * Create a multi peer map (hash map for public keys of peers).
 *
 * @param len initial size (map will grow as needed)
 * @param do_not_copy_keys #GNUNET_NO is always safe and should be used by default;
 *                         #GNUNET_YES means that on 'put', the 'key' does not have
 *                         to be copied as the destination of the pointer is
 *                         guaranteed to be life as long as the value is stored in
 *                         the hashmap.  This can significantly reduce memory
 *                         consumption, but of course is also a recipie for
 *                         heap corruption if the assumption is not true.  Only
 *                         use this if (1) memory use is important in this case and
 *                         (2) you have triple-checked that the invariant holds
 * @return NULL on error
 */
struct GNUNET_CONTAINER_MultiPeerMap *
GNUNET_CONTAINER_multipeermap_create (unsigned int len,
				      int do_not_copy_keys);


/**
 * @ingroup hashmap
 * Destroy a hash map.  Will not free any values
 * stored in the hash map!
 *
 * @param map the map
 */
void
GNUNET_CONTAINER_multipeermap_destroy (struct GNUNET_CONTAINER_MultiPeerMap *map);


/**
 * @ingroup hashmap
 * Given a key find a value in the map matching the key.
 *
 * @param map the map
 * @param key what to look for
 * @return NULL if no value was found; note that
 *   this is indistinguishable from values that just
 *   happen to be NULL; use "contains" to test for
 *   key-value pairs with value NULL
 */
void *
GNUNET_CONTAINER_multipeermap_get (const struct GNUNET_CONTAINER_MultiPeerMap *map,
                                   const struct GNUNET_PeerIdentity *key);


/**
 * @ingroup hashmap
 * Remove the given key-value pair from the map.  Note that if the
 * key-value pair is in the map multiple times, only one of the pairs
 * will be removed.
 *
 * @param map the map
 * @param key key of the key-value pair
 * @param value value of the key-value pair
 * @return #GNUNET_YES on success, #GNUNET_NO if the key-value pair
 *  is not in the map
 */
int
GNUNET_CONTAINER_multipeermap_remove (struct GNUNET_CONTAINER_MultiPeerMap *map,
                                      const struct GNUNET_PeerIdentity * key,
				      const void *value);

/**
 * @ingroup hashmap
 * Remove all entries for the given key from the map.
 * Note that the values would not be "freed".
 *
 * @param map the map
 * @param key identifies values to be removed
 * @return number of values removed
 */
int
GNUNET_CONTAINER_multipeermap_remove_all (struct GNUNET_CONTAINER_MultiPeerMap *map,
                                          const struct GNUNET_PeerIdentity *key);


/**
 * @ingroup hashmap
 * Check if the map contains any value under the given
 * key (including values that are NULL).
 *
 * @param map the map
 * @param key the key to test if a value exists for it
 * @return #GNUNET_YES if such a value exists,
 *         #GNUNET_NO if not
 */
int
GNUNET_CONTAINER_multipeermap_contains (const struct GNUNET_CONTAINER_MultiPeerMap *map,
                                        const struct GNUNET_PeerIdentity *key);


/**
 * @ingroup hashmap
 * Check if the map contains the given value under the given
 * key.
 *
 * @param map the map
 * @param key the key to test if a value exists for it
 * @param value value to test for
 * @return #GNUNET_YES if such a value exists,
 *         #GNUNET_NO if not
 */
int
GNUNET_CONTAINER_multipeermap_contains_value (const struct GNUNET_CONTAINER_MultiPeerMap *map,
                                              const struct GNUNET_PeerIdentity * key,
                                              const void *value);


/**
 * @ingroup hashmap
 * Store a key-value pair in the map.
 *
 * @param map the map
 * @param key key to use
 * @param value value to use
 * @param opt options for put
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if a value was replaced (with REPLACE)
 *         #GNUNET_SYSERR if #GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY was the option and the
 *                       value already exists
 */
int
GNUNET_CONTAINER_multipeermap_put (struct GNUNET_CONTAINER_MultiPeerMap *map,
                                   const struct GNUNET_PeerIdentity *key,
                                   void *value,
                                   enum GNUNET_CONTAINER_MultiHashMapOption opt);


/**
 * @ingroup hashmap
 * Get the number of key-value pairs in the map.
 *
 * @param map the map
 * @return the number of key value pairs
 */
unsigned int
GNUNET_CONTAINER_multipeermap_size (const struct GNUNET_CONTAINER_MultiPeerMap *map);


/**
 * @ingroup hashmap
 * Iterate over all entries in the map.
 *
 * @param map the map
 * @param it function to call on each entry
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed,
 *         #GNUNET_SYSERR if it aborted iteration
 */
int
GNUNET_CONTAINER_multipeermap_iterate (const struct GNUNET_CONTAINER_MultiPeerMap *map,
                                       GNUNET_CONTAINER_PeerMapIterator it,
                                       void *it_cls);


struct GNUNET_CONTAINER_MultiPeerMapIterator;
/**
 * @ingroup hashmap
 * Create an iterator for a multihashmap.
 * The iterator can be used to retrieve all the elements in the multihashmap
 * one by one, without having to handle all elements at once (in contrast to
 * #GNUNET_CONTAINER_multipeermap_iterate).  Note that the iterator can not be
 * used anymore if elements have been removed from @a map after the creation of
 * the iterator, or 'map' has been destroyed.  Adding elements to @a map may
 * result in skipped or repeated elements.
 *
 * @param map the map to create an iterator for
 * @return an iterator over the given multihashmap @a map
 */
struct GNUNET_CONTAINER_MultiPeerMapIterator *
GNUNET_CONTAINER_multipeermap_iterator_create (const struct GNUNET_CONTAINER_MultiPeerMap *map);


/**
 * @ingroup hashmap
 * Retrieve the next element from the hash map at the iterator's
 * position.  If there are no elements left, #GNUNET_NO is returned,
 * and @a key and @a value are not modified.  This operation is only
 * allowed if no elements have been removed from the multihashmap
 * since the creation of @a iter, and the map has not been destroyed.
 * Adding elements may result in repeating or skipping elements.
 *
 * @param iter the iterator to get the next element from
 * @param key pointer to store the key in, can be NULL
 * @param value pointer to store the value in, can be NULL
 * @return #GNUNET_YES we returned an element,
 *         #GNUNET_NO if we are out of elements
 */
int
GNUNET_CONTAINER_multipeermap_iterator_next (struct GNUNET_CONTAINER_MultiPeerMapIterator *iter,
                                             struct GNUNET_PeerIdentity *key,
                                             const void **value);


/**
 * @ingroup hashmap
 * Destroy a multipeermap iterator.
 *
 * @param iter the iterator to destroy
 */
void
GNUNET_CONTAINER_multipeermap_iterator_destroy (struct GNUNET_CONTAINER_MultiPeerMapIterator *iter);


/**
 * @ingroup hashmap
 * Iterate over all entries in the map that match a particular key.
 *
 * @param map the map
 * @param key public key that the entries must correspond to
 * @param it function to call on each entry
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed,
 *         #GNUNET_SYSERR if it aborted iteration
 */
int
GNUNET_CONTAINER_multipeermap_get_multiple (const struct GNUNET_CONTAINER_MultiPeerMap *map,
                                            const struct GNUNET_PeerIdentity *key,
                                            GNUNET_CONTAINER_PeerMapIterator it,
                                            void *it_cls);


/**
 * @ingroup hashmap
 * Call @a it on a random value from the map, or not at all
 * if the map is empty.  Note that this function has linear
 * complexity (in the size of the map).
 *
 * @param map the map
 * @param it function to call on a random entry
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed, zero or one.
 */
unsigned int
GNUNET_CONTAINER_multipeermap_get_random (const struct GNUNET_CONTAINER_MultiPeerMap *map,
                                          GNUNET_CONTAINER_PeerMapIterator it,
                                          void *it_cls);


/* ***************** Version of Multihashmap for short hashes ****************** */

/**
 * @ingroup hashmap
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current public key
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
typedef int
(*GNUNET_CONTAINER_ShortmapIterator) (void *cls,
                                     const struct GNUNET_ShortHashCode *key,
                                     void *value);


/**
 * Hash map from peer identities to values.
 */
struct GNUNET_CONTAINER_MultiShortmap;


/**
 * @ingroup hashmap
 * Create a multi peer map (hash map for public keys of peers).
 *
 * @param len initial size (map will grow as needed)
 * @param do_not_copy_keys #GNUNET_NO is always safe and should be used by default;
 *                         #GNUNET_YES means that on 'put', the 'key' does not have
 *                         to be copied as the destination of the pointer is
 *                         guaranteed to be life as long as the value is stored in
 *                         the hashmap.  This can significantly reduce memory
 *                         consumption, but of course is also a recipie for
 *                         heap corruption if the assumption is not true.  Only
 *                         use this if (1) memory use is important in this case and
 *                         (2) you have triple-checked that the invariant holds
 * @return NULL on error
 */
struct GNUNET_CONTAINER_MultiShortmap *
GNUNET_CONTAINER_multishortmap_create (unsigned int len,
                                       int do_not_copy_keys);


/**
 * @ingroup hashmap
 * Destroy a hash map.  Will not free any values
 * stored in the hash map!
 *
 * @param map the map
 */
void
GNUNET_CONTAINER_multishortmap_destroy (struct GNUNET_CONTAINER_MultiShortmap *map);


/**
 * @ingroup hashmap
 * Given a key find a value in the map matching the key.
 *
 * @param map the map
 * @param key what to look for
 * @return NULL if no value was found; note that
 *   this is indistinguishable from values that just
 *   happen to be NULL; use "contains" to test for
 *   key-value pairs with value NULL
 */
void *
GNUNET_CONTAINER_multishortmap_get (const struct GNUNET_CONTAINER_MultiShortmap *map,
                                    const struct GNUNET_ShortHashCode *key);


/**
 * @ingroup hashmap
 * Remove the given key-value pair from the map.  Note that if the
 * key-value pair is in the map multiple times, only one of the pairs
 * will be removed.
 *
 * @param map the map
 * @param key key of the key-value pair
 * @param value value of the key-value pair
 * @return #GNUNET_YES on success, #GNUNET_NO if the key-value pair
 *  is not in the map
 */
int
GNUNET_CONTAINER_multishortmap_remove (struct GNUNET_CONTAINER_MultiShortmap *map,
                                       const struct GNUNET_ShortHashCode * key,
                                       const void *value);

/**
 * @ingroup hashmap
 * Remove all entries for the given key from the map.
 * Note that the values would not be "freed".
 *
 * @param map the map
 * @param key identifies values to be removed
 * @return number of values removed
 */
int
GNUNET_CONTAINER_multishortmap_remove_all (struct GNUNET_CONTAINER_MultiShortmap *map,
                                           const struct GNUNET_ShortHashCode *key);


/**
 * @ingroup hashmap
 * Check if the map contains any value under the given
 * key (including values that are NULL).
 *
 * @param map the map
 * @param key the key to test if a value exists for it
 * @return #GNUNET_YES if such a value exists,
 *         #GNUNET_NO if not
 */
int
GNUNET_CONTAINER_multishortmap_contains (const struct GNUNET_CONTAINER_MultiShortmap *map,
                                         const struct GNUNET_ShortHashCode *key);


/**
 * @ingroup hashmap
 * Check if the map contains the given value under the given
 * key.
 *
 * @param map the map
 * @param key the key to test if a value exists for it
 * @param value value to test for
 * @return #GNUNET_YES if such a value exists,
 *         #GNUNET_NO if not
 */
int
GNUNET_CONTAINER_multishortmap_contains_value (const struct GNUNET_CONTAINER_MultiShortmap *map,
                                               const struct GNUNET_ShortHashCode * key,
                                               const void *value);


/**
 * @ingroup hashmap
 * Store a key-value pair in the map.
 *
 * @param map the map
 * @param key key to use
 * @param value value to use
 * @param opt options for put
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if a value was replaced (with REPLACE)
 *         #GNUNET_SYSERR if #GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY was the option and the
 *                       value already exists
 */
int
GNUNET_CONTAINER_multishortmap_put (struct GNUNET_CONTAINER_MultiShortmap *map,
                                    const struct GNUNET_ShortHashCode *key,
                                    void *value,
                                    enum GNUNET_CONTAINER_MultiHashMapOption opt);


/**
 * @ingroup hashmap
 * Get the number of key-value pairs in the map.
 *
 * @param map the map
 * @return the number of key value pairs
 */
unsigned int
GNUNET_CONTAINER_multishortmap_size (const struct GNUNET_CONTAINER_MultiShortmap *map);


/**
 * @ingroup hashmap
 * Iterate over all entries in the map.
 *
 * @param map the map
 * @param it function to call on each entry
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed,
 *         #GNUNET_SYSERR if it aborted iteration
 */
int
GNUNET_CONTAINER_multishortmap_iterate (const struct GNUNET_CONTAINER_MultiShortmap *map,
                                        GNUNET_CONTAINER_ShortmapIterator it,
                                        void *it_cls);


struct GNUNET_CONTAINER_MultiShortmapIterator;


/**
 * @ingroup hashmap
 * Create an iterator for a multihashmap.
 * The iterator can be used to retrieve all the elements in the multihashmap
 * one by one, without having to handle all elements at once (in contrast to
 * #GNUNET_CONTAINER_multishortmap_iterate).  Note that the iterator can not be
 * used anymore if elements have been removed from @a map after the creation of
 * the iterator, or 'map' has been destroyed.  Adding elements to @a map may
 * result in skipped or repeated elements.
 *
 * @param map the map to create an iterator for
 * @return an iterator over the given multihashmap @a map
 */
struct GNUNET_CONTAINER_MultiShortmapIterator *
GNUNET_CONTAINER_multishortmap_iterator_create (const struct GNUNET_CONTAINER_MultiShortmap *map);


/**
 * @ingroup hashmap
 * Retrieve the next element from the hash map at the iterator's
 * position.  If there are no elements left, #GNUNET_NO is returned,
 * and @a key and @a value are not modified.  This operation is only
 * allowed if no elements have been removed from the multihashmap
 * since the creation of @a iter, and the map has not been destroyed.
 * Adding elements may result in repeating or skipping elements.
 *
 * @param iter the iterator to get the next element from
 * @param key pointer to store the key in, can be NULL
 * @param value pointer to store the value in, can be NULL
 * @return #GNUNET_YES we returned an element,
 *         #GNUNET_NO if we are out of elements
 */
int
GNUNET_CONTAINER_multishortmap_iterator_next (struct GNUNET_CONTAINER_MultiShortmapIterator *iter,
                                              struct GNUNET_ShortHashCode *key,
                                              const void **value);


/**
 * @ingroup hashmap
 * Destroy a multishortmap iterator.
 *
 * @param iter the iterator to destroy
 */
void
GNUNET_CONTAINER_multishortmap_iterator_destroy (struct GNUNET_CONTAINER_MultiShortmapIterator *iter);


/**
 * @ingroup hashmap
 * Iterate over all entries in the map that match a particular key.
 *
 * @param map the map
 * @param key public key that the entries must correspond to
 * @param it function to call on each entry
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed,
 *         #GNUNET_SYSERR if it aborted iteration
 */
int
GNUNET_CONTAINER_multishortmap_get_multiple (const struct GNUNET_CONTAINER_MultiShortmap *map,
                                             const struct GNUNET_ShortHashCode *key,
                                             GNUNET_CONTAINER_ShortmapIterator it,
                                             void *it_cls);


/**
 * @ingroup hashmap
 * Call @a it on a random value from the map, or not at all
 * if the map is empty.  Note that this function has linear
 * complexity (in the size of the map).
 *
 * @param map the map
 * @param it function to call on a random entry
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed, zero or one.
 */
unsigned int
GNUNET_CONTAINER_multishortmap_get_random (const struct GNUNET_CONTAINER_MultiShortmap *map,
                                          GNUNET_CONTAINER_ShortmapIterator it,
                                          void *it_cls);


/* Version of multihashmap with 32 bit keys */

/**
 * @ingroup hashmap
 * Opaque handle for the 32-bit key HashMap.
 */
struct GNUNET_CONTAINER_MultiHashMap32;


/**
 * @ingroup hashmap
 * Opaque handle to an iterator over
 * a 32-bit key multihashmap.
 */
struct GNUNET_CONTAINER_MultiHashMap32Iterator;


/**
 * @ingroup hashmap
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
typedef int (*GNUNET_CONTAINER_HashMapIterator32) (void *cls,
                                                   uint32_t key,
                                                   void *value);


/**
 * @ingroup hashmap
 * Create a 32-bit key multi hash map.
 *
 * @param len initial size (map will grow as needed)
 * @return NULL on error
 */
struct GNUNET_CONTAINER_MultiHashMap32 *
GNUNET_CONTAINER_multihashmap32_create (unsigned int len);


/**
 * @ingroup hashmap
 * Destroy a 32-bit key hash map.  Will not free any values
 * stored in the hash map!
 *
 * @param map the map
 */
void
GNUNET_CONTAINER_multihashmap32_destroy (struct GNUNET_CONTAINER_MultiHashMap32
                                         *map);


/**
 * @ingroup hashmap
 * Get the number of key-value pairs in the map.
 *
 * @param map the map
 * @return the number of key value pairs
 */
unsigned int
GNUNET_CONTAINER_multihashmap32_size (const struct
                                      GNUNET_CONTAINER_MultiHashMap32 *map);


/**
 * @ingroup hashmap
 * Given a key find a value in the map matching the key.
 *
 * @param map the map
 * @param key what to look for
 * @return NULL if no value was found; note that
 *   this is indistinguishable from values that just
 *   happen to be NULL; use "contains" to test for
 *   key-value pairs with value NULL
 */
void *
GNUNET_CONTAINER_multihashmap32_get (const struct
                                     GNUNET_CONTAINER_MultiHashMap32 *map,
                                     uint32_t key);


/**
 * @ingroup hashmap
 * Iterate over all entries in the map.
 *
 * @param map the map
 * @param it function to call on each entry
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed,
 *         #GNUNET_SYSERR if it aborted iteration
 */
int
GNUNET_CONTAINER_multihashmap32_iterate (const struct
                                         GNUNET_CONTAINER_MultiHashMap32 *map,
                                         GNUNET_CONTAINER_HashMapIterator32 it,
                                         void *it_cls);


/**
 * @ingroup hashmap
 * Remove the given key-value pair from the map.  Note that if the
 * key-value pair is in the map multiple times, only one of the pairs
 * will be removed.
 *
 * @param map the map
 * @param key key of the key-value pair
 * @param value value of the key-value pair
 * @return #GNUNET_YES on success, #GNUNET_NO if the key-value pair
 *  is not in the map
 */
int
GNUNET_CONTAINER_multihashmap32_remove (struct GNUNET_CONTAINER_MultiHashMap32 *map,
                                        uint32_t key,
					const void *value);


/**
 * @ingroup hashmap
 * Remove all entries for the given key from the map.
 * Note that the values would not be "freed".
 *
 * @param map the map
 * @param key identifies values to be removed
 * @return number of values removed
 */
int
GNUNET_CONTAINER_multihashmap32_remove_all (struct GNUNET_CONTAINER_MultiHashMap32 *map,
                                            uint32_t key);


/**
 * @ingroup hashmap
 * Check if the map contains any value under the given
 * key (including values that are NULL).
 *
 * @param map the map
 * @param key the key to test if a value exists for it
 * @return #GNUNET_YES if such a value exists,
 *         #GNUNET_NO if not
 */
int
GNUNET_CONTAINER_multihashmap32_contains (const struct GNUNET_CONTAINER_MultiHashMap32 *map,
                                          uint32_t key);


/**
 * @ingroup hashmap
 * Check if the map contains the given value under the given
 * key.
 *
 * @param map the map
 * @param key the key to test if a value exists for it
 * @param value value to test for
 * @return #GNUNET_YES if such a value exists,
 *         #GNUNET_NO if not
 */
int
GNUNET_CONTAINER_multihashmap32_contains_value (const struct GNUNET_CONTAINER_MultiHashMap32 *map,
                                                uint32_t key,
                                                const void *value);


/**
 * @ingroup hashmap
 * Store a key-value pair in the map.
 *
 * @param map the map
 * @param key key to use
 * @param value value to use
 * @param opt options for put
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if a value was replaced (with REPLACE)
 *         #GNUNET_SYSERR if #GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY was the option and the
 *                       value already exists
 */
int
GNUNET_CONTAINER_multihashmap32_put (struct GNUNET_CONTAINER_MultiHashMap32 *map,
                                     uint32_t key,
                                     void *value,
                                     enum GNUNET_CONTAINER_MultiHashMapOption opt);


/**
 * @ingroup hashmap
 * Iterate over all entries in the map that match a particular key.
 *
 * @param map the map
 * @param key key that the entries must correspond to
 * @param it function to call on each entry
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed,
 *         #GNUNET_SYSERR if it aborted iteration
 */
int
GNUNET_CONTAINER_multihashmap32_get_multiple (const struct GNUNET_CONTAINER_MultiHashMap32 *map,
                                              uint32_t key,
                                              GNUNET_CONTAINER_HashMapIterator32 it,
                                              void *it_cls);


/**
 * Create an iterator for a 32-bit multihashmap.
 * The iterator can be used to retrieve all the elements in the multihashmap
 * one by one, without having to handle all elements at once (in contrast to
 * #GNUNET_CONTAINER_multihashmap32_iterate).  Note that the iterator can not be
 * used anymore if elements have been removed from 'map' after the creation of
 * the iterator, or 'map' has been destroyed.  Adding elements to 'map' may
 * result in skipped or repeated elements.
 *
 * @param map the map to create an iterator for
 * @return an iterator over the given multihashmap map
 */
struct GNUNET_CONTAINER_MultiHashMap32Iterator *
GNUNET_CONTAINER_multihashmap32_iterator_create (const struct GNUNET_CONTAINER_MultiHashMap32 *map);


/**
 * Retrieve the next element from the hash map at the iterator's position.
 * If there are no elements left, GNUNET_NO is returned, and 'key' and 'value'
 * are not modified.
 * This operation is only allowed if no elements have been removed from the
 * multihashmap since the creation of 'iter', and the map has not been destroyed.
 * Adding elements may result in repeating or skipping elements.
 *
 * @param iter the iterator to get the next element from
 * @param key pointer to store the key in, can be NULL
 * @param value pointer to store the value in, can be NULL
 * @return #GNUNET_YES we returned an element,
 *         #GNUNET_NO if we are out of elements
 */
int
GNUNET_CONTAINER_multihashmap32_iterator_next (struct GNUNET_CONTAINER_MultiHashMap32Iterator *iter,
                                               uint32_t *key,
                                               const void **value);


/**
 * Destroy a 32-bit multihashmap iterator.
 *
 * @param iter the iterator to destroy
 */
void
GNUNET_CONTAINER_multihashmap32_iterator_destroy (struct GNUNET_CONTAINER_MultiHashMapIterator *iter);


/* ******************** doubly-linked list *************** */
/* To avoid mistakes: head->prev == tail->next == NULL     */

/**
 * @ingroup dll
 * Insert an element at the head of a DLL. Assumes that head, tail and
 * element are structs with prev and next fields.
 *
 * @param head pointer to the head of the DLL
 * @param tail pointer to the tail of the DLL
 * @param element element to insert
 */
#define GNUNET_CONTAINER_DLL_insert(head,tail,element) do { \
  GNUNET_assert ( ( (element)->prev == NULL) && ((head) != (element))); \
  GNUNET_assert ( ( (element)->next == NULL) && ((tail) != (element))); \
  (element)->next = (head); \
  (element)->prev = NULL; \
  if ((tail) == NULL) \
    (tail) = element; \
  else \
    (head)->prev = element; \
  (head) = (element); } while (0)


/**
 * @ingroup dll
 * Insert an element at the tail of a DLL. Assumes that head, tail and
 * element are structs with prev and next fields.
 *
 * @param head pointer to the head of the DLL
 * @param tail pointer to the tail of the DLL
 * @param element element to insert
 */
#define GNUNET_CONTAINER_DLL_insert_tail(head,tail,element) do { \
  GNUNET_assert ( ( (element)->prev == NULL) && ((head) != (element))); \
  GNUNET_assert ( ( (element)->next == NULL) && ((tail) != (element))); \
  (element)->prev = (tail); \
  (element)->next = NULL; \
  if ((head) == NULL) \
    (head) = element; \
  else \
    (tail)->next = element; \
  (tail) = (element); } while (0)


/**
 * @ingroup dll
 * Insert an element into a DLL after the given other element.  Insert
 * at the head if the other element is NULL.
 *
 * @param head pointer to the head of the DLL
 * @param tail pointer to the tail of the DLL
 * @param other prior element, NULL for insertion at head of DLL
 * @param element element to insert
 */
#define GNUNET_CONTAINER_DLL_insert_after(head,tail,other,element) do { \
  GNUNET_assert ( ( (element)->prev == NULL) && ((head) != (element))); \
  GNUNET_assert ( ( (element)->next == NULL) && ((tail) != (element))); \
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
    (element)->next->prev = (element); } while (0)


/**
 * @ingroup dll
 * Insert an element into a DLL before the given other element.  Insert
 * at the tail if the other element is NULL.
 *
 * @param head pointer to the head of the DLL
 * @param tail pointer to the tail of the DLL
 * @param other prior element, NULL for insertion at head of DLL
 * @param element element to insert
 */
#define GNUNET_CONTAINER_DLL_insert_before(head,tail,other,element) do { \
  GNUNET_assert ( ( (element)->prev == NULL) && ((head) != (element))); \
  GNUNET_assert ( ( (element)->next == NULL) && ((tail) != (element))); \
  (element)->next = (other); \
  if (NULL == other) \
    { \
      (element)->prev = (tail); \
      (tail) = (element); \
    } \
  else \
    { \
      (element)->prev = (other)->prev; \
      (other)->prev = (element); \
    } \
  if (NULL == (element)->prev) \
    (head) = (element); \
  else \
    (element)->prev->next = (element); } while (0)


/**
 * @ingroup dll
 * Remove an element from a DLL. Assumes that head, tail and
 * element point to structs with prev and next fields.
 *
 * Using the head or tail pointer as the element
 * argument does NOT work with this macro.
 * Make sure to store head/tail in another pointer
 * and use it to remove the head or tail of the list.
 *
 * @param head pointer to the head of the DLL
 * @param tail pointer to the tail of the DLL
 * @param element element to remove
 */
#define GNUNET_CONTAINER_DLL_remove(head,tail,element) do { \
  GNUNET_assert ( ( (element)->prev != NULL) || ((head) == (element))); \
  GNUNET_assert ( ( (element)->next != NULL) || ((tail) == (element))); \
  if ((element)->prev == NULL) \
    (head) = (element)->next;  \
  else \
    (element)->prev->next = (element)->next; \
  if ((element)->next == NULL) \
    (tail) = (element)->prev;  \
  else \
    (element)->next->prev = (element)->prev; \
  (element)->next = NULL; \
  (element)->prev = NULL; } while (0)


/* ************ Multi-DLL interface, allows DLL elements to be
   in multiple lists at the same time *********************** */

/**
 * @ingroup dll
 * Insert an element at the head of a MDLL. Assumes that head, tail and
 * element are structs with prev and next fields.
 *
 * @param mdll suffix name for the next and prev pointers in the element
 * @param head pointer to the head of the MDLL
 * @param tail pointer to the tail of the MDLL
 * @param element element to insert
 */
#define GNUNET_CONTAINER_MDLL_insert(mdll,head,tail,element) do {	\
  GNUNET_assert ( ( (element)->prev_##mdll == NULL) && ((head) != (element))); \
  GNUNET_assert ( ( (element)->next_##mdll == NULL) && ((tail) != (element))); \
  (element)->next_##mdll = (head); \
  (element)->prev_##mdll = NULL; \
  if ((tail) == NULL) \
    (tail) = element; \
  else \
    (head)->prev_##mdll = element; \
  (head) = (element); } while (0)


/**
 * @ingroup dll
 * Insert an element at the tail of a MDLL. Assumes that head, tail and
 * element are structs with prev and next fields.
 *
 * @param mdll suffix name for the next and prev pointers in the element
 * @param head pointer to the head of the MDLL
 * @param tail pointer to the tail of the MDLL
 * @param element element to insert
 */
#define GNUNET_CONTAINER_MDLL_insert_tail(mdll,head,tail,element) do {	\
  GNUNET_assert ( ( (element)->prev_##mdll == NULL) && ((head) != (element))); \
  GNUNET_assert ( ( (element)->next_##mdll == NULL) && ((tail) != (element))); \
  (element)->prev_##mdll = (tail); \
  (element)->next_##mdll = NULL; \
  if ((head) == NULL) \
    (head) = element; \
  else \
    (tail)->next_##mdll = element; \
  (tail) = (element); } while (0)


/**
 * @ingroup dll
 * Insert an element into a MDLL after the given other element.  Insert
 * at the head if the other element is NULL.
 *
 * @param mdll suffix name for the next and prev pointers in the element
 * @param head pointer to the head of the MDLL
 * @param tail pointer to the tail of the MDLL
 * @param other prior element, NULL for insertion at head of MDLL
 * @param element element to insert
 */
#define GNUNET_CONTAINER_MDLL_insert_after(mdll,head,tail,other,element) do { \
  GNUNET_assert ( ( (element)->prev_##mdll == NULL) && ((head) != (element))); \
  GNUNET_assert ( ( (element)->next_##mdll == NULL) && ((tail) != (element))); \
  (element)->prev_##mdll = (other); \
  if (NULL == other) \
    { \
      (element)->next_##mdll = (head); \
      (head) = (element); \
    } \
  else \
    { \
      (element)->next_##mdll = (other)->next_##mdll; \
      (other)->next_##mdll = (element); \
    } \
  if (NULL == (element)->next_##mdll) \
    (tail) = (element); \
  else \
    (element)->next->prev_##mdll = (element); } while (0)


/**
 * @ingroup dll
 * Insert an element into a MDLL before the given other element.  Insert
 * at the tail if the other element is NULL.
 *
 * @param mdll suffix name for the next and prev pointers in the element
 * @param head pointer to the head of the MDLL
 * @param tail pointer to the tail of the MDLL
 * @param other prior element, NULL for insertion at head of MDLL
 * @param element element to insert
 */
#define GNUNET_CONTAINER_MDLL_insert_before(mdll,head,tail,other,element) do { \
  GNUNET_assert ( ( (element)->prev_##mdll == NULL) && ((head) != (element))); \
  GNUNET_assert ( ( (element)->next_##mdll == NULL) && ((tail) != (element))); \
  (element)->next_##mdll = (other); \
  if (NULL == other) \
    { \
      (element)->prev = (tail); \
      (tail) = (element); \
    } \
  else \
    { \
      (element)->prev_##mdll = (other)->prev_##mdll; \
      (other)->prev_##mdll = (element); \
    } \
  if (NULL == (element)->prev_##mdll) \
    (head) = (element); \
  else \
    (element)->prev_##mdll->next_##mdll = (element); } while (0)


/**
 * @ingroup dll
 * Remove an element from a MDLL. Assumes
 * that head, tail and element are structs
 * with prev and next fields.
 *
 * @param mdll suffix name for the next and prev pointers in the element
 * @param head pointer to the head of the MDLL
 * @param tail pointer to the tail of the MDLL
 * @param element element to remove
 */
#define GNUNET_CONTAINER_MDLL_remove(mdll,head,tail,element) do {	\
  GNUNET_assert ( ( (element)->prev_##mdll != NULL) || ((head) == (element))); \
  GNUNET_assert ( ( (element)->next_##mdll != NULL) || ((tail) == (element))); \
  if ((element)->prev_##mdll == NULL) \
    (head) = (element)->next_##mdll;  \
  else \
    (element)->prev_##mdll->next_##mdll = (element)->next_##mdll; \
  if ((element)->next_##mdll == NULL) \
    (tail) = (element)->prev_##mdll;  \
  else \
    (element)->next_##mdll->prev_##mdll = (element)->prev_##mdll; \
  (element)->next_##mdll = NULL; \
  (element)->prev_##mdll = NULL; } while (0)



/**
 * Insertion sort of @a element into DLL from @a head to @a tail
 * sorted by @a comparator.
 *
 * @param TYPE element type of the elements, i.e. `struct ListElement`
 * @param comparator function like memcmp() to compare elements; takes
 *                   three arguments, the @a comparator_cls and two elements,
 *                   returns an `int` (-1, 0 or 1)
 * @param comparator_cls closure for @a comparator
 * @param[in,out] head head of DLL
 * @param[in,out] tail tail of DLL
 * @param element element to insert
 */
#define GNUNET_CONTAINER_DLL_insert_sorted(TYPE,comparator,comparator_cls,head,tail,element) do { \
  if ( (NULL == head) || \
       (0 < comparator (comparator_cls, \
                        element, \
                        head)) ) \
  { \
    /* insert at head, e;e,emt < head */ \
    GNUNET_CONTAINER_DLL_insert (head, \
                                 tail, \
                                 element); \
  } \
  else \
  {          \
    TYPE *pos; \
    \
    for (pos = head; \
         NULL != pos; \
         pos = pos->next) \
      if (0 < \
          comparator (comparator_cls, \
                      element, \
                      pos)) \
        break; /* element < pos */ \
    if (NULL == pos) /* => element > tail */ \
      GNUNET_CONTAINER_DLL_insert_tail (head, \
                                        tail, \
                                        element); \
    else /* prev < element < pos */ \
      GNUNET_CONTAINER_DLL_insert_after (head, \
                                         tail, \
                                         element, \
                                         pos->prev); \
  } \
} while (0)


/* ******************** Heap *************** */


/**
 * @ingroup heap
 * Cost by which elements in a heap can be ordered.
 */
typedef uint64_t GNUNET_CONTAINER_HeapCostType;


/**
 * @ingroup heap
 * Heap type, either max or min.
 */
enum GNUNET_CONTAINER_HeapOrder
{
  /**
   * @ingroup heap
   * Heap with the maximum cost at the root.
   */
  GNUNET_CONTAINER_HEAP_ORDER_MAX,

  /**
   * @ingroup heap
   * Heap with the minimum cost at the root.
   */
  GNUNET_CONTAINER_HEAP_ORDER_MIN
};


/**
 * @ingroup heap
 * Handle to a Heap.
 */
struct GNUNET_CONTAINER_Heap;


/**
 * @ingroup heap
 * Handle to a node in a heap.
 */
struct GNUNET_CONTAINER_HeapNode;


/**
 * @ingroup heap
 * Create a new heap.
 *
 * @param order how should the heap be sorted?
 * @return handle to the heap
 */
struct GNUNET_CONTAINER_Heap *
GNUNET_CONTAINER_heap_create (enum GNUNET_CONTAINER_HeapOrder order);


/**
 * @ingroup heap
 * Destroys the heap.  Only call on a heap that
 * is already empty.
 *
 * @param heap heap to destroy
 */
void
GNUNET_CONTAINER_heap_destroy (struct GNUNET_CONTAINER_Heap *heap);


/**
 * @ingroup heap
 * Get element stored at the root of @a heap.
 *
 * @param heap  Heap to inspect.
 * @return Element at the root, or NULL if heap is empty.
 */
void *
GNUNET_CONTAINER_heap_peek (const struct GNUNET_CONTAINER_Heap *heap);


/**
 * Get @a element and @a cost stored at the root of @a heap.
 *
 * @param[in]  heap     Heap to inspect.
 * @param[out] element  Root element is returned here.
 * @param[out] cost     Cost of @a element is returned here.
 * @return #GNUNET_YES if an element is returned,
 *         #GNUNET_NO  if the heap is empty.
 */
int
GNUNET_CONTAINER_heap_peek2 (const struct GNUNET_CONTAINER_Heap *heap,
                             void **element,
                             GNUNET_CONTAINER_HeapCostType *cost);


/**
 * @ingroup heap
 * Get the current size of the heap
 *
 * @param heap the heap to get the size of
 * @return number of elements stored
 */
unsigned int
GNUNET_CONTAINER_heap_get_size (const struct GNUNET_CONTAINER_Heap *heap);


/**
 * @ingroup heap
 * Get the current cost of the node
 *
 * @param node the node to get the cost of
 * @return cost of the node
 */
GNUNET_CONTAINER_HeapCostType
GNUNET_CONTAINER_heap_node_get_cost (const struct GNUNET_CONTAINER_HeapNode *node);


/**
 * @ingroup heap
 * Iterator for heap
 *
 * @param cls closure
 * @param node internal node of the heap
 * @param element value stored at the node
 * @param cost cost associated with the node
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
typedef int
(*GNUNET_CONTAINER_HeapIterator) (void *cls,
                                  struct GNUNET_CONTAINER_HeapNode *node,
                                  void *element,
                                  GNUNET_CONTAINER_HeapCostType cost);


/**
 * @ingroup heap
 * Iterate over all entries in the heap.
 *
 * @param heap the heap
 * @param iterator function to call on each entry
 * @param iterator_cls closure for @a iterator
 */
void
GNUNET_CONTAINER_heap_iterate (const struct GNUNET_CONTAINER_Heap *heap,
                               GNUNET_CONTAINER_HeapIterator iterator,
                               void *iterator_cls);

/**
 * @ingroup heap
 * Perform a random walk of the tree.  The walk is biased
 * towards elements closer to the root of the tree (since
 * each walk starts at the root and ends at a random leaf).
 * The heap internally tracks the current position of the
 * walk.
 *
 * @param heap heap to walk
 * @return data stored at the next random node in the walk;
 *         NULL if the tree is empty.
 */
void *
GNUNET_CONTAINER_heap_walk_get_next (struct GNUNET_CONTAINER_Heap *heap);


/**
 * @ingroup heap
 * Inserts a new element into the heap.
 *
 * @param heap heap to modify
 * @param element element to insert
 * @param cost cost for the element
 * @return node for the new element
 */
struct GNUNET_CONTAINER_HeapNode *
GNUNET_CONTAINER_heap_insert (struct GNUNET_CONTAINER_Heap *heap,
                              void *element,
                              GNUNET_CONTAINER_HeapCostType cost);


/**
 * @ingroup heap
 * Remove root of the heap.
 *
 * @param heap heap to modify
 * @return element data stored at the root node
 */
void *
GNUNET_CONTAINER_heap_remove_root (struct GNUNET_CONTAINER_Heap *heap);


/**
 * @ingroup heap
 * Removes a node from the heap.
 *
 * @param node node to remove
 * @return element data stored at the node, NULL if heap is empty
 */
void *
GNUNET_CONTAINER_heap_remove_node (struct GNUNET_CONTAINER_HeapNode *node);


/**
 * @ingroup heap
 * Updates the cost of any node in the tree
 *
 * @param node node for which the cost is to be changed
 * @param new_cost new cost for the node
 */
void
GNUNET_CONTAINER_heap_update_cost (struct GNUNET_CONTAINER_HeapNode *node,
                                   GNUNET_CONTAINER_HeapCostType new_cost);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_CONTAINER_LIB_H */
#endif
/* end of gnunet_container_lib.h */
