/*
     This file is part of GNUnet.
     Copyright (C) 2003, 2004, 2005, 2006, 2008, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file util/container_meta_data.c
 * @brief Storing of meta data
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#if HAVE_EXTRACTOR_H
#include <extractor.h>
#endif
#include <zlib.h>

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

/**
 * Meta data item.
 */
struct MetaItem
{
  /**
   * This is a doubly linked list.
   */
  struct MetaItem *next;

  /**
   * This is a doubly linked list.
   */
  struct MetaItem *prev;

  /**
   * Name of the extracting plugin.
   */
  char *plugin_name;

  /**
   * Mime-type of data.
   */
  char *mime_type;

  /**
   * The actual meta data.
   */
  char *data;

  /**
   * Number of bytes in 'data'.
   */
  size_t data_size;

  /**
   * Type of the meta data.
   */
  enum EXTRACTOR_MetaType type;

  /**
   * Format of the meta data.
   */
  enum EXTRACTOR_MetaFormat format;

};

/**
 * Meta data to associate with a file, directory or namespace.
 */
struct GNUNET_CONTAINER_MetaData
{
  /**
   * Head of linked list of the meta data items.
   */
  struct MetaItem *items_head;

  /**
   * Tail of linked list of the meta data items.
   */
  struct MetaItem *items_tail;

  /**
   * Complete serialized and compressed buffer of the items.
   * NULL if we have not computed that buffer yet.
   */
  char *sbuf;

  /**
   * Number of bytes in 'sbuf'. 0 if the buffer is stale.
   */
  size_t sbuf_size;

  /**
   * Number of items in the linked list.
   */
  unsigned int item_count;

};


/**
 * Create a fresh struct CONTAINER_MetaData token.
 *
 * @return empty meta-data container
 */
struct GNUNET_CONTAINER_MetaData *
GNUNET_CONTAINER_meta_data_create ()
{
  return GNUNET_new (struct GNUNET_CONTAINER_MetaData);
}


/**
 * Free meta data item.
 *
 * @param mi item to free
 */
static void
meta_item_free (struct MetaItem *mi)
{
  GNUNET_free_non_null (mi->plugin_name);
  GNUNET_free_non_null (mi->mime_type);
  GNUNET_free_non_null (mi->data);
  GNUNET_free (mi);
}


/**
 * The meta data has changed, invalidate its serialization
 * buffer.
 *
 * @param md meta data that changed
 */
static void
invalidate_sbuf (struct GNUNET_CONTAINER_MetaData *md)
{
  if (NULL == md->sbuf)
    return;
  GNUNET_free (md->sbuf);
  md->sbuf = NULL;
  md->sbuf_size = 0;
}


/**
 * Free meta data.
 *
 * @param md what to free
 */
void
GNUNET_CONTAINER_meta_data_destroy (struct GNUNET_CONTAINER_MetaData *md)
{
  struct MetaItem *pos;

  if (NULL == md)
    return;
  while (NULL != (pos = md->items_head))
  {
    GNUNET_CONTAINER_DLL_remove (md->items_head, md->items_tail, pos);
    meta_item_free (pos);
  }
  GNUNET_free_non_null (md->sbuf);
  GNUNET_free (md);
}


/**
 * Remove all items in the container.
 *
 * @param md metadata to manipulate
 */
void
GNUNET_CONTAINER_meta_data_clear (struct GNUNET_CONTAINER_MetaData *md)
{
  struct MetaItem *mi;

  if (NULL == md)
    return;
  while (NULL != (mi = md->items_head))
  {
    GNUNET_CONTAINER_DLL_remove (md->items_head, md->items_tail, mi);
    meta_item_free (mi);
  }
  GNUNET_free_non_null (md->sbuf);
  memset (md, 0, sizeof (struct GNUNET_CONTAINER_MetaData));
}


/**
 * Test if two MDs are equal.  We consider them equal if
 * the meta types, formats and content match (we do not
 * include the mime types and plugins names in this
 * consideration).
 *
 * @param md1 first value to check
 * @param md2 other value to check
 * @return #GNUNET_YES if they are equal
 */
int
GNUNET_CONTAINER_meta_data_test_equal (const struct GNUNET_CONTAINER_MetaData
                                       *md1,
                                       const struct GNUNET_CONTAINER_MetaData
                                       *md2)
{
  struct MetaItem *i;
  struct MetaItem *j;
  int found;

  if (md1 == md2)
    return GNUNET_YES;
  if (md1->item_count != md2->item_count)
    return GNUNET_NO;
  for (i = md1->items_head; NULL != i; i = i->next)
  {
    found = GNUNET_NO;
    for (j = md2->items_head; NULL != j; j = j->next)
    {
      if ((i->type == j->type) && (i->format == j->format) &&
          (i->data_size == j->data_size) &&
          (0 == memcmp (i->data, j->data, i->data_size)))
      {
        found = GNUNET_YES;
        break;
      }
      if (j->data_size < i->data_size)
	break; /* elements are sorted by (decreasing) size... */
    }
    if (GNUNET_NO == found)
      return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Extend metadata.  Note that the list of meta data items is
 * sorted by size (largest first).
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
 * @param data_size number of bytes in @a data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if this entry already exists
 *         data_mime_type and plugin_name are not considered for "exists" checks
 */
int
GNUNET_CONTAINER_meta_data_insert (struct GNUNET_CONTAINER_MetaData *md,
                                   const char *plugin_name,
                                   enum EXTRACTOR_MetaType type,
                                   enum EXTRACTOR_MetaFormat format,
                                   const char *data_mime_type, const char *data,
                                   size_t data_size)
{
  struct MetaItem *pos;
  struct MetaItem *mi;
  char *p;

  if ((EXTRACTOR_METAFORMAT_UTF8 == format) ||
      (EXTRACTOR_METAFORMAT_C_STRING == format))
    GNUNET_break ('\0' == data[data_size - 1]);

  for (pos = md->items_head; NULL != pos; pos = pos->next)
  {
    if (pos->data_size < data_size)
      break; /* elements are sorted by size in the list */
    if ((pos->type == type) && (pos->data_size == data_size) &&
        (0 == memcmp (pos->data, data, data_size)))
    {
      if ((NULL == pos->mime_type) && (NULL != data_mime_type))
      {
        pos->mime_type = GNUNET_strdup (data_mime_type);
        invalidate_sbuf (md);
      }
      if ((EXTRACTOR_METAFORMAT_C_STRING == pos->format) &&
          (EXTRACTOR_METAFORMAT_UTF8 == format))
      {
        pos->format = EXTRACTOR_METAFORMAT_UTF8;
        invalidate_sbuf (md);
      }
      return GNUNET_SYSERR;
    }
  }
  md->item_count++;
  mi = GNUNET_new (struct MetaItem);
  mi->type = type;
  mi->format = format;
  mi->data_size = data_size;
  if (NULL == pos)
    GNUNET_CONTAINER_DLL_insert_tail (md->items_head,
				      md->items_tail,
				      mi);
  else
    GNUNET_CONTAINER_DLL_insert_after (md->items_head,
				       md->items_tail,
				       pos->prev,
				       mi);
  mi->mime_type =
      (NULL == data_mime_type) ? NULL : GNUNET_strdup (data_mime_type);
  mi->plugin_name = (NULL == plugin_name) ? NULL : GNUNET_strdup (plugin_name);
  mi->data = GNUNET_malloc (data_size);
  memcpy (mi->data, data, data_size);
  /* change all dir separators to POSIX style ('/') */
  if ( (EXTRACTOR_METATYPE_FILENAME == type) ||
       (EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME == type) )
  {
    p = mi->data;
    while (('\0' != *p) && (p < mi->data + data_size))
    {
      if ('\\' == *p)
        *p = '/';
      p++;
    }
  }
  invalidate_sbuf (md);
  return GNUNET_OK;
}


/**
 * Merge given meta data.
 *
 * @param cls the `struct GNUNET_CONTAINER_MetaData` to merge into
 * @param plugin_name name of the plugin that produced this value;
 *        special values can be used (i.e. '&lt;zlib&gt;' for zlib being
 *        used in the main libextractor library and yielding
 *        meta data).
 * @param type libextractor-type describing the meta data
 * @param format basic format information about data
 * @param data_mime_type mime-type of data (not of the original file);
 *        can be NULL (if mime-type is not known)
 * @param data actual meta-data found
 * @param data_size number of bytes in @a data
 * @return 0 (to continue)
 */
static int
merge_helper (void *cls, const char *plugin_name, enum EXTRACTOR_MetaType type,
              enum EXTRACTOR_MetaFormat format, const char *data_mime_type,
              const char *data, size_t data_size)
{
  struct GNUNET_CONTAINER_MetaData *md = cls;

  (void) GNUNET_CONTAINER_meta_data_insert (md, plugin_name, type, format,
                                            data_mime_type, data, data_size);
  return 0;
}


/**
 * Extend metadata.  Merges the meta data from the second argument
 * into the first, discarding duplicate key-value pairs.
 *
 * @param md metadata to extend
 * @param in metadata to merge
 */
void
GNUNET_CONTAINER_meta_data_merge (struct GNUNET_CONTAINER_MetaData *md,
                                  const struct GNUNET_CONTAINER_MetaData *in)
{
  GNUNET_CONTAINER_meta_data_iterate (in, &merge_helper, md);
}


/**
 * Remove an item.
 *
 * @param md metadata to manipulate
 * @param type type of the item to remove
 * @param data specific value to remove, NULL to remove all
 *        entries of the given type
 * @param data_size number of bytes in @a data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the item does not exist in md
 */
int
GNUNET_CONTAINER_meta_data_delete (struct GNUNET_CONTAINER_MetaData *md,
                                   enum EXTRACTOR_MetaType type,
                                   const char *data, size_t data_size)
{
  struct MetaItem *pos;

  for (pos = md->items_head; NULL != pos; pos = pos->next)
  {
    if (pos->data_size < data_size)
      break; /* items are sorted by (decreasing) size */
    if ((pos->type == type) &&
        ((NULL == data) ||
         ((pos->data_size == data_size) &&
          (0 == memcmp (pos->data, data, data_size)))))
    {
      GNUNET_CONTAINER_DLL_remove (md->items_head, md->items_tail, pos);
      meta_item_free (pos);
      md->item_count--;
      invalidate_sbuf (md);
      return GNUNET_OK;
    }
  }
  return GNUNET_SYSERR;
}


/**
 * Add the current time as the publication date
 * to the meta-data.
 *
 * @param md metadata to modify
 */
void
GNUNET_CONTAINER_meta_data_add_publication_date (struct
                                                 GNUNET_CONTAINER_MetaData *md)
{
  const char *dat;
  struct GNUNET_TIME_Absolute t;

  t = GNUNET_TIME_absolute_get ();
  GNUNET_CONTAINER_meta_data_delete (md,
                                     EXTRACTOR_METATYPE_PUBLICATION_DATE,
                                     NULL, 0);
  dat = GNUNET_STRINGS_absolute_time_to_string (t);
  GNUNET_CONTAINER_meta_data_insert (md, "<gnunet>",
                                     EXTRACTOR_METATYPE_PUBLICATION_DATE,
                                     EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                     dat, strlen (dat) + 1);
}


/**
 * Iterate over MD entries.
 *
 * @param md metadata to inspect
 * @param iter function to call on each entry
 * @param iter_cls closure for iterator
 * @return number of entries
 */
int
GNUNET_CONTAINER_meta_data_iterate (const struct GNUNET_CONTAINER_MetaData *md,
                                    EXTRACTOR_MetaDataProcessor iter,
                                    void *iter_cls)
{
  struct MetaItem *pos;

  if (NULL == md)
    return 0;
  if (NULL == iter)
    return md->item_count;
  for (pos = md->items_head; NULL != pos; pos = pos->next)
    if (0 !=
        iter (iter_cls, pos->plugin_name, pos->type, pos->format,
              pos->mime_type, pos->data, pos->data_size))
      return md->item_count;
  return md->item_count;
}


/**
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
                                        enum EXTRACTOR_MetaType type)
{
  struct MetaItem *pos;

  if (NULL == md)
    return NULL;
  for (pos = md->items_head; NULL != pos; pos = pos->next)
    if ((type == pos->type) &&
        ((pos->format == EXTRACTOR_METAFORMAT_UTF8) ||
         (pos->format == EXTRACTOR_METAFORMAT_C_STRING)))
      return GNUNET_strdup (pos->data);
  return NULL;
}


/**
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
GNUNET_CONTAINER_meta_data_get_first_by_types (const struct
                                               GNUNET_CONTAINER_MetaData *md,
                                               ...)
{
  char *ret;
  va_list args;
  enum EXTRACTOR_MetaType type;

  if (NULL == md)
    return NULL;
  ret = NULL;
  va_start (args, md);
  while (1)
  {
    type = va_arg (args, enum EXTRACTOR_MetaType);
    if (-1 == type)
      break;
    if (NULL != (ret = GNUNET_CONTAINER_meta_data_get_by_type (md, type)))
      break;
  }
  va_end (args);
  return ret;
}


/**
 * Get a thumbnail from the meta-data (if present).
 *
 * @param md metadata to get the thumbnail from
 * @param thumb will be set to the thumbnail data.  Must be
 *        freed by the caller!
 * @return number of bytes in thumbnail, 0 if not available
 */
size_t
GNUNET_CONTAINER_meta_data_get_thumbnail (const struct GNUNET_CONTAINER_MetaData
                                          * md, unsigned char **thumb)
{
  struct MetaItem *pos;
  struct MetaItem *match;

  if (NULL == md)
    return 0;
  match = NULL;
  for (pos = md->items_head; NULL != pos; pos = pos->next)
  {
    if ((NULL != pos->mime_type) &&
        (0 == strncasecmp ("image/", pos->mime_type, strlen ("image/"))) &&
        (EXTRACTOR_METAFORMAT_BINARY == pos->format))
    {
      if (NULL == match)
        match = pos;
      else if ((match->type != EXTRACTOR_METATYPE_THUMBNAIL) &&
               (pos->type == EXTRACTOR_METATYPE_THUMBNAIL))
        match = pos;
    }
  }
  if ((NULL == match) || (0 == match->data_size))
    return 0;
  *thumb = GNUNET_malloc (match->data_size);
  memcpy (*thumb, match->data, match->data_size);
  return match->data_size;
}


/**
 * Duplicate a `struct GNUNET_CONTAINER_MetaData`.
 *
 * @param md what to duplicate
 * @return duplicate meta-data container
 */
struct GNUNET_CONTAINER_MetaData *
GNUNET_CONTAINER_meta_data_duplicate (const struct GNUNET_CONTAINER_MetaData
                                      *md)
{
  struct GNUNET_CONTAINER_MetaData *ret;
  struct MetaItem *pos;

  if (NULL == md)
    return NULL;
  ret = GNUNET_CONTAINER_meta_data_create ();
  for (pos = md->items_tail; NULL != pos; pos = pos->prev)
    GNUNET_CONTAINER_meta_data_insert (ret, pos->plugin_name, pos->type,
                                       pos->format, pos->mime_type, pos->data,
                                       pos->data_size);
  return ret;
}



/**
 * Try to compress the given block of data.
 *
 * @param data block to compress; if compression
 *        resulted in a smaller block, the first
 *        bytes of data are updated to the compressed
 *        data
 * @param oldSize number of bytes in data
 * @param result set to the compressed data
 * @param newSize set to size of result
 * @return #GNUNET_YES if compression reduce the size,
 *         #GNUNET_NO if compression did not help
 */
static int
try_compression (const char *data, size_t oldSize, char **result,
                 size_t * newSize)
{
  char *tmp;
  uLongf dlen;

#ifdef compressBound
  dlen = compressBound (oldSize);
#else
  dlen = oldSize + (oldSize / 100) + 20;
  /* documentation says 100.1% oldSize + 12 bytes, but we
   * should be able to overshoot by more to be safe */
#endif
  tmp = GNUNET_malloc (dlen);
  if (Z_OK ==
      compress2 ((Bytef *) tmp, &dlen, (const Bytef *) data, oldSize, 9))
  {
    if (dlen < oldSize)
    {
      *result = tmp;
      *newSize = dlen;
      return GNUNET_YES;
    }
  }
  GNUNET_free (tmp);
  return GNUNET_NO;
}


/**
 * Flag in 'version' that indicates compressed meta-data.
 */
#define HEADER_COMPRESSED 0x80000000


/**
 * Bits in 'version' that give the version number.
 */
#define HEADER_VERSION_MASK 0x7FFFFFFF


/**
 * Header for serialized meta data.
 */
struct MetaDataHeader
{
  /**
   * The version of the MD serialization.  The highest bit is used to
   * indicate compression.
   *
   * Version 0 is traditional (pre-0.9) meta data (unsupported)
   * Version is 1 for a NULL pointer
   * Version 2 is for 0.9.x (and possibly higher)
   * Other version numbers are not yet defined.
   */
  uint32_t version;

  /**
   * How many MD entries are there?
   */
  uint32_t entries;

  /**
   * Size of the decompressed meta data.
   */
  uint32_t size;

  /**
   * This is followed by 'entries' values of type 'struct MetaDataEntry'
   * and then by 'entry' plugin names, mime-types and data blocks
   * as specified in those meta data entries.
   */
};


/**
 * Entry of serialized meta data.
 */
struct MetaDataEntry
{
  /**
   * Meta data type.  Corresponds to an 'enum EXTRACTOR_MetaType'
   */
  uint32_t type;

  /**
   * Meta data format. Corresponds to an 'enum EXTRACTOR_MetaFormat'
   */
  uint32_t format;

  /**
   * Number of bytes of meta data.
   */
  uint32_t data_size;

  /**
   * Number of bytes in the plugin name including 0-terminator.  0 for NULL.
   */
  uint32_t plugin_name_len;

  /**
   * Number of bytes in the mime type including 0-terminator.  0 for NULL.
   */
  uint32_t mime_type_len;

};


/**
 * Serialize meta-data to target.
 *
 * @param md metadata to serialize
 * @param target where to write the serialized metadata;
 *         *target can be NULL, in which case memory is allocated
 * @param max maximum number of bytes available in target
 * @param opt is it ok to just write SOME of the
 *        meta-data to match the size constraint,
 *        possibly discarding some data?
 * @return number of bytes written on success,
 *         #GNUNET_SYSERR on error (typically: not enough
 *         space)
 */
ssize_t
GNUNET_CONTAINER_meta_data_serialize (const struct GNUNET_CONTAINER_MetaData
                                      *md, char **target, size_t max,
                                      enum
                                      GNUNET_CONTAINER_MetaDataSerializationOptions
                                      opt)
{
  struct GNUNET_CONTAINER_MetaData *vmd;
  struct MetaItem *pos;
  struct MetaDataHeader ihdr;
  struct MetaDataHeader *hdr;
  struct MetaDataEntry *ent;
  char *dst;
  unsigned int i;
  uint64_t msize;
  size_t off;
  char *mdata;
  char *cdata;
  size_t mlen;
  size_t plen;
  size_t size;
  size_t left;
  size_t clen;
  size_t rlen;
  int comp;

  if (max < sizeof (struct MetaDataHeader))
    return GNUNET_SYSERR;       /* far too small */
  if (NULL == md)
    return 0;

  if (NULL != md->sbuf)
  {
    /* try to use serialization cache */
    if (md->sbuf_size <= max)
    {
      if (NULL == *target)
        *target = GNUNET_malloc (md->sbuf_size);
      memcpy (*target, md->sbuf, md->sbuf_size);
      return md->sbuf_size;
    }
    if (0 == (opt & GNUNET_CONTAINER_META_DATA_SERIALIZE_PART))
      return GNUNET_SYSERR;     /* can say that this will fail */
    /* need to compute a partial serialization, sbuf useless ... */
  }
  dst = NULL;
  msize = 0;
  for (pos = md->items_tail; NULL != pos; pos = pos->prev)
  {
    msize += sizeof (struct MetaDataEntry);
    msize += pos->data_size;
    if (NULL != pos->plugin_name)
      msize += strlen (pos->plugin_name) + 1;
    if (NULL != pos->mime_type)
      msize += strlen (pos->mime_type) + 1;
  }
  size = (size_t) msize;
  if (size != msize)
  {
    GNUNET_break (0);           /* integer overflow */
    return GNUNET_SYSERR;
  }
  if (size >= GNUNET_MAX_MALLOC_CHECKED)
  {
    /* too large to be processed */
    return GNUNET_SYSERR;
  }
  ent = GNUNET_malloc (size);
  mdata = (char *) &ent[md->item_count];
  off = size - (md->item_count * sizeof (struct MetaDataEntry));
  i = 0;
  for (pos = md->items_head; NULL != pos; pos = pos->next)
  {
    ent[i].type = htonl ((uint32_t) pos->type);
    ent[i].format = htonl ((uint32_t) pos->format);
    ent[i].data_size = htonl ((uint32_t) pos->data_size);
    if (NULL == pos->plugin_name)
      plen = 0;
    else
      plen = strlen (pos->plugin_name) + 1;
    ent[i].plugin_name_len = htonl ((uint32_t) plen);
    if (NULL == pos->mime_type)
      mlen = 0;
    else
      mlen = strlen (pos->mime_type) + 1;
    ent[i].mime_type_len = htonl ((uint32_t) mlen);
    off -= pos->data_size;
    if ((EXTRACTOR_METAFORMAT_UTF8 == pos->format) ||
        (EXTRACTOR_METAFORMAT_C_STRING == pos->format))
      GNUNET_break ('\0' == pos->data[pos->data_size - 1]);
    memcpy (&mdata[off], pos->data, pos->data_size);
    off -= plen;
    if (NULL != pos->plugin_name)
      memcpy (&mdata[off], pos->plugin_name, plen);
    off -= mlen;
    if (NULL != pos->mime_type)
      memcpy (&mdata[off], pos->mime_type, mlen);
    i++;
  }
  GNUNET_assert (0 == off);

  clen = 0;
  cdata = NULL;
  left = size;
  i = 0;
  for (pos = md->items_head; NULL != pos; pos = pos->next)
  {
    comp = GNUNET_NO;
    if (0 == (opt & GNUNET_CONTAINER_META_DATA_SERIALIZE_NO_COMPRESS))
      comp = try_compression ((const char *) &ent[i], left, &cdata, &clen);

    if ((NULL == md->sbuf) && (0 == i))
    {
      /* fill 'sbuf'; this "modifies" md, but since this is only
       * an internal cache we will cast away the 'const' instead
       * of making the API look strange. */
      vmd = (struct GNUNET_CONTAINER_MetaData *) md;
      hdr = GNUNET_malloc (left + sizeof (struct MetaDataHeader));
      hdr->size = htonl (left);
      hdr->entries = htonl (md->item_count);
      if (GNUNET_YES == comp)
      {
        GNUNET_assert (clen < left);
        hdr->version = htonl (2 | HEADER_COMPRESSED);
        memcpy (&hdr[1], cdata, clen);
        vmd->sbuf_size = clen + sizeof (struct MetaDataHeader);
      }
      else
      {
        hdr->version = htonl (2);
        memcpy (&hdr[1], &ent[0], left);
        vmd->sbuf_size = left + sizeof (struct MetaDataHeader);
      }
      vmd->sbuf = (char *) hdr;
    }

    if (((left + sizeof (struct MetaDataHeader)) <= max) ||
        ((GNUNET_YES == comp) && (clen <= max)))
    {
      /* success, this now fits! */
      if (GNUNET_YES == comp)
      {
        if (NULL == dst)
          dst = GNUNET_malloc (clen + sizeof (struct MetaDataHeader));
        hdr = (struct MetaDataHeader *) dst;
        hdr->version = htonl (2 | HEADER_COMPRESSED);
        hdr->size = htonl (left);
        hdr->entries = htonl (md->item_count - i);
        memcpy (&dst[sizeof (struct MetaDataHeader)], cdata, clen);
        GNUNET_free (cdata);
	cdata = NULL;
        GNUNET_free (ent);
        rlen = clen + sizeof (struct MetaDataHeader);
      }
      else
      {
        if (NULL == dst)
          dst = GNUNET_malloc (left + sizeof (struct MetaDataHeader));
        hdr = (struct MetaDataHeader *) dst;
        hdr->version = htonl (2);
        hdr->entries = htonl (md->item_count - i);
        hdr->size = htonl (left);
        memcpy (&dst[sizeof (struct MetaDataHeader)], &ent[i], left);
        GNUNET_free (ent);
        rlen = left + sizeof (struct MetaDataHeader);
      }
      if (NULL != *target)
      {
        if (GNUNET_YES == comp)
          memcpy (*target, dst, clen + sizeof (struct MetaDataHeader));
        else
          memcpy (*target, dst, left + sizeof (struct MetaDataHeader));
        GNUNET_free (dst);
      }
      else
      {
        *target = dst;
      }
      return rlen;
    }

    if (0 == (opt & GNUNET_CONTAINER_META_DATA_SERIALIZE_PART))
    {
      /* does not fit! */
      GNUNET_free (ent);
      return GNUNET_SYSERR;
    }

    /* next iteration: ignore the corresponding meta data at the
     * end and try again without it */
    left -= sizeof (struct MetaDataEntry);
    left -= pos->data_size;
    if (NULL != pos->plugin_name)
      left -= strlen (pos->plugin_name) + 1;
    if (NULL != pos->mime_type)
      left -= strlen (pos->mime_type) + 1;

    GNUNET_free_non_null (cdata);
    cdata = NULL;

    i++;
  }
  GNUNET_free (ent);

  /* nothing fit, only write header! */
  ihdr.version = htonl (2);
  ihdr.entries = htonl (0);
  ihdr.size = htonl (0);
  if (NULL == *target)
    *target = (char *) GNUNET_new (struct MetaDataHeader);
  memcpy (*target, &ihdr, sizeof (struct MetaDataHeader));
  return sizeof (struct MetaDataHeader);
}


/**
 * Get the size of the full meta-data in serialized form.
 *
 * @param md metadata to inspect
 * @return number of bytes needed for serialization, -1 on error
 */
ssize_t
GNUNET_CONTAINER_meta_data_get_serialized_size (const struct
                                                GNUNET_CONTAINER_MetaData *md)
{
  ssize_t ret;
  char *ptr;

  if (NULL != md->sbuf)
    return md->sbuf_size;
  ptr = NULL;
  ret =
      GNUNET_CONTAINER_meta_data_serialize (md, &ptr, GNUNET_MAX_MALLOC_CHECKED,
                                            GNUNET_CONTAINER_META_DATA_SERIALIZE_FULL);
  if (-1 != ret)
    GNUNET_free (ptr);
  return ret;
}


/**
 * Decompress input, return the decompressed data
 * as output, set outputSize to the number of bytes
 * that were found.
 *
 * @param input compressed data
 * @param inputSize number of bytes in input
 * @param outputSize expected size of the output
 * @return NULL on error
 */
static char *
decompress (const char *input, size_t inputSize, size_t outputSize)
{
  char *output;
  uLongf olen;

  olen = outputSize;
  output = GNUNET_malloc (olen);
  if (Z_OK ==
      uncompress ((Bytef *) output, &olen, (const Bytef *) input, inputSize))
    return output;
  GNUNET_free (output);
  return NULL;
}


/**
 * Deserialize meta-data.  Initializes md.
 *
 * @param input buffer with the serialized metadata
 * @param size number of bytes available in input
 * @return MD on success, NULL on error (i.e.
 *         bad format)
 */
struct GNUNET_CONTAINER_MetaData *
GNUNET_CONTAINER_meta_data_deserialize (const char *input, size_t size)
{
  struct GNUNET_CONTAINER_MetaData *md;
  struct MetaDataHeader hdr;
  struct MetaDataEntry ent;
  uint32_t ic;
  uint32_t i;
  char *data;
  const char *cdata;
  uint32_t version;
  uint32_t dataSize;
  int compressed;
  size_t left;
  uint32_t mlen;
  uint32_t plen;
  uint32_t dlen;
  const char *mdata;
  const char *meta_data;
  const char *plugin_name;
  const char *mime_type;
  enum EXTRACTOR_MetaFormat format;

  if (size < sizeof (struct MetaDataHeader))
    return NULL;
  memcpy (&hdr, input, sizeof (struct MetaDataHeader));
  version = ntohl (hdr.version) & HEADER_VERSION_MASK;
  compressed = (ntohl (hdr.version) & HEADER_COMPRESSED) != 0;

  if (1 == version)
    return NULL;                /* null pointer */
  if (2 != version)
  {
    GNUNET_break_op (0);        /* unsupported version */
    return NULL;
  }

  ic = ntohl (hdr.entries);
  dataSize = ntohl (hdr.size);
  if ( ((sizeof (struct MetaDataEntry) * ic) > dataSize) ||
       ( (0 != ic) &&
         (dataSize / ic < sizeof (struct MetaDataEntry)) ) )
  {
    GNUNET_break_op (0);
    return NULL;
  }

  if (compressed)
  {
    if (dataSize >= GNUNET_MAX_MALLOC_CHECKED)
    {
      /* make sure we don't blow our memory limit because of a mal-formed
       * message... */
      GNUNET_break_op (0);
      return NULL;
    }
    data =
        decompress ((const char *) &input[sizeof (struct MetaDataHeader)],
                    size - sizeof (struct MetaDataHeader), dataSize);
    if (NULL == data)
    {
      GNUNET_break_op (0);
      return NULL;
    }
    cdata = data;
  }
  else
  {
    data = NULL;
    cdata = (const char *) &input[sizeof (struct MetaDataHeader)];
    if (dataSize != size - sizeof (struct MetaDataHeader))
    {
      GNUNET_break_op (0);
      return NULL;
    }
  }

  md = GNUNET_CONTAINER_meta_data_create ();
  left = dataSize - ic * sizeof (struct MetaDataEntry);
  mdata = &cdata[ic * sizeof (struct MetaDataEntry)];
  for (i = 0; i < ic; i++)
  {
    memcpy (&ent, &cdata[i * sizeof (struct MetaDataEntry)],
            sizeof (struct MetaDataEntry));
    format = (enum EXTRACTOR_MetaFormat) ntohl (ent.format);
    if ((EXTRACTOR_METAFORMAT_UTF8 != format) &&
        (EXTRACTOR_METAFORMAT_C_STRING != format) &&
        (EXTRACTOR_METAFORMAT_BINARY != format))
    {
      GNUNET_break_op (0);
      break;
    }
    dlen = ntohl (ent.data_size);
    plen = ntohl (ent.plugin_name_len);
    mlen = ntohl (ent.mime_type_len);
    if (dlen > left)
    {
      GNUNET_break_op (0);
      break;
    }
    left -= dlen;
    meta_data = &mdata[left];
    if ((EXTRACTOR_METAFORMAT_UTF8 == format) ||
        (EXTRACTOR_METAFORMAT_C_STRING == format))
    {
      if (0 == dlen)
      {
        GNUNET_break_op (0);
        break;
      }
      if ('\0' != meta_data[dlen - 1])
      {
        GNUNET_break_op (0);
        break;
      }
    }
    if (plen > left)
    {
      GNUNET_break_op (0);
      break;
    }
    left -= plen;
    if ((plen > 0) && ('\0' != mdata[left + plen - 1]))
    {
      GNUNET_break_op (0);
      break;
    }
    if (0 == plen)
      plugin_name = NULL;
    else
      plugin_name = &mdata[left];

    if (mlen > left)
    {
      GNUNET_break_op (0);
      break;
    }
    left -= mlen;
    if ((mlen > 0) && ('\0' != mdata[left + mlen - 1]))
    {
      GNUNET_break_op (0);
      break;
    }
    if (0 == mlen)
      mime_type = NULL;
    else
      mime_type = &mdata[left];
    GNUNET_CONTAINER_meta_data_insert (md, plugin_name,
                                       (enum EXTRACTOR_MetaType)
                                       ntohl (ent.type), format, mime_type,
                                       meta_data, dlen);
  }
  GNUNET_free_non_null (data);
  return md;
}


/* end of container_meta_data.c */
