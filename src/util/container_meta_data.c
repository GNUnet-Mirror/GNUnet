/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/container_meta_data.c
 * @brief Storing of meta data
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_container_lib.h"
#include "gnunet_strings_lib.h"
#include "gnunet_time_lib.h"
#include <extractor.h>
#include <zlib.h>

#define EXTRA_CHECKS ALLOW_EXTRA_CHECKS

struct Item
{
  EXTRACTOR_KeywordType type;
  char *data;
};

/**
 * Meta data to associate with a file, directory or namespace.
 */
struct GNUNET_CONTAINER_MetaData
{
  uint32_t itemCount;
  struct Item *items;
};

/**
 * Create a fresh struct CONTAINER_MetaData token.
 */
struct GNUNET_CONTAINER_MetaData *
GNUNET_CONTAINER_meta_data_create ()
{
  struct GNUNET_CONTAINER_MetaData *ret;
  ret = GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_MetaData));
  ret->items = NULL;
  ret->itemCount = 0;
  return ret;
}

/**
 * Free meta data.
 */
void
GNUNET_CONTAINER_meta_data_destroy (struct GNUNET_CONTAINER_MetaData *md)
{
  int i;

  if (md == NULL)
    return;
  for (i = 0; i < md->itemCount; i++)
    GNUNET_free (md->items[i].data);
  GNUNET_array_grow (md->items, md->itemCount, 0);
  GNUNET_free (md);
}

/**
 * Add the current time as the publication date
 * to the meta-data.
 */
void
GNUNET_CONTAINER_meta_data_add_publication_date (struct
                                                 GNUNET_CONTAINER_MetaData
                                                 *md)
{
  char *dat;
  struct GNUNET_TIME_Absolute t;

  t = GNUNET_TIME_absolute_get ();
  GNUNET_CONTAINER_meta_data_delete (md, EXTRACTOR_PUBLICATION_DATE, NULL);
  dat = GNUNET_STRINGS_absolute_time_to_string (t);
  GNUNET_CONTAINER_meta_data_insert (md, EXTRACTOR_PUBLICATION_DATE, dat);
  GNUNET_free (dat);
}

/**
 * Extend metadata.
 * @return GNUNET_OK on success, GNUNET_SYSERR if this entry already exists
 */
int
GNUNET_CONTAINER_meta_data_insert (struct GNUNET_CONTAINER_MetaData *md,
                                   EXTRACTOR_KeywordType type,
                                   const char *data)
{
  uint32_t idx;
  char *p;

  GNUNET_assert (data != NULL);
  for (idx = 0; idx < md->itemCount; idx++)
    {
      if ((md->items[idx].type == type) &&
          (0 == strcmp (md->items[idx].data, data)))
        return GNUNET_SYSERR;
    }
  idx = md->itemCount;
  GNUNET_array_grow (md->items, md->itemCount, md->itemCount + 1);
  md->items[idx].type = type;
  md->items[idx].data = p = GNUNET_strdup (data);

  /* change OS native dir separators to unix '/' and others to '_' */
  if (type == EXTRACTOR_FILENAME)
    {
      while (*p != '\0')
        {
          if (*p == DIR_SEPARATOR)
            *p = '/';
          else if (*p == '\\')
            *p = '_';
          p++;
        }
    }

  return GNUNET_OK;
}

/**
 * Remove an item.
 *
 * @param md metadata to manipulate
 * @param type type of the item to remove
 * @param data specific value to remove, NULL to remove all
 *        entries of the given type
 * @return GNUNET_OK on success, GNUNET_SYSERR if the item does not exist in md
 */
int
GNUNET_CONTAINER_meta_data_delete (struct GNUNET_CONTAINER_MetaData *md,
                                   EXTRACTOR_KeywordType type,
                                   const char *data)
{
  uint32_t idx;
  int ret = GNUNET_SYSERR;
  for (idx = 0; idx < md->itemCount; idx++)
    {
      if ((md->items[idx].type == type) &&
          ((data == NULL) || (0 == strcmp (md->items[idx].data, data))))
        {
          GNUNET_free (md->items[idx].data);
          md->items[idx] = md->items[md->itemCount - 1];
          GNUNET_array_grow (md->items, md->itemCount, md->itemCount - 1);
          if (data == NULL)
            {
              ret = GNUNET_OK;
              continue;
            }
          return GNUNET_OK;
        }
    }
  return ret;
}

/**
 * Iterate over MD entries, excluding thumbnails.
 *
 * @param md metadata to inspect
 * @param iter function to call on each entry
 * @param iter_cls closure for iterator
 * @return number of entries
 */
int
GNUNET_CONTAINER_meta_data_get_contents (const struct
                                         GNUNET_CONTAINER_MetaData *md,
                                         GNUNET_CONTAINER_MetaDataProcessor
                                         iter, void *iter_cls)
{
  uint32_t i;
  uint32_t sub;

  sub = 0;
  for (i = 0; i < md->itemCount; i++)
    {
      if (!EXTRACTOR_isBinaryType (md->items[i].type))
        {
          if ((iter != NULL) &&
              (GNUNET_OK != iter (iter_cls,
				  md->items[i].type,
				  md->items[i].data)))
            return GNUNET_SYSERR;
        }
      else
        sub++;
    }
  return (int) (md->itemCount - sub);
}

/**
 * Iterate over MD entries
 *
 * @return number of entries
 */
char *
GNUNET_CONTAINER_meta_data_get_by_type (const struct GNUNET_CONTAINER_MetaData
                                        *md, EXTRACTOR_KeywordType type)
{
  uint32_t i;

  for (i = 0; i < md->itemCount; i++)
    if (type == md->items[i].type)
      return GNUNET_strdup (md->items[i].data);
  return NULL;
}

/**
 * Iterate over MD entries
 *
 * @return number of entries
 */
char *
GNUNET_CONTAINER_meta_data_get_first_by_types (const struct
                                               GNUNET_CONTAINER_MetaData *md,
                                               ...)
{
  char *ret;
  va_list args;
  EXTRACTOR_KeywordType type;

  ret = NULL;
  va_start (args, md);
  while (1)
    {
      type = va_arg (args, EXTRACTOR_KeywordType);
      if (type == -1)
        break;
      ret = GNUNET_CONTAINER_meta_data_get_by_type (md, type);
      if (ret != NULL)
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
GNUNET_CONTAINER_meta_data_get_thumbnail (const struct
                                          GNUNET_CONTAINER_MetaData * md,
                                          unsigned char **thumb)
{
  char *encoded;
  int ret;
  size_t size;

  encoded =
    GNUNET_CONTAINER_meta_data_get_by_type (md, EXTRACTOR_THUMBNAIL_DATA);
  if (encoded == NULL)
    return 0;
  if (strlen (encoded) == 0)
    {
      GNUNET_free (encoded);
      return 0;                 /* invalid */
    }
  *thumb = NULL;
  ret = EXTRACTOR_binaryDecode (encoded, thumb, &size);
  GNUNET_free (encoded);
  if (ret != 0)
    return 0;
  return size;
}

/**
 * Duplicate struct GNUNET_CONTAINER_MetaData.
 * 
 * @param md what to duplicate
 * @return duplicate meta-data container
 */
struct GNUNET_CONTAINER_MetaData *
GNUNET_CONTAINER_meta_data_duplicate (const struct GNUNET_CONTAINER_MetaData
                                      *md)
{
  uint32_t i;
  struct GNUNET_CONTAINER_MetaData *ret;

  if (md == NULL)
    return NULL;
  ret = GNUNET_CONTAINER_meta_data_create ();
  for (i = 0; i < md->itemCount; i++)
    GNUNET_CONTAINER_meta_data_insert (ret, md->items[i].type,
                                       md->items[i].data);
  return ret;
}

/**
 * Extract meta-data from a file.
 *
 * @return GNUNET_SYSERR on error, otherwise the number
 *   of meta-data items obtained
 */
int
GNUNET_CONTAINER_meta_data_extract_from_file (struct GNUNET_CONTAINER_MetaData
                                              *md, const char *filename,
                                              EXTRACTOR_ExtractorList *
                                              extractors)
{
  EXTRACTOR_KeywordList *head;
  EXTRACTOR_KeywordList *pos;
  int ret;

  if (filename == NULL)
    return GNUNET_SYSERR;
  if (extractors == NULL)
    return 0;
  head = EXTRACTOR_getKeywords (extractors, filename);
  head = EXTRACTOR_removeDuplicateKeywords (head,
                                            EXTRACTOR_DUPLICATES_REMOVE_UNKNOWN);
  pos = head;
  ret = 0;
  while (pos != NULL)
    {
      if (GNUNET_OK ==
          GNUNET_CONTAINER_meta_data_insert (md, pos->keywordType,
                                             pos->keyword))
        ret++;
      pos = pos->next;
    }
  EXTRACTOR_freeKeywords (head);
  return ret;
}


static unsigned int
tryCompression (char *data, unsigned int oldSize)
{
  char *tmp;
  uLongf dlen;

#ifdef compressBound
  dlen = compressBound (oldSize);
#else
  dlen = oldSize + (oldSize / 100) + 20;
  /* documentation says 100.1% oldSize + 12 bytes, but we
     should be able to overshoot by more to be safe */
#endif
  tmp = GNUNET_malloc (dlen);
  if (Z_OK == compress2 ((Bytef *) tmp,
                         &dlen, (const Bytef *) data, oldSize, 9))
    {
      if (dlen < oldSize)
        {
          memcpy (data, tmp, dlen);
          GNUNET_free (tmp);
          return dlen;
        }
    }
  GNUNET_free (tmp);
  return oldSize;
}

/**
 * Decompress input, return the decompressed data
 * as output, set outputSize to the number of bytes
 * that were found.
 *
 * @return NULL on error
 */
static char *
decompress (const char *input,
            unsigned int inputSize, unsigned int outputSize)
{
  char *output;
  uLongf olen;

  olen = outputSize;
  output = GNUNET_malloc (olen);
  if (Z_OK == uncompress ((Bytef *) output,
                          &olen, (const Bytef *) input, inputSize))
    {
      return output;
    }
  else
    {
      GNUNET_free (output);
      return NULL;
    }
}

/**
 * Flag in 'version' that indicates compressed meta-data.
 */
#define HEADER_COMPRESSED 0x80000000

/**
 * Bits in 'version' that give the version number.
 */
#define HEADER_VERSION_MASK 0x7FFFFFFF

struct MetaDataHeader
{
  /**
   * The version of the MD serialization.
   * The highest bit is used to indicate
   * compression.
   *
   * Version 0 is the current version;
   * Version is 1 for a NULL pointer.
   * Other version numbers are not yet defined.
   */
  uint32_t version;

  /**
   * How many MD entries are there?
   */
  uint32_t entries;

  /**
   * Size of the MD (decompressed)
   */
  uint32_t size;

  /**
   * This is followed by 'entries' values of type 'unsigned int' that
   * correspond to EXTRACTOR_KeywordTypes.  After that, the meta-data
   * keywords follow (0-terminated).  The MD block always ends with
   * 0-termination, padding with 0 until a multiple of 8 bytes.
   */

};

/**
 * Serialize meta-data to target.
 *
 * @param md metadata to serialize
 * @param target where to write the serialized metadata
 * @param max maximum number of bytes available in target
 * @param opt is it ok to just write SOME of the
 *        meta-data to match the size constraint,
 *        possibly discarding some data?
 * @return number of bytes written on success,
 *         GNUNET_SYSERR on error (typically: not enough
 *         space)
 */
ssize_t
GNUNET_CONTAINER_meta_data_serialize (const struct GNUNET_CONTAINER_MetaData
                                      *md, char *target, size_t max,
                                      enum
                                      GNUNET_CONTAINER_MetaDataSerializationOptions
                                      opt)
{
  struct MetaDataHeader *hdr;
  size_t size;
  size_t pos;
  uint32_t i;
  size_t len;
  uint32_t ic;

  if (max < sizeof (struct MetaDataHeader))
    return GNUNET_SYSERR;       /* far too small */
  ic = md ? md->itemCount : 0;
  hdr = NULL;
  while (1)
    {
      size = sizeof (struct MetaDataHeader);
      size += sizeof (uint32_t) * ic;
      for (i = 0; i < ic; i++)
        size += 1 + strlen (md->items[i].data);
      while (size % 8 != 0)
        size++;
      hdr = GNUNET_malloc (size);
      hdr->version = htonl (md == NULL ? 1 : 0);
      hdr->entries = htonl (ic);
      for (i = 0; i < ic; i++)
        ((uint32_t *) &hdr[1])[i] =
          htonl ((uint32_t) md->items[i].type);
      pos = sizeof (struct MetaDataHeader);
      pos += sizeof (unsigned int) * ic;
      for (i = 0; i < ic; i++)
        {
          len = strlen (md->items[i].data) + 1;
          memcpy (&((char *) hdr)[pos], md->items[i].data, len);
          pos += len;
        }

      hdr->size = htonl (size);
      if ((opt & GNUNET_CONTAINER_META_DATA_SERIALIZE_NO_COMPRESS) == 0)
        {
          pos = tryCompression ((char *) &hdr[1],
                                size - sizeof (struct MetaDataHeader));
        }
      else
        {
          pos = size - sizeof (struct MetaDataHeader);
        }
      if (pos < size - sizeof (struct MetaDataHeader))
        {
          hdr->version = htonl (HEADER_COMPRESSED);
          size = pos + sizeof (struct MetaDataHeader);
        }
      if (size <= max)
        break;
      GNUNET_free (hdr);
      hdr = NULL;

      if ((opt & GNUNET_CONTAINER_META_DATA_SERIALIZE_PART) == 0)
        {
          return GNUNET_SYSERR; /* does not fit! */
        }
      /* partial serialization ok, try again with less meta-data */
      if (size > 2 * max)
        ic = ic * 2 / 3;        /* still far too big, make big reductions */
      else
        ic--;                   /* small steps, we're close */
    }
  GNUNET_assert (size <= max);
  memcpy (target, hdr, size);
  GNUNET_free (hdr);
  /* extra check: deserialize! */
#if EXTRA_CHECKS
  {
    struct GNUNET_CONTAINER_MetaData *mdx;
    mdx = GNUNET_CONTAINER_meta_data_deserialize (target, size);
    GNUNET_assert (NULL != mdx);
    GNUNET_CONTAINER_meta_data_destroy (mdx);
  }
#endif
  return size;
}

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
ssize_t
GNUNET_CONTAINER_meta_data_get_serialized_size (const struct
                                                GNUNET_CONTAINER_MetaData *md,
                                                enum
                                                GNUNET_CONTAINER_MetaDataSerializationOptions
                                                opt)
{
  struct MetaDataHeader *hdr;
  size_t size;
  size_t pos;
  uint32_t i;
  size_t len;
  uint32_t ic;

  ic = md ? md->itemCount : 0;
  size = sizeof (struct MetaDataHeader);
  size += sizeof (uint32_t) * ic;
  for (i = 0; i < ic; i++)
    size += 1 + strlen (md->items[i].data);
  while (size % 8 != 0)
    size++;
  hdr = GNUNET_malloc (size);
  hdr->version = htonl (md == NULL ? 1 : 0);
  hdr->entries = htonl (ic);
  for (i = 0; i < ic; i++)
    ((uint32_t *) &hdr[1])[i] = htonl ((uint32_t) md->items[i].type);
  pos = sizeof (struct MetaDataHeader);
  pos += sizeof (uint32_t) * ic;
  for (i = 0; i < ic; i++)
    {
      len = strlen (md->items[i].data) + 1;
      memcpy (&((char *) hdr)[pos], md->items[i].data, len);
      pos += len;
    }
  if ((opt & GNUNET_CONTAINER_META_DATA_SERIALIZE_NO_COMPRESS) == 0)
    {
      pos =
        tryCompression ((char *) &hdr[1],
                        size - sizeof (struct MetaDataHeader));
    }
  else
    {
      pos = size - sizeof (struct MetaDataHeader);
    }
  if (pos < size - sizeof (struct MetaDataHeader))
    size = pos + sizeof (struct MetaDataHeader);
  GNUNET_free (hdr);
  return size;
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
  const struct MetaDataHeader *hdr;
  uint32_t ic;
  char *data;
  const char *cdata;
  uint32_t dataSize;
  int compressed;
  uint32_t i;
  size_t pos;
  size_t len;
  uint32_t version;

  if (size < sizeof (struct MetaDataHeader))
    return NULL;
  hdr = (const struct MetaDataHeader *) input;
  version = ntohl (MAKE_UNALIGNED (hdr->version)) & HEADER_VERSION_MASK;
  if (version == 1)
    return NULL;                /* null pointer */
  if (version != 0)
    {
      GNUNET_break_op (0);      /* unsupported version */
      return NULL;
    }
  ic = ntohl (MAKE_UNALIGNED (hdr->entries));
  compressed =
    (ntohl (MAKE_UNALIGNED (hdr->version)) & HEADER_COMPRESSED) != 0;
  if (compressed)
    {
      dataSize =
        ntohl (MAKE_UNALIGNED (hdr->size)) - sizeof (struct MetaDataHeader);
      if (dataSize > 2 * 1042 * 1024)
        {
          GNUNET_break (0);
          return NULL;          /* only 2 MB allowed [to make sure we don't blow
                                   our memory limit because of a mal-formed
                                   message... ] */
        }
      data =
        decompress ((const char *) &input[sizeof (struct MetaDataHeader)],
                    size - sizeof (struct MetaDataHeader), dataSize);
      if (data == NULL)
        {
          GNUNET_break_op (0);
          return NULL;
        }
      cdata = data;
    }
  else
    {
      data = NULL;
      cdata = (const char *) &hdr[1];
      dataSize = size - sizeof (struct MetaDataHeader);
      if (size != ntohl (MAKE_UNALIGNED (hdr->size)))
        {
          GNUNET_break (0);
          return NULL;
        }
    }

  if ((sizeof (uint32_t) * ic + ic) > dataSize)
    {
      GNUNET_break (0);
      goto FAILURE;
    }
  if ((ic > 0) && (cdata[dataSize - 1] != '\0'))
    {
      GNUNET_break (0);
      goto FAILURE;
    }

  md = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_array_grow (md->items, md->itemCount, ic);
  i = 0;
  pos = sizeof (uint32_t) * ic;
  while ((pos < dataSize) && (i < ic))
    {
      len = strlen (&cdata[pos]) + 1;
      md->items[i].type = (EXTRACTOR_KeywordType)
        ntohl (MAKE_UNALIGNED (((const uint32_t *) cdata)[i]));
      md->items[i].data = GNUNET_strdup (&cdata[pos]);
      pos += len;
      i++;
    }
  if (i < ic)
    {                           /* oops */
      GNUNET_CONTAINER_meta_data_destroy (md);
      goto FAILURE;
    }
  GNUNET_free_non_null (data);
  return md;
FAILURE:
  GNUNET_free_non_null (data);
  return NULL;                  /* size too small */
}

/**
 * Test if two MDs are equal.
 *
 * @param md1 first value to check
 * @param md2 other value to check
 * @return GNUNET_YES if they are equal
 */
int
GNUNET_CONTAINER_meta_data_test_equal (const struct GNUNET_CONTAINER_MetaData
                                       *md1,
                                       const struct GNUNET_CONTAINER_MetaData
                                       *md2)
{
  uint32_t i;
  uint32_t j;
  int found;

  if (md1->itemCount != md2->itemCount)
    return GNUNET_NO;
  for (i = 0; i < md1->itemCount; i++)
    {
      found = GNUNET_NO;
      for (j = 0; j < md2->itemCount; j++)
        if ((md1->items[i].type == md2->items[j].type) &&
            (0 == strcmp (md1->items[i].data, md2->items[j].data)))
          {
            found = GNUNET_YES;
            break;
          }
      if (found == GNUNET_NO)
        return GNUNET_NO;
    }
  return GNUNET_YES;
}


/* end of container_meta_data.c */
