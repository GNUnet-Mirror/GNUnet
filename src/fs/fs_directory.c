/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_directory.c
 * @brief Helper functions for building directories.
 * @author Christian Grothoff
 *
 * TODO:
 * - modify directory builder API to support incremental
 *   generation of directories (to allow directories that
 *   would not fit into memory to be created)
 * - modify directory processor API to support incremental
 *   iteration over FULL directories (without missing entries)
 *   to allow access to directories that do not fit entirely
 *   into memory
 */
#include "platform.h"
#include "gnunet_fs_service.h"
#include "fs_api.h"

/**
 * String that is used to indicate that a file
 * is a GNUnet directory.
 */
#define GNUNET_DIRECTORY_MAGIC "\211GND\r\n\032\n"


/**
 * Does the meta-data claim that this is a directory?
 * Checks if the mime-type is that of a GNUnet directory.
 *
 * @return GNUNET_YES if it is, GNUNET_NO if it is not, GNUNET_SYSERR if
 *  we have no mime-type information (treat as 'GNUNET_NO')
 */
int
GNUNET_FS_meta_data_test_for_directory (const struct GNUNET_CONTAINER_MetaData
                                        *md)
{
  char *mime;
  int ret;

  if (NULL == md)
    return GNUNET_SYSERR;
  mime =
      GNUNET_CONTAINER_meta_data_get_by_type (md, EXTRACTOR_METATYPE_MIMETYPE);
  if (mime == NULL)
    return GNUNET_SYSERR;
  ret = (0 == strcmp (mime, GNUNET_FS_DIRECTORY_MIME)) ? GNUNET_YES : GNUNET_NO;
  GNUNET_free (mime);
  return ret;
}


/**
 * Set the MIMETYPE information for the given
 * metadata to "application/gnunet-directory".
 *
 * @param md metadata to add mimetype to
 */
void
GNUNET_FS_meta_data_make_directory (struct GNUNET_CONTAINER_MetaData *md)
{
  char *mime;

  mime =
      GNUNET_CONTAINER_meta_data_get_by_type (md, EXTRACTOR_METATYPE_MIMETYPE);
  if (mime != NULL)
  {
    GNUNET_break (0 == strcmp (mime, GNUNET_FS_DIRECTORY_MIME));
    GNUNET_free (mime);
    return;
  }
  GNUNET_CONTAINER_meta_data_insert (md, "<gnunet>",
                                     EXTRACTOR_METATYPE_MIMETYPE,
                                     EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                     GNUNET_FS_DIRECTORY_MIME,
                                     strlen (GNUNET_FS_DIRECTORY_MIME) + 1);
}


/**
 * Closure for 'find_full_data'.
 */
struct GetFullDataClosure
{

  /**
   * Extracted binary meta data.
   */
  void *data;

  /**
   * Number of bytes stored in data.
   */
  size_t size;
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
 * @param format basic format information about data
 * @param data_mime_type mime-type of data (not of the original file);
 *        can be NULL (if mime-type is not known)
 * @param data actual meta-data found
 * @param data_len number of bytes in data
 * @return 0 to continue extracting, 1 to abort
 */
static int
find_full_data (void *cls, const char *plugin_name,
                enum EXTRACTOR_MetaType type, enum EXTRACTOR_MetaFormat format,
                const char *data_mime_type, const char *data, size_t data_len)
{
  struct GetFullDataClosure *gfdc = cls;

  if (type == EXTRACTOR_METATYPE_GNUNET_FULL_DATA)
  {
    gfdc->size = data_len;
    if (data_len > 0)
    {
      gfdc->data = GNUNET_malloc (data_len);
      memcpy (gfdc->data, data, data_len);
    }
    return 1;
  }
  return 0;
}


/**
 * Iterate over all entries in a directory.  Note that directories
 * are structured such that it is possible to iterate over the
 * individual blocks as well as over the entire directory.  Thus
 * a client can call this function on the buffer in the
 * GNUNET_FS_ProgressCallback.  Also, directories can optionally
 * include the contents of (small) files embedded in the directory
 * itself; for those files, the processor may be given the
 * contents of the file directly by this function.
 * <p>
 *
 * Note that this function maybe called on parts of directories.  Thus
 * parser errors should not be reported _at all_ (with GNUNET_break).
 * Still, if some entries can be recovered despite these parsing
 * errors, the function should try to do this.
 *
 * @param size number of bytes in data
 * @param data pointer to the beginning of the directory
 * @param offset offset of data in the directory
 * @param dep function to call on each entry
 * @param dep_cls closure for dep
 * @return GNUNET_OK if this could be a block in a directory,
 *         GNUNET_NO if this could be part of a directory (but not 100% OK)
 *         GNUNET_SYSERR if 'data' does not represent a directory
 */
int
GNUNET_FS_directory_list_contents (size_t size, const void *data,
                                   uint64_t offset,
                                   GNUNET_FS_DirectoryEntryProcessor dep,
                                   void *dep_cls)
{
  struct GetFullDataClosure full_data;
  const char *cdata = data;
  char *emsg;
  uint64_t pos;
  uint64_t align;
  uint32_t mdSize;
  uint64_t epos;
  struct GNUNET_FS_Uri *uri;
  struct GNUNET_CONTAINER_MetaData *md;
  char *filename;

  if ((offset == 0) &&
      ((size < 8 + sizeof (uint32_t)) ||
       (0 != memcmp (cdata, GNUNET_FS_DIRECTORY_MAGIC, 8))))
    return GNUNET_SYSERR;
  pos = offset;
  if (offset == 0)
  {
    memcpy (&mdSize, &cdata[8], sizeof (uint32_t));
    mdSize = ntohl (mdSize);
    if (mdSize > size - 8 - sizeof (uint32_t))
    {
      /* invalid size */
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("MAGIC mismatch.  This is not a GNUnet directory.\n"));
      return GNUNET_SYSERR;
    }
    md = GNUNET_CONTAINER_meta_data_deserialize (&cdata[8 + sizeof (uint32_t)],
                                                 mdSize);
    if (md == NULL)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;     /* malformed ! */
    }
    dep (dep_cls, NULL, NULL, md, 0, NULL);
    GNUNET_CONTAINER_meta_data_destroy (md);
    pos = 8 + sizeof (uint32_t) + mdSize;
  }
  while (pos < size)
  {
    /* find end of URI */
    if (cdata[pos] == '\0')
    {
      /* URI is never empty, must be end of block,
       * skip to next alignment */
      align = ((pos / DBLOCK_SIZE) + 1) * DBLOCK_SIZE;
      if (align == pos)
      {
        /* if we were already aligned, still skip a block! */
        align += DBLOCK_SIZE;
      }
      pos = align;
      if (pos >= size)
      {
        /* malformed - or partial download... */
        break;
      }
    }
    epos = pos;
    while ((epos < size) && (cdata[epos] != '\0'))
      epos++;
    if (epos >= size)
      return GNUNET_NO;         /* malformed - or partial download */

    uri = GNUNET_FS_uri_parse (&cdata[pos], &emsg);
    pos = epos + 1;
    if (uri == NULL)
    {
      GNUNET_free (emsg);
      pos--;                    /* go back to '\0' to force going to next alignment */
      continue;
    }
    if (GNUNET_FS_uri_test_ksk (uri))
    {
      GNUNET_FS_uri_destroy (uri);
      GNUNET_break (0);
      return GNUNET_NO;         /* illegal in directory! */
    }

    memcpy (&mdSize, &cdata[pos], sizeof (uint32_t));
    mdSize = ntohl (mdSize);
    pos += sizeof (uint32_t);
    if (pos + mdSize > size)
    {
      GNUNET_FS_uri_destroy (uri);
      return GNUNET_NO;         /* malformed - or partial download */
    }

    md = GNUNET_CONTAINER_meta_data_deserialize (&cdata[pos], mdSize);
    if (md == NULL)
    {
      GNUNET_FS_uri_destroy (uri);
      GNUNET_break (0);
      return GNUNET_NO;         /* malformed ! */
    }
    pos += mdSize;
    filename =
        GNUNET_CONTAINER_meta_data_get_by_type (md,
                                                EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME);
    full_data.size = 0;
    full_data.data = NULL;
    GNUNET_CONTAINER_meta_data_iterate (md, &find_full_data, &full_data);
    if (dep != NULL)
    {
      dep (dep_cls, filename, uri, md, full_data.size, full_data.data);
    }
    GNUNET_free_non_null (full_data.data);
    GNUNET_free_non_null (filename);
    GNUNET_CONTAINER_meta_data_destroy (md);
    GNUNET_FS_uri_destroy (uri);
  }
  return GNUNET_OK;
}

/**
 * Entries in the directory (builder).
 */
struct BuilderEntry
{
  /**
   * This is a linked list.
   */
  struct BuilderEntry *next;

  /**
   * Length of this entry.
   */
  size_t len;
};

/**
 * Internal state of a directory builder.
 */
struct GNUNET_FS_DirectoryBuilder
{
  /**
   * Meta-data for the directory itself.
   */
  struct GNUNET_CONTAINER_MetaData *meta;

  /**
   * Head of linked list of entries.
   */
  struct BuilderEntry *head;

  /**
   * Number of entires in the directory.
   */
  unsigned int count;
};


/**
 * Create a directory builder.
 *
 * @param mdir metadata for the directory
 */
struct GNUNET_FS_DirectoryBuilder *
GNUNET_FS_directory_builder_create (const struct GNUNET_CONTAINER_MetaData
                                    *mdir)
{
  struct GNUNET_FS_DirectoryBuilder *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_DirectoryBuilder));
  if (mdir != NULL)
    ret->meta = GNUNET_CONTAINER_meta_data_duplicate (mdir);
  else
    ret->meta = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_FS_meta_data_make_directory (ret->meta);
  return ret;
}


/**
 * Add an entry to a directory.
 *
 * @param bld directory to extend
 * @param uri uri of the entry (must not be a KSK)
 * @param md metadata of the entry
 * @param data raw data of the entry, can be NULL, otherwise
 *        data must point to exactly the number of bytes specified
 *        by the uri which must be of type LOC or CHK
 */
void
GNUNET_FS_directory_builder_add (struct GNUNET_FS_DirectoryBuilder *bld,
                                 const struct GNUNET_FS_Uri *uri,
                                 const struct GNUNET_CONTAINER_MetaData *md,
                                 const void *data)
{
  struct GNUNET_FS_Uri *curi;
  struct BuilderEntry *e;
  uint64_t fsize;
  uint32_t big;
  ssize_t ret;
  size_t mds;
  size_t mdxs;
  char *uris;
  char *ser;
  char *sptr;
  size_t slen;
  struct GNUNET_CONTAINER_MetaData *meta;
  const struct GNUNET_CONTAINER_MetaData *meta_use;

  GNUNET_assert (!GNUNET_FS_uri_test_ksk (uri));
  if (NULL != data)
  {
    GNUNET_assert (!GNUNET_FS_uri_test_sks (uri));
    if (GNUNET_FS_uri_test_chk (uri))
    {
      fsize = GNUNET_FS_uri_chk_get_file_size (uri);
    }
    else
    {
      curi = GNUNET_FS_uri_loc_get_uri (uri);
      GNUNET_assert (NULL != curi);
      fsize = GNUNET_FS_uri_chk_get_file_size (curi);
      GNUNET_FS_uri_destroy (curi);
    }
  }
  else
  {
    fsize = 0;                  /* not given */
  }
  if (fsize > MAX_INLINE_SIZE)
    fsize = 0;                  /* too large */
  uris = GNUNET_FS_uri_to_string (uri);
  slen = strlen (uris) + 1;
  mds = GNUNET_CONTAINER_meta_data_get_serialized_size (md);
  meta_use = md;
  meta = NULL;
  if (fsize > 0)
  {
    meta = GNUNET_CONTAINER_meta_data_duplicate (md);
    GNUNET_CONTAINER_meta_data_insert (meta, "<gnunet>",
                                       EXTRACTOR_METATYPE_GNUNET_FULL_DATA,
                                       EXTRACTOR_METAFORMAT_BINARY, NULL, data,
                                       fsize);
    mdxs = GNUNET_CONTAINER_meta_data_get_serialized_size (meta);
    if ((slen + sizeof (uint32_t) + mdxs - 1) / DBLOCK_SIZE ==
        (slen + sizeof (uint32_t) + mds - 1) / DBLOCK_SIZE)
    {
      /* adding full data would not cause us to cross
       * additional blocks, so add it! */
      meta_use = meta;
      mds = mdxs;
    }
  }

  if (mds > GNUNET_MAX_MALLOC_CHECKED / 2)
    mds = GNUNET_MAX_MALLOC_CHECKED / 2;
  e = GNUNET_malloc (sizeof (struct BuilderEntry) + slen + mds +
                     sizeof (uint32_t));
  ser = (char *) &e[1];
  memcpy (ser, uris, slen);
  GNUNET_free (uris);
  sptr = &ser[slen + sizeof (uint32_t)];
  ret =
      GNUNET_CONTAINER_meta_data_serialize (meta_use, &sptr, mds,
                                            GNUNET_CONTAINER_META_DATA_SERIALIZE_PART);
  if (NULL != meta)
    GNUNET_CONTAINER_meta_data_destroy (meta);
  if (ret == -1)
    mds = 0;
  else
    mds = ret;
  big = htonl (mds);
  memcpy (&ser[slen], &big, sizeof (uint32_t));
  e->len = slen + sizeof (uint32_t) + mds;
  e->next = bld->head;
  bld->head = e;
  bld->count++;
}


/**
 * Given the start and end position of a block of
 * data, return the end position of that data
 * after alignment to the DBLOCK_SIZE.
 */
static size_t
do_align (size_t start_position, size_t end_position)
{
  size_t align;

  align = (end_position / DBLOCK_SIZE) * DBLOCK_SIZE;
  if ((start_position < align) && (end_position > align))
    return align + end_position - start_position;
  return end_position;
}


/**
 * Compute a permuation of the blocks to
 * minimize the cost of alignment.  Greedy packer.
 *
 * @param start starting position for the first block
 * @param count size of the two arrays
 * @param sizes the sizes of the individual blocks
 * @param perm the permutation of the blocks (updated)
 */
static void
block_align (size_t start, unsigned int count, const size_t * sizes,
             unsigned int *perm)
{
  unsigned int i;
  unsigned int j;
  unsigned int tmp;
  unsigned int best;
  ssize_t badness;
  size_t cpos;
  size_t cend;
  ssize_t cbad;
  unsigned int cval;

  cpos = start;
  for (i = 0; i < count; i++)
  {
    start = cpos;
    badness = 0x7FFFFFFF;
    best = -1;
    for (j = i; j < count; j++)
    {
      cval = perm[j];
      cend = cpos + sizes[cval];
      if (cpos % DBLOCK_SIZE == 0)
      {
        /* prefer placing the largest blocks first */
        cbad = -(cend % DBLOCK_SIZE);
      }
      else
      {
        if (cpos / DBLOCK_SIZE == cend / DBLOCK_SIZE)
        {
          /* Data fits into the same block! Prefer small left-overs! */
          cbad = DBLOCK_SIZE - cend % DBLOCK_SIZE;
        }
        else
        {
          /* Would have to waste space to re-align, add big factor, this
           * case is a real loss (proportional to space wasted)! */
          cbad = DBLOCK_SIZE * (DBLOCK_SIZE - cpos % DBLOCK_SIZE);
        }
      }
      if (cbad < badness)
      {
        best = j;
        badness = cbad;
      }
    }
    GNUNET_assert (best != -1);
    tmp = perm[i];
    perm[i] = perm[best];
    perm[best] = tmp;
    cpos += sizes[perm[i]];
    cpos = do_align (start, cpos);
  }
}


/**
 * Finish building the directory.  Frees the
 * builder context and returns the directory
 * in-memory.
 *
 * @param bld directory to finish
 * @param rsize set to the number of bytes needed
 * @param rdata set to the encoded directory
 * @return GNUNET_OK on success
 */
int
GNUNET_FS_directory_builder_finish (struct GNUNET_FS_DirectoryBuilder *bld,
                                    size_t * rsize, void **rdata)
{
  char *data;
  char *sptr;
  size_t *sizes;
  unsigned int *perm;
  unsigned int i;
  unsigned int j;
  struct BuilderEntry *pos;
  struct BuilderEntry **bes;
  size_t size;
  size_t psize;
  size_t off;
  ssize_t ret;
  uint32_t big;

  size = strlen (GNUNET_DIRECTORY_MAGIC) + sizeof (uint32_t);
  size += GNUNET_CONTAINER_meta_data_get_serialized_size (bld->meta);
  sizes = NULL;
  perm = NULL;
  bes = NULL;
  if (0 < bld->count)
  {
    sizes = GNUNET_malloc (bld->count * sizeof (size_t));
    perm = GNUNET_malloc (bld->count * sizeof (unsigned int));
    bes = GNUNET_malloc (bld->count * sizeof (struct BuilderEntry *));
    pos = bld->head;
    for (i = 0; i < bld->count; i++)
    {
      perm[i] = i;
      bes[i] = pos;
      sizes[i] = pos->len;
      pos = pos->next;
    }
    block_align (size, bld->count, sizes, perm);
    /* compute final size with alignment */
    for (i = 0; i < bld->count; i++)
    {
      psize = size;
      size += sizes[perm[i]];
      size = do_align (psize, size);
    }
  }
  *rsize = size;
  data = GNUNET_malloc_large (size);
  if (data == NULL)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "malloc");
    *rsize = 0;
    *rdata = NULL;
    GNUNET_free_non_null (sizes);
    GNUNET_free_non_null (perm);
    GNUNET_free_non_null (bes);
    return GNUNET_SYSERR;
  }
  *rdata = data;
  memcpy (data, GNUNET_DIRECTORY_MAGIC, strlen (GNUNET_DIRECTORY_MAGIC));
  off = strlen (GNUNET_DIRECTORY_MAGIC);

  sptr = &data[off + sizeof (uint32_t)];
  ret =
      GNUNET_CONTAINER_meta_data_serialize (bld->meta, &sptr,
                                            size - off - sizeof (uint32_t),
                                            GNUNET_CONTAINER_META_DATA_SERIALIZE_FULL);
  GNUNET_assert (ret != -1);
  big = htonl (ret);
  memcpy (&data[off], &big, sizeof (uint32_t));
  off += sizeof (uint32_t) + ret;
  for (j = 0; j < bld->count; j++)
  {
    i = perm[j];
    psize = off;
    off += sizes[i];
    off = do_align (psize, off);
    memcpy (&data[off - sizes[i]], &(bes[i])[1], sizes[i]);
    GNUNET_free (bes[i]);
  }
  GNUNET_free_non_null (sizes);
  GNUNET_free_non_null (perm);
  GNUNET_free_non_null (bes);
  GNUNET_assert (off == size);
  GNUNET_CONTAINER_meta_data_destroy (bld->meta);
  GNUNET_free (bld);
  return GNUNET_OK;
}


/* end of fs_directory.c */
