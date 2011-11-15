/*
     This file is part of GNUnet.
     (C) 2009, 2011 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_file_information.c
 * @brief  Manage information for publishing directory hierarchies
 * @author Christian Grothoff
 *
 * TODO:
 * - metadata filename clean up code
 * - metadata/ksk generation for directories from contained files
 */
#include "platform.h"
#include <extractor.h>
#include "gnunet_fs_service.h"
#include "fs_api.h"
#include "fs_tree.h"


/**
 * Add meta data that libextractor finds to our meta data
 * container.
 *
 * @param cls closure, our meta data container
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
 * @return always 0 to continue extracting
 */
static int
add_to_md (void *cls, const char *plugin_name, enum EXTRACTOR_MetaType type,
           enum EXTRACTOR_MetaFormat format, const char *data_mime_type,
           const char *data, size_t data_len)
{
  struct GNUNET_CONTAINER_MetaData *md = cls;

  (void) GNUNET_CONTAINER_meta_data_insert (md, plugin_name, type, format,
                                            data_mime_type, data, data_len);
  return 0;
}


/**
 * Extract meta-data from a file.
 *
 * @return GNUNET_SYSERR on error, otherwise the number
 *   of meta-data items obtained
 */
int
GNUNET_FS_meta_data_extract_from_file (struct GNUNET_CONTAINER_MetaData *md,
                                       const char *filename,
                                       struct EXTRACTOR_PluginList *extractors)
{
  int old;

  if (filename == NULL)
    return GNUNET_SYSERR;
  if (extractors == NULL)
    return 0;
  old = GNUNET_CONTAINER_meta_data_iterate (md, NULL, NULL);
  GNUNET_assert (old >= 0);
  EXTRACTOR_extract (extractors, filename, NULL, 0, &add_to_md, md);
  return (GNUNET_CONTAINER_meta_data_iterate (md, NULL, NULL) - old);
}



/**
 * Obtain the name under which this file information
 * structure is stored on disk.  Only works for top-level
 * file information structures.
 *
 * @param s structure to get the filename for
 * @return NULL on error, otherwise filename that
 *         can be passed to "GNUNET_FS_file_information_recover"
 *         to read this fi-struct from disk.
 */
const char *
GNUNET_FS_file_information_get_id (struct GNUNET_FS_FileInformation *s)
{
  if (NULL != s->dir)
    return NULL;
  return s->serialization;
}


/**
 * Create an entry for a file in a publish-structure.
 *
 * @param h handle to the file sharing subsystem
 * @param client_info initial value for the client-info value for this entry
 * @param filename name of the file or directory to publish
 * @param keywords under which keywords should this file be available
 *         directly; can be NULL
 * @param meta metadata for the file
 * @param do_index GNUNET_YES for index, GNUNET_NO for insertion,
 *                GNUNET_SYSERR for simulation
 * @param bo block options
 * @return publish structure entry for the file
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_file (struct GNUNET_FS_Handle *h,
                                             void *client_info,
                                             const char *filename,
                                             const struct GNUNET_FS_Uri
                                             *keywords,
                                             const struct
                                             GNUNET_CONTAINER_MetaData *meta,
                                             int do_index,
                                             const struct GNUNET_FS_BlockOptions
                                             *bo)
{
  struct FileInfo *fi;
  struct stat sbuf;
  struct GNUNET_FS_FileInformation *ret;
  const char *fn;
  const char *ss;

#if WINDOWS
  char fn_conv[MAX_PATH];
#endif

  if (0 != STAT (filename, &sbuf))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "stat", filename);
    return NULL;
  }
  fi = GNUNET_FS_make_file_reader_context_ (filename);
  if (fi == NULL)
  {
    GNUNET_break (0);
    return NULL;
  }
  ret =
      GNUNET_FS_file_information_create_from_reader (h, client_info,
                                                     sbuf.st_size,
                                                     &GNUNET_FS_data_reader_file_,
                                                     fi, keywords, meta,
                                                     do_index, bo);
  if (ret == NULL)
    return NULL;
  ret->h = h;
  ret->filename = GNUNET_strdup (filename);
#if !WINDOWS
  fn = filename;
#else
  plibc_conv_to_win_path (filename, fn_conv);
  fn = fn_conv;
#endif
  while (NULL != (ss = strstr (fn, DIR_SEPARATOR_STR)))
    fn = ss + 1;
  GNUNET_CONTAINER_meta_data_insert (ret->meta, "<gnunet>",
                                     EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME,
                                     EXTRACTOR_METAFORMAT_C_STRING,
                                     "text/plain", fn, strlen (fn) + 1);
  return ret;
}


/**
 * Create an entry for a file in a publish-structure.
 *
 * @param h handle to the file sharing subsystem
 * @param client_info initial value for the client-info value for this entry
 * @param length length of the file
 * @param data data for the file (should not be used afterwards by
 *        the caller; callee will "free")
 * @param keywords under which keywords should this file be available
 *         directly; can be NULL
 * @param meta metadata for the file
 * @param do_index GNUNET_YES for index, GNUNET_NO for insertion,
 *                GNUNET_SYSERR for simulation
 * @param bo block options
 * @return publish structure entry for the file
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_data (struct GNUNET_FS_Handle *h,
                                             void *client_info, uint64_t length,
                                             void *data,
                                             const struct GNUNET_FS_Uri
                                             *keywords,
                                             const struct
                                             GNUNET_CONTAINER_MetaData *meta,
                                             int do_index,
                                             const struct GNUNET_FS_BlockOptions
                                             *bo)
{
  if (GNUNET_YES == do_index)
  {
    GNUNET_break (0);
    return NULL;
  }
  return GNUNET_FS_file_information_create_from_reader (h, client_info, length,
                                                        &GNUNET_FS_data_reader_copy_,
                                                        data, keywords, meta,
                                                        do_index, bo);
}


/**
 * Create an entry for a file in a publish-structure.
 *
 * @param h handle to the file sharing subsystem
 * @param client_info initial value for the client-info value for this entry
 * @param length length of the file
 * @param reader function that can be used to obtain the data for the file
 * @param reader_cls closure for "reader"
 * @param keywords under which keywords should this file be available
 *         directly; can be NULL
 * @param meta metadata for the file
 * @param do_index GNUNET_YES for index, GNUNET_NO for insertion,
 *                GNUNET_SYSERR for simulation
 * @param bo block options
 * @return publish structure entry for the file
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_reader (struct GNUNET_FS_Handle *h,
                                               void *client_info,
                                               uint64_t length,
                                               GNUNET_FS_DataReader reader,
                                               void *reader_cls,
                                               const struct GNUNET_FS_Uri
                                               *keywords,
                                               const struct
                                               GNUNET_CONTAINER_MetaData *meta,
                                               int do_index,
                                               const struct
                                               GNUNET_FS_BlockOptions *bo)
{
  struct GNUNET_FS_FileInformation *ret;

  if ((GNUNET_YES == do_index) && (reader != &GNUNET_FS_data_reader_file_))
  {
    GNUNET_break (0);
    return NULL;
  }
  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_FileInformation));
  ret->h = h;
  ret->client_info = client_info;
  ret->meta = GNUNET_CONTAINER_meta_data_duplicate (meta);
  if (ret->meta == NULL)
    ret->meta = GNUNET_CONTAINER_meta_data_create ();
  ret->keywords = (keywords == NULL) ? NULL : GNUNET_FS_uri_dup (keywords);
  ret->data.file.reader = reader;
  ret->data.file.reader_cls = reader_cls;
  ret->data.file.do_index = do_index;
  ret->data.file.file_size = length;
  ret->bo = *bo;
  return ret;
}


/**
 * Closure for "dir_scan_cb".
 */
struct DirScanCls
{
  /**
   * Metadata extractors to use.
   */
  struct EXTRACTOR_PluginList *extractors;

  /**
   * Master context.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * Function to call on each directory entry.
   */
  GNUNET_FS_FileProcessor proc;

  /**
   * Closure for proc.
   */
  void *proc_cls;

  /**
   * Scanner to use for subdirectories.
   */
  GNUNET_FS_DirectoryScanner scanner;

  /**
   * Closure for scanner.
   */
  void *scanner_cls;

  /**
   * Set to an error message (if any).
   */
  char *emsg;

  /**
   * Block options.
   */
  const struct GNUNET_FS_BlockOptions *bo;

  /**
   * Should files be indexed?
   */
  int do_index;

};


/**
 * Function called on each entry in a file to cause
 * default-publishing.
 *
 * @param cls closure (struct DirScanCls)
 * @param filename name of the file to be published
 * @return GNUNET_OK on success, GNUNET_SYSERR to abort
 */
static int
dir_scan_cb (void *cls, const char *filename)
{
  struct DirScanCls *dsc = cls;
  struct stat sbuf;
  struct GNUNET_FS_FileInformation *fi;
  struct GNUNET_FS_Uri *ksk_uri;
  struct GNUNET_FS_Uri *keywords;
  struct GNUNET_CONTAINER_MetaData *meta;

  if (0 != STAT (filename, &sbuf))
  {
    GNUNET_asprintf (&dsc->emsg, _("`%s' failed on file `%s': %s"), "stat",
                     filename, STRERROR (errno));
    return GNUNET_SYSERR;
  }
  if (S_ISDIR (sbuf.st_mode))
  {
    fi = GNUNET_FS_file_information_create_from_directory (dsc->h, NULL,
                                                           filename,
                                                           dsc->scanner,
                                                           dsc->scanner_cls,
                                                           dsc->do_index,
                                                           dsc->bo, &dsc->emsg);
    if (NULL == fi)
    {
      GNUNET_assert (NULL != dsc->emsg);
      return GNUNET_SYSERR;
    }
  }
  else
  {
    meta = GNUNET_CONTAINER_meta_data_create ();
    GNUNET_FS_meta_data_extract_from_file (meta, filename, dsc->extractors);
    keywords = GNUNET_FS_uri_ksk_create_from_meta_data (meta);
    ksk_uri = GNUNET_FS_uri_ksk_canonicalize (keywords);
    fi = GNUNET_FS_file_information_create_from_file (dsc->h, NULL, filename,
                                                      ksk_uri, meta,
                                                      dsc->do_index, dsc->bo);
    GNUNET_CONTAINER_meta_data_destroy (meta);
    GNUNET_FS_uri_destroy (keywords);
    GNUNET_FS_uri_destroy (ksk_uri);
  }
  dsc->proc (dsc->proc_cls, filename, fi);
  return GNUNET_OK;
}


/**
 * Simple, useful default implementation of a directory scanner
 * (GNUNET_FS_DirectoryScanner).  This implementation expects to get a
 * UNIX filename, will publish all files in the directory except hidden
 * files (those starting with a ".").  Metadata will be extracted
 * using GNU libextractor; the specific list of plugins should be
 * specified in "cls", passing NULL will disable (!)  metadata
 * extraction.  Keywords will be derived from the metadata and be
 * subject to default canonicalization.  This is strictly a
 * convenience function.
 *
 * @param cls must be of type "struct EXTRACTOR_Extractor*"
 * @param h handle to the file sharing subsystem
 * @param dirname name of the directory to scan
 * @param do_index should files be indexed or inserted
 * @param bo block options
 * @param proc function called on each entry
 * @param proc_cls closure for proc
 * @param emsg where to store an error message (on errors)
 * @return GNUNET_OK on success
 */
int
GNUNET_FS_directory_scanner_default (void *cls, struct GNUNET_FS_Handle *h,
                                     const char *dirname, int do_index,
                                     const struct GNUNET_FS_BlockOptions *bo,
                                     GNUNET_FS_FileProcessor proc,
                                     void *proc_cls, char **emsg)
{
  struct EXTRACTOR_PluginList *ex = cls;
  struct DirScanCls dsc;

  dsc.h = h;
  dsc.extractors = ex;
  dsc.proc = proc;
  dsc.proc_cls = proc_cls;
  dsc.scanner = &GNUNET_FS_directory_scanner_default;
  dsc.scanner_cls = cls;
  dsc.do_index = do_index;
  dsc.bo = bo;
  if (-1 == GNUNET_DISK_directory_scan (dirname, &dir_scan_cb, &dsc))
  {
    GNUNET_assert (NULL != dsc.emsg);
    *emsg = dsc.emsg;
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Aggregate information we keep for meta data in each directory.
 */
struct MetaValueInformation
{

  /**
   * Mime-type of data.
   */
  const char *mime_type;

  /**
   * The actual meta data.
   */
  const char *data;

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

  /**
   * How often does this meta value occur in this directory?
   */
  unsigned int frequency;

};


/**
 * Type of a function that libextractor calls for each
 * meta data item found.
 *
 * @param cls the container multihashmap to update
 * @param plugin_name name of the plugin that produced this value;
 *        special values can be used (i.e. '<zlib>' for zlib being
 *        used in the main libextractor library and yielding
 *        meta data).
 * @param type libextractor-type describing the meta data
 * @param format basic format information about data
 * @param data_mime_type mime-type of data (not of the original file);
 *        can be NULL (if mime-type is not known)
 * @param data actual meta-data found
 * @param data_len number of bytes in data
 * @return 0 to continue extracting / iterating
 */
static int
update_metamap (void *cls, const char *plugin_name,
                enum EXTRACTOR_MetaType type, enum EXTRACTOR_MetaFormat format,
                const char *data_mime_type, const char *data, size_t data_len)
{
  struct GNUNET_CONTAINER_MultiHashMap *map = cls;
  GNUNET_HashCode key;
  struct MetaValueInformation *mvi;

  GNUNET_CRYPTO_hash (data, data_len, &key);
  mvi = GNUNET_CONTAINER_multihashmap_get (map, &key);
  if (mvi == NULL)
  {
    mvi = GNUNET_malloc (sizeof (struct MetaValueInformation));
    mvi->mime_type = data_mime_type;
    mvi->data = data;
    mvi->data_size = data_len;
    mvi->type = type;
    mvi->format = format;
    GNUNET_CONTAINER_multihashmap_put (map, &key, mvi,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }
  mvi->frequency++;
  return 0;
}


/**
 * Aggregate information we keep for keywords in each directory.
 */
struct KeywordInformation
{

  /**
   * Mime-type of keyword.
   */
  const char *keyword;

  /**
   * How often does this meta value occur in this directory?
   */
  unsigned int frequency;

};


/**
 * Closure for dirproc function.
 */
struct EntryProcCls
{
  /**
   * Linked list of directory entries that is being
   * created.
   */
  struct GNUNET_FS_FileInformation *entries;

  /**
   * Map describing the meta data for all entries in the
   * directory.  Keys are the hash of the meta-value,
   * values are of type 'struct MetaValueInformation'.
   */
  struct GNUNET_CONTAINER_MultiHashMap *metamap;

  /**
   * Map describing the keywords for all entries in the
   * directory.  Keys are the hash of the keyword,
   * values are of type 'struct KeywordInformation'.
   */
  struct GNUNET_CONTAINER_MultiHashMap *keywordmap;

  /**
   * Number of entries in 'entries'.
   */
  unsigned int count;

};


/**
 * Function that processes a directory entry that
 * was obtained from the scanner.  Adds each entry to
 * the directory and computes directroy meta map.
 *
 * @param cls our closure
 * @param filename name of the file (unused, why there???)
 * @param fi information for publishing the file
 */
static void
dirproc_add (void *cls, const char *filename,
             struct GNUNET_FS_FileInformation *fi)
{
  struct EntryProcCls *dc = cls;
  unsigned int i;
  const char *kw;
  struct KeywordInformation *ki;
  GNUNET_HashCode key;

  GNUNET_assert (fi->next == NULL);
  GNUNET_assert (fi->dir == NULL);
  fi->next = dc->entries;
  dc->entries = fi;
  dc->count++;
  if (NULL != fi->meta)
    GNUNET_CONTAINER_meta_data_iterate (fi->meta, &update_metamap, dc->metamap);
  for (i = 0; i < fi->keywords->data.ksk.keywordCount; i++)
  {
    kw = fi->keywords->data.ksk.keywords[i];
    GNUNET_CRYPTO_hash (kw, strlen (kw), &key);
    ki = GNUNET_CONTAINER_multihashmap_get (dc->keywordmap, &key);
    if (ki == NULL)
    {
      ki = GNUNET_malloc (sizeof (struct KeywordInformation));
      ki->keyword = &kw[1];
      GNUNET_CONTAINER_multihashmap_put (dc->keywordmap, &key, ki,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    }
    ki->frequency++;
  }
}


/**
 * Closure for 'compute_directory_metadata'.
 */
struct ComputeDirectoryMetadataContext
{
  /**
   * Where to store the extracted keywords.
   */
  struct GNUNET_FS_Uri *ksk;

  /**
   * Where to store the extracted meta data.
   */
  struct GNUNET_CONTAINER_MetaData *meta;

  /**
   * Threshold to apply for adding meta data.
   */
  unsigned int threshold;
};


/**
 * Add metadata that occurs in more than the threshold entries of the
 * directory to the directory itself.  For example, if most files in a
 * directory are of the same mime-type, the directory should have that
 * mime-type as a keyword.
 *
 * @param cls the 'struct ComputeDirectoryMetadataContext'
 * @param key unused
 * @param value the 'struct MetaValueInformation' (to be freed as well)
 * @return GNUNET_OK
 */
static int
compute_directory_metadata (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ComputeDirectoryMetadataContext *cdmc = cls;
  struct MetaValueInformation *mvi = value;

  if (mvi->frequency > cdmc->threshold)
  {
    if (mvi->type != EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME)
      (void) GNUNET_CONTAINER_meta_data_insert (cdmc->meta, "<children>",
                                                mvi->type, mvi->format,
                                                mvi->mime_type, mvi->data,
                                                mvi->data_size);
    if ((mvi->format == EXTRACTOR_METAFORMAT_UTF8) ||
        (mvi->format == EXTRACTOR_METAFORMAT_C_STRING))
      GNUNET_FS_uri_ksk_add_keyword (cdmc->ksk, mvi->data, GNUNET_NO);
  }
  GNUNET_free (mvi);
  return GNUNET_OK;
}


/**
 * Add keywords that occur in more than the threshold entries of the
 * directory to the directory itself.
 *
 * @param cls the 'struct ComputeDirectoryMetadataContext'
 * @param key unused
 * @param value the 'struct Keywordnformation' (to be freed as well)
 * @return GNUNET_OK
 */
static int
compute_directory_keywords (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ComputeDirectoryMetadataContext *cdmc = cls;
  struct KeywordInformation *ki = value;

  if (ki->frequency > cdmc->threshold)
    (void) GNUNET_FS_uri_ksk_add_keyword (cdmc->ksk, ki->keyword, GNUNET_NO);
  GNUNET_free (ki);
  return GNUNET_OK;
}


/**
 * Create a publish-structure from an existing file hierarchy, inferring
 * and organizing keywords and metadata as much as possible.  This
 * function primarily performs the recursive build and re-organizes
 * keywords and metadata; for automatically getting metadata
 * extraction, scanning of directories and creation of the respective
 * GNUNET_FS_FileInformation entries the default scanner should be
 * passed (GNUNET_FS_directory_scanner_default).  This is strictly a
 * convenience function.
 *
 * @param h handle to the file sharing subsystem
 * @param client_info initial value for the client-info value for this entry
 * @param filename name of the top-level file or directory
 * @param scanner function used to get a list of files in a directory
 * @param scanner_cls closure for scanner
 * @param do_index should files in the hierarchy be indexed?
 * @param bo block options
 * @param emsg where to store an error message
 * @return publish structure entry for the directory, NULL on error
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_directory (struct GNUNET_FS_Handle *h,
                                                  void *client_info,
                                                  const char *filename,
                                                  GNUNET_FS_DirectoryScanner
                                                  scanner, void *scanner_cls,
                                                  int do_index,
                                                  const struct
                                                  GNUNET_FS_BlockOptions *bo,
                                                  char **emsg)
{
  struct GNUNET_FS_FileInformation *ret;
  struct ComputeDirectoryMetadataContext cdmc;
  struct EntryProcCls dc;
  const char *fn;
  const char *ss;
  struct GNUNET_FS_Uri *cksk;
  char *dn;
  struct GNUNET_FS_FileInformation *epos;
  unsigned int i;
  const char *kw;

  dc.entries = NULL;
  dc.count = 0;
  dc.metamap = GNUNET_CONTAINER_multihashmap_create (64);
  dc.keywordmap = GNUNET_CONTAINER_multihashmap_create (64);
  /* update children to point to directory and generate statistics
   * on all meta data in children */
  scanner (scanner_cls, h, filename, do_index, bo, &dirproc_add, &dc, emsg);
  cdmc.meta = GNUNET_CONTAINER_meta_data_create ();
  cdmc.ksk = GNUNET_malloc (sizeof (struct GNUNET_FS_Uri));
  cdmc.ksk->type = ksk;
  cdmc.threshold = 1 + dc.count / 2;    /* 50% threshold for now */
  GNUNET_FS_meta_data_make_directory (cdmc.meta);
  GNUNET_CONTAINER_multihashmap_iterate (dc.metamap,
                                         &compute_directory_metadata, &cdmc);
  GNUNET_CONTAINER_multihashmap_iterate (dc.keywordmap,
                                         &compute_directory_keywords, &cdmc);
  GNUNET_CONTAINER_multihashmap_destroy (dc.metamap);
  GNUNET_CONTAINER_multihashmap_destroy (dc.keywordmap);
  GNUNET_FS_uri_ksk_add_keyword (cdmc.ksk, GNUNET_FS_DIRECTORY_MIME, GNUNET_NO);
  cksk = GNUNET_FS_uri_ksk_canonicalize (cdmc.ksk);

  /* remove keywords in children that are already in the
   * parent */
  for (epos = dc.entries; NULL != epos; epos = epos->next)
  {
    for (i = 0; i < cksk->data.ksk.keywordCount; i++)
    {
      kw = cksk->data.ksk.keywords[i];
      GNUNET_FS_uri_ksk_remove_keyword (epos->keywords, &kw[1]);
    }
  }
  ret =
      GNUNET_FS_file_information_create_empty_directory (h, client_info, cksk,
                                                         cdmc.meta, bo);
  GNUNET_CONTAINER_meta_data_destroy (cdmc.meta);
  GNUNET_FS_uri_destroy (cdmc.ksk);
  ret->data.dir.entries = dc.entries;
  while (dc.entries != NULL)
  {
    dc.entries->dir = ret;
    dc.entries = dc.entries->next;
  }
  fn = filename;
  while ((NULL != (ss = strstr (fn, DIR_SEPARATOR_STR))) && (strlen (ss) > 1))
    fn = ss + 1;
  GNUNET_asprintf (&dn, "%s/", fn);
  GNUNET_CONTAINER_meta_data_insert (ret->meta, "<gnunet>",
                                     EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME,
                                     EXTRACTOR_METAFORMAT_C_STRING,
                                     "text/plain", dn, strlen (dn) + 1);
  GNUNET_free (dn);
  ret->filename = GNUNET_strdup (filename);
  return ret;
}


/**
 * Test if a given entry represents a directory.
 *
 * @param ent check if this FI represents a directory
 * @return GNUNET_YES if so, GNUNET_NO if not
 */
int
GNUNET_FS_file_information_is_directory (const struct GNUNET_FS_FileInformation
                                         *ent)
{
  return ent->is_directory;
}


/**
 * Create an entry for an empty directory in a publish-structure.
 * This function should be used by applications for which the
 * use of "GNUNET_FS_file_information_create_from_directory"
 * is not appropriate.
 *
 * @param h handle to the file sharing subsystem
 * @param client_info initial value for the client-info value for this entry
 * @param meta metadata for the directory
 * @param keywords under which keywords should this directory be available
 *         directly; can be NULL
 * @param bo block options
 * @return publish structure entry for the directory , NULL on error
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_empty_directory (struct GNUNET_FS_Handle *h,
                                                   void *client_info,
                                                   const struct GNUNET_FS_Uri
                                                   *keywords,
                                                   const struct
                                                   GNUNET_CONTAINER_MetaData
                                                   *meta,
                                                   const struct
                                                   GNUNET_FS_BlockOptions *bo)
{
  struct GNUNET_FS_FileInformation *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_FileInformation));
  ret->h = h;
  ret->client_info = client_info;
  ret->meta = GNUNET_CONTAINER_meta_data_duplicate (meta);
  ret->keywords = GNUNET_FS_uri_dup (keywords);
  ret->bo = *bo;
  ret->is_directory = GNUNET_YES;
  return ret;
}


/**
 * Add an entry to a directory in a publish-structure.  Clients
 * should never modify publish structures that were passed to
 * "GNUNET_FS_publish_start" already.
 *
 * @param dir the directory
 * @param ent the entry to add; the entry must not have been
 *            added to any other directory at this point and
 *            must not include "dir" in its structure
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_FS_file_information_add (struct GNUNET_FS_FileInformation *dir,
                                struct GNUNET_FS_FileInformation *ent)
{
  if ((ent->dir != NULL) || (ent->next != NULL) || (!dir->is_directory))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  ent->dir = dir;
  ent->next = dir->data.dir.entries;
  dir->data.dir.entries = ent;
  dir->data.dir.dir_size = 0;
  return GNUNET_OK;
}


/**
 * Inspect a file or directory in a publish-structure.  Clients
 * should never modify publish structures that were passed to
 * "GNUNET_FS_publish_start" already.  When called on a directory,
 * this function will FIRST call "proc" with information about
 * the directory itself and then for each of the files in the
 * directory (but not for files in subdirectories).  When called
 * on a file, "proc" will be called exactly once (with information
 * about the specific file).
 *
 * @param dir the directory
 * @param proc function to call on each entry
 * @param proc_cls closure for proc
 */
void
GNUNET_FS_file_information_inspect (struct GNUNET_FS_FileInformation *dir,
                                    GNUNET_FS_FileInformationProcessor proc,
                                    void *proc_cls)
{
  struct GNUNET_FS_FileInformation *pos;
  int no;

  no = GNUNET_NO;
  if (GNUNET_OK !=
      proc (proc_cls, dir,
            (dir->is_directory) ? dir->data.dir.dir_size : dir->data.
            file.file_size, dir->meta, &dir->keywords, &dir->bo,
            (dir->is_directory) ? &no : &dir->data.file.do_index,
            &dir->client_info))
    return;
  if (!dir->is_directory)
    return;
  pos = dir->data.dir.entries;
  while (pos != NULL)
  {
    no = GNUNET_NO;
    if (GNUNET_OK !=
        proc (proc_cls, pos,
              (pos->is_directory) ? pos->data.dir.dir_size : pos->data.
              file.file_size, pos->meta, &pos->keywords, &pos->bo,
              (dir->is_directory) ? &no : &dir->data.file.do_index,
              &pos->client_info))
      break;
    pos = pos->next;
  }
}


/**
 * Destroy publish-structure.  Clients should never destroy publish
 * structures that were passed to "GNUNET_FS_publish_start" already.
 *
 * @param fi structure to destroy
 * @param cleaner function to call on each entry in the structure
 *        (useful to clean up client_info); can be NULL; return
 *        values are ignored
 * @param cleaner_cls closure for cleaner
 */
void
GNUNET_FS_file_information_destroy (struct GNUNET_FS_FileInformation *fi,
                                    GNUNET_FS_FileInformationProcessor cleaner,
                                    void *cleaner_cls)
{
  struct GNUNET_FS_FileInformation *pos;
  int no;

  no = GNUNET_NO;
  if (fi->is_directory)
  {
    /* clean up directory */
    while (NULL != (pos = fi->data.dir.entries))
    {
      fi->data.dir.entries = pos->next;
      GNUNET_FS_file_information_destroy (pos, cleaner, cleaner_cls);
    }
    /* clean up client-info */
    if (NULL != cleaner)
      cleaner (cleaner_cls, fi, fi->data.dir.dir_size, fi->meta, &fi->keywords,
               &fi->bo, &no, &fi->client_info);
    GNUNET_free_non_null (fi->data.dir.dir_data);
  }
  else
  {
    /* call clean-up function of the reader */
    if (fi->data.file.reader != NULL)
      fi->data.file.reader (fi->data.file.reader_cls, 0, 0, NULL, NULL);
    /* clean up client-info */
    if (NULL != cleaner)
      cleaner (cleaner_cls, fi, fi->data.file.file_size, fi->meta,
               &fi->keywords, &fi->bo, &fi->data.file.do_index,
               &fi->client_info);
  }
  GNUNET_free_non_null (fi->filename);
  GNUNET_free_non_null (fi->emsg);
  GNUNET_free_non_null (fi->chk_uri);
  /* clean up serialization */
  if ((NULL != fi->serialization) && (0 != UNLINK (fi->serialization)))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink",
                              fi->serialization);
  if (NULL != fi->keywords)
    GNUNET_FS_uri_destroy (fi->keywords);
  if (NULL != fi->meta)
    GNUNET_CONTAINER_meta_data_destroy (fi->meta);
  GNUNET_free_non_null (fi->serialization);
  if (fi->te != NULL)
  {
    GNUNET_FS_tree_encoder_finish (fi->te, NULL, NULL);
    fi->te = NULL;
  }
  GNUNET_free (fi);
}


/* end of fs_file_information.c */
