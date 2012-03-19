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
 */
#include "platform.h"
#include <extractor.h>
#include "gnunet_fs_service.h"
#include "fs_api.h"
#include "fs_tree.h"


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
 * Obtain the filename from the file information structure.
 *
 * @param s structure to get the filename for
 * @return "filename" field of the structure (can be NULL)
 */
const char *
GNUNET_FS_file_information_get_filename (struct GNUNET_FS_FileInformation *s)
{
  return s->filename;
}


/**
 * Set the filename in the file information structure.
 * If filename was already set, frees it before setting the new one.
 * Makes a copy of the argument.
 *
 * @param s structure to get the filename for
 * @param filename filename to set
 */
void
GNUNET_FS_file_information_set_filename (struct GNUNET_FS_FileInformation *s,
                                         const char *filename)
{
  GNUNET_free_non_null (s->filename);
  if (filename)
    s->filename = GNUNET_strdup (filename);
  else
    s->filename = NULL;
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
  uint64_t fsize;
  struct GNUNET_FS_FileInformation *ret;
  const char *fn;
  const char *ss;

#if WINDOWS
  char fn_conv[MAX_PATH];
#endif

  /* FIXME: should includeSymLinks be GNUNET_NO or GNUNET_YES here? */
  if (GNUNET_OK != GNUNET_DISK_file_size (filename, &fsize, GNUNET_NO, GNUNET_YES))
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
                                                     fsize,
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
/* FIXME: If we assume that on other platforms CRT is UTF-8-aware, then
 * this should be changed to EXTRACTOR_METAFORMAT_UTF8
 */
#if !WINDOWS
  GNUNET_CONTAINER_meta_data_insert (ret->meta, "<gnunet>",
                                     EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME,
                                     EXTRACTOR_METAFORMAT_C_STRING,
                                     "text/plain", fn, strlen (fn) + 1);
#else
  GNUNET_CONTAINER_meta_data_insert (ret->meta, "<gnunet>",
                                     EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME,
                                     EXTRACTOR_METAFORMAT_UTF8,
                                     "text/plain", fn, strlen (fn) + 1);
#endif
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
 * @param filename name of the directory; can be NULL
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
                                                   GNUNET_FS_BlockOptions *bo,
                                                   const char *filename)
{
  struct GNUNET_FS_FileInformation *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_FileInformation));
  ret->h = h;
  ret->client_info = client_info;
  ret->meta = GNUNET_CONTAINER_meta_data_duplicate (meta);
  ret->keywords = GNUNET_FS_uri_dup (keywords);
  ret->bo = *bo;
  ret->is_directory = GNUNET_YES;
  if (filename != NULL)
    ret->filename = GNUNET_strdup (filename);
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
  if ((ent->dir != NULL) || (ent->next != NULL) || (dir->is_directory != GNUNET_YES))
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
            (dir->is_directory == GNUNET_YES) ? dir->data.dir.dir_size : dir->data.
            file.file_size, dir->meta, &dir->keywords, &dir->bo,
            (dir->is_directory == GNUNET_YES) ? &no : &dir->data.file.do_index,
            &dir->client_info))
    return;
  if (dir->is_directory != GNUNET_YES)
    return;
  pos = dir->data.dir.entries;
  while (pos != NULL)
  {
    no = GNUNET_NO;
    if (GNUNET_OK !=
        proc (proc_cls, pos,
              (pos->is_directory == GNUNET_YES) ? pos->data.dir.dir_size : pos->data.
              file.file_size, pos->meta, &pos->keywords, &pos->bo,
              (pos->is_directory == GNUNET_YES) ? &no : &pos->data.file.do_index,
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
  if (fi->is_directory == GNUNET_YES)
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
