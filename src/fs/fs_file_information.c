/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_file_information.c
 * @brief  Manage information for publishing directory hierarchies
 * @author Christian Grothoff
 *
 * TODO:
 * - serialization/deserialization (& deserialization API)
 * - metadata filename clean up code
 * - metadata/ksk generation for directories from contained files
 */
#include "platform.h"
#include <extractor.h>
#include "gnunet_fs_service.h"
#include "fs.h"


/**
 * Create a temporary file on disk to store the current
 * state of "fi" in.
 */
void
GNUNET_FS_file_information_sync (struct GNUNET_FS_FileInformation * fi)
{
  if (NULL == fi->serialization)
    {
      fi->serialization = NULL; // FIXME -- need cfg!
    }
  // FIXME...
}


/**
 * Load file information from the file to which
 * it was sync'ed.
 *
 * @param fn name of the file to use
 * @return NULL on error
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_recover (const char *fn)
{
  struct GNUNET_FS_FileInformation *ret;
  ret = NULL;
  // FIXME!
  return ret;
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
 * Closure for "data_reader_file".
 */
struct FileInfo
{
  /**
   * Name of the file to read.
   */
  char *filename;

  /**
   * File descriptor, NULL if it has not yet been opened.
   */
  struct GNUNET_DISK_FileHandle *fd;
};


/**
 * Function that provides data by reading from a file.
 *
 * @param cls closure (points to the file information)
 * @param offset offset to read from; it is possible
 *            that the caller might need to go backwards
 *            a bit at times
 * @param max maximum number of bytes that should be 
 *            copied to buf; readers are not allowed
 *            to provide less data unless there is an error;
 *            a value of "0" will be used at the end to allow
 *            the reader to clean up its internal state
 * @param buf where the reader should write the data
 * @param emsg location for the reader to store an error message
 * @return number of bytes written, usually "max", 0 on error
 */
static size_t
data_reader_file(void *cls, 
		 uint64_t offset,
		 size_t max, 
		 void *buf,
		 char **emsg)
{
  struct FileInfo *fi = cls;
  ssize_t ret;

  if (max == 0)
    {
      if (fi->fd != NULL)
	GNUNET_DISK_file_close (fi->fd);
      GNUNET_free (fi->filename);
      GNUNET_free (fi);
      return 0;
    }  
  if (fi->fd == NULL)
    {
      fi->fd = GNUNET_DISK_file_open (fi->filename,
				      GNUNET_DISK_OPEN_READ);
      if (fi->fd == NULL)
	{
	  GNUNET_asprintf (emsg, 
			   _("Could not open file `%s': %s"),
			   fi->filename,
			   STRERROR (errno));
	  return 0;
	}
    }
  GNUNET_DISK_file_seek (fi->fd, offset, GNUNET_DISK_SEEK_SET);
  ret = GNUNET_DISK_file_read (fi->fd, buf, max);
  if (ret == -1)
    {
      GNUNET_asprintf (emsg, 
		       _("Could not read file `%s': %s"),
		       fi->filename,
		       STRERROR (errno));
      return 0;
    }
  if (ret != max)
    {
      GNUNET_asprintf (emsg, 
		       _("Short read reading from file `%s'!"),
		       fi->filename);
      return 0;
    }
  return max;
}


/**
 * Create an entry for a file in a publish-structure.
 *
 * @param client_info initial value for the client-info value for this entry
 * @param filename name of the file or directory to publish
 * @param keywords under which keywords should this file be available
 *         directly; can be NULL
 * @param meta metadata for the file
 * @param do_index GNUNET_YES for index, GNUNET_NO for insertion,
 *                GNUNET_SYSERR for simulation
 * @param anonymity what is the desired anonymity level for sharing?
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param expirationTime when should this content expire?
 * @return publish structure entry for the file
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_file (void *client_info,
					     const char *filename,
					     const struct GNUNET_FS_Uri *keywords,
					     const struct GNUNET_CONTAINER_MetaData *meta,
					     int do_index,
					     uint32_t anonymity,
					     uint32_t priority,
					     struct GNUNET_TIME_Absolute expirationTime)
{
  struct FileInfo *fi;
  struct stat sbuf;

  if (0 != STAT (filename, &sbuf))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
				"stat",
				filename);
      return NULL;
    }
  fi = GNUNET_malloc (sizeof(struct FileInfo));
  fi->filename = GNUNET_strdup (filename);
  return GNUNET_FS_file_information_create_from_reader (client_info,
							sbuf.st_size,
							&data_reader_file,
							fi,
							keywords,
							meta,
							do_index,
							anonymity,
							priority,
							expirationTime);
}


/**
 * Function that provides data by copying from a buffer.
 *
 * @param cls closure (points to the buffer)
 * @param offset offset to read from; it is possible
 *            that the caller might need to go backwards
 *            a bit at times
 * @param max maximum number of bytes that should be 
 *            copied to buf; readers are not allowed
 *            to provide less data unless there is an error;
 *            a value of "0" will be used at the end to allow
 *            the reader to clean up its internal state
 * @param buf where the reader should write the data
 * @param emsg location for the reader to store an error message
 * @return number of bytes written, usually "max", 0 on error
 */
static size_t
data_reader_copy(void *cls, 
		 uint64_t offset,
		 size_t max, 
		 void *buf,
		 char **emsg)
{
  char *data = cls;
  if (max == 0)
    {
      GNUNET_free (data);
      return 0;
    }  
  memcpy (buf, &data[offset], max);
  return max;
}


/**
 * Create an entry for a file in a publish-structure.
 *
 * @param client_info initial value for the client-info value for this entry
 * @param length length of the file
 * @param data data for the file (should not be used afterwards by
 *        the caller; caller will "free")
 * @param keywords under which keywords should this file be available
 *         directly; can be NULL
 * @param meta metadata for the file
 * @param do_index GNUNET_YES for index, GNUNET_NO for insertion,
 *                GNUNET_SYSERR for simulation
 * @param anonymity what is the desired anonymity level for sharing?
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param expirationTime when should this content expire?
 * @return publish structure entry for the file
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_data (void *client_info,
					     uint64_t length,
					     void *data,
					     const struct GNUNET_FS_Uri *keywords,
					     const struct GNUNET_CONTAINER_MetaData *meta,
					     int do_index,
					     uint32_t anonymity,
					     uint32_t priority,
					     struct GNUNET_TIME_Absolute expirationTime)
{
  return GNUNET_FS_file_information_create_from_reader (client_info,
							length,
							&data_reader_copy,
							data,
							keywords,
							meta,
							do_index,
							anonymity,
							priority,
							expirationTime);
}


/**
 * Create an entry for a file in a publish-structure.
 *
 * @param client_info initial value for the client-info value for this entry
 * @param length length of the file
 * @param reader function that can be used to obtain the data for the file 
 * @param reader_cls closure for "reader"
 * @param keywords under which keywords should this file be available
 *         directly; can be NULL
 * @param meta metadata for the file
 * @param do_index GNUNET_YES for index, GNUNET_NO for insertion,
 *                GNUNET_SYSERR for simulation
 * @param anonymity what is the desired anonymity level for sharing?
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param expirationTime when should this content expire?
 * @return publish structure entry for the file
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_reader (void *client_info,
					       uint64_t length,
					       GNUNET_FS_DataReader reader,
					       void *reader_cls,
					       const struct GNUNET_FS_Uri *keywords,
					       const struct GNUNET_CONTAINER_MetaData *meta,
					       int do_index,
					       uint32_t anonymity,
					       uint32_t priority,
					       struct GNUNET_TIME_Absolute expirationTime)
{
  struct GNUNET_FS_FileInformation *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_FileInformation));
  ret->client_info = client_info;
  ret->meta = GNUNET_CONTAINER_meta_data_duplicate (meta);
  ret->keywords = (keywords == NULL) ? NULL : GNUNET_FS_uri_dup (keywords);
  ret->expirationTime = expirationTime;
  ret->data.file.reader = reader; 
  ret->data.file.reader_cls = reader_cls;
  ret->data.file.do_index = do_index;
  ret->anonymity = anonymity;
  ret->priority = priority;
  GNUNET_FS_file_information_sync (ret);
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
  struct EXTRACTOR_Extractor *extractors;

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
   * Should files be indexed?
   */ 
  int do_index;

  /**
   * Desired anonymity level.
   */
  uint32_t anonymity;

  /**
   * Desired publishing priority.
   */
  uint32_t priority;

  /**
   * Expiration time for publication.
   */
  struct GNUNET_TIME_Absolute expiration;
};


/**
 * Function called on each entry in a file to
 * cause default-publishing.
 * @param cls closure (struct DirScanCls)
 * @param filename name of the file to be published
 * @return GNUNET_OK on success, GNUNET_SYSERR to abort
 */
static int
dir_scan_cb (void *cls,
	     const char *filename)
{
  struct DirScanCls *dsc = cls;  
  struct stat sbuf;
  struct GNUNET_FS_FileInformation *fi;
  struct GNUNET_FS_Uri *ksk_uri;
  struct GNUNET_FS_Uri *keywords;
  struct GNUNET_CONTAINER_MetaData *meta;

  if (0 != STAT (filename, &sbuf))
    {
      GNUNET_asprintf (&dsc->emsg,
		       _("`%s' failed on file `%s': %s"),
		       "stat",
		       filename,
		       STRERROR (errno));
      return GNUNET_SYSERR;
    }
  if (S_ISDIR (sbuf.st_mode))
    {
      fi = GNUNET_FS_file_information_create_from_directory (NULL,
							     filename,
							     dsc->scanner,
							     dsc->scanner_cls,
							     dsc->do_index,
							     dsc->anonymity,
							     dsc->priority,
							     dsc->expiration,
							     &dsc->emsg);
      if (NULL == fi)
	{
	  GNUNET_assert (NULL != dsc->emsg);
	  return GNUNET_SYSERR;
	}
    }
  else
    {
      meta = GNUNET_CONTAINER_meta_data_create ();
      GNUNET_CONTAINER_meta_data_extract_from_file (meta,
						    filename,
						    dsc->extractors);
      // FIXME: remove path from filename in metadata!
      keywords = GNUNET_FS_uri_ksk_create_from_meta_data (meta);
      ksk_uri = GNUNET_FS_uri_ksk_canonicalize (keywords);
      fi = GNUNET_FS_file_information_create_from_file (NULL,
							filename,
							ksk_uri,
							meta,
							dsc->do_index,
							dsc->anonymity,
							dsc->priority,
							dsc->expiration);
      GNUNET_CONTAINER_meta_data_destroy (meta);
      GNUNET_FS_uri_destroy (keywords);
      GNUNET_FS_uri_destroy (ksk_uri);
    }
  dsc->proc (dsc->proc_cls,
	     filename,
	     fi);
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
 * @param dirname name of the directory to scan
 * @param do_index should files be indexed or inserted
 * @param anonymity desired anonymity level
 * @param priority priority for publishing
 * @param expirationTime expiration for publication
 * @param proc function called on each entry
 * @param proc_cls closure for proc
 * @param emsg where to store an error message (on errors)
 * @return GNUNET_OK on success
 */
int
GNUNET_FS_directory_scanner_default (void *cls,
				     const char *dirname,
				     int do_index,
				     uint32_t anonymity,
				     uint32_t priority,
				     struct GNUNET_TIME_Absolute expirationTime,
				     GNUNET_FS_FileProcessor proc,
				     void *proc_cls,
				     char **emsg)
{
  struct EXTRACTOR_Extractor *ex = cls;
  struct DirScanCls dsc;

  dsc.extractors = ex;
  dsc.proc = proc;
  dsc.proc_cls = proc_cls;
  dsc.scanner = &GNUNET_FS_directory_scanner_default;
  dsc.scanner_cls = cls;
  dsc.do_index = do_index;
  dsc.anonymity = anonymity;
  dsc.priority = priority;
  dsc.expiration = expirationTime;
  if (-1 == GNUNET_DISK_directory_scan (dirname,
					&dir_scan_cb,
					&dsc))
    {
      GNUNET_assert (NULL != dsc.emsg);
      *emsg = dsc.emsg;
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}


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

};


/**
 * Function that processes a directory entry that
 * was obtained from the scanner.
 * @param cls our closure
 * @param filename name of the file (unused, why there???)
 * @param fi information for publishing the file
 */
static void
dirproc (void *cls,
	 const char *filename,
	 struct GNUNET_FS_FileInformation *fi)
{
  struct EntryProcCls *dc = cls;

  GNUNET_assert (fi->next == NULL);
  GNUNET_assert (fi->dir == NULL);
  fi->next = dc->entries;
  dc->entries = fi;
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
 * @param client_info initial value for the client-info value for this entry
 * @param filename name of the top-level file or directory
 * @param scanner function used to get a list of files in a directory
 * @param scanner_cls closure for scanner
 * @param do_index should files in the hierarchy be indexed?
 * @param anonymity what is the desired anonymity level for sharing?
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param expirationTime when should this content expire?
 * @param emsg where to store an error message
 * @return publish structure entry for the directory, NULL on error
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_directory (void *client_info,
						  const char *filename,
						  GNUNET_FS_DirectoryScanner scanner,
						  void *scanner_cls,
						  int do_index,
						  uint32_t anonymity,
						  uint32_t priority,
						  struct GNUNET_TIME_Absolute expirationTime,
						  char **emsg)
{
  struct GNUNET_FS_FileInformation *ret;
  struct EntryProcCls dc;
  struct GNUNET_FS_Uri *ksk;
  struct GNUNET_CONTAINER_MetaData *meta;

  dc.entries = NULL;
  meta = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_FS_meta_data_make_directory (meta);
  
  scanner (scanner_cls,
	   filename,
	   do_index,
	   anonymity,
	   priority,
	   expirationTime,
	   &dirproc,
	   &dc,
	   emsg);
  ksk = NULL; // FIXME...
  // FIXME: create meta!
  ret = GNUNET_FS_file_information_create_empty_directory (client_info,
							   meta,
							   ksk,
							   anonymity,
							   priority,
							   expirationTime);
  ret->data.dir.entries = dc.entries;
  while (dc.entries != NULL)
    {
      dc.entries->dir = ret;
      GNUNET_FS_file_information_sync (dc.entries);
      dc.entries = dc.entries->next;
    }
  GNUNET_FS_file_information_sync (ret);
  return ret;
}


/**
 * Create an entry for an empty directory in a publish-structure.
 * This function should be used by applications for which the
 * use of "GNUNET_FS_file_information_create_from_directory"
 * is not appropriate.
 *
 * @param client_info initial value for the client-info value for this entry
 * @param meta metadata for the directory
 * @param keywords under which keywords should this directory be available
 *         directly; can be NULL
 * @param anonymity what is the desired anonymity level for sharing?
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param expirationTime when should this content expire?
 * @return publish structure entry for the directory , NULL on error
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_empty_directory (void *client_info,
						   const struct GNUNET_CONTAINER_MetaData *meta,
						   const struct GNUNET_FS_Uri *keywords,
						   uint32_t anonymity,
						   uint32_t priority,
						   struct GNUNET_TIME_Absolute expirationTime)
{
  struct GNUNET_FS_FileInformation *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_FileInformation));
  ret->client_info = client_info;
  ret->meta = GNUNET_CONTAINER_meta_data_duplicate (meta);
  ret->keywords = GNUNET_FS_uri_dup (keywords);
  ret->expirationTime = expirationTime;
  ret->is_directory = GNUNET_YES;
  ret->anonymity = anonymity;
  ret->priority = priority;
  GNUNET_FS_file_information_sync (ret);
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
  if ( (ent->dir != NULL) ||
       (ent->next != NULL) ||
       (! dir->is_directory) )
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  ent->dir = dir;
  ent->next = dir->data.dir.entries;
  dir->data.dir.entries = ent;
  dir->data.dir.dir_size = 0;
  GNUNET_FS_file_information_sync (ent);
  GNUNET_FS_file_information_sync (dir);
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

  if (dir->is_directory)
    {
      proc (proc_cls, 
	    dir,
	    dir->data.dir.dir_size,
	    dir->meta,
	    &dir->keywords,
	    &dir->anonymity,
	    &dir->priority,
	    &dir->expirationTime,
	    &dir->client_info);
      pos = dir->data.dir.entries;
      while (pos != NULL)
	{
	  proc (proc_cls, 
		pos,
		pos->data.dir.dir_size,
		pos->meta,
		&pos->keywords,
		&pos->anonymity,
		&pos->priority,
		&pos->expirationTime,
		&pos->client_info);
	  pos = pos->next;
	}
    }
  else
    {
      proc (proc_cls, 
	    dir,
	    dir->data.file.file_size,
	    dir->meta,
	    &dir->keywords,
	    &dir->anonymity,
	    &dir->priority,
	    &dir->expirationTime,
	    &dir->client_info);
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

  if (fi->is_directory)
    {
      /* clean up directory */
      while (NULL != (pos = fi->data.dir.entries))
	{
	  fi->data.dir.entries = pos->next;
	  GNUNET_FS_file_information_destroy (pos, cleaner, cleaner_cls);
	}
      /* clean up client-info */
      cleaner (cleaner_cls, 
	       fi,
	       fi->data.dir.dir_size,
	       fi->meta,
	       &fi->keywords,
	       &fi->anonymity,
	       &fi->priority,
	       &fi->expirationTime,
	       &fi->client_info);
      GNUNET_free_non_null (fi->data.dir.dir_data);
      GNUNET_free (fi->data.dir.dirname);
    }
  else
    {
      /* call clean-up function of the reader */
      fi->data.file.reader (fi->data.file.reader_cls, 0, 0, NULL, NULL);
      /* clean up client-info */
      cleaner (cleaner_cls, 
	       fi,
	       fi->data.file.file_size,
	       fi->meta,
	       &fi->keywords,
	       &fi->anonymity,
	       &fi->priority,
	       &fi->expirationTime,
	       &fi->client_info);
    }
  GNUNET_free_non_null (fi->emsg);
  /* clean up serialization */
  if (0 != UNLINK (fi->serialization))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
			      "unlink",
			      fi->serialization);
  GNUNET_FS_uri_destroy (fi->keywords);
  GNUNET_CONTAINER_meta_data_destroy (fi->meta);
  GNUNET_free (fi->serialization);
  GNUNET_free (fi);
}


/* end of fs_file_information.c */
