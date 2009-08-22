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
 */
#include "platform.h"
#include "gnunet_fs_service.h"
#include "fs.h"


/**
 * Create an entry for a file in a publish-structure.
 *
 * @param filename name of the file or directory to publish
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
					     const struct GNUNET_CONTAINER_MetaData *meta,
					     int do_index,
					     unsigned int anonymity,
					     unsigned int priority,
					     struct GNUNET_TIME_Absolute expirationTime)
{
  return NULL;
}

/**
 * Create an entry for a file in a publish-structure.
 *
 * @param length length of the file
 * @param data data for the file (should not be used afterwards by
 *        the caller; caller will "free")
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
					     const struct GNUNET_CONTAINER_MetaData *meta,
					     int do_index,
					     unsigned int anonymity,
					     unsigned int priority,
					     struct GNUNET_TIME_Absolute expirationTime)
{
  return NULL;
}


/**
 * Create an entry for a file in a publish-structure.
 *
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
					       unsigned int anonymity,
					       unsigned int priority,
					       struct GNUNET_TIME_Absolute expirationTime)
{
  return NULL;
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
 * @param proc function called on each entry
 * @param proc_cls closure for proc
 * @param emsg where to store an error message (on errors)
 * @return GNUNET_OK on success
 */
int
GNUNET_FS_directory_scanner_default (void *cls,
				     const char *dirname,
				     GNUNET_FS_FileProcessor proc,
				     void *proc_cls)
{
  return GNUNET_SYSERR;
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
 * @param filename name of the top-level file or directory
 * @param scanner function used to get a list of files in a directory
 * @param scanner_cls closure for scanner
 * @param anonymity what is the desired anonymity level for sharing?
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param expirationTime when should this content expire?
 * @return publish structure entry for the directory, NULL on error
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_directory (void *client_info,
						  GNUNET_FS_DirectoryScanner scanner,
						  void *scanner_cls,
						  unsigned int anonymity,
						  unsigned int priority,
						  struct GNUNET_TIME_Absolute expirationTime)
{
  return NULL;
}


/**
 * Create an entry for an empty directory in a publish-structure.
 * This function should be used by applications for which the
 * use of "GNUNET_FS_file_information_create_from_directory"
 * is not appropriate.
 *
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
						   unsigned int anonymity,
						   unsigned int priority,
						   struct GNUNET_TIME_Absolute expirationTime)
{
  return NULL;
}


/**
 * Add an entry to a directory in a publish-structure.  Clients
 * should never modify publish structures that were passed to
 * "GNUNET_FS_publish_start" already.
 *
 * @param dir the directory
 * @param end the entry to add; the entry must not have been
 *            added to any other directory at this point and 
 *            must not include "dir" in its structure
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_FS_file_information_add (struct GNUNET_FS_FileInformation *dir,
				struct GNUNET_FS_FileInformation *end)
{
  return GNUNET_SYSERR;
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
}


/* end of fs_file_information.c */
