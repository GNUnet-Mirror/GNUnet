/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_disk_lib.h
 * @brief disk IO apis
 */

#ifndef GNUNET_DISK_LIB_H
#define GNUNET_DISK_LIB_H

#include "gnunet_configuration_lib.h"
#include "gnunet_scheduler_lib.h"

/* we need size_t, and since it can be both unsigned int
   or unsigned long long, this IS platform dependent;
   but "stdlib.h" should be portable 'enough' to be
   unconditionally available... */
#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Get the number of blocks that are left on the partition that
 * contains the given file (for normal users).
 *
 * @param part a file on the partition to check
 * @return -1 on errors, otherwise the number of free blocks
 */
long GNUNET_DISK_get_blocks_available (const char *part);


/**
 * Check that fil corresponds to a filename
 * (of a file that exists and that is not a directory).
 *
 * @returns GNUNET_YES if yes, GNUNET_NO if not a file, GNUNET_SYSERR if something
 * else (will print an error message in that case, too).
 */
int GNUNET_DISK_file_test (const char *fil);


/**
 * Get the size of the file (or directory)
 * of the given file (in bytes).
 *
 * @param includeSymLinks should symbolic links be
 *        included?
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_DISK_file_size (const char *filename,
                           unsigned long long *size, int includeSymLinks);


/**
 * Wrapper around "open()".  Opens a file.
 *
 * @return file handle, -1 on error
 */
int GNUNET_DISK_file_open (const char *filename, int oflag, ...);


/**
 * Wrapper around "close()".  Closes a file.
 */
void GNUNET_DISK_file_close (const char *filename, int fd);


/**
 * Read the contents of a binary file into a buffer.
 * @param fileName the name of the file, not freed,
 *        must already be expanded!
 * @param len the maximum number of bytes to read
 * @param result the buffer to write the result to
 * @return the number of bytes read on success, -1 on failure
 */
int GNUNET_DISK_file_read (const char *fileName, int len, void *result);


/**
 * Write a buffer to a file.
 * @param fileName the name of the file, NOT freed!
 * @param buffer the data to write
 * @param n number of bytes to write
 * @param mode the mode for file permissions
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_DISK_file_write (const char *fileName,
                            const void *buffer, unsigned int n,
                            const char *mode);


/**
 * Copy a file.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_DISK_file_copy (const char *src, const char *dst);


/**
 * Scan a directory for files. The name of the directory
 * must be expanded first (!).
 *
 * @param dirName the name of the directory
 * @param callback the method to call for each file
 * @param data argument to pass to callback
 * @return the number of files found, -1 on error
 */
int GNUNET_DISK_directory_scan (const char *dirName,
                                GNUNET_FileNameCallback callback, void *data);


/**
 * Opaque handle used for iterating over a directory.
 */
struct GNUNET_DISK_DirectoryIterator;


/**
 * Function called to iterate over a directory.
 *
 * @param cls closure
 * @param di argument to pass to "GNUNET_DISK_directory_iterator_next" to
 *           get called on the next entry (or finish cleanly)
 * @param filename complete filename (absolute path)
 * @param dirname directory name (absolute path)
 */
typedef void (*GNUNET_DISK_DirectoryIteratorCallback) (void *cls,
                                                       struct
                                                       GNUNET_DISK_DirectoryIterator
                                                       * di,
                                                       const char *filename,
                                                       const char *dirname);


/**
 * This function must be called during the DiskIteratorCallback
 * (exactly once) to schedule the task to process the next
 * filename in the directory (if there is one).
 *
 * @param iter opaque handle for the iterator
 * @param can set to GNUNET_YES to terminate the iteration early
 * @return GNUNET_YES if iteration will continue,
 *         GNUNET_NO if this was the last entry (and iteration is complete),
 *         GNUNET_SYSERR if "can" was YES
 */
int GNUNET_DISK_directory_iterator_next (struct GNUNET_DISK_DirectoryIterator
                                         *iter, int can);


/**
 * Scan a directory for files using the scheduler to run a task for
 * each entry.  The name of the directory must be expanded first (!).
 * If a scheduler does not need to be used, GNUNET_DISK_directory_scan
 * may provide a simpler API.
 *
 * @param sched scheduler to use
 * @param prio priority to use
 * @param dirName the name of the directory
 * @param callback the method to call for each file
 * @param callback_cls closure for callback
 */
void GNUNET_DISK_directory_iterator_start (struct GNUNET_SCHEDULER_Handle
                                           *sched,
                                           enum GNUNET_SCHEDULER_Priority
                                           prio, const char *dirName,
                                           GNUNET_DISK_DirectoryIteratorCallback
                                           callback, void *callback_cls);


/**
 * Create the directory structure for storing
 * a file.
 *
 * @param filename name of a file in the directory
 * @returns GNUNET_OK on success, GNUNET_SYSERR on failure,
 *          GNUNET_NO if directory exists but is not writeable
 */
int GNUNET_DISK_directory_create_for_file (const char *filename);


/**
 * Test if fil is a directory that can be accessed.
 * Will not print an error message if the directory
 * does not exist.  Will log errors if GNUNET_SYSERR is
 * returned.
 *
 * @return GNUNET_YES if yes, GNUNET_NO if does not exist, GNUNET_SYSERR
 *   on any error and if exists but not directory
 */
int GNUNET_DISK_directory_test (const char *fil);


/**
 * Remove all files in a directory (rm -rf). Call with
 * caution.
 *
 * @param fileName the file to remove
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_DISK_directory_remove (const char *fileName);


/**
 * Implementation of "mkdir -p"
 *
 * @param dir the directory to create
 * @returns GNUNET_SYSERR on failure, GNUNET_OK otherwise
 */
int GNUNET_DISK_directory_create (const char *dir);


/**
 * @brief Removes special characters as ':' from a filename.
 * @param fn the filename to canonicalize
 */
void GNUNET_DISK_filename_canonicalize (char *fn);


/**
 * @brief Change owner of a file
 * @param filename file to change
 * @param user new owner of the file
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int GNUNET_DISK_file_change_owner (const char *filename, const char *user);


/**
 * Construct full path to a file inside of the private
 * directory used by GNUnet.  Also creates the corresponding
 * directory.  If the resulting name is supposed to be
 * a directory, end the last argument in '/' (or pass
 * DIR_SEPARATOR_STR as the last argument before NULL).
 *
 * @param serviceName name of the service asking
 * @param varargs is NULL-terminated list of
 *                path components to append to the
 *                private directory name.
 * @return the constructed filename
 */
char *GNUNET_DISK_get_home_filename (struct GNUNET_CONFIGURATION_Handle *cfg,
                                     const char *serviceName, ...);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_DISK_LIB_H */
#endif
/* end of gnunet_disk_lib.h */
