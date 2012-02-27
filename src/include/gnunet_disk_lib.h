/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2009 Christian Grothoff (and other contributing authors)

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

#if WINDOWS
#define OFF_T uint64_t
#else
#define OFF_T off_t
#endif

/**
 * Handle used to manage a pipe.
 */
struct GNUNET_DISK_PipeHandle;


enum GNUNET_FILE_Type
{
  GNUNET_DISK_FILE, GNUNET_PIPE
};

/**
 * Handle used to access files (and pipes).
 */
struct GNUNET_DISK_FileHandle
{

#if WINDOWS
  /**
   * File handle under W32.
   */
  HANDLE h;

  /**
   * Type
   */
  enum GNUNET_FILE_Type type;

  /**
   * Structure for overlapped reading (for pipes)
   */
  OVERLAPPED *oOverlapRead;

  /**
   * Structure for overlapped writing (for pipes)
   */
  OVERLAPPED *oOverlapWrite;
#else

  /**
   * File handle on other OSes.
   */
  int fd;

#endif                          /*
                                 */
};


/* we need size_t, and since it can be both unsigned int
   or unsigned long long, this IS platform dependent;
   but "stdlib.h" should be portable 'enough' to be
   unconditionally available... */
#include <stdlib.h>
#include "gnunet_configuration_lib.h"
#include "gnunet_scheduler_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Specifies how a file should be opened.
 */
enum GNUNET_DISK_OpenFlags
{

    /**
     * Open the file for reading
     */
  GNUNET_DISK_OPEN_READ = 1,

    /**
     * Open the file for writing
     */
  GNUNET_DISK_OPEN_WRITE = 2,

    /**
     * Open the file for both reading and writing
     */
  GNUNET_DISK_OPEN_READWRITE = 3,

    /**
     * Fail if file already exists
     */
  GNUNET_DISK_OPEN_FAILIFEXISTS = 4,

    /**
     * Truncate file if it exists
     */
  GNUNET_DISK_OPEN_TRUNCATE = 8,

    /**
     * Create file if it doesn't exist
     */
  GNUNET_DISK_OPEN_CREATE = 16,

    /**
     * Append to the file
     */
  GNUNET_DISK_OPEN_APPEND = 32
};

/**
 * Specifies what type of memory map is desired.
 */
enum GNUNET_DISK_MapType
{
    /**
     * Read-only memory map.
     */
  GNUNET_DISK_MAP_TYPE_READ = 1,

    /**
     * Write-able memory map.
     */
  GNUNET_DISK_MAP_TYPE_WRITE = 2,
    /**
     * Read-write memory map.
     */
  GNUNET_DISK_MAP_TYPE_READWRITE = 3
};


/**
 * File access permissions, UNIX-style.
 */
enum GNUNET_DISK_AccessPermissions
{
    /**
     * Nobody is allowed to do anything to the file.
     */
  GNUNET_DISK_PERM_NONE = 0,

    /**
     * Owner can read.
     */
  GNUNET_DISK_PERM_USER_READ = 1,

    /**
     * Owner can write.
     */
  GNUNET_DISK_PERM_USER_WRITE = 2,

    /**
     * Owner can execute.
     */
  GNUNET_DISK_PERM_USER_EXEC = 4,

    /**
     * Group can read.
     */
  GNUNET_DISK_PERM_GROUP_READ = 8,

    /**
     * Group can write.
     */
  GNUNET_DISK_PERM_GROUP_WRITE = 16,

    /**
     * Group can execute.
     */
  GNUNET_DISK_PERM_GROUP_EXEC = 32,

    /**
     * Everybody can read.
     */
  GNUNET_DISK_PERM_OTHER_READ = 64,

    /**
     * Everybody can write.
     */
  GNUNET_DISK_PERM_OTHER_WRITE = 128,

    /**
     * Everybody can execute.
     */
  GNUNET_DISK_PERM_OTHER_EXEC = 256
};


/**
 * Constants for specifying how to seek.
 */
enum GNUNET_DISK_Seek
{
    /**
     * Seek an absolute position (from the start of the file).
     */
  GNUNET_DISK_SEEK_SET,

    /**
     * Seek a relative position (from the current offset).
     */
  GNUNET_DISK_SEEK_CUR,

    /**
     * Seek an absolute position from the end of the file.
     */
  GNUNET_DISK_SEEK_END
};


/**
 * Enumeration identifying the two ends of a pipe.
 */
enum GNUNET_DISK_PipeEnd
{
    /**
     * The reading-end of a pipe.
     */
  GNUNET_DISK_PIPE_END_READ = 0,

    /**
     * The writing-end of a pipe.
     */
  GNUNET_DISK_PIPE_END_WRITE = 1
};


/**
 * Get the number of blocks that are left on the partition that
 * contains the given file (for normal users).
 *
 * @param part a file on the partition to check
 * @return -1 on errors, otherwise the number of free blocks
 */
long
GNUNET_DISK_get_blocks_available (const char *part);


/**
 * Checks whether a handle is invalid
 *
 * @param h handle to check
 * @return GNUNET_YES if invalid, GNUNET_NO if valid
 */
int
GNUNET_DISK_handle_invalid (const struct GNUNET_DISK_FileHandle *h);


/**
 * Check that fil corresponds to a filename
 * (of a file that exists and that is not a directory).
 *
 * @param fil filename to check
 * @return GNUNET_YES if yes, GNUNET_NO if not a file, GNUNET_SYSERR if something
 * else (will print an error message in that case, too).
 */
int
GNUNET_DISK_file_test (const char *fil);


/**
 * Move the read/write pointer in a file
 * @param h handle of an open file
 * @param offset position to move to
 * @param whence specification to which position the offset parameter relates to
 * @return the new position on success, GNUNET_SYSERR otherwise
 */
OFF_T
GNUNET_DISK_file_seek (const struct GNUNET_DISK_FileHandle *h, OFF_T offset,
                       enum GNUNET_DISK_Seek whence);


/**
 * Get the size of the file (or directory)
 * of the given file (in bytes).
 *
 * @param filename name of the file or directory
 * @param size set to the size of the file (or,
 *             in the case of directories, the sum
 *             of all sizes of files in the directory)
 * @param includeSymLinks should symbolic links be
 *        included?
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DISK_file_size (const char *filename, uint64_t * size,
                       int includeSymLinks);


/**
 * Obtain some unique identifiers for the given file
 * that can be used to identify it in the local system.
 * This function is used between GNUnet processes to
 * quickly check if two files with the same absolute path
 * are actually identical.  The two processes represent
 * the same peer but may communicate over the network
 * (and the file may be on an NFS volume).  This function
 * may not be supported on all operating systems.
 *
 * @param filename name of the file
 * @param dev set to the device ID
 * @param ino set to the inode ID
 * @return GNUNET_OK on success
 */
int
GNUNET_DISK_file_get_identifiers (const char *filename, uint64_t * dev,
                                  uint64_t * ino);


/**
 * Create an (empty) temporary file on disk.  If the given name is not
 * an absolute path, the current 'TMPDIR' will be prepended.  In any case,
 * 6 random characters will be appended to the name to create a unique
 * filename.
 *
 * @param t component to use for the name;
 *        does NOT contain "XXXXXX" or "/tmp/".
 * @return NULL on error, otherwise name of fresh
 *         file on disk in directory for temporary files
 */
char *
GNUNET_DISK_mktemp (const char *t);


/**
 * Open a file.  Note that the access permissions will only be
 * used if a new file is created and if the underlying operating
 * system supports the given permissions.
 *
 * @param fn file name to be opened
 * @param flags opening flags, a combination of GNUNET_DISK_OPEN_xxx bit flags
 * @param perm permissions for the newly created file, use
 *             GNUNET_DISK_PERM_NONE if a file could not be created by this
 *             call (because of flags)
 * @return IO handle on success, NULL on error
 */
struct GNUNET_DISK_FileHandle *
GNUNET_DISK_file_open (const char *fn, enum GNUNET_DISK_OpenFlags flags,
                       enum GNUNET_DISK_AccessPermissions perm);


/**
 * Get the size of an open file.
 *
 * @param fh open file handle
 * @param size where to write size of the file
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DISK_file_handle_size (struct GNUNET_DISK_FileHandle *fh,
			      OFF_T *size);


/**
 * Creates an interprocess channel
 *
 * @param blocking_read creates an asynchronous pipe for reading if set to GNUNET_NO
 * @param blocking_write creates an asynchronous pipe for writing if set to GNUNET_NO
 * @param inherit_read 1 to make read handle inheritable, 0 otherwise (NT only)
 * @param inherit_write 1 to make write handle inheritable, 0 otherwise (NT only)
 * @return handle to the new pipe, NULL on error
 */
struct GNUNET_DISK_PipeHandle *
GNUNET_DISK_pipe (int blocking_read, int blocking_write, int inherit_read, int inherit_write);


/**
 * Creates a pipe object from a couple of file descriptors.
 * Useful for wrapping existing pipe FDs.
 *
 * @param blocking_read creates an asynchronous pipe for reading if set to GNUNET_NO
 * @param blocking_write creates an asynchronous pipe for writing if set to GNUNET_NO
 * @param fd an array of two fd values. One of them may be -1 for read-only or write-only pipes
 *
 * @return handle to the new pipe, NULL on error
 */
struct GNUNET_DISK_PipeHandle *
GNUNET_DISK_pipe_from_fd (int blocking_read, int blocking_write, int fd[2]);

/**
 * Closes an interprocess channel
 * @param p pipe
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_DISK_pipe_close (struct GNUNET_DISK_PipeHandle *p);

/**
 * Closes one half of an interprocess channel
 *
 * @param p pipe to close end of
 * @param end which end of the pipe to close
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_DISK_pipe_close_end (struct GNUNET_DISK_PipeHandle *p,
                            enum GNUNET_DISK_PipeEnd end);

/**
 * Close an open file.
 *
 * @param h file handle
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_DISK_file_close (struct GNUNET_DISK_FileHandle *h);


/**
 * Get the handle to a particular pipe end
 *
 * @param p pipe
 * @param n end to access
 * @return handle for the respective end
 */
const struct GNUNET_DISK_FileHandle *
GNUNET_DISK_pipe_handle (const struct GNUNET_DISK_PipeHandle *p,
                         enum GNUNET_DISK_PipeEnd n);

/**
 * Read the contents of a binary file into a buffer.
 * @param h handle to an open file
 * @param result the buffer to write the result to
 * @param len the maximum number of bytes to read
 * @return the number of bytes read on success, GNUNET_SYSERR on failure
 */
ssize_t
GNUNET_DISK_file_read (const struct GNUNET_DISK_FileHandle *h, void *result,
                       size_t len);

/**
 * Read the contents of a binary file into a buffer.
 * Guarantees not to block (returns GNUNET_SYSERR and sets errno to EAGAIN
 * when no data can be read).
 *
 * @param h handle to an open file
 * @param result the buffer to write the result to
 * @param len the maximum number of bytes to read
 * @return the number of bytes read on success, GNUNET_SYSERR on failure
 */
ssize_t
GNUNET_DISK_file_read_non_blocking (const struct GNUNET_DISK_FileHandle * h,
    void *result, size_t len);

/**
 * Read the contents of a binary file into a buffer.
 *
 * @param fn file name
 * @param result the buffer to write the result to
 * @param len the maximum number of bytes to read
 * @return number of bytes read, GNUNET_SYSERR on failure
 */
ssize_t
GNUNET_DISK_fn_read (const char *fn, void *result, size_t len);


/**
 * Write a buffer to a file.
 *
 * @param h handle to open file
 * @param buffer the data to write
 * @param n number of bytes to write
 * @return number of bytes written on success, GNUNET_SYSERR on error
 */
ssize_t
GNUNET_DISK_file_write (const struct GNUNET_DISK_FileHandle *h,
                        const void *buffer, size_t n);


/**
 * Write a buffer to a file, blocking, if necessary.
 * @param h handle to open file
 * @param buffer the data to write
 * @param n number of bytes to write
 * @return number of bytes written on success, GNUNET_SYSERR on error
 */
ssize_t
GNUNET_DISK_file_write_blocking (const struct GNUNET_DISK_FileHandle * h,
    const void *buffer, size_t n);

/**
 * Write a buffer to a file.  If the file is longer than
 * the given buffer size, it will be truncated.
 *
 * @param fn file name
 * @param buffer the data to write
 * @param n number of bytes to write
 * @param mode file permissions
 * @return number of bytes written on success, GNUNET_SYSERR on error
 */
ssize_t
GNUNET_DISK_fn_write (const char *fn, const void *buffer, size_t n,
                      enum GNUNET_DISK_AccessPermissions mode);


/**
 * Copy a file.
 *
 * @param src file to copy
 * @param dst destination file name
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DISK_file_copy (const char *src, const char *dst);


/**
 * Scan a directory for files.
 *
 * @param dirName the name of the directory
 * @param callback the method to call for each file
 * @param callback_cls closure for callback
 * @return the number of files found, -1 on error
 */
int
GNUNET_DISK_directory_scan (const char *dirName,
                            GNUNET_FileNameCallback callback,
                            void *callback_cls);


/**
 * Opaque handle used for iterating over a directory.
 */
struct GNUNET_DISK_DirectoryIterator;


/**
 * Function called to iterate over a directory.
 *
 * @param cls closure
 * @param di argument to pass to "GNUNET_DISK_directory_iterator_next" to
 *           get called on the next entry (or finish cleanly);
 *           NULL on error (will be the last call in that case)
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
int
GNUNET_DISK_directory_iterator_next (struct GNUNET_DISK_DirectoryIterator *iter,
                                     int can);


/**
 * Scan a directory for files using the scheduler to run a task for
 * each entry.  The name of the directory must be expanded first (!).
 * If a scheduler does not need to be used, GNUNET_DISK_directory_scan
 * may provide a simpler API.
 *
 * @param prio priority to use
 * @param dirName the name of the directory
 * @param callback the method to call for each file
 * @param callback_cls closure for callback
 * @return GNUNET_YES if directory is not empty and 'callback'
 *         will be called later, GNUNET_NO otherwise, GNUNET_SYSERR on error.
 */
int
GNUNET_DISK_directory_iterator_start (enum GNUNET_SCHEDULER_Priority prio,
                                      const char *dirName,
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
int
GNUNET_DISK_directory_create_for_file (const char *filename);


/**
 * Test if "fil" is a directory that can be accessed.
 * Will not print an error message if the directory
 * does not exist.  Will log errors if GNUNET_SYSERR is
 * returned.
 *
 * @param fil filename to test
 * @return GNUNET_YES if yes, GNUNET_NO if does not exist, GNUNET_SYSERR
 *   on any error and if exists but not directory
 */
int
GNUNET_DISK_directory_test (const char *fil);


/**
 * Remove all files in a directory (rm -rf). Call with
 * caution.
 *
 * @param fileName the file to remove
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DISK_directory_remove (const char *fileName);


/**
 * Implementation of "mkdir -p"
 *
 * @param dir the directory to create
 * @returns GNUNET_SYSERR on failure, GNUNET_OK otherwise
 */
int
GNUNET_DISK_directory_create (const char *dir);


/**
 * Lock a part of a file.
 *
 * @param fh file handle
 * @param lockStart absolute position from where to lock
 * @param lockEnd absolute position until where to lock
 * @param excl GNUNET_YES for an exclusive lock
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DISK_file_lock (struct GNUNET_DISK_FileHandle *fh, OFF_T lockStart,
                       OFF_T lockEnd, int excl);


/**
 * Unlock a part of a file
 * @param fh file handle
 * @param unlockStart absolute position from where to unlock
 * @param unlockEnd absolute position until where to unlock
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DISK_file_unlock (struct GNUNET_DISK_FileHandle *fh, OFF_T unlockStart,
                         OFF_T unlockEnd);


/**
 * @brief Removes special characters as ':' from a filename.
 * @param fn the filename to canonicalize
 */
void
GNUNET_DISK_filename_canonicalize (char *fn);


/**
 * @brief Change owner of a file
 * @param filename file to change
 * @param user new owner of the file
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_DISK_file_change_owner (const char *filename, const char *user);


/**
 * Construct full path to a file inside of the private
 * directory used by GNUnet.  Also creates the corresponding
 * directory.  If the resulting name is supposed to be
 * a directory, end the last argument in '/' (or pass
 * DIR_SEPARATOR_STR as the last argument before NULL).
 *
 * @param cfg configuration to use
 * @param serviceName name of the service asking
 * @param ... is NULL-terminated list of
 *                path components to append to the
 *                private directory name.
 * @return the constructed filename
 */
char *
GNUNET_DISK_get_home_filename (const struct GNUNET_CONFIGURATION_Handle *cfg,
                               const char *serviceName, ...);


/**
 * Opaque handle for a memory-mapping operation.
 */
struct GNUNET_DISK_MapHandle;

/**
 * Map a file into memory
 * @param h open file handle
 * @param m handle to the new mapping (will be set)
 * @param access access specification, GNUNET_DISK_MAP_TYPE_xxx
 * @param len size of the mapping
 * @return pointer to the mapped memory region, NULL on failure
 */
void *
GNUNET_DISK_file_map (const struct GNUNET_DISK_FileHandle *h,
                      struct GNUNET_DISK_MapHandle **m,
                      enum GNUNET_DISK_MapType access, size_t len);

/**
 * Unmap a file
 *
 * @param h mapping handle
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_DISK_file_unmap (struct GNUNET_DISK_MapHandle *h);

/**
 * Write file changes to disk
 * @param h handle to an open file
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_DISK_file_sync (const struct GNUNET_DISK_FileHandle *h);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_DISK_LIB_H */
#endif
/* end of gnunet_disk_lib.h */
