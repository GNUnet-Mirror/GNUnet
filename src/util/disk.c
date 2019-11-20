/*
     This file is part of GNUnet.
     Copyright (C) 2001--2013, 2016, 2018 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file util/disk.c
 * @brief disk IO convenience methods
 * @author Christian Grothoff
 * @author Nils Durner
 */
#include "platform.h"
#include "disk.h"
#include "gnunet_strings_lib.h"
#include "gnunet_disk_lib.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "util-disk", __VA_ARGS__)

#define LOG_STRERROR(kind, syscall) \
  GNUNET_log_from_strerror (kind, "util-disk", syscall)

#define LOG_STRERROR_FILE(kind, syscall, filename) \
  GNUNET_log_from_strerror_file (kind, "util-disk", syscall, filename)

/**
 * Block size for IO for copying files.
 */
#define COPY_BLK_SIZE 65536

#include <sys/types.h>
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#if HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif

#ifndef S_ISLNK
#define _IFMT 0170000 /* type of file */
#define _IFLNK 0120000 /* symbolic link */
#define S_ISLNK(m) (((m) & _IFMT) == _IFLNK)
#endif


/**
 * Handle used to manage a pipe.
 */
struct GNUNET_DISK_PipeHandle
{
  /**
   * File descriptors for the pipe.
   * One or both of them could be NULL.
   */
  struct GNUNET_DISK_FileHandle *fd[2];
};


/**
 * Closure for the recursion to determine the file size
 * of a directory.
 */
struct GetFileSizeData
{
  /**
   * Set to the total file size.
   */
  uint64_t total;

  /**
   * GNUNET_YES if symbolic links should be included.
   */
  int include_sym_links;

  /**
   * GNUNET_YES if mode is file-only (return total == -1 for directories).
   */
  int single_file_mode;
};


/**
 * Translate GNUnet-internal permission bitmap to UNIX file
 * access permission bitmap.
 *
 * @param perm file permissions, GNUnet style
 * @return file permissions, UNIX style
 */
static int
translate_unix_perms (enum GNUNET_DISK_AccessPermissions perm)
{
  int mode;

  mode = 0;
  if (perm & GNUNET_DISK_PERM_USER_READ)
    mode |= S_IRUSR;
  if (perm & GNUNET_DISK_PERM_USER_WRITE)
    mode |= S_IWUSR;
  if (perm & GNUNET_DISK_PERM_USER_EXEC)
    mode |= S_IXUSR;
  if (perm & GNUNET_DISK_PERM_GROUP_READ)
    mode |= S_IRGRP;
  if (perm & GNUNET_DISK_PERM_GROUP_WRITE)
    mode |= S_IWGRP;
  if (perm & GNUNET_DISK_PERM_GROUP_EXEC)
    mode |= S_IXGRP;
  if (perm & GNUNET_DISK_PERM_OTHER_READ)
    mode |= S_IROTH;
  if (perm & GNUNET_DISK_PERM_OTHER_WRITE)
    mode |= S_IWOTH;
  if (perm & GNUNET_DISK_PERM_OTHER_EXEC)
    mode |= S_IXOTH;

  return mode;
}


/**
 * Iterate over all files in the given directory and
 * accumulate their size.
 *
 * @param cls closure of type `struct GetFileSizeData`
 * @param fn current filename we are looking at
 * @return #GNUNET_SYSERR on serious errors, otherwise #GNUNET_OK
 */
static int
getSizeRec (void *cls, const char *fn)
{
  struct GetFileSizeData *gfsd = cls;

#if defined(HAVE_STAT64) && \
  ! (defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64)
  struct stat64 buf;

  if (0 != stat64 (fn, &buf))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_DEBUG, "stat64", fn);
    return GNUNET_SYSERR;
  }
#else
  struct stat buf;

  if (0 != stat (fn, &buf))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_DEBUG, "stat", fn);
    return GNUNET_SYSERR;
  }
#endif
  if ((S_ISDIR (buf.st_mode)) && (gfsd->single_file_mode == GNUNET_YES))
  {
    errno = EISDIR;
    return GNUNET_SYSERR;
  }
  if ((! S_ISLNK (buf.st_mode)) || (gfsd->include_sym_links == GNUNET_YES))
    gfsd->total += buf.st_size;
  if ((S_ISDIR (buf.st_mode)) && (0 == access (fn, X_OK)) &&
      ((! S_ISLNK (buf.st_mode)) || (gfsd->include_sym_links == GNUNET_YES)))
  {
    if (GNUNET_SYSERR == GNUNET_DISK_directory_scan (fn, &getSizeRec, gfsd))
      return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Checks whether a handle is invalid
 *
 * @param h handle to check
 * @return #GNUNET_YES if invalid, #GNUNET_NO if valid
 */
int
GNUNET_DISK_handle_invalid (const struct GNUNET_DISK_FileHandle *h)
{
  return ((! h) || (h->fd == -1)) ? GNUNET_YES : GNUNET_NO;
}


/**
 * Get the size of an open file.
 *
 * @param fh open file handle
 * @param size where to write size of the file
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_DISK_file_handle_size (struct GNUNET_DISK_FileHandle *fh, off_t *size)
{
  struct stat sbuf;

  if (0 != fstat (fh->fd, &sbuf))
    return GNUNET_SYSERR;
  *size = sbuf.st_size;
  return GNUNET_OK;
}


/**
 * Move the read/write pointer in a file
 *
 * @param h handle of an open file
 * @param offset position to move to
 * @param whence specification to which position the offset parameter relates to
 * @return the new position on success, #GNUNET_SYSERR otherwise
 */
off_t
GNUNET_DISK_file_seek (const struct GNUNET_DISK_FileHandle *h,
                       off_t offset,
                       enum GNUNET_DISK_Seek whence)
{
  if (h == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

  static int t[] = { SEEK_SET, SEEK_CUR, SEEK_END };

  return lseek (h->fd, offset, t[whence]);
}


/**
 * Get the size of the file (or directory) of the given file (in
 * bytes).
 *
 * @param filename name of the file or directory
 * @param size set to the size of the file (or,
 *             in the case of directories, the sum
 *             of all sizes of files in the directory)
 * @param include_symbolic_links should symbolic links be
 *        included?
 * @param single_file_mode #GNUNET_YES to only get size of one file
 *        and return #GNUNET_SYSERR for directories.
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
GNUNET_DISK_file_size (const char *filename,
                       uint64_t *size,
                       int include_symbolic_links,
                       int single_file_mode)
{
  struct GetFileSizeData gfsd;
  int ret;

  GNUNET_assert (size != NULL);
  gfsd.total = 0;
  gfsd.include_sym_links = include_symbolic_links;
  gfsd.single_file_mode = single_file_mode;
  ret = getSizeRec (&gfsd, filename);
  *size = gfsd.total;
  return ret;
}


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
 * @return #GNUNET_OK on success
 */
int
GNUNET_DISK_file_get_identifiers (const char *filename,
                                  uint64_t *dev,
                                  uint64_t *ino)
{
#if HAVE_STAT
  {
    struct stat sbuf;

    if (0 != stat (filename, &sbuf))
    {
      return GNUNET_SYSERR;
    }
    *ino = (uint64_t) sbuf.st_ino;
  }
#else
  *ino = 0;
#endif
#if HAVE_STATVFS
  {
    struct statvfs fbuf;

    if (0 != statvfs (filename, &fbuf))
    {
      return GNUNET_SYSERR;
    }
    *dev = (uint64_t) fbuf.f_fsid;
  }
#elif HAVE_STATFS
  {
    struct statfs fbuf;

    if (0 != statfs (filename, &fbuf))
    {
      return GNUNET_SYSERR;
    }
    *dev =
      ((uint64_t) fbuf.f_fsid.val[0]) << 32 || ((uint64_t) fbuf.f_fsid.val[1]);
  }
#else
  *dev = 0;
#endif
  return GNUNET_OK;
}


/**
 * Create the name for a temporary file or directory from a template.
 *
 * @param t template (without XXXXX or "/tmp/")
 * @return name ready for passing to 'mktemp' or 'mkdtemp', NULL on error
 */
static char *
mktemp_name (const char *t)
{
  const char *tmpdir;
  char *tmpl;
  char *fn;

  if ((t[0] != '/') && (t[0] != '\\'))
  {
    /* FIXME: This uses system codepage on W32, not UTF-8 */
    tmpdir = getenv ("TMPDIR");
    if (NULL == tmpdir)
      tmpdir = getenv ("TMP");
    if (NULL == tmpdir)
      tmpdir = getenv ("TEMP");
    if (NULL == tmpdir)
      tmpdir = "/tmp";
    GNUNET_asprintf (&tmpl, "%s/%s%s", tmpdir, t, "XXXXXX");
  }
  else
  {
    GNUNET_asprintf (&tmpl, "%s%s", t, "XXXXXX");
  }
  fn = tmpl;
  return fn;
}


/**
 * Update POSIX permissions mask of a file on disk.  If both argumets
 * are #GNUNET_NO, the file is made world-read-write-executable (777).
 *
 * @param fn name of the file to update
 * @param require_uid_match #GNUNET_YES means 700
 * @param require_gid_match #GNUNET_YES means 770 unless @a require_uid_match is set
 */
void
GNUNET_DISK_fix_permissions (const char *fn,
                             int require_uid_match,
                             int require_gid_match)
{
  mode_t mode;

  if (GNUNET_YES == require_uid_match)
    mode = S_IRUSR | S_IWUSR | S_IXUSR;
  else if (GNUNET_YES == require_gid_match)
    mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP;
  else
    mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH
           | S_IWOTH | S_IXOTH;
  if (0 != chmod (fn, mode))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "chmod", fn);
}


/**
 * Create an (empty) temporary directory on disk.  If the given name is not
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
GNUNET_DISK_mkdtemp (const char *t)
{
  char *fn;
  mode_t omask;

  omask = umask (S_IWGRP | S_IWOTH | S_IRGRP | S_IROTH);
  fn = mktemp_name (t);
  if (fn != mkdtemp (fn))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "mkdtemp", fn);
    GNUNET_free (fn);
    umask (omask);
    return NULL;
  }
  umask (omask);
  return fn;
}


/**
 * Move a file out of the way (create a backup) by
 * renaming it to "orig.NUM~" where NUM is the smallest
 * number that is not used yet.
 *
 * @param fil name of the file to back up
 */
void
GNUNET_DISK_file_backup (const char *fil)
{
  size_t slen;
  char *target;
  unsigned int num;

  slen = strlen (fil) + 20;
  target = GNUNET_malloc (slen);
  num = 0;
  do
  {
    GNUNET_snprintf (target, slen, "%s.%u~", fil, num++);
  }
  while (0 == access (target, F_OK));
  if (0 != rename (fil, target))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "rename", fil);
  GNUNET_free (target);
}


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
GNUNET_DISK_mktemp (const char *t)
{
  int fd;
  char *fn;
  mode_t omask;

  omask = umask (S_IWGRP | S_IWOTH | S_IRGRP | S_IROTH);
  fn = mktemp_name (t);
  if (-1 == (fd = mkstemp (fn)))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "mkstemp", fn);
    GNUNET_free (fn);
    umask (omask);
    return NULL;
  }
  umask (omask);
  if (0 != close (fd))
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "close", fn);
  return fn;
}


/**
 * Test if @a fil is a directory and listable. Optionally, also check if the
 * directory is readable.  Will not print an error message if the directory does
 * not exist.  Will log errors if #GNUNET_SYSERR is returned (i.e., a file exists
 * with the same name).
 *
 * @param fil filename to test
 * @param is_readable #GNUNET_YES to additionally check if @a fil is readable;
 *          #GNUNET_NO to disable this check
 * @return #GNUNET_YES if yes, #GNUNET_NO if not; #GNUNET_SYSERR if it
 *           does not exist or stat'ed
 */
int
GNUNET_DISK_directory_test (const char *fil, int is_readable)
{
  struct stat filestat;
  int ret;

  ret = stat (fil, &filestat);
  if (ret != 0)
  {
    if (errno != ENOENT)
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "stat", fil);
    return GNUNET_SYSERR;
  }
  if (! S_ISDIR (filestat.st_mode))
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "A file already exits with the same name %s\n",
         fil);
    return GNUNET_NO;
  }
  if (GNUNET_YES == is_readable)
    ret = access (fil, R_OK | X_OK);
  else
    ret = access (fil, X_OK);
  if (ret < 0)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "access", fil);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Check that fil corresponds to a filename
 * (of a file that exists and that is not a directory).
 *
 * @param fil filename to check
 * @return #GNUNET_YES if yes, #GNUNET_NO if not a file, #GNUNET_SYSERR if something
 * else (will print an error message in that case, too).
 */
int
GNUNET_DISK_file_test (const char *fil)
{
  struct stat filestat;
  int ret;
  char *rdir;

  rdir = GNUNET_STRINGS_filename_expand (fil);
  if (rdir == NULL)
    return GNUNET_SYSERR;

  ret = stat (rdir, &filestat);
  if (ret != 0)
  {
    if (errno != ENOENT)
    {
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "stat", rdir);
      GNUNET_free (rdir);
      return GNUNET_SYSERR;
    }
    GNUNET_free (rdir);
    return GNUNET_NO;
  }
  if (! S_ISREG (filestat.st_mode))
  {
    GNUNET_free (rdir);
    return GNUNET_NO;
  }
  if (access (rdir, F_OK) < 0)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "access", rdir);
    GNUNET_free (rdir);
    return GNUNET_SYSERR;
  }
  GNUNET_free (rdir);
  return GNUNET_YES;
}


/**
 * Implementation of "mkdir -p"
 *
 * @param dir the directory to create
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
GNUNET_DISK_directory_create (const char *dir)
{
  char *rdir;
  unsigned int len;
  unsigned int pos;
  unsigned int pos2;
  int ret = GNUNET_OK;

  rdir = GNUNET_STRINGS_filename_expand (dir);
  if (rdir == NULL)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  len = strlen (rdir);

  pos = 1; /* skip heading '/' */

  /* Check which low level directories already exist */
  pos2 = len;
  rdir[len] = DIR_SEPARATOR;
  while (pos <= pos2)
  {
    if (DIR_SEPARATOR == rdir[pos2])
    {
      rdir[pos2] = '\0';
      ret = GNUNET_DISK_directory_test (rdir, GNUNET_NO);
      if (GNUNET_NO == ret)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Creating directory `%s' failed",
                    rdir);
        GNUNET_free (rdir);
        return GNUNET_SYSERR;
      }
      rdir[pos2] = DIR_SEPARATOR;
      if (GNUNET_YES == ret)
      {
        pos2++;
        break;
      }
    }
    pos2--;
  }
  rdir[len] = '\0';
  if (pos < pos2)
    pos = pos2;
  /* Start creating directories */
  while (pos <= len)
  {
    if ((rdir[pos] == DIR_SEPARATOR) || (pos == len))
    {
      rdir[pos] = '\0';
      ret = GNUNET_DISK_directory_test (rdir, GNUNET_NO);
      if (GNUNET_NO == ret)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Creating directory `%s' failed",
                    rdir);
        GNUNET_free (rdir);
        return GNUNET_SYSERR;
      }
      if (GNUNET_SYSERR == ret)
      {
        ret = mkdir (rdir,
                     S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH
                     | S_IXOTH);    /* 755 */

        if ((ret != 0) && (errno != EEXIST))
        {
          LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "mkdir", rdir);
          GNUNET_free (rdir);
          return GNUNET_SYSERR;
        }
      }
      rdir[pos] = DIR_SEPARATOR;
    }
    pos++;
  }
  GNUNET_free (rdir);
  return GNUNET_OK;
}


/**
 * Create the directory structure for storing a file.
 *
 * @param filename name of a file in the directory
 * @returns #GNUNET_OK on success,
 *          #GNUNET_SYSERR on failure,
 *          #GNUNET_NO if the directory
 *          exists but is not writeable for us
 */
int
GNUNET_DISK_directory_create_for_file (const char *filename)
{
  char *rdir;
  size_t len;
  int ret;
  int eno;

  rdir = GNUNET_STRINGS_filename_expand (filename);
  if (NULL == rdir)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }
  if (0 == access (rdir, W_OK))
  {
    GNUNET_free (rdir);
    return GNUNET_OK;
  }

  len = strlen (rdir);
  while ((len > 0) && (rdir[len] != DIR_SEPARATOR))
    len--;
  rdir[len] = '\0';
  /* The empty path is invalid and in this case refers to / */
  if (0 == len)
  {
    GNUNET_free (rdir);
    rdir = GNUNET_strdup ("/");
  }
  ret = GNUNET_DISK_directory_create (rdir);
  if ((GNUNET_OK == ret) && (0 != access (rdir, W_OK)))
    ret = GNUNET_NO;
  eno = errno;
  GNUNET_free (rdir);
  errno = eno;
  return ret;
}


/**
 * Read the contents of a binary file into a buffer.
 *
 * @param h handle to an open file
 * @param result the buffer to write the result to
 * @param len the maximum number of bytes to read
 * @return the number of bytes read on success, #GNUNET_SYSERR on failure
 */
ssize_t
GNUNET_DISK_file_read (const struct GNUNET_DISK_FileHandle *h,
                       void *result,
                       size_t len)
{
  if (NULL == h)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

  return read (h->fd, result, len);
}


/**
 * Read the contents of a binary file into a buffer.
 * Guarantees not to block (returns GNUNET_SYSERR and sets errno to EAGAIN
 * when no data can be read).
 *
 * @param h handle to an open file
 * @param result the buffer to write the result to
 * @param len the maximum number of bytes to read
 * @return the number of bytes read on success, #GNUNET_SYSERR on failure
 */
ssize_t
GNUNET_DISK_file_read_non_blocking (const struct GNUNET_DISK_FileHandle *h,
                                    void *result,
                                    size_t len)
{
  if (NULL == h)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

  int flags;
  ssize_t ret;

  /* set to non-blocking, read, then set back */
  flags = fcntl (h->fd, F_GETFL);
  if (0 == (flags & O_NONBLOCK))
    (void) fcntl (h->fd, F_SETFL, flags | O_NONBLOCK);
  ret = read (h->fd, result, len);
  if (0 == (flags & O_NONBLOCK))
  {
    int eno = errno;
    (void) fcntl (h->fd, F_SETFL, flags);
    errno = eno;
  }
  return ret;
}


/**
 * Read the contents of a binary file into a buffer.
 *
 * @param fn file name
 * @param result the buffer to write the result to
 * @param len the maximum number of bytes to read
 * @return number of bytes read, #GNUNET_SYSERR on failure
 */
ssize_t
GNUNET_DISK_fn_read (const char *fn, void *result, size_t len)
{
  struct GNUNET_DISK_FileHandle *fh;
  ssize_t ret;
  int eno;

  fh = GNUNET_DISK_file_open (fn, GNUNET_DISK_OPEN_READ, GNUNET_DISK_PERM_NONE);
  if (NULL == fh)
    return GNUNET_SYSERR;
  ret = GNUNET_DISK_file_read (fh, result, len);
  eno = errno;
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));
  errno = eno;
  return ret;
}


/**
 * Write a buffer to a file.
 *
 * @param h handle to open file
 * @param buffer the data to write
 * @param n number of bytes to write
 * @return number of bytes written on success, #GNUNET_SYSERR on error
 */
ssize_t
GNUNET_DISK_file_write (const struct GNUNET_DISK_FileHandle *h,
                        const void *buffer,
                        size_t n)
{
  if (NULL == h)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }


  return write (h->fd, buffer, n);
}


/**
 * Write a buffer to a file, blocking, if necessary.
 *
 * @param h handle to open file
 * @param buffer the data to write
 * @param n number of bytes to write
 * @return number of bytes written on success, #GNUNET_SYSERR on error
 */
ssize_t
GNUNET_DISK_file_write_blocking (const struct GNUNET_DISK_FileHandle *h,
                                 const void *buffer,
                                 size_t n)
{
  if (NULL == h)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }


  int flags;
  ssize_t ret;

  /* set to blocking, write, then set back */
  flags = fcntl (h->fd, F_GETFL);
  if (0 != (flags & O_NONBLOCK))
    (void) fcntl (h->fd, F_SETFL, flags - O_NONBLOCK);
  ret = write (h->fd, buffer, n);
  if (0 == (flags & O_NONBLOCK))
    (void) fcntl (h->fd, F_SETFL, flags);
  return ret;
}


/**
 * Write a buffer to a file.  If the file is longer than the
 * number of bytes that will be written, it will be truncated.
 *
 * @param fn file name
 * @param buffer the data to write
 * @param n number of bytes to write
 * @param mode file permissions
 * @return number of bytes written on success, #GNUNET_SYSERR on error
 */
ssize_t
GNUNET_DISK_fn_write (const char *fn,
                      const void *buffer,
                      size_t n,
                      enum GNUNET_DISK_AccessPermissions mode)
{
  struct GNUNET_DISK_FileHandle *fh;
  ssize_t ret;

  fh =
    GNUNET_DISK_file_open (fn,
                           GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_TRUNCATE
                           | GNUNET_DISK_OPEN_CREATE,
                           mode);
  if (! fh)
    return GNUNET_SYSERR;
  ret = GNUNET_DISK_file_write (fh, buffer, n);
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));
  return ret;
}


/**
 * Scan a directory for files.
 *
 * @param dir_name the name of the directory
 * @param callback the method to call for each file,
 *        can be NULL, in that case, we only count
 * @param callback_cls closure for @a callback
 * @return the number of files found, #GNUNET_SYSERR on error or
 *         ieration aborted by callback returning #GNUNET_SYSERR
 */
int
GNUNET_DISK_directory_scan (const char *dir_name,
                            GNUNET_FileNameCallback callback,
                            void *callback_cls)
{
  DIR *dinfo;
  struct dirent *finfo;
  struct stat istat;
  int count = 0;
  int ret;
  char *name;
  char *dname;
  unsigned int name_len;
  unsigned int n_size;

  GNUNET_assert (NULL != dir_name);
  dname = GNUNET_STRINGS_filename_expand (dir_name);
  if (NULL == dname)
    return GNUNET_SYSERR;
  while ((strlen (dname) > 0) && (dname[strlen (dname) - 1] == DIR_SEPARATOR))
    dname[strlen (dname) - 1] = '\0';
  if (0 != stat (dname, &istat))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "stat", dname);
    GNUNET_free (dname);
    return GNUNET_SYSERR;
  }
  if (! S_ISDIR (istat.st_mode))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ ("Expected `%s' to be a directory!\n"),
         dir_name);
    GNUNET_free (dname);
    return GNUNET_SYSERR;
  }
  errno = 0;
  dinfo = opendir (dname);
  if ((EACCES == errno) || (NULL == dinfo))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "opendir", dname);
    if (NULL != dinfo)
      closedir (dinfo);
    GNUNET_free (dname);
    return GNUNET_SYSERR;
  }
  name_len = 256;
  n_size = strlen (dname) + name_len + strlen (DIR_SEPARATOR_STR) + 1;
  name = GNUNET_malloc (n_size);
  while (NULL != (finfo = readdir (dinfo)))
  {
    if ((0 == strcmp (finfo->d_name, ".")) ||
        (0 == strcmp (finfo->d_name, "..")))
      continue;
    if (NULL != callback)
    {
      if (name_len < strlen (finfo->d_name))
      {
        GNUNET_free (name);
        name_len = strlen (finfo->d_name);
        n_size = strlen (dname) + name_len + strlen (DIR_SEPARATOR_STR) + 1;
        name = GNUNET_malloc (n_size);
      }
      /* dname can end in "/" only if dname == "/";
       * if dname does not end in "/", we need to add
       * a "/" (otherwise, we must not!) */
      GNUNET_snprintf (name,
                       n_size,
                       "%s%s%s",
                       dname,
                       (0 == strcmp (dname, DIR_SEPARATOR_STR))
                       ? ""
                       : DIR_SEPARATOR_STR,
                       finfo->d_name);
      ret = callback (callback_cls, name);
      if (GNUNET_OK != ret)
      {
        closedir (dinfo);
        GNUNET_free (name);
        GNUNET_free (dname);
        if (GNUNET_NO == ret)
          return count;
        return GNUNET_SYSERR;
      }
    }
    count++;
  }
  closedir (dinfo);
  GNUNET_free (name);
  GNUNET_free (dname);
  return count;
}


/**
 * Function that removes the given directory by calling
 * #GNUNET_DISK_directory_remove().
 *
 * @param unused not used
 * @param fn directory to remove
 * @return #GNUNET_OK
 */
static int
remove_helper (void *unused, const char *fn)
{
  (void) unused;
  (void) GNUNET_DISK_directory_remove (fn);
  return GNUNET_OK;
}


/**
 * Remove all files in a directory (rm -r). Call with
 * caution.
 *
 * @param filename the file to remove
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_DISK_directory_remove (const char *filename)
{
  struct stat istat;

  if (NULL == filename)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (0 != lstat (filename, &istat))
    return GNUNET_NO; /* file may not exist... */
  (void) chmod (filename, S_IWUSR | S_IRUSR | S_IXUSR);
  if (0 == unlink (filename))
    return GNUNET_OK;
  if ((errno != EISDIR) &&
      /* EISDIR is not sufficient in all cases, e.g.
      * sticky /tmp directory may result in EPERM on BSD.
      * So we also explicitly check "isDirectory" */
      (GNUNET_YES != GNUNET_DISK_directory_test (filename, GNUNET_YES)))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "rmdir", filename);
    return GNUNET_SYSERR;
  }
  if (GNUNET_SYSERR ==
      GNUNET_DISK_directory_scan (filename, &remove_helper, NULL))
    return GNUNET_SYSERR;
  if (0 != rmdir (filename))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "rmdir", filename);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Copy a file.
 *
 * @param src file to copy
 * @param dst destination file name
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_DISK_file_copy (const char *src, const char *dst)
{
  char *buf;
  uint64_t pos;
  uint64_t size;
  size_t len;
  ssize_t sret;
  struct GNUNET_DISK_FileHandle *in;
  struct GNUNET_DISK_FileHandle *out;

  if (GNUNET_OK != GNUNET_DISK_file_size (src, &size, GNUNET_YES, GNUNET_YES))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "stat", src);
    return GNUNET_SYSERR;
  }
  pos = 0;
  in =
    GNUNET_DISK_file_open (src, GNUNET_DISK_OPEN_READ, GNUNET_DISK_PERM_NONE);
  if (! in)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", src);
    return GNUNET_SYSERR;
  }
  out =
    GNUNET_DISK_file_open (dst,
                           GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE
                           | GNUNET_DISK_OPEN_FAILIFEXISTS,
                           GNUNET_DISK_PERM_USER_READ
                           | GNUNET_DISK_PERM_USER_WRITE
                           | GNUNET_DISK_PERM_GROUP_READ
                           | GNUNET_DISK_PERM_GROUP_WRITE);
  if (! out)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", dst);
    GNUNET_DISK_file_close (in);
    return GNUNET_SYSERR;
  }
  buf = GNUNET_malloc (COPY_BLK_SIZE);
  while (pos < size)
  {
    len = COPY_BLK_SIZE;
    if (len > size - pos)
      len = size - pos;
    sret = GNUNET_DISK_file_read (in, buf, len);
    if ((sret < 0) || (len != (size_t) sret))
      goto FAIL;
    sret = GNUNET_DISK_file_write (out, buf, len);
    if ((sret < 0) || (len != (size_t) sret))
      goto FAIL;
    pos += len;
  }
  GNUNET_free (buf);
  GNUNET_DISK_file_close (in);
  GNUNET_DISK_file_close (out);
  return GNUNET_OK;
FAIL:
  GNUNET_free (buf);
  GNUNET_DISK_file_close (in);
  GNUNET_DISK_file_close (out);
  return GNUNET_SYSERR;
}


/**
 * @brief Removes special characters as ':' from a filename.
 * @param fn the filename to canonicalize
 */
void
GNUNET_DISK_filename_canonicalize (char *fn)
{
  char *idx;
  char c;

  for (idx = fn; *idx; idx++)
  {
    c = *idx;

    if ((c == '/') || (c == '\\') || (c == ':') || (c == '*') || (c == '?') ||
        (c ==
         '"')
        ||
        (c == '<') || (c == '>') || (c == '|') )
    {
      *idx = '_';
    }
  }
}


/**
 * @brief Change owner of a file
 *
 * @param filename name of file to change the owner of
 * @param user name of the new owner
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
GNUNET_DISK_file_change_owner (const char *filename, const char *user)
{
  struct passwd *pws;

  pws = getpwnam (user);
  if (NULL == pws)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Cannot obtain information about user `%s': %s\n"),
         user,
         strerror (errno));
    return GNUNET_SYSERR;
  }
  if (0 != chown (filename, pws->pw_uid, pws->pw_gid))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "chown", filename);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Lock a part of a file
 *
 * @param fh file handle
 * @param lock_start absolute position from where to lock
 * @param lock_end absolute position until where to lock
 * @param excl #GNUNET_YES for an exclusive lock
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_DISK_file_lock (struct GNUNET_DISK_FileHandle *fh,
                       off_t lock_start,
                       off_t lock_end,
                       int excl)
{
  if (fh == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

  struct flock fl;

  memset (&fl, 0, sizeof(struct flock));
  fl.l_type = excl ? F_WRLCK : F_RDLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = lock_start;
  fl.l_len = lock_end;

  return fcntl (fh->fd, F_SETLK, &fl) != 0 ? GNUNET_SYSERR : GNUNET_OK;
}


/**
 * Unlock a part of a file
 *
 * @param fh file handle
 * @param unlock_start absolute position from where to unlock
 * @param unlock_end absolute position until where to unlock
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_DISK_file_unlock (struct GNUNET_DISK_FileHandle *fh,
                         off_t unlock_start,
                         off_t unlock_end)
{
  if (fh == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

  struct flock fl;

  memset (&fl, 0, sizeof(struct flock));
  fl.l_type = F_UNLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = unlock_start;
  fl.l_len = unlock_end;

  return fcntl (fh->fd, F_SETLK, &fl) != 0 ? GNUNET_SYSERR : GNUNET_OK;
}


/**
 * Open a file.  Note that the access permissions will only be
 * used if a new file is created and if the underlying operating
 * system supports the given permissions.
 *
 * @param fn file name to be opened
 * @param flags opening flags, a combination of GNUNET_DISK_OPEN_xxx bit flags
 * @param perm permissions for the newly created file, use
 *             #GNUNET_DISK_PERM_NONE if a file could not be created by this
 *             call (because of flags)
 * @return IO handle on success, NULL on error
 */
struct GNUNET_DISK_FileHandle *
GNUNET_DISK_file_open (const char *fn,
                       enum GNUNET_DISK_OpenFlags flags,
                       enum GNUNET_DISK_AccessPermissions perm)
{
  char *expfn;
  struct GNUNET_DISK_FileHandle *ret;

  int oflags;
  int mode;
  int fd;

  expfn = GNUNET_STRINGS_filename_expand (fn);
  if (NULL == expfn)
    return NULL;

  mode = 0;
  if (GNUNET_DISK_OPEN_READWRITE == (flags & GNUNET_DISK_OPEN_READWRITE))
    oflags = O_RDWR; /* note: O_RDWR is NOT always O_RDONLY | O_WRONLY */
  else if (flags & GNUNET_DISK_OPEN_READ)
    oflags = O_RDONLY;
  else if (flags & GNUNET_DISK_OPEN_WRITE)
    oflags = O_WRONLY;
  else
  {
    GNUNET_break (0);
    GNUNET_free (expfn);
    return NULL;
  }
  if (flags & GNUNET_DISK_OPEN_FAILIFEXISTS)
    oflags |= (O_CREAT | O_EXCL);
  if (flags & GNUNET_DISK_OPEN_TRUNCATE)
    oflags |= O_TRUNC;
  if (flags & GNUNET_DISK_OPEN_APPEND)
    oflags |= O_APPEND;
  if (GNUNET_NO == GNUNET_DISK_file_test (fn))
  {
    if (flags & GNUNET_DISK_OPEN_CREATE)
    {
      (void) GNUNET_DISK_directory_create_for_file (expfn);
      oflags |= O_CREAT;
      mode = translate_unix_perms (perm);
    }
  }

  fd = open (expfn,
             oflags
#if O_CLOEXEC
             | O_CLOEXEC
#endif
             | O_LARGEFILE,
             mode);
  if (fd == -1)
  {
    if (0 == (flags & GNUNET_DISK_OPEN_FAILIFEXISTS))
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "open", expfn);
    else
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_DEBUG, "open", expfn);
    GNUNET_free (expfn);
    return NULL;
  }

  ret = GNUNET_new (struct GNUNET_DISK_FileHandle);

  ret->fd = fd;

  GNUNET_free (expfn);
  return ret;
}


/**
 * Close an open file.
 *
 * @param h file handle
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_DISK_file_close (struct GNUNET_DISK_FileHandle *h)
{
  int ret;

  if (h == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

  ret = GNUNET_OK;

  if (close (h->fd) != 0)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "close");
    ret = GNUNET_SYSERR;
  }

  GNUNET_free (h);
  return ret;
}


/**
 * Get a handle from a native integer FD.
 *
 * @param fno native integer file descriptor
 * @return file handle corresponding to the descriptor, NULL on error
 */
struct GNUNET_DISK_FileHandle *
GNUNET_DISK_get_handle_from_int_fd (int fno)
{
  struct GNUNET_DISK_FileHandle *fh;

  if ((((off_t) -1) == lseek (fno, 0, SEEK_CUR)) && (EBADF == errno))
    return NULL; /* invalid FD */

  fh = GNUNET_new (struct GNUNET_DISK_FileHandle);

  fh->fd = fno;

  return fh;
}


/**
 * Get a handle from a native streaming FD.
 *
 * @param fd native streaming file descriptor
 * @return file handle corresponding to the descriptor
 */
struct GNUNET_DISK_FileHandle *
GNUNET_DISK_get_handle_from_native (FILE *fd)
{
  int fno;

  fno = fileno (fd);
  if (-1 == fno)
    return NULL;

  return GNUNET_DISK_get_handle_from_int_fd (fno);
}


/**
 * Handle for a memory-mapping operation.
 */
struct GNUNET_DISK_MapHandle
{
  /**
   * Address where the map is in memory.
   */
  void *addr;

  /**
   * Number of bytes mapped.
   */
  size_t len;
};


#ifndef MAP_FAILED
#define MAP_FAILED ((void *) -1)
#endif

/**
 * Map a file into memory
 *
 * @param h open file handle
 * @param m handle to the new mapping
 * @param access access specification, GNUNET_DISK_MAP_TYPE_xxx
 * @param len size of the mapping
 * @return pointer to the mapped memory region, NULL on failure
 */
void *
GNUNET_DISK_file_map (const struct GNUNET_DISK_FileHandle *h,
                      struct GNUNET_DISK_MapHandle **m,
                      enum GNUNET_DISK_MapType access,
                      size_t len)
{
  if (NULL == h)
  {
    errno = EINVAL;
    return NULL;
  }

  int prot;

  prot = 0;
  if (access & GNUNET_DISK_MAP_TYPE_READ)
    prot = PROT_READ;
  if (access & GNUNET_DISK_MAP_TYPE_WRITE)
    prot |= PROT_WRITE;
  *m = GNUNET_new (struct GNUNET_DISK_MapHandle);
  (*m)->addr = mmap (NULL, len, prot, MAP_SHARED, h->fd, 0);
  GNUNET_assert (NULL != (*m)->addr);
  if (MAP_FAILED == (*m)->addr)
  {
    GNUNET_free (*m);
    return NULL;
  }
  (*m)->len = len;
  return (*m)->addr;
}


/**
 * Unmap a file
 * @param h mapping handle
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_DISK_file_unmap (struct GNUNET_DISK_MapHandle *h)
{
  int ret;

  if (h == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

  ret = munmap (h->addr, h->len) != -1 ? GNUNET_OK : GNUNET_SYSERR;

  GNUNET_free (h);
  return ret;
}


/**
 * Write file changes to disk
 * @param h handle to an open file
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_DISK_file_sync (const struct GNUNET_DISK_FileHandle *h)
{
  if (h == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

#if ! defined(__linux__) || ! defined(GNU)
  return fsync (h->fd) == -1 ? GNUNET_SYSERR : GNUNET_OK;
#else
  return fdatasync (h->fd) == -1 ? GNUNET_SYSERR : GNUNET_OK;
#endif
}


/**
 * Creates an interprocess channel
 *
 * @param blocking_read creates an asynchronous pipe for reading if set to GNUNET_NO
 * @param blocking_write creates an asynchronous pipe for writing if set to GNUNET_NO
 * @param inherit_read inherit the parent processes stdin (only for windows)
 * @param inherit_write inherit the parent processes stdout (only for windows)
 * @return handle to the new pipe, NULL on error
 */
struct GNUNET_DISK_PipeHandle *
GNUNET_DISK_pipe (int blocking_read,
                  int blocking_write,
                  int inherit_read,
                  int inherit_write)
{
  int fd[2];
  int ret;
  int eno;

  (void) inherit_read;
  (void) inherit_write;
  ret = pipe (fd);
  if (ret == -1)
  {
    eno = errno;
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "pipe");
    errno = eno;
    return NULL;
  }
  return GNUNET_DISK_pipe_from_fd (blocking_read, blocking_write, fd);
}


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
GNUNET_DISK_pipe_from_fd (int blocking_read, int blocking_write, int fd[2])
{
  struct GNUNET_DISK_PipeHandle *p;

  p = GNUNET_new (struct GNUNET_DISK_PipeHandle);

  int ret;
  int flags;
  int eno = 0; /* make gcc happy */

  ret = 0;
  if (fd[0] >= 0)
  {
    p->fd[0] = GNUNET_new (struct GNUNET_DISK_FileHandle);
    p->fd[0]->fd = fd[0];
    if (! blocking_read)
    {
      flags = fcntl (fd[0], F_GETFL);
      flags |= O_NONBLOCK;
      if (0 > fcntl (fd[0], F_SETFL, flags))
      {
        ret = -1;
        eno = errno;
      }
    }
    flags = fcntl (fd[0], F_GETFD);
    flags |= FD_CLOEXEC;
    if (0 > fcntl (fd[0], F_SETFD, flags))
    {
      ret = -1;
      eno = errno;
    }
  }

  if (fd[1] >= 0)
  {
    p->fd[1] = GNUNET_new (struct GNUNET_DISK_FileHandle);
    p->fd[1]->fd = fd[1];
    if (! blocking_write)
    {
      flags = fcntl (fd[1], F_GETFL);
      flags |= O_NONBLOCK;
      if (0 > fcntl (fd[1], F_SETFL, flags))
      {
        ret = -1;
        eno = errno;
      }
    }
    flags = fcntl (fd[1], F_GETFD);
    flags |= FD_CLOEXEC;
    if (0 > fcntl (fd[1], F_SETFD, flags))
    {
      ret = -1;
      eno = errno;
    }
  }
  if (ret == -1)
  {
    errno = eno;
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "fcntl");
    if (p->fd[0]->fd >= 0)
      GNUNET_break (0 == close (p->fd[0]->fd));
    if (p->fd[1]->fd >= 0)
      GNUNET_break (0 == close (p->fd[1]->fd));
    GNUNET_free_non_null (p->fd[0]);
    GNUNET_free_non_null (p->fd[1]);
    GNUNET_free (p);
    errno = eno;
    return NULL;
  }

  return p;
}


/**
 * Closes an interprocess channel
 *
 * @param p pipe to close
 * @param end which end of the pipe to close
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_DISK_pipe_close_end (struct GNUNET_DISK_PipeHandle *p,
                            enum GNUNET_DISK_PipeEnd end)
{
  int ret = GNUNET_OK;

  if (end == GNUNET_DISK_PIPE_END_READ)
  {
    if (p->fd[0])
    {
      ret = GNUNET_DISK_file_close (p->fd[0]);
      p->fd[0] = NULL;
    }
  }
  else if (end == GNUNET_DISK_PIPE_END_WRITE)
  {
    if (p->fd[1])
    {
      ret = GNUNET_DISK_file_close (p->fd[1]);
      p->fd[1] = NULL;
    }
  }

  return ret;
}


/**
 * Detaches one of the ends from the pipe.
 * Detached end is a fully-functional FileHandle, it will
 * not be affected by anything you do with the pipe afterwards.
 * Each end of a pipe can only be detched from it once (i.e.
 * it is not duplicated).
 *
 * @param p pipe to detach an end from
 * @param end which end of the pipe to detach
 * @return Detached end on success, NULL on failure
 * (or if that end is not present or is closed).
 */
struct GNUNET_DISK_FileHandle *
GNUNET_DISK_pipe_detach_end (struct GNUNET_DISK_PipeHandle *p,
                             enum GNUNET_DISK_PipeEnd end)
{
  struct GNUNET_DISK_FileHandle *ret = NULL;

  if (end == GNUNET_DISK_PIPE_END_READ)
  {
    if (p->fd[0])
    {
      ret = p->fd[0];
      p->fd[0] = NULL;
    }
  }
  else if (end == GNUNET_DISK_PIPE_END_WRITE)
  {
    if (p->fd[1])
    {
      ret = p->fd[1];
      p->fd[1] = NULL;
    }
  }

  return ret;
}


/**
 * Closes an interprocess channel
 *
 * @param p pipe to close
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_DISK_pipe_close (struct GNUNET_DISK_PipeHandle *p)
{
  int ret = GNUNET_OK;

  int read_end_close;
  int write_end_close;
  int read_end_close_errno;
  int write_end_close_errno;

  read_end_close = GNUNET_DISK_pipe_close_end (p, GNUNET_DISK_PIPE_END_READ);
  read_end_close_errno = errno;
  write_end_close = GNUNET_DISK_pipe_close_end (p, GNUNET_DISK_PIPE_END_WRITE);
  write_end_close_errno = errno;
  GNUNET_free (p);

  if (GNUNET_OK != read_end_close)
  {
    errno = read_end_close_errno;
    ret = read_end_close;
  }
  else if (GNUNET_OK != write_end_close)
  {
    errno = write_end_close_errno;
    ret = write_end_close;
  }

  return ret;
}


/**
 * Get the handle to a particular pipe end
 *
 * @param p pipe
 * @param n end to access
 * @return handle for the respective end
 */
const struct GNUNET_DISK_FileHandle *
GNUNET_DISK_pipe_handle (const struct GNUNET_DISK_PipeHandle *p,
                         enum GNUNET_DISK_PipeEnd n)
{
  switch (n)
  {
  case GNUNET_DISK_PIPE_END_READ:
  case GNUNET_DISK_PIPE_END_WRITE:
    return p->fd[n];

  default:
    GNUNET_break (0);
    return NULL;
  }
}


/**
 * Retrieve OS file handle
 * @internal
 * @param fh GNUnet file descriptor
 * @param dst destination buffer
 * @param dst_len length of dst
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_DISK_internal_file_handle_ (const struct GNUNET_DISK_FileHandle *fh,
                                   void *dst,
                                   size_t dst_len)
{
  if (NULL == fh)
    return GNUNET_SYSERR;

  if (dst_len < sizeof(int))
    return GNUNET_SYSERR;
  *((int *) dst) = fh->fd;

  return GNUNET_OK;
}


/**
 * Helper function for #GNUNET_DISK_purge_cfg_dir.
 *
 * @param cls a `const char *` with the option to purge
 * @param cfg our configuration
 * @return #GNUNET_OK on success
 */
static int
purge_cfg_dir (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  const char *option = cls;
  char *tmpname;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "PATHS", option, &tmpname))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "PATHS", option);
    return GNUNET_NO;
  }
  if (GNUNET_SYSERR == GNUNET_DISK_directory_remove (tmpname))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "remove", tmpname);
    GNUNET_free (tmpname);
    return GNUNET_OK;
  }
  GNUNET_free (tmpname);
  return GNUNET_OK;
}


/**
 * Remove the directory given under @a option in
 * section [PATHS] in configuration under @a cfg_filename
 *
 * @param cfg_filename configuration file to parse
 * @param option option with the dir name to purge
 */
void
GNUNET_DISK_purge_cfg_dir (const char *cfg_filename, const char *option)
{
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONFIGURATION_parse_and_run (cfg_filename,
                                                    &purge_cfg_dir,
                                                    (void *) option));
}


/* end of disk.c */
