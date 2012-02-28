/*
     This file is part of GNUnet.
     (C) 2001--2012 Christian Grothoff (and other contributing authors)

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
 * @file util/disk.c
 * @brief disk IO convenience methods
 * @author Christian Grothoff
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_directories.h"
#include "gnunet_disk_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_strings_lib.h"
#include "gnunet_crypto_lib.h"
#include "disk.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

#define DEBUG_NPIPE GNUNET_EXTRA_LOGGING

#define DEBUG_PIPE GNUNET_EXTRA_LOGGING

/**
 * Block size for IO for copying files.
 */
#define COPY_BLK_SIZE 65536



#if defined(LINUX) || defined(CYGWIN)
#include <sys/vfs.h>
#else
#if defined(SOMEBSD) || defined(DARWIN)
#include <sys/param.h>
#include <sys/mount.h>
#else
#ifdef SOLARIS
#include <sys/types.h>
#include <sys/statvfs.h>
#else
#ifdef MINGW
#ifndef PIPE_BUF
#define PIPE_BUF        512
ULONG PipeSerialNumber;
#endif
#define  	_IFMT		0170000 /* type of file */
#define  	_IFLNK		0120000 /* symbolic link */
#define  S_ISLNK(m)	(((m)&_IFMT) == _IFLNK)
#else
#error PORT-ME: need to port statfs (how much space is left on the drive?)
#endif
#endif
#endif
#endif

#if !defined(SOMEBSD) && !defined(DARWIN) && !defined(WINDOWS)
#include <wordexp.h>
#endif
#if LINUX
#include <sys/statvfs.h>
#endif


/**
 * Handle used to manage a pipe.
 */
struct GNUNET_DISK_PipeHandle
{
  /**
   * File descriptors for the pipe.
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
};


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
 * @param cls closure of type "struct GetFileSizeData"
 * @param fn current filename we are looking at
 * @return GNUNET_SYSERR on serious errors, otherwise GNUNET_OK
 */
static int
getSizeRec (void *cls, const char *fn)
{
  struct GetFileSizeData *gfsd = cls;

#ifdef HAVE_STAT64
  struct stat64 buf;
#else
  struct stat buf;
#endif

#ifdef HAVE_STAT64
  if (0 != STAT64 (fn, &buf))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "stat64", fn);
    return GNUNET_SYSERR;
  }
#else
  if (0 != STAT (fn, &buf))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "stat", fn);
    return GNUNET_SYSERR;
  }
#endif
  if ((!S_ISLNK (buf.st_mode)) || (gfsd->include_sym_links == GNUNET_YES))
    gfsd->total += buf.st_size;
  if ((S_ISDIR (buf.st_mode)) && (0 == ACCESS (fn, X_OK)) &&
      ((!S_ISLNK (buf.st_mode)) || (gfsd->include_sym_links == GNUNET_YES)))
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
 * @return GNUNET_YES if invalid, GNUNET_NO if valid
 */
int
GNUNET_DISK_handle_invalid (const struct GNUNET_DISK_FileHandle *h)
{
#ifdef MINGW
  return ((!h) || (h->h == INVALID_HANDLE_VALUE)) ? GNUNET_YES : GNUNET_NO;
#else
  return ((!h) || (h->fd == -1)) ? GNUNET_YES : GNUNET_NO;
#endif
}

/**
 * Get the size of an open file.
 *
 * @param fh open file handle
 * @param size where to write size of the file
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DISK_file_handle_size (struct GNUNET_DISK_FileHandle *fh,
			      OFF_T *size)
{
#if WINDOWS
  BOOL b;
  LARGE_INTEGER li;
  b = GetFileSizeEx (fh->h, &li);
  if (!b)
  {
    SetErrnoFromWinError (GetLastError ());
    return GNUNET_SYSERR;
  }
  *size = (OFF_T) li.QuadPart;
#else
  struct stat sbuf;

  if (0 != FSTAT (fh->fd, &sbuf))
    return GNUNET_SYSERR;
  *size = sbuf.st_size;
#endif
  return GNUNET_OK;
}


/**
 * Move the read/write pointer in a file
 *
 * @param h handle of an open file
 * @param offset position to move to
 * @param whence specification to which position the offset parameter relates to
 * @return the new position on success, GNUNET_SYSERR otherwise
 */
OFF_T
GNUNET_DISK_file_seek (const struct GNUNET_DISK_FileHandle * h, OFF_T offset,
                       enum GNUNET_DISK_Seek whence)
{
  if (h == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

#ifdef MINGW
  LARGE_INTEGER li, new_pos;
  BOOL b;

  static DWORD t[] = {[GNUNET_DISK_SEEK_SET] = FILE_BEGIN,
    [GNUNET_DISK_SEEK_CUR] = FILE_CURRENT,[GNUNET_DISK_SEEK_END] = FILE_END
  };
  li.QuadPart = offset;

  b = SetFilePointerEx (h->h, li, &new_pos, t[whence]);
  if (b == 0)
  {
    SetErrnoFromWinError (GetLastError ());
    return GNUNET_SYSERR;
  }
  return (OFF_T) new_pos.QuadPart;
#else
  static int t[] = {[GNUNET_DISK_SEEK_SET] = SEEK_SET,
    [GNUNET_DISK_SEEK_CUR] = SEEK_CUR,[GNUNET_DISK_SEEK_END] = SEEK_END
  };

  return lseek (h->fd, offset, t[whence]);
#endif
}


/**
 * Get the size of the file (or directory) of the given file (in
 * bytes).
 *
 * @param filename name of the file or directory
 * @param size set to the size of the file (or,
 *             in the case of directories, the sum
 *             of all sizes of files in the directory)
 * @param includeSymLinks should symbolic links be
 *        included?
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
GNUNET_DISK_file_size (const char *filename, uint64_t * size,
                       int includeSymLinks)
{
  struct GetFileSizeData gfsd;
  int ret;

  GNUNET_assert (size != NULL);
  gfsd.total = 0;
  gfsd.include_sym_links = includeSymLinks;
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
 * @return GNUNET_OK on success
 */
int
GNUNET_DISK_file_get_identifiers (const char *filename, uint64_t * dev,
                                  uint64_t * ino)
{
#if LINUX
  struct stat sbuf;
  struct statvfs fbuf;

  if ((0 == stat (filename, &sbuf)) && (0 == statvfs (filename, &fbuf)))
  {
    *dev = (uint64_t) fbuf.f_fsid;
    *ino = (uint64_t) sbuf.st_ino;
    return GNUNET_OK;
  }
#elif SOMEBSD
  struct stat sbuf;
  struct statfs fbuf;

  if ((0 == stat (filename, &sbuf)) && (0 == statfs (filename, &fbuf)))
  {
    *dev = ((uint64_t) fbuf.f_fsid.val[0]) << 32 ||
        ((uint64_t) fbuf.f_fsid.val[1]);
    *ino = (uint64_t) sbuf.st_ino;
    return GNUNET_OK;
  }
#elif WINDOWS
  // FIXME NILS: test this
  struct GNUNET_DISK_FileHandle *fh;
  BY_HANDLE_FILE_INFORMATION info;
  int succ;

  fh = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_READ, 0);
  if (fh == NULL)
    return GNUNET_SYSERR;
  succ = GetFileInformationByHandle (fh->h, &info);
  GNUNET_DISK_file_close (fh);
  if (succ)
  {
    *dev = info.dwVolumeSerialNumber;
    *ino = ((((uint64_t) info.nFileIndexHigh) << (sizeof (DWORD) * 8)) | info.nFileIndexLow);
    return GNUNET_OK;
  }
  else
    return GNUNET_SYSERR;

#endif
  return GNUNET_SYSERR;
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
  const char *tmpdir;
  int fd;
  char *tmpl;
  char *fn;

  if ((t[0] != '/') && (t[0] != '\\')
#if WINDOWS
      && !(isalpha ((int) t[0]) && (t[0] != '\0') && (t[1] == ':'))
#endif
      )
  {
    /* FIXME: This uses system codepage on W32, not UTF-8 */
    tmpdir = getenv ("TMPDIR");
    tmpdir = tmpdir ? tmpdir : "/tmp";
    GNUNET_asprintf (&tmpl, "%s/%s%s", tmpdir, t, "XXXXXX");
  }
  else
  {
    GNUNET_asprintf (&tmpl, "%s%s", t, "XXXXXX");
  }
#ifdef MINGW
  fn = (char *) GNUNET_malloc (MAX_PATH + 1);
  if (ERROR_SUCCESS != plibc_conv_to_win_path (tmpl, fn))
  {
    GNUNET_free (fn);
    GNUNET_free (tmpl);
    return NULL;
  }
  GNUNET_free (tmpl);
#else
  fn = tmpl;
#endif
  /* FIXME: why is this not MKSTEMP()? This function is implemented in plibc.
   * CG: really? If I put MKSTEMP here, I get a compilation error...
   * It will assume that fn is UTF-8-encoded, if compiled with UTF-8 support.
   */
  fd = mkstemp (fn);
  if (fd == -1)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "mkstemp", fn);
    GNUNET_free (fn);
    return NULL;
  }
  if (0 != CLOSE (fd))
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "close", fn);
  return fn;
}


/**
 * Get the number of blocks that are left on the partition that
 * contains the given file (for normal users).
 *
 * @param part a file on the partition to check
 * @return -1 on errors, otherwise the number of free blocks
 */
long
GNUNET_DISK_get_blocks_available (const char *part)
{
#ifdef SOLARIS
  struct statvfs buf;

  if (0 != statvfs (part, &buf))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "statfs", part);
    return -1;
  }
  return buf.f_bavail;
#elif MINGW
  DWORD dwDummy;
  DWORD dwBlocks;
  wchar_t szDrive[4];
  wchar_t wpath[MAX_PATH + 1];
  char *path;

  path = GNUNET_STRINGS_filename_expand (part);
  if (path == NULL)
    return -1;
  /* "part" was in UTF-8, and so is "path" */
  if (ERROR_SUCCESS != plibc_conv_to_win_pathwconv(path, wpath))
  {
    GNUNET_free (path);
    return -1;
  }
  GNUNET_free (path);
  wcsncpy (szDrive, wpath, 3);
  szDrive[3] = 0;
  if (!GetDiskFreeSpaceW (szDrive, &dwDummy, &dwDummy, &dwBlocks, &dwDummy))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, _("`%s' failed for drive `%S': %u\n"),
         "GetDiskFreeSpace", szDrive, GetLastError ());

    return -1;
  }
  return dwBlocks;
#else
  struct statfs s;

  if (0 != statfs (part, &s))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "statfs", part);
    return -1;
  }
  return s.f_bavail;
#endif
}


/**
 * Test if "fil" is a directory.
 * Will not print an error message if the directory
 * does not exist.  Will log errors if GNUNET_SYSERR is
 * returned (i.e., a file exists with the same name).
 *
 * @param fil filename to test
 * @return GNUNET_YES if yes, GNUNET_NO if not, GNUNET_SYSERR if it
 *   does not exist
 */
int
GNUNET_DISK_directory_test (const char *fil)
{
  struct stat filestat;
  int ret;

  ret = STAT (fil, &filestat);
  if (ret != 0)
  {
    if (errno != ENOENT)
    {
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "stat", fil);
      return GNUNET_SYSERR;
    }
    return GNUNET_NO;
  }
  if (!S_ISDIR (filestat.st_mode))
    return GNUNET_NO;
  if (ACCESS (fil, R_OK | X_OK) < 0)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "access", fil);
    return GNUNET_SYSERR;
  }
  return GNUNET_YES;
}


/**
 * Check that fil corresponds to a filename
 * (of a file that exists and that is not a directory).
 *
 * @param fil filename to check
 * @return GNUNET_YES if yes, GNUNET_NO if not a file, GNUNET_SYSERR if something
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

  ret = STAT (rdir, &filestat);
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
  if (!S_ISREG (filestat.st_mode))
  {
    GNUNET_free (rdir);
    return GNUNET_NO;
  }
  if (ACCESS (rdir, R_OK) < 0)
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
 * @param dir the directory to create
 * @returns GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_DISK_directory_create (const char *dir)
{
  char *rdir;
  int len;
  int pos;
  int ret = GNUNET_OK;

  rdir = GNUNET_STRINGS_filename_expand (dir);
  if (rdir == NULL)
    return GNUNET_SYSERR;

  len = strlen (rdir);
#ifndef MINGW
  pos = 1;                      /* skip heading '/' */
#else
  /* Local or Network path? */
  if (strncmp (rdir, "\\\\", 2) == 0)
  {
    pos = 2;
    while (rdir[pos])
    {
      if (rdir[pos] == '\\')
      {
        pos++;
        break;
      }
      pos++;
    }
  }
  else
  {
    pos = 3;                    /* strlen("C:\\") */
  }
#endif
  while (pos <= len)
  {
    if ((rdir[pos] == DIR_SEPARATOR) || (pos == len))
    {
      rdir[pos] = '\0';
      ret = GNUNET_DISK_directory_test (rdir);
      if (ret == GNUNET_SYSERR)
      {
        GNUNET_free (rdir);
        return GNUNET_SYSERR;
      }
      if (ret == GNUNET_NO)
      {
#ifndef MINGW
        ret = mkdir (rdir, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);        /* 755 */
#else
        wchar_t wrdir[MAX_PATH + 1];
        if (ERROR_SUCCESS == plibc_conv_to_win_pathwconv(rdir, wrdir))
          ret = !CreateDirectoryW (wrdir, NULL);
        else
          ret = 1;
#endif
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
 * Create the directory structure for storing
 * a file.
 *
 * @param filename name of a file in the directory
 * @returns GNUNET_OK on success,
 *          GNUNET_SYSERR on failure,
 *          GNUNET_NO if the directory
 *          exists but is not writeable for us
 */
int
GNUNET_DISK_directory_create_for_file (const char *filename)
{
  char *rdir;
  int len;
  int ret;

  rdir = GNUNET_STRINGS_filename_expand (filename);
  if (rdir == NULL)
    return GNUNET_SYSERR;
  len = strlen (rdir);
  while ((len > 0) && (rdir[len] != DIR_SEPARATOR))
    len--;
  rdir[len] = '\0';
  ret = GNUNET_DISK_directory_create (rdir);
  if ((ret == GNUNET_OK) && (0 != ACCESS (rdir, W_OK)))
    ret = GNUNET_NO;
  GNUNET_free (rdir);
  return ret;
}


/**
 * Read the contents of a binary file into a buffer.
 * @param h handle to an open file
 * @param result the buffer to write the result to
 * @param len the maximum number of bytes to read
 * @return the number of bytes read on success, GNUNET_SYSERR on failure
 */
ssize_t
GNUNET_DISK_file_read (const struct GNUNET_DISK_FileHandle * h, void *result,
                       size_t len)
{
  if (h == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

#ifdef MINGW
  DWORD bytesRead;

  if (h->type != GNUNET_PIPE)
  {
    if (!ReadFile (h->h, result, len, &bytesRead, NULL))
    {
      SetErrnoFromWinError (GetLastError ());
      return GNUNET_SYSERR;
    }
  }
  else
  {
#if DEBUG_PIPE
    LOG (GNUNET_ERROR_TYPE_DEBUG, "It is a pipe trying to read\n");
#endif
    if (!ReadFile (h->h, result, len, &bytesRead, h->oOverlapRead))
    {
      if (GetLastError () != ERROR_IO_PENDING)
      {
#if DEBUG_PIPE
        LOG (GNUNET_ERROR_TYPE_DEBUG, "Error reading from pipe: %u\n", GetLastError ());
#endif
        SetErrnoFromWinError (GetLastError ());
        return GNUNET_SYSERR;
      }
#if DEBUG_PIPE
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Will get overlapped result\n");
#endif
      GetOverlappedResult (h->h, h->oOverlapRead, &bytesRead, TRUE);
    }
#if DEBUG_PIPE
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Read %u bytes\n", bytesRead);
#endif
  }
  return bytesRead;
#else
  return read (h->fd, result, len);
#endif
}


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
    void *result, size_t len)
{
  if (h == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

#ifdef MINGW
  DWORD bytesRead;

  if (h->type != GNUNET_PIPE)
  {
    if (!ReadFile (h->h, result, len, &bytesRead, NULL))
    {
      SetErrnoFromWinError (GetLastError ());
      return GNUNET_SYSERR;
    }
  }
  else
  {
#if DEBUG_PIPE
    LOG (GNUNET_ERROR_TYPE_DEBUG, "It is a pipe, trying to read\n");
#endif
    if (!ReadFile (h->h, result, len, &bytesRead, h->oOverlapRead))
    {
      if (GetLastError () != ERROR_IO_PENDING)
      {
#if DEBUG_PIPE
        LOG (GNUNET_ERROR_TYPE_DEBUG, "Error reading from pipe: %u\n", GetLastError ());
#endif
        SetErrnoFromWinError (GetLastError ());
        return GNUNET_SYSERR;
      }
      else
      {
#if DEBUG_PIPE
        LOG (GNUNET_ERROR_TYPE_DEBUG,
            "ReadFile() queued a read, cancelling\n");
#endif
        CancelIo (h->h);
        errno = EAGAIN;
        return GNUNET_SYSERR;
      }
    }
#if DEBUG_PIPE
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Read %u bytes\n", bytesRead);
#endif
  }
  return bytesRead;
#else
  int flags;
  ssize_t ret;

  /* set to non-blocking, read, then set back */
  flags = fcntl (h->fd, F_GETFL);
  if (0 == (flags & O_NONBLOCK))
    fcntl (h->fd, F_SETFL, flags | O_NONBLOCK);
  ret = read (h->fd, result, len);
  if (0 == (flags & O_NONBLOCK))
    fcntl (h->fd, F_SETFL, flags);
  return ret;
#endif
}


/**
 * Read the contents of a binary file into a buffer.
 *
 * @param fn file name
 * @param result the buffer to write the result to
 * @param len the maximum number of bytes to read
 * @return number of bytes read, GNUNET_SYSERR on failure
 */
ssize_t
GNUNET_DISK_fn_read (const char *fn, void *result, size_t len)
{
  struct GNUNET_DISK_FileHandle *fh;
  ssize_t ret;

  fh = GNUNET_DISK_file_open (fn, GNUNET_DISK_OPEN_READ, GNUNET_DISK_PERM_NONE);
  if (!fh)
    return GNUNET_SYSERR;
  ret = GNUNET_DISK_file_read (fh, result, len);
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));

  return ret;
}


/**
 * Write a buffer to a file.
 * @param h handle to open file
 * @param buffer the data to write
 * @param n number of bytes to write
 * @return number of bytes written on success, GNUNET_SYSERR on error
 */
ssize_t
GNUNET_DISK_file_write (const struct GNUNET_DISK_FileHandle * h,
                        const void *buffer, size_t n)
{
  if (h == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

#ifdef MINGW
  DWORD bytesWritten;

  if (h->type != GNUNET_PIPE)
  {
    if (!WriteFile (h->h, buffer, n, &bytesWritten, NULL))
    {
      SetErrnoFromWinError (GetLastError ());
      return GNUNET_SYSERR;
    }
  }
  else
  {
#if DEBUG_PIPE
    LOG (GNUNET_ERROR_TYPE_DEBUG, "It is a pipe trying to write %u bytes\n", n);
#endif
    if (!WriteFile (h->h, buffer, n, &bytesWritten, h->oOverlapWrite))
    {
      if (GetLastError () != ERROR_IO_PENDING)
      {
        SetErrnoFromWinError (GetLastError ());
#if DEBUG_PIPE
        LOG (GNUNET_ERROR_TYPE_DEBUG, "Error writing to pipe: %u\n",
            GetLastError ());
#endif
        return GNUNET_SYSERR;
      }
#if DEBUG_PIPE
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Will get overlapped result\n");
#endif
      if (!GetOverlappedResult (h->h, h->oOverlapWrite, &bytesWritten, TRUE))
      {
        SetErrnoFromWinError (GetLastError ());
#if DEBUG_PIPE
        LOG (GNUNET_ERROR_TYPE_DEBUG,
            "Error getting overlapped result while writing to pipe: %u\n",
            GetLastError ());
#endif
        return GNUNET_SYSERR;
      }
    }
    else
    {
      DWORD ovr;
      if (!GetOverlappedResult (h->h, h->oOverlapWrite, &ovr, TRUE))
      {
#if DEBUG_PIPE
        LOG (GNUNET_ERROR_TYPE_DEBUG,
            "Error getting control overlapped result while writing to pipe: %u\n",
            GetLastError ());
#endif
      }
      else
      {
#if DEBUG_PIPE
        LOG (GNUNET_ERROR_TYPE_DEBUG,
            "Wrote %u bytes (ovr says %u), picking the greatest\n",
            bytesWritten, ovr);
#endif
      }
    }
    if (bytesWritten == 0)
    {
      if (n > 0)
      {
#if DEBUG_PIPE
        LOG (GNUNET_ERROR_TYPE_DEBUG, "Wrote %u bytes, returning -1 with EAGAIN\n", bytesWritten);
#endif
        errno = EAGAIN;
        return GNUNET_SYSERR;
      }
    }
#if DEBUG_PIPE
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Wrote %u bytes\n", bytesWritten);
#endif
  }
  return bytesWritten;
#else
  return write (h->fd, buffer, n);
#endif
}


/**
 * Write a buffer to a file, blocking, if necessary.
 * @param h handle to open file
 * @param buffer the data to write
 * @param n number of bytes to write
 * @return number of bytes written on success, GNUNET_SYSERR on error
 */
ssize_t
GNUNET_DISK_file_write_blocking (const struct GNUNET_DISK_FileHandle * h,
    const void *buffer, size_t n)
{
  if (h == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

#ifdef MINGW
  DWORD bytesWritten;
  /* We do a non-overlapped write, which is as blocking as it gets */
#if DEBUG_PIPE
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Writing %u bytes\n", n);
#endif
  if (!WriteFile (h->h, buffer, n, &bytesWritten, NULL))
  {
    SetErrnoFromWinError (GetLastError ());
#if DEBUG_PIPE
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Error writing to pipe: %u\n",
        GetLastError ());
#endif
    return GNUNET_SYSERR;
  }
  if (bytesWritten == 0 && n > 0)
  {
#if DEBUG_PIPE
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Waiting for pipe to clean\n");
#endif
    WaitForSingleObject (h->h, INFINITE);
    if (!WriteFile (h->h, buffer, n, &bytesWritten, NULL))
    {
      SetErrnoFromWinError (GetLastError ());
#if DEBUG_PIPE
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Error writing to pipe: %u\n",
          GetLastError ());
#endif
      return GNUNET_SYSERR;
    }
  }
#if DEBUG_PIPE
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Wrote %u bytes\n", bytesWritten);
#endif
  return bytesWritten;
#else
  int flags;
  ssize_t ret;

  /* set to blocking, write, then set back */
  flags = fcntl (h->fd, F_GETFL);
  if (0 != (flags & O_NONBLOCK))
    fcntl (h->fd, F_SETFL, flags - O_NONBLOCK);
  ret = write (h->fd, buffer, n);
  if (0 == (flags & O_NONBLOCK))
    fcntl (h->fd, F_SETFL, flags);
  return ret;
#endif
}


/**
 * Write a buffer to a file.  If the file is longer than the
 * number of bytes that will be written, it will be truncated.
 *
 * @param fn file name
 * @param buffer the data to write
 * @param n number of bytes to write
 * @param mode file permissions
 * @return number of bytes written on success, GNUNET_SYSERR on error
 */
ssize_t
GNUNET_DISK_fn_write (const char *fn, const void *buffer, size_t n,
                      enum GNUNET_DISK_AccessPermissions mode)
{
  struct GNUNET_DISK_FileHandle *fh;
  ssize_t ret;

  fh = GNUNET_DISK_file_open (fn,
                              GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_TRUNCATE
                              | GNUNET_DISK_OPEN_CREATE, mode);
  if (!fh)
    return GNUNET_SYSERR;
  ret = GNUNET_DISK_file_write (fh, buffer, n);
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));
  return ret;
}


/**
 * Scan a directory for files.
 *
 * @param dirName the name of the directory
 * @param callback the method to call for each file,
 *        can be NULL, in that case, we only count
 * @param callback_cls closure for callback
 * @return the number of files found, GNUNET_SYSERR on error or
 *         ieration aborted by callback returning GNUNET_SYSERR
 */
int
GNUNET_DISK_directory_scan (const char *dirName,
                            GNUNET_FileNameCallback callback,
                            void *callback_cls)
{
  DIR *dinfo;
  struct dirent *finfo;
  struct stat istat;
  int count = 0;
  char *name;
  char *dname;
  unsigned int name_len;
  unsigned int n_size;

  GNUNET_assert (dirName != NULL);
  dname = GNUNET_STRINGS_filename_expand (dirName);
  if (dname == NULL)
    return GNUNET_SYSERR;
  while ((strlen (dname) > 0) && (dname[strlen (dname) - 1] == DIR_SEPARATOR))
    dname[strlen (dname) - 1] = '\0';
  if (0 != STAT (dname, &istat))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "stat", dname);
    GNUNET_free (dname);
    return GNUNET_SYSERR;
  }
  if (!S_ISDIR (istat.st_mode))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, _("Expected `%s' to be a directory!\n"),
         dirName);
    GNUNET_free (dname);
    return GNUNET_SYSERR;
  }
  errno = 0;
  dinfo = OPENDIR (dname);
  if ((errno == EACCES) || (dinfo == NULL))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "opendir", dname);
    if (dinfo != NULL)
      CLOSEDIR (dinfo);
    GNUNET_free (dname);
    return GNUNET_SYSERR;
  }
  name_len = 256;
  n_size = strlen (dname) + name_len + 2;
  name = GNUNET_malloc (n_size);
  while ((finfo = READDIR (dinfo)) != NULL)
  {
    if ((0 == strcmp (finfo->d_name, ".")) ||
        (0 == strcmp (finfo->d_name, "..")))
      continue;
    if (callback != NULL)
    {
      if (name_len < strlen (finfo->d_name))
      {
        GNUNET_free (name);
        name_len = strlen (finfo->d_name);
        n_size = strlen (dname) + name_len + 2;
        name = GNUNET_malloc (n_size);
      }
      /* dname can end in "/" only if dname == "/";
       * if dname does not end in "/", we need to add
       * a "/" (otherwise, we must not!) */
      GNUNET_snprintf (name, n_size, "%s%s%s", dname,
                       (strcmp (dname, DIR_SEPARATOR_STR) ==
                        0) ? "" : DIR_SEPARATOR_STR, finfo->d_name);
      if (GNUNET_OK != callback (callback_cls, name))
      {
        CLOSEDIR (dinfo);
        GNUNET_free (name);
        GNUNET_free (dname);
        return GNUNET_SYSERR;
      }
    }
    count++;
  }
  CLOSEDIR (dinfo);
  GNUNET_free (name);
  GNUNET_free (dname);
  return count;
}


/**
 * Opaque handle used for iterating over a directory.
 */
struct GNUNET_DISK_DirectoryIterator
{

  /**
   * Function to call on directory entries.
   */
  GNUNET_DISK_DirectoryIteratorCallback callback;

  /**
   * Closure for callback.
   */
  void *callback_cls;

  /**
   * Reference to directory.
   */
  DIR *directory;

  /**
   * Directory name.
   */
  char *dirname;

  /**
   * Next filename to process.
   */
  char *next_name;

  /**
   * Our priority.
   */
  enum GNUNET_SCHEDULER_Priority priority;

};


/**
 * Task used by the directory iterator.
 */
static void
directory_iterator_task (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DISK_DirectoryIterator *iter = cls;
  char *name;

  name = iter->next_name;
  GNUNET_assert (name != NULL);
  iter->next_name = NULL;
  iter->callback (iter->callback_cls, iter, name, iter->dirname);
  GNUNET_free (name);
}


/**
 * This function must be called during the DiskIteratorCallback
 * (exactly once) to schedule the task to process the next
 * filename in the directory (if there is one).
 *
 * @param iter opaque handle for the iterator
 * @param can set to GNUNET_YES to terminate the iteration early
 * @return GNUNET_YES if iteration will continue,
 *         GNUNET_NO if this was the last entry (and iteration is complete),
 *         GNUNET_SYSERR if abort was YES
 */
int
GNUNET_DISK_directory_iterator_next (struct GNUNET_DISK_DirectoryIterator *iter,
                                     int can)
{
  struct dirent *finfo;

  GNUNET_assert (iter->next_name == NULL);
  if (can == GNUNET_YES)
  {
    CLOSEDIR (iter->directory);
    GNUNET_free (iter->dirname);
    GNUNET_free (iter);
    return GNUNET_SYSERR;
  }
  while (NULL != (finfo = READDIR (iter->directory)))
  {
    if ((0 == strcmp (finfo->d_name, ".")) ||
        (0 == strcmp (finfo->d_name, "..")))
      continue;
    GNUNET_asprintf (&iter->next_name, "%s%s%s", iter->dirname,
                     DIR_SEPARATOR_STR, finfo->d_name);
    break;
  }
  if (finfo == NULL)
  {
    GNUNET_DISK_directory_iterator_next (iter, GNUNET_YES);
    return GNUNET_NO;
  }
  GNUNET_SCHEDULER_add_with_priority (iter->priority, &directory_iterator_task,
                                      iter);
  return GNUNET_YES;
}


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
                                      callback, void *callback_cls)
{
  struct GNUNET_DISK_DirectoryIterator *di;

  di = GNUNET_malloc (sizeof (struct GNUNET_DISK_DirectoryIterator));
  di->callback = callback;
  di->callback_cls = callback_cls;
  di->directory = OPENDIR (dirName);
  if (di->directory == NULL)
  {
    GNUNET_free (di);
    callback (callback_cls, NULL, NULL, NULL);
    return GNUNET_SYSERR;
  }
  di->dirname = GNUNET_strdup (dirName);
  di->priority = prio;
  return GNUNET_DISK_directory_iterator_next (di, GNUNET_NO);
}


/**
 * Function that removes the given directory by calling
 * "GNUNET_DISK_directory_remove".
 *
 * @param unused not used
 * @param fn directory to remove
 * @return GNUNET_OK
 */
static int
remove_helper (void *unused, const char *fn)
{
  (void) GNUNET_DISK_directory_remove (fn);
  return GNUNET_OK;
}


/**
 * Remove all files in a directory (rm -rf). Call with
 * caution.
 *
 *
 * @param fileName the file to remove
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DISK_directory_remove (const char *fileName)
{
  struct stat istat;

  if (0 != LSTAT (fileName, &istat))
    return GNUNET_NO;           /* file may not exist... */
  CHMOD (fileName, S_IWUSR | S_IRUSR | S_IXUSR);
  if (UNLINK (fileName) == 0)
    return GNUNET_OK;
  if ((errno != EISDIR) &&
      /* EISDIR is not sufficient in all cases, e.g.
       * sticky /tmp directory may result in EPERM on BSD.
       * So we also explicitly check "isDirectory" */
      (GNUNET_YES != GNUNET_DISK_directory_test (fileName)))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "rmdir", fileName);
    return GNUNET_SYSERR;
  }
  if (GNUNET_SYSERR ==
      GNUNET_DISK_directory_scan (fileName, &remove_helper, NULL))
    return GNUNET_SYSERR;
  if (0 != RMDIR (fileName))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "rmdir", fileName);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Copy a file.
 *
 * @param src file to copy
 * @param dst destination file name
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DISK_file_copy (const char *src, const char *dst)
{
  char *buf;
  uint64_t pos;
  uint64_t size;
  size_t len;
  struct GNUNET_DISK_FileHandle *in;
  struct GNUNET_DISK_FileHandle *out;

  if (GNUNET_OK != GNUNET_DISK_file_size (src, &size, GNUNET_YES))
    return GNUNET_SYSERR;
  pos = 0;
  in = GNUNET_DISK_file_open (src, GNUNET_DISK_OPEN_READ,
                              GNUNET_DISK_PERM_NONE);
  if (!in)
    return GNUNET_SYSERR;
  out =
      GNUNET_DISK_file_open (dst,
                             GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE |
                             GNUNET_DISK_OPEN_FAILIFEXISTS,
                             GNUNET_DISK_PERM_USER_READ |
                             GNUNET_DISK_PERM_USER_WRITE |
                             GNUNET_DISK_PERM_GROUP_READ |
                             GNUNET_DISK_PERM_GROUP_WRITE);
  if (!out)
  {
    GNUNET_DISK_file_close (in);
    return GNUNET_SYSERR;
  }
  buf = GNUNET_malloc (COPY_BLK_SIZE);
  while (pos < size)
  {
    len = COPY_BLK_SIZE;
    if (len > size - pos)
      len = size - pos;
    if (len != GNUNET_DISK_file_read (in, buf, len))
      goto FAIL;
    if (len != GNUNET_DISK_file_write (out, buf, len))
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

  idx = fn;
  while (*idx)
  {
    c = *idx;

    if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' ||
        c == '<' || c == '>' || c == '|')
    {
      *idx = '_';
    }

    idx++;
  }
}



/**
 * @brief Change owner of a file
 *
 * @param filename name of file to change the owner of
 * @param user name of the new owner
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_DISK_file_change_owner (const char *filename, const char *user)
{
#ifndef MINGW
  struct passwd *pws;

  pws = getpwnam (user);
  if (pws == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Cannot obtain information about user `%s': %s\n"), user,
         STRERROR (errno));
    return GNUNET_SYSERR;
  }
  if (0 != chown (filename, pws->pw_uid, pws->pw_gid))
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "chown", filename);
#endif
  return GNUNET_OK;
}


/**
 * Lock a part of a file
 * @param fh file handle
 * @param lockStart absolute position from where to lock
 * @param lockEnd absolute position until where to lock
 * @param excl GNUNET_YES for an exclusive lock
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DISK_file_lock (struct GNUNET_DISK_FileHandle *fh, OFF_T lockStart,
                       OFF_T lockEnd, int excl)
{
  if (fh == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

#ifndef MINGW
  struct flock fl;

  memset (&fl, 0, sizeof (struct flock));
  fl.l_type = excl ? F_WRLCK : F_RDLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = lockStart;
  fl.l_len = lockEnd;

  return fcntl (fh->fd, F_SETLK, &fl) != 0 ? GNUNET_SYSERR : GNUNET_OK;
#else
  OVERLAPPED o;
  OFF_T diff = lockEnd - lockStart;
  DWORD diff_low, diff_high;
  diff_low = (DWORD) (diff & 0xFFFFFFFF);
  diff_high = (DWORD) ((diff >> (sizeof (DWORD) * 8)) & 0xFFFFFFFF);

  memset (&o, 0, sizeof (OVERLAPPED));
  o.Offset = (DWORD) (lockStart & 0xFFFFFFFF);;
  o.OffsetHigh = (DWORD) (((lockStart & ~0xFFFFFFFF) >> (sizeof (DWORD) * 8)) & 0xFFFFFFFF);

  if (!LockFileEx
      (fh->h, (excl ? LOCKFILE_EXCLUSIVE_LOCK : 0) | LOCKFILE_FAIL_IMMEDIATELY,
       0, diff_low, diff_high, &o))
  {
    SetErrnoFromWinError (GetLastError ());
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
#endif
}


/**
 * Unlock a part of a file
 * @param fh file handle
 * @param unlockStart absolute position from where to unlock
 * @param unlockEnd absolute position until where to unlock
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DISK_file_unlock (struct GNUNET_DISK_FileHandle *fh, OFF_T unlockStart,
                         OFF_T unlockEnd)
{
  if (fh == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

#ifndef MINGW
  struct flock fl;

  memset (&fl, 0, sizeof (struct flock));
  fl.l_type = F_UNLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = unlockStart;
  fl.l_len = unlockEnd;

  return fcntl (fh->fd, F_SETLK, &fl) != 0 ? GNUNET_SYSERR : GNUNET_OK;
#else
  OVERLAPPED o;
  OFF_T diff = unlockEnd - unlockStart;
  DWORD diff_low, diff_high;
  diff_low = (DWORD) (diff & 0xFFFFFFFF);
  diff_high = (DWORD) ((diff >> (sizeof (DWORD) * 8)) & 0xFFFFFFFF);

  memset (&o, 0, sizeof (OVERLAPPED));
  o.Offset = (DWORD) (unlockStart & 0xFFFFFFFF);;
  o.OffsetHigh = (DWORD) (((unlockStart & ~0xFFFFFFFF) >> (sizeof (DWORD) * 8)) & 0xFFFFFFFF);

  if (!UnlockFileEx (fh->h, 0, diff_low, diff_high, &o))
  {
    SetErrnoFromWinError (GetLastError ());
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
#endif
}


/**
 * Open a file.  Note that the access permissions will only be
 * used if a new file is created and if the underlying operating
 * system supports the given permissions.
 *
 * @param fn file name to be opened
 * @param flags opening flags, a combination of GNUNET_DISK_OPEN_xxx bit flags
 * @param perm permissions for the newly created file, use
 *             GNUNET_DISK_PERM_USER_NONE if a file could not be created by this
 *             call (because of flags)
 * @return IO handle on success, NULL on error
 */
struct GNUNET_DISK_FileHandle *
GNUNET_DISK_file_open (const char *fn, enum GNUNET_DISK_OpenFlags flags,
                       enum GNUNET_DISK_AccessPermissions perm)
{
  char *expfn;
  struct GNUNET_DISK_FileHandle *ret;

#ifdef MINGW
  DWORD access;
  DWORD disp;
  HANDLE h;
  wchar_t wexpfn[MAX_PATH + 1];
#else
  int oflags;
  int mode;
  int fd;
#endif

  expfn = GNUNET_STRINGS_filename_expand (fn);
  if (NULL == expfn)
    return NULL;
#ifndef MINGW
  mode = 0;
  if (GNUNET_DISK_OPEN_READWRITE == (flags & GNUNET_DISK_OPEN_READWRITE))
    oflags = O_RDWR;            /* note: O_RDWR is NOT always O_RDONLY | O_WRONLY */
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
  if (flags & GNUNET_DISK_OPEN_CREATE)
  {
    (void) GNUNET_DISK_directory_create_for_file (expfn);
    oflags |= O_CREAT;
    mode = translate_unix_perms (perm);
  }

  fd = open (expfn, oflags | O_LARGEFILE, mode);
  if (fd == -1)
  {
    if (0 == (flags & GNUNET_DISK_OPEN_FAILIFEXISTS))
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "open", expfn);
    else
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_DEBUG, "open", expfn);
    GNUNET_free (expfn);
    return NULL;
  }
#else
  access = 0;
  disp = OPEN_ALWAYS;

  if (GNUNET_DISK_OPEN_READWRITE == (flags & GNUNET_DISK_OPEN_READWRITE))
    access = FILE_READ_DATA | FILE_WRITE_DATA;
  else if (flags & GNUNET_DISK_OPEN_READ)
    access = FILE_READ_DATA;
  else if (flags & GNUNET_DISK_OPEN_WRITE)
    access = FILE_WRITE_DATA;

  if (flags & GNUNET_DISK_OPEN_FAILIFEXISTS)
  {
    disp = CREATE_NEW;
  }
  else if (flags & GNUNET_DISK_OPEN_CREATE)
  {
    (void) GNUNET_DISK_directory_create_for_file (expfn);
    if (flags & GNUNET_DISK_OPEN_TRUNCATE)
      disp = CREATE_ALWAYS;
    else
      disp = OPEN_ALWAYS;
  }
  else if (flags & GNUNET_DISK_OPEN_TRUNCATE)
  {
    disp = TRUNCATE_EXISTING;
  }
  else
  {
    disp = OPEN_EXISTING;
  }

  if (ERROR_SUCCESS == plibc_conv_to_win_pathwconv(expfn, wexpfn))
    h = CreateFileW (wexpfn, access,
                    FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    disp, FILE_ATTRIBUTE_NORMAL, NULL);
  else
    h = INVALID_HANDLE_VALUE;
  if (h == INVALID_HANDLE_VALUE)
  {
    SetErrnoFromWinError (GetLastError ());
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "open", expfn);
    GNUNET_free (expfn);
    return NULL;
  }

  if (flags & GNUNET_DISK_OPEN_APPEND)
    if (SetFilePointer (h, 0, 0, FILE_END) == INVALID_SET_FILE_POINTER)
    {
      SetErrnoFromWinError (GetLastError ());
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "SetFilePointer", expfn);
      CloseHandle (h);
      GNUNET_free (expfn);
      return NULL;
    }
#endif

  ret = GNUNET_malloc (sizeof (struct GNUNET_DISK_FileHandle));
#ifdef MINGW
  ret->h = h;
  ret->type = GNUNET_DISK_FILE;
#else
  ret->fd = fd;
#endif
  GNUNET_free (expfn);
  return ret;
}


/**
 * Close an open file
 * @param h file handle
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_DISK_file_close (struct GNUNET_DISK_FileHandle *h)
{
  if (h == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

#if MINGW
  if (!CloseHandle (h->h))
  {
    SetErrnoFromWinError (GetLastError ());
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "close");
    GNUNET_free (h->oOverlapRead);
    GNUNET_free (h->oOverlapWrite);
    GNUNET_free (h);
    return GNUNET_SYSERR;
  }
#else
  if (close (h->fd) != 0)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "close");
    GNUNET_free (h);
    return GNUNET_SYSERR;
  }
#endif
  GNUNET_free (h);
  return GNUNET_OK;
}


/**
 * Construct full path to a file inside of the private
 * directory used by GNUnet.  Also creates the corresponding
 * directory.  If the resulting name is supposed to be
 * a directory, end the last argument in '/' (or pass
 * DIR_SEPARATOR_STR as the last argument before NULL).
 *
 * @param cfg configuration to use (determines HOME)
 * @param serviceName name of the service
 * @param ... is NULL-terminated list of
 *                path components to append to the
 *                private directory name.
 * @return the constructed filename
 */
char *
GNUNET_DISK_get_home_filename (const struct GNUNET_CONFIGURATION_Handle *cfg,
                               const char *serviceName, ...)
{
  const char *c;
  char *pfx;
  char *ret;
  va_list ap;
  unsigned int needed;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, serviceName, "HOME", &pfx))
    return NULL;
  if (pfx == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("No `%s' specified for service `%s' in configuration.\n"), "HOME",
         serviceName);
    return NULL;
  }
  needed = strlen (pfx) + 2;
  if ((pfx[strlen (pfx) - 1] != '/') && (pfx[strlen (pfx) - 1] != '\\'))
    needed++;
  va_start (ap, serviceName);
  while (1)
  {
    c = va_arg (ap, const char *);

    if (c == NULL)
      break;
    needed += strlen (c);
    if ((c[strlen (c) - 1] != '/') && (c[strlen (c) - 1] != '\\'))
      needed++;
  }
  va_end (ap);
  ret = GNUNET_malloc (needed);
  strcpy (ret, pfx);
  GNUNET_free (pfx);
  va_start (ap, serviceName);
  while (1)
  {
    c = va_arg (ap, const char *);

    if (c == NULL)
      break;
    if ((c[strlen (c) - 1] != '/') && (c[strlen (c) - 1] != '\\'))
      strcat (ret, DIR_SEPARATOR_STR);
    strcat (ret, c);
  }
  va_end (ap);
  if ((ret[strlen (ret) - 1] != '/') && (ret[strlen (ret) - 1] != '\\'))
    (void) GNUNET_DISK_directory_create_for_file (ret);
  else
    (void) GNUNET_DISK_directory_create (ret);
  return ret;
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

#ifdef MINGW
  /**
   * Underlying OS handle.
   */
  HANDLE h;
#else
  /**
   * Number of bytes mapped.
   */
  size_t len;
#endif
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
                      enum GNUNET_DISK_MapType access, size_t len)
{
  if (h == NULL)
  {
    errno = EINVAL;
    return NULL;
  }

#ifdef MINGW
  DWORD mapAccess, protect;

  if ((access & GNUNET_DISK_MAP_TYPE_READ) &&
      (access & GNUNET_DISK_MAP_TYPE_WRITE))
  {
    protect = PAGE_READWRITE;
    mapAccess = FILE_MAP_ALL_ACCESS;
  }
  else if (access & GNUNET_DISK_MAP_TYPE_READ)
  {
    protect = PAGE_READONLY;
    mapAccess = FILE_MAP_READ;
  }
  else if (access & GNUNET_DISK_MAP_TYPE_WRITE)
  {
    protect = PAGE_READWRITE;
    mapAccess = FILE_MAP_WRITE;
  }
  else
  {
    GNUNET_break (0);
    return NULL;
  }

  *m = GNUNET_malloc (sizeof (struct GNUNET_DISK_MapHandle));
  (*m)->h = CreateFileMapping (h->h, NULL, protect, 0, 0, NULL);
  if ((*m)->h == INVALID_HANDLE_VALUE)
  {
    SetErrnoFromWinError (GetLastError ());
    GNUNET_free (*m);
    return NULL;
  }

  (*m)->addr = MapViewOfFile ((*m)->h, mapAccess, 0, 0, len);
  if (!(*m)->addr)
  {
    SetErrnoFromWinError (GetLastError ());
    CloseHandle ((*m)->h);
    GNUNET_free (*m);
  }

  return (*m)->addr;
#else
  int prot;

  prot = 0;
  if (access & GNUNET_DISK_MAP_TYPE_READ)
    prot = PROT_READ;
  if (access & GNUNET_DISK_MAP_TYPE_WRITE)
    prot |= PROT_WRITE;
  *m = GNUNET_malloc (sizeof (struct GNUNET_DISK_MapHandle));
  (*m)->addr = mmap (NULL, len, prot, MAP_SHARED, h->fd, 0);
  GNUNET_assert (NULL != (*m)->addr);
  if (MAP_FAILED == (*m)->addr)
  {
    GNUNET_free (*m);
    return NULL;
  }
  (*m)->len = len;
  return (*m)->addr;
#endif
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

#ifdef MINGW
  ret = UnmapViewOfFile (h->addr) ? GNUNET_OK : GNUNET_SYSERR;
  if (ret != GNUNET_OK)
    SetErrnoFromWinError (GetLastError ());
  if (!CloseHandle (h->h) && (ret == GNUNET_OK))
  {
    ret = GNUNET_SYSERR;
    SetErrnoFromWinError (GetLastError ());
  }
#else
  ret = munmap (h->addr, h->len) != -1 ? GNUNET_OK : GNUNET_SYSERR;
#endif
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

#ifdef MINGW
  int ret;

  ret = FlushFileBuffers (h->h) ? GNUNET_OK : GNUNET_SYSERR;
  if (ret != GNUNET_OK)
    SetErrnoFromWinError (GetLastError ());
  return ret;
#elif defined(FREEBSD) || defined(OPENBSD) || defined(DARWIN)
  return fsync (h->fd) == -1 ? GNUNET_SYSERR : GNUNET_OK;
#else
  return fdatasync (h->fd) == -1 ? GNUNET_SYSERR : GNUNET_OK;
#endif
}


#if WINDOWS
/* Copyright Bob Byrnes  <byrnes <at> curl.com>
   http://permalink.gmane.org/gmane.os.cygwin.patches/2121
*/
/* Create a pipe, and return handles to the read and write ends,
   just like CreatePipe, but ensure that the write end permits
   FILE_READ_ATTRIBUTES access, on later versions of win32 where
   this is supported.  This access is needed by NtQueryInformationFile,
   which is used to implement select and nonblocking writes.
   Note that the return value is either NO_ERROR or GetLastError,
   unlike CreatePipe, which returns a bool for success or failure.  */
static int
create_selectable_pipe (PHANDLE read_pipe_ptr, PHANDLE write_pipe_ptr,
                        LPSECURITY_ATTRIBUTES sa_ptr, DWORD psize,
                        DWORD dwReadMode, DWORD dwWriteMode)
{
  /* Default to error. */
  *read_pipe_ptr = *write_pipe_ptr = INVALID_HANDLE_VALUE;

  HANDLE read_pipe = INVALID_HANDLE_VALUE, write_pipe = INVALID_HANDLE_VALUE;

  /* Ensure that there is enough pipe buffer space for atomic writes.  */
  if (psize < PIPE_BUF)
    psize = PIPE_BUF;

  char pipename[MAX_PATH];

  /* Retry CreateNamedPipe as long as the pipe name is in use.
   * Retrying will probably never be necessary, but we want
   * to be as robust as possible.  */
  while (1)
  {
    static volatile LONG pipe_unique_id;

    snprintf (pipename, sizeof pipename, "\\\\.\\pipe\\gnunet-%d-%ld",
              getpid (), InterlockedIncrement ((LONG *) & pipe_unique_id));
#if DEBUG_PIPE
    LOG (GNUNET_ERROR_TYPE_DEBUG, "CreateNamedPipe: name = %s, size = %lu\n",
         pipename, psize);
#endif
    /* Use CreateNamedPipe instead of CreatePipe, because the latter
     * returns a write handle that does not permit FILE_READ_ATTRIBUTES
     * access, on versions of win32 earlier than WinXP SP2.
     * CreatePipe also stupidly creates a full duplex pipe, which is
     * a waste, since only a single direction is actually used.
     * It's important to only allow a single instance, to ensure that
     * the pipe was not created earlier by some other process, even if
     * the pid has been reused.  We avoid FILE_FLAG_FIRST_PIPE_INSTANCE
     * because that is only available for Win2k SP2 and WinXP.  */
    read_pipe = CreateNamedPipeA (pipename, PIPE_ACCESS_INBOUND | dwReadMode, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE, 1,   /* max instances */
                                  psize,        /* output buffer size */
                                  psize,        /* input buffer size */
                                  NMPWAIT_USE_DEFAULT_WAIT, sa_ptr);

    if (read_pipe != INVALID_HANDLE_VALUE)
    {
#if DEBUG_PIPE
      LOG (GNUNET_ERROR_TYPE_DEBUG, "pipe read handle = %p\n", read_pipe);
#endif
      break;
    }

    DWORD err = GetLastError ();

    switch (err)
    {
    case ERROR_PIPE_BUSY:
      /* The pipe is already open with compatible parameters.
       * Pick a new name and retry.  */
#if DEBUG_PIPE
      LOG (GNUNET_ERROR_TYPE_DEBUG, "pipe busy, retrying\n");
#endif
      continue;
    case ERROR_ACCESS_DENIED:
      /* The pipe is already open with incompatible parameters.
       * Pick a new name and retry.  */
#if DEBUG_PIPE
      LOG (GNUNET_ERROR_TYPE_DEBUG, "pipe access denied, retrying\n");
#endif
      continue;
    case ERROR_CALL_NOT_IMPLEMENTED:
      /* We are on an older Win9x platform without named pipes.
       * Return an anonymous pipe as the best approximation.  */
#if DEBUG_PIPE
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "CreateNamedPipe not implemented, resorting to "
           "CreatePipe: size = %lu\n", psize);
#endif
      if (CreatePipe (read_pipe_ptr, write_pipe_ptr, sa_ptr, psize))
      {
#if DEBUG_PIPE
        LOG (GNUNET_ERROR_TYPE_DEBUG, "pipe read handle = %p\n",
             *read_pipe_ptr);
        LOG (GNUNET_ERROR_TYPE_DEBUG, "pipe write handle = %p\n",
             *write_pipe_ptr);
#endif
        return GNUNET_OK;
      }
      err = GetLastError ();
      LOG (GNUNET_ERROR_TYPE_ERROR, "CreatePipe failed: %d\n", err);
      return err;
    default:
      LOG (GNUNET_ERROR_TYPE_ERROR, "CreateNamedPipe failed: %d\n", err);
      return err;
    }
    /* NOTREACHED */
  }
#if DEBUG_PIPE
  LOG (GNUNET_ERROR_TYPE_DEBUG, "CreateFile: name = %s\n", pipename);
#endif

  /* Open the named pipe for writing.
   * Be sure to permit FILE_READ_ATTRIBUTES access.  */
  write_pipe = CreateFileA (pipename, GENERIC_WRITE | FILE_READ_ATTRIBUTES, 0,  /* share mode */
                            sa_ptr, OPEN_EXISTING, dwWriteMode, /* flags and attributes */
                            0); /* handle to template file */

  if (write_pipe == INVALID_HANDLE_VALUE)
  {
    /* Failure. */
    DWORD err = GetLastError ();

#if DEBUG_PIPE
    LOG (GNUNET_ERROR_TYPE_DEBUG, "CreateFile failed: %d\n", err);
#endif
    CloseHandle (read_pipe);
    return err;
  }
#if DEBUG_PIPE
  LOG (GNUNET_ERROR_TYPE_DEBUG, "pipe write handle = %p\n", write_pipe);
#endif
  /* Success. */
  *read_pipe_ptr = read_pipe;
  *write_pipe_ptr = write_pipe;
  return GNUNET_OK;
}
#endif


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
GNUNET_DISK_pipe (int blocking_read, int blocking_write, int inherit_read, int inherit_write)
{
#ifndef MINGW
  int fd[2];
  int ret;
  int eno;

  ret = pipe (fd);
  if (ret == -1)
  {
    eno = errno;
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "pipe");
    errno = eno;
    return NULL;
  }
  return GNUNET_DISK_pipe_from_fd (blocking_read,
				   blocking_write,
				   fd);
#else
  struct GNUNET_DISK_PipeHandle *p;
  struct GNUNET_DISK_FileHandle *fds;
  BOOL ret;
  HANDLE tmp_handle;
  

  p = GNUNET_malloc (sizeof (struct GNUNET_DISK_PipeHandle) +
                     2 * sizeof (struct GNUNET_DISK_FileHandle));
  fds = (struct GNUNET_DISK_FileHandle *) &p[1];
  p->fd[0] = &fds[0];
  p->fd[1] = &fds[1];

  /* All pipes are overlapped. If you want them to block - just
   * call WriteFile() and ReadFile() with NULL overlapped pointer.
   */
  ret =
      create_selectable_pipe (&p->fd[0]->h, &p->fd[1]->h, NULL, 0,
                              FILE_FLAG_OVERLAPPED,
                              FILE_FLAG_OVERLAPPED);
  if (!ret)
  {
    GNUNET_free (p);
    SetErrnoFromWinError (GetLastError ());
    return NULL;
  }
  if (!DuplicateHandle
      (GetCurrentProcess (), p->fd[0]->h, GetCurrentProcess (), &tmp_handle, 0,
       inherit_read == GNUNET_YES ? TRUE : FALSE, DUPLICATE_SAME_ACCESS))
  {
    SetErrnoFromWinError (GetLastError ());
    CloseHandle (p->fd[0]->h);
    CloseHandle (p->fd[1]->h);
    GNUNET_free (p);
    return NULL;
  }
  CloseHandle (p->fd[0]->h);
  p->fd[0]->h = tmp_handle;

  if (!DuplicateHandle
      (GetCurrentProcess (), p->fd[1]->h, GetCurrentProcess (), &tmp_handle, 0,
       inherit_write == GNUNET_YES ? TRUE : FALSE, DUPLICATE_SAME_ACCESS))
  {
    SetErrnoFromWinError (GetLastError ());
    CloseHandle (p->fd[0]->h);
    CloseHandle (p->fd[1]->h);
    GNUNET_free (p);
    return NULL;
  }
  CloseHandle (p->fd[1]->h);
  p->fd[1]->h = tmp_handle;

  p->fd[0]->type = GNUNET_PIPE;
  p->fd[1]->type = GNUNET_PIPE;

  p->fd[0]->oOverlapRead = GNUNET_malloc (sizeof (OVERLAPPED));
  p->fd[0]->oOverlapWrite = GNUNET_malloc (sizeof (OVERLAPPED));
  p->fd[1]->oOverlapRead = GNUNET_malloc (sizeof (OVERLAPPED));
  p->fd[1]->oOverlapWrite = GNUNET_malloc (sizeof (OVERLAPPED));

  p->fd[0]->oOverlapRead->hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
  p->fd[0]->oOverlapWrite->hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);

  p->fd[1]->oOverlapRead->hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
  p->fd[1]->oOverlapWrite->hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);

  return p;
#endif
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
  struct GNUNET_DISK_FileHandle *fds;

  p = GNUNET_malloc (sizeof (struct GNUNET_DISK_PipeHandle) +
                     2 * sizeof (struct GNUNET_DISK_FileHandle));
  fds = (struct GNUNET_DISK_FileHandle *) &p[1];
  p->fd[0] = &fds[0];
  p->fd[1] = &fds[1];
#ifndef MINGW
  int ret;
  int flags;
  int eno = 0; /* make gcc happy */

  p->fd[0]->fd = fd[0];
  p->fd[1]->fd = fd[1];
  ret = 0;
  if (fd[0] >= 0)
  {
    if (!blocking_read)
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
    if (!blocking_write)
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
    GNUNET_free (p);
    errno = eno;
    return NULL;
  }
#else
  if (fd[0] >= 0)
    p->fd[0]->h = _get_osfhandle (fd[0]);
  else
    p->fd[0]->h = INVALID_HANDLE_VALUE;
  if (fd[1] >= 0)
    p->fd[1]->h = _get_osfhandle (fd[1]);
  else
    p->fd[1]->h = INVALID_HANDLE_VALUE;

  if (p->fd[0]->h != INVALID_HANDLE_VALUE)
  {
    p->fd[0]->type = GNUNET_PIPE;
    p->fd[0]->oOverlapRead = GNUNET_malloc (sizeof (OVERLAPPED));
    p->fd[0]->oOverlapWrite = GNUNET_malloc (sizeof (OVERLAPPED));
    p->fd[0]->oOverlapRead->hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
    p->fd[0]->oOverlapWrite->hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
  }

  if (p->fd[1]->h != INVALID_HANDLE_VALUE)
  {
    p->fd[1]->type = GNUNET_PIPE;
    p->fd[1]->oOverlapRead = GNUNET_malloc (sizeof (OVERLAPPED));
    p->fd[1]->oOverlapWrite = GNUNET_malloc (sizeof (OVERLAPPED));
    p->fd[1]->oOverlapRead->hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
    p->fd[1]->oOverlapWrite->hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
  }
#endif
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
  int save;

#ifdef MINGW
  if (end == GNUNET_DISK_PIPE_END_READ)
  {
    if (p->fd[0]->h != INVALID_HANDLE_VALUE)
    {
      if (!CloseHandle (p->fd[0]->h))
      {
        SetErrnoFromWinError (GetLastError ());
        ret = GNUNET_SYSERR;
      }
      GNUNET_free (p->fd[0]->oOverlapRead);
      GNUNET_free (p->fd[0]->oOverlapWrite);
      p->fd[0]->h = INVALID_HANDLE_VALUE;
    }
  }
  else if (end == GNUNET_DISK_PIPE_END_WRITE)
  {
    if (p->fd[0]->h != INVALID_HANDLE_VALUE)
    {
      if (!CloseHandle (p->fd[1]->h))
      {
        SetErrnoFromWinError (GetLastError ());
        ret = GNUNET_SYSERR;
      }
      GNUNET_free (p->fd[1]->oOverlapRead);
      GNUNET_free (p->fd[1]->oOverlapWrite);
      p->fd[1]->h = INVALID_HANDLE_VALUE;
    }
  }
  save = errno;
#else
  save = 0;
  if (end == GNUNET_DISK_PIPE_END_READ)
  {
    if (0 != close (p->fd[0]->fd))
    {
      ret = GNUNET_SYSERR;
      save = errno;
    }
    p->fd[0]->fd = -1;
  }
  else if (end == GNUNET_DISK_PIPE_END_WRITE)
  {
    if (0 != close (p->fd[1]->fd))
    {
      ret = GNUNET_SYSERR;
      save = errno;
    }
    p->fd[1]->fd = -1;
  }
#endif
  errno = save;
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
  int save;

#ifdef MINGW
  if (p->fd[0]->h != INVALID_HANDLE_VALUE)
  {
    if (!CloseHandle (p->fd[0]->h))
    {
      SetErrnoFromWinError (GetLastError ());
      ret = GNUNET_SYSERR;
    }
    GNUNET_free (p->fd[0]->oOverlapRead);
    GNUNET_free (p->fd[0]->oOverlapWrite);
  }
  if (p->fd[1]->h != INVALID_HANDLE_VALUE)
  {
    if (!CloseHandle (p->fd[1]->h))
    {
      SetErrnoFromWinError (GetLastError ());
      ret = GNUNET_SYSERR;
    }
    GNUNET_free (p->fd[1]->oOverlapRead);
    GNUNET_free (p->fd[1]->oOverlapWrite);
  }
  save = errno;
#else
  save = 0;
  if (p->fd[0]->fd != -1)
  {
    if (0 != close (p->fd[0]->fd))
    {
      ret = GNUNET_SYSERR;
      save = errno;
    }
  }

  if (p->fd[1]->fd != -1)
  {
    if (0 != close (p->fd[1]->fd))
    {
      ret = GNUNET_SYSERR;
      save = errno;
    }
  }
#endif
  GNUNET_free (p);
  errno = save;
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
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_DISK_internal_file_handle_ (const struct GNUNET_DISK_FileHandle *fh,
                                   void *dst, size_t dst_len)
{
#ifdef MINGW
  if (dst_len < sizeof (HANDLE))
    return GNUNET_SYSERR;
  *((HANDLE *) dst) = fh->h;
#else
  if (dst_len < sizeof (int))
    return GNUNET_SYSERR;
  *((int *) dst) = fh->fd;
#endif

  return GNUNET_OK;
}

/* end of disk.c */
