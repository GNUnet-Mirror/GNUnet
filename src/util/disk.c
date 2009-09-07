/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2005, 2006, 2009 Christian Grothoff (and other contributing authors)

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
#include "disk.h"


#if LINUX || CYGWIN
#include <sys/vfs.h>
#else
#ifdef SOMEBSD
#include <sys/param.h>
#include <sys/mount.h>
#else
#ifdef OSX
#include <sys/param.h>
#include <sys/mount.h>
#else
#ifdef SOLARIS
#include <sys/types.h>
#include <sys/statvfs.h>
#else
#ifdef MINGW
#define  	_IFMT		0170000 /* type of file */
#define  	_IFLNK		0120000 /* symbolic link */
#define  S_ISLNK(m)	(((m)&_IFMT) == _IFLNK)
#else
#error PORT-ME: need to port statfs (how much space is left on the drive?)
#endif
#endif
#endif
#endif
#endif

#ifndef SOMEBSD
#ifndef WINDOWS
#ifndef OSX
#include <wordexp.h>
#endif
#endif
#endif

typedef struct
{
  uint64_t total;
  int include_sym_links;
} GetFileSizeData;

struct GNUNET_DISK_PipeHandle
{
  struct GNUNET_DISK_FileHandle fd[2];
};

static int
getSizeRec (void *ptr, const char *fn)
{
  GetFileSizeData *gfsd = ptr;
#ifdef HAVE_STAT64
  struct stat64 buf;
#else
  struct stat buf;
#endif

#ifdef HAVE_STAT64
  if (0 != STAT64 (fn, &buf))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "stat64", fn);
      return GNUNET_SYSERR;
    }
#else
  if (0 != STAT (fn, &buf))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "stat", fn);
      return GNUNET_SYSERR;
    }
#endif
  if ((!S_ISLNK (buf.st_mode)) || (gfsd->include_sym_links == GNUNET_YES))
    gfsd->total += buf.st_size;
  if ((S_ISDIR (buf.st_mode)) &&
      (0 == ACCESS (fn, X_OK)) &&
      ((!S_ISLNK (buf.st_mode)) || (gfsd->include_sym_links == GNUNET_YES)))
    {
      if (GNUNET_SYSERR == GNUNET_DISK_directory_scan (fn, &getSizeRec, gfsd))
        return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

/**
 * Checks whether a handle is invalid
 * @param h handle to check
 * @return GNUNET_YES if invalid, GNUNET_NO if valid
 */
int
GNUNET_DISK_handle_invalid (const struct GNUNET_DISK_FileHandle *h)
{
#ifdef MINGW
  return !h || h->h == INVALID_HANDLE_VALUE ? GNUNET_YES : GNUNET_NO;
#else
  return !h || h->fd == -1 ? GNUNET_YES : GNUNET_NO;
#endif
}


/**
 * Move the read/write pointer in a file
 * @param h handle of an open file
 * @param offset position to move to
 * @param whence specification to which position the offset parameter relates to
 * @return the new position on success, GNUNET_SYSERR otherwise
 */
off_t
GNUNET_DISK_file_seek (const struct GNUNET_DISK_FileHandle *h, off_t offset,
    enum GNUNET_DISK_Seek whence)
{
  if (h == NULL)
    {
      errno = EINVAL;
      return GNUNET_SYSERR;
    }

#ifdef MINGW
  DWORD ret;
  static DWORD t[] = { [GNUNET_DISK_SEEK_SET] = FILE_BEGIN,
      [GNUNET_DISK_SEEK_CUR] = FILE_CURRENT, [GNUNET_DISK_SEEK_END] = FILE_END };

  ret = SetFilePointer (h->h, offset, NULL, t[whence]);
  if (ret == INVALID_SET_FILE_POINTER)
    {
      SetErrnoFromWinError (GetLastError ());
      return GNUNET_SYSERR;
    }
  return ret;
#else
  static int t[] = { [GNUNET_DISK_SEEK_SET] = SEEK_SET,
      [GNUNET_DISK_SEEK_CUR] = SEEK_CUR, [GNUNET_DISK_SEEK_END] = SEEK_END };

  return lseek (h->fd, offset, t[whence]);
#endif
}

/**
 * Get the size of the file (or directory)
 * of the given file (in bytes).
 *
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
GNUNET_DISK_file_size (const char *filename,
                       uint64_t *size, 
		       int includeSymLinks)
{
  GetFileSizeData gfsd;
  int ret;

  GNUNET_assert (size != NULL);
  gfsd.total = 0;
  gfsd.include_sym_links = includeSymLinks;
  ret = getSizeRec (&gfsd, filename);
  *size = gfsd.total;
  return ret;
}


/**
 * Create an (empty) temporary file on disk.
 * 
 * @param template component to use for the name;
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

  tmpdir = getenv ("TMPDIR");
  tmpdir = tmpdir ? tmpdir : "/tmp";

  GNUNET_asprintf (&tmpl,
		   "%s%s%s%s",
		   tmpdir,
		   DIR_SEPARATOR_STR,
		   t,
		   "XXXXXX");
#ifdef MINGW
  fn = (char *) GNUNET_malloc (MAX_PATH + 1);
  plibc_conv_to_win_path (tmpl, fn);
  GNUNET_free (tmpl);
#else
  fn = tmpl;
#endif
  fd = mkstemp (fn);
  if (fd == -1)
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
				"mkstemp",
				fn);
      GNUNET_free (fn);
      return NULL;
    }
  if (0 != CLOSE (fd))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
			      "close",
			      fn);
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
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "statfs", part);
      return -1;
    }
  return buf.f_bavail;
#elif MINGW
  DWORD dwDummy;
  DWORD dwBlocks;
  char szDrive[4];
  char *path;

  path = GNUNET_STRINGS_filename_expand (part);
  memcpy (szDrive, path, 3);
  GNUNET_free (path);
  szDrive[3] = 0;
  if (!GetDiskFreeSpace (szDrive, &dwDummy, &dwDummy, &dwBlocks, &dwDummy))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                     _("`%s' failed for drive `%s': %u\n"),
                     "GetDiskFreeSpace", szDrive, GetLastError ());

      return -1;
    }
  return dwBlocks;
#else
  struct statfs s;
  if (0 != statfs (part, &s))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "statfs", part);
      return -1;
    }
  return s.f_bavail;
#endif
}

/**
 * Test if fil is a directory.
 *
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
          GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "stat", fil);
          return GNUNET_SYSERR;
        }
      return GNUNET_NO;
    }
  if (!S_ISDIR (filestat.st_mode))
    return GNUNET_NO;
  if (ACCESS (fil, R_OK | X_OK) < 0)
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "access", fil);
      return GNUNET_SYSERR;
    }
  return GNUNET_YES;
}

/**
 * Check that fil corresponds to a filename
 * (of a file that exists and that is not a directory).
 * @returns GNUNET_YES if yes, GNUNET_NO if not a file, GNUNET_SYSERR if something
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
          GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "stat", rdir);
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
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "access", rdir);
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
      pos = 3;                  /* strlen("C:\\") */
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
              ret = mkdir (rdir, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);  /* 755 */
#else
              ret = mkdir (rdir);
#endif
              if ((ret != 0) && (errno != EEXIST))
                {
                  GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "mkdir",
                                            rdir);
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
GNUNET_DISK_directory_create_for_file (const char *dir)
{
  char *rdir;
  int len;
  int ret;

  rdir = GNUNET_STRINGS_filename_expand (dir);
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
GNUNET_DISK_file_read (const struct GNUNET_DISK_FileHandle *h, void *result, 
		       size_t len)
{
  if (h == NULL)
    {
      errno = EINVAL;
      return GNUNET_SYSERR;
    }

#ifdef MINGW
  DWORD bytesRead;

  if (!ReadFile (h->h, result, len, &bytesRead, NULL))
    {
      SetErrnoFromWinError (GetLastError ());
      return GNUNET_SYSERR;
    }
  return bytesRead;
#else
  return read (h->fd, result, len);
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
GNUNET_DISK_fn_read (const char * const fn, 
		     void *result,
		     size_t len)
{
  struct GNUNET_DISK_FileHandle *fh;
  ssize_t ret;

  fh = GNUNET_DISK_file_open (fn, GNUNET_DISK_OPEN_READ);
  if (!fh)
    return GNUNET_SYSERR;
  ret = GNUNET_DISK_file_read (fh, result, len);
  GNUNET_assert(GNUNET_OK == GNUNET_DISK_file_close(fh));

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
GNUNET_DISK_file_write (const struct GNUNET_DISK_FileHandle *h, const void *buffer,
			size_t n)
{
  if (h == NULL)
    {
      errno = EINVAL;
      return GNUNET_SYSERR;
    }

#ifdef MINGW
  DWORD bytesWritten;

  if (!WriteFile (h->h, buffer, n, &bytesWritten, NULL))
    {
      SetErrnoFromWinError (GetLastError ());
      return GNUNET_SYSERR;
    }
  return bytesWritten;
#else
  return write (h->fd, buffer, n);
#endif
}

/**
 * Write a buffer to a file.  If the file is longer than the
 * number of bytes that will be written, iit will be truncated.
 *
 * @param fn file name
 * @param buffer the data to write
 * @param n number of bytes to write
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
ssize_t
GNUNET_DISK_fn_write (const char * const fn, const void *buffer,
    size_t n, int mode)
{
  struct GNUNET_DISK_FileHandle *fh;
  int ret;

  fh = GNUNET_DISK_file_open (fn, 
			      GNUNET_DISK_OPEN_WRITE 
			      | GNUNET_DISK_OPEN_TRUNCATE
			      | GNUNET_DISK_OPEN_CREATE, mode);
  if (!fh)
    return GNUNET_SYSERR;
  ret = (n == GNUNET_DISK_file_write (fh, buffer, n)) ? GNUNET_OK : GNUNET_SYSERR;
  GNUNET_assert(GNUNET_OK == GNUNET_DISK_file_close(fh));

  return ret;
}

/**
 * Scan a directory for files. The name of the directory
 * must be expanded first (!).
 * @param dirName the name of the directory
 * @param callback the method to call for each file,
 *        can be NULL, in that case, we only count
 * @param data argument to pass to callback
 * @return the number of files found, GNUNET_SYSERR on error or
 *         ieration aborted by callback returning GNUNET_SYSERR
 */
int
GNUNET_DISK_directory_scan (const char *dirName,
                            GNUNET_FileNameCallback callback, void *data)
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
  while ((strlen (dname) > 0) && (dname[strlen (dname) - 1] == DIR_SEPARATOR))
    dname[strlen (dname) - 1] = '\0';
  if (0 != STAT (dname, &istat))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "stat", dname);
      GNUNET_free (dname);
      return GNUNET_SYSERR;
    }
  if (!S_ISDIR (istat.st_mode))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Expected `%s' to be a directory!\n"), dirName);
      GNUNET_free (dname);
      return GNUNET_SYSERR;
    }
  errno = 0;
  dinfo = OPENDIR (dname);
  if ((errno == EACCES) || (dinfo == NULL))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "opendir", dname);
      if (dinfo != NULL)
        closedir (dinfo);
      GNUNET_free (dname);
      return GNUNET_SYSERR;
    }
  name_len = 256;
  n_size = strlen (dname) + name_len + 2;
  name = GNUNET_malloc (n_size);
  while ((finfo = readdir (dinfo)) != NULL)
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
             if dname does not end in "/", we need to add
             a "/" (otherwise, we must not!) */
          GNUNET_snprintf (name,
                           n_size,
                           "%s%s%s",
                           dname,
                           (strcmp (dname, DIR_SEPARATOR_STR) ==
                            0) ? "" : DIR_SEPARATOR_STR, finfo->d_name);
          if (GNUNET_OK != callback (data, name))
            {
              closedir (dinfo);
              GNUNET_free (name);
              GNUNET_free (dname);
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
 * Opaque handle used for iterating over a directory.
 */
struct GNUNET_DISK_DirectoryIterator
{
  /**
   * Our scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

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
GNUNET_DISK_directory_iterator_next (struct GNUNET_DISK_DirectoryIterator
                                     *iter, int can)
{
  struct dirent *finfo;

  GNUNET_assert (iter->next_name == NULL);
  if (can == GNUNET_YES)
    {
      closedir (iter->directory);
      GNUNET_free (iter->dirname);
      GNUNET_free (iter);
      return GNUNET_SYSERR;
    }
  while (NULL != (finfo = readdir (iter->directory)))
    {
      if ((0 == strcmp (finfo->d_name, ".")) ||
          (0 == strcmp (finfo->d_name, "..")))
        continue;
      GNUNET_asprintf (&iter->next_name,
                       "%s%s%s",
                       iter->dirname, DIR_SEPARATOR_STR, finfo->d_name);
      break;
    }
  if (finfo == NULL)
    {
      GNUNET_DISK_directory_iterator_next (iter, GNUNET_YES);
      return GNUNET_NO;
    }
  GNUNET_SCHEDULER_add_after (iter->sched,
                              GNUNET_YES,
                              iter->priority,
                              GNUNET_SCHEDULER_NO_TASK,
                              &directory_iterator_task, iter);
  return GNUNET_YES;
}


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
void
GNUNET_DISK_directory_iterator_start (struct GNUNET_SCHEDULER_Handle *sched,
                                      enum GNUNET_SCHEDULER_Priority prio,
                                      const char *dirName,
                                      GNUNET_DISK_DirectoryIteratorCallback
                                      callback, void *callback_cls)
{
  struct GNUNET_DISK_DirectoryIterator *di;

  di = GNUNET_malloc (sizeof (struct GNUNET_DISK_DirectoryIterator));
  di->sched = sched;
  di->callback = callback;
  di->callback_cls = callback_cls;
  di->directory = OPENDIR (dirName);
  di->dirname = GNUNET_strdup (dirName);
  di->priority = prio;
  GNUNET_DISK_directory_iterator_next (di, GNUNET_NO);
}


static int
remove_helper (void *unused, const char *fn)
{
  GNUNET_DISK_directory_remove (fn);
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
  if (UNLINK (fileName) == 0)
    return GNUNET_OK;
  if ((errno != EISDIR) &&
      /* EISDIR is not sufficient in all cases, e.g.
         sticky /tmp directory may result in EPERM on BSD.
         So we also explicitly check "isDirectory" */
      (GNUNET_YES != GNUNET_DISK_directory_test (fileName)))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "rmdir", fileName);
      return GNUNET_SYSERR;
    }
  if (GNUNET_SYSERR ==
      GNUNET_DISK_directory_scan (fileName, remove_helper, NULL))
    return GNUNET_SYSERR;
  if (0 != RMDIR (fileName))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "rmdir", fileName);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

#define COPY_BLK_SIZE 65536

/**
 * Copy a file.
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
  in = GNUNET_DISK_file_open (src, GNUNET_DISK_OPEN_READ);
  if (!in)
    return GNUNET_SYSERR;
  out = GNUNET_DISK_file_open (dst, GNUNET_DISK_OPEN_WRITE
			       | GNUNET_DISK_OPEN_CREATE | GNUNET_DISK_OPEN_FAILIFEXISTS,
			       GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE
			       | GNUNET_DISK_PERM_GROUP_READ | GNUNET_DISK_PERM_GROUP_WRITE);
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

      if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' ||
          c == '"' || c == '<' || c == '>' || c == '|')
        {
          *idx = '_';
        }

      idx++;
    }
}



/**
 * @brief Change owner of a file
 */
int
GNUNET_DISK_file_change_owner (const char *filename, const char *user)
{
#ifndef MINGW
  struct passwd *pws;

  pws = getpwnam (user);
  if (pws == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Cannot obtain information about user `%s': %s\n"),
                  user, STRERROR (errno));
      return GNUNET_SYSERR;
    }
  if (0 != chown (filename, pws->pw_uid, pws->pw_gid))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "chown", filename);
#endif
  return GNUNET_OK;
}


/**
 * Lock a part of a file
 * @param fh file handle
 * @lockStart absolute position from where to lock
 * @lockEnd absolute position until where to lock
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DISK_file_lock(struct GNUNET_DISK_FileHandle *fh, off_t lockStart,
    off_t lockEnd)
{
  if (fh == NULL)
    {
      errno = EINVAL;
      return GNUNET_SYSERR;
    }

#ifndef MINGW
  struct flock fl;

  memset(&fl, 0, sizeof(struct flock));
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = lockStart;
  fl.l_len = lockEnd;

  return fcntl(fh->fd, F_SETLK, &fl) != 0 ? GNUNET_SYSERR : GNUNET_OK;
#else
  if (!LockFile(fh->h, 0, lockStart, 0, lockEnd))
  {
    SetErrnoFromWinError(GetLastError());
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
#endif
}


/**
 * Open a file
 * @param fn file name to be opened
 * @param flags opening flags, a combination of GNUNET_DISK_OPEN_xxx bit flags
 * @param perm permissions for the newly created file
 * @return IO handle on success, NULL on error
 */
struct GNUNET_DISK_FileHandle *
GNUNET_DISK_file_open (const char *fn, int flags, ...)
{
  char *expfn;
  struct GNUNET_DISK_FileHandle *ret;
#ifdef MINGW
  DWORD access;
  DWORD disp;
  HANDLE h;
#else
  int oflags;
  int mode;
  int fd;
#endif

  expfn = GNUNET_STRINGS_filename_expand (fn);

#ifndef MINGW
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
    oflags |= (O_CREAT & O_EXCL);
  if (flags & GNUNET_DISK_OPEN_TRUNCATE)
    oflags |= O_TRUNC;
  if (flags & GNUNET_DISK_OPEN_APPEND)
    oflags |= O_APPEND;
  if (flags & GNUNET_DISK_OPEN_CREATE)
    {
      int perm;

      oflags |= O_CREAT;

      va_list arg;
      va_start (arg, flags);
      perm = va_arg (arg, int);
      va_end (arg);

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
    }

  fd = open (expfn, oflags | O_LARGEFILE, mode);
  if (fd == -1)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "open", expfn);
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
    disp = OPEN_ALWAYS;
  }

  /* TODO: access priviledges? */
  h = CreateFile (expfn, access, FILE_SHARE_DELETE | FILE_SHARE_READ
      | FILE_SHARE_WRITE, NULL, disp, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
  {
    SetErrnoFromWinError (GetLastError ());
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "open", expfn);
    GNUNET_free (expfn);
    return NULL;
  }

  if (flags & GNUNET_DISK_OPEN_APPEND)
    if (SetFilePointer (h, 0, 0, FILE_END) == INVALID_SET_FILE_POINTER)
    {
      SetErrnoFromWinError (GetLastError ());
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "SetFilePointer", expfn);
      CloseHandle (h);
      GNUNET_free (expfn);
      return NULL;
    }
#endif

  ret = GNUNET_malloc(sizeof(struct GNUNET_DISK_FileHandle));
#ifdef MINGW
  ret->h = h;
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
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "close");
    GNUNET_free (h);
    return GNUNET_SYSERR;
  }
#else
  if (close (h->fd) != 0)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "close");
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
 * @param varargs is NULL-terminated list of
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
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               serviceName, "HOME", &pfx))
    return NULL;
  if (pfx == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("No `%s' specified for service `%s' in configuration.\n"),
                  "HOME", serviceName);
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
    GNUNET_DISK_directory_create_for_file (ret);
  else
    GNUNET_DISK_directory_create (ret);
  return ret;
}

struct GNUNET_DISK_MapHandle
{
#ifdef MINGW
  HANDLE h;
#else
  void *addr;
  size_t len;
#endif
};


/**
 * Map a file into memory
 * @param h open file handle
 * @param m handle to the new mapping
 * @param access access specification, GNUNET_DISK_MAP_xxx
 * @param len size of the mapping
 * @return pointer to the mapped memory region, NULL on failure
 */
void *
GNUNET_DISK_file_map (const struct GNUNET_DISK_FileHandle *h, struct GNUNET_DISK_MapHandle **m,
    int access, size_t len)
{
  if (h == NULL)
    {
      errno = EINVAL;
      return NULL;
    }

#ifdef MINGW
  DWORD mapAccess, protect;
  void *ret;

  if (access & GNUNET_DISK_MAP_READ && access & GNUNET_DISK_MAP_WRITE)
    {
      protect = PAGE_READWRITE;
      mapAccess = FILE_MAP_ALL_ACCESS;
    }
  else if (access & GNUNET_DISK_MAP_READ)
    {
      protect = PAGE_READONLY;
      mapAccess = FILE_MAP_READ;
    }
  else if (access & GNUNET_DISK_MAP_WRITE)
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

  ret = MapViewOfFile ((*m)->h, mapAccess, 0, 0, len);
  if (!ret)
    {
      SetErrnoFromWinError (GetLastError ());
      CloseHandle ((*m)->h);
      GNUNET_free (*m);
    }

  return ret;
#else
  int prot;

  prot = 0;
  if (access & GNUNET_DISK_MAP_READ)
    prot = PROT_READ;
  if (access & GNUNET_DISK_MAP_WRITE)
    prot |= PROT_WRITE;
  *m = GNUNET_malloc (sizeof (struct GNUNET_DISK_MapHandle));
  (*m)->addr = mmap (NULL, len, prot, MAP_SHARED, h->fd, 0);
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
  ret = UnmapViewOfFile (h->h) ? GNUNET_OK : GNUNET_SYSERR;
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
#else
  return fsync (h->fd) == -1 ? GNUNET_SYSERR : GNUNET_OK;
#endif
}

/**
 * Creates an interprocess channel
 * @param blocking creates an asynchronous pipe if set to GNUNET_NO
 * @return handle to the new pipe, NULL on error
 */
struct GNUNET_DISK_PipeHandle *
GNUNET_DISK_pipe (int blocking)
{
  struct GNUNET_DISK_PipeHandle *p;
  int err;

  err = GNUNET_NO;
  p = GNUNET_malloc (sizeof (struct GNUNET_DISK_PipeHandle));

#ifndef MINGW
  int fd[2];
  int ret;
  int flags;

  ret = pipe (fd);
  if (ret != -1)
    {
      p->fd[0].fd = fd[0];
      p->fd[1].fd = fd[1];

      if (!blocking)
        {
          flags = fcntl (fd[0], F_GETFL);
          flags |= O_NONBLOCK;
          ret = fcntl (fd[0], F_SETFL, flags);
          if (ret != -1)
            {
              flags = fcntl (fd[1], F_GETFL);
              flags |= O_NONBLOCK;
              ret = fcntl (fd[1], F_SETFL, flags);
            }
          if (ret == -1)
            {
              GNUNET_log_strerror(GNUNET_ERROR_TYPE_ERROR, "fcntl");
              close (fd[0]);
              close (fd[1]);
              err = GNUNET_YES;
            }
        }
    }
  else
    err = GNUNET_YES;
#else
  BOOL ret;

  ret = CreatePipe (&p->fd[0].h, &p->fd[1].h, NULL, 0);
  if (ret)
    {
      if (!blocking)
        {
          DWORD mode;

          mode = PIPE_NOWAIT;
          SetNamedPipeHandleState (p->fd[0].h, &mode, NULL, NULL);
          SetNamedPipeHandleState (p->fd[1].h, &mode, NULL, NULL);
          /* this always fails on Windows 95, so we don't care about error handling */
        }
    }
  else
      err = GNUNET_YES;
#endif

  if (GNUNET_YES == err)
    {
      GNUNET_free (p);
      p = NULL;
    }

  return p;
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
#ifdef MINGW
  if (!CloseHandle (p->fd[0].h))
    {
      SetErrnoFromWinError (GetLastError ());
      ret = GNUNET_SYSERR;
    }

  if (!CloseHandle (p->fd[1].h))
    {
      SetErrnoFromWinError (GetLastError ());
      ret = GNUNET_SYSERR;
    }
#else
  int save;
  
  if (0 != close (p->fd[0].fd))
    {
      ret = GNUNET_SYSERR;
      save = errno;
    }
  else
    save = 0;
  
  if (0 != close (p->fd[1].fd))
    ret = GNUNET_SYSERR;
  else
    errno = save;
#endif
  GNUNET_free (p);
  return ret;
}


/**
 * Get the handle to a particular pipe end
 * @param p pipe
 * @param n number of the end
 */
const struct GNUNET_DISK_FileHandle *
GNUNET_DISK_pipe_handle (const struct GNUNET_DISK_PipeHandle *p, int n)
{
  return &p->fd[n];
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
GNUNET_internal_disk_file_handle (const struct GNUNET_DISK_FileHandle *fh,
    void *dst, unsigned int dst_len)
{
#ifdef MINGW
  if (dst_len < sizeof (HANDLE))
    return GNUNET_SYSERR;
  *((HANDLE *) dst) = fh->h;
#else
  if (dst_len < sizeof(int))
    return GNUNET_SYSERR;
  *((int *) dst) = fh->fd;
#endif

  return GNUNET_OK;
}

/* end of disk.c */
