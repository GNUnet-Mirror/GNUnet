/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013 Christian Grothoff (and other contributing authors)

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
 * @file util/crypto_hash_file.c
 * @brief incremental hashing of files
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)


/**
 * Context used when hashing a file.
 */
struct GNUNET_CRYPTO_FileHashContext
{

  /**
   * Function to call upon completion.
   */
  GNUNET_CRYPTO_HashCompletedCallback callback;

  /**
   * Closure for callback.
   */
  void *callback_cls;

  /**
   * IO buffer.
   */
  unsigned char *buffer;

  /**
   * Name of the file we are hashing.
   */
  char *filename;

  /**
   * File descriptor.
   */
  struct GNUNET_DISK_FileHandle *fh;

  /**
   * Cummulated hash.
   */
  gcry_md_hd_t md;

  /**
   * Size of the file.
   */
  uint64_t fsize;

  /**
   * Current offset.
   */
  uint64_t offset;

  /**
   * Current task for hashing.
   */
  struct GNUNET_SCHEDULER_Task * task;

  /**
   * Priority we use.
   */
  enum GNUNET_SCHEDULER_Priority priority;

  /**
   * Blocksize.
   */
  size_t bsize;

};


/**
 * Report result of hash computation to callback
 * and free associated resources.
 */
static void
file_hash_finish (struct GNUNET_CRYPTO_FileHashContext *fhc,
                  const struct GNUNET_HashCode * res)
{
  fhc->callback (fhc->callback_cls, res);
  GNUNET_free (fhc->filename);
  if (!GNUNET_DISK_handle_invalid (fhc->fh))
    GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fhc->fh));
  gcry_md_close (fhc->md);
  GNUNET_free (fhc);            /* also frees fhc->buffer */
}


/**
 * File hashing task.
 *
 * @param cls closure
 * @param tc context
 */
static void
file_hash_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CRYPTO_FileHashContext *fhc = cls;
  struct GNUNET_HashCode *res;
  size_t delta;

  fhc->task = NULL;
  GNUNET_assert (fhc->offset <= fhc->fsize);
  delta = fhc->bsize;
  if (fhc->fsize - fhc->offset < delta)
    delta = fhc->fsize - fhc->offset;
  if (delta != GNUNET_DISK_file_read (fhc->fh, fhc->buffer, delta))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "read", fhc->filename);
    file_hash_finish (fhc, NULL);
    return;
  }
  gcry_md_write (fhc->md, fhc->buffer, delta);
  fhc->offset += delta;
  if (fhc->offset == fhc->fsize)
  {
    res = (struct GNUNET_HashCode *) gcry_md_read (fhc->md, GCRY_MD_SHA512);
    file_hash_finish (fhc, res);
    return;
  }
  fhc->task = GNUNET_SCHEDULER_add_with_priority (fhc->priority,
						  &file_hash_task, fhc);
}


/**
 * Compute the hash of an entire file.
 *
 * @param priority scheduling priority to use
 * @param filename name of file to hash
 * @param blocksize number of bytes to process in one task
 * @param callback function to call upon completion
 * @param callback_cls closure for callback
 * @return NULL on (immediate) errror
 */
struct GNUNET_CRYPTO_FileHashContext *
GNUNET_CRYPTO_hash_file (enum GNUNET_SCHEDULER_Priority priority,
                         const char *filename, size_t blocksize,
                         GNUNET_CRYPTO_HashCompletedCallback callback,
                         void *callback_cls)
{
  struct GNUNET_CRYPTO_FileHashContext *fhc;

  GNUNET_assert (blocksize > 0);
  fhc =
      GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_FileHashContext) + blocksize);
  fhc->callback = callback;
  fhc->callback_cls = callback_cls;
  fhc->buffer = (unsigned char *) &fhc[1];
  fhc->filename = GNUNET_strdup (filename);
  if (GPG_ERR_NO_ERROR != gcry_md_open (&fhc->md, GCRY_MD_SHA512, 0))
  {
    GNUNET_break (0);
    GNUNET_free (fhc);
    return NULL;
  }
  fhc->bsize = blocksize;
  if (GNUNET_OK != GNUNET_DISK_file_size (filename, &fhc->fsize, GNUNET_NO, GNUNET_YES))
  {
    GNUNET_free (fhc->filename);
    GNUNET_free (fhc);
    return NULL;
  }
  fhc->fh =
      GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_READ,
                             GNUNET_DISK_PERM_NONE);
  if (!fhc->fh)
  {
    GNUNET_free (fhc->filename);
    GNUNET_free (fhc);
    return NULL;
  }
  fhc->priority = priority;
  fhc->task =
      GNUNET_SCHEDULER_add_with_priority (priority, &file_hash_task, fhc);
  return fhc;
}


/**
 * Cancel a file hashing operation.
 *
 * @param fhc operation to cancel (callback must not yet have been invoked)
 */
void
GNUNET_CRYPTO_hash_file_cancel (struct GNUNET_CRYPTO_FileHashContext *fhc)
{
  GNUNET_SCHEDULER_cancel (fhc->task);
  GNUNET_free (fhc->filename);
  GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fhc->fh));
  GNUNET_free (fhc);
}

/* end of crypto_hash_file.c */
