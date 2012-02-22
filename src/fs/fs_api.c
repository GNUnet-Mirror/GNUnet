/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008, 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_api.c
 * @brief main FS functions (master initialization, serialization, deserialization, shared code)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "fs_api.h"
#include "fs_tree.h"


/**
 * Start the given job (send signal, remove from pending queue, update
 * counters and state).
 *
 * @param qe job to start
 */
static void
start_job (struct GNUNET_FS_QueueEntry *qe)
{
  GNUNET_assert (NULL == qe->client);
  qe->client = GNUNET_CLIENT_connect ("fs", qe->h->cfg);
  if (qe->client == NULL)
  {
    GNUNET_break (0);
    return;
  }
  qe->start (qe->cls, qe->client);
  qe->start_times++;
  qe->h->active_blocks += qe->blocks;
  qe->start_time = GNUNET_TIME_absolute_get ();
  GNUNET_CONTAINER_DLL_remove (qe->h->pending_head, qe->h->pending_tail, qe);
  GNUNET_CONTAINER_DLL_insert_after (qe->h->running_head, qe->h->running_tail,
                                     qe->h->running_tail, qe);
}


/**
 * Stop the given job (send signal, remove from active queue, update
 * counters and state).
 *
 * @param qe job to stop
 */
static void
stop_job (struct GNUNET_FS_QueueEntry *qe)
{
  qe->client = NULL;
  qe->stop (qe->cls);
  qe->h->active_downloads--;
  qe->h->active_blocks -= qe->blocks;
  qe->run_time =
      GNUNET_TIME_relative_add (qe->run_time,
                                GNUNET_TIME_absolute_get_duration
                                (qe->start_time));
  GNUNET_CONTAINER_DLL_remove (qe->h->running_head, qe->h->running_tail, qe);
  GNUNET_CONTAINER_DLL_insert_after (qe->h->pending_head, qe->h->pending_tail,
                                     qe->h->pending_tail, qe);
}


/**
 * Process the jobs in the job queue, possibly starting some
 * and stopping others.
 *
 * @param cls the 'struct GNUNET_FS_Handle'
 * @param tc scheduler context
 */
static void
process_job_queue (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_Handle *h = cls;
  struct GNUNET_FS_QueueEntry *qe;
  struct GNUNET_FS_QueueEntry *next;
  struct GNUNET_TIME_Relative run_time;
  struct GNUNET_TIME_Relative restart_at;
  struct GNUNET_TIME_Relative rst;
  struct GNUNET_TIME_Absolute end_time;

  h->queue_job = GNUNET_SCHEDULER_NO_TASK;
  next = h->pending_head;
  while (NULL != (qe = next))
  {
    next = qe->next;
    if (h->running_head == NULL)
    {
      start_job (qe);
      continue;
    }
    if ((qe->blocks + h->active_blocks <= h->max_parallel_requests) &&
        (h->active_downloads + 1 <= h->max_parallel_downloads))
    {
      start_job (qe);
      continue;
    }
  }
  if (h->pending_head == NULL)
    return;                     /* no need to stop anything */
  restart_at = GNUNET_TIME_UNIT_FOREVER_REL;
  next = h->running_head;
  while (NULL != (qe = next))
  {
    next = qe->next;
    run_time =
        GNUNET_TIME_relative_multiply (h->avg_block_latency,
                                       qe->blocks * qe->start_times);
    end_time = GNUNET_TIME_absolute_add (qe->start_time, run_time);
    rst = GNUNET_TIME_absolute_get_remaining (end_time);
    restart_at = GNUNET_TIME_relative_min (rst, restart_at);
    if (rst.rel_value > 0)
      continue;
    stop_job (qe);
  }
  h->queue_job =
      GNUNET_SCHEDULER_add_delayed (restart_at, &process_job_queue, h);
}


/**
 * Add a job to the queue.
 *
 * @param h handle to the overall FS state
 * @param start function to call to begin the job
 * @param stop function to call to pause the job, or on dequeue (if the job was running)
 * @param cls closure for start and stop
 * @param blocks number of blocks this jobs uses
 * @return queue handle
 */
struct GNUNET_FS_QueueEntry *
GNUNET_FS_queue_ (struct GNUNET_FS_Handle *h, GNUNET_FS_QueueStart start,
                  GNUNET_FS_QueueStop stop, void *cls, unsigned int blocks)
{
  struct GNUNET_FS_QueueEntry *qe;

  qe = GNUNET_malloc (sizeof (struct GNUNET_FS_QueueEntry));
  qe->h = h;
  qe->start = start;
  qe->stop = stop;
  qe->cls = cls;
  qe->queue_time = GNUNET_TIME_absolute_get ();
  qe->blocks = blocks;
  GNUNET_CONTAINER_DLL_insert_after (h->pending_head, h->pending_tail,
                                     h->pending_tail, qe);
  if (h->queue_job != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (h->queue_job);
  h->queue_job = GNUNET_SCHEDULER_add_now (&process_job_queue, h);
  return qe;
}


/**
 * Dequeue a job from the queue.
 * @param qh handle for the job
 */
void
GNUNET_FS_dequeue_ (struct GNUNET_FS_QueueEntry *qh)
{
  struct GNUNET_FS_Handle *h;

  h = qh->h;
  if (qh->client != NULL)
    stop_job (qh);
  GNUNET_CONTAINER_DLL_remove (h->pending_head, h->pending_tail, qh);
  GNUNET_free (qh);
  if (h->queue_job != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (h->queue_job);
  h->queue_job = GNUNET_SCHEDULER_add_now (&process_job_queue, h);
}


/**
 * Create a top-level activity entry.
 *
 * @param h global fs handle
 * @param ssf suspend signal function to use
 * @param ssf_cls closure for ssf
 * @return fresh top-level activity handle
 */
struct TopLevelActivity *
GNUNET_FS_make_top (struct GNUNET_FS_Handle *h, SuspendSignalFunction ssf,
                    void *ssf_cls)
{
  struct TopLevelActivity *ret;

  ret = GNUNET_malloc (sizeof (struct TopLevelActivity));
  ret->ssf = ssf;
  ret->ssf_cls = ssf_cls;
  GNUNET_CONTAINER_DLL_insert (h->top_head, h->top_tail, ret);
  return ret;
}


/**
 * Destroy a top-level activity entry.
 *
 * @param h global fs handle
 * @param top top level activity entry
 */
void
GNUNET_FS_end_top (struct GNUNET_FS_Handle *h, struct TopLevelActivity *top)
{
  GNUNET_CONTAINER_DLL_remove (h->top_head, h->top_tail, top);
  GNUNET_free (top);
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
size_t
GNUNET_FS_data_reader_file_ (void *cls, uint64_t offset, size_t max, void *buf,
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
    fi->fd =
        GNUNET_DISK_file_open (fi->filename, GNUNET_DISK_OPEN_READ,
                               GNUNET_DISK_PERM_NONE);
    if (fi->fd == NULL)
    {
      GNUNET_asprintf (emsg, _("Could not open file `%s': %s"), fi->filename,
                       STRERROR (errno));
      return 0;
    }
  }
  GNUNET_DISK_file_seek (fi->fd, offset, GNUNET_DISK_SEEK_SET);
  ret = GNUNET_DISK_file_read (fi->fd, buf, max);
  if (ret == -1)
  {
    GNUNET_asprintf (emsg, _("Could not read file `%s': %s"), fi->filename,
                     STRERROR (errno));
    return 0;
  }
  if (ret != max)
  {
    GNUNET_asprintf (emsg, _("Short read reading from file `%s'!"),
                     fi->filename);
    return 0;
  }
  return max;
}


/**
 * Create the closure for the 'GNUNET_FS_data_reader_file_' callback.
 *
 * @param filename file to read
 * @return closure to use, NULL on error
 */
void *
GNUNET_FS_make_file_reader_context_ (const char *filename)
{
  struct FileInfo *fi;

  fi = GNUNET_malloc (sizeof (struct FileInfo));
  fi->filename = GNUNET_STRINGS_filename_expand (filename);
  if (fi->filename == NULL)
  {
    GNUNET_free (fi);
    return NULL;
  }
  return fi;
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
size_t
GNUNET_FS_data_reader_copy_ (void *cls, uint64_t offset, size_t max, void *buf,
                             char **emsg)
{
  char *data = cls;

  if (max == 0)
  {
    GNUNET_free_non_null (data);
    return 0;
  }
  memcpy (buf, &data[offset], max);
  return max;
}


/**
 * Return the full filename where we would store state information
 * (for serialization/deserialization).
 *
 * @param h master context
 * @param ext component of the path
 * @param ent entity identifier (or emtpy string for the directory)
 * @return NULL on error
 */
static char *
get_serialization_file_name (struct GNUNET_FS_Handle *h, const char *ext,
                             const char *ent)
{
  char *basename;
  char *ret;

  if (0 == (h->flags & GNUNET_FS_FLAGS_PERSISTENCE))
    return NULL;                /* persistence not requested */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (h->cfg, "fs", "STATE_DIR",
                                               &basename))
    return NULL;
  GNUNET_asprintf (&ret, "%s%s%s%s%s%s%s", basename, DIR_SEPARATOR_STR,
                   h->client_name, DIR_SEPARATOR_STR, ext, DIR_SEPARATOR_STR,
                   ent);
  GNUNET_free (basename);
  return ret;
}


/**
 * Return the full filename where we would store state information
 * (for serialization/deserialization) that is associated with a
 * parent operation.
 *
 * @param h master context
 * @param ext component of the path
 * @param uni name of the parent operation
 * @param ent entity identifier (or emtpy string for the directory)
 * @return NULL on error
 */
static char *
get_serialization_file_name_in_dir (struct GNUNET_FS_Handle *h, const char *ext,
                                    const char *uni, const char *ent)
{
  char *basename;
  char *ret;

  if (0 == (h->flags & GNUNET_FS_FLAGS_PERSISTENCE))
    return NULL;                /* persistence not requested */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (h->cfg, "fs", "STATE_DIR",
                                               &basename))
    return NULL;
  GNUNET_asprintf (&ret, "%s%s%s%s%s%s%s.dir%s%s", basename, DIR_SEPARATOR_STR,
                   h->client_name, DIR_SEPARATOR_STR, ext, DIR_SEPARATOR_STR,
                   uni, DIR_SEPARATOR_STR, ent);
  GNUNET_free (basename);
  return ret;
}


/**
 * Return a read handle for deserialization.
 *
 * @param h master context
 * @param ext component of the path
 * @param ent entity identifier (or emtpy string for the directory)
 * @return NULL on error
 */
static struct GNUNET_BIO_ReadHandle *
get_read_handle (struct GNUNET_FS_Handle *h, const char *ext, const char *ent)
{
  char *fn;
  struct GNUNET_BIO_ReadHandle *ret;

  fn = get_serialization_file_name (h, ext, ent);
  if (fn == NULL)
    return NULL;
  ret = GNUNET_BIO_read_open (fn);
  GNUNET_free (fn);
  return ret;
}


/**
 * Return a write handle for serialization.
 *
 * @param h master context
 * @param ext component of the path
 * @param ent entity identifier (or emtpy string for the directory)
 * @return NULL on error
 */
static struct GNUNET_BIO_WriteHandle *
get_write_handle (struct GNUNET_FS_Handle *h, const char *ext, const char *ent)
{
  char *fn;
  struct GNUNET_BIO_WriteHandle *ret;

  fn = get_serialization_file_name (h, ext, ent);
  if (fn == NULL)
  {
    return NULL;
  }
  ret = GNUNET_BIO_write_open (fn);
  if (ret == NULL)
    GNUNET_break (0);
  GNUNET_free (fn);
  return ret;
}


/**
 * Return a write handle for serialization.
 *
 * @param h master context
 * @param ext component of the path
 * @param uni name of parent
 * @param ent entity identifier (or emtpy string for the directory)
 * @return NULL on error
 */
static struct GNUNET_BIO_WriteHandle *
get_write_handle_in_dir (struct GNUNET_FS_Handle *h, const char *ext,
                         const char *uni, const char *ent)
{
  char *fn;
  struct GNUNET_BIO_WriteHandle *ret;

  fn = get_serialization_file_name_in_dir (h, ext, uni, ent);
  if (fn == NULL)
    return NULL;
  ret = GNUNET_BIO_write_open (fn);
  GNUNET_free (fn);
  return ret;
}


/**
 * Remove serialization/deserialization file from disk.
 *
 * @param h master context
 * @param ext component of the path
 * @param ent entity identifier
 */
void
GNUNET_FS_remove_sync_file_ (struct GNUNET_FS_Handle *h, const char *ext,
                             const char *ent)
{
  char *filename;

  if ((NULL == ent) || (0 == strlen (ent)))
  {
    GNUNET_break (0);
    return;
  }
  filename = get_serialization_file_name (h, ext, ent);
  if (filename != NULL)
  {
    if (0 != UNLINK (filename))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", filename);
    GNUNET_free (filename);
  }
}


/**
 * Remove serialization/deserialization file from disk.
 *
 * @param h master context
 * @param ext component of the path
 * @param uni parent name
 * @param ent entity identifier
 */
static void
remove_sync_file_in_dir (struct GNUNET_FS_Handle *h, const char *ext,
                         const char *uni, const char *ent)
{
  char *filename;

  if ((NULL == ent) || (0 == strlen (ent)))
  {
    GNUNET_break (0);
    return;
  }
  filename = get_serialization_file_name_in_dir (h, ext, uni, ent);
  if (filename != NULL)
  {
    if (0 != UNLINK (filename))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", filename);
    GNUNET_free (filename);
  }
}


/**
 * Remove serialization/deserialization directory from disk.
 *
 * @param h master context
 * @param ext component of the path
 * @param uni unique name of parent
 */
void
GNUNET_FS_remove_sync_dir_ (struct GNUNET_FS_Handle *h, const char *ext,
                            const char *uni)
{
  char *dn;

  if (uni == NULL)
    return;
  dn = get_serialization_file_name_in_dir (h, ext, uni, "");
  if (dn == NULL)
    return;
  if ((GNUNET_OK == GNUNET_DISK_directory_test (dn)) &&
      (GNUNET_OK != GNUNET_DISK_directory_remove (dn)))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "rmdir", dn);
  GNUNET_free (dn);
}


/**
 * Serialize a 'start_time'.  Since we use start-times to
 * calculate the duration of some operation, we actually
 * do not serialize the absolute time but the (relative)
 * duration since the start time.  When we then
 * deserialize the start time, we take the current time and
 * subtract that duration so that we get again an absolute
 * time stamp that will result in correct performance
 * calculations.
 *
 * @param wh handle for writing
 * @param timestamp time to serialize
 * @return GNUNET_OK on success
 */
static int
write_start_time (struct GNUNET_BIO_WriteHandle *wh,
                  struct GNUNET_TIME_Absolute timestamp)
{
  struct GNUNET_TIME_Relative dur;

  dur = GNUNET_TIME_absolute_get_duration (timestamp);
  return GNUNET_BIO_write_int64 (wh, dur.rel_value);
}


/**
 * Serialize a 'start_time'.  Since we use start-times to
 * calculate the duration of some operation, we actually
 * do not serialize the absolute time but the (relative)
 * duration since the start time.  When we then
 * deserialize the start time, we take the current time and
 * subtract that duration so that we get again an absolute
 * time stamp that will result in correct performance
 * calculations.
 *
 * @param rh handle for reading
 * @param timestamp where to write the deserialized timestamp
 * @return GNUNET_OK on success
 */
static int
read_start_time (struct GNUNET_BIO_ReadHandle *rh,
                 struct GNUNET_TIME_Absolute *timestamp)
{
  struct GNUNET_TIME_Relative dur;

  if (GNUNET_OK != GNUNET_BIO_read_int64 (rh, &dur.rel_value))
    return GNUNET_SYSERR;
  *timestamp = GNUNET_TIME_absolute_subtract (GNUNET_TIME_absolute_get (), dur);
  return GNUNET_OK;
}


/**
 * Using the given serialization filename, try to deserialize
 * the file-information tree associated with it.
 *
 * @param h master context
 * @param filename name of the file (without directory) with
 *        the infromation
 * @return NULL on error
 */
static struct GNUNET_FS_FileInformation *
deserialize_file_information (struct GNUNET_FS_Handle *h, const char *filename);


/**
 * Using the given serialization filename, try to deserialize
 * the file-information tree associated with it.
 *
 * @param h master context
 * @param fn name of the file (without directory) with
 *        the infromation
 * @param rh handle for reading
 * @return NULL on error
 */
static struct GNUNET_FS_FileInformation *
deserialize_fi_node (struct GNUNET_FS_Handle *h, const char *fn,
                     struct GNUNET_BIO_ReadHandle *rh)
{
  struct GNUNET_FS_FileInformation *ret;
  struct GNUNET_FS_FileInformation *nxt;
  char b;
  char *ksks;
  char *chks;
  char *filename;
  uint32_t dsize;

  if (GNUNET_OK != GNUNET_BIO_read (rh, "status flag", &b, sizeof (b)))
  {
    GNUNET_break (0);
    return NULL;
  }
  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_FileInformation));
  ret->h = h;
  ksks = NULL;
  chks = NULL;
  filename = NULL;
  if ((GNUNET_OK != GNUNET_BIO_read_meta_data (rh, "metadata", &ret->meta)) ||
      (GNUNET_OK != GNUNET_BIO_read_string (rh, "ksk-uri", &ksks, 32 * 1024)) ||
      ( (NULL != ksks) &&
	( (NULL == (ret->keywords = GNUNET_FS_uri_parse (ksks, NULL))) ||
	  (GNUNET_YES != GNUNET_FS_uri_test_ksk (ret->keywords)) ) ) ||
      (GNUNET_OK != GNUNET_BIO_read_string (rh, "chk-uri", &chks, 1024)) ||
      ( (NULL != chks) &&
	( (NULL == (ret->chk_uri = GNUNET_FS_uri_parse (chks, NULL))) ||
	  (GNUNET_YES != GNUNET_FS_uri_test_chk (ret->chk_uri))) ) ||
      (GNUNET_OK != read_start_time (rh, &ret->start_time)) ||
      (GNUNET_OK != GNUNET_BIO_read_string (rh, "emsg", &ret->emsg, 16 * 1024))
      || (GNUNET_OK !=
          GNUNET_BIO_read_string (rh, "fn", &ret->filename, 16 * 1024)) ||
      (GNUNET_OK !=
       GNUNET_BIO_read_int64 (rh, &ret->bo.expiration_time.abs_value)) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &ret->bo.anonymity_level)) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &ret->bo.content_priority)) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &ret->bo.replication_level)))
  {
    GNUNET_break (0);
    goto cleanup;
  }
  switch (b)
  {
  case 0:                      /* file-insert */
    if (GNUNET_OK != GNUNET_BIO_read_int64 (rh, &ret->data.file.file_size))
    {
      GNUNET_break (0);
      goto cleanup;
    }
    ret->is_directory = GNUNET_NO;
    ret->data.file.do_index = GNUNET_NO;
    ret->data.file.have_hash = GNUNET_NO;
    ret->data.file.index_start_confirmed = GNUNET_NO;
    if (GNUNET_NO == ret->is_published)
    {
      if (NULL == ret->filename)
      {
        ret->data.file.reader = &GNUNET_FS_data_reader_copy_;
        ret->data.file.reader_cls =
            GNUNET_malloc_large (ret->data.file.file_size);
        if (ret->data.file.reader_cls == NULL)
          goto cleanup;
        if (GNUNET_OK !=
            GNUNET_BIO_read (rh, "file-data", ret->data.file.reader_cls,
                             ret->data.file.file_size))
        {
          GNUNET_break (0);
          goto cleanup;
        }
      }
      else
      {
        ret->data.file.reader = &GNUNET_FS_data_reader_file_;
        ret->data.file.reader_cls =
            GNUNET_FS_make_file_reader_context_ (ret->filename);
      }
    }
    break;
  case 1:                      /* file-index, no hash */
    if (NULL == ret->filename)
    {
      GNUNET_break (0);
      goto cleanup;
    }
    if (GNUNET_OK != GNUNET_BIO_read_int64 (rh, &ret->data.file.file_size))
    {
      GNUNET_break (0);
      goto cleanup;
    }
    ret->is_directory = GNUNET_NO;
    ret->data.file.do_index = GNUNET_YES;
    ret->data.file.have_hash = GNUNET_NO;
    ret->data.file.index_start_confirmed = GNUNET_NO;
    ret->data.file.reader = &GNUNET_FS_data_reader_file_;
    ret->data.file.reader_cls =
        GNUNET_FS_make_file_reader_context_ (ret->filename);
    break;
  case 2:                      /* file-index-with-hash */
    if (NULL == ret->filename)
    {
      GNUNET_break (0);
      goto cleanup;
    }
    if ((GNUNET_OK != GNUNET_BIO_read_int64 (rh, &ret->data.file.file_size)) ||
        (GNUNET_OK !=
         GNUNET_BIO_read (rh, "fileid", &ret->data.file.file_id,
                          sizeof (GNUNET_HashCode))))
    {
      GNUNET_break (0);
      goto cleanup;
    }
    ret->is_directory = GNUNET_NO;
    ret->data.file.do_index = GNUNET_YES;
    ret->data.file.have_hash = GNUNET_YES;
    ret->data.file.index_start_confirmed = GNUNET_NO;
    ret->data.file.reader = &GNUNET_FS_data_reader_file_;
    ret->data.file.reader_cls =
        GNUNET_FS_make_file_reader_context_ (ret->filename);
    break;
  case 3:                      /* file-index-with-hash-confirmed */
    if (NULL == ret->filename)
    {
      GNUNET_break (0);
      goto cleanup;
    }
    if ((GNUNET_OK != GNUNET_BIO_read_int64 (rh, &ret->data.file.file_size)) ||
        (GNUNET_OK !=
         GNUNET_BIO_read (rh, "fileid", &ret->data.file.file_id,
                          sizeof (GNUNET_HashCode))))
    {
      GNUNET_break (0);
      goto cleanup;
    }
    ret->is_directory = GNUNET_NO;
    ret->data.file.do_index = GNUNET_YES;
    ret->data.file.have_hash = GNUNET_YES;
    ret->data.file.index_start_confirmed = GNUNET_YES;
    ret->data.file.reader = &GNUNET_FS_data_reader_file_;
    ret->data.file.reader_cls =
        GNUNET_FS_make_file_reader_context_ (ret->filename);
    break;
  case 4:                      /* directory */
    ret->is_directory = GNUNET_YES;
    if ((GNUNET_OK != GNUNET_BIO_read_int32 (rh, &dsize)) ||
        (NULL == (ret->data.dir.dir_data = GNUNET_malloc_large (dsize))) ||
        (GNUNET_OK !=
         GNUNET_BIO_read (rh, "dir-data", ret->data.dir.dir_data, dsize)) ||
        (GNUNET_OK !=
         GNUNET_BIO_read_string (rh, "ent-filename", &filename, 16 * 1024)))
    {
      GNUNET_break (0);
      goto cleanup;
    }
    ret->data.dir.dir_size = (uint32_t) dsize;
    if (filename != NULL)
    {
      ret->data.dir.entries = deserialize_file_information (h, filename);
      GNUNET_free (filename);
      filename = NULL;
      nxt = ret->data.dir.entries;
      while (nxt != NULL)
      {
        nxt->dir = ret;
        nxt = nxt->next;
      }
    }
    break;
  default:
    GNUNET_break (0);
    goto cleanup;
  }
  ret->serialization = GNUNET_strdup (fn);
  if (GNUNET_OK !=
      GNUNET_BIO_read_string (rh, "nxt-filename", &filename, 16 * 1024))
  {
    GNUNET_break (0);
    goto cleanup;
  }
  if (filename != NULL)
  {
    ret->next = deserialize_file_information (h, filename);
    GNUNET_free (filename);
    filename = NULL;
  }
  GNUNET_free_non_null (ksks);
  GNUNET_free_non_null (chks);
  return ret;
cleanup:
  GNUNET_free_non_null (ksks);
  GNUNET_free_non_null (chks);
  GNUNET_free_non_null (filename);
  GNUNET_FS_file_information_destroy (ret, NULL, NULL);
  return NULL;
}


/**
 * Using the given serialization filename, try to deserialize
 * the file-information tree associated with it.
 *
 * @param h master context
 * @param filename name of the file (without directory) with
 *        the infromation
 * @return NULL on error
 */
static struct GNUNET_FS_FileInformation *
deserialize_file_information (struct GNUNET_FS_Handle *h, const char *filename)
{
  struct GNUNET_FS_FileInformation *ret;
  struct GNUNET_BIO_ReadHandle *rh;
  char *emsg;

  rh = get_read_handle (h, GNUNET_FS_SYNC_PATH_FILE_INFO, filename);
  if (rh == NULL)
    return NULL;
  ret = deserialize_fi_node (h, filename, rh);
  if (GNUNET_OK != GNUNET_BIO_read_close (rh, &emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to resume publishing information `%s': %s\n"),
                filename, emsg);
    GNUNET_free (emsg);
  }
  if (ret == NULL)
  {
    if (0 != UNLINK (filename))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", filename);
  }
  return ret;
}


/**
 * Given a serialization name (full absolute path), return the
 * basename of the file (without the path), which must only
 * consist of the 6 random characters.
 *
 * @param fullname name to extract the basename from
 * @return copy of the basename, NULL on error
 */
static char *
get_serialization_short_name (const char *fullname)
{
  const char *end;
  const char *nxt;

  end = NULL;
  nxt = fullname;
  /* FIXME: we could do this faster since we know
   * the length of 'end'... */
  while ('\0' != *nxt)
  {
    if (DIR_SEPARATOR == *nxt)
      end = nxt + 1;
    nxt++;
  }
  if ((end == NULL) || (strlen (end) == 0))
  {
    GNUNET_break (0);
    return NULL;
  }
  GNUNET_break (6 == strlen (end));
  return GNUNET_strdup (end);
}


/**
 * Create a new random name for serialization.  Also checks if persistence
 * is enabled and returns NULL if not.
 *
 * @param h master context
 * @param ext component of the path
 * @return NULL on errror
 */
static char *
make_serialization_file_name (struct GNUNET_FS_Handle *h, const char *ext)
{
  char *fn;
  char *dn;
  char *ret;

  if (0 == (h->flags & GNUNET_FS_FLAGS_PERSISTENCE))
    return NULL;                /* persistence not requested */
  dn = get_serialization_file_name (h, ext, "");
  if (dn == NULL)
    return NULL;
  if (GNUNET_OK != GNUNET_DISK_directory_create_for_file (dn))
  {
    GNUNET_free (dn);
    return NULL;
  }
  fn = GNUNET_DISK_mktemp (dn);
  GNUNET_free (dn);
  if (fn == NULL)
    return NULL;                /* epic fail */
  ret = get_serialization_short_name (fn);
  GNUNET_free (fn);
  return ret;
}


/**
 * Create a new random name for serialization.  Also checks if persistence
 * is enabled and returns NULL if not.
 *
 * @param h master context
 * @param ext component of the path
 * @param uni name of parent
 * @return NULL on errror
 */
static char *
make_serialization_file_name_in_dir (struct GNUNET_FS_Handle *h,
                                     const char *ext, const char *uni)
{
  char *fn;
  char *dn;
  char *ret;

  if (0 == (h->flags & GNUNET_FS_FLAGS_PERSISTENCE))
    return NULL;                /* persistence not requested */
  dn = get_serialization_file_name_in_dir (h, ext, uni, "");
  if (dn == NULL)
    return NULL;
  if (GNUNET_OK != GNUNET_DISK_directory_create_for_file (dn))
  {
    GNUNET_free (dn);
    return NULL;
  }
  fn = GNUNET_DISK_mktemp (dn);
  GNUNET_free (dn);
  if (fn == NULL)
    return NULL;                /* epic fail */
  ret = get_serialization_short_name (fn);
  GNUNET_free (fn);
  return ret;
}


/**
 * Copy all of the data from the reader to the write handle.
 *
 * @param wh write handle
 * @param fi file with reader
 * @return GNUNET_OK on success
 */
static int
copy_from_reader (struct GNUNET_BIO_WriteHandle *wh,
                  struct GNUNET_FS_FileInformation *fi)
{
  char buf[32 * 1024];
  uint64_t off;
  size_t ret;
  size_t left;
  char *emsg;

  emsg = NULL;
  off = 0;
  while (off < fi->data.file.file_size)
  {
    left = GNUNET_MIN (sizeof (buf), fi->data.file.file_size - off);
    ret =
        fi->data.file.reader (fi->data.file.reader_cls, off, left, buf, &emsg);
    if (ret == 0)
    {
      GNUNET_free (emsg);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != GNUNET_BIO_write (wh, buf, ret))
      return GNUNET_SYSERR;
    off += ret;
  }
  return GNUNET_OK;
}


/**
 * Create a temporary file on disk to store the current
 * state of "fi" in.
 *
 * @param fi file information to sync with disk
 */
void
GNUNET_FS_file_information_sync_ (struct GNUNET_FS_FileInformation *fi)
{
  char *fn;
  struct GNUNET_BIO_WriteHandle *wh;
  char b;
  char *ksks;
  char *chks;

  if (NULL == fi->serialization)
    fi->serialization =
        make_serialization_file_name (fi->h, GNUNET_FS_SYNC_PATH_FILE_INFO);
  if (NULL == fi->serialization)
    return;
  wh = get_write_handle (fi->h, GNUNET_FS_SYNC_PATH_FILE_INFO,
                         fi->serialization);
  if (wh == NULL)
  {
    GNUNET_free (fi->serialization);
    fi->serialization = NULL;
    return;
  }
  if (GNUNET_YES == fi->is_directory)
    b = 4;
  else if (GNUNET_YES == fi->data.file.index_start_confirmed)
    b = 3;
  else if (GNUNET_YES == fi->data.file.have_hash)
    b = 2;
  else if (GNUNET_YES == fi->data.file.do_index)
    b = 1;
  else
    b = 0;
  if (fi->keywords != NULL)
    ksks = GNUNET_FS_uri_to_string (fi->keywords);
  else
    ksks = NULL;
  if (fi->chk_uri != NULL)
    chks = GNUNET_FS_uri_to_string (fi->chk_uri);
  else
    chks = NULL;
  if ((GNUNET_OK != GNUNET_BIO_write (wh, &b, sizeof (b))) ||
      (GNUNET_OK != GNUNET_BIO_write_meta_data (wh, fi->meta)) ||
      (GNUNET_OK != GNUNET_BIO_write_string (wh, ksks)) ||
      (GNUNET_OK != GNUNET_BIO_write_string (wh, chks)) ||
      (GNUNET_OK != write_start_time (wh, fi->start_time)) ||
      (GNUNET_OK != GNUNET_BIO_write_string (wh, fi->emsg)) ||
      (GNUNET_OK != GNUNET_BIO_write_string (wh, fi->filename)) ||
      (GNUNET_OK !=
       GNUNET_BIO_write_int64 (wh, fi->bo.expiration_time.abs_value)) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, fi->bo.anonymity_level)) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, fi->bo.content_priority)) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, fi->bo.replication_level)))
  {
    GNUNET_break (0);
    goto cleanup;
  }
  GNUNET_free_non_null (chks);
  chks = NULL;
  GNUNET_free_non_null (ksks);
  ksks = NULL;

  switch (b)
  {
  case 0:                      /* file-insert */
    if (GNUNET_OK != GNUNET_BIO_write_int64 (wh, fi->data.file.file_size))
    {
      GNUNET_break (0);
      goto cleanup;
    }
    if ((GNUNET_NO == fi->is_published) && (NULL == fi->filename))
      if (GNUNET_OK != copy_from_reader (wh, fi))
      {
        GNUNET_break (0);
        goto cleanup;
      }
    break;
  case 1:                      /* file-index, no hash */
    if (NULL == fi->filename)
    {
      GNUNET_break (0);
      goto cleanup;
    }
    if (GNUNET_OK != GNUNET_BIO_write_int64 (wh, fi->data.file.file_size))
    {
      GNUNET_break (0);
      goto cleanup;
    }
    break;
  case 2:                      /* file-index-with-hash */
  case 3:                      /* file-index-with-hash-confirmed */
    if (NULL == fi->filename)
    {
      GNUNET_break (0);
      goto cleanup;
    }
    if ((GNUNET_OK != GNUNET_BIO_write_int64 (wh, fi->data.file.file_size)) ||
        (GNUNET_OK !=
         GNUNET_BIO_write (wh, &fi->data.file.file_id,
                           sizeof (GNUNET_HashCode))))
    {
      GNUNET_break (0);
      goto cleanup;
    }
    break;
  case 4:                      /* directory */
    if ((GNUNET_OK != GNUNET_BIO_write_int32 (wh, fi->data.dir.dir_size)) ||
        (GNUNET_OK !=
         GNUNET_BIO_write (wh, fi->data.dir.dir_data,
                           (uint32_t) fi->data.dir.dir_size)) ||
        (GNUNET_OK !=
         GNUNET_BIO_write_string (wh,
                                  (fi->data.dir.entries ==
                                   NULL) ? NULL : fi->data.dir.
                                  entries->serialization)))
    {
      GNUNET_break (0);
      goto cleanup;
    }
    break;
  default:
    GNUNET_assert (0);
    goto cleanup;
  }
  if (GNUNET_OK !=
      GNUNET_BIO_write_string (wh,
                               (fi->next !=
                                NULL) ? fi->next->serialization : NULL))
  {
    GNUNET_break (0);
    goto cleanup;
  }
  if (GNUNET_OK != GNUNET_BIO_write_close (wh))
  {
    wh = NULL;
    GNUNET_break (0);
    goto cleanup;
  }
  return;                       /* done! */
cleanup:
  if (wh != NULL)
    (void) GNUNET_BIO_write_close (wh);
  GNUNET_free_non_null (chks);
  GNUNET_free_non_null (ksks);
  fn = get_serialization_file_name (fi->h, GNUNET_FS_SYNC_PATH_FILE_INFO,
                                    fi->serialization);
  if (NULL != fn)
  {
    if (0 != UNLINK (fn))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
    GNUNET_free (fn);
  }
  GNUNET_free (fi->serialization);
  fi->serialization = NULL;
}



/**
 * Find the entry in the file information struct where the
 * serialization filename matches the given name.
 *
 * @param pos file information to search
 * @param srch filename to search for
 * @return NULL if srch was not found in this subtree
 */
static struct GNUNET_FS_FileInformation *
find_file_position (struct GNUNET_FS_FileInformation *pos, const char *srch)
{
  struct GNUNET_FS_FileInformation *r;

  while (pos != NULL)
  {
    if (0 == strcmp (srch, pos->serialization))
      return pos;
    if (pos->is_directory == GNUNET_YES)
    {
      r = find_file_position (pos->data.dir.entries, srch);
      if (r != NULL)
        return r;
    }
    pos = pos->next;
  }
  return NULL;
}


/**
 * Signal the FS's progress function that we are resuming
 * an upload.
 *
 * @param cls closure (of type "struct GNUNET_FS_PublishContext*")
 * @param fi the entry in the publish-structure
 * @param length length of the file or directory
 * @param meta metadata for the file or directory (can be modified)
 * @param uri pointer to the keywords that will be used for this entry (can be modified)
 * @param bo block options (can be modified)
 * @param do_index should we index?
 * @param client_info pointer to client context set upon creation (can be modified)
 * @return GNUNET_OK to continue (always)
 */
static int
fip_signal_resume (void *cls, struct GNUNET_FS_FileInformation *fi,
                   uint64_t length, struct GNUNET_CONTAINER_MetaData *meta,
                   struct GNUNET_FS_Uri **uri,
                   struct GNUNET_FS_BlockOptions *bo, int *do_index,
                   void **client_info)
{
  struct GNUNET_FS_PublishContext *pc = cls;
  struct GNUNET_FS_ProgressInfo pi;

  if (GNUNET_YES == pc->skip_next_fi_callback)
  {
    pc->skip_next_fi_callback = GNUNET_NO;
    return GNUNET_OK;
  }
  pi.status = GNUNET_FS_STATUS_PUBLISH_RESUME;
  pi.value.publish.specifics.resume.message = pc->fi->emsg;
  pi.value.publish.specifics.resume.chk_uri = pc->fi->chk_uri;
  *client_info = GNUNET_FS_publish_make_status_ (&pi, pc, fi, 0);
  if (GNUNET_YES == GNUNET_FS_meta_data_test_for_directory (meta))
  {
    /* process entries in directory */
    pc->skip_next_fi_callback = GNUNET_YES;
    GNUNET_FS_file_information_inspect (fi, &fip_signal_resume, pc);
  }
  return GNUNET_OK;
}


/**
 * Function called with a filename of serialized publishing operation
 * to deserialize.
 *
 * @param cls the 'struct GNUNET_FS_Handle*'
 * @param filename complete filename (absolute path)
 * @return GNUNET_OK (continue to iterate)
 */
static int
deserialize_publish_file (void *cls, const char *filename)
{
  struct GNUNET_FS_Handle *h = cls;
  struct GNUNET_BIO_ReadHandle *rh;
  struct GNUNET_FS_PublishContext *pc;
  int32_t options;
  int32_t all_done;
  char *fi_root;
  char *ns;
  char *fi_pos;
  char *emsg;

  pc = GNUNET_malloc (sizeof (struct GNUNET_FS_PublishContext));
  pc->h = h;
  pc->serialization = get_serialization_short_name (filename);
  fi_root = NULL;
  fi_pos = NULL;
  ns = NULL;
  rh = GNUNET_BIO_read_open (filename);
  if (rh == NULL)
  {
    GNUNET_break (0);
    goto cleanup;
  }
  if ((GNUNET_OK != GNUNET_BIO_read_string (rh, "publish-nid", &pc->nid, 1024))
      || (GNUNET_OK !=
          GNUNET_BIO_read_string (rh, "publish-nuid", &pc->nuid, 1024)) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &options)) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &all_done)) ||
      (GNUNET_OK !=
       GNUNET_BIO_read_string (rh, "publish-firoot", &fi_root, 128)) ||
      (GNUNET_OK != GNUNET_BIO_read_string (rh, "publish-fipos", &fi_pos, 128))
      || (GNUNET_OK != GNUNET_BIO_read_string (rh, "publish-ns", &ns, 1024)))
  {
    GNUNET_break (0);
    goto cleanup;
  }
  pc->options = options;
  pc->all_done = all_done;
  if (NULL == fi_root)
  {
    GNUNET_break (0);
    goto cleanup;
  }
  pc->fi = deserialize_file_information (h, fi_root);
  if (pc->fi == NULL)
  {
    GNUNET_break (0);
    goto cleanup;
  }
  if (ns != NULL)
  {
    pc->namespace = GNUNET_FS_namespace_create (h, ns);
    if (pc->namespace == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Failed to recover namespace `%s', cannot resume publishing operation.\n"),
                  ns);
      goto cleanup;
    }
  }
  if ((0 == (pc->options & GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY)) &&
      (GNUNET_YES != pc->all_done))
  {
    pc->dsh = GNUNET_DATASTORE_connect (h->cfg);
    if (NULL == pc->dsh)
      goto cleanup;
  }
  if (fi_pos != NULL)
  {
    pc->fi_pos = find_file_position (pc->fi, fi_pos);
    GNUNET_free (fi_pos);
    fi_pos = NULL;
    if (pc->fi_pos == NULL)
    {
      /* failed to find position for resuming, outch! Will start from root! */
      GNUNET_break (0);
      if (pc->all_done != GNUNET_YES)
        pc->fi_pos = pc->fi;
    }
  }
  GNUNET_free (fi_root);
  fi_root = NULL;
  /* generate RESUME event(s) */
  GNUNET_FS_file_information_inspect (pc->fi, &fip_signal_resume, pc);

  /* re-start publishing (if needed)... */
  if (pc->all_done != GNUNET_YES)
  {
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == pc->upload_task);
    pc->upload_task =
        GNUNET_SCHEDULER_add_with_priority
        (GNUNET_SCHEDULER_PRIORITY_BACKGROUND, 
	 &GNUNET_FS_publish_main_, pc);
  }
  if (GNUNET_OK != GNUNET_BIO_read_close (rh, &emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failure while resuming publishing operation `%s': %s\n"),
                filename, emsg);
    GNUNET_free (emsg);
  }
  GNUNET_free_non_null (ns);
  pc->top = GNUNET_FS_make_top (h, &GNUNET_FS_publish_signal_suspend_, pc);
  return GNUNET_OK;
cleanup:
  GNUNET_free_non_null (pc->nid);
  GNUNET_free_non_null (pc->nuid);
  GNUNET_free_non_null (fi_root);
  GNUNET_free_non_null (fi_pos);
  GNUNET_free_non_null (ns);
  if ((rh != NULL) && (GNUNET_OK != GNUNET_BIO_read_close (rh, &emsg)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to resume publishing operation `%s': %s\n"), filename,
                emsg);
    GNUNET_free (emsg);
  }
  if (pc->fi != NULL)
    GNUNET_FS_file_information_destroy (pc->fi, NULL, NULL);
  if (0 != UNLINK (filename))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", filename);
  GNUNET_free (pc->serialization);
  GNUNET_free (pc);
  return GNUNET_OK;
}


/**
 * Synchronize this publishing struct with its mirror
 * on disk.  Note that all internal FS-operations that change
 * publishing structs should already call "sync" internally,
 * so this function is likely not useful for clients.
 *
 * @param pc the struct to sync
 */
void
GNUNET_FS_publish_sync_ (struct GNUNET_FS_PublishContext *pc)
{
  struct GNUNET_BIO_WriteHandle *wh;

  if (NULL == pc->serialization)
    pc->serialization =
        make_serialization_file_name (pc->h,
                                      GNUNET_FS_SYNC_PATH_MASTER_PUBLISH);
  if (NULL == pc->serialization)
    return;
  if (NULL == pc->fi)
    return;
  if (NULL == pc->fi->serialization)
  {
    GNUNET_break (0);
    return;
  }
  wh = get_write_handle (pc->h, GNUNET_FS_SYNC_PATH_MASTER_PUBLISH,
                         pc->serialization);
  if (wh == NULL)
  {
    GNUNET_break (0);
    goto cleanup;
  }
  if ((GNUNET_OK != GNUNET_BIO_write_string (wh, pc->nid)) ||
      (GNUNET_OK != GNUNET_BIO_write_string (wh, pc->nuid)) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, pc->options)) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, pc->all_done)) ||
      (GNUNET_OK != GNUNET_BIO_write_string (wh, pc->fi->serialization)) ||
      (GNUNET_OK !=
       GNUNET_BIO_write_string (wh,
                                (pc->fi_pos ==
                                 NULL) ? NULL : pc->fi_pos->serialization)) ||
      (GNUNET_OK !=
       GNUNET_BIO_write_string (wh,
                                (pc->namespace ==
                                 NULL) ? NULL : pc->namespace->name)))
  {
    GNUNET_break (0);
    goto cleanup;
  }
  if (GNUNET_OK != GNUNET_BIO_write_close (wh))
  {
    wh = NULL;
    GNUNET_break (0);
    goto cleanup;
  }
  return;
cleanup:
  if (wh != NULL)
    (void) GNUNET_BIO_write_close (wh);
  GNUNET_FS_remove_sync_file_ (pc->h, GNUNET_FS_SYNC_PATH_MASTER_PUBLISH,
                               pc->serialization);
  GNUNET_free (pc->serialization);
  pc->serialization = NULL;
}


/**
 * Synchronize this unindex struct with its mirror
 * on disk.  Note that all internal FS-operations that change
 * publishing structs should already call "sync" internally,
 * so this function is likely not useful for clients.
 *
 * @param uc the struct to sync
 */
void
GNUNET_FS_unindex_sync_ (struct GNUNET_FS_UnindexContext *uc)
{
  struct GNUNET_BIO_WriteHandle *wh;

  if (NULL == uc->serialization)
    uc->serialization =
        make_serialization_file_name (uc->h,
                                      GNUNET_FS_SYNC_PATH_MASTER_UNINDEX);
  if (NULL == uc->serialization)
    return;
  wh = get_write_handle (uc->h, GNUNET_FS_SYNC_PATH_MASTER_UNINDEX,
                         uc->serialization);
  if (wh == NULL)
  {
    GNUNET_break (0);
    goto cleanup;
  }
  if ((GNUNET_OK != GNUNET_BIO_write_string (wh, uc->filename)) ||
      (GNUNET_OK != GNUNET_BIO_write_int64 (wh, uc->file_size)) ||
      (GNUNET_OK != write_start_time (wh, uc->start_time)) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, (uint32_t) uc->state)) ||
      ((uc->state == UNINDEX_STATE_FS_NOTIFY) &&
       (GNUNET_OK !=
        GNUNET_BIO_write (wh, &uc->file_id, sizeof (GNUNET_HashCode)))) ||
      ((uc->state == UNINDEX_STATE_ERROR) &&
       (GNUNET_OK != GNUNET_BIO_write_string (wh, uc->emsg))))
  {
    GNUNET_break (0);
    goto cleanup;
  }
  if (GNUNET_OK != GNUNET_BIO_write_close (wh))
  {
    wh = NULL;
    GNUNET_break (0);
    goto cleanup;
  }
  return;
cleanup:
  if (wh != NULL)
    (void) GNUNET_BIO_write_close (wh);
  GNUNET_FS_remove_sync_file_ (uc->h, GNUNET_FS_SYNC_PATH_MASTER_UNINDEX,
                               uc->serialization);
  GNUNET_free (uc->serialization);
  uc->serialization = NULL;
}


/**
 * Serialize a download request.
 *
 * @param wh the 'struct GNUNET_BIO_WriteHandle*'
 * @param dr the 'struct DownloadRequest'
 * @return GNUNET_YES on success, GNUNET_NO on error
 */
static int
write_download_request (struct GNUNET_BIO_WriteHandle *wh,
                        struct DownloadRequest *dr)
{
  unsigned int i;

  if ((GNUNET_OK != GNUNET_BIO_write_int32 (wh, dr->state)) ||
      (GNUNET_OK != GNUNET_BIO_write_int64 (wh, dr->offset)) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, dr->num_children)) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, dr->depth)))
    return GNUNET_NO;
  if ((dr->state == BRS_CHK_SET) &&
      (GNUNET_OK !=
       GNUNET_BIO_write (wh, &dr->chk, sizeof (struct ContentHashKey))))
    return GNUNET_NO;
  for (i = 0; i < dr->num_children; i++)
    if (GNUNET_NO == write_download_request (wh, dr->children[i]))
      return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Read a download request tree.
 *
 * @param rh stream to read from
 * @return value the 'struct DownloadRequest', NULL on error
 */
static struct DownloadRequest *
read_download_request (struct GNUNET_BIO_ReadHandle *rh)
{
  struct DownloadRequest *dr;
  unsigned int i;

  dr = GNUNET_malloc (sizeof (struct DownloadRequest));

  if ((GNUNET_OK != GNUNET_BIO_read_int32 (rh, &dr->state)) ||
      (GNUNET_OK != GNUNET_BIO_read_int64 (rh, &dr->offset)) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &dr->num_children)) ||
      (dr->num_children > CHK_PER_INODE) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &dr->depth)) || ((dr->depth == 0)
                                                                &&
                                                                (dr->num_children
                                                                 > 0)) ||
      ((dr->depth > 0) && (dr->num_children == 0)))
  {
    GNUNET_break (0);
    dr->num_children = 0;
    goto cleanup;
  }
  if (dr->num_children > 0)
    dr->children =
        GNUNET_malloc (dr->num_children * sizeof (struct ContentHashKey));
  switch (dr->state)
  {
  case BRS_INIT:
  case BRS_RECONSTRUCT_DOWN:
  case BRS_RECONSTRUCT_META_UP:
  case BRS_RECONSTRUCT_UP:
    break;
  case BRS_CHK_SET:
    if (GNUNET_OK !=
        GNUNET_BIO_read (rh, "chk", &dr->chk, sizeof (struct ContentHashKey)))
      goto cleanup;
    break;
  case BRS_DOWNLOAD_DOWN:
  case BRS_DOWNLOAD_UP:
  case BRS_ERROR:
    break;
  default:
    GNUNET_break (0);
    goto cleanup;
  }
  for (i = 0; i < dr->num_children; i++)
  {
    if (NULL == (dr->children[i] = read_download_request (rh)))
      goto cleanup;
    dr->children[i]->parent = dr;
  }
  return dr;
cleanup:
  GNUNET_FS_free_download_request_ (dr);
  return NULL;
}


/**
 * Compute the name of the sync file (or directory) for the given download
 * context.
 *
 * @param dc download context to compute for
 * @param uni unique filename to use, use "" for the directory name
 * @param ext extension to use, use ".dir" for our own subdirectory
 * @return the expanded file name, NULL for none
 */
static char *
get_download_sync_filename (struct GNUNET_FS_DownloadContext *dc,
                            const char *uni, const char *ext)
{
  char *par;
  char *epar;

  if (dc->parent == NULL)
    return get_serialization_file_name (dc->h,
                                        (dc->search !=
                                         NULL) ?
                                        GNUNET_FS_SYNC_PATH_CHILD_DOWNLOAD :
                                        GNUNET_FS_SYNC_PATH_MASTER_DOWNLOAD,
                                        uni);
  if (dc->parent->serialization == NULL)
    return NULL;
  par = get_download_sync_filename (dc->parent, dc->parent->serialization, "");
  if (par == NULL)
    return NULL;
  GNUNET_asprintf (&epar, "%s.dir%s%s%s", par, DIR_SEPARATOR_STR, uni, ext);
  GNUNET_free (par);
  return epar;
}


/**
 * Synchronize this download struct with its mirror
 * on disk.  Note that all internal FS-operations that change
 * publishing structs should already call "sync" internally,
 * so this function is likely not useful for clients.
 *
 * @param dc the struct to sync
 */
void
GNUNET_FS_download_sync_ (struct GNUNET_FS_DownloadContext *dc)
{
  struct GNUNET_BIO_WriteHandle *wh;
  char *uris;
  char *fn;
  char *dir;

  if (NULL == dc->serialization)
  {
    dir = get_download_sync_filename (dc, "", "");
    if (dir == NULL)
      return;
    if (GNUNET_OK != GNUNET_DISK_directory_create_for_file (dir))
    {
      GNUNET_free (dir);
      return;
    }
    fn = GNUNET_DISK_mktemp (dir);
    GNUNET_free (dir);
    if (fn == NULL)
      return;
    dc->serialization = get_serialization_short_name (fn);
  }
  else
  {
    fn = get_download_sync_filename (dc, dc->serialization, "");
    if (fn == NULL)
    {
      GNUNET_free (dc->serialization);
      dc->serialization = NULL;
      GNUNET_free (fn);
      return;
    }
  }
  wh = GNUNET_BIO_write_open (fn);
  if (wh == NULL)
  {
    GNUNET_free (dc->serialization);
    dc->serialization = NULL;
    GNUNET_free (fn);
    return;
  }
  GNUNET_assert ((GNUNET_YES == GNUNET_FS_uri_test_chk (dc->uri)) ||
                 (GNUNET_YES == GNUNET_FS_uri_test_loc (dc->uri)));
  uris = GNUNET_FS_uri_to_string (dc->uri);
  if ((GNUNET_OK != GNUNET_BIO_write_string (wh, uris)) ||
      (GNUNET_OK != GNUNET_BIO_write_meta_data (wh, dc->meta)) ||
      (GNUNET_OK != GNUNET_BIO_write_string (wh, dc->emsg)) ||
      (GNUNET_OK != GNUNET_BIO_write_string (wh, dc->filename)) ||
      (GNUNET_OK != GNUNET_BIO_write_string (wh, dc->temp_filename)) ||
      (GNUNET_OK != GNUNET_BIO_write_int64 (wh, dc->old_file_size)) ||
      (GNUNET_OK != GNUNET_BIO_write_int64 (wh, dc->offset)) ||
      (GNUNET_OK != GNUNET_BIO_write_int64 (wh, dc->length)) ||
      (GNUNET_OK != GNUNET_BIO_write_int64 (wh, dc->completed)) ||
      (GNUNET_OK != write_start_time (wh, dc->start_time)) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, dc->anonymity)) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, (uint32_t) dc->options)) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, (uint32_t) dc->has_finished)))
  {
    GNUNET_break (0);
    goto cleanup;
  }
  if (NULL == dc->emsg)
  {
    GNUNET_assert (dc->top_request != NULL);
    if (GNUNET_YES != write_download_request (wh, dc->top_request))
    {
      GNUNET_break (0);
      goto cleanup;
    }
  }
  GNUNET_free_non_null (uris);
  uris = NULL;
  if (GNUNET_OK != GNUNET_BIO_write_close (wh))
  {
    wh = NULL;
    GNUNET_break (0);
    goto cleanup;
  }
  GNUNET_free (fn);
  return;
cleanup:
  if (NULL != wh)
    (void) GNUNET_BIO_write_close (wh);
  GNUNET_free_non_null (uris);
  if (0 != UNLINK (fn))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
  GNUNET_free (fn);
  GNUNET_free (dc->serialization);
  dc->serialization = NULL;
}


/**
 * Synchronize this search result with its mirror
 * on disk.  Note that all internal FS-operations that change
 * publishing structs should already call "sync" internally,
 * so this function is likely not useful for clients.
 *
 * @param sr the struct to sync
 */
void
GNUNET_FS_search_result_sync_ (struct GNUNET_FS_SearchResult *sr)
{
  struct GNUNET_BIO_WriteHandle *wh;
  char *uris;

  uris = NULL;
  if (NULL == sr->serialization)
    sr->serialization =
        make_serialization_file_name_in_dir (sr->sc->h,
                                             (sr->sc->psearch_result ==
                                              NULL) ?
                                             GNUNET_FS_SYNC_PATH_MASTER_SEARCH :
                                             GNUNET_FS_SYNC_PATH_CHILD_SEARCH,
                                             sr->sc->serialization);
  if (NULL == sr->serialization)
    return;
  wh = get_write_handle_in_dir (sr->sc->h,
                                (sr->sc->psearch_result ==
                                 NULL) ? GNUNET_FS_SYNC_PATH_MASTER_SEARCH :
                                GNUNET_FS_SYNC_PATH_CHILD_SEARCH,
                                sr->sc->serialization, sr->serialization);
  if (wh == NULL)
  {
    GNUNET_break (0);
    goto cleanup;
  }
  uris = GNUNET_FS_uri_to_string (sr->uri);
  if ((GNUNET_OK != GNUNET_BIO_write_string (wh, uris)) ||
      (GNUNET_OK !=
       GNUNET_BIO_write_string (wh,
                                sr->download !=
                                NULL ? sr->download->serialization : NULL)) ||
      (GNUNET_OK !=
       GNUNET_BIO_write_string (wh,
                                sr->update_search !=
                                NULL ? sr->update_search->serialization : NULL))
      || (GNUNET_OK != GNUNET_BIO_write_meta_data (wh, sr->meta)) ||
      (GNUNET_OK != GNUNET_BIO_write (wh, &sr->key, sizeof (GNUNET_HashCode)))
      || (GNUNET_OK != GNUNET_BIO_write_int32 (wh, sr->mandatory_missing)) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, sr->optional_support)) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, sr->availability_success)) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, sr->availability_trials)) )
  {
    GNUNET_break (0);
    goto cleanup;
  }
  if ( (sr->uri != NULL) &&
       (sr->sc->uri->type == ksk) &&
       (GNUNET_OK != GNUNET_BIO_write (wh, sr->keyword_bitmap,
				       (sr->sc->uri->data.ksk.keywordCount + 7) / 8)) )
  {
    GNUNET_break (0);
    goto cleanup;
  }
  if (GNUNET_OK != GNUNET_BIO_write_close (wh))
  {
    wh = NULL;
    GNUNET_break (0);
    goto cleanup;
  }
  GNUNET_free_non_null (uris);
  return;
cleanup:
  GNUNET_free_non_null (uris);
  if (wh != NULL)
    (void) GNUNET_BIO_write_close (wh);
  remove_sync_file_in_dir (sr->sc->h,
                           (sr->sc->psearch_result ==
                            NULL) ? GNUNET_FS_SYNC_PATH_MASTER_SEARCH :
                           GNUNET_FS_SYNC_PATH_CHILD_SEARCH,
                           sr->sc->serialization, sr->serialization);
  GNUNET_free (sr->serialization);
  sr->serialization = NULL;
}


/**
 * Synchronize this search struct with its mirror
 * on disk.  Note that all internal FS-operations that change
 * publishing structs should already call "sync" internally,
 * so this function is likely not useful for clients.
 *
 * @param sc the struct to sync
 */
void
GNUNET_FS_search_sync_ (struct GNUNET_FS_SearchContext *sc)
{
  struct GNUNET_BIO_WriteHandle *wh;
  char *uris;
  char in_pause;
  const char *category;

  category =
      (sc->psearch_result ==
       NULL) ? GNUNET_FS_SYNC_PATH_MASTER_SEARCH :
      GNUNET_FS_SYNC_PATH_CHILD_SEARCH;
  if (NULL == sc->serialization)
    sc->serialization = make_serialization_file_name (sc->h, category);
  if (NULL == sc->serialization)
    return;
  uris = NULL;
  wh = get_write_handle (sc->h, category, sc->serialization);
  if (wh == NULL)
  {
    GNUNET_break (0);
    goto cleanup;
  }
  GNUNET_assert ((GNUNET_YES == GNUNET_FS_uri_test_ksk (sc->uri)) ||
                 (GNUNET_YES == GNUNET_FS_uri_test_sks (sc->uri)));
  uris = GNUNET_FS_uri_to_string (sc->uri);
  in_pause = (sc->task != GNUNET_SCHEDULER_NO_TASK) ? 'r' : '\0';
  if ((GNUNET_OK != GNUNET_BIO_write_string (wh, uris)) ||
      (GNUNET_OK != write_start_time (wh, sc->start_time)) ||
      (GNUNET_OK != GNUNET_BIO_write_string (wh, sc->emsg)) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, (uint32_t) sc->options)) ||
      (GNUNET_OK != GNUNET_BIO_write (wh, &in_pause, sizeof (in_pause))) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (wh, sc->anonymity)))
  {
    GNUNET_break (0);
    goto cleanup;
  }
  GNUNET_free (uris);
  uris = NULL;
  if (GNUNET_OK != GNUNET_BIO_write_close (wh))
  {
    wh = NULL;
    GNUNET_break (0);
    goto cleanup;
  }
  return;
cleanup:
  if (wh != NULL)
    (void) GNUNET_BIO_write_close (wh);
  GNUNET_free_non_null (uris);
  GNUNET_FS_remove_sync_file_ (sc->h, category, sc->serialization);
  GNUNET_free (sc->serialization);
  sc->serialization = NULL;
}


/**
 * Function called with a filename of serialized unindexing operation
 * to deserialize.
 *
 * @param cls the 'struct GNUNET_FS_Handle*'
 * @param filename complete filename (absolute path)
 * @return GNUNET_OK (continue to iterate)
 */
static int
deserialize_unindex_file (void *cls, const char *filename)
{
  struct GNUNET_FS_Handle *h = cls;
  struct GNUNET_BIO_ReadHandle *rh;
  struct GNUNET_FS_UnindexContext *uc;
  struct GNUNET_FS_ProgressInfo pi;
  char *emsg;
  uint32_t state;

  uc = GNUNET_malloc (sizeof (struct GNUNET_FS_UnindexContext));
  uc->h = h;
  uc->serialization = get_serialization_short_name (filename);
  rh = GNUNET_BIO_read_open (filename);
  if (rh == NULL)
  {
    GNUNET_break (0);
    goto cleanup;
  }
  if ((GNUNET_OK !=
       GNUNET_BIO_read_string (rh, "unindex-fn", &uc->filename, 10 * 1024)) ||
      (GNUNET_OK != GNUNET_BIO_read_int64 (rh, &uc->file_size)) ||
      (GNUNET_OK != read_start_time (rh, &uc->start_time)) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &state)))
  {
    GNUNET_break (0);
    goto cleanup;
  }
  uc->state = (enum UnindexState) state;
  switch (state)
  {
  case UNINDEX_STATE_HASHING:
    break;
  case UNINDEX_STATE_FS_NOTIFY:
    if (GNUNET_OK !=
        GNUNET_BIO_read (rh, "unindex-hash", &uc->file_id,
                         sizeof (GNUNET_HashCode)))
    {
      GNUNET_break (0);
      goto cleanup;
    }
    break;
  case UNINDEX_STATE_DS_REMOVE:
    break;
  case UNINDEX_STATE_COMPLETE:
    break;
  case UNINDEX_STATE_ERROR:
    if (GNUNET_OK !=
        GNUNET_BIO_read_string (rh, "unindex-emsg", &uc->emsg, 10 * 1024))
    {
      GNUNET_break (0);
      goto cleanup;
    }
    break;
  default:
    GNUNET_break (0);
    goto cleanup;
  }
  uc->top = GNUNET_FS_make_top (h, &GNUNET_FS_unindex_signal_suspend_, uc);
  pi.status = GNUNET_FS_STATUS_UNINDEX_RESUME;
  pi.value.unindex.specifics.resume.message = uc->emsg;
  GNUNET_FS_unindex_make_status_ (&pi, uc,
                                  (uc->state ==
                                   UNINDEX_STATE_COMPLETE) ? uc->file_size : 0);
  switch (uc->state)
  {
  case UNINDEX_STATE_HASHING:
    uc->fhc =
        GNUNET_CRYPTO_hash_file (GNUNET_SCHEDULER_PRIORITY_IDLE, uc->filename,
                                 HASHING_BLOCKSIZE,
                                 &GNUNET_FS_unindex_process_hash_, uc);
    break;
  case UNINDEX_STATE_FS_NOTIFY:
    uc->state = UNINDEX_STATE_HASHING;
    GNUNET_FS_unindex_process_hash_ (uc, &uc->file_id);
    break;
  case UNINDEX_STATE_DS_REMOVE:
    GNUNET_FS_unindex_do_remove_ (uc);
    break;
  case UNINDEX_STATE_COMPLETE:
  case UNINDEX_STATE_ERROR:
    /* no need to resume any operation, we were done */
    break;
  default:
    break;
  }
  if (GNUNET_OK != GNUNET_BIO_read_close (rh, &emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failure while resuming unindexing operation `%s': %s\n"),
                filename, emsg);
    GNUNET_free (emsg);
  }
  return GNUNET_OK;
cleanup:
  GNUNET_free_non_null (uc->filename);
  if ((rh != NULL) && (GNUNET_OK != GNUNET_BIO_read_close (rh, &emsg)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to resume unindexing operation `%s': %s\n"), filename,
                emsg);
    GNUNET_free (emsg);
  }
  if (uc->serialization != NULL)
    GNUNET_FS_remove_sync_file_ (h, GNUNET_FS_SYNC_PATH_MASTER_UNINDEX,
                                 uc->serialization);
  GNUNET_free_non_null (uc->serialization);
  GNUNET_free (uc);
  return GNUNET_OK;
}


/**
 * Deserialize a download.
 *
 * @param h overall context
 * @param rh file to deserialize from
 * @param parent parent download
 * @param search associated search
 * @param serialization name under which the search was serialized
 */
static void
deserialize_download (struct GNUNET_FS_Handle *h,
                      struct GNUNET_BIO_ReadHandle *rh,
                      struct GNUNET_FS_DownloadContext *parent,
                      struct GNUNET_FS_SearchResult *search,
                      const char *serialization);


/**
 * Deserialize a search.
 *
 * @param h overall context
 * @param rh file to deserialize from
 * @param psearch_result parent search result
 * @param serialization name under which the search was serialized
 */
static struct GNUNET_FS_SearchContext *
deserialize_search (struct GNUNET_FS_Handle *h,
                    struct GNUNET_BIO_ReadHandle *rh,
                    struct GNUNET_FS_SearchResult *psearch_result,
                    const char *serialization);


/**
 * Function called with a filename of serialized search result
 * to deserialize.
 *
 * @param cls the 'struct GNUNET_FS_SearchContext*'
 * @param filename complete filename (absolute path)
 * @return GNUNET_OK (continue to iterate)
 */
static int
deserialize_search_result (void *cls, const char *filename)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  char *ser;
  char *uris;
  char *emsg;
  char *download;
  char *update_srch;
  struct GNUNET_BIO_ReadHandle *rh;
  struct GNUNET_BIO_ReadHandle *drh;
  struct GNUNET_FS_SearchResult *sr;

  ser = get_serialization_short_name (filename);
  rh = GNUNET_BIO_read_open (filename);
  if (rh == NULL)
  {
    if (ser != NULL)
    {
      remove_sync_file_in_dir (sc->h,
                               (sc->psearch_result ==
                                NULL) ? GNUNET_FS_SYNC_PATH_MASTER_SEARCH :
                               GNUNET_FS_SYNC_PATH_CHILD_SEARCH,
                               sc->serialization, ser);
      GNUNET_free (ser);
    }
    return GNUNET_OK;
  }
  emsg = NULL;
  uris = NULL;
  download = NULL;
  update_srch = NULL;
  sr = GNUNET_malloc (sizeof (struct GNUNET_FS_SearchResult));
  sr->sc = sc;
  sr->serialization = ser;
  if ((GNUNET_OK != GNUNET_BIO_read_string (rh, "result-uri", &uris, 10 * 1024))
      || (NULL == (sr->uri = GNUNET_FS_uri_parse (uris, &emsg))) ||
      (GNUNET_OK != GNUNET_BIO_read_string (rh, "download-lnk", &download, 16))
      || (GNUNET_OK !=
          GNUNET_BIO_read_string (rh, "search-lnk", &update_srch, 16)) ||
      (GNUNET_OK != GNUNET_BIO_read_meta_data (rh, "result-meta", &sr->meta)) ||
      (GNUNET_OK !=
       GNUNET_BIO_read (rh, "result-key", &sr->key, sizeof (GNUNET_HashCode)))
      || (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &sr->mandatory_missing)) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &sr->optional_support)) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &sr->availability_success)) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &sr->availability_trials)))
  {
    GNUNET_break (0);
    goto cleanup;
  }
  if (sr->sc->uri->type == ksk)
  {
    sr->keyword_bitmap = GNUNET_malloc ((sr->sc->uri->data.ksk.keywordCount + 7) / 8); /* round up, count bits */
    if (GNUNET_OK != GNUNET_BIO_read (rh, "keyword-bitmap",
				      sr->keyword_bitmap,
				      (sr->sc->uri->data.ksk.keywordCount + 7) / 8))
    {
      GNUNET_break (0);
      goto cleanup;
    }
  }
  GNUNET_free (uris);
  if (download != NULL)
  {
    drh = get_read_handle (sc->h, GNUNET_FS_SYNC_PATH_CHILD_DOWNLOAD, download);
    if (drh != NULL)
    {
      deserialize_download (sc->h, drh, NULL, sr, download);
      if (GNUNET_OK != GNUNET_BIO_read_close (drh, &emsg))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _("Failed to resume sub-download `%s': %s\n"), download,
                    emsg);
        GNUNET_free (emsg);
      }
    }
    GNUNET_free (download);
  }
  if (update_srch != NULL)
  {
    drh =
        get_read_handle (sc->h, GNUNET_FS_SYNC_PATH_CHILD_SEARCH, update_srch);
    if (drh != NULL)
    {
      deserialize_search (sc->h, drh, sr, update_srch);
      if (GNUNET_OK != GNUNET_BIO_read_close (drh, &emsg))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _("Failed to resume sub-search `%s': %s\n"), update_srch,
                    emsg);
        GNUNET_free (emsg);
      }
    }
    GNUNET_free (update_srch);
  }
  GNUNET_CONTAINER_multihashmap_put (sc->master_result_map, &sr->key, sr,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  if (GNUNET_OK != GNUNET_BIO_read_close (rh, &emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failure while resuming search operation `%s': %s\n"),
                filename, emsg);
    GNUNET_free (emsg);
  }
  return GNUNET_OK;
cleanup:
  GNUNET_free_non_null (download);
  GNUNET_free_non_null (emsg);
  GNUNET_free_non_null (uris);
  GNUNET_free_non_null (update_srch);
  if (sr->uri != NULL)
    GNUNET_FS_uri_destroy (sr->uri);
  if (sr->meta != NULL)
    GNUNET_CONTAINER_meta_data_destroy (sr->meta);
  GNUNET_free (sr->serialization);
  GNUNET_free (sr);
  if (GNUNET_OK != GNUNET_BIO_read_close (rh, &emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failure while resuming search operation `%s': %s\n"),
                filename, emsg);
    GNUNET_free (emsg);
  }
  return GNUNET_OK;
}


/**
 * Send the 'resume' signal to the callback; also actually
 * resume the download (put it in the queue).  Does this
 * recursively for the top-level download and all child
 * downloads.
 *
 * @param dc download to resume
 */
static void
signal_download_resume (struct GNUNET_FS_DownloadContext *dc)
{
  struct GNUNET_FS_DownloadContext *dcc;
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_DOWNLOAD_RESUME;
  pi.value.download.specifics.resume.meta = dc->meta;
  pi.value.download.specifics.resume.message = dc->emsg;
  GNUNET_FS_download_make_status_ (&pi, dc);
  dcc = dc->child_head;
  while (NULL != dcc)
  {
    signal_download_resume (dcc);
    dcc = dcc->next;
  }
  if (dc->pending_head != NULL)
    GNUNET_FS_download_start_downloading_ (dc);
}


/**
 * Signal resuming of a search to our clients (for the
 * top level search and all sub-searches).
 *
 * @param sc search being resumed
 */
static void
signal_search_resume (struct GNUNET_FS_SearchContext *sc);


/**
 * Iterator over search results signaling resume to the client for
 * each result.
 *
 * @param cls closure, the 'struct GNUNET_FS_SearchContext'
 * @param key current key code
 * @param value value in the hash map, the 'struct GNUNET_FS_SearchResult'
 * @return GNUNET_YES (we should continue to iterate)
 */
static int
signal_result_resume (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  struct GNUNET_FS_ProgressInfo pi;
  struct GNUNET_FS_SearchResult *sr = value;

  if (0 == sr->mandatory_missing)
  {
    pi.status = GNUNET_FS_STATUS_SEARCH_RESUME_RESULT;
    pi.value.search.specifics.resume_result.meta = sr->meta;
    pi.value.search.specifics.resume_result.uri = sr->uri;
    pi.value.search.specifics.resume_result.result = sr;
    pi.value.search.specifics.resume_result.availability_rank =
        2 * sr->availability_success - sr->availability_trials;
    pi.value.search.specifics.resume_result.availability_certainty =
        sr->availability_trials;
    pi.value.search.specifics.resume_result.applicability_rank =
        sr->optional_support;
    sr->client_info = GNUNET_FS_search_make_status_ (&pi, sc);
  }
  if (sr->download != NULL)
  {
    signal_download_resume (sr->download);
  }
  else
  {
    GNUNET_FS_search_start_probe_ (sr);
  }
  if (sr->update_search != NULL)
    signal_search_resume (sr->update_search);
  return GNUNET_YES;
}


/**
 * Free memory allocated by the search context and its children
 *
 * @param sc search context to free
 */
static void
free_search_context (struct GNUNET_FS_SearchContext *sc);


/**
 * Iterator over search results freeing each.
 *
 * @param cls closure, the 'struct GNUNET_FS_SearchContext'
 * @param key current key code
 * @param value value in the hash map, the 'struct GNUNET_FS_SearchResult'
 * @return GNUNET_YES (we should continue to iterate)
 */
static int
free_result (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_FS_SearchResult *sr = value;

  if (sr->update_search != NULL)
  {
    free_search_context (sr->update_search);
    GNUNET_assert (NULL == sr->update_search);
  }
  GNUNET_CONTAINER_meta_data_destroy (sr->meta);
  GNUNET_FS_uri_destroy (sr->uri);
  GNUNET_free (sr);
  return GNUNET_YES;
}


/**
 * Free memory allocated by the search context and its children
 *
 * @param sc search context to free
 */
static void
free_search_context (struct GNUNET_FS_SearchContext *sc)
{
  if (sc->serialization != NULL)
  {
    GNUNET_FS_remove_sync_file_ (sc->h,
                                 (sc->psearch_result ==
                                  NULL) ? GNUNET_FS_SYNC_PATH_MASTER_SEARCH :
                                 GNUNET_FS_SYNC_PATH_CHILD_SEARCH,
                                 sc->serialization);
    GNUNET_FS_remove_sync_dir_ (sc->h,
                                (sc->psearch_result ==
                                 NULL) ? GNUNET_FS_SYNC_PATH_MASTER_SEARCH :
                                GNUNET_FS_SYNC_PATH_CHILD_SEARCH,
                                sc->serialization);
  }
  GNUNET_free_non_null (sc->serialization);
  GNUNET_free_non_null (sc->emsg);
  if (sc->uri != NULL)
    GNUNET_FS_uri_destroy (sc->uri);
  if (sc->master_result_map != NULL)
  {
    GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map, &free_result,
                                           sc);
    GNUNET_CONTAINER_multihashmap_destroy (sc->master_result_map);
  }
  GNUNET_free (sc);
}


/**
 * Function called with a filename of serialized sub-download
 * to deserialize.
 *
 * @param cls the 'struct GNUNET_FS_DownloadContext*' (parent)
 * @param filename complete filename (absolute path)
 * @return GNUNET_OK (continue to iterate)
 */
static int
deserialize_subdownload (void *cls, const char *filename)
{
  struct GNUNET_FS_DownloadContext *parent = cls;
  char *ser;
  char *emsg;
  struct GNUNET_BIO_ReadHandle *rh;

  ser = get_serialization_short_name (filename);
  rh = GNUNET_BIO_read_open (filename);
  if (rh == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Failed to resume sub-download `%s': could not open file `%s'\n"),
                ser, filename);
    GNUNET_free (ser);
    return GNUNET_OK;
  }
  deserialize_download (parent->h, rh, parent, NULL, ser);
  if (GNUNET_OK != GNUNET_BIO_read_close (rh, &emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to resume sub-download `%s': %s\n"), ser, emsg);
    GNUNET_free (emsg);
  }
  GNUNET_free (ser);
  return GNUNET_OK;
}


/**
 * Free this download context and all of its descendants.
 * (only works during deserialization since not all possible
 * state it taken care of).
 *
 * @param dc context to free
 */
static void
free_download_context (struct GNUNET_FS_DownloadContext *dc)
{
  struct GNUNET_FS_DownloadContext *dcc;

  if (dc->meta != NULL)
    GNUNET_CONTAINER_meta_data_destroy (dc->meta);
  if (dc->uri != NULL)
    GNUNET_FS_uri_destroy (dc->uri);
  GNUNET_free_non_null (dc->temp_filename);
  GNUNET_free_non_null (dc->emsg);
  GNUNET_free_non_null (dc->filename);
  GNUNET_free_non_null (dc->serialization);
  while (NULL != (dcc = dc->child_head))
  {
    GNUNET_CONTAINER_DLL_remove (dc->child_head, dc->child_tail, dcc);
    free_download_context (dcc);
  }
  GNUNET_FS_free_download_request_ (dc->top_request);
  if (NULL != dc->active)
    GNUNET_CONTAINER_multihashmap_destroy (dc->active);
  GNUNET_free (dc);
}


/**
 * Deserialize a download.
 *
 * @param h overall context
 * @param rh file to deserialize from
 * @param parent parent download
 * @param search associated search
 * @param serialization name under which the search was serialized
 */
static void
deserialize_download (struct GNUNET_FS_Handle *h,
                      struct GNUNET_BIO_ReadHandle *rh,
                      struct GNUNET_FS_DownloadContext *parent,
                      struct GNUNET_FS_SearchResult *search,
                      const char *serialization)
{
  struct GNUNET_FS_DownloadContext *dc;
  char *emsg;
  char *uris;
  char *dn;
  uint32_t options;
  uint32_t status;

  uris = NULL;
  emsg = NULL;
  dc = GNUNET_malloc (sizeof (struct GNUNET_FS_DownloadContext));
  dc->parent = parent;
  dc->h = h;
  dc->serialization = GNUNET_strdup (serialization);
  if ((GNUNET_OK !=
       GNUNET_BIO_read_string (rh, "download-uri", &uris, 10 * 1024)) ||
      (NULL == (dc->uri = GNUNET_FS_uri_parse (uris, &emsg))) ||
      ((GNUNET_YES != GNUNET_FS_uri_test_chk (dc->uri)) &&
       (GNUNET_YES != GNUNET_FS_uri_test_loc (dc->uri))) ||
      (GNUNET_OK != GNUNET_BIO_read_meta_data (rh, "download-meta", &dc->meta))
      || (GNUNET_OK !=
          GNUNET_BIO_read_string (rh, "download-emsg", &dc->emsg, 10 * 1024)) ||
      (GNUNET_OK !=
       GNUNET_BIO_read_string (rh, "download-fn", &dc->filename, 10 * 1024)) ||
      (GNUNET_OK !=
       GNUNET_BIO_read_string (rh, "download-tfn", &dc->temp_filename,
                               10 * 1024)) ||
      (GNUNET_OK != GNUNET_BIO_read_int64 (rh, &dc->old_file_size)) ||
      (GNUNET_OK != GNUNET_BIO_read_int64 (rh, &dc->offset)) ||
      (GNUNET_OK != GNUNET_BIO_read_int64 (rh, &dc->length)) ||
      (GNUNET_OK != GNUNET_BIO_read_int64 (rh, &dc->completed)) ||
      (GNUNET_OK != read_start_time (rh, &dc->start_time)) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &dc->anonymity)) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &options)) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &status)))
  {
    GNUNET_break (0);
    goto cleanup;
  }
  dc->options = (enum GNUNET_FS_DownloadOptions) options;
  dc->active =
      GNUNET_CONTAINER_multihashmap_create (1 + 2 * (dc->length / DBLOCK_SIZE));
  dc->has_finished = (int) status;
  dc->treedepth =
      GNUNET_FS_compute_depth (GNUNET_FS_uri_chk_get_file_size (dc->uri));
  if (GNUNET_FS_uri_test_loc (dc->uri))
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_FS_uri_loc_get_peer_identity (dc->uri, &dc->target));
  if (dc->emsg == NULL)
  {
    dc->top_request = read_download_request (rh);
    if (dc->top_request == NULL)
    {
      GNUNET_break (0);
      goto cleanup;
    }
  }
  dn = get_download_sync_filename (dc, dc->serialization, ".dir");
  if (dn != NULL)
  {
    if (GNUNET_YES == GNUNET_DISK_directory_test (dn))
      GNUNET_DISK_directory_scan (dn, &deserialize_subdownload, dc);
    GNUNET_free (dn);
  }
  if (parent != NULL)
  {
    GNUNET_abort ();            // for debugging for now - FIXME
    GNUNET_CONTAINER_DLL_insert (parent->child_head, parent->child_tail, dc);
  }
  if (search != NULL)
  {
    dc->search = search;
    search->download = dc;
  }
  if ((parent == NULL) && (search == NULL))
  {
    dc->top =
        GNUNET_FS_make_top (dc->h, &GNUNET_FS_download_signal_suspend_, dc);
    signal_download_resume (dc);
  }
  GNUNET_free (uris);
  dc->task = GNUNET_SCHEDULER_add_now (&GNUNET_FS_download_start_task_, dc);
  return;
cleanup:
  GNUNET_free_non_null (uris);
  GNUNET_free_non_null (emsg);
  free_download_context (dc);
}


/**
 * Signal resuming of a search to our clients (for the
 * top level search and all sub-searches).
 *
 * @param sc search being resumed
 */
static void
signal_search_resume (struct GNUNET_FS_SearchContext *sc)
{
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_SEARCH_RESUME;
  pi.value.search.specifics.resume.message = sc->emsg;
  pi.value.search.specifics.resume.is_paused =
      (sc->client == NULL) ? GNUNET_YES : GNUNET_NO;
  sc->client_info = GNUNET_FS_search_make_status_ (&pi, sc);
  GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
                                         &signal_result_resume, sc);

}


/**
 * Deserialize a search.
 *
 * @param h overall context
 * @param rh file to deserialize from
 * @param psearch_result parent search result
 * @param serialization name under which the search was serialized
 */
static struct GNUNET_FS_SearchContext *
deserialize_search (struct GNUNET_FS_Handle *h,
                    struct GNUNET_BIO_ReadHandle *rh,
                    struct GNUNET_FS_SearchResult *psearch_result,
                    const char *serialization)
{
  struct GNUNET_FS_SearchContext *sc;
  char *emsg;
  char *uris;
  char *dn;
  uint32_t options;
  char in_pause;

  if ((psearch_result != NULL) && (psearch_result->update_search != NULL))
  {
    GNUNET_break (0);
    return NULL;
  }
  uris = NULL;
  emsg = NULL;
  sc = GNUNET_malloc (sizeof (struct GNUNET_FS_SearchContext));
  if (psearch_result != NULL)
  {
    sc->psearch_result = psearch_result;
    psearch_result->update_search = sc;
  }
  sc->h = h;
  sc->serialization = GNUNET_strdup (serialization);
  if ((GNUNET_OK != GNUNET_BIO_read_string (rh, "search-uri", &uris, 10 * 1024))
      || (NULL == (sc->uri = GNUNET_FS_uri_parse (uris, &emsg))) ||
      ((GNUNET_YES != GNUNET_FS_uri_test_ksk (sc->uri)) &&
       (GNUNET_YES != GNUNET_FS_uri_test_sks (sc->uri))) ||
      (GNUNET_OK != read_start_time (rh, &sc->start_time)) ||
      (GNUNET_OK !=
       GNUNET_BIO_read_string (rh, "search-emsg", &sc->emsg, 10 * 1024)) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &options)) ||
      (GNUNET_OK !=
       GNUNET_BIO_read (rh, "search-pause", &in_pause, sizeof (in_pause))) ||
      (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &sc->anonymity)))
  {
    GNUNET_break (0);
    goto cleanup;
  }
  sc->options = (enum GNUNET_FS_SearchOptions) options;
  sc->master_result_map = GNUNET_CONTAINER_multihashmap_create (16);
  dn = get_serialization_file_name_in_dir (h,
                                           (sc->psearch_result ==
                                            NULL) ?
                                           GNUNET_FS_SYNC_PATH_MASTER_SEARCH :
                                           GNUNET_FS_SYNC_PATH_CHILD_SEARCH,
                                           sc->serialization, "");
  if (dn != NULL)
  {
    if (GNUNET_YES == GNUNET_DISK_directory_test (dn))
      GNUNET_DISK_directory_scan (dn, &deserialize_search_result, sc);
    GNUNET_free (dn);
  }
  if (('\0' == in_pause) &&
      (GNUNET_OK != GNUNET_FS_search_start_searching_ (sc)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Could not resume running search, will resume as paused search\n"));
  }
  signal_search_resume (sc);
  GNUNET_free (uris);
  return sc;
cleanup:
  GNUNET_free_non_null (emsg);
  free_search_context (sc);
  GNUNET_free_non_null (uris);
  return NULL;
}


/**
 * Function called with a filename of serialized search operation
 * to deserialize.
 *
 * @param cls the 'struct GNUNET_FS_Handle*'
 * @param filename complete filename (absolute path)
 * @return GNUNET_OK (continue to iterate)
 */
static int
deserialize_search_file (void *cls, const char *filename)
{
  struct GNUNET_FS_Handle *h = cls;
  char *ser;
  char *emsg;
  struct GNUNET_BIO_ReadHandle *rh;
  struct GNUNET_FS_SearchContext *sc;
  struct stat buf;

  if (0 != STAT (filename, &buf))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "stat", filename);
    return GNUNET_OK;
  }
  if (S_ISDIR (buf.st_mode))
    return GNUNET_OK; /* skip directories */
  ser = get_serialization_short_name (filename);
  rh = GNUNET_BIO_read_open (filename);
  if (rh == NULL)
  {
    if (ser != NULL)
    {
      GNUNET_FS_remove_sync_file_ (h, GNUNET_FS_SYNC_PATH_MASTER_SEARCH, ser);
      GNUNET_free (ser);
    }
    return GNUNET_OK;
  }
  sc = deserialize_search (h, rh, NULL, ser);
  if (sc != NULL)
    sc->top = GNUNET_FS_make_top (h, &GNUNET_FS_search_signal_suspend_, sc);
  GNUNET_free (ser);
  if (GNUNET_OK != GNUNET_BIO_read_close (rh, &emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failure while resuming search operation `%s': %s\n"),
                filename, emsg);
    GNUNET_free (emsg);
  }
  return GNUNET_OK;
}


/**
 * Function called with a filename of serialized download operation
 * to deserialize.
 *
 * @param cls the 'struct GNUNET_FS_Handle*'
 * @param filename complete filename (absolute path)
 * @return GNUNET_OK (continue to iterate)
 */
static int
deserialize_download_file (void *cls, const char *filename)
{
  struct GNUNET_FS_Handle *h = cls;
  char *ser;
  char *emsg;
  struct GNUNET_BIO_ReadHandle *rh;

  ser = get_serialization_short_name (filename);
  rh = GNUNET_BIO_read_open (filename);
  if (rh == NULL)
  {
    if (0 != UNLINK (filename))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", filename);
    GNUNET_free (ser);
    return GNUNET_OK;
  }
  deserialize_download (h, rh, NULL, NULL, ser);
  GNUNET_free (ser);
  if (GNUNET_OK != GNUNET_BIO_read_close (rh, &emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failure while resuming download operation `%s': %s\n"),
                filename, emsg);
    GNUNET_free (emsg);
  }
  return GNUNET_OK;
}


/**
 * Deserialize informatin about pending operations.
 *
 * @param master_path which master directory should be scanned
 * @param proc function to call for each entry (will get 'h' for 'cls')
 * @param h the 'struct GNUNET_FS_Handle*'
 */
static void
deserialization_master (const char *master_path, GNUNET_FileNameCallback proc,
                        struct GNUNET_FS_Handle *h)
{
  char *dn;

  dn = get_serialization_file_name (h, master_path, "");
  if (dn == NULL)
    return;
  if (GNUNET_YES == GNUNET_DISK_directory_test (dn))
    GNUNET_DISK_directory_scan (dn, proc, h);
  GNUNET_free (dn);
}


/**
 * Setup a connection to the file-sharing service.
 *
 * @param cfg configuration to use
 * @param client_name unique identifier for this client
 * @param upcb function to call to notify about FS actions
 * @param upcb_cls closure for upcb
 * @param flags specific attributes for fs-operations
 * @param ... list of optional options, terminated with GNUNET_FS_OPTIONS_END
 * @return NULL on error
 */
struct GNUNET_FS_Handle *
GNUNET_FS_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                 const char *client_name, GNUNET_FS_ProgressCallback upcb,
                 void *upcb_cls, enum GNUNET_FS_Flags flags, ...)
{
  struct GNUNET_FS_Handle *ret;
  enum GNUNET_FS_OPTIONS opt;
  va_list ap;

  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_Handle));
  ret->cfg = cfg;
  ret->client_name = GNUNET_strdup (client_name);
  ret->upcb = upcb;
  ret->upcb_cls = upcb_cls;
  ret->flags = flags;
  ret->max_parallel_downloads = 1;
  ret->max_parallel_requests = 1;
  ret->avg_block_latency = GNUNET_TIME_UNIT_MINUTES;    /* conservative starting point */
  va_start (ap, flags);
  while (GNUNET_FS_OPTIONS_END != (opt = va_arg (ap, enum GNUNET_FS_OPTIONS)))
  {
    switch (opt)
    {
    case GNUNET_FS_OPTIONS_DOWNLOAD_PARALLELISM:
      ret->max_parallel_downloads = va_arg (ap, unsigned int);

      break;
    case GNUNET_FS_OPTIONS_REQUEST_PARALLELISM:
      ret->max_parallel_requests = va_arg (ap, unsigned int);

      break;
    default:
      GNUNET_break (0);
      GNUNET_free (ret->client_name);
      GNUNET_free (ret);
      va_end (ap);
      return NULL;
    }
  }
  va_end (ap);
  if (0 != (GNUNET_FS_FLAGS_PERSISTENCE & flags))
  {
    deserialization_master (GNUNET_FS_SYNC_PATH_MASTER_PUBLISH,
                            &deserialize_publish_file, ret);
    deserialization_master (GNUNET_FS_SYNC_PATH_MASTER_SEARCH,
                            &deserialize_search_file, ret);
    deserialization_master (GNUNET_FS_SYNC_PATH_MASTER_DOWNLOAD,
                            &deserialize_download_file, ret);
    deserialization_master (GNUNET_FS_SYNC_PATH_MASTER_UNINDEX,
                            &deserialize_unindex_file, ret);
  }
  return ret;
}


/**
 * Close our connection with the file-sharing service.
 * The callback given to GNUNET_FS_start will no longer be
 * called after this function returns.
 *
 * @param h handle that was returned from GNUNET_FS_start
 */
void
GNUNET_FS_stop (struct GNUNET_FS_Handle *h)
{
  while (h->top_head != NULL)
    h->top_head->ssf (h->top_head->ssf_cls);
  if (h->queue_job != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (h->queue_job);
  GNUNET_free (h->client_name);
  GNUNET_free (h);
}


/* end of fs.c */
