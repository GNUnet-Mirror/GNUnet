/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs.c
 * @brief main FS functions (master initialization, serialization, deserialization, shared code)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "fs.h"


/**
 * Start the given job (send signal, remove from pending queue, update
 * counters and state).
 *
 * @param qe job to start
 */
static void
start_job (struct GNUNET_FS_QueueEntry *qe)
{
  qe->client = GNUNET_CLIENT_connect (qe->h->sched, "fs", qe->h->cfg);
  if (qe->client == NULL)
    {
      GNUNET_break (0);
      return;
    }
  qe->start (qe->cls, qe->client);
  qe->start_times++;
  qe->h->active_blocks += qe->blocks;
  qe->start_time = GNUNET_TIME_absolute_get ();
  GNUNET_CONTAINER_DLL_remove (qe->h->pending_head,
			       qe->h->pending_tail,
			       qe);
  GNUNET_CONTAINER_DLL_insert_after (qe->h->running_head,
				     qe->h->running_tail,
				     qe->h->running_tail,
				     qe);
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
  qe->run_time = GNUNET_TIME_relative_add (qe->run_time,
					   GNUNET_TIME_absolute_get_duration (qe->start_time));
  GNUNET_CONTAINER_DLL_remove (qe->h->running_head,
			       qe->h->running_tail,
			       qe);
  GNUNET_CONTAINER_DLL_insert_after (qe->h->pending_head,
				     qe->h->pending_tail,
				     qe->h->pending_tail,
				     qe);
}


/**
 * Process the jobs in the job queue, possibly starting some
 * and stopping others.
 *
 * @param cls the 'struct GNUNET_FS_Handle'
 * @param tc scheduler context
 */
static void
process_job_queue (void *cls,
		   const struct GNUNET_SCHEDULER_TaskContext *tc)
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
      if ( (qe->blocks + h->active_blocks <= h->max_parallel_requests) &&
	   (h->active_downloads + 1 <= h->max_parallel_downloads) )
	{
	  start_job (qe);
	  continue;
	}
    }
  if (h->pending_head == NULL)
    return; /* no need to stop anything */
  restart_at = GNUNET_TIME_UNIT_FOREVER_REL;
  next = h->running_head;
  while (NULL != (qe = next))
    {
      next = qe->next;
      /* FIXME: might be faster/simpler to do this calculation only once
	 when we start a job (OTOH, this would allow us to dynamically
	 and easily adjust qe->blocks over time, given the right API...) */
      run_time = GNUNET_TIME_relative_multiply (h->avg_block_latency,
						qe->blocks * qe->start_times);
      end_time = GNUNET_TIME_absolute_add (qe->start_time,
					   run_time);
      rst = GNUNET_TIME_absolute_get_remaining (end_time);
      restart_at = GNUNET_TIME_relative_min (rst, restart_at);
      if (rst.value > 0)
	continue;	
      stop_job (qe);
    }
  h->queue_job = GNUNET_SCHEDULER_add_delayed (h->sched,
					       restart_at,
					       &process_job_queue,
					       h);
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
GNUNET_FS_queue_ (struct GNUNET_FS_Handle *h,
		  GNUNET_FS_QueueStart start,
		  GNUNET_FS_QueueStop stop,
		  void *cls,
		  unsigned int blocks)
{
  struct GNUNET_FS_QueueEntry *qe;

  qe = GNUNET_malloc (sizeof (struct GNUNET_FS_QueueEntry));
  qe->h = h;
  qe->start = start;
  qe->stop = stop;
  qe->cls = cls;
  qe->queue_time = GNUNET_TIME_absolute_get ();
  qe->blocks = blocks;
  GNUNET_CONTAINER_DLL_insert_after (h->pending_head,
				     h->pending_tail,
				     h->pending_tail,
				     qe);
  if (h->queue_job != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (h->sched,
			     h->queue_job);
  h->queue_job 
    = GNUNET_SCHEDULER_add_now (h->sched,
				&process_job_queue,
				h);
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
  GNUNET_CONTAINER_DLL_remove (h->pending_head,
			       h->pending_tail,
			       qh);
  GNUNET_free (qh);
  if (h->queue_job != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (h->sched,
			     h->queue_job);
  h->queue_job 
    = GNUNET_SCHEDULER_add_now (h->sched,
				&process_job_queue,
				h);
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
GNUNET_FS_data_reader_file_(void *cls, 
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
				      GNUNET_DISK_OPEN_READ,
				      GNUNET_DISK_PERM_NONE);
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
 * Create the closure for the 'GNUNET_FS_data_reader_file_' callback.
 *
 * @param filename file to read
 * @return closure to use, NULL on error
 */
void *
GNUNET_FS_make_file_reader_context_ (const char *filename)
{
  struct FileInfo *fi;

  fi = GNUNET_malloc (sizeof(struct FileInfo));
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
GNUNET_FS_data_reader_copy_ (void *cls, 
			     uint64_t offset,
			     size_t max, 
			     void *buf,
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
get_serialization_file_name (struct GNUNET_FS_Handle *h,
			     const char *ext,
			     const char *ent)
{
  char *basename;
  char *ret;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (h->cfg,
					       "fs",
					       "STATE_DIR",
					       &basename))
    return NULL;
  GNUNET_asprintf (&ret,
		   "%s%s%s-%s%s%s",
		   basename,
		   DIR_SEPARATOR_STR,
		   h->client_name,
		   ext,
		   DIR_SEPARATOR_STR,
		   ent);
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
get_read_handle (struct GNUNET_FS_Handle *h,
		 const char *ext,
		 const char *ent)
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
get_write_handle (struct GNUNET_FS_Handle *h,
		 const char *ext,
		 const char *ent)
{
  char *fn;
  struct GNUNET_BIO_WriteHandle *ret;

  fn = get_serialization_file_name (h, ext, ent);
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
static void
remove_sync_file (struct GNUNET_FS_Handle *h,
		  const char *ext,
		  const char *ent)
{
  char *filename;

  if ( (NULL == ent) ||
       (0 == strlen (ent)) )
    {
      GNUNET_break (0);
      return;
    }
  filename = get_serialization_file_name (h, ext, ent);
  if (0 != UNLINK (filename))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
			      "unlink", 
			      filename);
  GNUNET_free (filename);
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
deserialize_file_information (struct GNUNET_FS_Handle *h,
			      const char *filename);


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
deserialize_fi_node (struct GNUNET_FS_Handle *h,
		     const char *fn,
		     struct GNUNET_BIO_ReadHandle *rh)
{
  struct GNUNET_FS_FileInformation *ret;
  struct GNUNET_FS_FileInformation *nxt;
  char b;
  char *ksks;
  char *chks;
  char *filename;
  uint32_t dsize;

  if (GNUNET_OK !=
      GNUNET_BIO_read (rh, "status flag", &b, sizeof(b)))
    {
      GNUNET_break (0);
      return NULL;
    }
  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_FileInformation));
  ksks = NULL;
  chks = NULL;
  filename = NULL;
  if ( (GNUNET_OK !=
	GNUNET_BIO_read_meta_data (rh, "metadata", &ret->meta)) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_string (rh, "ksk-uri", &ksks, 32*1024)) ||
       ( (ksks != NULL) &&
	 (NULL == 
	  (ret->keywords = GNUNET_FS_uri_parse (ksks, NULL))) ) ||
       (GNUNET_YES !=
	GNUNET_FS_uri_test_ksk (ret->keywords)) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_string (rh, "chk-uri", &chks, 1024)) ||
       ( (chks != NULL) &&
	 ( (NULL == 
	    (ret->chk_uri = GNUNET_FS_uri_parse (chks, NULL))) ||
	   (GNUNET_YES !=
	    GNUNET_FS_uri_test_chk (ret->chk_uri)) ) ) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_int64 (rh, &ret->expirationTime.value)) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_int64 (rh, &ret->start_time.value)) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_string (rh, "emsg", &ret->emsg, 16*1024)) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_string (rh, "fn", &ret->filename, 16*1024)) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_int32 (rh, &ret->anonymity)) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_int32 (rh, &ret->priority)) )
    goto cleanup;
  switch (b)
    {
    case 0: /* file-insert */
      if (GNUNET_OK !=
	  GNUNET_BIO_read_int64 (rh, &ret->data.file.file_size))
	goto cleanup;
      ret->is_directory = GNUNET_NO;
      ret->data.file.do_index = GNUNET_NO;
      ret->data.file.have_hash = GNUNET_NO;
      ret->data.file.index_start_confirmed = GNUNET_NO;
      if (GNUNET_NO == ret->is_published) 
	{
	  if (NULL == ret->filename)
	    {
	      ret->data.file.reader = &GNUNET_FS_data_reader_copy_;
	      ret->data.file.reader_cls = GNUNET_malloc_large (ret->data.file.file_size);
	      if (ret->data.file.reader_cls == NULL)
		goto cleanup;
	      if (GNUNET_OK !=
		  GNUNET_BIO_read (rh, "file-data", ret->data.file.reader_cls, ret->data.file.file_size))
		goto cleanup;
	    }      
	  else
	    {
	      ret->data.file.reader = &GNUNET_FS_data_reader_file_;
	      ret->data.file.reader_cls = GNUNET_FS_make_file_reader_context_ (ret->filename);
	    }
	}
      break;
    case 1: /* file-index, no hash */
      if (NULL == ret->filename)
	goto cleanup;
      if (GNUNET_OK !=
	  GNUNET_BIO_read_int64 (rh, &ret->data.file.file_size))
	goto cleanup;
      ret->is_directory = GNUNET_NO;
      ret->data.file.do_index = GNUNET_YES;
      ret->data.file.have_hash = GNUNET_NO;
      ret->data.file.index_start_confirmed = GNUNET_NO;
      ret->data.file.reader = &GNUNET_FS_data_reader_file_;
      ret->data.file.reader_cls = GNUNET_FS_make_file_reader_context_ (ret->filename);
      break;
    case 2: /* file-index-with-hash */
      if (NULL == ret->filename)
	goto cleanup;
      if ( (GNUNET_OK !=
	    GNUNET_BIO_read_int64 (rh, &ret->data.file.file_size)) ||
	   (GNUNET_OK !=
	    GNUNET_BIO_read (rh, "fileid", &ret->data.file.file_id, sizeof (GNUNET_HashCode))) )
	goto cleanup;
      ret->is_directory = GNUNET_NO;
      ret->data.file.do_index = GNUNET_YES;
      ret->data.file.have_hash = GNUNET_YES;
      ret->data.file.index_start_confirmed = GNUNET_NO;
      ret->data.file.reader = &GNUNET_FS_data_reader_file_;
      ret->data.file.reader_cls = GNUNET_FS_make_file_reader_context_ (ret->filename);
      break;
    case 3: /* file-index-with-hash-confirmed */
      if (NULL == ret->filename)
	goto cleanup;
      if ( (GNUNET_OK !=
	    GNUNET_BIO_read_int64 (rh, &ret->data.file.file_size)) ||
	   (GNUNET_OK !=
	    GNUNET_BIO_read (rh, "fileid", &ret->data.file.file_id, sizeof (GNUNET_HashCode))) )
	goto cleanup;

      ret->is_directory = GNUNET_NO;
      ret->data.file.do_index = GNUNET_YES;
      ret->data.file.have_hash = GNUNET_YES;
      ret->data.file.index_start_confirmed = GNUNET_YES;
      ret->data.file.reader = &GNUNET_FS_data_reader_file_;
      ret->data.file.reader_cls = GNUNET_FS_make_file_reader_context_ (ret->filename);
      break;
    case 4: /* directory */
      if ( (GNUNET_OK !=
	    GNUNET_BIO_read_int32 (rh, &dsize)) ||
	   (NULL == (ret->data.dir.dir_data = GNUNET_malloc_large (dsize))) ||
	   (GNUNET_OK !=
	    GNUNET_BIO_read (rh, "dir-data", ret->data.dir.dir_data, dsize)) ||
	   (GNUNET_OK !=
	    GNUNET_BIO_read_string (rh, "ent-filename", &filename, 16*1024)) )
	goto cleanup;
      ret->data.dir.dir_size = (uint32_t) dsize;
      ret->is_directory = GNUNET_YES;
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
  /* FIXME: adjust ret->start_time! */
  ret->serialization = GNUNET_strdup (fn);
  if (GNUNET_OK !=
      GNUNET_BIO_read_string (rh, "nxt-filename", &filename, 16*1024))
    goto cleanup;  
  if (filename != NULL)
    {
      ret->next = deserialize_file_information (h, filename);
      GNUNET_free (filename);
      filename = NULL;
    }
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
deserialize_file_information (struct GNUNET_FS_Handle *h,
			      const char *filename)
{
  struct GNUNET_FS_FileInformation *ret;
  struct GNUNET_BIO_ReadHandle *rh;
  char *emsg;

  rh = get_read_handle (h, "publish-fi", filename);
  if (rh == NULL)
    return NULL;
  ret = deserialize_fi_node (h, filename, rh);
  if (GNUNET_OK !=
      GNUNET_BIO_read_close (rh, &emsg))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Failed to resume publishing information `%s': %s\n"),
		  filename,
		  emsg);
      GNUNET_free (emsg);
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
     the length of 'end'... */
  while ('\0' != nxt)
    {
      if (DIR_SEPARATOR == *nxt)
	end = nxt + 1;
      nxt++;
    }
  if ( (end == NULL) ||
       (strlen (end) == 0) )
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
make_serialization_file_name (struct GNUNET_FS_Handle *h,
			      const char *ext)
{
  char *fn;
  char *dn;
  char *ret;

  if (0 == (h->flags & GNUNET_FS_FLAGS_PERSISTENCE))
    return NULL; /* persistence not requested */
  dn = get_serialization_file_name (h, ext, "");
  fn = GNUNET_DISK_mktemp (dn);
  GNUNET_free (dn);
  if (fn == NULL)
    return NULL; /* epic fail */
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
		  struct GNUNET_FS_FileInformation * fi)
{
  char buf[32 * 1024];
  uint64_t off;
  size_t ret;
  char *emsg;

  emsg = NULL;
  off = 0;
  while (off < fi->data.file.file_size)
    {
      ret = fi->data.file.reader (fi->data.file.reader_cls,
				  off, sizeof (buf),
				  buf,
				  &emsg);
      if (ret == 0)
	{
	  GNUNET_free (emsg);
	  return GNUNET_SYSERR;
	}
      if (GNUNET_OK != 
	  GNUNET_BIO_write (wh, buf, ret))
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
GNUNET_FS_file_information_sync_ (struct GNUNET_FS_FileInformation * fi)
{
  char *fn;
  struct GNUNET_BIO_WriteHandle *wh;
  char b;
  char *ksks;
  char *chks;

  if (NULL == fi->serialization)    
    fi->serialization = make_serialization_file_name (fi->h, "publish-fi");
  if (NULL == fi->serialization)
    return;
  wh = get_write_handle (fi->h, "publish-fi", fi->serialization);
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
  if ( (GNUNET_OK !=
	GNUNET_BIO_write (wh, &b, sizeof (b))) ||
       (GNUNET_OK != 
	GNUNET_BIO_write_meta_data (wh, fi->meta)) ||
       (GNUNET_OK !=
	GNUNET_BIO_write_string (wh, ksks)) ||
       (GNUNET_OK !=
	GNUNET_BIO_write_string (wh, chks)) ||
       (GNUNET_OK != 
	GNUNET_BIO_write_int64 (wh, fi->expirationTime.value)) ||
       (GNUNET_OK != 
	GNUNET_BIO_write_int64 (wh, fi->start_time.value)) ||
       (GNUNET_OK !=
	GNUNET_BIO_write_string (wh, fi->emsg)) ||
       (GNUNET_OK !=
	GNUNET_BIO_write_string (wh, fi->filename)) ||
       (GNUNET_OK != 
	GNUNET_BIO_write_int32 (wh, fi->anonymity)) ||
       (GNUNET_OK != 
	GNUNET_BIO_write_int32 (wh, fi->priority)) )
    goto cleanup;
  GNUNET_free_non_null (chks);
  chks = NULL;
  GNUNET_free_non_null (ksks);
  ksks = NULL;
  
  switch (b)
    {
    case 0: /* file-insert */
      if (GNUNET_OK !=
	  GNUNET_BIO_write_int64 (wh, fi->data.file.file_size))
	goto cleanup;
      if ( (GNUNET_NO == fi->is_published) &&
	   (NULL == fi->filename) )	
	if (GNUNET_OK != 
	    copy_from_reader (wh, fi))
	  goto cleanup;
      break;
    case 1: /* file-index, no hash */
      if (NULL == fi->filename)
	goto cleanup;
      if (GNUNET_OK !=
	  GNUNET_BIO_write_int64 (wh, fi->data.file.file_size))
	goto cleanup;
      break;
    case 2: /* file-index-with-hash */
    case 3: /* file-index-with-hash-confirmed */
      if (NULL == fi->filename)
	goto cleanup;
      if ( (GNUNET_OK !=
	    GNUNET_BIO_write_int64 (wh, fi->data.file.file_size)) ||
	   (GNUNET_OK !=
	    GNUNET_BIO_write (wh, &fi->data.file.file_id, sizeof (GNUNET_HashCode))) )
	goto cleanup;
      break;
    case 4: /* directory */
      if ( (GNUNET_OK !=
	    GNUNET_BIO_write_int32 (wh, fi->data.dir.dir_size)) ||
	   (GNUNET_OK !=
	    GNUNET_BIO_write (wh, fi->data.dir.dir_data, (uint32_t) fi->data.dir.dir_size)) ||
	   (GNUNET_OK !=
	    GNUNET_BIO_write_string (wh, fi->data.dir.entries->serialization)) )
	goto cleanup;
      break;
    default:
      GNUNET_assert (0);
      goto cleanup;
    }
  if (GNUNET_OK !=
      GNUNET_BIO_write_string (wh, fi->next->serialization))
    goto cleanup;  
  if (GNUNET_OK ==
      GNUNET_BIO_write_close (wh))
    return; /* done! */
 cleanup:
  (void) GNUNET_BIO_write_close (wh);
  GNUNET_free_non_null (chks);
  GNUNET_free_non_null (ksks);
  fn = get_serialization_file_name (fi->h, "publish-fi", fi->serialization);
  if (0 != UNLINK (fn))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
  GNUNET_free (fn);
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
find_file_position (struct GNUNET_FS_FileInformation *pos,
		    const char *srch)
{
  struct GNUNET_FS_FileInformation *r;

  while (pos != NULL)
    {
      if (0 == strcmp (srch,
		       pos->serialization))
	return pos;
      if (pos->is_directory)
	{
	  r = find_file_position (pos->data.dir.entries,
				  srch);
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
 * @param anonymity pointer to selected anonymity level (can be modified)
 * @param priority pointer to selected priority (can be modified)
 * @param expirationTime pointer to selected expiration time (can be modified)
 * @param client_info pointer to client context set upon creation (can be modified)
 * @return GNUNET_OK to continue (always)
 */
static int
fip_signal_resume(void *cls,
		  struct GNUNET_FS_FileInformation *fi,
		  uint64_t length,
		  struct GNUNET_CONTAINER_MetaData *meta,
		  struct GNUNET_FS_Uri **uri,
		  uint32_t *anonymity,
		  uint32_t *priority,
		  struct GNUNET_TIME_Absolute *expirationTime,
		  void **client_info)
{
  struct GNUNET_FS_PublishContext *sc = cls;
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_PUBLISH_RESUME;
  pi.value.publish.specifics.resume.message = sc->fi->emsg;
  pi.value.publish.specifics.resume.chk_uri = sc->fi->chk_uri;
  *client_info = GNUNET_FS_publish_make_status_ (&pi, sc, fi, 0);
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
deserialize_publish_file (void *cls,
			  const char *filename)
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
  fi_root = NULL;
  fi_pos = NULL;
  ns = NULL;
  rh = GNUNET_BIO_read_open (filename);
  if (rh == NULL)
    goto cleanup;
  if ( (GNUNET_OK !=
	GNUNET_BIO_read_string (rh, "publish-nid", &pc->nid, 1024)) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_string (rh, "publish-nuid", &pc->nuid, 1024)) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_int32 (rh, &options)) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_int32 (rh, &all_done)) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_string (rh, "publish-firoot", &fi_root, 128)) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_string (rh, "publish-fipos", &fi_pos, 128)) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_string (rh, "publish-ns", &ns, 1024)) )
    goto cleanup;          
  pc->options = options;
  pc->all_done = all_done;
  pc->fi = deserialize_file_information (h, fi_root);
  if (pc->fi == NULL)
    goto cleanup;    
  if (ns != NULL)
    {
      pc->namespace = GNUNET_FS_namespace_create (h, ns);
      if (pc->namespace == NULL)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		      _("Failed to recover namespace `%s', cannot resume publishing operation.\n"),
		      ns);
	  goto cleanup;
	}
    }
  if (fi_pos != NULL)
    {
      pc->fi_pos = find_file_position (pc->fi,
				       fi_pos);
      GNUNET_free (fi_pos);
      if (pc->fi_pos == NULL)
	{
	  /* failed to find position for resuming, outch! Will start from root! */
	  GNUNET_break (0);
	  if (pc->all_done != GNUNET_YES)
	    pc->fi_pos = pc->fi;
	}
    }
  pc->serialization = get_serialization_short_name (filename);
  /* generate RESUME event(s) */
  GNUNET_FS_file_information_inspect (pc->fi,
				      &fip_signal_resume,
				      pc);
  
  /* re-start publishing (if needed)... */
  if (pc->all_done != GNUNET_YES)
    pc->upload_task 
      = GNUNET_SCHEDULER_add_with_priority (h->sched,
					    GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
					    &GNUNET_FS_publish_main_,
					    pc);       
  if (GNUNET_OK !=
      GNUNET_BIO_read_close (rh, &emsg))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Failed to resume publishing operation `%s': %s\n"),
		  filename,
		  emsg);
      GNUNET_free (emsg);
    }
  return GNUNET_OK;
 cleanup:
  GNUNET_free_non_null (pc->nid);
  GNUNET_free_non_null (pc->nuid);
  GNUNET_free_non_null (fi_root);
  GNUNET_free_non_null (ns);
  if ( (rh != NULL) &&
       (GNUNET_OK !=
	GNUNET_BIO_read_close (rh, &emsg)) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Failed to resume publishing operation `%s': %s\n"),
		  filename,
		  emsg);
      GNUNET_free (emsg);
    }
  if (pc->fi != NULL)
    GNUNET_FS_file_information_destroy (pc->fi, NULL, NULL);
  remove_sync_file (h, "publish", pc->serialization);
  GNUNET_free_non_null (pc->serialization);
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
    pc->serialization = make_serialization_file_name (pc->h,
						      "publish");
  if (NULL == pc->serialization)
    return;
  if (NULL == pc->fi)
    return;
  if (NULL == pc->fi->serialization)
    {
      GNUNET_break (0);
      return;
    }
  wh = get_write_handle (pc->h, "publish", pc->serialization);
 if ( (GNUNET_OK !=
	GNUNET_BIO_write_string (wh, pc->nid)) ||
       (GNUNET_OK !=
	GNUNET_BIO_write_string (wh, pc->nuid)) ||
       (GNUNET_OK !=
	GNUNET_BIO_write_int32 (wh, pc->options)) ||
       (GNUNET_OK !=
	GNUNET_BIO_write_int32 (wh, pc->all_done)) ||
       (GNUNET_OK !=
	GNUNET_BIO_write_string (wh, pc->fi->serialization)) ||
       (GNUNET_OK !=
	GNUNET_BIO_write_string (wh, (pc->fi_pos == NULL) ? NULL : pc->fi_pos->serialization)) ||
       (GNUNET_OK !=
	GNUNET_BIO_write_string (wh, (pc->namespace == NULL) ? NULL : pc->namespace->name)) )
   {
     (void) GNUNET_BIO_write_close (wh);
     remove_sync_file (pc->h, "publish", pc->serialization);
     GNUNET_free (pc->serialization);
     pc->serialization = NULL;
     return;
   }
 if (GNUNET_OK !=
     GNUNET_BIO_write_close (wh))
   {
     remove_sync_file (pc->h, "publish", pc->serialization);
     GNUNET_free (pc->serialization);
     pc->serialization = NULL;
     return;     
   }  
}


/**
 * Deserialize information about pending publish operations.
 *
 * @param h master context
 */
static void
deserialize_publish (struct GNUNET_FS_Handle *h)
{
  char *dn;

  dn = get_serialization_file_name (h, "publish", "");
  if (dn == NULL)
    return;
  GNUNET_DISK_directory_scan (dn, &deserialize_publish_file, h);
  GNUNET_free (dn);
}


/**
 * Setup a connection to the file-sharing service.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param client_name unique identifier for this client 
 * @param upcb function to call to notify about FS actions
 * @param upcb_cls closure for upcb
 * @param flags specific attributes for fs-operations
 * @param ... list of optional options, terminated with GNUNET_FS_OPTIONS_END
 * @return NULL on error
 */
struct GNUNET_FS_Handle *
GNUNET_FS_start (struct GNUNET_SCHEDULER_Handle *sched,
		 const struct GNUNET_CONFIGURATION_Handle *cfg,
		 const char *client_name,
		 GNUNET_FS_ProgressCallback upcb,
		 void *upcb_cls,
		 enum GNUNET_FS_Flags flags,
		 ...)
{
  struct GNUNET_FS_Handle *ret;
  struct GNUNET_CLIENT_Connection *client;
  enum GNUNET_FS_OPTIONS opt;
  va_list ap;

  client = GNUNET_CLIENT_connect (sched,
				  "fs",
				  cfg);
  if (NULL == client)
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_Handle));
  ret->sched = sched;
  ret->cfg = cfg;
  ret->client_name = GNUNET_strdup (client_name);
  ret->upcb = upcb;
  ret->upcb_cls = upcb_cls;
  ret->client = client;
  ret->flags = flags;
  ret->max_parallel_downloads = 1;
  ret->max_parallel_requests = 1;
  ret->avg_block_latency = GNUNET_TIME_UNIT_MINUTES; /* conservative starting point */
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
  // FIXME: setup receive-loop with client (do we need one?)

  if (0 != (GNUNET_FS_FLAGS_PERSISTENCE & flags))
    {
      deserialize_publish (ret);
      /* FIXME: not implemented! */
      // Deserialize Search:
      // * read search queries
      // * for each query, read file with search results
      // * for each search result with active download, deserialize download
      // * for each directory search result, check for active downloads of contents
      // Deserialize Download:
      // * always part of search???
      // Deserialize Unindex:
      // * read FNs for unindex with progress offset
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
  if (0 != (GNUNET_FS_FLAGS_PERSISTENCE & h->flags))
    {
      // FIXME: generate SUSPEND events and clean up state!
    }
  // FIXME: terminate receive-loop with client  (do we need one?)
  if (h->queue_job != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (h->sched,
			     h->queue_job);
  GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
  GNUNET_free (h->client_name);
  GNUNET_free (h);
}


/* end of fs.c */
