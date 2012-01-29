/*
     This file is part of GNUnet
     (C) 2005-2012 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_dirmetascan.c
 * @brief code to asynchronously build a 'struct GNUNET_FS_ShareTreeItem'
 *        from an on-disk directory for publishing
 * @author LRN
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_fs_service.h"
#include "gnunet_scheduler_lib.h"
#include <pthread.h>


/**
 * An opaque structure a pointer to which is returned to the
 * caller to be used to control the scanner.
 */
struct GNUNET_FS_DirScanner
{

  /**
   * A thread object for the scanner thread.
   */
#if WINDOWS
  HANDLE thread;
#else
  pthread_t thread;
#endif

  /**
   * Expanded filename (as given by the scan initiator).
   * The scanner thread stores a copy here, and frees it when it finishes.
   */
  char *filename_expanded;

  /**
   * List of libextractor plugins to use for extracting.
   * Initialized when the scan starts, removed when it finishes.
   */
  struct EXTRACTOR_PluginList *plugins;
  
  /**
   * A pipe transfer signals to the scanner.
   */
  struct GNUNET_DISK_PipeHandle *stop_pipe;

  /**
   * A pipe end to read signals from.
   */
  const struct GNUNET_DISK_FileHandle *stop_read;

  /**
   * A pipe end to read signals from.
   */
  const struct GNUNET_DISK_FileHandle *stop_write;
  
  /**
   * The pipe that is used to read progress messages.  Only closed
   * after the scanner thread is finished.
   */
  struct GNUNET_DISK_PipeHandle *progress_pipe;

  /**
   * The end of the pipe that is used to read progress messages.
   */
  const struct GNUNET_DISK_FileHandle *progress_read;

  /**
   * Handle of the pipe end into which the progress messages are written
   * The initiator MUST keep it alive until the scanner thread is finished.
   */
  const struct GNUNET_DISK_FileHandle *progress_write;
  
  /**
   * The function that will be called every time there's a progress
   * message.
   */
  GNUNET_FS_DirScannerProgressCallback progress_callback;
  
  /**
   * A closure for progress_callback.
   */
  void *progress_callback_cls;
  
  /**
   * A task for reading progress messages from the scanner.
   */
  GNUNET_SCHEDULER_TaskIdentifier progress_read_task;

  /**
   * After the scan is finished, it will contain a pointer to the
   * top-level directory entry in the directory tree built by the
   * scanner.  Must only be manipulated by the thread for the
   * duration of the thread's runtime.
   */
  struct GNUNET_FS_ShareTreeItem *toplevel;

  /**
   * 1 if the scanner should stop, 0 otherwise. Set in response
   * to communication errors or when the initiator wants the scanning
   * process to stop.
   */
  int do_stop;

};



/**
 * Abort the scan.
 *
 * @param ds directory scanner structure
 */
void
GNUNET_FS_directory_scan_abort (struct GNUNET_FS_DirScanner *ds)
{
  static char c = 1;

  /* signal shutdown to other thread */
  (void) GNUNET_DISK_file_write (ds->stop_write, &c, 1);
  GNUNET_DISK_pipe_close_end (ds->stop_pipe, GNUNET_DISK_PIPE_END_WRITE);

  /* stop reading from progress */
  if (ds->progress_read_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (ds->progress_read_task);
    ds->progress_read_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_DISK_pipe_close_end (ds->progress_pipe, GNUNET_DISK_PIPE_END_READ);

  /* wait for other thread to terminate */
#if WINDOWS
  WaitForSingleObject (ds->thread, INFINITE);
  CloseHandle (ds->thread);
#else
  pthread_join (ds->thread, NULL);
  pthread_detach (ds->thread);
#endif

  /* free resources */
  GNUNET_DISK_pipe_close (ds->stop_pipe);
  GNUNET_DISK_pipe_close (ds->progress_pipe);
  if (NULL != ds->toplevel)
    GNUNET_FS_share_tree_free (ds->toplevel);
  if (NULL != ds->plugins)
    EXTRACTOR_plugin_remove_all (ds->plugins);
  GNUNET_free (ds);
}


/**
 * Obtain the result of the scan after the scan has signalled
 * completion.  Must not be called prior to completion.  The 'ds' is
 * freed as part of this call.
 *
 * @param ds directory scanner structure
 * @return the results of the scan (a directory tree)
 */
struct GNUNET_FS_ShareTreeItem *
GNUNET_FS_directory_scan_get_result (struct GNUNET_FS_DirScanner *ds)
{
  struct GNUNET_FS_ShareTreeItem *result;

  /* check that we're actually done */
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == ds->progress_read_task);
  /* preserve result */
  result = ds->toplevel;
  ds->toplevel = NULL; 
  GNUNET_FS_directory_scan_abort (ds);
  return result;
}


/**
 * Write 'size' bytes from 'buf' into 'out'.
 *
 * @param in pipe to write to
 * @param buf buffer with data to write
 * @param size number of bytes to write
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
write_all (const struct GNUNET_DISK_FileHandle *out,
	   const void *buf,
	   size_t size)
{
  const char *cbuf = buf;
  size_t total;
  ssize_t wr;

  total = 0;
  do
  {
    wr = GNUNET_DISK_file_write (out,
				 &cbuf[total],
				 size - total);
    if (wr > 0)
      total += wr;
  } while ( (wr > 0) && (total < size) );
  if (wr <= 0)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Failed to write to inter thread communication pipe: %s\n",
		strerror (errno));
  return (total == size) ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Write progress message.
 *
 * @param ds
 * @param filename name of the file to transmit, never NULL
 * @param is_directory GNUNET_YES for directory, GNUNET_NO for file, GNUNET_SYSERR for neither
 * @param reason reason for the progress call
 * @return GNUNET_SYSERR to stop scanning (the pipe was broken somehow)
 */
static int
write_progress (struct GNUNET_FS_DirScanner *ds,
		const char *filename,
		int is_directory, 
		enum GNUNET_FS_DirScannerProgressUpdateReason reason)
{
  size_t slen;

  slen = strlen (filename) + 1;
  if ( (GNUNET_OK !=
	write_all (ds->progress_write,
		   &reason,
		   sizeof (reason))) ||
       (GNUNET_OK !=
	write_all (ds->progress_write,
		   &slen,
		   sizeof (slen))) ||
       (GNUNET_OK !=
	write_all (ds->progress_write,
		   filename,
		   slen)) ||
       (GNUNET_OK !=
	write_all (ds->progress_write,
		   &is_directory,
		   sizeof (is_directory))) )
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Called every now and then by the scanner thread to check
 * if we're being aborted.
 * 
 * @param ds scanner context
 * @return GNUNET_OK to continue, GNUNET_SYSERR to stop
 */
static int
test_thread_stop (struct GNUNET_FS_DirScanner *ds)
{
  char c;

  if ( (GNUNET_DISK_file_read_non_blocking (ds->stop_read, &c, 1) == 1) ||
       (EAGAIN != errno) )
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Function called to (recursively) add all of the files in the
 * directory to the tree.  Called by the directory scanner to initiate
 * the scan.  Does NOT yet add any metadata.
 *
 * @param ds directory scanner context to use
 * @param filename file or directory to scan
 * @param dst where to store the resulting share tree item
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
preprocess_file (struct GNUNET_FS_DirScanner *ds,
		 const char *filename,
		 struct GNUNET_FS_ShareTreeItem **dst);


/**
 * Closure for the 'scan_callback'
 */
struct RecursionContext
{
  /**
   * Global scanner context.
   */
  struct GNUNET_FS_DirScanner *ds;

  /**
   * Parent to add the files to.
   */
  struct GNUNET_FS_ShareTreeItem *parent;

  /**
   * Flag to set to GNUNET_YES on serious errors.
   */
  int stop;
};


/**
 * Function called by the directory iterator to (recursively) add all
 * of the files in the directory to the tree.  Called by the directory
 * scanner to initiate the scan.  Does NOT yet add any metadata.
 *
 * @param cls the 'struct RecursionContext'
 * @param filename file or directory to scan
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
scan_callback (void *cls,
	       const char *filename)
{
  struct RecursionContext *rc = cls;
  struct GNUNET_FS_ShareTreeItem *chld;

  if (GNUNET_OK !=
      preprocess_file (rc->ds,
		       filename,
		       &chld))
  {
    rc->stop = GNUNET_YES;
    return GNUNET_SYSERR;
  }
  chld->parent = rc->parent;
  GNUNET_CONTAINER_DLL_insert (rc->parent->children_head,
			       rc->parent->children_tail,
			       chld);
  return GNUNET_OK;
}


/**
 * Function called to (recursively) add all of the files in the
 * directory to the tree.  Called by the directory scanner to initiate
 * the scan.  Does NOT yet add any metadata.
 *
 * @param ds directory scanner context to use
 * @param filename file or directory to scan
 * @param dst where to store the resulting share tree item
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
preprocess_file (struct GNUNET_FS_DirScanner *ds,
		 const char *filename,
		 struct GNUNET_FS_ShareTreeItem **dst)
{
  struct GNUNET_FS_ShareTreeItem *item;
  struct stat sbuf;

  if (0 != STAT (filename, &sbuf))
  {
    /* If the file doesn't exist (or is not stat-able for any other reason)
       skip it (but report it), but do continue. */
    if (GNUNET_OK !=
	write_progress (ds, filename, GNUNET_SYSERR,
			GNUNET_FS_DIRSCANNER_DOES_NOT_EXIST))
      return GNUNET_SYSERR;
    return GNUNET_OK;
  }

  /* Report the progress */
  if (GNUNET_OK !=
      write_progress (ds, 
		      filename, 
		      S_ISDIR (sbuf.st_mode) ? GNUNET_YES : GNUNET_NO,
		      GNUNET_FS_DIRSCANNER_FILE_START))
    return GNUNET_SYSERR;
  item = GNUNET_malloc (sizeof (struct GNUNET_FS_ShareTreeItem));
  item->meta = GNUNET_CONTAINER_meta_data_create ();
  item->filename = GNUNET_strdup (filename);
  item->short_filename = GNUNET_strdup (GNUNET_STRINGS_get_short_name (filename));
  item->is_directory = (S_ISDIR (sbuf.st_mode)) ? GNUNET_YES : GNUNET_NO;
  item->file_size = (uint64_t) sbuf.st_size;
  if (item->is_directory)
  {
    struct RecursionContext rc;

    rc.parent = item;
    rc.ds = ds;
    rc.stop = GNUNET_NO;
    GNUNET_DISK_directory_scan (filename, 
				&scan_callback, 
				&rc);    
    if ( (rc.stop == GNUNET_YES) ||
	 (GNUNET_OK != 
	  test_thread_stop (ds)) )
    {
      GNUNET_FS_share_tree_free (item);
      return GNUNET_SYSERR;
    }
  }
  /* Report the progress */
  if (GNUNET_OK !=
      write_progress (ds, 
		      filename, 
		      S_ISDIR (sbuf.st_mode) ? GNUNET_YES : GNUNET_NO,
		      GNUNET_FS_DIRSCANNER_SUBTREE_COUNTED))
  {
    GNUNET_FS_share_tree_free (item);
    return GNUNET_SYSERR;
  }
  *dst = item;
  return GNUNET_OK;
}


/**
 * Extract metadata from files.
 *
 * @param ds directory scanner context
 * @param item entry we are processing
 * @return GNUNET_OK on success, GNUNET_SYSERR on fatal errors
 */
static int
extract_files (struct GNUNET_FS_DirScanner *ds,
	       struct GNUNET_FS_ShareTreeItem *item)
{  
  if (item->is_directory)
  {
    /* for directories, we simply only descent, no extraction, no
       progress reporting */
    struct GNUNET_FS_ShareTreeItem *pos;

    for (pos = item->children_head; NULL != pos; pos = pos->next)
      if (GNUNET_OK !=
	  extract_files (ds, pos))
	return GNUNET_SYSERR;
    return GNUNET_OK;
  }
  
  /* this is the expensive operation, *afterwards* we'll check for aborts */
  fprintf (stderr, "\tCalling extract on `%s'\n", item->filename);
  GNUNET_FS_meta_data_extract_from_file (item->meta, 
					 item->filename,
					 ds->plugins);
  fprintf (stderr, "\tExtract `%s' done\n", item->filename);

  /* having full filenames is too dangerous; always make sure we clean them up */
  GNUNET_CONTAINER_meta_data_delete (item->meta, 
				     EXTRACTOR_METATYPE_FILENAME,
				     NULL, 0);
  GNUNET_CONTAINER_meta_data_insert (item->meta, "<libgnunetfs>",
                                     EXTRACTOR_METATYPE_FILENAME,
                                     EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                     item->short_filename, 
				     strlen (item->short_filename) + 1);
  /* check for abort */
  if (GNUNET_OK != 
      test_thread_stop (ds))
    return GNUNET_SYSERR;

  /* Report the progress */
  if (GNUNET_OK !=
      write_progress (ds, 
		      item->filename, 
		      GNUNET_NO,
		      GNUNET_FS_DIRSCANNER_EXTRACT_FINISHED))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * The function from which the scanner thread starts
 *
 * @param cls the 'struct GNUNET_FS_DirScanner'
 * @return 0/NULL
 */
#if WINDOWS
DWORD
#else
static void *
#endif
run_directory_scan_thread (void *cls)
{
  struct GNUNET_FS_DirScanner *ds = cls;

  if (GNUNET_OK != preprocess_file (ds, 
				    ds->filename_expanded, 
				    &ds->toplevel))
  {
    (void) write_progress (ds, "", GNUNET_SYSERR, GNUNET_FS_DIRSCANNER_INTERNAL_ERROR);
    GNUNET_DISK_pipe_close_end (ds->progress_pipe, GNUNET_DISK_PIPE_END_WRITE);
    return 0;
  }
  if (GNUNET_OK !=
      write_progress (ds, "", GNUNET_SYSERR, GNUNET_FS_DIRSCANNER_ALL_COUNTED))
  {
    GNUNET_DISK_pipe_close_end (ds->progress_pipe, GNUNET_DISK_PIPE_END_WRITE);
    return 0;
  }
  if (GNUNET_OK !=
      extract_files (ds, ds->toplevel))
  {
    (void) write_progress (ds, "", GNUNET_SYSERR, GNUNET_FS_DIRSCANNER_INTERNAL_ERROR);
    GNUNET_DISK_pipe_close_end (ds->progress_pipe, GNUNET_DISK_PIPE_END_WRITE);
    return 0;
  }
  (void) write_progress (ds, "", GNUNET_SYSERR, GNUNET_FS_DIRSCANNER_FINISHED);
  GNUNET_DISK_pipe_close_end (ds->progress_pipe, GNUNET_DISK_PIPE_END_WRITE);
  return 0;
}


/**
 * Read 'size' bytes from 'in' into 'buf'.
 *
 * @param in pipe to read from
 * @param buf buffer to read to
 * @param size number of bytes to read
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
read_all (const struct GNUNET_DISK_FileHandle *in,
	  char *buf,
	  size_t size)
{
  size_t total;
  ssize_t rd;

  total = 0;
  do
  {
    rd = GNUNET_DISK_file_read (in,
				&buf[total],
				size - total);
    if (rd > 0)
      total += rd;
  } while ( (rd > 0) && (total < size) );
  if (rd <= 0)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Failed to read from inter thread communication pipe: %s\n",
		strerror (errno));
  return (total == size) ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Called every time there is data to read from the scanner.
 * Calls the scanner progress handler.
 *
 * @param cls the closure (directory scanner object)
 * @param tc task context in which the task is running
 */
static void
read_progress_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_DirScanner *ds = cls;
  enum GNUNET_FS_DirScannerProgressUpdateReason reason;
  size_t filename_len;
  int is_directory;
  char *filename;

  ds->progress_read_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY))
  {
    ds->progress_read_task
      = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
					ds->progress_read, &read_progress_task,
					ds);
    return;
  }

  /* Read one message. If message is malformed or can't be read, end the scanner */
  filename = NULL;
  if ( (GNUNET_OK !=
	read_all (ds->progress_read,
		  (char*) &reason,
		  sizeof (reason))) ||
       (reason < GNUNET_FS_DIRSCANNER_FILE_START) ||
       (reason > GNUNET_FS_DIRSCANNER_INTERNAL_ERROR) ||
       (GNUNET_OK !=
	read_all (ds->progress_read,
		  (char*) &filename_len,
		  sizeof (size_t))) ||
       (filename_len == 0) ||
       (filename_len > PATH_MAX) ||
       (GNUNET_OK !=
	read_all (ds->progress_read,
		  filename = GNUNET_malloc (filename_len),
		  filename_len)) ||
       (filename[filename_len-1] != '\0') ||
       (GNUNET_OK !=
	read_all (ds->progress_read,
		  (char*) &is_directory,
		  sizeof (is_directory))) )
  {
    /* IPC error, complain, signal client and stop reading
       from the pipe */
    GNUNET_break (0);
    ds->progress_callback (ds->progress_callback_cls, ds,
			   NULL, GNUNET_SYSERR, 
			   GNUNET_FS_DIRSCANNER_INTERNAL_ERROR);
    GNUNET_free_non_null (filename);
    return;
  }
  /* schedule task to keep reading (done here in case client calls
     abort or something similar) */
  if ( (reason != GNUNET_FS_DIRSCANNER_FINISHED) &&
       (reason != GNUNET_FS_DIRSCANNER_INTERNAL_ERROR) )
  {
    ds->progress_read_task 
      = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, 
					ds->progress_read, 
					&read_progress_task, ds);
  }
  /* read successfully, notify client about progress */
  ds->progress_callback (ds->progress_callback_cls, 
			 ds, 
			 filename,
			 is_directory, 
			 reason);
  GNUNET_free (filename);
}


/**
 * Start a directory scanner thread.
 *
 * @param filename name of the directory to scan
 * @param GNUNET_YES to not to run libextractor on files (only build a tree)
 * @param ex if not NULL, must be a list of extra plugins for extractor
 * @param cb the callback to call when there are scanning progress messages
 * @param cb_cls closure for 'cb'
 * @return directory scanner object to be used for controlling the scanner
 */
struct GNUNET_FS_DirScanner *
GNUNET_FS_directory_scan_start (const char *filename,
				int disable_extractor, const char *ex,
				GNUNET_FS_DirScannerProgressCallback cb, 
				void *cb_cls)
{
  struct stat sbuf;
  char *filename_expanded;
  struct GNUNET_FS_DirScanner *ds;
  struct GNUNET_DISK_PipeHandle *progress_pipe;
  struct GNUNET_DISK_PipeHandle *stop_pipe;
  int ok;

  if (0 != STAT (filename, &sbuf))
    return NULL;
  filename_expanded = GNUNET_STRINGS_filename_expand (filename);
  if (NULL == filename_expanded)
    return NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting to scan directory `%s'\n",
	      filename_expanded);
  progress_pipe = GNUNET_DISK_pipe (GNUNET_NO, GNUNET_NO, GNUNET_NO, GNUNET_NO);
  if (NULL == progress_pipe)
  {
    GNUNET_free (filename_expanded);
    return NULL;
  }
  stop_pipe = GNUNET_DISK_pipe (GNUNET_NO, GNUNET_NO, GNUNET_NO, GNUNET_NO);
  if (NULL == stop_pipe)
  {
    GNUNET_DISK_pipe_close (progress_pipe);
    GNUNET_free (filename_expanded);
    return NULL;
  }
  
  ds = GNUNET_malloc (sizeof (struct GNUNET_FS_DirScanner));
  ds->progress_callback = cb;
  ds->progress_callback_cls = cb_cls;
  ds->stop_pipe = stop_pipe;
  ds->stop_write = GNUNET_DISK_pipe_handle (ds->stop_pipe,
					    GNUNET_DISK_PIPE_END_WRITE);
  ds->stop_read = GNUNET_DISK_pipe_handle (ds->stop_pipe,
					   GNUNET_DISK_PIPE_END_READ);
  ds->progress_pipe = progress_pipe;
  ds->progress_write = GNUNET_DISK_pipe_handle (progress_pipe,
						GNUNET_DISK_PIPE_END_WRITE);
  ds->progress_read = GNUNET_DISK_pipe_handle (progress_pipe,
					       GNUNET_DISK_PIPE_END_READ);
  ds->filename_expanded = filename_expanded;
  if (! disable_extractor)
  {
    ds->plugins = EXTRACTOR_plugin_add_defaults (EXTRACTOR_OPTION_DEFAULT_POLICY);
    if ( (NULL != ex) && strlen (ex) > 0)
      ds->plugins = EXTRACTOR_plugin_add_config (ds->plugins, ex,
						 EXTRACTOR_OPTION_DEFAULT_POLICY);
  }
#if WINDOWS
  ds->thread = CreateThread (NULL, 0,
			     (LPTHREAD_START_ROUTINE) &run_directory_scan_thread, 
			     (LPVOID) ds, 0, NULL);
  ok = (ds->thread != NULL);
#else
  ok = (0 == pthread_create (&ds->thread, NULL, 
			     &run_directory_scan_thread, ds));
#endif
  if (!ok)
  {
    EXTRACTOR_plugin_remove_all (ds->plugins);
    GNUNET_free (filename_expanded);
    GNUNET_DISK_pipe_close (stop_pipe);
    GNUNET_DISK_pipe_close (progress_pipe);
    GNUNET_free (ds);
    return NULL;
  }
  ds->progress_read_task 
    = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, 
				      ds->progress_read, 
				      &read_progress_task, ds);
  return ds;
}


/* end of fs_dirmetascan.c */
