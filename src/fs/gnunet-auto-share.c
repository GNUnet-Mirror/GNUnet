/*
     This file is part of GNUnet.
     Copyright (C) 2001--2012 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file fs/gnunet-auto-share.c
 * @brief automatically publish files on GNUnet
 * @author Christian Grothoff
 *
 * TODO:
 * - support loading meta data / keywords from resource file
 * - add stability timer (a la buildbot)
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#define MIN_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 4)

#define MAX_FREQUENCY GNUNET_TIME_UNIT_MINUTES


/**
 * Item in our work queue (or in the set of files/directories
 * we have successfully published).
 */
struct WorkItem
{

  /**
   * PENDING Work is kept in a linked list.
   */
  struct WorkItem *prev;

  /**
   * PENDING Work is kept in a linked list.
   */
  struct WorkItem *next;

  /**
   * Filename of the work item.
   */
  char *filename;

  /**
   * Unique identity for this work item (used to detect
   * if we need to do the work again).
   */
  struct GNUNET_HashCode id;
};


/**
 * Global return value from 'main'.
 */
static int ret;

/**
 * Are we running 'verbosely'?
 */
static int verbose;

/**
 * Configuration to use.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Name of the configuration file.
 */
static char *cfg_filename;

/**
 * Disable extractor option to use for publishing.
 */
static int disable_extractor;

/**
 * Disable creation time option to use for publishing.
 */
static int do_disable_creation_time;

/**
 * Handle for the 'shutdown' task.
 */
static struct GNUNET_SCHEDULER_Task *kill_task;

/**
 * Handle for the main task that does scanning and working.
 */
static struct GNUNET_SCHEDULER_Task *run_task;

/**
 * Anonymity level option to use for publishing.
 */
static unsigned int anonymity_level = 1;

/**
 * Content priority option to use for publishing.
 */
static unsigned int content_priority = 365;

/**
 * Replication level option to use for publishing.
 */
static unsigned int replication_level = 1;

/**
 * Top-level directory we monitor to auto-publish.
 */
static const char *dir_name;

/**
 * Head of linked list of files still to publish.
 */
static struct WorkItem *work_head;

/**
 * Tail of linked list of files still to publish.
 */
static struct WorkItem *work_tail;

/**
 * Map from the hash of the filename (!) to a `struct WorkItem`
 * that was finished.
 */
static struct GNUNET_CONTAINER_MultiHashMap *work_finished;

/**
 * Set to #GNUNET_YES if we are shutting down.
 */
static int do_shutdown;

/**
 * Start time of the current round; used to determine how long
 * one iteration takes (which influences how fast we schedule
 * the next one).
 */
static struct GNUNET_TIME_Absolute start_time;

/**
 * Pipe used to communicate 'gnunet-publish' completion (SIGCHLD) via signal.
 */
static struct GNUNET_DISK_PipeHandle *sigpipe;

/**
 * Handle to the 'gnunet-publish' process that we executed.
 */
static struct GNUNET_OS_Process *publish_proc;


/**
 * Compute the name of the state database file we will use.
 */
static char *
get_state_file ()
{
  char *ret;

  GNUNET_asprintf (&ret,
		   "%s%s.auto-share",
		   dir_name,
		   (DIR_SEPARATOR == dir_name[strlen(dir_name)-1]) ? "" : DIR_SEPARATOR_STR);
  return ret;
}


/**
 * Load the set of #work_finished items from disk.
 */
static void
load_state ()
{
  char *fn;
  struct GNUNET_BIO_ReadHandle *rh;
  uint32_t n;
  struct GNUNET_HashCode id;
  struct WorkItem *wi;
  char *emsg;

  emsg = NULL;
  fn = get_state_file ();
  rh = GNUNET_BIO_read_open (fn);
  GNUNET_free (fn);
  if (NULL == rh)
    return;
  fn = NULL;
  if (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &n))
    goto error;
  while (n-- > 0)
  {
    if ( (GNUNET_OK !=
	  GNUNET_BIO_read_string (rh, "filename", &fn, 1024)) ||
	 (GNUNET_OK !=
	  GNUNET_BIO_read (rh, "id", &id, sizeof (struct GNUNET_HashCode))) )
      goto error;
    wi = GNUNET_new (struct WorkItem);
    wi->id = id;
    wi->filename = fn;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Loaded serialization ID for `%s' is `%s'\n",
		wi->filename,
		GNUNET_h2s (&id));
    fn = NULL;
    GNUNET_CRYPTO_hash (wi->filename,
			strlen (wi->filename),
			&id);
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONTAINER_multihashmap_put (work_finished,
                                                     &id,
                                                     wi,
                                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  if (GNUNET_OK ==
      GNUNET_BIO_read_close (rh, &emsg))
    return;
  rh = NULL;
 error:
  GNUNET_free_non_null (fn);
  if (NULL != rh)
    (void) GNUNET_BIO_read_close (rh, &emsg);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
	      _("Failed to load state: %s\n"),
	      emsg);
  GNUNET_free_non_null (emsg);
}


/**
 * Write work item from the #work_finished map to the given write handle.
 *
 * @param cls the `struct GNUNET_BIO_WriteHandle *`
 * @param key key of the item in the map (unused)
 * @param value the `struct WorkItem` to write
 * @return #GNUNET_OK to continue to iterate (if write worked)
 */
static int
write_item (void *cls,
	    const struct GNUNET_HashCode *key,
	    void *value)
{
  struct GNUNET_BIO_WriteHandle *wh = cls;
  struct WorkItem *wi = value;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Saving serialization ID of file `%s' with value `%s'\n",
	      wi->filename,
	      GNUNET_h2s (&wi->id));
  if ( (GNUNET_OK !=
	GNUNET_BIO_write_string (wh, wi->filename)) ||
       (GNUNET_OK !=
	GNUNET_BIO_write (wh,
			  &wi->id,
			  sizeof (struct GNUNET_HashCode))) )
    return GNUNET_SYSERR; /* write error, abort iteration */
  return GNUNET_OK;
}


/**
 * Save the set of #work_finished items on disk.
 */
static void
save_state ()
{
  uint32_t n;
  struct GNUNET_BIO_WriteHandle *wh;
  char *fn;

  n = GNUNET_CONTAINER_multihashmap_size (work_finished);
  fn = get_state_file ();
  wh = GNUNET_BIO_write_open (fn);
  if (NULL == wh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to save state to file %s\n"),
		fn);
    GNUNET_free (fn);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_BIO_write_int32 (wh, n))
  {
    (void) GNUNET_BIO_write_close (wh);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to save state to file %s\n"),
		fn);
    GNUNET_free (fn);
    return;
  }
  (void) GNUNET_CONTAINER_multihashmap_iterate (work_finished,
						&write_item,
						wh);
  if (GNUNET_OK != GNUNET_BIO_write_close (wh))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to save state to file %s\n"),
		fn);
  GNUNET_free (fn);
}


/**
 * Task run on shutdown.  Serializes our current state to disk.
 *
 * @param cls closure, unused
 * @param tc scheduler context, unused
 */
static void
do_stop_task (void *cls, 
	      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  kill_task = NULL;
  do_shutdown = GNUNET_YES;
  if (NULL != publish_proc)
  {
    GNUNET_OS_process_kill (publish_proc, 
			    SIGKILL);
    return;
  }
  if (NULL != run_task)
  {
    GNUNET_SCHEDULER_cancel (run_task);
    run_task = NULL;
  }
}


/**
 * Decide what the next task is (working or scanning) and schedule it.
 */
static void
schedule_next_task (void);


/**
 * Task triggered whenever we receive a SIGCHLD (child
 * process died).
 *
 * @param cls the `struct WorkItem` we were working on
 * @param tc context
 */
static void
maint_child_death (void *cls, 
		   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct WorkItem *wi = cls;
  struct GNUNET_HashCode key;
  enum GNUNET_OS_ProcessStatusType type;
  unsigned long code;
  int ret;
  char c;
  const struct GNUNET_DISK_FileHandle *pr;

  run_task = NULL;
  pr = GNUNET_DISK_pipe_handle (sigpipe,
				GNUNET_DISK_PIPE_END_READ);
  if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY))
  {
    /* shutdown scheduled us, someone else will kill child,
       we should just try again */
    run_task =
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
				      pr,
				      &maint_child_death, wi);
    return;
  }
  /* consume the signal */
  GNUNET_break (0 < GNUNET_DISK_file_read (pr, &c, sizeof (c)));

  ret = GNUNET_OS_process_status (publish_proc,
				  &type,
				  &code);
  GNUNET_assert (GNUNET_SYSERR != ret);
  if (GNUNET_NO == ret)
  {
    /* process still running? Then where did the SIGCHLD come from?
       Well, let's declare it spurious (kernel bug?) and keep rolling.
    */  
    GNUNET_break (0);
    run_task =
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
				      pr,
				      &maint_child_death, wi);
    return;
  }
  GNUNET_assert (GNUNET_OK == ret);
  
  GNUNET_OS_process_destroy (publish_proc);
  publish_proc = NULL;

  if (GNUNET_YES == do_shutdown)
  {
    GNUNET_free (wi->filename);
    GNUNET_free (wi);
    return;
  }
  if ( (GNUNET_OS_PROCESS_EXITED == type) &&
       (0 == code) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Publication of `%s' done\n"),
		wi->filename);
    GNUNET_CRYPTO_hash (wi->filename,
			strlen (wi->filename),
			&key);
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONTAINER_multihashmap_put (work_finished,
                                                     &key,
                                                     wi,
                                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  else
  {
    GNUNET_CONTAINER_DLL_insert_tail (work_head,
				      work_tail,
				      wi);
  }
  save_state ();
  schedule_next_task ();
}


/**
 * Signal handler called for SIGCHLD.  Triggers the
 * respective handler by writing to the trigger pipe.
 */
static void
sighandler_child_death ()
{
  static char c;
  int old_errno = errno;	/* back-up errno */

  GNUNET_break (1 ==
		GNUNET_DISK_file_write (GNUNET_DISK_pipe_handle
					(sigpipe,
					 GNUNET_DISK_PIPE_END_WRITE),
					&c, sizeof (c)));
  errno = old_errno;		/* restore errno */
}


/**
 * Function called to process work items.
 *
 * @param cls closure, NULL
 * @param tc scheduler context (unused)
 */
static void
work (void *cls,
      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static char *argv[14];
  static char anon_level[20];
  static char content_prio[20];
  static char repl_level[20];
  struct WorkItem *wi;
  const struct GNUNET_DISK_FileHandle *pr;
  int argc;

  run_task = NULL;
  wi = work_head;
  GNUNET_CONTAINER_DLL_remove (work_head,
			       work_tail,
			       wi);
  argc = 0;
  argv[argc++] = "gnunet-publish";
  if (verbose)
    argv[argc++] = "-V";
  if (disable_extractor)
    argv[argc++] = "-D";
  if (do_disable_creation_time)
    argv[argc++] = "-d";
  argv[argc++] = "-c";
  argv[argc++] = cfg_filename;
  GNUNET_snprintf (anon_level, sizeof (anon_level),
		   "%u", anonymity_level);
  argv[argc++] = "-a";
  argv[argc++] = anon_level;
  GNUNET_snprintf (content_prio, sizeof (content_prio),
		   "%u", content_priority);
  argv[argc++] = "-p";
  argv[argc++] = content_prio;
  GNUNET_snprintf (repl_level, sizeof (repl_level),
		   "%u", replication_level);
  argv[argc++] = "-r";
  argv[argc++] = repl_level;
  argv[argc++] = wi->filename;
  argv[argc] = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Publishing `%s'\n"),
	      wi->filename);
  GNUNET_assert (NULL == publish_proc);
  publish_proc = GNUNET_OS_start_process_vap (GNUNET_YES,
                                              0, NULL, NULL, NULL,
					      "gnunet-publish",
					      argv);
  if (NULL == publish_proc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to run `%s'\n"),
		"gnunet-publish");
    GNUNET_CONTAINER_DLL_insert (work_head,
				 work_tail,
				 wi);
    run_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
					     &work,
					     NULL);
    return;
  }
  pr = GNUNET_DISK_pipe_handle (sigpipe, 
				GNUNET_DISK_PIPE_END_READ);
  run_task =
    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
				    pr,
				    &maint_child_death, wi);
}


/**
 * Recursively scan the given file/directory structure to determine
 * a unique ID that represents the current state of the hierarchy.
 *
 * @param cls where to store the unique ID we are computing
 * @param filename file to scan
 * @return #GNUNET_OK (always)
 */
static int
determine_id (void *cls,
	      const char *filename)
{
  struct GNUNET_HashCode *id = cls;
  struct stat sbuf;
  struct GNUNET_HashCode fx[2];
  struct GNUNET_HashCode ft;

  if (0 != STAT (filename, &sbuf))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, 
			      "stat", 
			      filename);
    return GNUNET_OK;
  }
  GNUNET_CRYPTO_hash (filename, 
		      strlen (filename), 
		      &fx[0]);
  if (!S_ISDIR (sbuf.st_mode))
  {
    uint64_t fattr[2];

    fattr[0] = GNUNET_htonll (sbuf.st_size);
    fattr[0] = GNUNET_htonll (sbuf.st_mtime);

    GNUNET_CRYPTO_hash (fattr, 
			sizeof (fattr), 
			&fx[1]);
  }
  else
  {
    memset (&fx[1],
	    1,
	    sizeof (struct GNUNET_HashCode));
    GNUNET_DISK_directory_scan (filename,
				&determine_id,
				&fx[1]);
  }
  /* use hash here to make hierarchical structure distinct from
     all files on the same level */
  GNUNET_CRYPTO_hash (fx, 
		      sizeof (fx),
		      &ft);
  /* use XOR here so that order of the files in the directory
     does not matter! */
  GNUNET_CRYPTO_hash_xor (&ft,
			  id,
			  id);
  return GNUNET_OK;
}


/**
 * Function called with a filename (or directory name) to publish
 * (if it has changed since the last time we published it).  This function
 * is called for the top-level files only.
 *
 * @param cls closure, NULL
 * @param filename complete filename (absolute path)
 * @return #GNUNET_OK to continue to iterate, #GNUNET_SYSERR during shutdown
 */
static int
add_file (void *cls,
	  const char *filename)
{
  struct WorkItem *wi;
  struct GNUNET_HashCode key;
  struct GNUNET_HashCode id;

  if (GNUNET_YES == do_shutdown)
    return GNUNET_SYSERR;
  if ( (NULL != strstr (filename,
		      "/.auto-share")) ||
       (NULL != strstr (filename,
			"\\.auto-share")) )
    return GNUNET_OK; /* skip internal file */
  GNUNET_CRYPTO_hash (filename,
		      strlen (filename),
		      &key);
  wi = GNUNET_CONTAINER_multihashmap_get (work_finished,
					  &key);
  memset (&id, 0, sizeof (struct GNUNET_HashCode));
  determine_id (&id, filename);
  if (NULL != wi)
  {
    if (0 == memcmp (&id,
		     &wi->id,
		     sizeof (struct GNUNET_HashCode)))
      return GNUNET_OK; /* skip: we did this one already */
    /* contents changed, need to re-do the directory... */
    GNUNET_assert (GNUNET_YES ==
		   GNUNET_CONTAINER_multihashmap_remove (work_finished,
							 &key,
							 wi));
  }
  else
  {
    wi = GNUNET_new (struct WorkItem);
    wi->filename = GNUNET_strdup (filename);
  }
  wi->id = id;
  GNUNET_CONTAINER_DLL_insert (work_head,
			       work_tail,
			       wi);
  if (GNUNET_YES == do_shutdown)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Periodically run task to update our view of the directory to share.
 *
 * @param cls NULL
 * @param tc scheduler context, unused
 */
static void
scan (void *cls, 
      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  run_task = NULL;
  start_time = GNUNET_TIME_absolute_get ();
  (void) GNUNET_DISK_directory_scan (dir_name,
				     &add_file,
				     NULL);
  schedule_next_task ();
}


/**
 * Decide what the next task is (working or scanning) and schedule it.
 */
static void
schedule_next_task ()
{
  struct GNUNET_TIME_Relative delay;

  if (GNUNET_YES == do_shutdown)
    return;
  GNUNET_assert (NULL == run_task);
  if (NULL == work_head)
  {
    /* delay by at most 4h, at least 1s, and otherwise in between depending
       on how long it took to scan */
    delay = GNUNET_TIME_absolute_get_duration (start_time);
    delay = GNUNET_TIME_relative_min (MIN_FREQUENCY,
				      GNUNET_TIME_relative_multiply (delay,
								     100));
    delay = GNUNET_TIME_relative_max (delay,
				      MAX_FREQUENCY);
    run_task = GNUNET_SCHEDULER_add_delayed (delay,
					     &scan,
					     NULL);
  }
  else
  {
    run_task = GNUNET_SCHEDULER_add_now (&work, 
					 NULL);
  }
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls, 
     char *const *args, 
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  /* check arguments */
  if ( (NULL == args[0]) || 
       (NULL != args[1]) ||
       (GNUNET_YES != 
	GNUNET_DISK_directory_test (args[0],
				    GNUNET_YES)) )
  {
    printf (_("You must specify one and only one directory name for automatic publication.\n"));
    ret = -1;
    return;
  }
  cfg_filename = GNUNET_strdup (cfgfile);
  cfg = c;
  dir_name = args[0];
  work_finished = GNUNET_CONTAINER_multihashmap_create (1024, 
							GNUNET_NO);
  load_state ();
  run_task = GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE,
						 &scan, 
						 NULL);
  kill_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, 
				    &do_stop_task,
                                    NULL);
}


/**
 * Free memory associated with the work item from the work_finished map.
 *
 * @param cls NULL (unused)
 * @param key key of the item in the map (unused)
 * @param value the `struct WorkItem` to free
 * @return #GNUNET_OK to continue to iterate
 */
static int
free_item (void *cls,
	   const struct GNUNET_HashCode *key,
	   void *value)
{
  struct WorkItem *wi = value;

  GNUNET_free (wi->filename);
  GNUNET_free (wi);
  return GNUNET_OK;
}


/**
 * The main function to automatically publish content to GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'a', "anonymity", "LEVEL",
     gettext_noop ("set the desired LEVEL of sender-anonymity"),
     1, &GNUNET_GETOPT_set_uint, &anonymity_level},
    {'d', "disable-creation-time", NULL,
     gettext_noop
     ("disable adding the creation time to the metadata of the uploaded file"),
     0, &GNUNET_GETOPT_set_one, &do_disable_creation_time},
    {'D', "disable-extractor", NULL,
     gettext_noop ("do not use libextractor to add keywords or metadata"),
     0, &GNUNET_GETOPT_set_one, &disable_extractor},
    {'p', "priority", "PRIORITY",
     gettext_noop ("specify the priority of the content"),
     1, &GNUNET_GETOPT_set_uint, &content_priority},
    {'r', "replication", "LEVEL",
     gettext_noop ("set the desired replication LEVEL"),
     1, &GNUNET_GETOPT_set_uint, &replication_level},
    {'V', "verbose", NULL,
     gettext_noop ("be verbose (print progress information)"),
     0, &GNUNET_GETOPT_set_one, &verbose},
    GNUNET_GETOPT_OPTION_END
  };
  struct WorkItem *wi;
  int ok;
  struct GNUNET_SIGNAL_Context *shc_chld;

  if (GNUNET_OK != 
      GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  sigpipe = GNUNET_DISK_pipe (GNUNET_NO, GNUNET_NO, 
			      GNUNET_NO, GNUNET_NO);
  GNUNET_assert (NULL != sigpipe);
  shc_chld =
    GNUNET_SIGNAL_handler_install (GNUNET_SIGCHLD,
				   &sighandler_child_death);
  ok = (GNUNET_OK ==
	GNUNET_PROGRAM_run (argc, argv, 
			    "gnunet-auto-share [OPTIONS] FILENAME",
			    gettext_noop
			    ("Automatically publish files from a directory on GNUnet"),
			    options, &run, NULL)) ? ret : 1;
  if (NULL != work_finished)
  {
    (void) GNUNET_CONTAINER_multihashmap_iterate (work_finished,
						  &free_item,
						  NULL);
    GNUNET_CONTAINER_multihashmap_destroy (work_finished);
  }
  while (NULL != (wi = work_head))
  {
    GNUNET_CONTAINER_DLL_remove (work_head, 
				 work_tail,
				 wi);
    GNUNET_free (wi->filename);
    GNUNET_free (wi);
  }
  GNUNET_SIGNAL_handler_uninstall (shc_chld);
  shc_chld = NULL;
  GNUNET_DISK_pipe_close (sigpipe);
  sigpipe = NULL;
  GNUNET_free (cfg_filename);
  cfg_filename = NULL;
  GNUNET_free ((void*) argv);
  return ok;
}

/* end of gnunet-auto-share.c */
