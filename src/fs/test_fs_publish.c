/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/test_fs_publish.c
 * @brief simple testcase for publish operation (indexing, listing
 *        indexed, directory structure)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_fs_service.h"

#define VERBOSE GNUNET_NO

#define START_ARM GNUNET_YES

/**
 * File-size we use for testing.
 */
#define FILESIZE (1024 * 1024 * 2)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/**
 * How long should our test-content live?
 */ 
#define LIFETIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 15)

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
#if START_ARM
  pid_t arm_pid;
#endif
};

static struct PeerContext p1;

static struct GNUNET_TIME_Absolute start;

static struct GNUNET_SCHEDULER_Handle *sched;

static struct GNUNET_FS_Handle *fs;

static struct GNUNET_FS_PublishContext *publish;

static char *fn1;

static char *fn2;

static int err;

static void
abort_publish_task (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_FS_publish_stop (publish);
  publish = NULL;
  GNUNET_DISK_directory_remove (fn1);
  GNUNET_free (fn1);
  fn1 = NULL;
  GNUNET_DISK_directory_remove (fn2);
  GNUNET_free (fn2);
  fn2 = NULL;
}


static void *
progress_cb (void *cls, 
	     const struct GNUNET_FS_ProgressInfo *event)
{
  void *ret;

  ret = NULL;
  switch (event->status)
    {
    case GNUNET_FS_STATUS_PUBLISH_COMPLETED:
      ret = event->value.publish.cctx;
      printf ("Publish complete,  %llu kbps.\n",
	      (unsigned long long) (FILESIZE * 1000 / (1+GNUNET_TIME_absolute_get_duration (start).value) / 1024));
      if (0 == strcmp ("publish-context-dir", 
		       event->value.publish.cctx))	
	GNUNET_SCHEDULER_add_continuation (sched,
					   &abort_publish_task,
					   NULL,
					   GNUNET_SCHEDULER_REASON_PREREQ_DONE);	
      break;
    case GNUNET_FS_STATUS_PUBLISH_PROGRESS:
      ret = event->value.publish.cctx;
      GNUNET_assert (publish == event->value.publish.pc);
#if VERBOSE
      printf ("Publish is progressing (%llu/%llu at level %u off %llu)...\n",
              (unsigned long long) event->value.publish.completed,
              (unsigned long long) event->value.publish.size,
	      event->value.publish.specifics.progress.depth,
	      (unsigned long long) event->value.publish.specifics.progress.offset);
#endif
      break;
    case GNUNET_FS_STATUS_PUBLISH_ERROR:
      ret = event->value.publish.cctx;
      fprintf (stderr,
	       "Error publishing file: %s\n",
	       event->value.publish.specifics.error.message);
      err = 1;
      if (0 == strcmp ("publish-context-dir", 
		       event->value.publish.cctx))		
	{
	  fprintf (stderr, "Scheduling abort task for error on `%s'\n",
		   (const char*) event->value.publish.cctx);
	  GNUNET_SCHEDULER_add_continuation (sched,
					     &abort_publish_task,
					     NULL,
					     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
	}
      break;
    case GNUNET_FS_STATUS_PUBLISH_START:
      ret = event->value.publish.cctx;
      if (0 == strcmp ("publish-context1", 
		       event->value.publish.cctx))
	{
	  GNUNET_assert (0 == strcmp ("publish-context-dir", 
				      event->value.publish.pctx));
	  GNUNET_assert (FILESIZE == event->value.publish.size);
	  GNUNET_assert (0 == event->value.publish.completed);
	  GNUNET_assert (1 == event->value.publish.anonymity);
	}
      else if (0 == strcmp ("publish-context2", 
			    event->value.publish.cctx))
	{
	  GNUNET_assert (0 == strcmp ("publish-context-dir", 
				      event->value.publish.pctx));
	  GNUNET_assert (FILESIZE == event->value.publish.size);
	  GNUNET_assert (0 == event->value.publish.completed);
	  GNUNET_assert (2 == event->value.publish.anonymity);
	}
      else if (0 == strcmp ("publish-context-dir", 
			    event->value.publish.cctx))
	{
	  GNUNET_assert (0 == event->value.publish.completed);
	  GNUNET_assert (3 == event->value.publish.anonymity);
	}
      else
	GNUNET_assert (0);
      break;
    case GNUNET_FS_STATUS_PUBLISH_STOPPED:
      if (0 == strcmp ("publish-context-dir", 
		       event->value.publish.cctx))	
	GNUNET_assert (publish == event->value.publish.pc);	
      break;
    default:
      printf ("Unexpected event: %d\n", 
	      event->status);
      break;
    }
  return ret;
}


static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_pid = GNUNET_OS_start_process (NULL, NULL, "gnunet-service-arm",
                                        "gnunet-service-arm",
#if VERBOSE
                                        "-L", "DEBUG",
#endif
                                        "-c", cfgname, NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
}


static void
stop_arm (struct PeerContext *p)
{
#if START_ARM
  if (0 != PLIBC_KILL (p->arm_pid, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  if (GNUNET_OS_process_wait(p->arm_pid) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "ARM process %u stopped\n", p->arm_pid);
#endif
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  const char *keywords[] = {
    "down_foo",
    "down_bar",
  };
  char *buf;
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_FS_Uri *kuri;
  struct GNUNET_FS_FileInformation *fi1;
  struct GNUNET_FS_FileInformation *fi2;
  struct GNUNET_FS_FileInformation *fidir;
  size_t i;

  sched = s;
  setup_peer (&p1, "test_fs_publish_data.conf");
  fs = GNUNET_FS_start (sched,
			cfg,
			"test-fs-publish",
			&progress_cb,
			NULL,
			GNUNET_FS_FLAGS_NONE,
			GNUNET_FS_OPTIONS_END);
  GNUNET_assert (NULL != fs); 
  fn1 = GNUNET_DISK_mktemp ("gnunet-publish-test-dst");
  buf = GNUNET_malloc (FILESIZE);
  for (i = 0; i < FILESIZE; i++)
    buf[i] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 256);
  GNUNET_assert (FILESIZE ==
		 GNUNET_DISK_fn_write (fn1,
				       buf,
				       FILESIZE,
				       GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE));
  GNUNET_free (buf);

  fn2 = GNUNET_DISK_mktemp ("gnunet-publish-test-dst");
  buf = GNUNET_malloc (FILESIZE);
  for (i = 0; i < FILESIZE; i++)
    buf[i] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 256);
  GNUNET_assert (FILESIZE ==
		 GNUNET_DISK_fn_write (fn2,
				       buf,
				       FILESIZE,
				       GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE));
  GNUNET_free (buf);

  meta = GNUNET_CONTAINER_meta_data_create ();
  kuri = GNUNET_FS_uri_ksk_create_from_args (2, keywords);
  fi1 = GNUNET_FS_file_information_create_from_file (fs,
						     "publish-context1",
						     fn1,
						     kuri,
						     meta,
						     GNUNET_YES,
						     1,
						     42,
						     GNUNET_TIME_relative_to_absolute (LIFETIME)); 
  GNUNET_assert (NULL != fi1);
  fi2 = GNUNET_FS_file_information_create_from_file (fs,
						     "publish-context2",
						     fn2,
						     kuri,
						     meta,
						     GNUNET_YES,
						     2,
						     42,
						     GNUNET_TIME_relative_to_absolute (LIFETIME)); 
  GNUNET_assert (NULL != fi2);
  fidir = GNUNET_FS_file_information_create_empty_directory (fs,
							     "publish-context-dir",
							     kuri,
							     meta,
							     3,
							     42,
							     GNUNET_TIME_relative_to_absolute (LIFETIME)); 
  GNUNET_assert (GNUNET_OK == GNUNET_FS_file_information_add (fidir, fi1));
  GNUNET_assert (GNUNET_OK == GNUNET_FS_file_information_add (fidir, fi2));
  GNUNET_FS_uri_destroy (kuri);
  GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_assert (NULL != fidir);
  start = GNUNET_TIME_absolute_get ();
  publish = GNUNET_FS_publish_start (fs,
				     fidir,
				     NULL, NULL, NULL,
				     GNUNET_FS_PUBLISH_OPTION_NONE);
  GNUNET_assert (publish != NULL);
}


int
main (int argc, char *argv[])
{
  char *const argvx[] = { 
    "test-fs-publish",
    "-c",
    "test_fs_publish_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_log_setup ("test_fs_publish", 
#if VERBOSE
		    "DEBUG",
#else
		    "WARNING",
#endif
		    NULL);
  GNUNET_PROGRAM_run ((sizeof (argvx) / sizeof (char *)) - 1,
                      argvx, "test-fs-publish",
		      "nohelp", options, &run, NULL);
  stop_arm (&p1);
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-publish/");
  if (fn1 != NULL)
    {
      GNUNET_DISK_directory_remove (fn1);
      GNUNET_free (fn1);
    }
  if (fn2 != NULL)
    {
      GNUNET_DISK_directory_remove (fn2);
      GNUNET_free (fn2);
    }
  return err;
}

/* end of test_fs_publish.c */
