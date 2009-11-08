/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/test_fs_unindex.c
 * @brief simple testcase for simple publish + unindex operation
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

static struct GNUNET_FS_UnindexContext *unindex;

static struct GNUNET_FS_PublishContext *publish;

static char *fn;


static void
abort_publish_task (void *cls,
		     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_FS_publish_stop (publish);
  publish = NULL;
}


static void
abort_unindex_task (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_FS_unindex_stop (unindex);
  unindex = NULL;
  GNUNET_DISK_directory_remove (fn);
  GNUNET_free (fn);
  fn = NULL;
}


static void *
progress_cb (void *cls, 
	     const struct GNUNET_FS_ProgressInfo *event)
{

  switch (event->status)
    {
    case GNUNET_FS_STATUS_PUBLISH_PROGRESS:
#if VERBOSE
      printf ("Publish is progressing (%llu/%llu at level %u off %llu)...\n",
              (unsigned long long) event->value.publish.completed,
              (unsigned long long) event->value.publish.size,
	      event->value.publish.specifics.progress.depth,
	      (unsigned long long) event->value.publish.specifics.progress.offset);
#endif      
      break;
    case GNUNET_FS_STATUS_PUBLISH_COMPLETED:
      printf ("Publishing complete, %llu kbps.\n",
	      (unsigned long long) (FILESIZE * 1000 / (1+GNUNET_TIME_absolute_get_duration (start).value) / 1024));
      start = GNUNET_TIME_absolute_get ();
      unindex = GNUNET_FS_unindex_start (fs,
					 fn,
					 "unindex");
      GNUNET_assert (unindex != NULL);
      break;
    case GNUNET_FS_STATUS_UNINDEX_COMPLETED:
      printf ("Unindex complete,  %llu kbps.\n",
	      (unsigned long long) (FILESIZE * 1000 / (1+GNUNET_TIME_absolute_get_duration (start).value) / 1024));
      GNUNET_SCHEDULER_add_continuation (sched,
					 &abort_unindex_task,
					 NULL,
					 GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      break;
    case GNUNET_FS_STATUS_UNINDEX_PROGRESS:
      GNUNET_assert (unindex == event->value.unindex.uc);
#if VERBOSE
      printf ("Unindex is progressing (%llu/%llu at level %u off %llu)...\n",
              (unsigned long long) event->value.unindex.completed,
              (unsigned long long) event->value.unindex.size,
	      event->value.unindex.specifics.progress.depth,
	      (unsigned long long) event->value.unindex.specifics.progress.offset);
#endif
      break;
    case GNUNET_FS_STATUS_PUBLISH_ERROR:
      fprintf (stderr,
	       "Error publishing file: %s\n",
	       event->value.publish.specifics.error.message);
      GNUNET_break (0);
      GNUNET_SCHEDULER_add_continuation (sched,
					 &abort_publish_task,
					 NULL,
					 GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      break;
    case GNUNET_FS_STATUS_UNINDEX_ERROR:
      fprintf (stderr,
	       "Error unindexing file: %s\n",
	       event->value.unindex.specifics.error.message);
      GNUNET_SCHEDULER_add_continuation (sched,
					 &abort_unindex_task,
					 NULL,
					 GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      break;
    case GNUNET_FS_STATUS_PUBLISH_START:
      GNUNET_assert (0 == strcmp ("publish-context", event->value.publish.cctx));
      GNUNET_assert (NULL == event->value.publish.pctx);
      GNUNET_assert (FILESIZE == event->value.publish.size);
      GNUNET_assert (0 == event->value.publish.completed);
      GNUNET_assert (1 == event->value.publish.anonymity);
      break;
    case GNUNET_FS_STATUS_PUBLISH_STOPPED:
      GNUNET_assert (publish == event->value.publish.sc);
      GNUNET_assert (FILESIZE == event->value.publish.size);
      GNUNET_assert (1 == event->value.publish.anonymity);
      GNUNET_FS_stop (fs);
      fs = NULL;
      break;
    case GNUNET_FS_STATUS_UNINDEX_START:
      GNUNET_assert (unindex == NULL);
      GNUNET_assert (0 == strcmp ("unindex", event->value.unindex.cctx));
      GNUNET_assert (0 == strcmp (fn, event->value.unindex.filename));
      GNUNET_assert (FILESIZE == event->value.unindex.size);
      GNUNET_assert (0 == event->value.unindex.completed);
      break;
    case GNUNET_FS_STATUS_UNINDEX_STOPPED:
      GNUNET_assert (unindex == event->value.unindex.uc);
      GNUNET_SCHEDULER_add_continuation (sched,
					 &abort_publish_task,
					 NULL,
					 GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      break;
    default:
      printf ("Unexpected event: %d\n", 
	      event->status);
      break;
    }
  return NULL;
}


static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_pid = GNUNET_OS_start_process ("gnunet-service-arm",
                                        "gnunet-service-arm",
#if VERBOSE
                                        "-L", "DEBUG",
#endif
                                        "-c", cfgname, NULL);
  sleep (1);                    /* allow ARM to start */
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  GNUNET_ARM_start_services (p->cfg, sched, "core", NULL);
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
  struct GNUNET_FS_FileInformation *fi;
  size_t i;

  sched = s;
  setup_peer (&p1, "test_fs_unindex_data.conf");
  fn = GNUNET_DISK_mktemp ("gnunet-unindex-test-dst");
  fs = GNUNET_FS_start (sched,
			cfg,
			"test-fs-unindex",
			&progress_cb,
			NULL,
			GNUNET_FS_FLAGS_NONE,
			GNUNET_FS_OPTIONS_END);
  GNUNET_assert (NULL != fs); 
  buf = GNUNET_malloc (FILESIZE);
  for (i = 0; i < FILESIZE; i++)
    buf[i] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 256);
  GNUNET_assert (FILESIZE ==
		 GNUNET_DISK_fn_write (fn,
				       buf,
				       FILESIZE,
				       GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE));
  GNUNET_free (buf);
  meta = GNUNET_CONTAINER_meta_data_create ();
  kuri = GNUNET_FS_uri_ksk_create_from_args (2, keywords);
  fi = GNUNET_FS_file_information_create_from_file ("publish-context",
						    fn,
						    kuri,
						    meta,
						    GNUNET_YES,
						    1,
						    42,
						    GNUNET_TIME_relative_to_absolute (LIFETIME)); 
  GNUNET_FS_uri_destroy (kuri);
  GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_assert (NULL != fi);
  start = GNUNET_TIME_absolute_get ();
  publish = GNUNET_FS_publish_start (fs,
				    fi,
				    NULL, NULL, NULL,
				    GNUNET_FS_PUBLISH_OPTION_NONE);
  GNUNET_assert (publish != NULL);
}


int
main (int argc, char *argv[])
{
  char *const argvx[] = { 
    "test-fs-unindex",
    "-c",
    "test_fs_unindex_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_log_setup ("test_fs_unindex", 
#if VERBOSE
		    "DEBUG",
#else
		    "WARNING",
#endif
		    NULL);
  GNUNET_PROGRAM_run ((sizeof (argvx) / sizeof (char *)) - 1,
                      argvx, "test-fs-unindex",
		      "nohelp", options, &run, NULL);
  stop_arm (&p1);
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-unindex/");
  GNUNET_DISK_directory_remove (fn);
  GNUNET_free_non_null (fn);
  return 0;
}

/* end of test_fs_unindex.c */
