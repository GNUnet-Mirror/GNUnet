/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2008, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file fs/test_fs_download_persistence.c
 * @brief simple testcase for persistence of simple download operation
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_fs_service.h"

#define VERBOSE GNUNET_EXTRA_LOGGING

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
  struct GNUNET_OS_Process *arm_proc;
#endif
};

static struct PeerContext p1;

static struct GNUNET_TIME_Absolute start;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_FS_Handle *fs;

static struct GNUNET_FS_DownloadContext *download;

static struct GNUNET_FS_PublishContext *publish;

static GNUNET_SCHEDULER_TaskIdentifier timeout_kill;

static char *fn;

static int err;

static void
timeout_kill_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Timeout downloading file\n");
  if (download != NULL)
  {
    GNUNET_FS_download_stop (download, GNUNET_YES);
    download = NULL;
  }
  else if (publish != NULL)
  {
    GNUNET_FS_publish_stop (publish);
    publish = NULL;
  }
  timeout_kill = GNUNET_SCHEDULER_NO_TASK;
  err = 1;
}

static void
abort_publish_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (publish != NULL)
  {
    GNUNET_FS_publish_stop (publish);
    publish = NULL;
  }
}


static void
abort_download_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  uint64_t size;

  if (download != NULL)
  {
    GNUNET_FS_download_stop (download, GNUNET_YES);
    download = NULL;
  }
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_size (fn, &size, GNUNET_YES));
  GNUNET_assert (size == FILESIZE);
  GNUNET_DISK_directory_remove (fn);
  GNUNET_free (fn);
  fn = NULL;
  GNUNET_SCHEDULER_cancel (timeout_kill);
  timeout_kill = GNUNET_SCHEDULER_NO_TASK;
}


static void *
progress_cb (void *cls, const struct GNUNET_FS_ProgressInfo *event);


static void
restart_fs_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Restarting FS.\n");
  GNUNET_FS_stop (fs);
  fs = GNUNET_FS_start (cfg, "test-fs-download-persistence", &progress_cb, NULL,
                        GNUNET_FS_FLAGS_PERSISTENCE, GNUNET_FS_OPTIONS_END);
}


/**
 * Consider scheduling the restart-task.
 * Only runs the restart task once per event
 * category.
 *
 * @param ev type of the event to consider
 */
static void
consider_restart (int ev)
{
  static int prev[32];
  static int off;
  int i;

  for (i = 0; i < off; i++)
    if (prev[i] == ev)
      return;
  prev[off++] = ev;
  GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_URGENT,
                                      &restart_fs_task, NULL);
}


static void *
progress_cb (void *cls, const struct GNUNET_FS_ProgressInfo *event)
{
  switch (event->status)
  {
  case GNUNET_FS_STATUS_PUBLISH_PROGRESS:
#if VERBOSE
    printf ("Publish is progressing (%llu/%llu at level %u off %llu)...\n",
            (unsigned long long) event->value.publish.completed,
            (unsigned long long) event->value.publish.size,
            event->value.publish.specifics.progress.depth,
            (unsigned long long) event->value.publish.specifics.
            progress.offset);
#endif
    break;
  case GNUNET_FS_STATUS_PUBLISH_COMPLETED:
    printf ("Publishing complete, %llu kbps.\n",
            (unsigned long long) (FILESIZE * 1000LL /
                                  (1 +
                                   GNUNET_TIME_absolute_get_duration
                                   (start).rel_value) / 1024LL));
    fn = GNUNET_DISK_mktemp ("gnunet-download-test-dst");
    start = GNUNET_TIME_absolute_get ();
    GNUNET_assert (download == NULL);
    GNUNET_FS_download_start (fs,
                              event->value.publish.specifics.completed.chk_uri,
                              NULL, fn, NULL, 0, FILESIZE, 1,
                              GNUNET_FS_DOWNLOAD_OPTION_NONE, "download", NULL);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_COMPLETED:
    consider_restart (event->status);
    printf ("Download complete,  %llu kbps.\n",
            (unsigned long long) (FILESIZE * 1000LL /
                                  (1 +
                                   GNUNET_TIME_absolute_get_duration
                                   (start).rel_value) / 1024LL));
    GNUNET_SCHEDULER_add_now (&abort_download_task, NULL);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_PROGRESS:
    consider_restart (event->status);
    GNUNET_assert (download == event->value.download.dc);
#if VERBOSE
    printf ("Download is progressing (%llu/%llu at level %u off %llu)...\n",
            (unsigned long long) event->value.download.completed,
            (unsigned long long) event->value.download.size,
            event->value.download.specifics.progress.depth,
            (unsigned long long) event->value.download.specifics.
            progress.offset);
#endif
    break;
  case GNUNET_FS_STATUS_PUBLISH_ERROR:
    fprintf (stderr, "Error publishing file: %s\n",
             event->value.publish.specifics.error.message);
    GNUNET_break (0);
    GNUNET_SCHEDULER_add_continuation (&abort_publish_task, NULL,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_ERROR:
    fprintf (stderr, "Error downloading file: %s\n",
             event->value.download.specifics.error.message);
    GNUNET_SCHEDULER_add_now (&abort_download_task, NULL);
    break;
  case GNUNET_FS_STATUS_PUBLISH_SUSPEND:
    GNUNET_assert (event->value.publish.pc == publish);
    publish = NULL;
    break;
  case GNUNET_FS_STATUS_PUBLISH_RESUME:
    GNUNET_assert (NULL == publish);
    publish = event->value.publish.pc;
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_SUSPEND:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Download suspended.\n");
    GNUNET_assert (event->value.download.dc == download);
    download = NULL;
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_RESUME:
    GNUNET_assert (NULL == download);
    download = event->value.download.dc;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Download resumed.\n");
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_ACTIVE:
    consider_restart (event->status);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Download active.\n");
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_INACTIVE:
    consider_restart (event->status);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Download inactive.\n");
    break;
  case GNUNET_FS_STATUS_PUBLISH_START:
    GNUNET_assert (0 == strcmp ("publish-context", event->value.publish.cctx));
    GNUNET_assert (NULL == event->value.publish.pctx);
    GNUNET_assert (FILESIZE == event->value.publish.size);
    GNUNET_assert (0 == event->value.publish.completed);
    GNUNET_assert (1 == event->value.publish.anonymity);
    break;
  case GNUNET_FS_STATUS_PUBLISH_STOPPED:
    GNUNET_assert (publish == event->value.publish.pc);
    GNUNET_assert (FILESIZE == event->value.publish.size);
    GNUNET_assert (1 == event->value.publish.anonymity);
    GNUNET_FS_stop (fs);
    fs = NULL;
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_START:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Download started.\n");
    consider_restart (event->status);
    GNUNET_assert (download == NULL);
    download = event->value.download.dc;
    GNUNET_assert (0 == strcmp ("download", event->value.download.cctx));
    GNUNET_assert (NULL == event->value.download.pctx);
    GNUNET_assert (NULL != event->value.download.uri);
    GNUNET_assert (0 == strcmp (fn, event->value.download.filename));
    GNUNET_assert (FILESIZE == event->value.download.size);
    GNUNET_assert (0 == event->value.download.completed);
    GNUNET_assert (1 == event->value.download.anonymity);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_STOPPED:
    GNUNET_assert (download == event->value.download.dc);
    GNUNET_SCHEDULER_add_continuation (&abort_publish_task, NULL,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    download = NULL;
    break;
  default:
    printf ("Unexpected event: %d\n", event->status);
    break;
  }
  return NULL;
}


static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_proc =
      GNUNET_OS_start_process (NULL, NULL, "gnunet-service-arm",
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
  if (NULL != p->arm_proc)
  {
    if (0 != GNUNET_OS_process_kill (p->arm_proc, SIGTERM))
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    if (GNUNET_OS_process_wait (p->arm_proc) != GNUNET_OK)
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ARM process %u stopped\n",
                GNUNET_OS_process_get_pid (p->arm_proc));
    GNUNET_OS_process_close (p->arm_proc);
    p->arm_proc = NULL;
  }
#endif
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
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
  struct GNUNET_FS_BlockOptions bo;

  cfg = c;
  setup_peer (&p1, "test_fs_download_data.conf");
  fs = GNUNET_FS_start (cfg, "test-fs-download-persistence", &progress_cb, NULL,
                        GNUNET_FS_FLAGS_PERSISTENCE, GNUNET_FS_OPTIONS_END);
  GNUNET_assert (NULL != fs);
  buf = GNUNET_malloc (FILESIZE);
  for (i = 0; i < FILESIZE; i++)
    buf[i] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 256);
  meta = GNUNET_CONTAINER_meta_data_create ();
  kuri = GNUNET_FS_uri_ksk_create_from_args (2, keywords);
  bo.content_priority = 42;
  bo.anonymity_level = 1;
  bo.replication_level = 0;
  bo.expiration_time = GNUNET_TIME_relative_to_absolute (LIFETIME);
  fi = GNUNET_FS_file_information_create_from_data (fs, "publish-context",
                                                    FILESIZE, buf, kuri, meta,
                                                    GNUNET_NO, &bo);
  GNUNET_FS_uri_destroy (kuri);
  GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_assert (NULL != fi);
  timeout_kill =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &timeout_kill_task, NULL);
  start = GNUNET_TIME_absolute_get ();
  publish =
      GNUNET_FS_publish_start (fs, fi, NULL, NULL, NULL,
                               GNUNET_FS_PUBLISH_OPTION_NONE);
  GNUNET_assert (publish != NULL);
}


int
main (int argc, char *argv[])
{
  char *const argvx[] = {
    "test-fs-download-persistence",
    "-c",
    "test_fs_download_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_log_setup ("test_fs_download_persistence",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-download/");
  GNUNET_PROGRAM_run ((sizeof (argvx) / sizeof (char *)) - 1, argvx,
                      "test-fs-download-persistence", "nohelp", options, &run,
                      NULL);
  stop_arm (&p1);
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-download/");
  return err;
}

/* end of test_fs_download_persistence.c */
