/*
     This file is part of GNUnet.
     Copyright (C) 2004, 2005, 2006, 2008, 2009, 2011, 2012 Christian Grothoff (and other contributing authors)

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
 * @file fs/test_fs_download.c
 * @brief simple testcase for simple publish + download operation
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "gnunet_testing_lib.h"
#include <gauger.h>

/**
 * File-size we use for testing.
 */
#define FILESIZE (1024 * 1024 * 2)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * How long should our test-content live?
 */
#define LIFETIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 15)

static unsigned int anonymity_level;

static int indexed;

static struct GNUNET_TIME_Absolute start;

static struct GNUNET_FS_Handle *fs;

static struct GNUNET_FS_DownloadContext *download;

static struct GNUNET_FS_PublishContext *publish;

static struct GNUNET_SCHEDULER_Task * timeout_kill;

static char *fn;

static char *fn1;

static int err;


static void
timeout_kill_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != download)
  {
    GNUNET_FS_download_stop (download, GNUNET_YES);
    download = NULL;
  }
  else if (NULL != publish)
  {
    GNUNET_FS_publish_stop (publish);
    publish = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Timeout downloading file\n");
  timeout_kill = NULL;
  err = 1;
}


static void
abort_publish_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != publish)
  {
    GNUNET_FS_publish_stop (publish);
    publish = NULL;
  }
}


static void
stop_fs_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_FS_stop (fs);
  fs = NULL;
}


static void
abort_download_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  uint64_t size;

  if (NULL != download)
  {
    GNUNET_FS_download_stop (download, GNUNET_YES);
    download = NULL;
  }
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_size (fn, &size, GNUNET_YES, GNUNET_NO));
  GNUNET_assert (size == FILESIZE);
  GNUNET_DISK_directory_remove (fn);
  GNUNET_free (fn);
  fn = NULL;
  GNUNET_SCHEDULER_cancel (timeout_kill);
  timeout_kill = NULL;
}


static void *
progress_cb (void *cls, const struct GNUNET_FS_ProgressInfo *event)
{

  switch (event->status)
  {
  case GNUNET_FS_STATUS_PUBLISH_PROGRESS:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Publish is progressing (%llu/%llu at level %u off %llu)...\n",
		(unsigned long long) event->value.publish.completed,
		(unsigned long long) event->value.publish.size,
		event->value.publish.specifics.progress.depth,
		(unsigned long long) event->value.publish.specifics.
		progress.offset);
    break;
  case GNUNET_FS_STATUS_PUBLISH_PROGRESS_DIRECTORY:
    break;
  case GNUNET_FS_STATUS_PUBLISH_COMPLETED:
    fprintf (stdout,
	     "Publishing complete, %llu kb/s.\n",
	     (unsigned long long) (FILESIZE * 1000000LL /
				   (1 +
				    GNUNET_TIME_absolute_get_duration
				    (start).rel_value_us) / 1024LL));
    GAUGER ("FS",
	    (GNUNET_YES == indexed)
	    ? "Publishing speed (indexing)"
	     : "Publishing speed (insertion)",
	    (unsigned long long) (FILESIZE * 1000000LL /
				  (1 +
				   GNUNET_TIME_absolute_get_duration
				   (start).rel_value_us) / 1024LL), "kb/s");
    fn = GNUNET_DISK_mktemp ("gnunet-download-test-dst");
    start = GNUNET_TIME_absolute_get ();
    download =
        GNUNET_FS_download_start (fs,
                                  event->value.publish.specifics.
                                  completed.chk_uri, NULL, fn, NULL, 0,
                                  FILESIZE, anonymity_level,
				  GNUNET_FS_DOWNLOAD_OPTION_NONE,
                                  "download", NULL);
    GNUNET_assert (download != NULL);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_COMPLETED:
    fprintf (stdout,
	     "Download complete,  %llu kb/s.\n",
	     (unsigned long long) (FILESIZE * 1000000LL /
				   (1 +
				    GNUNET_TIME_absolute_get_duration
				    (start).rel_value_us) / 1024LL));
    GAUGER ("FS",
	    (GNUNET_YES == indexed)
	    ? "Local download speed (indexed)"
	    : "Local download speed (inserted)",
            (unsigned long long) (FILESIZE * 1000000LL /
                                  (1 +
                                   GNUNET_TIME_absolute_get_duration
                                   (start).rel_value_us) / 1024LL), "kb/s");
    GNUNET_SCHEDULER_add_now (&abort_download_task, NULL);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_PROGRESS:
    GNUNET_assert (download == event->value.download.dc);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Download is progressing (%llu/%llu at level %u off %llu)...\n",
		(unsigned long long) event->value.download.completed,
		(unsigned long long) event->value.download.size,
		event->value.download.specifics.progress.depth,
		(unsigned long long) event->value.download.specifics.
		progress.offset);
    break;
  case GNUNET_FS_STATUS_PUBLISH_ERROR:
    FPRINTF (stderr, "Error publishing file: %s\n",
             event->value.publish.specifics.error.message);
    GNUNET_break (0);
    GNUNET_SCHEDULER_add_now (&abort_publish_task, NULL);
    GNUNET_SCHEDULER_shutdown ();
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_ERROR:
    FPRINTF (stderr, "Error downloading file: %s\n",
             event->value.download.specifics.error.message);
    GNUNET_SCHEDULER_add_now (&abort_download_task, NULL);
    GNUNET_SCHEDULER_shutdown ();
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_ACTIVE:
  case GNUNET_FS_STATUS_DOWNLOAD_INACTIVE:
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
    GNUNET_SCHEDULER_add_now (&stop_fs_task, NULL);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_START:
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
    GNUNET_SCHEDULER_add_now (&abort_publish_task, NULL);
    break;
  default:
    printf ("Unexpected event: %d\n", event->status);
    break;
  }
  return NULL;
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  const char *binary_name = cls;
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

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg,
					    "download-test",
					    "USE_STREAM"))
    anonymity_level = 0;
  else
    anonymity_level = 1;
  fs = GNUNET_FS_start (cfg, binary_name, &progress_cb, NULL,
                        GNUNET_FS_FLAGS_NONE, GNUNET_FS_OPTIONS_END);
  GNUNET_assert (NULL != fs);
  buf = GNUNET_malloc (FILESIZE);
  for (i = 0; i < FILESIZE; i++)
    buf[i] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 256);
  meta = GNUNET_CONTAINER_meta_data_create ();
  kuri = GNUNET_FS_uri_ksk_create_from_args (2, keywords);
  bo.content_priority = 42;
  bo.anonymity_level = anonymity_level;
  bo.replication_level = 0;
  bo.expiration_time = GNUNET_TIME_relative_to_absolute (LIFETIME);

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg,
					    "download-test",
					    "USE_INDEX"))
  {
    fn1 = GNUNET_DISK_mktemp ("gnunet-download-indexed-test");
    GNUNET_assert (FILESIZE ==
		   GNUNET_DISK_fn_write (fn1, buf, FILESIZE,
					 GNUNET_DISK_PERM_USER_READ |
					 GNUNET_DISK_PERM_USER_WRITE));
    GNUNET_free (buf);
    fi = GNUNET_FS_file_information_create_from_file (fs, "publish-context", fn1,
						      kuri, meta, GNUNET_YES,
						      &bo);
    indexed = GNUNET_YES;
  }
  else
  {
    fi = GNUNET_FS_file_information_create_from_data (fs, "publish-context",
						      FILESIZE, buf, kuri, meta,
						      GNUNET_NO, &bo);
    /* note: buf will be free'd as part of 'fi' now */
    indexed = GNUNET_NO;
  }
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
  const char *binary_name;
  const char *config_name;

  binary_name = "test-fs-download";
  config_name = "test_fs_download_data.conf";
  if (NULL != strstr (argv[0], "indexed"))
  {
    binary_name = "test-fs-download-indexed";
    config_name = "test_fs_download_indexed.conf";
  }
  if (NULL != strstr (argv[0], "cadet"))
  {
    binary_name = "test-fs-download-cadet";
    config_name = "test_fs_download_cadet.conf";
  }
  if (0 != GNUNET_TESTING_peer_run (binary_name,
				    config_name,
				    &run, (void *) binary_name))
    return 1;
  if (NULL != fn1)
  {
    UNLINK (fn1);
    GNUNET_free (fn1);
  }
  return err;
}

/* end of test_fs_download.c */
