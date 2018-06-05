/*
     This file is part of GNUnet.
     Copyright (C) 2004, 2005, 2006, 2008, 2009, 2010 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/

/**
 * @file fs/test_fs_unindex_persistence.c
 * @brief simple testcase for simple publish + unindex operation
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_fs_service.h"

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


static struct GNUNET_TIME_Absolute start;

static struct GNUNET_FS_Handle *fs;

static struct GNUNET_FS_UnindexContext *unindex;

static struct GNUNET_FS_PublishContext *publish;

static char *fn;

static const struct GNUNET_CONFIGURATION_Handle *cfg;


static void
abort_publish_task (void *cls)
{
  GNUNET_FS_publish_stop (publish);
  publish = NULL;
}


static void
abort_unindex_task (void *cls)
{
  if (unindex != NULL)
  {
    GNUNET_FS_unindex_stop (unindex);
    unindex = NULL;
  }
  if (fn != NULL)
  {
    GNUNET_DISK_directory_remove (fn);
    GNUNET_free (fn);
    fn = NULL;
  }
}


static void *
progress_cb (void *cls, const struct GNUNET_FS_ProgressInfo *event);


static void
restart_fs_task (void *cls)
{
  GNUNET_FS_stop (fs);
  fs = GNUNET_FS_start (cfg, "test-fs-unindex-persistence", &progress_cb, NULL,
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
    printf ("Publishing complete, %llu kbps.\n",
            (unsigned long long) (FILESIZE * 1000000LL /
                                  (1 +
                                   GNUNET_TIME_absolute_get_duration
                                   (start).rel_value_us) / 1024));
    start = GNUNET_TIME_absolute_get ();
    unindex = GNUNET_FS_unindex_start (fs, fn, "unindex");
    GNUNET_assert (unindex != NULL);
    break;
  case GNUNET_FS_STATUS_UNINDEX_COMPLETED:
    printf ("Unindex complete,  %llu kbps.\n",
            (unsigned long long) (FILESIZE * 1000000LL /
                                  (1 +
                                   GNUNET_TIME_absolute_get_duration
                                   (start).rel_value_us) / 1024));
    GNUNET_SCHEDULER_add_now (&abort_unindex_task, NULL);
    break;
  case GNUNET_FS_STATUS_UNINDEX_PROGRESS:
    consider_restart (event->status);
    GNUNET_assert (unindex == event->value.unindex.uc);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Unindex is progressing (%llu/%llu at level %u off %llu)...\n",
		(unsigned long long) event->value.unindex.completed,
		(unsigned long long) event->value.unindex.size,
		event->value.unindex.specifics.progress.depth,
		(unsigned long long) event->value.unindex.specifics.
		progress.offset);
    break;
  case GNUNET_FS_STATUS_PUBLISH_SUSPEND:
    if (event->value.publish.pc == publish)
      publish = NULL;
    break;
  case GNUNET_FS_STATUS_PUBLISH_RESUME:
    if (NULL == publish)
    {
      publish = event->value.publish.pc;
      return "publish-context";
    }
    break;
  case GNUNET_FS_STATUS_UNINDEX_SUSPEND:
    GNUNET_assert (event->value.unindex.uc == unindex);
    unindex = NULL;
    break;
  case GNUNET_FS_STATUS_UNINDEX_RESUME:
    GNUNET_assert (NULL == unindex);
    unindex = event->value.unindex.uc;
    return "unindex";
  case GNUNET_FS_STATUS_PUBLISH_ERROR:
    FPRINTF (stderr, "Error publishing file: %s\n",
             event->value.publish.specifics.error.message);
    GNUNET_break (0);
    GNUNET_SCHEDULER_add_now (&abort_publish_task, NULL);
    break;
  case GNUNET_FS_STATUS_UNINDEX_ERROR:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Error unindexing file: %s\n",
		event->value.unindex.specifics.error.message);
    GNUNET_SCHEDULER_add_now (&abort_unindex_task, NULL);
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
  case GNUNET_FS_STATUS_UNINDEX_START:
    consider_restart (event->status);
    GNUNET_assert (unindex == NULL);
    GNUNET_assert (0 == strcmp ("unindex", event->value.unindex.cctx));
    GNUNET_assert (0 == strcmp (fn, event->value.unindex.filename));
    GNUNET_assert (FILESIZE == event->value.unindex.size);
    GNUNET_assert (0 == event->value.unindex.completed);
    break;
  case GNUNET_FS_STATUS_UNINDEX_STOPPED:
    GNUNET_assert (unindex == event->value.unindex.uc);
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
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_TESTING_Peer *peer)
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
  fn = GNUNET_DISK_mktemp ("gnunet-unindex-test-dst");
  fs = GNUNET_FS_start (cfg, "test-fs-unindex-persistence", &progress_cb, NULL,
                        GNUNET_FS_FLAGS_PERSISTENCE, GNUNET_FS_OPTIONS_END);
  GNUNET_assert (NULL != fs);
  buf = GNUNET_malloc (FILESIZE);
  for (i = 0; i < FILESIZE; i++)
    buf[i] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 256);
  GNUNET_assert (FILESIZE ==
                 GNUNET_DISK_fn_write (fn, buf, FILESIZE,
                                       GNUNET_DISK_PERM_USER_READ |
                                       GNUNET_DISK_PERM_USER_WRITE));
  GNUNET_free (buf);
  meta = GNUNET_CONTAINER_meta_data_create ();
  kuri = GNUNET_FS_uri_ksk_create_from_args (2, keywords);
  bo.content_priority = 42;
  bo.anonymity_level = 1;
  bo.replication_level = 0;
  bo.expiration_time = GNUNET_TIME_relative_to_absolute (LIFETIME);
  fi = GNUNET_FS_file_information_create_from_file (fs, "publish-context", fn,
                                                    kuri, meta, GNUNET_YES,
                                                    &bo);
  GNUNET_FS_uri_destroy (kuri);
  GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_assert (NULL != fi);
  start = GNUNET_TIME_absolute_get ();
  publish =
      GNUNET_FS_publish_start (fs, fi, NULL, NULL, NULL,
                               GNUNET_FS_PUBLISH_OPTION_NONE);
  GNUNET_assert (publish != NULL);
}


int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test-fs-unindex-persistence",
				    "test_fs_unindex_data.conf",
				    &run, NULL))
    return 1;
  return 0;
}

/* end of test_fs_unindex_persistence.c */
