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
 * @file fs/test_fs_search_persistence.c
 * @brief simple testcase for persistence of search operation
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_fs_service.h"


/**
 * File-size we use for testing.
 */
#define FILESIZE 1024

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

static struct GNUNET_FS_SearchContext *search;

static struct GNUNET_FS_PublishContext *publish;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_SCHEDULER_Task * timeout_task;

static int err;


static void
abort_error (void *cls)
{
  timeout_task = NULL;
  fprintf (stderr,
	   "Timeout\n");
  if (NULL != search)
  {
    GNUNET_FS_search_stop (search);
    search = NULL;
  }
  if (NULL != publish)
  {
    GNUNET_FS_publish_stop (publish);
    publish = NULL;
  }
  err = 1;
}


static void
abort_publish_task (void *cls)
{
  if (NULL != publish)
  {
    GNUNET_FS_publish_stop (publish);
    publish = NULL;
  }
  if (NULL != timeout_task)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
  }
}


static void
abort_search_task (void *cls)
{
  if (NULL != search)
  {
    GNUNET_FS_search_stop (search);
    search = NULL;
  }
}


static void *
progress_cb (void *cls, const struct GNUNET_FS_ProgressInfo *event);


static void
restart_fs_task (void *cls)
{
  GNUNET_FS_stop (fs);
  fs = GNUNET_FS_start (cfg, "test-fs-search-persistence", &progress_cb, NULL,
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
  const char *keywords[] = {
    "down_foo"
  };
  struct GNUNET_FS_Uri *kuri;

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
    kuri = GNUNET_FS_uri_ksk_create_from_args (1, keywords);
    start = GNUNET_TIME_absolute_get ();
    GNUNET_FS_search_start (fs, kuri, 1, GNUNET_FS_SEARCH_OPTION_NONE,
                            "search");
    GNUNET_FS_uri_destroy (kuri);
    GNUNET_assert (search != NULL);
    break;
  case GNUNET_FS_STATUS_PUBLISH_SUSPEND:
    if (event->value.publish.pc == publish)
      publish = NULL;
    break;
  case GNUNET_FS_STATUS_PUBLISH_RESUME:
    if (NULL == publish)
      publish = event->value.publish.pc;
    break;
  case GNUNET_FS_STATUS_SEARCH_RESULT:
    /* FIXME: consider_restart (event->status); cannot be tested with
     * search result since we exit here after the first one... */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Search complete.\n");
    GNUNET_SCHEDULER_add_now (&abort_search_task, NULL);
    break;
  case GNUNET_FS_STATUS_PUBLISH_ERROR:
    FPRINTF (stderr, "Error publishing file: %s\n",
             event->value.publish.specifics.error.message);
    GNUNET_break (0);
    GNUNET_SCHEDULER_add_now (&abort_publish_task, NULL);
    break;
  case GNUNET_FS_STATUS_SEARCH_ERROR:
    FPRINTF (stderr, "Error searching file: %s\n",
             event->value.search.specifics.error.message);
    GNUNET_SCHEDULER_add_now (&abort_search_task, NULL);
    break;
  case GNUNET_FS_STATUS_SEARCH_SUSPEND:
    if (event->value.search.sc == search)
      search = NULL;
    break;
  case GNUNET_FS_STATUS_SEARCH_RESUME:
    if (NULL == search)
    {
      search = event->value.search.sc;
      return "search";
    }
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
  case GNUNET_FS_STATUS_SEARCH_START:
    consider_restart (event->status);
    GNUNET_assert (search == NULL);
    search = event->value.search.sc;
    GNUNET_assert (0 == strcmp ("search", event->value.search.cctx));
    GNUNET_assert (1 == event->value.search.anonymity);
    break;
  case GNUNET_FS_STATUS_SEARCH_RESULT_STOPPED:
    break;
  case GNUNET_FS_STATUS_SEARCH_STOPPED:
    GNUNET_assert (search == event->value.search.sc);
    GNUNET_SCHEDULER_add_now (&abort_publish_task, NULL);
    search = NULL;
    break;
  default:
    FPRINTF (stderr, "Unexpected event: %d\n", event->status);
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
    "down_bar"
  };
  char *buf;
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_FS_Uri *kuri;
  struct GNUNET_FS_FileInformation *fi;
  size_t i;
  struct GNUNET_FS_BlockOptions bo;

  cfg = c;
  fs = GNUNET_FS_start (cfg, "test-fs-search-persistence", &progress_cb, NULL,
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
  start = GNUNET_TIME_absolute_get ();
  publish =
      GNUNET_FS_publish_start (fs, fi, NULL, NULL, NULL,
                               GNUNET_FS_PUBLISH_OPTION_NONE);
  GNUNET_assert (publish != NULL);
  timeout_task = GNUNET_SCHEDULER_add_delayed (LIFETIME,
					       &abort_error, NULL);
}


int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test-fs-search-persistence",
				    "test_fs_search_data.conf",
				    &run, NULL))
    return 1;
  return err;
}

/* end of test_fs_search_persistence.c */
