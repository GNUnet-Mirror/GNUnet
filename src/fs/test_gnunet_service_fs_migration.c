/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2012, 2015 Christian Grothoff (and other contributing authors)

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
 * @file fs/test_gnunet_service_fs_migration.c
 * @brief test content migration between two peers
 * @author Christian Grothoff
 */
#include "platform.h"
#include "fs_test_lib.h"
#include "gnunet_testbed_service.h"

#define VERBOSE GNUNET_NO

/**
 * File-size we use for testing.
 */
#define FILESIZE (2 * 32 * 1024)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * How long do we give the peers for content migration?
 */
#define MIGRATION_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 90)

#define SEED 42

static struct GNUNET_TESTBED_Peer *daemons[2];

static int ok;

static struct GNUNET_TIME_Absolute start_time;

static struct GNUNET_TESTBED_Operation *op;


struct DownloadContext
{
  char *fn;

  struct GNUNET_FS_Uri *uri;
};


static void
do_stop (void *cls,
         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TIME_Relative del;
  char *fancy;

  GNUNET_SCHEDULER_shutdown ();
  if (0 ==
      GNUNET_TIME_absolute_get_remaining (GNUNET_TIME_absolute_add (start_time,
                                                                    TIMEOUT)).rel_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Timeout during download, shutting down with error\n");
    ok = 1;
  }
  else
  {
    del = GNUNET_TIME_absolute_get_duration (start_time);
    if (del.rel_value_us == 0)
      del.rel_value_us = 1;
    fancy =
        GNUNET_STRINGS_byte_size_fancy (((unsigned long long) FILESIZE) *
                                        1000000LL / del.rel_value_us);
    FPRINTF (stdout,
             "Download speed was %s/s\n",
             fancy);
    GNUNET_free (fancy);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Finished download, shutting down\n",
                (unsigned long long) FILESIZE);
  }
}


static void
do_download (void *cls,
	     const char *emsg)
{
  struct DownloadContext *dc = cls;
  struct GNUNET_FS_Uri *uri = dc->uri;

  GNUNET_TESTBED_operation_done (op);
  op = NULL;
  if (NULL != dc->fn)
  {
    GNUNET_DISK_directory_remove (dc->fn);
    GNUNET_free (dc->fn);
  }
  GNUNET_free (dc);
  if (NULL != emsg)
  {
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to stop source daemon: %s\n",
                emsg);
    GNUNET_FS_uri_destroy (uri);
    ok = 1;
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Downloading %llu bytes\n",
              (unsigned long long) FILESIZE);
  start_time = GNUNET_TIME_absolute_get ();
  GNUNET_FS_TEST_download (daemons[0],
                           TIMEOUT,
                           1,
                           SEED,
                           uri,
                           VERBOSE,
                           &do_stop,
                           NULL);
  GNUNET_FS_uri_destroy (uri);
}


static void
stop_source_peer (void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct DownloadContext *dc = cls;

  /* Do not interact with testbed when shutting down */
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Stopping source peer\n");
  op = GNUNET_TESTBED_peer_stop (NULL, daemons[1], &do_download, dc);
  GNUNET_assert (NULL != op);
}


static void
do_wait (void *cls,
         const struct GNUNET_FS_Uri *uri,
	 const char *fn)
{
  struct DownloadContext *dc;

  if (NULL == uri)
  {
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Timeout during upload attempt, shutting down with error\n");
    ok = 1;
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Waiting to allow content to migrate\n");
  dc = GNUNET_new (struct DownloadContext);
  dc->uri = GNUNET_FS_uri_dup (uri);
  if (NULL != fn)
    dc->fn = GNUNET_strdup (fn);
  (void) GNUNET_SCHEDULER_add_delayed (MIGRATION_DELAY, &stop_source_peer, dc);
}


static void
do_publish (void *cls,
            struct GNUNET_TESTBED_RunHandle *h,
	    unsigned int num_peers,
	    struct GNUNET_TESTBED_Peer **peers,
            unsigned int links_succeeded,
            unsigned int links_failed)
{
  unsigned int i;

  GNUNET_assert (2 == num_peers);
  for (i=0;i<num_peers;i++)
    daemons[i] = peers[i];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Publishing %llu bytes\n",
              (unsigned long long) FILESIZE);
  GNUNET_FS_TEST_publish (daemons[1], TIMEOUT, 1, GNUNET_NO, FILESIZE, SEED,
                          VERBOSE, &do_wait, NULL);
}


int
main (int argc,
      char *argv[])
{
  (void) GNUNET_TESTBED_test_run ("test-gnunet-service-fs-migration",
                                  "fs_test_lib_data.conf",
                                  2,
                                  0, NULL, NULL,
                                  &do_publish,
                                  NULL);
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-service-fs-migration/");
  return ok;
}

/* end of test_gnunet_service_fs_migration.c */
