/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file fs/test_gnunet_service_fs_migration.c
 * @brief test content migration between two peers
 * @author Christian Grothoff
 */
#include "platform.h"
#include "fs_test_lib.h"
#include "gnunet_testing_lib.h"

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

static struct GNUNET_FS_TestDaemon *daemons[2];

static int ok;

static struct GNUNET_TIME_Absolute start_time;

static struct GNUNET_FS_TEST_ConnectContext *cc;

static void
do_stop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TIME_Relative del;
  char *fancy;

  if (NULL != cc)
  {
    GNUNET_FS_TEST_daemons_connect_cancel (cc);
    cc = NULL;
  }
  GNUNET_FS_TEST_daemons_stop (2, daemons);
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE))
  {
    del = GNUNET_TIME_absolute_get_duration (start_time);
    if (del.rel_value == 0)
      del.rel_value = 1;
    fancy =
        GNUNET_STRINGS_byte_size_fancy (((unsigned long long) FILESIZE) *
                                        1000LL / del.rel_value);
    FPRINTF (stdout, "Download speed was %s/s\n", fancy);
    GNUNET_free (fancy);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Finished download, shutting down\n",
                (unsigned long long) FILESIZE);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Timeout during download, shutting down with error\n");
    ok = 1;
  }
}


static void
do_download (void *cls, const char *emsg)
{
  struct GNUNET_FS_Uri *uri = cls;

  if (emsg != NULL)
  {
    GNUNET_FS_TEST_daemons_stop (2, daemons);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to stop source daemon: %s\n",
                emsg);
    GNUNET_FS_uri_destroy (uri);
    ok = 1;
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Downloading %llu bytes\n",
              (unsigned long long) FILESIZE);
  start_time = GNUNET_TIME_absolute_get ();
  GNUNET_FS_TEST_download (daemons[0], TIMEOUT, 1, SEED, uri, VERBOSE, &do_stop,
                           NULL);
  GNUNET_FS_uri_destroy (uri);
}


static void
stop_source_peer (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_Uri *uri = cls;
  struct GNUNET_TESTING_PeerGroup *pg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping source peer\n");
  pg = GNUNET_FS_TEST_get_group (daemons);
  GNUNET_TESTING_daemons_vary (pg, 1, GNUNET_NO, TIMEOUT, &do_download, uri);
}


static void
do_wait (void *cls, const struct GNUNET_FS_Uri *uri)
{
  struct GNUNET_FS_Uri *d;

  if (NULL == uri)
  {
    GNUNET_FS_TEST_daemons_stop (2, daemons);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Timeout during upload attempt, shutting down with error\n");
    ok = 1;
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Waiting to allow content to migrate\n");
  d = GNUNET_FS_uri_dup (uri);
  (void) GNUNET_SCHEDULER_add_delayed (MIGRATION_DELAY, &stop_source_peer, d);
}


static void
do_publish (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  cc = NULL;
  if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE))
  {
    GNUNET_FS_TEST_daemons_stop (2, daemons);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Timeout during connect attempt, shutting down with error\n");
    ok = 1;
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Publishing %llu bytes\n",
              (unsigned long long) FILESIZE);
  GNUNET_FS_TEST_publish (daemons[1], TIMEOUT, 1, GNUNET_NO, FILESIZE, SEED,
                          VERBOSE, &do_wait, NULL);
}


static void
do_connect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE))
  {
    FPRINTF (stderr, "%s",  "Daemons failed to start!\n");
    GNUNET_break (0);
    ok = 1;
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Daemons started, will now try to connect them\n");
  cc = GNUNET_FS_TEST_daemons_connect (daemons[0], daemons[1], TIMEOUT,
                                       &do_publish, NULL);
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_FS_TEST_daemons_start ("test_gnunet_service_fs_migration_data.conf",
                                TIMEOUT, 2, daemons, &do_connect, NULL);
}


int
main (int argc, char *argv[])
{
  char *const argvx[] = {
    "test-gnunet-service-fs-migration",
    "-c",
    "fs_test_lib_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-service-fs-migration/");
  GNUNET_log_setup ("test_gnunet_service_fs_migration",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  GNUNET_PROGRAM_run ((sizeof (argvx) / sizeof (char *)) - 1, argvx,
                      "test-gnunet-service-fs-migration", "nohelp", options,
                      &run, NULL);
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-service-fs-migration/");
  return ok;
}

/* end of test_gnunet_service_fs_migration.c */
