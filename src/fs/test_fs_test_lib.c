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
 * @file fs/test_fs_test_lib.c
 * @brief test fs test library
 * @author Christian Grothoff
 */
#include "platform.h"
#include "fs_test_lib.h"

#define VERBOSE GNUNET_NO

/**
 * File-size we use for testing.
 */
#define FILESIZE (1024 * 1024 * 2)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

#define NUM_DAEMONS 2

#define SEED 42

static struct GNUNET_FS_TestDaemon *daemons[NUM_DAEMONS];

static struct GNUNET_FS_TEST_ConnectContext *cc;

static int ret;

static void
do_stop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != cc)
  {
    GNUNET_FS_TEST_daemons_connect_cancel (cc);
    cc = NULL;
  }
  if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE))
  {
    GNUNET_break (0);
    ret = 1;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Finished download, shutting down\n",
                (unsigned long long) FILESIZE);
  }
  GNUNET_FS_TEST_daemons_stop (NUM_DAEMONS, daemons);
}


static void
do_download (void *cls, const struct GNUNET_FS_Uri *uri)
{
  if (NULL == uri)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_add_now (&do_stop, NULL);
    ret = 1;
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Downloading %llu bytes\n",
              (unsigned long long) FILESIZE);
  GNUNET_FS_TEST_download (daemons[0], TIMEOUT, 1, SEED, uri, VERBOSE, &do_stop,
                           NULL);
}


static void
do_publish (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  cc = NULL;
  if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE))
  {
    GNUNET_break (0);
    ret = 1;
    GNUNET_SCHEDULER_add_now (&do_stop, NULL);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Publishing %llu bytes\n",
              (unsigned long long) FILESIZE);
  GNUNET_FS_TEST_publish (daemons[0], TIMEOUT, 1, GNUNET_NO, FILESIZE, SEED,
                          VERBOSE, &do_download, NULL);
}


static void
do_connect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE))
  {
    GNUNET_break (0);
    ret = 1;
    GNUNET_SCHEDULER_add_now (&do_stop, NULL);
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
  GNUNET_FS_TEST_daemons_start ("fs_test_lib_data.conf", TIMEOUT, NUM_DAEMONS,
                                daemons, &do_connect, NULL);
}


int
main (int argc, char *argv[])
{
  char *const argvx[] = {
    "test-fs-test-lib",
    "-c",
    "fs_test_lib_data.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-lib/");
  GNUNET_log_setup ("test_fs_test_lib",
                    "WARNING",
                    NULL);
  GNUNET_PROGRAM_run ((sizeof (argvx) / sizeof (char *)) - 1, argvx,
                      "test-fs-test-lib", "nohelp", options, &run, NULL);
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-lib/");
  return ret;
}

/* end of test_fs_test_lib.c */
