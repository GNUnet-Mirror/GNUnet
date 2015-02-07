/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2012 Christian Grothoff (and other contributing authors)

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

static struct GNUNET_TESTBED_Peer *the_peers[NUM_DAEMONS];

static int ret;


static void
do_stop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char *fn = cls;

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
  if (NULL != fn)
  {
    GNUNET_DISK_directory_remove (fn);
    GNUNET_free (fn);
  }
  GNUNET_SCHEDULER_shutdown ();
}


static void
do_download (void *cls, const struct GNUNET_FS_Uri *uri,
	     const char *fn)
{
  if (NULL == uri)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    ret = 1;
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Downloading %llu bytes\n",
              (unsigned long long) FILESIZE);
  GNUNET_FS_TEST_download (the_peers[0], TIMEOUT, 1, SEED, uri, VERBOSE, &do_stop,
                           (NULL == fn) ? NULL : GNUNET_strdup (fn));
}


static void
do_publish (void *cls,
	    struct GNUNET_TESTBED_Operation *op,
	    const char *emsg)
{
  GNUNET_TESTBED_operation_done (op);
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to connect peers: %s\n", emsg);
    GNUNET_break (0);
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Publishing %llu bytes\n",
              (unsigned long long) FILESIZE);
  GNUNET_FS_TEST_publish (the_peers[0], TIMEOUT, 1, GNUNET_NO, FILESIZE, SEED,
                          VERBOSE, &do_download, NULL);

}


/**
 * Actual main function for the test.
 *
 * @param cls closure
 * @param h the run handle
 * @param num_peers number of peers in 'peers'
 * @param peers handle to peers run in the testbed
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 */
static void
run (void *cls,
     struct GNUNET_TESTBED_RunHandle *h,
     unsigned int num_peers,
     struct GNUNET_TESTBED_Peer **peers,
     unsigned int links_succeeded,
     unsigned int links_failed)
{
  unsigned int i;

  GNUNET_assert (NUM_DAEMONS == num_peers);
  for (i=0;i<num_peers;i++)
    the_peers[i] = peers[i];
  GNUNET_TESTBED_overlay_connect (NULL,
				  &do_publish,
				  NULL,
				  peers[0],
				  peers[1]);
}


/**
 * Main function that initializes the testbed.
 *
 * @param argc ignored
 * @param argv ignored
 * @return 0 on success
 */
int
main (int argc, char *argv[])
{
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-lib/");
  (void) GNUNET_TESTBED_test_run ("test_fs_test_lib",
                                  "fs_test_lib_data.conf",
                                  NUM_DAEMONS,
                                  0, NULL, NULL,
                                  &run, NULL);
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-lib/");
  return ret;
}

/* end of test_fs_test_lib.c */
