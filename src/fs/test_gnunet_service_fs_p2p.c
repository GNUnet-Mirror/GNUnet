/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file fs/test_gnunet_service_fs_p2p.c
 * @brief test P2P routing using simple publish + download operation
 * @author Christian Grothoff
 */
#include "platform.h"
#include "test_fs_lib.h"

#define VERBOSE GNUNET_NO

/**
 * File-size we use for testing.
 */
#define FILESIZE (1024 * 1024 * 2)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

#define NUM_DAEMONS 2

#define SEED 42

static struct GNUNET_FS_TestDaemon *daemons[NUM_DAEMONS];

static struct GNUNET_SCHEDULER_Handle *sched;


static void
do_stop (void *cls,
	 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE));
  GNUNET_FS_TEST_daemons_stop (sched,
			       NUM_DAEMONS,
			       daemons);
}


static void
do_download (void *cls,
	     const struct GNUNET_FS_Uri *uri)
{
  GNUNET_assert (NULL != uri);
  GNUNET_FS_TEST_download (sched,
			   daemons[1],
			   TIMEOUT,
			   1, SEED, uri, 
			   VERBOSE, 
			   &do_stop, NULL);
}


static void
do_publish (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE));
  GNUNET_FS_TEST_publish (sched,
			  daemons[1],
			  TIMEOUT,
			  1, GNUNET_NO, FILESIZE, SEED, 
			  VERBOSE, 
			  &do_download, NULL);
}


static void
do_connect (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE));
  GNUNET_FS_TEST_daemons_connect (sched,
				  daemons[1],
				  daemons[2],
				  TIMEOUT,
				  &do_publish,
				  NULL);  
}


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  sched = s;
  GNUNET_FS_TEST_daemons_start (sched,
				TIMEOUT,
				NUM_DAEMONS,
				daemons,
				&do_connect,
				NULL);
}


int
main (int argc, char *argv[])
{
  char *const argvx[] = { 
    "test-gnunet-service-fs-p2p",
    "-c",
    "test_fs_lib_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_log_setup ("test_gnunet_service_fs_p2p", 
#if VERBOSE
		    "DEBUG",
#else
		    "WARNING",
#endif
		    NULL);
  GNUNET_PROGRAM_run ((sizeof (argvx) / sizeof (char *)) - 1,
                      argvx, "test-gnunet-service-fs-p2p",
		      "nohelp", options, &run, NULL);
  return 0;
}

/* end of test_gnunet_service_fs_p2p.c */
