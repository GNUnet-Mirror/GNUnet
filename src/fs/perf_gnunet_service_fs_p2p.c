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
 * @file fs/perf_gnunet_service_fs_p2p.c
 * @brief profile P2P routing using simple publish + download operation
 * @author Christian Grothoff
 */
#include "platform.h"
#include "fs_test_lib.h"
#include "gnunet_testing_lib.h"

#define VERBOSE GNUNET_NO

/**
 * File-size we use for testing.
 */
#define FILESIZE (1024 * 1024 * 1)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 30)

#define NUM_DAEMONS 2

#define SEED 42

static struct GNUNET_FS_TestDaemon *daemons[NUM_DAEMONS];

static int ok;

static struct GNUNET_TIME_Absolute start_time;

static const char *progname;

static void
do_stop (void *cls,
	 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_FS_TEST_daemons_stop (NUM_DAEMONS,
			       daemons);
}


/**
 * Master context for 'stat_run'.
 */
struct StatMaster
{
  struct GNUNET_STATISTICS_Handle *stat;  
  unsigned int daemon;
  unsigned int value;
};

struct StatValues
{
  const char *subsystem;
  const char *name;
};

/**
 * Statistics we print out.
 */
static struct StatValues stats[] =
  {
    { "fs", "# queries forwarded"},
    { "fs", "# replies received and matched"},
    { "fs", "# results found locally"},
    { "fs", "# requests forwarded due to high load"},
    { "fs", "# requests done for free (low load)"},
    { "fs", "# requests dropped, priority insufficient"},
    { "fs", "# requests done for a price (normal load)"},
    { "fs", "# requests dropped by datastore (queue length limit)"},
    { "fs", "# P2P searches received"},
    { "fs", "# P2P searches discarded (queue length bound)"},
    { "fs", "# replies received for local clients"},
    { "fs", "# queries retransmitted to same target"},
    { "fs", "cummulative artificial delay introduced (ms)"},
    { "core", "# bytes decrypted"},
    { "core", "# bytes encrypted"},
    { "core", "# discarded CORE_SEND requests"},
    { "core", "# discarded CORE_SEND request bytes"},
    { "core", "# discarded lower priority CORE_SEND requests"},
    { "core", "# discarded lower priority CORE_SEND request bytes"},
    { "transport", "# bytes received via TCP"},
    { "transport", "# bytes transmitted via TCP"},
    { "datacache", "# bytes stored"},
    { NULL, NULL}
  };


/**
 * Callback function to process statistic values.
 *
 * @param cls closure
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
print_stat (void *cls,
	    const char *subsystem,
	    const char *name,
	    uint64_t value,
	    int is_persistent)
{
  struct StatMaster *sm = cls;
  fprintf (stderr,
	   "Peer %2u: %12s/%50s = %12llu\n",
	   sm->daemon,
	   subsystem,
	   name,
	   (unsigned long long) value);
  return GNUNET_OK;
}


/**
 * Function that gathers stats from all daemons.
 */
static void
stat_run (void *cls,
	  const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function called when GET operation on stats is done.
 */
static void
get_done (void *cls,
	  int success)
{
  struct StatMaster *sm = cls;
  GNUNET_break (GNUNET_OK ==  success);
  sm->value++;
  GNUNET_SCHEDULER_add_now (&stat_run, sm);
}


/**
 * Function that gathers stats from all daemons.
 */
static void
stat_run (void *cls,
	  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct StatMaster *sm = cls;
 
  if (stats[sm->value].name != NULL)
    {
      GNUNET_STATISTICS_get (sm->stat,
#if 0
			     NULL, NULL, 
#else
			     stats[sm->value].subsystem,
			     stats[sm->value].name,
#endif
			     GNUNET_TIME_UNIT_FOREVER_REL,
			     &get_done,
			     &print_stat, sm);
      return;
    }
  GNUNET_STATISTICS_destroy (sm->stat, GNUNET_NO);
  sm->value = 0;
  sm->daemon++;
  if (sm->daemon == NUM_DAEMONS)
    {
      GNUNET_free (sm);
      GNUNET_SCHEDULER_add_now (&do_stop, NULL);
      return;
    }
  sm->stat = GNUNET_STATISTICS_create ("<driver>",
				       GNUNET_FS_TEST_get_configuration (daemons,
									 sm->daemon));
  GNUNET_SCHEDULER_add_now (&stat_run, sm);
}


static void
do_report (void *cls,
	 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TIME_Relative del;
  char *fancy; 
  struct StatMaster *sm;
  
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE))
    {
      del = GNUNET_TIME_absolute_get_duration (start_time);
      if (del.rel_value == 0)
	del.rel_value = 1;
      fancy = GNUNET_STRINGS_byte_size_fancy (((unsigned long long)FILESIZE) * 1000LL / del.rel_value);
      fprintf (stdout,
	       "Download speed was %s/s\n",
	       fancy);
      GNUNET_free (fancy);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Finished download, shutting down\n",
		  (unsigned long long) FILESIZE);
      sm = GNUNET_malloc (sizeof (struct StatMaster));
      sm->stat = GNUNET_STATISTICS_create ("<driver>",
					   GNUNET_FS_TEST_get_configuration (daemons,
									     sm->daemon));
      GNUNET_SCHEDULER_add_now (&stat_run, sm);
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Timeout during download, shutting down with error\n");
      ok = 1;
      GNUNET_SCHEDULER_add_now (&do_stop, NULL);
    }
}


static void
do_download (void *cls,
	     const struct GNUNET_FS_Uri *uri)
{
  int anonymity;

  if (NULL == uri)
    {
      GNUNET_FS_TEST_daemons_stop (NUM_DAEMONS,
				   daemons);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Timeout during upload attempt, shutting down with error\n");
      ok = 1;
      return;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Downloading %llu bytes\n",
	      (unsigned long long) FILESIZE);
  start_time = GNUNET_TIME_absolute_get ();
  if (NULL != strstr (progname, "dht"))
    anonymity = 0;
  else
    anonymity = 1;
  GNUNET_FS_TEST_download (daemons[0],
			   TIMEOUT,
			   anonymity, SEED, uri, 
			   VERBOSE, 
			   &do_report, NULL);
}


static void
do_publish (void *cls,
	    const char *emsg)
{
  int do_index;
  int anonymity;

  if (NULL != emsg)
    {
      GNUNET_FS_TEST_daemons_stop (NUM_DAEMONS,
				   daemons);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Error trying to connect: %s\n",
		  emsg);
      ok = 1;
      return;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Publishing %llu bytes\n",
	      (unsigned long long) FILESIZE);
  if (NULL != strstr (progname, "index"))
    do_index = GNUNET_YES;
  else
    do_index = GNUNET_NO;
  if (NULL != strstr (progname, "dht"))
    anonymity = 0;
  else
    anonymity = 1;
  
  GNUNET_FS_TEST_publish (daemons[NUM_DAEMONS-1],
			  TIMEOUT,
			  anonymity, 
			  do_index, FILESIZE, SEED, 
			  VERBOSE, 
			  &do_download, NULL);
}


static void
do_connect (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TESTING_PeerGroup *pg;

  GNUNET_assert (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Daemons started, will now try to connect them\n");
  pg = GNUNET_FS_TEST_get_group (daemons);
  GNUNET_break ( (NUM_DAEMONS - 1) * 2
		 == (GNUNET_TESTING_create_topology (pg, 
						     GNUNET_TESTING_TOPOLOGY_LINE,
						     GNUNET_TESTING_TOPOLOGY_NONE,
						     NULL)));
  GNUNET_TESTING_connect_topology (pg,
				   GNUNET_TESTING_TOPOLOGY_LINE,				   
				   GNUNET_TESTING_TOPOLOGY_OPTION_NONE,
				   0.0,
				   TIMEOUT,
				   NUM_DAEMONS,
				   &do_publish,
				   NULL);
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_FS_TEST_daemons_start ("fs_test_lib_data.conf",
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
    "perf-gnunet-service-fs-p2p",
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
  progname = argv[0];
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-lib/");
  GNUNET_log_setup ("perf_gnunet_service_fs_p2p_index", 
#if VERBOSE
		    "DEBUG",
#else
		    "WARNING",
#endif
		    NULL);
  GNUNET_PROGRAM_run ((sizeof (argvx) / sizeof (char *)) - 1,
                      argvx, "perf-gnunet-service-fs-p2p-index",
		      "nohelp", options, &run, NULL);
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-lib/");
  return ok;
}

/* end of perf_gnunet_service_fs_p2p.c */
