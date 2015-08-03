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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file fs/perf_gnunet_service_fs_p2p.c
 * @brief profile P2P routing using simple publish + download operation
 * @author Christian Grothoff
 */
#include "platform.h"
#include "fs_test_lib.h"
#include "gnunet_testbed_service.h"

#define VERBOSE GNUNET_NO

/**
 * File-size we use for testing.
 */
#define FILESIZE (1024 * 1024 * 10)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 30)

#define NUM_DAEMONS 2

#define SEED 42

static struct GNUNET_TESTBED_Peer *daemons[NUM_DAEMONS];

static int ok;

static struct GNUNET_TIME_Absolute start_time;

static const char *progname;

static struct GNUNET_TIME_Absolute start_time;


/**
 * Master context for 'stat_run'.
 */
struct StatMaster
{
  struct GNUNET_STATISTICS_Handle *stat;
  struct GNUNET_TESTBED_Operation *op;
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
static struct StatValues stats[] = {
  {"fs", "# queries forwarded"},
  {"fs", "# replies received and matched"},
  {"fs", "# results found locally"},
  {"fs", "# requests forwarded due to high load"},
  {"fs", "# requests done for free (low load)"},
  {"fs", "# requests dropped, priority insufficient"},
  {"fs", "# requests done for a price (normal load)"},
  {"fs", "# requests dropped by datastore (queue length limit)"},
  {"fs", "# P2P searches received"},
  {"fs", "# P2P searches discarded (queue length bound)"},
  {"fs", "# replies received for local clients"},
  {"fs", "# queries retransmitted to same target"},
  {"core", "# bytes decrypted"},
  {"core", "# bytes encrypted"},
  {"core", "# discarded CORE_SEND requests"},
  {"core", "# discarded CORE_SEND request bytes"},
  {"core", "# discarded lower priority CORE_SEND requests"},
  {"core", "# discarded lower priority CORE_SEND request bytes"},
  {"transport", "# bytes received via TCP"},
  {"transport", "# bytes transmitted via TCP"},
  {"datacache", "# bytes stored"},
  {NULL, NULL}
};


/**
 * Callback function to process statistic values.
 *
 * @param cls closure
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent #GNUNET_YES if the value is persistent, #GNUNET_NO if not
 * @return #GNUNET_OK to continue, #GNUNET_SYSERR to abort iteration
 */
static int
print_stat (void *cls, const char *subsystem, const char *name, uint64_t value,
            int is_persistent)
{
  struct StatMaster *sm = cls;

  FPRINTF (stderr,
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
	  struct GNUNET_TESTBED_Operation *op,
	  void *ca_result,
	  const char *emsg);


/**
 * Function called when GET operation on stats is done.
 */
static void
get_done (void *cls, int success)
{
  struct StatMaster *sm = cls;

  GNUNET_break (GNUNET_OK == success);
  sm->value++;
  stat_run (sm, sm->op, sm->stat, NULL);
}


/**
 * Adapter function called to establish a connection to
 * statistics service.
 *
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
statistics_connect_adapter (void *cls,
			    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  return GNUNET_STATISTICS_create ("<driver>",
				   cfg);
}


/**
 * Adapter function called to destroy a connection to
 * statistics service.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
statistics_disconnect_adapter (void *cls,
			       void *op_result)
{
  GNUNET_STATISTICS_destroy (op_result, GNUNET_NO);
}


/**
 * Function that gathers stats from all daemons.
 */
static void
stat_run (void *cls,
	  struct GNUNET_TESTBED_Operation *op,
	  void *ca_result,
	  const char *emsg)
{
  struct StatMaster *sm = cls;

  if (NULL != emsg)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Failed to statistics service: %s\n",
		  emsg);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  sm->stat = ca_result;

  if (stats[sm->value].name != NULL)
  {
    GNUNET_STATISTICS_get (sm->stat,
#if 0
                           NULL, NULL,
#else
                           stats[sm->value].subsystem, stats[sm->value].name,
#endif
                           GNUNET_TIME_UNIT_FOREVER_REL, &get_done, &print_stat,
                           sm);
    return;
  }
  GNUNET_TESTBED_operation_done (sm->op);
  sm->value = 0;
  sm->daemon++;
  if (NUM_DAEMONS == sm->daemon)
  {
    GNUNET_free (sm);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  sm->op =
    GNUNET_TESTBED_service_connect (NULL,
				    daemons[sm->daemon],
				    "statistics",
				    &stat_run, sm,
				    &statistics_connect_adapter,
				    &statistics_disconnect_adapter,
				    NULL);
}


static void
do_report (void *cls,
           const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char *fn = cls;
  struct GNUNET_TIME_Relative del;
  char *fancy;
  struct StatMaster *sm;

  if (NULL != fn)
  {
    GNUNET_DISK_directory_remove (fn);
    GNUNET_free (fn);
  }
  if (0 ==
      GNUNET_TIME_absolute_get_remaining (GNUNET_TIME_absolute_add (start_time,
                                                                    TIMEOUT)).rel_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Timeout during download, shutting down with error\n");
    ok = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  del = GNUNET_TIME_absolute_get_duration (start_time);
  if (del.rel_value_us == 0)
    del.rel_value_us = 1;
  fancy =
    GNUNET_STRINGS_byte_size_fancy (((unsigned long long) FILESIZE) *
				    1000000LL / del.rel_value_us);
  FPRINTF (stdout, "Download speed was %s/s\n", fancy);
  GNUNET_free (fancy);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Finished download, shutting down\n",
	      (unsigned long long) FILESIZE);
  sm = GNUNET_new (struct StatMaster);
  sm->op =
    GNUNET_TESTBED_service_connect (NULL,
				    daemons[sm->daemon],
				    "statistics",
				    &stat_run, sm,
				    &statistics_connect_adapter,
				    &statistics_disconnect_adapter,
				    NULL);
}


static void
do_download (void *cls,
	     const struct GNUNET_FS_Uri *uri,
	     const char *fn)
{
  int anonymity;

  if (NULL == uri)
    {
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Timeout during upload attempt, shutting down with error\n");
    ok = 1;
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Downloading %llu bytes\n",
              (unsigned long long) FILESIZE);
  start_time = GNUNET_TIME_absolute_get ();
  if (NULL != strstr (progname, "dht"))
    anonymity = 0;
  else
    anonymity = 1;
  start_time = GNUNET_TIME_absolute_get ();
  GNUNET_FS_TEST_download (daemons[0],
                           TIMEOUT,
                           anonymity,
                           SEED,
                           uri,
                           VERBOSE,
                           &do_report,
			   (NULL == fn) ? NULL : GNUNET_strdup (fn));
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
  int do_index;
  int anonymity;

  GNUNET_assert (NUM_DAEMONS == num_peers);
  for (i=0;i<num_peers;i++)
    daemons[i] = peers[i];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Publishing %llu bytes\n",
              (unsigned long long) FILESIZE);
  if (NULL != strstr (progname, "index"))
    do_index = GNUNET_YES;
  else
    do_index = GNUNET_NO;
  if (NULL != strstr (progname, "dht"))
    anonymity = 0;
  else
    anonymity = 1;
  GNUNET_FS_TEST_publish (daemons[NUM_DAEMONS - 1], TIMEOUT, anonymity,
                          do_index, FILESIZE, SEED, VERBOSE, &do_download,
                          NULL);
}


int
main (int argc, char *argv[])
{
  progname = argv[0];
  (void) GNUNET_TESTBED_test_run ("perf-gnunet-service-fs-p2p",
                                  "perf_gnunet_service_fs_p2p.conf",
                                  NUM_DAEMONS,
                                  0, NULL, NULL,
                                  &do_publish, NULL);
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-lib/");
  return ok;
}

/* end of perf_gnunet_service_fs_p2p.c */
