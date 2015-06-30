/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2011, 2012 Christian Grothoff (and other contributing authors)

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
 * @file fs/perf_gnunet_service_fs_p2p_respect.c
 * @brief profile P2P routing respect mechanism. Creates
 *        a clique of NUM_DAEMONS (i.e. 3) where two
 *        peers share (seed) different files and download
 *        them from each other while all the other peers
 *        just "leach" those files.  Ideally, the seeders
 *        "learn" that they contribute (to each other),
 *        and give the other seeder higher priority;
 *        naturally, this only happens nicely for larger
 *        files; finally, once the seeders are done, the
 *        leachers should see fast download rates as well.
 * @author Christian Grothoff
 *
 * Sample output:
 * - 10 MB, 3 peers, with delays:
 * Download speed of type `seeder 1' was 757 KiB/s
 * Download speed of type `seeder 2' was 613 KiB/s
 * Download speed of type `leach` was 539 KiB/s
 *
 * - 10 MB, 3 peers, without delays:
 * Download speed of type `seeder 1' was 1784 KiB/s
 * Download speed of type `seeder 2' was 1604 KiB/s
 * Download speed of type `leach` was 1384 KiB/s
 */
#include "platform.h"
#include "fs_test_lib.h"
#include "gnunet_testbed_service.h"

#define VERBOSE GNUNET_NO

/**
 * File-size we use for testing.
 */
#define FILESIZE (1024 * 1024 * 1)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 30)

/**
 * Number of daemons in clique, must be at least 3 (!).
 */
#define NUM_DAEMONS 3

/**
 * Seed for first file on offer.
 */
#define SEED1 42

/**
 * Seed for second file on offer.
 */
#define SEED2 43

static struct GNUNET_TESTBED_Peer *daemons[NUM_DAEMONS];

static int ok;

static struct GNUNET_TIME_Absolute start_time;

static const char *progname;

static struct GNUNET_FS_Uri *uri1;

static struct GNUNET_FS_Uri *uri2;

static char *fn1;

static char *fn2;

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
  {"fs", "# artificial delays introduced (ms)"},
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
  {"core", "# discarded lower priority CORE_SEND requests"},
  {"transport", "# bytes received via TCP"},
  {"transport", "# bytes transmitted via TCP"},
  {"datacache", "# bytes stored"},
  {NULL, NULL}
};


static void
cleanup ()
{
  GNUNET_SCHEDULER_shutdown ();
  if (NULL != fn1)
  {
    GNUNET_DISK_directory_remove (fn1);
    GNUNET_free (fn1);
  }
  if (NULL != fn2)
  {
    GNUNET_DISK_directory_remove (fn2);
    GNUNET_free (fn2);
  }
}


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
print_stat (void *cls, const char *subsystem, const char *name, uint64_t value,
            int is_persistent)
{
  struct StatMaster *sm = cls;

  FPRINTF (stderr, "Peer %2u: %12s/%50s = %12llu\n", sm->daemon, subsystem,
           name, (unsigned long long) value);
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

  sm->stat = ca_result;
  GNUNET_assert (NULL != sm->stat);
  if (NULL != stats[sm->value].name)
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
    cleanup ();
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
do_report (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static int download_counter;
  const char *type = cls;
  struct GNUNET_TIME_Relative del;
  char *fancy;
  struct StatMaster *sm;

  if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Timeout during download for type `%s', shutting down with error\n",
                type);
    ok = 1;
    cleanup ();
    return;
  }
  del = GNUNET_TIME_absolute_get_duration (start_time);
  if (del.rel_value_us == 0)
    del.rel_value_us = 1;
  fancy =
    GNUNET_STRINGS_byte_size_fancy (((unsigned long long) FILESIZE) *
				    1000000LL / del.rel_value_us);
  FPRINTF (stderr, "Download speed of type `%s' was %s/s\n", type, fancy);
  GNUNET_free (fancy);
  if (NUM_DAEMONS != ++download_counter)
    return;                   /* more downloads to come */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Finished all downloads, getting statistics\n");
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
do_downloads (void *cls, const struct GNUNET_FS_Uri *u2,
	      const char *fn)
{
  int anonymity;
  unsigned int i;

  if (NULL == u2)
  {
    cleanup ();
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Timeout during upload attempt, shutting down with error\n");
    ok = 1;
    return;
  }
  if (NULL != fn)
    fn2 = GNUNET_strdup (fn);
  uri2 = GNUNET_FS_uri_dup (u2);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Downloading %llu bytes\n",
              (unsigned long long) FILESIZE);
  start_time = GNUNET_TIME_absolute_get ();
  if (NULL != strstr (progname, "dht"))
    anonymity = 0;
  else
    anonymity = 1;
  /* (semi) leach-download(s); not true leaches since
   * these peers do participate in sharing, they just
   * don't have to offer anything *initially*.  */
  for (i = 0; i < NUM_DAEMONS - 2; i++)
    GNUNET_FS_TEST_download (daemons[i], TIMEOUT, anonymity,
                             0 == (i % 2) ? SEED1 : SEED2,
                             0 == (i % 2) ? uri1 : uri2, VERBOSE, &do_report,
                             "leach");
  /* mutual downloads of (primary) sharing peers */
  GNUNET_FS_TEST_download (daemons[NUM_DAEMONS - 2], TIMEOUT, anonymity, SEED1,
                           uri1, VERBOSE, &do_report, "seeder 2");
  GNUNET_FS_TEST_download (daemons[NUM_DAEMONS - 1], TIMEOUT, anonymity, SEED2,
                           uri2, VERBOSE, &do_report, "seeder 1");
}


static void
do_publish2 (void *cls,	
	     const struct GNUNET_FS_Uri *u1,
	     const char *fn)
{
  int do_index;
  int anonymity;

  if (NULL == u1)
  {
    cleanup ();
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Timeout during upload attempt, shutting down with error\n");
    ok = 1;
    return;
  }
  if (NULL != fn)
    fn1 = GNUNET_strdup (fn);
  uri1 = GNUNET_FS_uri_dup (u1);
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

  GNUNET_FS_TEST_publish (daemons[NUM_DAEMONS - 2], TIMEOUT, anonymity,
                          do_index, FILESIZE, SEED2, VERBOSE, &do_downloads,
                          NULL);
}


static void
do_publish1 (void *cls,
	     struct GNUNET_TESTBED_Operation *op,
	     const char *emsg)
{
  unsigned int *coco = cls;
  int do_index;
  int anonymity;

  GNUNET_TESTBED_operation_done (op);
  if (NULL != emsg)
  {
    cleanup ();
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error trying to connect: %s\n", emsg);
    ok = 1;
    return;
  }
  if (0 != (--(*coco)))
    return; /* more connections to be created */
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
                          do_index, FILESIZE, SEED1, VERBOSE, &do_publish2,
                          NULL);
}


static void
do_connect (void *cls,
            struct GNUNET_TESTBED_RunHandle *h,
	    unsigned int num_peers,
	    struct GNUNET_TESTBED_Peer **peers,
            unsigned int links_succeeded,
            unsigned int links_failed)
{
  static unsigned int coco;
  unsigned int i;
  unsigned int j;

  GNUNET_assert (NUM_DAEMONS == num_peers);
  for (i=0;i<num_peers;i++)
    daemons[i] = peers[i];
  for (i=0;i<NUM_DAEMONS;i++)
    for (j=i+1;j<NUM_DAEMONS;j++)
      {
	coco++;
	GNUNET_TESTBED_overlay_connect (NULL,
					&do_publish1,
					&coco,
					peers[i],
					peers[j]);
      }
}


int
main (int argc, char *argv[])
{
  progname = argv[0];
  (void) GNUNET_TESTBED_test_run ("perf-gnunet-service-fs-p2p-respect",
                                  "perf_gnunet_service_fs_p2p.conf",
                                  NUM_DAEMONS,
                                  0, NULL, NULL,
                                  &do_connect, NULL);
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-lib/");
  return ok;
}

/* end of perf_gnunet_service_fs_p2p_respect.c */
