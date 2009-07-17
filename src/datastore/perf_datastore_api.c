/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
/*
 * @file datastore/perf_datastore_api.c
 * @brief performance measurement for the datastore implementation
 * @author Christian Grothoff
 *
 * This testcase inserts a bunch of (variable size) data and then deletes
 * data until the (reported) database size drops below a given threshold.
 * This is iterated 10 times, with the actual size of the content stored,
 * the database size reported and the file size on disk being printed for
 * each iteration.  The code also prints a "I" for every 40 blocks
 * inserted and a "D" for every 40 blocks deleted.  The deletion
 * strategy alternates between "lowest priority" and "earliest expiration".
 * Priorities and expiration dates are set using a pseudo-random value
 * within a realistic range.
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_datastore_service.h"

static struct GNUNET_DATASTORE_Handle *datastore;

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

/**
 * Target datastore size (in bytes).
 * <p>
 * Example impact of total size on the reported number
 * of operations (insert and delete) per second (once
 * roughly stabilized -- this is not "sound" experimental
 * data but just a rough idea) for a particular machine:
 * <pre>
 *    4: 60   at   7k ops total
 *    8: 50   at   3k ops total
 *   16: 48   at   8k ops total
 *   32: 46   at   8k ops total
 *   64: 61   at   9k ops total
 *  128: 89   at   9k ops total
 * 4092: 11   at 383k ops total (12 GB stored, 14.8 GB DB size on disk, 2.5 GB reported)
 * </pre>
 * Pure insertion performance into an empty DB initially peaks
 * at about 400 ops.  The performance seems to drop especially
 * once the existing (fragmented) ISAM space is filled up and
 * the DB needs to grow on disk.  This could be explained with
 * ISAM looking more carefully for defragmentation opportunities.
 * <p>
 * MySQL disk space overheads (for otherwise unused database when
 * run with 128 MB target data size; actual size 651 MB, useful
 * data stored 520 MB) are quite large in the range of 25-30%.
 * <p>
 * This kind of processing seems to be IO bound (system is roughly
 * at 90% wait, 10% CPU).  This is with MySQL 5.0.
 *
 */
#define MAX_SIZE 1024LL * 1024 * 16

/**
 * Report progress outside of major reports? Should probably be GNUNET_YES if
 * size is > 16 MB.
 */
#define REPORT_ID GNUNET_NO

/**
 * Number of put operations equivalent to 1/10th of MAX_SIZE
 */
#define PUT_10 MAX_SIZE / 32 / 1024 / 10

/**
 * Progress report frequency.  1/10th of a put operation block.
 */
#define REP_FREQ PUT_10 / 10

/**
 * Total number of iterations (each iteration doing
 * PUT_10 put operations); we report full status every
 * 10 iterations.  Abort with CTRL-C.
 */
#define ITERATIONS 100


static unsigned long long stored_bytes;

static unsigned long long stored_entries;

static unsigned long long stored_ops;

static struct GNUNET_TIME_Absolute start_time;

static int ok;

static int
putValue (int i, int k)
{
  size_t size;
  static GNUNET_HashCode key;
  static int ic;
  static char data[65536];

  /* most content is 32k */
  size = 32 * 1024;
  if (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 16) == 0)  /* but some of it is less! */
    size = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 32 * 1024);
  size = size - (size & 7);     /* always multiple of 8 */

  GNUNET_CRYPTO_hash (&key, sizeof (GNUNET_HashCode), &key);
  memset (data, i, size);
  if (i > 255)
    memset (data, i - 255, size / 2);
  data[0] = k;
  GNUNET_DATASTORE_put (datastore,
			0,
			&key,
			size,
			data,
			i,
			GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 100),
			i,
			GNUNET_TIME_relative_to_absolute 
			(GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
							GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 1000))),
			TIMEOUT,
			NULL, NULL);
  ic++;
#if REPORT_ID
  if (ic % REP_FREQ == 0)
    fprintf (stderr, "I");
#endif
  stored_bytes += size;
  stored_ops++;
  stored_entries++;
  return GNUNET_OK;
}


static void
iterate_delete (void *cls,
		const GNUNET_HashCode * key,
		uint32_t size,
		const void *data,
		uint32_t type,
		uint32_t priority,
		uint32_t anonymity,
		struct GNUNET_TIME_Absolute
		expiration, uint64_t uid)
{
  GNUNET_DATASTORE_remove (datastore, key, size, data, NULL, NULL);
}


enum RunPhase
  {
    RP_DONE = 0,
    RP_PUT,
    RP_CUT,
    RP_REPORT,
    RP_END
  };


struct CpsRunContext
{
  struct GNUNET_SCHEDULER_Handle *sched;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  enum RunPhase phase;
  int j;
  unsigned long long size;
  int i;


  GNUNET_HashCode key;
  int *iptr;
};



static void
run_continuation (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc);



static void
run_continuation (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CpsRunContext *crc = cls;
  ok = (int) crc->phase;
  switch (crc->phase)
    {
    case RP_PUT:
      memset (&crc->key, 256 - crc->i, sizeof (GNUNET_HashCode));

      GNUNET_assert (GNUNET_OK == putValue (j, i));
      GNUNET_DATASTORE_put (datastore,
			    0,
			    &crc->key,
			    get_size (crc->i),
			    get_data (crc->i),
			    get_type (crc->i),
			    get_priority (crc->i),
			    get_anonymity (crc->i),
			    get_expiration (crc->i),
			    TIMEOUT,
			    &check_success,
			    crc);
      crc->j++;
      if (crc->j < PUT_10)
	break;
      crc->j = 0;
      crc->i++;
      if (crc->i == ITERATIONS)
	crc->phase = RP_DONE;
      else
	crc->phase = RP_CUT;
      break;
    case RP_CUT:
      /* trim down below MAX_SIZE again */
      if ((i % 2) == 0)
        GNUNET_DATASTORE_get_random (datastore, 
				     &iterate_delete,
				     NULL);
      crc->phase = RP_REPORT;
      break;
    case RP_REPORT:
      size = 0;
      printf (
#if REPORT_ID
               "\n"
#endif
               "Stored %llu kB / %lluk ops / %llu ops/s\n", 
	       stored_bytes / 1024,     /* used size in k */
               (stored_ops * 2 - stored_entries) / 1024,        /* total operations (in k) */
               1000 * (stored_ops * 2 - stored_entries) / (1 + GNUNET_TIME_absolute_get_duration(start_time).value));       /* operations per second */
      crc->phase = RP_PUT;
      // fixme: trigger next round...
      GNUNET_SCHEDULER_add_continuation (crc->sched,
					 GNUNET_NO,
					 &run_continuation,
					 crc,
					 GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      break;
    case RP_DONE:
      GNUNET_DATASTORE_disconnect (datastore, GNUNET_YES);
      ok = 0;
      break;
    }
}


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     char *const *args,
     const char *cfgfile, struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct CpsRunContext *crc;

  datastore = GNUNET_DATASTORE_connect (cfg, sched);

  crc = GNUNET_malloc(sizeof(struct CpsRunContext));
  crc->sched = sched;
  crc->cfg = cfg;
  crc->phase = RP_PUT;
  GNUNET_SCHEDULER_add_continuation (crc->sched,
				     GNUNET_NO,
				     &run_continuation,
				     crc,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static int
check ()
{
  pid_t pid;
  char *const argv[] = { "perf-datastore-api",
    "-c",
    "test_datastore_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  pid = GNUNET_OS_start_process ("gnunet-service-datastore",
                                 "gnunet-service-datastore",
#if VERBOSE
                                 "-L", "DEBUG",
#endif
                                 "-c", "test_datastore_api_data.conf", NULL);
  sleep (1);
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "perf-datastore-api", "nohelp",
                      options, &run, NULL);
  if (0 != PLIBC_KILL (pid, SIGTERM))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
      ok = 1;
    }
  GNUNET_OS_process_wait(pid);
  if (ok != 0)
    fprintf (stderr, "Missed some testcases: %u\n", ok);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("perf-datastore-api",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();

  return ret;
}


/* end of perf_datastore_api.c */
