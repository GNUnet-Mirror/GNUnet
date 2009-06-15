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
 * @file applications/sqstore_sqlite/sqlitetest2.c
 * @brief Test for the sqstore implementations.
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
 * <p>
 *
 * Note that the disk overhead calculations are not very sane for
 * MySQL: we take the entire /var/lib/mysql directory (best we can
 * do for ISAM), which may contain other data and which never
 * shrinks.  The scanning of the entire mysql directory during
 * each report is also likely to be the cause of a minor
 * slowdown compared to sqlite.<p>
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_sqstore_service.h"
#include "core.h"

#define ASSERT(x) do { if (! (x)) { printf("Error at %s:%d\n", __FILE__, __LINE__); goto FAILURE;} } while (0)

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

/**
 * Name of the database on disk.
 * You may have to adjust this path and the access
 * permission to the respective directory in order
 * to obtain all of the performance information.
 */
#define DB_NAME "/tmp/gnunet-sqlite-sqstore-test/data/fs/"

static unsigned long long stored_bytes;

static unsigned long long stored_entries;

static unsigned long long stored_ops;

static GNUNET_CronTime start_time;

static int
putValue (GNUNET_SQstore_ServiceAPI * api, int i, int k)
{
  GNUNET_DatastoreValue *value;
  size_t size;
  static GNUNET_HashCode key;
  static int ic;

  /* most content is 32k */
  size = sizeof (GNUNET_DatastoreValue) + 32 * 1024;
  if (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 16) == 0)  /* but some of it is less! */
    size =
      sizeof (GNUNET_DatastoreValue) +
      GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 32 * 1024);
  size = size - (size & 7);     /* always multiple of 8 */

  /* generate random key */
  GNUNET_hash (&key, sizeof (GNUNET_HashCode), &key);
  value = GNUNET_malloc (size);
  value->size = htonl (size);
  value->type = htonl (i);
  value->priority =
    htonl (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 100));
  value->anonymity_level = htonl (i);
  value->expiration_time =
    GNUNET_htonll (GNUNET_get_time () +
                   GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 1000));
  memset (&value[1], i, size - sizeof (GNUNET_DatastoreValue));
  if (i > 255)
    memset (&value[1], i - 255, (size - sizeof (GNUNET_DatastoreValue)) / 2);
  ((char *) &value[1])[0] = k;
  if (GNUNET_OK != api->put (&key, value))
    {
      GNUNET_free (value);
      fprintf (stderr, "E");
      return GNUNET_SYSERR;
    }
  ic++;
#if REPORT_ID
  if (ic % REP_FREQ == 0)
    fprintf (stderr, "I");
#endif
  stored_bytes += ntohl (value->size);
  stored_ops++;
  stored_entries++;
  GNUNET_free (value);
  return GNUNET_OK;
}

static int
iterateDelete (const GNUNET_HashCode * key,
               const GNUNET_DatastoreValue * val, void *cls,
               unsigned long long uid)
{
  GNUNET_SQstore_ServiceAPI *api = cls;
  static int dc;

  if (api->getSize () < MAX_SIZE)
    return GNUNET_SYSERR;
  if (GNUNET_shutdown_test () == GNUNET_YES)
    return GNUNET_SYSERR;
  dc++;
#if REPORT_ID
  if (dc % REP_FREQ == 0)
    fprintf (stderr, "D");
#endif
  stored_bytes -= ntohl (val->size);
  stored_entries--;
  return GNUNET_NO;
}

/**
 * Add testcode here!
 */
static int
test (GNUNET_SQstore_ServiceAPI * api)
{
  int i;
  int j;
  unsigned long long size;
  int have_file;
  struct stat sbuf;

  have_file = 0 == stat (DB_NAME, &sbuf);

  for (i = 0; i < ITERATIONS; i++)
    {
#if REPORT_ID
      fprintf (stderr, ".");
#endif
      /* insert data equivalent to 1/10th of MAX_SIZE */
      for (j = 0; j < PUT_10; j++)
        {
          ASSERT (GNUNET_OK == putValue (api, j, i));
          if (GNUNET_shutdown_test () == GNUNET_YES)
            break;
        }

      /* trim down below MAX_SIZE again */
      if ((i % 2) == 0)
        api->iterateLowPriority (0, &iterateDelete, api);
      else
        api->iterateExpirationTime (0, &iterateDelete, api);

      size = 0;
      if (have_file)
        GNUNET_disk_file_size (NULL, DB_NAME, &size, GNUNET_NO);
      printf (
#if REPORT_ID
               "\n"
#endif
               "Useful %llu, API %llu, disk %llu (%.2f%%) / %lluk ops / %llu ops/s\n", stored_bytes / 1024,     /* used size in k */
               api->getSize () / 1024,  /* API-reported size in k */
               size / 1024,     /* disk size in kb */
               (100.0 * size / stored_bytes) - 100,     /* overhead */
               (stored_ops * 2 - stored_entries) / 1024,        /* total operations (in k) */
               1000 * (stored_ops * 2 - stored_entries) / (1 + GNUNET_get_time () - start_time));       /* operations per second */
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  api->drop ();
  return GNUNET_OK;

FAILURE:
  api->drop ();
  return GNUNET_SYSERR;
}

int
main (int argc, char *argv[])
{
  GNUNET_SQstore_ServiceAPI *api;
  int ok;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_CronManager *cron;

  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  cron = GNUNET_cron_create (NULL);
  GNUNET_CORE_init (NULL, cfg, cron, NULL);
  api = GNUNET_CORE_request_service ("sqstore");
  if (api != NULL)
    {
      start_time = GNUNET_get_time ();
      ok = test (api);
      GNUNET_CORE_release_service (api);
    }
  else
    ok = GNUNET_SYSERR;
  GNUNET_CORE_done ();
  GNUNET_cron_destroy (cron);
  GNUNET_GC_free (cfg);
  if (ok == GNUNET_SYSERR)
    return 1;
  return 0;
}

/* end of mysqltest2.c */
