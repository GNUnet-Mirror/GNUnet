/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2007, 2009, 2011 Christian Grothoff (and other contributing authors)

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
/*
 * @file datastore/perf_datastore_api.c
 * @brief performance measurement for the datastore implementation
 * @author Christian Grothoff
 *
 * This testcase inserts a bunch of (variable size) data and then
 * deletes data until the (reported) database size drops below a given
 * threshold.  This is iterated 10 times, with the actual size of the
 * content stored and the number of operations performed being printed
 * for each iteration.  The code also prints a "I" for every 40 blocks
 * inserted and a "D" for every 40 blocks deleted.  The deletion
 * strategy uses the "random" iterator.  Priorities and expiration
 * dates are set using a pseudo-random value within a realistic range.
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_datastore_service.h"
#include <gauger.h>

#define VERBOSE GNUNET_NO

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

static const char *plugin_name;

static struct GNUNET_DATASTORE_Handle *datastore;

/**
 * Target datastore size (in bytes).
 */
#define MAX_SIZE 1024LL * 1024 * 4

/**
 * Report progress outside of major reports? Should probably be GNUNET_YES if
 * size is > 16 MB.
 */
#define REPORT_ID GNUNET_YES

/**
 * Number of put operations equivalent to 1/3rd of MAX_SIZE
 */
#define PUT_10 MAX_SIZE / 32 / 1024 / 3

/**
 * Total number of iterations (each iteration doing
 * PUT_10 put operations); we report full status every
 * 10 iterations.  Abort with CTRL-C.
 */
#define ITERATIONS 8


static unsigned long long stored_bytes;

static unsigned long long stored_entries;

static unsigned long long stored_ops;

static struct GNUNET_TIME_Absolute start_time;

static int ok;

enum RunPhase
{
  RP_DONE = 0,
  RP_PUT,
  RP_CUT,
  RP_REPORT,
  RP_ERROR
};


struct CpsRunContext
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  enum RunPhase phase;
  int j;
  unsigned long long size;
  int i;
};



static void
run_continuation (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);




static void
check_success (void *cls, int success, struct GNUNET_TIME_Absolute min_expiration,  const char *msg)
{
  struct CpsRunContext *crc = cls;

  if (GNUNET_OK != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Check success failed: `%s'\n", msg);
    crc->phase = RP_ERROR;
    GNUNET_SCHEDULER_add_now (&run_continuation, crc);
    return;
  }
#if REPORT_ID
  FPRINTF (stderr, "%s",  "I");
#endif
  stored_bytes += crc->size;
  stored_ops++;
  stored_entries++;
  crc->j++;
  if (crc->j >= PUT_10)
  {
    crc->j = 0;
    crc->i++;
    if (crc->i == ITERATIONS)
      crc->phase = RP_DONE;
    else
      crc->phase = RP_CUT;
  }
  GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param success GNUNET_SYSERR on failure
 * @param min_expiration minimum expiration time required for content to be stored
 *                by the datacache at this time, zero for unknown
 * @param msg NULL on success, otherwise an error message
 */
static void
remove_next (void *cls, int success, struct GNUNET_TIME_Absolute min_expiration, const char *msg)
{
  struct CpsRunContext *crc = cls;

  if (GNUNET_OK != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "remove_next failed: `%s'\n", msg);
    crc->phase = RP_ERROR;
    GNUNET_SCHEDULER_add_now (&run_continuation, crc);
    return;
  }
#if REPORT_ID
  FPRINTF (stderr, "%s",  "D");
#endif
  GNUNET_assert (GNUNET_OK == success);
  GNUNET_SCHEDULER_add_now (&run_continuation, crc);
}


static void
delete_value (void *cls, const GNUNET_HashCode * key, size_t size,
              const void *data, enum GNUNET_BLOCK_Type type, uint32_t priority,
              uint32_t anonymity, struct GNUNET_TIME_Absolute expiration,
              uint64_t uid)
{
  struct CpsRunContext *crc = cls;

  GNUNET_assert (NULL != key);
  stored_ops++;
  stored_bytes -= size;
  stored_entries--;
  stored_ops++;
  if (stored_bytes < MAX_SIZE)
    crc->phase = RP_PUT;
  GNUNET_assert (NULL !=
                 GNUNET_DATASTORE_remove (datastore, key, size, data, 1, 1,
                                          TIMEOUT, &remove_next, crc));
}


static void
run_continuation (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CpsRunContext *crc = cls;
  size_t size;
  static GNUNET_HashCode key;
  static char data[65536];
  int i;
  int k;
  char gstr[128];

  ok = (int) crc->phase;
  switch (crc->phase)
  {
  case RP_PUT:
    memset (&key, 256 - crc->i, sizeof (GNUNET_HashCode));
    i = crc->j;
    k = crc->i;
    /* most content is 32k */
    size = 32 * 1024;
    if (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 16) == 0) /* but some of it is less! */
      size = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 32 * 1024);
    crc->size = size = size - (size & 7);       /* always multiple of 8 */
    GNUNET_CRYPTO_hash (&key, sizeof (GNUNET_HashCode), &key);
    memset (data, i, size);
    if (i > 255)
      memset (data, i - 255, size / 2);
    data[0] = k;
    GNUNET_assert (NULL !=
                   GNUNET_DATASTORE_put (datastore, 0, &key, size, data, i + 1,
                                         GNUNET_CRYPTO_random_u32
                                         (GNUNET_CRYPTO_QUALITY_WEAK, 100), i,
                                         0,
                                         GNUNET_TIME_relative_to_absolute
                                         (GNUNET_TIME_relative_multiply
                                          (GNUNET_TIME_UNIT_SECONDS,
                                           GNUNET_CRYPTO_random_u32
                                           (GNUNET_CRYPTO_QUALITY_WEAK, 1000))),
                                         1, 1, TIMEOUT, &check_success, crc));
    break;
  case RP_CUT:
    /* trim down below MAX_SIZE again */
    GNUNET_assert (NULL !=
                   GNUNET_DATASTORE_get_for_replication (datastore, 1, 1,
                                                         TIMEOUT, &delete_value,
                                                         crc));
    break;
  case RP_REPORT:
    printf (
#if REPORT_ID
             "\n"
#endif
             "Stored %llu kB / %lluk ops / %llu ops/s\n", stored_bytes / 1024,  /* used size in k */
             stored_ops / 1024, /* total operations (in k) */
             1000 * stored_ops / (1 +
                                  GNUNET_TIME_absolute_get_duration
                                  (start_time).rel_value));
    crc->phase = RP_PUT;
    crc->j = 0;
    GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    break;
  case RP_DONE:
    GNUNET_snprintf (gstr, sizeof (gstr), "DATASTORE-%s", plugin_name);
    if ((crc->i == ITERATIONS) && (stored_ops > 0))
      GAUGER (gstr, "PUT operation duration",
              GNUNET_TIME_absolute_get_duration (start_time).rel_value /
              stored_ops, "ms/operation");
    GNUNET_DATASTORE_disconnect (datastore, GNUNET_YES);
    GNUNET_free (crc);
    ok = 0;
    break;
  case RP_ERROR:
    GNUNET_DATASTORE_disconnect (datastore, GNUNET_YES);
    GNUNET_free (crc);
    ok = 1;
    break;
  default:
    GNUNET_assert (0);
  }
}


static void
run_tests (void *cls, int success, struct GNUNET_TIME_Absolute min_expiration, const char *msg)
{
  struct CpsRunContext *crc = cls;

  if (success != GNUNET_YES)
  {
    FPRINTF (stderr,
             "Test 'put' operation failed with error `%s' database likely not setup, skipping test.\n",
             msg);
    GNUNET_DATASTORE_disconnect (datastore, GNUNET_YES);
    GNUNET_free (crc);
    return;
  }
  GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct CpsRunContext *crc;
  static GNUNET_HashCode zkey;

  datastore = GNUNET_DATASTORE_connect (cfg);
  start_time = GNUNET_TIME_absolute_get ();
  crc = GNUNET_malloc (sizeof (struct CpsRunContext));
  crc->cfg = cfg;
  crc->phase = RP_PUT;
  if (NULL ==
      GNUNET_DATASTORE_put (datastore, 0, &zkey, 4, "TEST",
                            GNUNET_BLOCK_TYPE_TEST, 0, 0, 0,
                            GNUNET_TIME_relative_to_absolute
                            (GNUNET_TIME_UNIT_SECONDS), 0, 1,
                            GNUNET_TIME_UNIT_MINUTES, &run_tests, crc))
  {
    FPRINTF (stderr, "%s",  "Test 'put' operation failed.\n");
    ok = 1;
    GNUNET_free (crc);
  }
}


static int
check ()
{
  struct GNUNET_OS_Process *proc;
  char cfg_name[128];

  char *const argv[] = {
    "perf-datastore-api",
    "-c",
    cfg_name,
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_snprintf (cfg_name, sizeof (cfg_name),
                   "test_datastore_api_data_%s.conf", plugin_name);
  proc =
      GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm",
#if VERBOSE
                               "-L", "DEBUG",
#endif
                               "-c", cfg_name, NULL);
  GNUNET_assert (NULL != proc);
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "perf-datastore-api", "nohelp", options, &run, NULL);
  sleep (1);                    /* give datastore chance to process 'DROP' */
  if (0 != GNUNET_OS_process_kill (proc, SIGTERM))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    ok = 1;
  }
  GNUNET_OS_process_wait (proc);
  GNUNET_OS_process_destroy (proc);
  proc = NULL;
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;
  char *pos;
  char dir_name[128];

  sleep (1);
  /* determine name of plugin to use */
  plugin_name = argv[0];
  while (NULL != (pos = strstr (plugin_name, "_")))
    plugin_name = pos + 1;
  if (NULL != (pos = strstr (plugin_name, ".")))
    pos[0] = 0;
  else
    pos = (char *) plugin_name;

  GNUNET_snprintf (dir_name, sizeof (dir_name), "/tmp/test-gnunet-datastore-%s",
                   plugin_name);
  GNUNET_DISK_directory_remove (dir_name);
  GNUNET_log_setup ("perf-datastore-api",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  if (pos != plugin_name)
    pos[0] = '.';
#if REPORT_ID
  FPRINTF (stderr, "%s",  "\n");
#endif
  GNUNET_DISK_directory_remove (dir_name);
  return ret;
}

/* end of perf_datastore_api.c */
