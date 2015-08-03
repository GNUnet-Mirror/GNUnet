/*
     This file is part of GNUnet.
     Copyright (C) 2004, 2005, 2006, 2007, 2009, 2011, 2015 Christian Grothoff (and other contributing authors)

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
#include "gnunet_testing_lib.h"
#include <gauger.h>

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

/**
 * Target datastore size (in bytes).
 */
#define MAX_SIZE 1024LL * 1024 * 4

/**
 * Report progress outside of major reports? Should probably be #GNUNET_YES if
 * size is > 16 MB.
 */
#define REPORT_ID GNUNET_YES

/**
 * Number of put operations equivalent to 1/3rd of #MAX_SIZE
 */
#define PUT_10 MAX_SIZE / 32 / 1024 / 3

/**
 * Total number of iterations (each iteration doing
 * PUT_10 put operations); we report full status every
 * 10 iterations.  Abort with CTRL-C.
 */
#define ITERATIONS 8


/**
 * Number of bytes stored in the datastore in total.
 */
static unsigned long long stored_bytes;

/**
 * Number of entries stored in the datastore in total.
 */
static unsigned long long stored_entries;

/**
 * Number of database operations performed.  Inserting
 * counts as one operation, deleting as two (as deletion
 * requires selecting a value for deletion first).
 */
static unsigned long long stored_ops;

/**
 * Start time of the benchmark.
 */
static struct GNUNET_TIME_Absolute start_time;

/**
 * Database backend we use.
 */
static const char *plugin_name;

/**
 * Handle to the datastore.
 */
static struct GNUNET_DATASTORE_Handle *datastore;

/**
 * Value we return from #main().
 */
static int ok;

/**
 * Which phase of the process are we in?
 */
enum RunPhase
{
  /**
   * We are done (shutting down normally).
   */
  RP_DONE = 0,

  /**
   * We are adding new entries to the datastore.
   */
  RP_PUT,

  /**
   * We are deleting entries from the datastore.
   */
  RP_CUT,

  /**
   * We are generating a report.
   */
  RP_REPORT,

  /**
   * Execution failed with some kind of error.
   */
  RP_ERROR
};


/**
 * Closure we give to all of the functions executing the
 * benchmark.  Could right now be global, but this allows
 * us to theoretically run multiple clients "in parallel".
 */
struct CpsRunContext
{
  /**
   * Execution phase we are in.
   */
  enum RunPhase phase;

  /**
   * Size of the value we are currently storing (during #RP_PUT).
   */
  size_t size;

  /**
   * Current iteration counter, we are done with the benchmark
   * once it hits #ITERATIONS.
   */
  unsigned int i;

  /**
   * Counts the number of items put in the current phase.
   * Once it hits #PUT_10, we progress tot he #RP_CUT phase
   * or are done if @e i reaches #ITERATIONS.
   */
  unsigned int j;
};


/**
 * Main state machine.  Executes the next step of the benchmark
 * depending on the current state.
 *
 * @param cls the `struct CpsRunContext`
 * @param tc scheduler context (unused)
 */
static void
run_continuation (void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Continuation called to notify client about result of the insertion
 * operation.  Checks for errors, updates our iteration counters and
 * continues execution with #run_continuation().
 *
 * @param cls the `struct CpsRunContext`
 * @param success #GNUNET_SYSERR on failure
 * @param min_expiration minimum expiration time required for content to be stored
 *                by the datacache at this time, zero for unknown
 * @param msg NULL on success, otherwise an error message
 */
static void
check_success (void *cls,
               int success,
               struct GNUNET_TIME_Absolute min_expiration,
               const char *msg)
{
  struct CpsRunContext *crc = cls;

  if (GNUNET_OK != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Check success failed: `%s'\n",
                msg);
    crc->phase = RP_ERROR;
    GNUNET_SCHEDULER_add_now (&run_continuation,
                              crc);
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
  GNUNET_SCHEDULER_add_now (&run_continuation,
                            crc);
}


/**
 * Continuation called to notify client about result of the
 * deletion operation.  Checks for errors and continues
 * execution with #run_continuation().
 *
 * @param cls the `struct CpsRunContext`
 * @param success #GNUNET_SYSERR on failure
 * @param min_expiration minimum expiration time required for content to be stored
 *                by the datacache at this time, zero for unknown
 * @param msg NULL on success, otherwise an error message
 */
static void
remove_next (void *cls,
             int success,
             struct GNUNET_TIME_Absolute min_expiration,
             const char *msg)
{
  struct CpsRunContext *crc = cls;

  if (GNUNET_OK != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "remove_next failed: `%s'\n",
                msg);
    crc->phase = RP_ERROR;
    GNUNET_SCHEDULER_add_now (&run_continuation,
                              crc);
    return;
  }
#if REPORT_ID
  FPRINTF (stderr, "%s",  "D");
#endif
  GNUNET_assert (GNUNET_OK == success);
  GNUNET_SCHEDULER_add_now (&run_continuation,
                            crc);
}


/**
 * We have selected a value for deletion, trigger removal.
 *
 * @param cls the `struct CpsRunContext`
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
static void
delete_value (void *cls,
              const struct GNUNET_HashCode *key,
              size_t size,
              const void *data,
              enum GNUNET_BLOCK_Type type,
              uint32_t priority,
              uint32_t anonymity,
              struct GNUNET_TIME_Absolute expiration,
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
                 GNUNET_DATASTORE_remove (datastore,
                                          key,
                                          size,
                                          data, 1, 1,
                                          TIMEOUT,
                                          &remove_next, crc));
}


/**
 * Main state machine.  Executes the next step of the benchmark
 * depending on the current state.
 *
 * @param cls the `struct CpsRunContext`
 * @param tc scheduler context (unused)
 */
static void
run_continuation (void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CpsRunContext *crc = cls;
  size_t size;
  static struct GNUNET_HashCode key;
  static char data[65536];
  char gstr[128];

  ok = (int) crc->phase;
  switch (crc->phase)
  {
  case RP_PUT:
    memset (&key,
            256 - crc->i,
            sizeof (struct GNUNET_HashCode));
    /* most content is 32k */
    size = 32 * 1024;
    if (0 ==
        GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                  16)) /* but some of it is less! */
      size = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                       32 * 1024);
    crc->size = size = size - (size & 7);       /* always multiple of 8 */
    GNUNET_CRYPTO_hash (&key,
                        sizeof (struct GNUNET_HashCode),
                        &key);
    memset (data,
            (int) crc->j,
            size);
    if (crc->j > 255)
      memset (data,
              (int) (crc->j - 255),
              size / 2);
    data[0] = crc->i;
    GNUNET_assert (NULL !=
                   GNUNET_DATASTORE_put (datastore,
                                         0,
                                         &key,
                                         size,
                                         data,
                                         crc->j + 1,
                                         GNUNET_CRYPTO_random_u32
                                         (GNUNET_CRYPTO_QUALITY_WEAK, 100),
                                         crc->j,
                                         0,
                                         GNUNET_TIME_relative_to_absolute
                                         (GNUNET_TIME_relative_multiply
                                          (GNUNET_TIME_UNIT_SECONDS,
                                           GNUNET_CRYPTO_random_u32
                                           (GNUNET_CRYPTO_QUALITY_WEAK, 1000))),
                                         1,
                                         1,
                                         TIMEOUT,
                                         &check_success, crc));
    break;
  case RP_CUT:
    /* trim down below MAX_SIZE again */
    GNUNET_assert (NULL !=
                   GNUNET_DATASTORE_get_for_replication (datastore,
                                                         1, 1,
                                                         TIMEOUT,
                                                         &delete_value,
                                                         crc));
    break;
  case RP_REPORT:
    printf (
#if REPORT_ID
             "\n"
#endif
             "Stored %llu kB / %lluk ops / %llu ops/s\n",
             stored_bytes / 1024,  /* used size in k */
             stored_ops / 1024, /* total operations (in k) */
             1000LL * 1000LL * stored_ops / (1 +
					     GNUNET_TIME_absolute_get_duration
					     (start_time).rel_value_us));
    crc->phase = RP_PUT;
    crc->j = 0;
    GNUNET_SCHEDULER_add_now (&run_continuation,
                              crc);
    break;
  case RP_DONE:
    GNUNET_snprintf (gstr,
                     sizeof (gstr),
                     "DATASTORE-%s",
                     plugin_name);
    if ((crc->i == ITERATIONS) && (stored_ops > 0))
    {
      GAUGER (gstr,
              "PUT operation duration",
              GNUNET_TIME_absolute_get_duration (start_time).rel_value_us / 1000LL /
              stored_ops,
              "ms/operation");
      fprintf (stdout,
               "\nPUT performance: %s for %llu operations\n",
               GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (start_time),
                                                       GNUNET_YES),
               stored_ops);
      fprintf (stdout,
               "PUT performance: %llu ms/operation\n",
               GNUNET_TIME_absolute_get_duration (start_time).rel_value_us / 1000LL /
               stored_ops);
    }
    GNUNET_DATASTORE_disconnect (datastore,
                                 GNUNET_YES);
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


/**
 * Function called with the result of the initial PUT operation.  If
 * the PUT succeeded, we start the actual benchmark loop, otherwise we
 * bail out with an error.
 *
 *
 * @param cls closure
 * @param success #GNUNET_SYSERR on failure
 * @param min_expiration minimum expiration time required for content to be stored
 *                by the datacache at this time, zero for unknown
 * @param msg NULL on success, otherwise an error message
 */
static void
run_tests (void *cls,
           int success,
           struct GNUNET_TIME_Absolute min_expiration,
           const char *msg)
{
  struct CpsRunContext *crc = cls;

  if (success != GNUNET_YES)
  {
    FPRINTF (stderr,
             "Test 'put' operation failed with error `%s' database likely not setup, skipping test.\n",
             msg);
    GNUNET_DATASTORE_disconnect (datastore,
                                 GNUNET_YES);
    GNUNET_free (crc);
    return;
  }
  GNUNET_SCHEDULER_add_now (&run_continuation,
                            crc);
}


/**
 * Beginning of the actual execution of the benchmark.
 * Performs a first test operation (PUT) to verify that
 * the plugin works at all.
 *
 * @param cls NULL
 * @param cfg configuration to use
 * @param peer peer handle (unused)
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct CpsRunContext *crc;
  static struct GNUNET_HashCode zkey;

  datastore = GNUNET_DATASTORE_connect (cfg);
  start_time = GNUNET_TIME_absolute_get ();
  crc = GNUNET_new (struct CpsRunContext);
  crc->phase = RP_PUT;
  if (NULL ==
      GNUNET_DATASTORE_put (datastore,
                            0,
                            &zkey,
                            4, "TEST",
                            GNUNET_BLOCK_TYPE_TEST,
                            0, 0, 0,
                            GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_SECONDS),
                            0, 1,
                            TIMEOUT,
                            &run_tests, crc))
  {
    FPRINTF (stderr,
             "%s",
             "Test 'put' operation failed.\n");
    ok = 1;
    GNUNET_free (crc);
  }
}


/**
 * Entry point into the test. Determines which configuration / plugin
 * we are running with based on the name of the binary and starts
 * the peer.
 *
 * @param argc should be 1
 * @param argv used to determine plugin / configuration name.
 * @return 0 on success
 */
int
main (int argc,
      char *argv[])
{
  char cfg_name[128];

  plugin_name = GNUNET_TESTING_get_testname_from_underscore (argv[0]);
  GNUNET_snprintf (cfg_name,
                   sizeof (cfg_name),
                   "test_datastore_api_data_%s.conf",
                   plugin_name);
  if (0 !=
      GNUNET_TESTING_peer_run ("perf-gnunet-datastore",
			       cfg_name,
			       &run,
			       NULL))
    return 1;
  FPRINTF (stderr, "%s", "\n");
  return ok;
}

/* end of perf_datastore_api.c */
