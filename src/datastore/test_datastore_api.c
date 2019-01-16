/*
     This file is part of GNUnet.
     Copyright (C) 2004, 2005, 2006, 2007, 2009, 2015 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/
/*
 * @file datastore/test_datastore_api.c
 * @brief Test for the basic datastore API.
 * @author Christian Grothoff
 *
 * TODO:
 * - test reservation failure
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_datastore_service.h"
#include "gnunet_datastore_plugin.h"
#include "gnunet_testing_lib.h"


/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

#define ITERATIONS 256

/**
 * Handle to the datastore.
 */
static struct GNUNET_DATASTORE_Handle *datastore;

static struct GNUNET_TIME_Absolute now;

/**
 * Value we return from #main().
 */
static int ok;

/**
 * Name of plugin under test.
 */
static const char *plugin_name;


static size_t
get_size (int i)
{
  return 8 * i;
}


static const void *
get_data (int i)
{
  static char buf[60000];

  memset (buf, i, 8 * i);
  return buf;
}


static int
get_type (int i)
{
  return i + 1;
}


static int
get_priority (int i)
{
  return i + 1;
}


static int
get_anonymity (int i)
{
  return i;
}


static struct GNUNET_TIME_Absolute
get_expiration (int i)
{
  struct GNUNET_TIME_Absolute av;

  av.abs_value_us = now.abs_value_us + 20000000000LL - i * 1000 * 1000LL;
  return av;
}


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
  RP_PUT = 1,
  RP_GET = 2,
  RP_DEL = 3,
  RP_DO_DEL = 4,
  RP_DELVALIDATE = 5,
  RP_RESERVE = 6,
  RP_PUT_MULTIPLE = 7,
  RP_PUT_MULTIPLE_NEXT = 8,
  RP_GET_MULTIPLE = 9,
  RP_GET_MULTIPLE_NEXT = 10,

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

  struct GNUNET_HashCode key;
  int i;
  int rid;
  void *data;
  size_t size;

  uint64_t first_uid;
};


/**
 * Main state machine.  Executes the next step of the test
 * depending on the current state.
 *
 * @param cls the `struct CpsRunContext`
 */
static void
run_continuation (void *cls);


/**
 * Continuation called to notify client about result of an
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
                "Operation %d/%d not successful: `%s'\n",
                crc->phase,
                crc->i,
                msg);
    crc->phase = RP_ERROR;
  }
  GNUNET_free_non_null (crc->data);
  crc->data = NULL;
  GNUNET_SCHEDULER_add_now (&run_continuation, crc);
}


static void
get_reserved (void *cls,
              int success,
              struct GNUNET_TIME_Absolute min_expiration,
              const char *msg)
{
  struct CpsRunContext *crc = cls;

  if (0 >= success)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error obtaining reservation: `%s'\n",
                msg);
  GNUNET_assert (0 < success);
  crc->rid = success;
  GNUNET_SCHEDULER_add_now (&run_continuation,
                            crc);
}


static void
check_value (void *cls,
             const struct GNUNET_HashCode *key,
             size_t size,
             const void *data,
             enum GNUNET_BLOCK_Type type,
             uint32_t priority,
             uint32_t anonymity,
             uint32_t replication,
             struct GNUNET_TIME_Absolute expiration,
             uint64_t uid)
{
  struct CpsRunContext *crc = cls;
  int i;

  i = crc->i;
  if (NULL == key)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Value check failed (got NULL key) in %d/%d\n",
                crc->phase,
                crc->i);
    crc->phase = RP_ERROR;
    GNUNET_SCHEDULER_add_now (&run_continuation,
                              crc);
    return;
  }
#if 0
  FPRINTF (stderr,
	   "Check value got `%s' of size %u, type %d, expire %s\n",
           GNUNET_h2s (key), (unsigned int) size, type,
           GNUNET_STRINGS_absolute_time_to_string (expiration));
  FPRINTF (stderr,
           "Check value iteration %d wants size %u, type %d, expire %s\n", i,
           (unsigned int) get_size (i), get_type (i),
           GNUNET_STRINGS_absolute_time_to_string (get_expiration(i)));
#endif
  GNUNET_assert (size == get_size (i));
  GNUNET_assert (0 == memcmp (data, get_data (i), size));
  GNUNET_assert (type == get_type (i));
  GNUNET_assert (priority == get_priority (i));
  GNUNET_assert (anonymity == get_anonymity (i));
  GNUNET_assert (expiration.abs_value_us == get_expiration (i).abs_value_us);
  if (crc->i == 0)
  {
    crc->phase = RP_DEL;
    crc->i = ITERATIONS;
  }
  GNUNET_SCHEDULER_add_now (&run_continuation,
                            crc);
}


static void
delete_value (void *cls,
              const struct GNUNET_HashCode *key,
              size_t size,
              const void *data,
              enum GNUNET_BLOCK_Type type,
              uint32_t priority,
              uint32_t anonymity,
              uint32_t replication,
              struct GNUNET_TIME_Absolute expiration,
              uint64_t uid)
{
  struct CpsRunContext *crc = cls;

  GNUNET_assert (NULL == crc->data);
  GNUNET_assert (NULL != key);
  crc->size = size;
  crc->key = *key;
  crc->data = GNUNET_malloc (size);
  GNUNET_memcpy (crc->data, data, size);
  crc->phase = RP_DO_DEL;
  GNUNET_SCHEDULER_add_now (&run_continuation,
                            crc);
}


static void
check_nothing (void *cls,
               const struct GNUNET_HashCode *key,
               size_t size,
               const void *data,
               enum GNUNET_BLOCK_Type type,
               uint32_t priority,
               uint32_t anonymity,
               uint32_t replication,
               struct GNUNET_TIME_Absolute expiration,
               uint64_t uid)
{
  struct CpsRunContext *crc = cls;

  GNUNET_assert (key == NULL);
  if (crc->i == 0)
    crc->phase = RP_RESERVE;
  GNUNET_SCHEDULER_add_now (&run_continuation,
                            crc);
}


static void
check_multiple (void *cls,
                const struct GNUNET_HashCode *key,
                size_t size,
                const void *data,
                enum GNUNET_BLOCK_Type type,
                uint32_t priority,
                uint32_t anonymity,
                uint32_t replication,
                struct GNUNET_TIME_Absolute expiration,
                uint64_t uid)
{
  struct CpsRunContext *crc = cls;

  GNUNET_assert (key != NULL);
  switch (crc->phase)
  {
  case RP_GET_MULTIPLE:
    crc->phase = RP_GET_MULTIPLE_NEXT;
    crc->first_uid = uid;
    break;
  case RP_GET_MULTIPLE_NEXT:
    GNUNET_assert (uid != crc->first_uid);
    crc->phase = RP_DONE;
    break;
  default:
    GNUNET_break (0);
    crc->phase = RP_ERROR;
    break;
  }
  GNUNET_SCHEDULER_add_now (&run_continuation, crc);
}


/**
 * Main state machine.  Executes the next step of the test
 * depending on the current state.
 *
 * @param cls the `struct CpsRunContext`
 */
static void
run_continuation (void *cls)
{
  struct CpsRunContext *crc = cls;

  ok = (int) crc->phase;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Test in phase %u\n",
              crc->phase);
  switch (crc->phase)
  {
  case RP_PUT:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Executing PUT number %u\n",
                crc->i);
    GNUNET_CRYPTO_hash (&crc->i, sizeof (int), &crc->key);
    GNUNET_DATASTORE_put (datastore, 0, &crc->key, get_size (crc->i),
                          get_data (crc->i), get_type (crc->i),
                          get_priority (crc->i), get_anonymity (crc->i), 0,
                          get_expiration (crc->i), 1, 1,
                          &check_success, crc);
    crc->i++;
    if (crc->i == ITERATIONS)
      crc->phase = RP_GET;
    break;
  case RP_GET:
    crc->i--;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Executing GET number %u\n",
                crc->i);
    GNUNET_CRYPTO_hash (&crc->i,
                        sizeof (int),
                        &crc->key);
    GNUNET_DATASTORE_get_key (datastore,
                              0,
                              false,
                              &crc->key,
                              get_type (crc->i),
                              1,
                              1,
                              &check_value,
                              crc);
    break;
  case RP_DEL:
    crc->i--;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Executing DEL number %u\n",
                crc->i);
    crc->data = NULL;
    GNUNET_CRYPTO_hash (&crc->i, sizeof (int), &crc->key);
    GNUNET_assert (NULL !=
                   GNUNET_DATASTORE_get_key (datastore,
                                             0,
                                             false,
                                             &crc->key,
                                             get_type (crc->i),
                                             1,
                                             1,
                                             &delete_value,
                                             crc));
    break;
  case RP_DO_DEL:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Executing DO_DEL number %u\n",
                crc->i);
    if (crc->i == 0)
    {
      crc->i = ITERATIONS;
      crc->phase = RP_DELVALIDATE;
    }
    else
    {
      crc->phase = RP_DEL;
    }
    GNUNET_assert (NULL !=
                   GNUNET_DATASTORE_remove (datastore, &crc->key, crc->size,
                                            crc->data, 1, 1,
                                            &check_success, crc));
    break;
  case RP_DELVALIDATE:
    crc->i--;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Executing DELVALIDATE number %u\n",
                crc->i);
    GNUNET_CRYPTO_hash (&crc->i, sizeof (int), &crc->key);
    GNUNET_assert (NULL !=
                   GNUNET_DATASTORE_get_key (datastore,
                                             0,
                                             false,
                                             &crc->key,
                                             get_type (crc->i),
                                             1,
                                             1,
                                             &check_nothing,
                                             crc));
    break;
  case RP_RESERVE:
    crc->phase = RP_PUT_MULTIPLE;
    GNUNET_DATASTORE_reserve (datastore, 128 * 1024, 2,
                              &get_reserved, crc);
    break;
  case RP_PUT_MULTIPLE:
    crc->phase = RP_PUT_MULTIPLE_NEXT;
    GNUNET_DATASTORE_put (datastore, crc->rid, &crc->key, get_size (42),
                          get_data (42), get_type (42), get_priority (42),
                          get_anonymity (42), 0, get_expiration (42), 1, 1,
                          &check_success, crc);
    break;
  case RP_PUT_MULTIPLE_NEXT:
    crc->phase = RP_GET_MULTIPLE;
    GNUNET_DATASTORE_put (datastore, crc->rid,
                          &crc->key,
                          get_size (43),
                          get_data (43),
                          get_type (42),
                          get_priority (43),
                          get_anonymity (43),
                          0,
                          get_expiration (43),
                          1, 1,
                          &check_success, crc);
    break;
  case RP_GET_MULTIPLE:
    GNUNET_assert (NULL !=
                   GNUNET_DATASTORE_get_key (datastore,
                                             0,
                                             false,
                                             &crc->key,
                                             get_type (42),
                                             1,
                                             1,
                                             &check_multiple,
                                             crc));
    break;
  case RP_GET_MULTIPLE_NEXT:
    GNUNET_assert (NULL !=
                   GNUNET_DATASTORE_get_key (datastore,
                                             crc->first_uid + 1,
                                             false,
                                             &crc->key,
                                             get_type (42),
                                             1,
                                             1,
                                             &check_multiple,
                                             crc));
    break;
  case RP_DONE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Finished, disconnecting\n");
    GNUNET_DATASTORE_disconnect (datastore,
                                 GNUNET_YES);
    GNUNET_free (crc);
    ok = 0;
    break;
  case RP_ERROR:
    GNUNET_DATASTORE_disconnect (datastore,
                                 GNUNET_YES);
    GNUNET_free (crc);
    ok = 43;
    break;
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
           int32_t success,
           struct GNUNET_TIME_Absolute min_expiration,
           const char *msg)
{
  struct CpsRunContext *crc = cls;

  switch (success)
  {
  case GNUNET_YES:
    GNUNET_SCHEDULER_add_now (&run_continuation,
                              crc);
    return;
  case GNUNET_NO:
    FPRINTF (stderr,
             "%s", "Test 'put' operation failed, key already exists (!?)\n");
    GNUNET_DATASTORE_disconnect (datastore,
                                 GNUNET_YES);
    GNUNET_free (crc);
    return;
  case GNUNET_SYSERR:
    FPRINTF (stderr,
             "Test 'put' operation failed with error `%s' database likely not setup, skipping test.\n",
             msg);
    GNUNET_DATASTORE_disconnect (datastore,
                                 GNUNET_YES);
    GNUNET_free (crc);
    return;
  default:
    GNUNET_assert (0);
  }
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

  crc = GNUNET_new (struct CpsRunContext);
  crc->phase = RP_PUT;
  now = GNUNET_TIME_absolute_get ();
  datastore = GNUNET_DATASTORE_connect (cfg);
  if (NULL ==
      GNUNET_DATASTORE_put (datastore,
                            0,
                            &zkey,
                            4,
                            "TEST",
                            GNUNET_BLOCK_TYPE_TEST,
                            0, 0, 0,
                            GNUNET_TIME_relative_to_absolute
                            (GNUNET_TIME_UNIT_SECONDS),
                            0, 1,
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
 * Function invoked to notify service of disk utilization
 * changes.
 *
 * @param cls closure
 * @param delta change in disk utilization,
 *        0 for "reset to empty"
 */
static void
duc_dummy (void *cls,
	   int delta)
{
  /* intentionally empty */
}


/**
 * check if plugin is actually working 
 */
static int
test_plugin (const char *cfg_name)
{
  char libname[128];
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_DATASTORE_PluginFunctions *api;
  struct GNUNET_DATASTORE_PluginEnvironment env;
  
  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_load (cfg,
				 cfg_name))
  {
    GNUNET_CONFIGURATION_destroy (cfg);
    fprintf (stderr,
	     "Failed to load configuration %s\n",
	     cfg_name);
    return 1;
  }
  memset (&env, 0, sizeof (env));
  env.cfg = cfg;
  env.duc = &duc_dummy;
  GNUNET_snprintf (libname,
		   sizeof (libname),
                   "libgnunet_plugin_datastore_%s",
                   plugin_name);
  api = GNUNET_PLUGIN_load (libname, &env);
  if (NULL == api)
  {
    GNUNET_CONFIGURATION_destroy (cfg);
    fprintf (stderr,
	     "Failed to load plugin `%s'\n",
	     libname);
    return 77;
  }
  GNUNET_PLUGIN_unload (libname, api);
  GNUNET_CONFIGURATION_destroy (cfg);
  return 0;
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
  int ret;
    
  plugin_name = GNUNET_TESTING_get_testname_from_underscore (argv[0]);
  GNUNET_snprintf (cfg_name,
                   sizeof (cfg_name),
                   "test_datastore_api_data_%s.conf",
                   plugin_name);
  ret = test_plugin (cfg_name);
  if (0 != ret)
    return ret;
  /* run actual test */
  if (0 !=
      GNUNET_TESTING_peer_run ("test-gnunet-datastore",
			       cfg_name,
			       &run,
			       NULL))
    return 1;
  return ok;
}

/* end of test_datastore_api.c */
