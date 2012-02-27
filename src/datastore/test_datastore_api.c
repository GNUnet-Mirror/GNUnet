/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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

#define VERBOSE GNUNET_NO

#define START_DATASTORE GNUNET_YES

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

#define ITERATIONS 256

static struct GNUNET_DATASTORE_Handle *datastore;

static struct GNUNET_TIME_Absolute now;

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

  av.abs_value = now.abs_value + 20000000 - i * 1000;
  return av;
}

enum RunPhase
{
  RP_DONE = 0,
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
  RP_UPDATE = 11,
  RP_UPDATE_VALIDATE = 12,
  RP_ERROR
};


struct CpsRunContext
{
  GNUNET_HashCode key;
  int i;
  int rid;
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  void *data;
  size_t size;
  enum RunPhase phase;
  uint64_t uid;
  uint64_t offset;
  uint64_t first_uid;
};


static void
run_continuation (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
check_success (void *cls, int success, struct GNUNET_TIME_Absolute min_expiration, const char *msg)
{
  struct CpsRunContext *crc = cls;

  if (GNUNET_OK != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Operation %d/%d not successfull: `%s'\n", crc->phase, crc->i,
                msg);
    crc->phase = RP_ERROR;
  }
  GNUNET_free_non_null (crc->data);
  crc->data = NULL;
  GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static void
get_reserved (void *cls, int success, struct GNUNET_TIME_Absolute min_expiration, const char *msg)
{
  struct CpsRunContext *crc = cls;

  if (0 >= success)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error obtaining reservation: `%s'\n",
                msg);
  GNUNET_assert (0 < success);
  crc->rid = success;
  GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static void
check_value (void *cls, const GNUNET_HashCode * key, size_t size,
             const void *data, enum GNUNET_BLOCK_Type type, uint32_t priority,
             uint32_t anonymity, struct GNUNET_TIME_Absolute expiration,
             uint64_t uid)
{
  struct CpsRunContext *crc = cls;
  int i;

  i = crc->i;
  if (NULL == key)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Value check failed (got NULL key) in %d/%d\n", crc->phase,
                crc->i);
    crc->phase = RP_ERROR;
    GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    return;
  }
#if 0
  FPRINTF (stderr, "Check value got `%s' of size %u, type %d, expire %llu\n",
           GNUNET_h2s (key), (unsigned int) size, type,
           (unsigned long long) expiration.abs_value);
  FPRINTF (stderr,
           "Check value iteration %d wants size %u, type %d, expire %llu\n", i,
           (unsigned int) get_size (i), get_type (i),
           (unsigned long long) get_expiration (i).abs_value);
#endif
  GNUNET_assert (size == get_size (i));
  GNUNET_assert (0 == memcmp (data, get_data (i), size));
  GNUNET_assert (type == get_type (i));
  GNUNET_assert (priority == get_priority (i));
  GNUNET_assert (anonymity == get_anonymity (i));
  GNUNET_assert (expiration.abs_value == get_expiration (i).abs_value);
  crc->offset++;
  if (crc->i == 0)
  {
    crc->phase = RP_DEL;
    crc->i = ITERATIONS;
  }
  GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static void
delete_value (void *cls, const GNUNET_HashCode * key, size_t size,
              const void *data, enum GNUNET_BLOCK_Type type, uint32_t priority,
              uint32_t anonymity, struct GNUNET_TIME_Absolute expiration,
              uint64_t uid)
{
  struct CpsRunContext *crc = cls;

  GNUNET_assert (crc->data == NULL);
  GNUNET_assert (NULL != key);
  crc->size = size;
  crc->key = *key;
  crc->data = GNUNET_malloc (size);
  memcpy (crc->data, data, size);
  crc->phase = RP_DO_DEL;
  GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static void
check_nothing (void *cls, const GNUNET_HashCode * key, size_t size,
               const void *data, enum GNUNET_BLOCK_Type type, uint32_t priority,
               uint32_t anonymity, struct GNUNET_TIME_Absolute expiration,
               uint64_t uid)
{
  struct CpsRunContext *crc = cls;

  GNUNET_assert (key == NULL);
  if (crc->i == 0)
    crc->phase = RP_RESERVE;
  GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static void
check_multiple (void *cls, const GNUNET_HashCode * key, size_t size,
                const void *data, enum GNUNET_BLOCK_Type type,
                uint32_t priority, uint32_t anonymity,
                struct GNUNET_TIME_Absolute expiration, uint64_t uid)
{
  struct CpsRunContext *crc = cls;

  GNUNET_assert (key != NULL);
  switch (crc->phase)
  {
  case RP_GET_MULTIPLE:
    crc->phase = RP_GET_MULTIPLE_NEXT;
    crc->first_uid = uid;
    crc->offset++;
    break;
  case RP_GET_MULTIPLE_NEXT:
    GNUNET_assert (uid != crc->first_uid);
    crc->phase = RP_UPDATE;
    break;
  default:
    GNUNET_break (0);
    crc->phase = RP_ERROR;
    break;
  }
  if (priority == get_priority (42))
    crc->uid = uid;
  GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static void
check_update (void *cls, const GNUNET_HashCode * key, size_t size,
              const void *data, enum GNUNET_BLOCK_Type type, uint32_t priority,
              uint32_t anonymity, struct GNUNET_TIME_Absolute expiration,
              uint64_t uid)
{
  struct CpsRunContext *crc = cls;

  GNUNET_assert (key != NULL);
  if ((anonymity == get_anonymity (42)) && (size == get_size (42)) &&
      (priority == get_priority (42) + 100))
    crc->phase = RP_DONE;
  else
  {
    GNUNET_assert (size == get_size (43));
    crc->offset++;
  }
  GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static void
run_continuation (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CpsRunContext *crc = cls;

  ok = (int) crc->phase;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test in phase %u\n", crc->phase);
#endif
  switch (crc->phase)
  {
  case RP_PUT:
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Executing `%s' number %u\n", "PUT",
                crc->i);
#endif
    GNUNET_CRYPTO_hash (&crc->i, sizeof (int), &crc->key);
    GNUNET_DATASTORE_put (datastore, 0, &crc->key, get_size (crc->i),
                          get_data (crc->i), get_type (crc->i),
                          get_priority (crc->i), get_anonymity (crc->i), 0,
                          get_expiration (crc->i), 1, 1, TIMEOUT,
                          &check_success, crc);
    crc->i++;
    if (crc->i == ITERATIONS)
      crc->phase = RP_GET;
    break;
  case RP_GET:
    crc->i--;
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Executing `%s' number %u\n", "GET",
                crc->i);
#endif
    GNUNET_CRYPTO_hash (&crc->i, sizeof (int), &crc->key);
    GNUNET_DATASTORE_get_key (datastore, crc->offset, &crc->key,
                              get_type (crc->i), 1, 1, TIMEOUT, &check_value,
                              crc);
    break;
  case RP_DEL:
    crc->i--;
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Executing `%s' number %u\n", "DEL",
                crc->i);
#endif
    crc->data = NULL;
    GNUNET_CRYPTO_hash (&crc->i, sizeof (int), &crc->key);
    GNUNET_assert (NULL !=
                   GNUNET_DATASTORE_get_key (datastore, crc->offset, &crc->key,
                                             get_type (crc->i), 1, 1, TIMEOUT,
                                             &delete_value, crc));
    break;
  case RP_DO_DEL:
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Executing `%s' number %u\n", "DO_DEL",
                crc->i);
#endif
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
                                            crc->data, 1, 1, TIMEOUT,
                                            &check_success, crc));
    break;
  case RP_DELVALIDATE:
    crc->i--;
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Executing `%s' number %u\n",
                "DEL-VALIDATE", crc->i);
#endif
    GNUNET_CRYPTO_hash (&crc->i, sizeof (int), &crc->key);
    GNUNET_assert (NULL !=
                   GNUNET_DATASTORE_get_key (datastore, crc->offset, &crc->key,
                                             get_type (crc->i), 1, 1, TIMEOUT,
                                             &check_nothing, crc));
    break;
  case RP_RESERVE:
    crc->phase = RP_PUT_MULTIPLE;
    GNUNET_DATASTORE_reserve (datastore, 128 * 1024, 2, 1, 1, TIMEOUT,
                              &get_reserved, crc);
    break;
  case RP_PUT_MULTIPLE:
    crc->phase = RP_PUT_MULTIPLE_NEXT;
    GNUNET_DATASTORE_put (datastore, crc->rid, &crc->key, get_size (42),
                          get_data (42), get_type (42), get_priority (42),
                          get_anonymity (42), 0, get_expiration (42), 1, 1,
                          TIMEOUT, &check_success, crc);
    break;
  case RP_PUT_MULTIPLE_NEXT:
    crc->phase = RP_GET_MULTIPLE;
    GNUNET_DATASTORE_put (datastore, crc->rid, &crc->key, get_size (43),
                          get_data (43), get_type (42), get_priority (43),
                          get_anonymity (43), 0, get_expiration (43), 1, 1,
                          TIMEOUT, &check_success, crc);
    break;
  case RP_GET_MULTIPLE:
    GNUNET_assert (NULL !=
                   GNUNET_DATASTORE_get_key (datastore, crc->offset, &crc->key,
                                             get_type (42), 1, 1, TIMEOUT,
                                             &check_multiple, crc));
    break;
  case RP_GET_MULTIPLE_NEXT:
    GNUNET_assert (NULL !=
                   GNUNET_DATASTORE_get_key (datastore, crc->offset, &crc->key,
                                             get_type (42), 1, 1, TIMEOUT,
                                             &check_multiple, crc));
    break;
  case RP_UPDATE:
    GNUNET_assert (crc->uid > 0);
    crc->phase = RP_UPDATE_VALIDATE;
    GNUNET_DATASTORE_update (datastore, crc->uid, 100, get_expiration (42), 1,
                             1, TIMEOUT, &check_success, crc);
    break;
  case RP_UPDATE_VALIDATE:
    GNUNET_assert (NULL !=
                   GNUNET_DATASTORE_get_key (datastore, crc->offset, &crc->key,
                                             get_type (42), 1, 1, TIMEOUT,
                                             &check_update, crc));
    break;
  case RP_DONE:
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Finished, disconnecting\n");
#endif
    GNUNET_DATASTORE_disconnect (datastore, GNUNET_YES);
    GNUNET_free (crc);
    ok = 0;
    break;
  case RP_ERROR:
    GNUNET_DATASTORE_disconnect (datastore, GNUNET_YES);
    GNUNET_free (crc);
    ok = 43;
    break;
  }
}


static void
run_tests (void *cls, int32_t success, struct GNUNET_TIME_Absolute min_expiration, const char *msg)
{
  struct CpsRunContext *crc = cls;

  switch (success)
  {
  case GNUNET_YES:
    GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    return;
  case GNUNET_NO:
    FPRINTF (stderr, "%s", "Test 'put' operation failed, key already exists (!?)\n");
    GNUNET_free (crc);
    return;
  case GNUNET_SYSERR:
    FPRINTF (stderr,
             "Test 'put' operation failed with error `%s' database likely not setup, skipping test.\n",
             msg);
    GNUNET_free (crc);
    return;
  default:
    GNUNET_assert (0);
  }
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct CpsRunContext *crc;
  static GNUNET_HashCode zkey;

  crc = GNUNET_malloc (sizeof (struct CpsRunContext));
  crc->cfg = cfg;
  crc->phase = RP_PUT;
  now = GNUNET_TIME_absolute_get ();
  datastore = GNUNET_DATASTORE_connect (cfg);
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
  char cfg_name[128];

#if START_DATASTORE
  struct GNUNET_OS_Process *proc;
#endif
  char *const argv[] = {
    "test-datastore-api",
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
#if START_DATASTORE
  proc =
    GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm",
#if VERBOSE
                               "-L", "DEBUG",
#endif
                               "-c", cfg_name, NULL);
#endif
  GNUNET_assert (NULL != proc);
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "test-datastore-api", "nohelp", options, &run, NULL);
#if START_DATASTORE
  sleep (1);                    /* give datastore chance to receive 'DROP' request */
  if (0 != GNUNET_OS_process_kill (proc, SIGTERM))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    ok = 1;
  }
  GNUNET_OS_process_wait (proc);
  GNUNET_OS_process_close (proc);
  proc = NULL;
#endif
  if (ok != 0)
    FPRINTF (stderr, "Missed some testcases: %u\n", ok);
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
  GNUNET_log_setup ("test-datastore-api",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  if (pos != plugin_name)
    pos[0] = '.';
  GNUNET_DISK_directory_remove (dir_name);
  return ret;
}

/* end of test_datastore_api.c */
