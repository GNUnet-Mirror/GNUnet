/*
     This file is part of GNUnet.
     Copyright (C) 2004, 2005, 2006, 2007, 2009, 2011 Christian Grothoff (and other contributing authors)

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
 * @file datastore/test_datastore_api_management.c
 * @brief Test for the space management functions of the datastore implementation.
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_datastore_service.h"
#include "gnunet_testing_lib.h"


/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/**
 * Number of iterations to run; must be large enough
 * so that the quota will be exceeded!
 */
#define ITERATIONS 5000

enum RunPhase
{
  RP_PUT,
  RP_GET,
  RP_DONE,
  RP_GET_FAIL
};


struct CpsRunContext
{
  struct GNUNET_HashCode key;
  int i;
  int found;
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  void *data;
  enum RunPhase phase;
  uint64_t offset;
};


static struct GNUNET_DATASTORE_Handle *datastore;

static struct GNUNET_TIME_Absolute now;

static int ok;

static const char *plugin_name;


static size_t
get_size (int i)
{
  return 8 + 8 * (i % 256);
}


static const void *
get_data (int i)
{
  static char buf[60000];

  memset (buf, i, 8 + 8 * (i % 256));
  return buf;
}


static int
get_type (int i)
{
  return 1;
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

  av.abs_value_us = now.abs_value_us + i * 1000 * 1000LL;
  return av;
}


static void
run_continuation (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
check_success (void *cls, int success, struct GNUNET_TIME_Absolute min_expiration, const char *msg)
{
  struct CpsRunContext *crc = cls;

  if (GNUNET_OK != success)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n", msg);
  GNUNET_assert (GNUNET_OK == success);
  GNUNET_free_non_null (crc->data);
  crc->data = NULL;
  GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static void
check_value (void *cls, const struct GNUNET_HashCode * key, size_t size,
             const void *data, enum GNUNET_BLOCK_Type type, uint32_t priority,
             uint32_t anonymity, struct GNUNET_TIME_Absolute expiration,
             uint64_t uid)
{
  struct CpsRunContext *crc = cls;
  int i;

  if (NULL == key)
  {
    crc->phase = RP_GET_FAIL;
    GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    return;
  }
  i = crc->i;
  GNUNET_assert (size == get_size (i));
  GNUNET_assert (0 == memcmp (data, get_data (i), size));
  GNUNET_assert (type == get_type (i));
  GNUNET_assert (priority == get_priority (i));
  GNUNET_assert (anonymity == get_anonymity (i));
  GNUNET_assert (expiration.abs_value_us == get_expiration (i).abs_value_us);
  crc->offset++;
  crc->i--;
  if (crc->i == 0)
    crc->phase = RP_DONE;
  GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static void
check_nothing (void *cls, const struct GNUNET_HashCode * key, size_t size,
               const void *data, enum GNUNET_BLOCK_Type type, uint32_t priority,
               uint32_t anonymity, struct GNUNET_TIME_Absolute expiration,
               uint64_t uid)
{
  struct CpsRunContext *crc = cls;

  GNUNET_assert (key == NULL);
  if (0 == --crc->i)
    crc->phase = RP_DONE;
  GNUNET_SCHEDULER_add_continuation (&run_continuation, crc,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static void
run_continuation (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CpsRunContext *crc = cls;

  ok = (int) crc->phase;
  switch (crc->phase)
  {
  case RP_PUT:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Executing `%s' number %u\n", "PUT",
                crc->i);
    GNUNET_CRYPTO_hash (&crc->i, sizeof (int), &crc->key);
    GNUNET_DATASTORE_put (datastore, 0, &crc->key, get_size (crc->i),
                          get_data (crc->i), get_type (crc->i),
                          get_priority (crc->i), get_anonymity (crc->i), 0,
                          get_expiration (crc->i), 1, 1, TIMEOUT,
                          &check_success, crc);
    crc->i++;
    if (crc->i == ITERATIONS)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Sleeping to give datastore time to clean up\n");
      sleep (1);
      crc->phase = RP_GET;
      crc->i--;
    }
    break;
  case RP_GET:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Executing `%s' number %u\n", "GET",
                crc->i);
    GNUNET_CRYPTO_hash (&crc->i, sizeof (int), &crc->key);
    GNUNET_DATASTORE_get_key (datastore, crc->offset++, &crc->key,
                              get_type (crc->i), 1, 1, TIMEOUT, &check_value,
                              crc);
    break;
  case RP_GET_FAIL:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Executing `%s' number %u\n", "GET(f)",
                crc->i);
    GNUNET_CRYPTO_hash (&crc->i, sizeof (int), &crc->key);
    GNUNET_DATASTORE_get_key (datastore, crc->offset++, &crc->key,
                              get_type (crc->i), 1, 1, TIMEOUT, &check_nothing,
                              crc);
    break;
  case RP_DONE:
    GNUNET_assert (0 == crc->i);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Finished, disconnecting\n");
    GNUNET_DATASTORE_disconnect (datastore, GNUNET_YES);
    GNUNET_free (crc);
    ok = 0;
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
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct CpsRunContext *crc;
  static struct GNUNET_HashCode zkey;

  crc = GNUNET_new (struct CpsRunContext);
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
    GNUNET_free (crc);
    ok = 1;
  }
}


int
main (int argc, char *argv[])
{
  char cfg_name[128];

  plugin_name = GNUNET_TESTING_get_testname_from_underscore (argv[0]);
  GNUNET_snprintf (cfg_name, sizeof (cfg_name),
                   "test_datastore_api_data_%s.conf", plugin_name);
  if (0 !=
      GNUNET_TESTING_peer_run ("test-gnunet-datastore-management",
			       cfg_name,
			       &run,
			       NULL))
    return 1;
  return ok;
}

/* end of test_datastore_api_management.c */
