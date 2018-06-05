/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2018 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/
/**
 * @file namestore/perf_namestore_api_zone_iteration.c
 * @brief testcase for zone iteration functionality: iterate all zones
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"
#include "namestore.h"
#include "gnunet_dnsparser_lib.h"

#define TEST_RECORD_TYPE GNUNET_DNSPARSER_TYPE_TXT

/**
 * A #BENCHMARK_SIZE of 1000 takes less than a minute on a reasonably
 * modern system, so 30 minutes should be OK even for very, very
 * slow systems.
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 30)

/**
 * The runtime of the benchmark is expected to be linear
 * for the iteration phase with a *good* database.  The FLAT
 * database uses a quadratic retrieval algorithm,
 * hence it should be quadratic in the size.
 */
#define BENCHMARK_SIZE 1000

/**
 * Maximum record size
 */
#define MAX_REC_SIZE 500

/**
 * How big are the blocks we fetch? Note that the first block is
 * always just 1 record set per current API.  Smaller block
 * sizes will make quadratic iteration-by-offset penalties
 * more pronounced.
 */
#define BLOCK_SIZE 100

static struct GNUNET_NAMESTORE_Handle *nsh;

static struct GNUNET_SCHEDULER_Task *timeout_task;

static struct GNUNET_SCHEDULER_Task *t;

static struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey;

static struct GNUNET_NAMESTORE_ZoneIterator *zi;

static struct GNUNET_NAMESTORE_QueueEntry *qe;

static int res;

static unsigned int off;

static unsigned int left_until_next;

static uint8_t seen[1 + BENCHMARK_SIZE / 8];

static struct GNUNET_TIME_Absolute start;


/**
 * Terminate everything
 *
 * @param cls NULL
 */
static void
end (void *cls)
{
  (void) cls;
  if (NULL != qe)
  {
    GNUNET_NAMESTORE_cancel (qe);
    qe = NULL;
  }
  if (NULL != zi)
  {
    GNUNET_NAMESTORE_zone_iteration_stop (zi);
    zi = NULL;
  }
  if (NULL != nsh)
  {
    GNUNET_NAMESTORE_disconnect (nsh);
    nsh = NULL;
  }
  if (NULL != t)
  {
    GNUNET_SCHEDULER_cancel (t);
    t = NULL;
  }
  if (NULL != timeout_task)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
  }
  if (NULL != privkey)
  {
    GNUNET_free (privkey);
    privkey = NULL;
  }
}


/**
 * End with timeout. As this is a benchmark, we do not
 * fail hard but return "skipped".
 */
static void
timeout (void *cls)
{
  (void) cls;
  timeout_task = NULL;
  GNUNET_SCHEDULER_shutdown ();
  res = 77;
}


static struct GNUNET_GNSRECORD_Data *
create_record (unsigned int count)
{
  struct GNUNET_GNSRECORD_Data *rd;

  rd = GNUNET_malloc (count + sizeof (struct GNUNET_GNSRECORD_Data));
  rd->expiration_time = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_HOURS).abs_value_us;
  rd->record_type = TEST_RECORD_TYPE;
  rd->data_size = count;
  rd->data = (void *) &rd[1];
  rd->flags = 0;
  memset (&rd[1],
          'a',
          count);
  return rd;
}


static void
zone_end (void *cls)
{
  struct GNUNET_TIME_Relative delay;

  zi = NULL;
  delay = GNUNET_TIME_absolute_get_duration (start);
  fprintf (stdout,
           "Iterating over %u records took %s\n",
           off,
           GNUNET_STRINGS_relative_time_to_string (delay,
                                                   GNUNET_YES));
  if (BENCHMARK_SIZE == off)
  {
    res = 0;
  }
  else
  {
    GNUNET_break (0);
    res = 1;
  }
  GNUNET_SCHEDULER_shutdown ();
}


static void
fail_cb (void *cls)
{
  zi = NULL;
  res = 2;
  GNUNET_break (0);
  GNUNET_SCHEDULER_shutdown ();
}


static void
zone_proc (void *cls,
           const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
           const char *label,
           unsigned int rd_count,
           const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Data *wrd;
  unsigned int xoff;

  GNUNET_assert (NULL != zone);
  if (1 != sscanf (label,
                   "l%u",
                   &xoff))
  {
    res = 3;
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if ( (xoff > BENCHMARK_SIZE) ||
       (0 != (seen[xoff / 8] & (1U << (xoff % 8)))) )
  {
    res = 3;
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  seen[xoff / 8] |= (1U << (xoff % 8));
  wrd = create_record (xoff % MAX_REC_SIZE);
  if ( (rd->record_type != wrd->record_type) ||
       (rd->data_size != wrd->data_size) ||
       (rd->flags != wrd->flags) )
  {
    res = 4;
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (wrd);
    return;
  }
  if (0 != memcmp (rd->data,
                   wrd->data,
                   wrd->data_size))
  {
    res = 4;
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (wrd);
    return;
  }
  GNUNET_free (wrd);
  if (0 != memcmp (zone,
                   privkey,
                   sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey)))
  {
    res = 5;
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  off++;
  left_until_next--;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Obtained record %u, expecting %u more until asking for mor explicitly\n",
              off,
              left_until_next);
  if (0 == left_until_next)
  {
    left_until_next = BLOCK_SIZE;
    GNUNET_NAMESTORE_zone_iterator_next (zi,
                                         left_until_next);
  }
}


static void
publish_record (void *cls);


static void
put_cont (void *cls,
          int32_t success,
          const char *emsg)
{
  (void) cls;
  qe = NULL;
  GNUNET_assert (GNUNET_OK == success);
  t = GNUNET_SCHEDULER_add_now (&publish_record,
                                NULL);
}


static void
publish_record (void *cls)
{
  struct GNUNET_GNSRECORD_Data *rd;
  char *label;

  (void) cls;
  t = NULL;
  if (BENCHMARK_SIZE == off)
  {
    struct GNUNET_TIME_Relative delay;

    delay = GNUNET_TIME_absolute_get_duration (start);
    fprintf (stdout,
             "Inserting %u records took %s\n",
             off,
             GNUNET_STRINGS_relative_time_to_string (delay,
                                                     GNUNET_YES));
    start = GNUNET_TIME_absolute_get ();
    off = 0;
    left_until_next = 1;
    zi = GNUNET_NAMESTORE_zone_iteration_start (nsh,
                                                NULL,
                                                &fail_cb,
                                                NULL,
                                                &zone_proc,
                                                NULL,
                                                &zone_end,
                                                NULL);
    GNUNET_assert (NULL != zi);
    return;
  }
  rd = create_record ((++off) % MAX_REC_SIZE);
  GNUNET_asprintf (&label,
                   "l%u",
                   off);
  qe = GNUNET_NAMESTORE_records_store (nsh,
                                       privkey,
                                       label,
                                       1, rd,
                                       &put_cont,
                                       NULL);
  GNUNET_free (label);
  GNUNET_free (rd);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  GNUNET_SCHEDULER_add_shutdown (&end,
                                 NULL);
  timeout_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                               &timeout,
                                               NULL);
  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_assert (NULL != nsh);
  privkey = GNUNET_CRYPTO_ecdsa_key_create ();
  GNUNET_assert (NULL != privkey);
  start = GNUNET_TIME_absolute_get ();
  t = GNUNET_SCHEDULER_add_now (&publish_record,
                                NULL);
}


int
main (int argc,
      char *argv[])
{
  const char *plugin_name;
  char *cfg_name;

  plugin_name = GNUNET_TESTING_get_testname_from_underscore (argv[0]);
  GNUNET_asprintf (&cfg_name,
                   "perf_namestore_api_%s.conf",
                   plugin_name);
  res = 1;
  GNUNET_DISK_purge_cfg_dir (cfg_name,
                             "GNUNET_TEST_HOME");
  if (0 !=
      GNUNET_TESTING_peer_run ("perf-namestore-api-zone-iteration",
                               cfg_name,
                               &run,
                               NULL))
  {
    res = 1;
  }
  GNUNET_DISK_purge_cfg_dir (cfg_name,
                             "GNUNET_TEST_HOME");
  GNUNET_free (cfg_name);
  return res;
}


/* end of perf_namestore_api_zone_iteration.c */
