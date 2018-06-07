/*
     This file is part of GNUnet.
     Copyright (C)

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/
/**
 * @file peerstore/perf_peerstore_store.c
 * @brief performance test for peerstore store operation
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_peerstore_service.h"

#define STORES 10000

static int ok = 1;

static struct GNUNET_PEERSTORE_Handle *h;

static char *ss = "test_peerstore_stress";
static struct GNUNET_PeerIdentity p;
static char *k = "test_peerstore_stress_key";
static char *v = "test_peerstore_stress_val";

static int count = 0;

static void
disconnect ()
{
  if (NULL != h)
    GNUNET_PEERSTORE_disconnect (h, GNUNET_YES);
  GNUNET_SCHEDULER_shutdown ();
}


static void
store ()
{
  GNUNET_PEERSTORE_store (h, ss, &p, k, v, strlen (v) + 1,
                          GNUNET_TIME_UNIT_FOREVER_ABS,
                          (count ==
                           0) ? GNUNET_PEERSTORE_STOREOPTION_REPLACE :
                          GNUNET_PEERSTORE_STOREOPTION_MULTIPLE, NULL, NULL);
  count++;
}


static void
watch_cb (void *cls, const struct GNUNET_PEERSTORE_Record *record,
          const char *emsg)
{
  GNUNET_assert (NULL == emsg);
  if (STORES == count)
  {
    ok = 0;
    disconnect ();
  }
  else
    store ();
}


static void
run (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  memset (&p, 5, sizeof (p));
  h = GNUNET_PEERSTORE_connect (cfg);
  GNUNET_assert (NULL != h);
  GNUNET_PEERSTORE_watch (h, ss, &p, k, &watch_cb, NULL);
  store ();
}


int
main (int argc, char *argv[])
{
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_TIME_Relative diff;

  start = GNUNET_TIME_absolute_get ();
  if (0 !=
      GNUNET_TESTING_service_run ("perf-peerstore-store", "peerstore",
                                  "test_peerstore_api_data.conf", &run, NULL))
    return 1;
  diff = GNUNET_TIME_absolute_get_duration (start);
  fprintf (stderr, "Stored and retrieved %d records in %s (%s).\n", STORES,
           GNUNET_STRINGS_relative_time_to_string (diff, GNUNET_YES),
           GNUNET_STRINGS_relative_time_to_string (diff, GNUNET_NO));
  return ok;
}

/* end of perf_peerstore_store.c */
