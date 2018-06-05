/*
     This file is part of GNUnet.
     Copyright (C) 2013-2016 GNUnet e.V.

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
 * @file peerstore/test_peerstore_api_watch.c
 * @brief testcase for peerstore watch functionality
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_peerstore_service.h"


static int ok = 1;

static struct GNUNET_PEERSTORE_Handle *h;

static char *ss = "test_peerstore_api_watch";

static char *k = "test_peerstore_api_watch_key";

static char *val = "test_peerstore_api_watch_val";


static void
watch_cb (void *cls,
          const struct GNUNET_PEERSTORE_Record *record,
          const char *emsg)
{
  GNUNET_assert (NULL == emsg);
  GNUNET_assert (0 == strcmp (val,
                              (char *) record->value));
  ok = 0;
  GNUNET_PEERSTORE_disconnect (h,
                               GNUNET_NO);
  GNUNET_SCHEDULER_shutdown ();
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_PeerIdentity p;

  h = GNUNET_PEERSTORE_connect (cfg);
  GNUNET_assert (NULL != h);
  memset (&p,
          4,
          sizeof (p));
  GNUNET_PEERSTORE_watch (h,
                          ss,
                          &p,
                          k,
                          &watch_cb,
                          NULL);
  GNUNET_PEERSTORE_store (h,
                          ss,
                          &p,
                          k,
                          val,
                          strlen (val) + 1,
                          GNUNET_TIME_UNIT_FOREVER_ABS,
                          GNUNET_PEERSTORE_STOREOPTION_REPLACE,
                          NULL,
                          NULL);
}


int
main (int argc,
      char *argv[])
{
  if (0 !=
      GNUNET_TESTING_service_run ("test-gnunet-peerstore",
                                  "peerstore",
                                  "test_peerstore_api_data.conf",
                                  &run,
                                  NULL))
    return 1;
  return ok;
}

/* end of test_peerstore_api_watch.c */
