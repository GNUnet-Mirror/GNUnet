/*
     This file is part of GNUnet.
     (C)

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
/**
 * @file peerstore/test_peerstore_api_sync.c
 * @brief testcase for peerstore sync before disconnect feature
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_peerstore_service.h"

int ok = 1;

const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_PEERSTORE_Handle *h;

static char *subsystem = "test_peerstore_api_sync";
static struct GNUNET_PeerIdentity pid;
static char *key = "test_peerstore_api_store_key";
static char *val = "test_peerstore_api_store_val";

int
iterate_cb (void *cls, struct GNUNET_PEERSTORE_Record *record, char *emsg)
{
  const char *rec_val;

  GNUNET_break (NULL == emsg);
  if (NULL == record)
  {
    GNUNET_PEERSTORE_disconnect (h, GNUNET_NO);
    GNUNET_SCHEDULER_shutdown ();
    return GNUNET_YES;
  }
  rec_val = record->value;
  GNUNET_break (0 == strcmp (rec_val, val));
  ok = 0;
  return GNUNET_YES;
}


static void
test1 ()
{
  GNUNET_PEERSTORE_store (h, subsystem, &pid, key, val, strlen (val) + 1,
                          GNUNET_TIME_UNIT_FOREVER_ABS,
                          GNUNET_PEERSTORE_STOREOPTION_REPLACE, NULL, NULL);
  GNUNET_PEERSTORE_disconnect (h, GNUNET_YES);
  h = GNUNET_PEERSTORE_connect (cfg);
  GNUNET_PEERSTORE_iterate (h, subsystem, &pid, key,
                            GNUNET_TIME_UNIT_FOREVER_REL, &iterate_cb, NULL);
}


static void
run (void *cls, const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_TESTING_Peer *peer)
{
  cfg = c;
  h = GNUNET_PEERSTORE_connect (cfg);
  GNUNET_assert (NULL != h);
  memset (&pid, 1, sizeof (pid));
  test1 ();
}


int
main (int argc, char *argv[])
{
  if (0 !=
      GNUNET_TESTING_service_run ("test-gnunet-peerstore", "peerstore",
                                  "test_peerstore_api_data.conf", &run, NULL))
    return 1;
  return ok;
}

/* end of test_peerstore_api_store.c */
