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
 * @file peerstore/test_peerstore_api_iterate.c
 * @brief testcase for peerstore iteration operation
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_peerstore_service.h"

static int ok = 1;

static struct GNUNET_PEERSTORE_Handle *h;

static char *ss = "test_peerstore_api_iterate";
static struct GNUNET_PeerIdentity p1;
static struct GNUNET_PeerIdentity p2;
static char *k1 = "test_peerstore_api_iterate_key1";
static char *k2 = "test_peerstore_api_iterate_key2";
static char *k3 = "test_peerstore_api_iterate_key3";
static char *val = "test_peerstore_api_iterate_val";
static int count = 0;

static int
iter3_cb (void *cls, struct GNUNET_PEERSTORE_Record *record, char *emsg)
{
  if (NULL != emsg)
    return GNUNET_NO;
  if (NULL != record)
  {
    count++;
    return GNUNET_YES;
  }
  GNUNET_assert (count == 3);
  ok = 0;
  GNUNET_PEERSTORE_disconnect (h, GNUNET_NO);
  GNUNET_SCHEDULER_shutdown ();
  return GNUNET_YES;
}


static int
iter2_cb (void *cls, struct GNUNET_PEERSTORE_Record *record, char *emsg)
{
  if (NULL != emsg)
    return GNUNET_NO;
  if (NULL != record)
  {
    count++;
    return GNUNET_YES;
  }
  GNUNET_assert (count == 2);
  count = 0;
  GNUNET_PEERSTORE_iterate (h, ss, NULL, NULL, GNUNET_TIME_UNIT_FOREVER_REL,
                            iter3_cb, NULL);
  return GNUNET_YES;
}


static int
iter1_cb (void *cls, struct GNUNET_PEERSTORE_Record *record, char *emsg)
{
  if (NULL != emsg)
    return GNUNET_NO;
  if (NULL != record)
  {
    count++;
    return GNUNET_YES;
  }
  GNUNET_assert (count == 1);
  count = 0;
  GNUNET_PEERSTORE_iterate (h, ss, &p1, NULL, GNUNET_TIME_UNIT_FOREVER_REL,
                            iter2_cb, NULL);
  return GNUNET_YES;
}


static void
run (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  h = GNUNET_PEERSTORE_connect (cfg);
  GNUNET_assert (NULL != h);
  memset (&p1, 1, sizeof (p1));
  memset (&p2, 2, sizeof (p2));
  GNUNET_PEERSTORE_store (h, ss, &p1, k1, val, strlen (val) + 1,
                          GNUNET_TIME_UNIT_FOREVER_ABS,
                          GNUNET_PEERSTORE_STOREOPTION_REPLACE, NULL, NULL);
  GNUNET_PEERSTORE_store (h, ss, &p1, k2, val, strlen (val) + 1,
                          GNUNET_TIME_UNIT_FOREVER_ABS,
                          GNUNET_PEERSTORE_STOREOPTION_REPLACE, NULL, NULL);
  GNUNET_PEERSTORE_store (h, ss, &p2, k3, val, strlen (val) + 1,
                          GNUNET_TIME_UNIT_FOREVER_ABS,
                          GNUNET_PEERSTORE_STOREOPTION_REPLACE, NULL, NULL);
  GNUNET_PEERSTORE_iterate (h, ss, &p1, k1, GNUNET_TIME_UNIT_FOREVER_REL,
                            iter1_cb, NULL);
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

/* end of test_peerstore_api_iterate.c */
