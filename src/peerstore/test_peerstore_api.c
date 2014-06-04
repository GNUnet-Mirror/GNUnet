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
 * @file peerstore/test_peerstore_api.c
 * @brief testcase for peerstore_api.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_peerstore_service.h"
#include <inttypes.h>

//TODO: test single cycle of watch, store, iterate

static int ok = 1;

static int counter = 0;

struct GNUNET_PEERSTORE_Handle *h;

int iterate_cb (void *cls,
    struct GNUNET_PEERSTORE_Record *record,
    char *emsg)
{
  if(NULL != emsg)
  {
    printf("Error received: %s.\n", emsg);
    return GNUNET_YES;
  }
  printf("Record:\n");
  if(NULL == record)
  {
    GNUNET_assert(counter > 0);
    counter = 0;
    printf("END\n");
    GNUNET_PEERSTORE_disconnect(h);
    return GNUNET_YES;
  }
  printf("Sub system: %s\n", record->sub_system);
  printf("Peer: %s\n", GNUNET_i2s (record->peer));
  printf("Key: %s\n", record->key);
  printf("Value: %.*s\n", (int)record->value_size, (char *)record->value);
  printf("Expiry: %" PRIu64 "\n", record->expiry->abs_value_us);
  counter ++;

  return GNUNET_YES;
}

void store_cont(void *cls, int success)
{
  if(GNUNET_OK == success)
    ok = 0;
  else
    ok = 1;
  printf("Store success: %d\n", success);
  GNUNET_PEERSTORE_iterate(h, "peerstore-test",
      NULL,
      NULL,
      GNUNET_TIME_UNIT_FOREVER_REL,
      &iterate_cb,
      NULL);
}

int watch_cb (void *cls,
    struct GNUNET_PEERSTORE_Record *record,
    char *emsg)
{
  if(NULL != emsg)
  {
    printf("Error received: %s.\n", emsg);
    return GNUNET_YES;
  }

  printf("Watch Record:\n");
  printf("Sub system: %s\n", record->sub_system);
  printf("Peer: %s\n", GNUNET_i2s (record->peer));
  printf("Key: %s\n", record->key);
  printf("Value: %.*s\n", (int)record->value_size, (char *)record->value);
  printf("Expiry: %" PRIu64 "\n", record->expiry->abs_value_us);
  return GNUNET_YES;
}

static void
run (void *cls,
    const struct GNUNET_CONFIGURATION_Handle *cfg,
    struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_PeerIdentity pid;
  char *val = "peerstore-test-value";
  size_t val_size = strlen(val);
  struct GNUNET_TIME_Absolute expiry;

  ok = 1;
  memset (&pid, 32, sizeof (pid));
  expiry = GNUNET_TIME_absolute_get();
  h = GNUNET_PEERSTORE_connect(cfg);
  GNUNET_assert(NULL != h);
  GNUNET_PEERSTORE_watch(h,
      "peerstore-test",
      &pid,
      "peerstore-test-key",
      &watch_cb,
      NULL);
  GNUNET_PEERSTORE_store(h,
      "peerstore-test",
      &pid,
      "peerstore-test-key",
      val,
      val_size,
      expiry,
      GNUNET_PEERSTORE_STOREOPTION_MULTIPLE,
      &store_cont,
      NULL);
}

int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_service_run ("test-gnunet-peerstore",
                 "peerstore",
                 "test_peerstore_api_data.conf",
                 &run, NULL))
    return 1;
  return ok;
}

/* end of test_peerstore_api.c */
