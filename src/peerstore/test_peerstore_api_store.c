/*
     This file is part of GNUnet.
     Copyright (C) GNUnet e.V.

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
/**
 * @file peerstore/test_peerstore_api_store.c
 * @brief testcase for peerstore store operation
 */
#include "platform.h"
#include "gnunet_peerstore_service.h"
#include "gnunet_testing_lib.h"


static int ok = 1;

static struct GNUNET_PEERSTORE_Handle *h;

static char *subsystem = "test_peerstore_api_store";
static struct GNUNET_PeerIdentity pid;
static char *key = "test_peerstore_api_store_key";
static char *val1 = "test_peerstore_api_store_val1";
static char *val2 = "test_peerstore_api_store_val2-";
static char *val3 = "test_peerstore_api_store_val3--";

static int count = 0;


static void
test3_cont2(void *cls,
            const struct GNUNET_PEERSTORE_Record *record,
            const char *emsg)
{
  if (NULL != emsg)
    return;
  if (NULL != record)
    {
      GNUNET_assert((strlen(val3) + 1) == record->value_size);
      GNUNET_assert(0 == strcmp((char *)val3,
                                (char *)record->value));
      count++;
      return;
    }
  GNUNET_assert(count == 1);
  ok = 0;
  GNUNET_PEERSTORE_disconnect(h, GNUNET_YES);
  GNUNET_SCHEDULER_shutdown();
}


static void
test3_cont(void *cls,
           int success)
{
  if (GNUNET_YES != success)
    return;
  count = 0;
  GNUNET_PEERSTORE_iterate(h,
                           subsystem,
                           &pid,
                           key,
                           &test3_cont2,
                           NULL);
}


/**
 * Replace the previous 2 records
 */
static void
test3()
{
  GNUNET_PEERSTORE_store(h,
                         subsystem,
                         &pid,
                         key,
                         val3,
                         strlen(val3) + 1,
                         GNUNET_TIME_UNIT_FOREVER_ABS,
                         GNUNET_PEERSTORE_STOREOPTION_REPLACE,
                         &test3_cont,
                         NULL);
}


static void
test2_cont2(void *cls,
            const struct GNUNET_PEERSTORE_Record *record,
            const char *emsg)
{
  if (NULL != emsg)
    return;
  if (NULL != record)
    {
      GNUNET_assert(((strlen(val1) + 1) == record->value_size) ||
                    ((strlen(val2) + 1) == record->value_size));
      GNUNET_assert((0 == strcmp((char *)val1, (char *)record->value)) ||
                    (0 == strcmp((char *)val2, (char *)record->value)));
      count++;
      return;
    }
  GNUNET_assert(count == 2);
  count = 0;
  test3();
}


static void
test2_cont(void *cls, int success)
{
  if (GNUNET_YES != success)
    return;
  count = 0;
  GNUNET_PEERSTORE_iterate(h,
                           subsystem,
                           &pid, key,
                           &test2_cont2,
                           NULL);
}


/**
 * Test storing a second value with the same key
 */
void
test2()
{
  GNUNET_PEERSTORE_store(h,
                         subsystem,
                         &pid,
                         key,
                         val2,
                         strlen(val2) + 1,
                         GNUNET_TIME_UNIT_FOREVER_ABS,
                         GNUNET_PEERSTORE_STOREOPTION_MULTIPLE,
                         &test2_cont,
                         NULL);
}


static void
test1_cont2(void *cls,
            const struct GNUNET_PEERSTORE_Record *record,
            const char *emsg)
{
  if (NULL != emsg)
    return;
  if (NULL != record)
    {
      GNUNET_assert((strlen(val1) + 1) == record->value_size);
      GNUNET_assert(0 == strcmp((char *)val1, (char *)record->value));
      count++;
      return;
    }
  GNUNET_assert(count == 1);
  count = 0;
  test2();
}


static void
test1_cont(void *cls, int success)
{
  if (GNUNET_YES != success)
    return;
  count = 0;
  GNUNET_PEERSTORE_iterate(h,
                           subsystem,
                           &pid,
                           key,
                           &test1_cont2,
                           NULL);
}


/**
 * Store a single record
 */
static void
test1()
{
  GNUNET_PEERSTORE_store(h,
                         subsystem,
                         &pid,
                         key,
                         val1,
                         strlen(val1) + 1,
                         GNUNET_TIME_UNIT_FOREVER_ABS,
                         GNUNET_PEERSTORE_STOREOPTION_REPLACE,
                         &test1_cont,
                         NULL);
}


static void
run(void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
    struct GNUNET_TESTING_Peer *peer)
{
  h = GNUNET_PEERSTORE_connect(cfg);
  GNUNET_assert(NULL != h);
  memset(&pid, 1, sizeof(pid));
  test1();
}


int
main(int argc, char *argv[])
{
  if (0 !=
      GNUNET_TESTING_service_run("test-gnunet-peerstore",
                                 "peerstore",
                                 "test_peerstore_api_data.conf",
                                 &run, NULL))
    return 1;
  return ok;
}

/* end of test_peerstore_api_store.c */
