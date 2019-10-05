/*
     This file is part of GNUnet.
     Copyright (C) 2012 GNUnet e.V.

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
 * @file namestore/test_namestore_api_store.c
 * @brief testcase for namestore_api.c: store a record
 */
#include "platform.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"
#include "gnunet_dnsparser_lib.h"

#define TEST_RECORD_TYPE GNUNET_DNSPARSER_TYPE_TXT

#define TEST_RECORD_DATALEN 123

#define TEST_RECORD_DATA 'a'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)


static struct GNUNET_NAMESTORE_Handle *nsh;

static struct GNUNET_SCHEDULER_Task *endbadly_task;

static struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey;

static struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;

static int res;

static struct GNUNET_NAMESTORE_QueueEntry *nsqe;


static void
cleanup ()
{
  if (NULL != nsh)
  {
    GNUNET_NAMESTORE_disconnect (nsh);
    nsh = NULL;
  }
  if (NULL != privkey)
  {
    GNUNET_free (privkey);
    privkey = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Re-establish the connection to the service.
 *
 * @param cls handle to use to re-connect.
 */
static void
endbadly (void *cls)
{
  if (NULL != nsqe)
  {
    GNUNET_NAMESTORE_cancel (nsqe);
    nsqe = NULL;
  }
  cleanup ();
  res = 1;
}


static void
end (void *cls)
{
  cleanup ();
  res = 0;
}


static void
put_cont (void *cls, int32_t success, const char *emsg)
{
  const char *name = cls;

  nsqe = NULL;
  GNUNET_assert (NULL != cls);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Name store added record for `%s': %s\n",
              name,
              (success == GNUNET_OK) ? "SUCCESS" : "FAIL");
  GNUNET_SCHEDULER_cancel (endbadly_task);
  endbadly_task = NULL;
  GNUNET_SCHEDULER_add_now (&end, NULL);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_GNSRECORD_Data rd;
  const char *name = "dummy.dummy.gnunet";

  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                                &endbadly, NULL);
  privkey = GNUNET_CRYPTO_ecdsa_key_create ();
  GNUNET_assert (privkey != NULL);
  GNUNET_CRYPTO_ecdsa_key_get_public (privkey, &pubkey);


  rd.expiration_time = GNUNET_TIME_absolute_get ().abs_value_us;
  rd.record_type = TEST_RECORD_TYPE;
  rd.data_size = TEST_RECORD_DATALEN;
  rd.data = GNUNET_malloc (TEST_RECORD_DATALEN);
  rd.flags = 0;
  memset ((char *) rd.data, 'a', TEST_RECORD_DATALEN);

  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);
  nsqe = GNUNET_NAMESTORE_records_store (nsh,
                                         privkey,
                                         name,
                                         1,
                                         &rd,
                                         &put_cont,
                                         (void *) name);
  if (NULL == nsqe)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Namestore cannot store no block\n"));
  }
  GNUNET_free ((void *) rd.data);
}


#include "test_common.c"


int
main (int argc, char *argv[])
{
  const char *plugin_name;
  char *cfg_name;

  SETUP_CFG (plugin_name, cfg_name);
  res = 1;
  if (0 !=
      GNUNET_TESTING_peer_run ("test-namestore-api",
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


/* end of test_namestore_api_store.c */
