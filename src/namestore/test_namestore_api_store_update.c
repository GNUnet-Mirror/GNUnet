/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013, 2018 GNUnet e.V.

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
 * @file namestore/test_namestore_api_store_update.c
 * @brief testcase for namestore_api.c: store a record, update it and perform a lookup
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_namecache_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"
#include "gnunet_dnsparser_lib.h"

#define TEST_RECORD_TYPE GNUNET_DNSPARSER_TYPE_TXT

#define TEST_RECORD_DATALEN 123

#define TEST_RECORD_DATA 'a'

#define TEST_RECORD_DATALEN2 234

#define TEST_RECORD_DATA2 'b'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)


static struct GNUNET_NAMESTORE_Handle *nsh;

static struct GNUNET_NAMECACHE_Handle *nch;

static struct GNUNET_SCHEDULER_Task *endbadly_task;

static struct GNUNET_CRYPTO_EcdsaPrivateKey privkey;

static struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;

static int res;

static int update_performed;

static struct GNUNET_NAMESTORE_QueueEntry *nsqe;

static struct GNUNET_NAMECACHE_QueueEntry *ncqe;

static const char *name = "dummy";


/**
 * Terminate test with error.
 *
 * @param cls handle to use to re-connect.
 */
static void
endbadly (void *cls)
{
  GNUNET_break (0);
  endbadly_task = NULL;
  GNUNET_SCHEDULER_shutdown ();
  res = 1;
}


static void
end (void *cls)
{
  if (NULL != endbadly_task)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = NULL;
  }
  if (NULL != nsqe)
  {
    GNUNET_NAMESTORE_cancel (nsqe);
    nsqe = NULL;
  }
  if (NULL != ncqe)
  {
    GNUNET_NAMECACHE_cancel (ncqe);
    ncqe = NULL;
  }
  if (NULL != nsh)
  {
    GNUNET_NAMESTORE_disconnect (nsh);
    nsh = NULL;
  }
  if (NULL != nch)
  {
    GNUNET_NAMECACHE_disconnect (nch);
    nch = NULL;
  }
}


static void
put_cont (void *cls,
          int32_t success,
          const char *emsg);


static void
rd_decrypt_cb (void *cls,
               unsigned int rd_count,
               const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Data rd_new;

  GNUNET_assert (1 == rd_count);
  GNUNET_assert (NULL != rd);

  if (GNUNET_NO == update_performed)
  {
    char rd_cmp_data[TEST_RECORD_DATALEN];

    memset (rd_cmp_data,
            TEST_RECORD_DATA,
            TEST_RECORD_DATALEN);
    GNUNET_assert (TEST_RECORD_TYPE == rd[0].record_type);
    GNUNET_assert (TEST_RECORD_DATALEN == rd[0].data_size);
    GNUNET_assert (0 == memcmp (&rd_cmp_data,
                                rd[0].data,
                                TEST_RECORD_DATALEN));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Block was decrypted successfully, updating record \n");

    rd_new.flags = GNUNET_GNSRECORD_RF_NONE;
    rd_new.expiration_time = GNUNET_TIME_absolute_get ().abs_value_us
                             + 1000000000;
    rd_new.record_type = TEST_RECORD_TYPE;
    rd_new.data_size = TEST_RECORD_DATALEN2;
    rd_new.data = GNUNET_malloc (TEST_RECORD_DATALEN2);
    memset ((char *) rd_new.data,
            TEST_RECORD_DATA2,
            TEST_RECORD_DATALEN2);

    nsqe = GNUNET_NAMESTORE_records_store (nsh,
                                           &privkey,
                                           name,
                                           1,
                                           &rd_new,
                                           &put_cont,
                                           (void *) name);
    update_performed = GNUNET_YES;
  }
  else
  {
    char rd_cmp_data[TEST_RECORD_DATALEN2];

    memset (rd_cmp_data,
            TEST_RECORD_DATA2,
            TEST_RECORD_DATALEN2);
    GNUNET_assert (TEST_RECORD_TYPE == rd[0].record_type);
    GNUNET_assert (TEST_RECORD_DATALEN2 == rd[0].data_size);
    GNUNET_assert (0 == memcmp (&rd_cmp_data,
                                rd[0].data,
                                TEST_RECORD_DATALEN2));
    GNUNET_SCHEDULER_shutdown ();
    res = 0;
  }
}


static void
name_lookup_proc (void *cls,
                  const struct GNUNET_GNSRECORD_Block *block)
{
  const char *name = cls;

  ncqe = NULL;
  GNUNET_assert (NULL != cls);
  if (NULL == block)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Namecache returned no block for `%s'\n"),
                name);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Namecache returned block, decrypting \n");
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_GNSRECORD_block_decrypt (block,
                                                 &pubkey,
                                                 name,
                                                 &rd_decrypt_cb,
                                                 (void *) name));
}


static void
put_cont (void *cls,
          int32_t success,
          const char *emsg)
{
  const char *name = cls;
  struct GNUNET_HashCode derived_hash;

  nsqe = NULL;
  GNUNET_assert (NULL != cls);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Name store added record for `%s': %s\n",
              name,
              (success == GNUNET_OK) ? "SUCCESS" : "FAIL");
  /* Create derived hash */
  GNUNET_GNSRECORD_query_from_private_key (&privkey,
                                           name,
                                           &derived_hash);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Looking in namecache for `%s'\n",
              GNUNET_h2s (&derived_hash));
  ncqe = GNUNET_NAMECACHE_lookup_block (nch,
                                        &derived_hash,
                                        &name_lookup_proc, (void *) name);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_GNSRECORD_Data rd;

  update_performed = GNUNET_NO;
  GNUNET_SCHEDULER_add_shutdown (&end,
                                 NULL);
  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                                &endbadly,
                                                NULL);
  GNUNET_CRYPTO_ecdsa_key_create (&privkey);
  GNUNET_CRYPTO_ecdsa_key_get_public (&privkey,
                                      &pubkey);
  rd.flags = GNUNET_GNSRECORD_RF_NONE;
  rd.expiration_time = GNUNET_TIME_absolute_get ().abs_value_us + 1000000000;
  rd.record_type = TEST_RECORD_TYPE;
  rd.data_size = TEST_RECORD_DATALEN;
  rd.data = GNUNET_malloc (TEST_RECORD_DATALEN);
  memset ((char *) rd.data,
          TEST_RECORD_DATA,
          TEST_RECORD_DATALEN);

  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);
  nch = GNUNET_NAMECACHE_connect (cfg);
  GNUNET_break (NULL != nch);
  nsqe = GNUNET_NAMESTORE_records_store (nsh,
                                         &privkey,
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
  GNUNET_free_nz ((void *) rd.data);
}


#include "test_common.c"


int
main (int argc,
      char *argv[])
{
  const char *plugin_name;
  char *cfg_name;

  SETUP_CFG (plugin_name, cfg_name);
  res = 1;
  if (0 !=
      GNUNET_TESTING_peer_run ("test-namestore-api-store-update",
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


/* end of test_namestore_api_store_update.c */
