/*
     This file is part of GNUnet.
     Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
/**
 * @file namestore/test_namestore_api_lookup_shadow_filter.c
 * @brief testcase for namestore_api.c: store a record with short expiration
 *      and a shadow record, perform lookup:
 *      - when active record is valid, expect only active record
 *      - when active record is expired, expect shadow record only
 */
#include "platform.h"
#include "gnunet_namecache_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"

#define TEST_NAME "dummy.dummy.gnunet"
#define TEST_RECORD_TYPE 1234
#define TEST_RECORD_DATALEN 123
#define TEST_RECORD_DATA 'a'
#define TEST_SHADOW_RECORD_DATA 'b'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)
#define EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

static struct GNUNET_NAMESTORE_Handle *nsh;

static struct GNUNET_NAMECACHE_Handle *nch;

static struct GNUNET_SCHEDULER_Task * endbadly_task;

static struct GNUNET_SCHEDULER_Task * delayed_lookup_task;

static struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey;

static struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;

static int res;

static struct GNUNET_NAMESTORE_QueueEntry *nsqe;

static struct GNUNET_NAMECACHE_QueueEntry *ncqe;

static struct GNUNET_NAMECACHE_QueueEntry *ncqe_shadow;

static struct GNUNET_GNSRECORD_Data records[2];

static struct GNUNET_TIME_Absolute record_expiration;

static struct GNUNET_HashCode derived_hash;

static struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;

static char *directory;

static void
cleanup ()
{
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
 * @param tc scheduler context
 */
static void
endbadly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != delayed_lookup_task)
  {
    GNUNET_SCHEDULER_cancel (delayed_lookup_task);
    delayed_lookup_task = NULL;
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
  cleanup ();
  res = 1;
}


static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  cleanup ();
  res = 0;
}


static void
rd_decrypt_cb (void *cls,
               unsigned int rd_count,
               const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Data *expected_rd = cls;
  char rd_cmp_data[TEST_RECORD_DATALEN];

  if (1 != rd_count)
  {
    GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    GNUNET_break (0);
    return;
  }
  if (NULL == rd)
  {
    GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    GNUNET_break (0);
    return;
  }
  if (expected_rd == &records[0])
  {
    /* Expecting active record */
    memset (rd_cmp_data, TEST_RECORD_DATA, TEST_RECORD_DATALEN);
    if (TEST_RECORD_TYPE != rd[0].record_type)
    {
      GNUNET_SCHEDULER_add_now (&endbadly, NULL);
      GNUNET_break (0);
      return;
    }
    if (TEST_RECORD_DATALEN != rd[0].data_size)
    {
      GNUNET_SCHEDULER_add_now (&endbadly, NULL);
      GNUNET_break (0);
      return;
    }
    if (0 != memcmp (&rd_cmp_data, rd[0].data, TEST_RECORD_DATALEN))
    {
      GNUNET_SCHEDULER_add_now (&endbadly, NULL);
      GNUNET_break (0);
      return;
    }
    if (0 != (GNUNET_GNSRECORD_RF_SHADOW_RECORD & rd[0].flags))
    {
      GNUNET_SCHEDULER_add_now (&endbadly, NULL);
      GNUNET_break (0);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Block was decrypted successfully with active record\n");
  }
  if (expected_rd == &records[1])
  {
    /* Expecting shadow record  but without shadow flag*/
    memset (rd_cmp_data, TEST_SHADOW_RECORD_DATA, TEST_RECORD_DATALEN);
    if (TEST_RECORD_TYPE != rd[0].record_type)
    {
      GNUNET_SCHEDULER_add_now (&endbadly, NULL);
      GNUNET_break (0);
      return;
    }
    if (TEST_RECORD_DATALEN != rd[0].data_size)
    {
      GNUNET_SCHEDULER_add_now (&endbadly, NULL);
      GNUNET_break (0);
      return;
    }
    if (0 != memcmp (&rd_cmp_data, rd[0].data, TEST_RECORD_DATALEN))
    {
      GNUNET_SCHEDULER_add_now (&endbadly, NULL);
      GNUNET_break (0);
      return;
    }
    if (0 != (GNUNET_GNSRECORD_RF_SHADOW_RECORD & rd[0].flags))
    {
      GNUNET_SCHEDULER_add_now (&endbadly, NULL);
      GNUNET_break (0);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Block was decrypted successfully with former shadow record \n");
    GNUNET_SCHEDULER_add_now (&end, NULL );
  }
}


static void
name_lookup_active_proc (void *cls,
                  const struct GNUNET_GNSRECORD_Block *block)
{
  struct GNUNET_GNSRECORD_Data *expected_rd = cls;
  GNUNET_assert (NULL != expected_rd);

  ncqe = NULL;
  ncqe_shadow = NULL;
  if (endbadly_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = NULL;
  }

  if (NULL == block)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
  	      _("Namestore returned no block\n"));
    if (endbadly_task != NULL)
      GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task =  GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Namestore returned block, decrypting \n");
  GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_block_decrypt(block,
  		&pubkey, TEST_NAME, &rd_decrypt_cb, expected_rd));
}

static void
name_lookup_shadow (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Performing lookup for shadow record \n");
  delayed_lookup_task = NULL;
  ncqe_shadow = GNUNET_NAMECACHE_lookup_block (nch, &derived_hash,
      &name_lookup_active_proc, &records[1]);
}


static void
put_cont (void *cls, int32_t success, const char *emsg)
{
  nsqe = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Name store added record for `%s': %s\n",
	      TEST_NAME,
	      (success == GNUNET_OK) ? "SUCCESS" : "FAIL");

  /* Create derived hash */
  GNUNET_CRYPTO_ecdsa_key_get_public (privkey, &pubkey);
  GNUNET_GNSRECORD_query_from_public_key (&pubkey, TEST_NAME, &derived_hash);

  if (0 == GNUNET_TIME_absolute_get_remaining(record_expiration).rel_value_us )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Test to too long to store records, cannot run test!\n");
    GNUNET_SCHEDULER_add_now (&end, NULL );
    return;
  }
  /* Lookup active record now */
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Performing lookup for active record \n");
  ncqe = GNUNET_NAMECACHE_lookup_block (nch, &derived_hash,
                                        &name_lookup_active_proc, &records[0]);

  delayed_lookup_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (EXPIRATION, 2), &name_lookup_shadow, NULL);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  char *hostkey_file;

  directory = NULL;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string(cfg, "PATHS", "GNUNET_TEST_HOME", &directory));
  GNUNET_DISK_directory_remove (directory);

  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
						&endbadly, NULL);
  GNUNET_asprintf (&hostkey_file,
		   "zonefiles%s%s",
		   DIR_SEPARATOR_STR,
		   "N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Using zonekey file `%s' \n", hostkey_file);
  privkey = GNUNET_CRYPTO_ecdsa_key_create_from_file (hostkey_file);
  GNUNET_free (hostkey_file);
  GNUNET_assert (privkey != NULL);
  GNUNET_CRYPTO_ecdsa_key_get_public (privkey, &pubkey);

  record_expiration = GNUNET_TIME_absolute_add(GNUNET_TIME_absolute_get(), EXPIRATION);
  records[0].expiration_time = record_expiration.abs_value_us;
  records[0].record_type = TEST_RECORD_TYPE;
  records[0].data_size = TEST_RECORD_DATALEN;
  records[0].data = GNUNET_malloc (TEST_RECORD_DATALEN);
  records[0].flags = GNUNET_GNSRECORD_RF_NONE;
  memset ((char *) records[0].data, TEST_RECORD_DATA, TEST_RECORD_DATALEN);

  records[1].expiration_time = GNUNET_TIME_absolute_get().abs_value_us + 1000000000;
  records[1].record_type = TEST_RECORD_TYPE;
  records[1].data_size = TEST_RECORD_DATALEN;
  records[1].data = GNUNET_malloc (TEST_RECORD_DATALEN);
  records[1].flags = GNUNET_GNSRECORD_RF_SHADOW_RECORD;
  memset ((char *) records[1].data, TEST_SHADOW_RECORD_DATA, TEST_RECORD_DATALEN);

  nsh = GNUNET_NAMESTORE_connect (cfg);
  nch = GNUNET_NAMECACHE_connect (cfg);
  GNUNET_break (NULL != nsh);
  GNUNET_break (NULL != nch);
  nsqe = GNUNET_NAMESTORE_records_store (nsh, privkey, TEST_NAME,
				      2, records, &put_cont, NULL);
  if (NULL == nsqe)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
  	      _("Namestore cannot store no block\n"));
  }

  GNUNET_free ((void *) records[0].data);
  GNUNET_free ((void *) records[1].data);
}


int
main (int argc, char *argv[])
{
  res = 1;
  if (0 !=
      GNUNET_TESTING_peer_run ("test-namestore-api",
                               "test_namestore_api.conf",
                               &run,
                               NULL))
  {
    res = 1;
  }
  if (NULL != directory)
  {
      GNUNET_DISK_directory_remove (directory);
      GNUNET_free (directory);
  }
  return res;
}


/* end of test_namestore_api_lookup_shadow_filter.c */
