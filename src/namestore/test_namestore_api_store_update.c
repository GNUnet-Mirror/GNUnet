/*
     This file is part of GNUnet.
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file namestore/test_namestore_api_store_update.c
 * @brief testcase for namestore_api.c: store a record, update it and perform a lookup
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"

#define TEST_RECORD_TYPE 1234

#define TEST_RECORD_DATALEN 123

#define TEST_RECORD_DATA 'a'


#define TEST_RECORD_TYPE2 4321

#define TEST_RECORD_DATALEN2 234

#define TEST_RECORD_DATA2 'b'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)


static struct GNUNET_NAMESTORE_Handle *nsh;

static GNUNET_SCHEDULER_TaskIdentifier endbadly_task;

static struct GNUNET_CRYPTO_EccPrivateKey *privkey;

static struct GNUNET_CRYPTO_EccPublicSignKey pubkey;

static int res;

static int update_performed;

static struct GNUNET_NAMESTORE_QueueEntry *nsqe;

static const char * name = "dummy.dummy.gnunet";


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
 * @param tc scheduler context
 */
static void
endbadly (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc)
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
end (void *cls,
     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  cleanup ();
  res = 0;
}


static void
put_cont (void *cls, int32_t success, const char *emsg);


static void
rd_decrypt_cb (void *cls,
               unsigned int rd_count,
               const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GNUNET_NAMESTORE_RecordData rd_new;

  GNUNET_assert (1 == rd_count);
  GNUNET_assert (NULL != rd);

  if (GNUNET_NO == update_performed)
  {
    char rd_cmp_data[TEST_RECORD_DATALEN];
    memset (rd_cmp_data, TEST_RECORD_DATA, TEST_RECORD_DATALEN);
    
    GNUNET_assert (TEST_RECORD_TYPE == rd[0].record_type);
    GNUNET_assert (TEST_RECORD_DATALEN == rd[0].data_size);
    GNUNET_assert (0 == memcmp (&rd_cmp_data, rd[0].data, TEST_RECORD_DATALEN));
    
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Block was decrypted successfully, updating record \n");
    
    rd_new.flags = GNUNET_NAMESTORE_RF_NONE;
    rd_new.expiration_time = GNUNET_TIME_absolute_get().abs_value_us;
    rd_new.record_type = TEST_RECORD_TYPE2;
    rd_new.data_size = TEST_RECORD_DATALEN2;
    rd_new.data = GNUNET_malloc (TEST_RECORD_DATALEN2);
    memset ((char *) rd_new.data, TEST_RECORD_DATA2, TEST_RECORD_DATALEN2);
    
    nsqe = GNUNET_NAMESTORE_records_store (nsh, privkey, name,
                                           1, &rd_new, &put_cont, (void *) name);
    update_performed = GNUNET_YES;
  }
  else
  {
    char rd_cmp_data[TEST_RECORD_DATALEN2];
    memset (rd_cmp_data, TEST_RECORD_DATA2, TEST_RECORD_DATALEN2);
    
    GNUNET_assert (TEST_RECORD_TYPE2 == rd[0].record_type);
    GNUNET_assert (TEST_RECORD_DATALEN2 == rd[0].data_size);
    GNUNET_assert (0 == memcmp (&rd_cmp_data, rd[0].data, TEST_RECORD_DATALEN2));
    
    GNUNET_SCHEDULER_add_now (&end, NULL);
  }
}


static void
name_lookup_proc (void *cls,
                  const struct GNUNET_NAMESTORE_Block *block)
{
  const char *name = cls;
  nsqe = NULL;

  GNUNET_assert (NULL != cls);

  if (endbadly_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (NULL == block)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
  	      _("Namestore returned no block\n"));
    if (endbadly_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task =  GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Namestore returned block, decrypting \n");
  GNUNET_assert (GNUNET_OK == GNUNET_NAMESTORE_block_decrypt(block,
  		&pubkey, name, &rd_decrypt_cb, (void *) name));
}


static void
put_cont (void *cls, int32_t success, const char *emsg)
{
  const char *name = cls;
  struct GNUNET_HashCode derived_hash;

  GNUNET_assert (NULL != cls);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Name store added record for `%s': %s\n",
	      name,
	      (success == GNUNET_OK) ? "SUCCESS" : "FAIL");

  /* Create derived hash */
  GNUNET_NAMESTORE_query_from_private_key (privkey, name, &derived_hash);

  nsqe = GNUNET_NAMESTORE_lookup_block (nsh, &derived_hash,
					 &name_lookup_proc, (void *) name);
}


static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_NAMESTORE_RecordData rd;
  char *hostkey_file;

  update_performed = GNUNET_NO;
  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, 
						&endbadly, NULL);
  GNUNET_asprintf (&hostkey_file,
		   "zonefiles%s%s",
		   DIR_SEPARATOR_STR,
		   "N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Using zonekey file `%s' \n", hostkey_file);
  privkey = GNUNET_CRYPTO_ecc_key_create_from_file (hostkey_file);
  GNUNET_free (hostkey_file);
  GNUNET_assert (privkey != NULL);
  GNUNET_CRYPTO_ecc_key_get_public_for_signature (privkey, &pubkey);

  rd.flags = GNUNET_NAMESTORE_RF_NONE;
  rd.expiration_time = GNUNET_TIME_absolute_get().abs_value_us;
  rd.record_type = TEST_RECORD_TYPE;
  rd.data_size = TEST_RECORD_DATALEN;
  rd.data = GNUNET_malloc (TEST_RECORD_DATALEN);
  memset ((char *) rd.data, TEST_RECORD_DATA, TEST_RECORD_DATALEN);

  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);
  nsqe = GNUNET_NAMESTORE_records_store (nsh, privkey, name,
				      1, &rd, &put_cont, (void *) name);
  if (NULL == nsqe)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
  	      _("Namestore cannot store no block\n"));
  }

  GNUNET_free ((void *)rd.data);
}


int
main (int argc, char *argv[])
{
  res = 1;
  if (0 != 
      GNUNET_TESTING_service_run ("test-namestore-api-store-update",
				  "namestore",
				  "test_namestore_api.conf",
				  &run,
				  NULL))
    return 1;
  return res;
}


/* end of test_namestore_api_store_update.c*/
