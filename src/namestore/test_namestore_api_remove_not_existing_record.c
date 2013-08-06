/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file namestore/test_namestore_api_remove_not_existing_record.c
 * @brief testcase for namestore_api.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"
#include "namestore.h"
#include "gnunet_signatures.h"

#define RECORDS 5

#define TEST_RECORD_TYPE 1234

#define TEST_RECORD_DATALEN 123

#define TEST_RECORD_DATA 'a'

#define TEST_REMOVE_RECORD_TYPE 4321

#define TEST_REMOVE_RECORD_DATALEN 255

#define TEST_REMOVE_RECORD_DATA 'b'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)


static struct GNUNET_NAMESTORE_Handle * nsh;

static GNUNET_SCHEDULER_TaskIdentifier endbadly_task;

static struct GNUNET_CRYPTO_EccPrivateKey * privkey;

static struct GNUNET_CRYPTO_EccPublicKey pubkey;

static struct GNUNET_CRYPTO_EccSignature *s_signature;

static struct GNUNET_HashCode s_zone;

static struct GNUNET_NAMESTORE_RecordData *s_rd;

static char *s_name;

static int res;


/**
 * Re-establish the connection to the service.
 *
 * @param cls handle to use to re-connect.
 * @param tc scheduler context
 */
static void
endbadly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (nsh != NULL)
    GNUNET_NAMESTORE_disconnect (nsh);
  nsh = NULL;
  if (privkey != NULL)
    GNUNET_CRYPTO_ecc_key_free (privkey);
  privkey = NULL;
  GNUNET_free_non_null (s_name);
  res = 1;
}


static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int c;

  if (endbadly_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_NO_TASK;
  }
  for (c = 0; c < RECORDS; c++)
    GNUNET_free_non_null((void *) s_rd[c].data);
  GNUNET_free (s_rd);

  if (privkey != NULL)
    GNUNET_CRYPTO_ecc_key_free (privkey);
  privkey = NULL;
  if (nsh != NULL)
    GNUNET_NAMESTORE_disconnect (nsh);
  nsh = NULL;
  GNUNET_free_non_null (s_name);
}


static void
remove_cont (void *cls, int32_t success, const char *emsg)
{
  char *name = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Remove record for `%s': %s `%s'\n", name, (success == GNUNET_YES) ? "SUCCESS" : "FAIL", emsg);
  if (GNUNET_OK == success)
  {
    res = 0;
  }
  else
  {
    res = 1;
    GNUNET_break (0);
  }
  GNUNET_SCHEDULER_add_now(&end, NULL);
}


static void
put_cont (void *cls, int32_t success, const char *emsg)
{
  char *name = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Name store added record for `%s': %s\n", name, (success == GNUNET_OK) ? "SUCCESS" : "FAIL");
  if (success == GNUNET_OK)
  {
    res = 0;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Removing non existing record for `%s'\n", name);
    GNUNET_NAMESTORE_record_put_by_authority (nsh, privkey, name, 
					      0, NULL,
					      &remove_cont, name);
  }
  else
  {
    res = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to put records for name `%s'\n", name);
    GNUNET_SCHEDULER_add_now(&end, NULL);
  }
}


static struct GNUNET_NAMESTORE_RecordData *
create_record (unsigned int count)
{
  unsigned int c;
  struct GNUNET_NAMESTORE_RecordData * rd;

  rd = GNUNET_malloc (count * sizeof (struct GNUNET_NAMESTORE_RecordData));
  for (c = 0; c < count; c++)
  {
    rd[c].expiration_time = GNUNET_TIME_absolute_get().abs_value;
    rd[c].record_type = TEST_RECORD_TYPE;
    rd[c].data_size = TEST_RECORD_DATALEN;
    rd[c].data = GNUNET_malloc(TEST_RECORD_DATALEN);
    memset ((char *) rd[c].data, TEST_RECORD_DATA, TEST_RECORD_DATALEN);
  }
  return rd;
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  char *hostkey_file;
  size_t rd_ser_len;
  struct GNUNET_TIME_Absolute et;

  endbadly_task = GNUNET_SCHEDULER_add_delayed(TIMEOUT,endbadly, NULL);

  /* load privat key */
  GNUNET_asprintf(&hostkey_file,"zonefiles%s%s",DIR_SEPARATOR_STR,
      "N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Using zonekey file `%s' \n", hostkey_file);
  privkey = GNUNET_CRYPTO_ecc_key_create_from_file(hostkey_file);
  GNUNET_free (hostkey_file);
  GNUNET_assert (privkey != NULL);
  /* get public key */
  GNUNET_CRYPTO_ecc_key_get_public(privkey, &pubkey);

  /* create record */
  s_name = GNUNET_NAMESTORE_normalize_string ("DUMMY.dummy.gnunet");
  s_rd = create_record (RECORDS);

  rd_ser_len = GNUNET_NAMESTORE_records_get_size(RECORDS, s_rd);
  char rd_ser[rd_ser_len];
  GNUNET_NAMESTORE_records_serialize(RECORDS, s_rd, rd_ser_len, rd_ser);

  /* sign */
  et.abs_value = s_rd[0].expiration_time;
  s_signature = GNUNET_NAMESTORE_create_signature(privkey, et, s_name, s_rd, RECORDS);

  /* create random zone hash */
  GNUNET_CRYPTO_hash (&pubkey, sizeof (struct GNUNET_CRYPTO_EccPublicKey), &s_zone);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Name: `%s' Zone: `%s' \n", s_name, GNUNET_h2s_full(&s_zone));
  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);
  GNUNET_break (s_rd != NULL);
  GNUNET_break (s_name != NULL);
  GNUNET_NAMESTORE_record_put (nsh, &pubkey, s_name,
                              GNUNET_TIME_UNIT_FOREVER_ABS,
                              RECORDS, s_rd, s_signature, put_cont, s_name);
}


int
main (int argc, char *argv[])
{
  res = 1;
  if (0 != 
      GNUNET_TESTING_service_run ("test-namestore-api-remove-not-existing-record",
				  "namestore",
				  "test_namestore_api.conf",
				  &run,
				  NULL))
    return 1;
  GNUNET_free_non_null (s_signature);
  return res;
}

/* end of test_namestore_api_remove_not_existing_record.c */
