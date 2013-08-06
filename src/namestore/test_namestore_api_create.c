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
 * @file namestore/test_namestore_api.c
 * @brief testcase for namestore_api.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"
#include "namestore.h"
#include "gnunet_signatures.h"


#define RECORDS 1

#define TEST_RECORD_TYPE 1234

#define TEST_RECORD_DATALEN 123

#define TEST_RECORD_DATA 'a'

#define TEST_CREATE_RECORD_TYPE 4321

#define TEST_CREATE_RECORD_DATALEN 255

#define TEST_CREATE_RECORD_DATA 'b'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)


static struct GNUNET_NAMESTORE_Handle * nsh;

static GNUNET_SCHEDULER_TaskIdentifier endbadly_task;

static struct GNUNET_CRYPTO_EccPrivateKey * privkey;

static struct GNUNET_CRYPTO_EccPublicKey pubkey;

static struct GNUNET_CRYPTO_ShortHashCode s_zone;

static struct GNUNET_NAMESTORE_RecordData *s_first_record;

static struct GNUNET_NAMESTORE_RecordData *s_second_record;

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
  if (endbadly_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free ((void *) s_first_record->data);
  GNUNET_free (s_first_record);
  GNUNET_free_non_null (s_second_record);
  GNUNET_free_non_null (s_name);
  if (privkey != NULL)
    GNUNET_CRYPTO_ecc_key_free (privkey);
  privkey = NULL;
  if (nsh != NULL)
    GNUNET_NAMESTORE_disconnect (nsh);
  nsh = NULL;
}


static void 
name_lookup_second_proc (void *cls,
			 const struct GNUNET_CRYPTO_EccPublicKey *zone_key,
			 struct GNUNET_TIME_Absolute expire,
			 const char *n,
			 unsigned int rd_count,
			 const struct GNUNET_NAMESTORE_RecordData *rd,
			 const struct GNUNET_CRYPTO_EccSignature *signature)
{
  static int found = GNUNET_NO;
  int failed = GNUNET_NO;
  int c;

  if (n != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Checking returned results\n");
    if (0 != memcmp (zone_key, &pubkey, sizeof (struct GNUNET_CRYPTO_EccPublicKey)))
    {
      GNUNET_break (0);
      failed = GNUNET_YES;
    }

    if (0 != strcmp(n, s_name))
    {
      GNUNET_break (0);
      failed = GNUNET_YES;
    }

    if (2 != rd_count)
    {
      GNUNET_break (0);
      failed = GNUNET_YES;
    }

    for (c = 0; c < rd_count; c++)
    {
      if ((GNUNET_NO == GNUNET_NAMESTORE_records_cmp(&rd[c], s_first_record)) &&
          (GNUNET_NO == GNUNET_NAMESTORE_records_cmp(&rd[c], s_second_record)))
      {
        GNUNET_break (0);
        failed = GNUNET_YES;
      }
    }

    if (GNUNET_OK != GNUNET_NAMESTORE_verify_signature (zone_key, expire, n, rd_count, rd, signature))
    {
      GNUNET_break (0);
      failed = GNUNET_YES;
    }

    if (GNUNET_OK != GNUNET_NAMESTORE_verify_signature (&pubkey, expire, n, rd_count, rd, signature))
    {
      GNUNET_break (0);
      failed = GNUNET_YES;
    }

    found = GNUNET_YES;
    if (failed == GNUNET_NO)
      res = 0;
    else
      res = 1;
  }
  else
  {
    if (found != GNUNET_YES)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to lookup records for name `%s'\n", s_name);
      res = 1;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Lookup done for name %s'\n", s_name);
  }
  GNUNET_SCHEDULER_add_now(&end, NULL);
}


static void
create_second_cont (void *cls, int32_t success, const char *emsg)
{
  char *name = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Create second record for `%s': %s\n", name, (success == GNUNET_OK) ? "SUCCESS" : "FAIL");
  if (success == GNUNET_OK)
  {
    res = 0;
    GNUNET_NAMESTORE_lookup_record (nsh, &s_zone, name, 0, &name_lookup_second_proc, name);
  }
  else
  {
    res = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to put records for name `%s'\n", name);
    GNUNET_SCHEDULER_add_now(&end, NULL);
  }
}


static void 
name_lookup_initial_proc (void *cls,
			  const struct GNUNET_CRYPTO_EccPublicKey *zone_key,
			  struct GNUNET_TIME_Absolute expire,
			  const char *n,
			  unsigned int rd_count,
			  const struct GNUNET_NAMESTORE_RecordData *rd,
			  const struct GNUNET_CRYPTO_EccSignature *signature)
{
  struct GNUNET_NAMESTORE_RecordData both_records[2];
  char * name = cls;
  static int found = GNUNET_NO;
  int failed = GNUNET_NO;
  int c;

  if (n != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Checking returned results\n");
    if (0 != memcmp (zone_key, &pubkey, sizeof (struct GNUNET_CRYPTO_EccPublicKey)))
    {
      GNUNET_break (0);
      failed = GNUNET_YES;
    }

    if (0 != strcmp(n, s_name))
    {
      GNUNET_break (0);
      failed = GNUNET_YES;
    }

    if (RECORDS != rd_count)
    {
      GNUNET_break (0);
      failed = GNUNET_YES;
    }

    for (c = 0; c < RECORDS; c++)
    {
      if (GNUNET_NO == GNUNET_NAMESTORE_records_cmp (&rd[c], &s_first_record[c]))
      {
        GNUNET_break (0);
        failed = GNUNET_YES;
      }
    }

    if (GNUNET_OK != GNUNET_NAMESTORE_verify_signature (&pubkey, expire, n, rd_count, rd, signature))
    {
      GNUNET_break (0);
      failed = GNUNET_YES;
    }

    found = GNUNET_YES;
    if (failed == GNUNET_NO)
      res = 0;
    else
      res = 1;

    /* create a second record */
    s_second_record = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_RecordData) + TEST_CREATE_RECORD_DATALEN);
    s_second_record->expiration_time = UINT64_MAX;
    s_second_record->record_type = TEST_CREATE_RECORD_TYPE;
    s_second_record->flags = GNUNET_NAMESTORE_RF_AUTHORITY;
    s_second_record->data = &s_second_record[1];
    s_second_record->data_size = TEST_CREATE_RECORD_DATALEN;
    memset ((char *) s_second_record->data, TEST_CREATE_RECORD_DATA, TEST_CREATE_RECORD_DATALEN);

    both_records[0] = *s_first_record;
    both_records[1] = *s_second_record;
    GNUNET_NAMESTORE_record_put_by_authority (nsh, privkey, name, 
					      2, both_records,
					      &create_second_cont, name);

  }
  else
  {
    if (found != GNUNET_YES)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to lookup records for name `%s'\n", s_name);
      res = 1;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Lookup done for name %s'\n", s_name);
    GNUNET_SCHEDULER_add_now (&end, NULL);
  }
}


static void
create_first_cont (void *cls, int32_t success, const char *emsg)
{
  char *name = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Create record for `%s': %s\n", name, (success == GNUNET_OK) ? "SUCCESS" : "FAIL");
  if (success == GNUNET_OK)
  {
    res = 0;
    /* check if record was created correct */
    GNUNET_NAMESTORE_lookup_record (nsh, &s_zone, name, 0, &name_lookup_initial_proc, name);
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
    rd[c].expiration_time = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_HOURS).abs_value;
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
  size_t rd_ser_len;
  char *hostkey_file;

  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,endbadly, NULL);
  /* load privat key */
  GNUNET_asprintf(&hostkey_file,"zonefiles%s%s",DIR_SEPARATOR_STR,
      "N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Using zonekey file `%s' \n", hostkey_file);
  privkey = GNUNET_CRYPTO_ecc_key_create_from_file(hostkey_file);
  GNUNET_free (hostkey_file);
  /* get public key */
  GNUNET_CRYPTO_ecc_key_get_public(privkey, &pubkey);

  /* create record */
  s_name = GNUNET_NAMESTORE_normalize_string ("DUMMY.dummy.gnunet");
  s_first_record = create_record (1);

  rd_ser_len = GNUNET_NAMESTORE_records_get_size(1, s_first_record);
  char rd_ser[rd_ser_len];
  GNUNET_NAMESTORE_records_serialize(1, s_first_record, rd_ser_len, rd_ser);

  /* create random zone hash */
  GNUNET_CRYPTO_short_hash (&pubkey, sizeof (struct GNUNET_CRYPTO_EccPublicKey), &s_zone);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Name: `%s' Zone: `%s' \n", s_name, GNUNET_NAMESTORE_short_h2s (&s_zone));
  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);

  GNUNET_break (s_first_record != NULL);
  GNUNET_break (s_name != NULL);

  /* create initial record */
  GNUNET_NAMESTORE_record_put_by_authority (nsh, privkey, s_name, 
					    1, s_first_record,
					    &create_first_cont, s_name);
}


int
main (int argc, char *argv[])
{
  res = 1;
  if (0 != 
      GNUNET_TESTING_service_run ("test-namestore-api-create",
				  "namestore",
				  "test_namestore_api.conf",
				  &run,
				  NULL))
    return 1;
  return res;
}

/* end of test_namestore_api_create.c */
