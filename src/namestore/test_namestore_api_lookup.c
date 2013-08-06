/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file namestore/test_namestore_api_lookup.c
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

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)


static struct GNUNET_NAMESTORE_Handle * nsh;

static GNUNET_SCHEDULER_TaskIdentifier endbadly_task;

static struct GNUNET_CRYPTO_EccPrivateKey * privkey;

static struct GNUNET_CRYPTO_EccPublicKey pubkey;

static struct GNUNET_CRYPTO_EccSignature *s_signature;

static struct GNUNET_CRYPTO_ShortHashCode s_zone;

static struct GNUNET_NAMESTORE_RecordData *s_rd;

static struct GNUNET_NAMESTORE_QueueEntry *nsqe;

static char *s_name;

static int res;


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
    GNUNET_CRYPTO_ecc_key_free (privkey);
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
  cleanup ();
  res = 1;
}


static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int c;

  for (c = 0; c < RECORDS; c++)
    GNUNET_free_non_null((void *) s_rd[c].data);
  GNUNET_free (s_rd);
  cleanup ();
}


static void
name_lookup_proc (void *cls,
		  const struct GNUNET_CRYPTO_EccPublicKey *zone_key,
		  struct GNUNET_TIME_Absolute expire,
		  const char *n,
		  unsigned int rd_count,
		  const struct GNUNET_NAMESTORE_RecordData *rd,
		  const struct GNUNET_CRYPTO_EccSignature *signature)
{
  static int found = GNUNET_NO;
  int c;

  if (NULL != n)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Checking returned results\n");
    if (0 != memcmp (zone_key, &pubkey, 
		     sizeof (struct GNUNET_CRYPTO_EccPublicKey)))
    {
      GNUNET_break (0);
    }
    GNUNET_assert (NULL != signature);
    if (0 != memcmp (signature, s_signature, 
		     sizeof (struct GNUNET_CRYPTO_EccSignature)))
    {
      GNUNET_break (0);
    }
    if (0 != strcmp (n, s_name))
    {
      GNUNET_break (0);
    }
    if (RECORDS != rd_count)
    {
      GNUNET_break (0);
    }
    for (c = 0; c < RECORDS; c++)
    {
      if (GNUNET_NO == GNUNET_NAMESTORE_records_cmp (&rd[c], &s_rd[c]))
      {
        GNUNET_break (0);
      }
    }
    found = GNUNET_YES;
    res = 0;
  }
  else
  {
    if (GNUNET_YES != found)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		  "Failed to lookup records for name `%s'\n", s_name);
      res = 1;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Lookup done for name %s'\n", s_name);
  }
  if (GNUNET_SCHEDULER_NO_TASK != endbadly_task)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_SCHEDULER_add_now (&end, NULL);
}


static void
put_cont (void *cls, int32_t success, const char *emsg)
{
  char * name = cls;

  nsqe = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Name store added record for `%s': %s\n", name, 
	      (GNUNET_OK == success) ? "SUCCESS" : "FAIL");
  if (GNUNET_OK == success)
  {
    res = 0;
    GNUNET_NAMESTORE_lookup_record (nsh, &s_zone, name, 0, 
				    &name_lookup_proc, NULL);
  }
  else
  {
    res = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Failed to put records for name `%s'\n", name);
    GNUNET_SCHEDULER_shutdown ();
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
  struct GNUNET_TIME_Absolute et;

  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
						&endbadly, NULL);

  /* load privat key from file not included in zonekey dir */
  privkey = GNUNET_CRYPTO_ecc_key_create_from_file ("test_hostkey");
  GNUNET_assert (NULL != privkey);
  /* get public key */
  GNUNET_CRYPTO_ecc_key_get_public(privkey, &pubkey);

  /* create record */
  s_name = GNUNET_NAMESTORE_normalize_string ("DUMMY.dummy.gnunet");
  s_rd = create_record (RECORDS);

  rd_ser_len = GNUNET_NAMESTORE_records_get_size(RECORDS, s_rd);
  {
    char rd_ser[rd_ser_len];
    GNUNET_NAMESTORE_records_serialize(RECORDS, s_rd, rd_ser_len, rd_ser);

    /* sign */
    et.abs_value = s_rd[0].expiration_time;
    s_signature = GNUNET_NAMESTORE_create_signature (privkey, et, s_name, 
						     s_rd, RECORDS);
    
    /* create random zone hash */
    GNUNET_CRYPTO_short_hash (&pubkey, 
			      sizeof (struct GNUNET_CRYPTO_EccPublicKey), 
			      &s_zone);
    nsh = GNUNET_NAMESTORE_connect (cfg);
    GNUNET_break (NULL != nsh);
    nsqe = GNUNET_NAMESTORE_record_put (nsh, &pubkey, s_name,
					GNUNET_TIME_UNIT_FOREVER_ABS,
					RECORDS, s_rd, s_signature, 
					&put_cont, s_name);
  }
}


int
main (int argc, char *argv[])
{
  res = 1;
  if (0 != 
      GNUNET_TESTING_service_run ("test-namestore-api-lookup",
				  "namestore",
				  "test_namestore_api.conf",
				  &run,
				  NULL))
    return 1;
  GNUNET_free_non_null (s_signature);
  return res;
}


/* end of test_namestore_api_lookup.c */
