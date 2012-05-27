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
 * @brief testcase for namestore_api.c for updating an existing record
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_namestore_service.h"
#include "namestore.h"
#include "gnunet_signatures.h"

#define VERBOSE GNUNET_NO

#define RECORDS 1
#define TEST_RECORD_TYPE 1234
#define TEST_RECORD_DATALEN 123
#define TEST_RECORD_DATA 'a'

#define TEST_CREATE_RECORD_TYPE 4321
#define TEST_CREATE_RECORD_DATALEN 255
#define TEST_CREATE_RECORD_DATA 'b'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static struct GNUNET_NAMESTORE_Handle * nsh;

static GNUNET_SCHEDULER_TaskIdentifier endbadly_task;
static struct GNUNET_OS_Process *arm;

static struct GNUNET_CRYPTO_RsaPrivateKey * privkey;
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pubkey;
struct GNUNET_CRYPTO_RsaSignature *s_signature;
struct GNUNET_CRYPTO_RsaSignature *s_signature_updated;
static struct GNUNET_CRYPTO_ShortHashCode s_zone;
struct GNUNET_NAMESTORE_RecordData *s_first_record;
struct GNUNET_NAMESTORE_RecordData *s_second_record;
static char *s_name;



static int res;

static void
start_arm (const char *cfgname)
{
  arm = GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm", "-c", cfgname,
#if VERBOSE_PEERS
                               "-L", "DEBUG",
#else
                               "-L", "ERROR",
#endif
                               NULL);
}

static void
stop_arm ()
{
  if (NULL != arm)
  {
    if (0 != GNUNET_OS_process_kill (arm, SIGTERM))
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    GNUNET_OS_process_wait (arm);
    GNUNET_OS_process_destroy (arm);
    arm = NULL;
  }
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
  if (nsh != NULL)
    GNUNET_NAMESTORE_disconnect (nsh, GNUNET_YES);
  nsh = NULL;

  if (privkey != NULL)
    GNUNET_CRYPTO_rsa_key_free (privkey);
  privkey = NULL;

  if (NULL != arm)
    stop_arm();

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

  if (privkey != NULL)
    GNUNET_CRYPTO_rsa_key_free (privkey);
  privkey = NULL;

  if (nsh != NULL)
    GNUNET_NAMESTORE_disconnect (nsh, GNUNET_YES);
  nsh = NULL;

  if (NULL != arm)
    stop_arm();
}

void name_lookup_second_proc (void *cls,
                            const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                            struct GNUNET_TIME_Absolute expire,
                            const char *n,
                            unsigned int rd_count,
                            const struct GNUNET_NAMESTORE_RecordData *rd,
                            const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  static int found = GNUNET_NO;
  int failed = GNUNET_NO;
  int c;

  if (n != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Checking returned results\n");
    if (0 != memcmp (zone_key, &pubkey, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded)))
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

    if (GNUNET_OK != GNUNET_NAMESTORE_verify_signature(&pubkey, expire, n, rd_count, rd, signature))
    {
      GNUNET_break (0);
      failed = GNUNET_YES;
    }

    struct GNUNET_NAMESTORE_RecordData rd_new[2];
    rd_new[0] = *s_first_record;
    rd_new[1] = *s_second_record;
    s_signature_updated = GNUNET_NAMESTORE_create_signature(privkey, expire, s_name, rd_new, 2);

    if (0 != memcmp (s_signature_updated, signature, sizeof (struct GNUNET_CRYPTO_RsaSignature)))
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


void
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

void name_lookup_initial_proc (void *cls,
                            const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                            struct GNUNET_TIME_Absolute expire,
                            const char *n,
                            unsigned int rd_count,
                            const struct GNUNET_NAMESTORE_RecordData *rd,
                            const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  char * name = cls;
  static int found = GNUNET_NO;
  int failed = GNUNET_NO;
  int c;

  if (n != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Checking returned results\n");
    if (0 != memcmp (zone_key, &pubkey, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded)))
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
      if (GNUNET_NO == GNUNET_NAMESTORE_records_cmp(&rd[c], &s_first_record[c]))
      {
        GNUNET_break (0);
        failed = GNUNET_YES;
      }
    }

    if (GNUNET_OK != GNUNET_NAMESTORE_verify_signature(&pubkey, expire, n, rd_count, rd, signature))
    {
      GNUNET_break (0);
      failed = GNUNET_YES;
    }

    if (0 != memcmp (s_signature, signature, sizeof (struct GNUNET_CRYPTO_RsaSignature)))
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
    s_second_record = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_RecordData) + TEST_CREATE_RECORD_DATALEN);
    s_second_record->expiration = GNUNET_TIME_UNIT_FOREVER_ABS;
    s_second_record->record_type = TEST_CREATE_RECORD_TYPE;
    s_second_record->flags = GNUNET_NAMESTORE_RF_AUTHORITY;
    s_second_record->data = &s_second_record[1];
    s_second_record->data_size = TEST_CREATE_RECORD_DATALEN;
    memset ((char *) s_second_record->data, TEST_CREATE_RECORD_DATA, TEST_CREATE_RECORD_DATALEN);

    GNUNET_NAMESTORE_record_create (nsh, privkey, name, s_second_record, &create_second_cont, name);

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


void
create_updated_cont (void *cls, int32_t success, const char *emsg)
{
  char *name = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating expiration for record `%s': %s `%s'\n", name, ((success == GNUNET_YES) || (success == GNUNET_NO)) ? "SUCCESS" : "FAIL", emsg);
  if (success == GNUNET_NO)
  {
    res = 0;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updated record for name `%s'\n", name);
  }
  else if (success == GNUNET_OK)
  {
    res = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "FAIL, Create new record for name `%s'\n", name);
  }
  else
  {
    res = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to create records for name `%s'\n", name);
  }
  GNUNET_SCHEDULER_add_now(&end, NULL);
}

void
create_identical_cont (void *cls, int32_t success, const char *emsg)
{
  char *name = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating identical record for `%s': %s `%s'\n", name, ((success == GNUNET_YES) || (success == GNUNET_NO)) ? "SUCCESS" : "FAIL", emsg);
  if (success == GNUNET_NO)
  {
    res = 0;
    s_first_record->expiration = GNUNET_TIME_absolute_get ();
    GNUNET_NAMESTORE_record_create (nsh, privkey, s_name, s_first_record, &create_updated_cont, s_name);
  }
  else
  {
    res = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating identical record for `%s': %s `%s'\n", name, ((success == GNUNET_YES) || (success == GNUNET_NO)) ? "SUCCESS" : "FAIL", emsg);
    GNUNET_SCHEDULER_add_now(&end, NULL);
  }

}

void
create_first_cont (void *cls, int32_t success, const char *emsg)
{
  char *name = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Create record for `%s': %s `%s'\n", name, (success == GNUNET_OK) ? "SUCCESS" : "FAIL", emsg);
  if (success == GNUNET_OK)
  {
    res = 0;
    /* check if record was created correct */
    GNUNET_NAMESTORE_record_create (nsh, privkey, s_name, s_first_record, &create_identical_cont, s_name);
  }
  else
  {
    res = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to put records for name `%s'\n", name);
    GNUNET_SCHEDULER_add_now(&end, NULL);
  }

}

void
put_cont (void *cls, int32_t success, const char *emsg)
{
  char *name = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Name store added record for `%s': %s `%s'\n", name, (success == GNUNET_OK) ? "SUCCESS" : "FAIL", emsg);
  if (success == GNUNET_OK)
  {

  }
  else
  {
    res = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to put records for name `%s'\n", name);
    GNUNET_SCHEDULER_add_now(&end, NULL);
  }
}

static struct GNUNET_NAMESTORE_RecordData *
create_record (int count)
{
  int c;
  struct GNUNET_NAMESTORE_RecordData * rd;
  rd = GNUNET_malloc (count * sizeof (struct GNUNET_NAMESTORE_RecordData));

  for (c = 0; c < count; c++)
  {
    rd[c].expiration = GNUNET_TIME_UNIT_ZERO_ABS;
    rd[c].record_type = TEST_RECORD_TYPE;
    rd[c].data_size = TEST_RECORD_DATALEN;
    rd[c].data = GNUNET_malloc(TEST_RECORD_DATALEN);
    memset ((char *) rd[c].data, TEST_RECORD_DATA, TEST_RECORD_DATALEN);
  }

  return rd;
}

void
delete_existing_db (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *afsdir;

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_filename (cfg, "namestore-sqlite",
                                               "FILENAME", &afsdir))
  {
    if (GNUNET_OK == GNUNET_DISK_file_test (afsdir))
      if (GNUNET_OK == GNUNET_DISK_file_test (afsdir))
        if (GNUNET_OK == GNUNET_DISK_directory_remove(afsdir))
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deleted existing database `%s' \n", afsdir);
   GNUNET_free (afsdir);
  }

}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  delete_existing_db(cfg);

  endbadly_task = GNUNET_SCHEDULER_add_delayed(TIMEOUT,endbadly, NULL);
  size_t rd_ser_len;

  /* load privat key */
  char *hostkey_file;
  GNUNET_asprintf(&hostkey_file,"zonefiles%s%s",DIR_SEPARATOR_STR,
      "N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Using zonekey file `%s' \n", hostkey_file);
  privkey = GNUNET_CRYPTO_rsa_key_create_from_file(hostkey_file);
  GNUNET_free (hostkey_file);

  GNUNET_assert (privkey != NULL);
  /* get public key */
  GNUNET_CRYPTO_rsa_key_get_public(privkey, &pubkey);

  /* create record */
  s_name = "dummy.dummy.gnunet";
  s_first_record = create_record (1);

  rd_ser_len = GNUNET_NAMESTORE_records_get_size(1, s_first_record);
  char rd_ser[rd_ser_len];
  GNUNET_NAMESTORE_records_serialize(1, s_first_record, rd_ser_len, rd_ser);

  s_signature = GNUNET_NAMESTORE_create_signature(privkey, s_first_record->expiration, s_name, s_first_record, 1);

  /* create random zone hash */
  GNUNET_CRYPTO_short_hash (&pubkey, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), &s_zone);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Name: `%s' Zone: `%s' \n", s_name, GNUNET_short_h2s (&s_zone));

  start_arm (cfgfile);
  GNUNET_assert (arm != NULL);

  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);

  GNUNET_break (s_first_record != NULL);
  GNUNET_break (s_name != NULL);

  /* create initial record */
  GNUNET_NAMESTORE_record_create (nsh, privkey, s_name, s_first_record, &create_first_cont, s_name);
}

static int
check ()
{
  static char *const argv[] = { "test-namestore-api",
    "-c",
    "test_namestore_api.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  res = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv, "test-namestore-api",
                      "nohelp", options, &run, &res);
  return res;
}

int
main (int argc, char *argv[])
{
  int ret;

  ret = check ();
  GNUNET_free (s_signature);
  return ret;
}

/* end of test_namestore_api.c */
