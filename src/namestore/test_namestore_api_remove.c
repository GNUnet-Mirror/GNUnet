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
#include "namestore.h"
#include "gnunet_signatures.h"

#define VERBOSE GNUNET_NO

#define RECORDS 5
#define TEST_RECORD_TYPE 1234
#define TEST_RECORD_DATALEN 123
#define TEST_RECORD_DATA 'a'

#define TEST_REMOVE_RECORD_TYPE 4321
#define TEST_REMOVE_RECORD_DATALEN 255
#define TEST_REMOVE_RECORD_DATA 'b'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static struct GNUNET_NAMESTORE_Handle * nsh;

static GNUNET_SCHEDULER_TaskIdentifier endbadly_task;
static struct GNUNET_OS_Process *arm;

static struct GNUNET_CRYPTO_RsaPrivateKey * privkey;
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pubkey;
struct GNUNET_CRYPTO_RsaSignature *s_signature;
static struct GNUNET_CRYPTO_ShortHashCode s_zone;
struct GNUNET_NAMESTORE_RecordData *s_rd;
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

  int c;
  for (c = 0; c < RECORDS; c++)
    GNUNET_free_non_null((void *) s_rd[c].data);
  GNUNET_free (s_rd);

  if (privkey != NULL)
    GNUNET_CRYPTO_rsa_key_free (privkey);
  privkey = NULL;

  if (nsh != NULL)
    GNUNET_NAMESTORE_disconnect (nsh, GNUNET_YES);
  nsh = NULL;

  if (NULL != arm)
    stop_arm();
}

void name_lookup_proc (void *cls,
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Lookup for name `%s' returned %u records\n", n, rd_count);
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

    if (RECORDS-1 != rd_count)
    {
      GNUNET_break (0);
      failed = GNUNET_YES;
    }

    for (c = 0; c < rd_count; c++)
    {
      if (GNUNET_NO == GNUNET_NAMESTORE_records_cmp (&rd[c], &s_rd[c+1]))
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
remove_cont (void *cls, int32_t success, const char *emsg)
{
  char *name = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Remove record for `%s': %s\n", name, (success == GNUNET_YES) ? "SUCCESS" : "FAIL", emsg);
  if (success == GNUNET_OK)
  {
    res = 0;
    GNUNET_NAMESTORE_lookup_record (nsh, &s_zone, name, 0, &name_lookup_proc, name);
  }
  else
  {
    res = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to remove record for name `%s'\n", name);
    GNUNET_SCHEDULER_add_now(&end, NULL);
  }

}

void
put_cont (void *cls, int32_t success, const char *emsg)
{
  char *name = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Name store added record for `%s': %s\n", name, (success == GNUNET_OK) ? "SUCCESS" : "FAIL");
  if (success == GNUNET_OK)
  {
    res = 0;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Removing record for `%s'\n", name);

    GNUNET_NAMESTORE_record_remove (nsh, privkey, name, &s_rd[0], &remove_cont, name);
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

  rd[0].expiration = GNUNET_TIME_absolute_get();
  rd[0].record_type = 0;
  rd[0].data_size = TEST_REMOVE_RECORD_DATALEN;
  rd[0].data = GNUNET_malloc(TEST_REMOVE_RECORD_DATALEN);
  memset ((char *) rd[0].data, TEST_RECORD_DATA, TEST_RECORD_DATALEN);

  for (c = 1; c < RECORDS; c++)
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
  s_rd = create_record (RECORDS);

  rd_ser_len = GNUNET_NAMESTORE_records_get_size(RECORDS, s_rd);
  char rd_ser[rd_ser_len];
  GNUNET_NAMESTORE_records_serialize(RECORDS, s_rd, rd_ser_len, rd_ser);

  /* sign */
  s_signature = GNUNET_NAMESTORE_create_signature(privkey, s_rd[0].expiration, s_name, s_rd, RECORDS);

  /* create random zone hash */
  GNUNET_CRYPTO_short_hash (&pubkey, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), &s_zone);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Name: `%s' Zone: `%s' \n", s_name, GNUNET_short_h2s (&s_zone));


  start_arm (cfgfile);
  GNUNET_assert (arm != NULL);

  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);

  GNUNET_break (s_rd != NULL);
  GNUNET_break (s_name != NULL);

  GNUNET_NAMESTORE_record_put (nsh, &pubkey, s_name,
                              GNUNET_TIME_UNIT_FOREVER_ABS,
                              RECORDS, s_rd, s_signature, put_cont, s_name);



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
