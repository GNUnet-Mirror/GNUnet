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
 * @file namestore/test_namestore_api_zone_iteration_specific_zone.c
 * @brief testcase for zone iteration functionality: iterate of a specific zone
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_namestore_service.h"
#include "namestore.h"

#define VERBOSE GNUNET_NO

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static struct GNUNET_NAMESTORE_Handle * nsh;

static GNUNET_SCHEDULER_TaskIdentifier endbadly_task;
static GNUNET_SCHEDULER_TaskIdentifier stopiteration_task;
static struct GNUNET_OS_Process *arm;

static struct GNUNET_CRYPTO_RsaPrivateKey * privkey;
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pubkey;
static struct GNUNET_CRYPTO_ShortHashCode zone;

static struct GNUNET_CRYPTO_RsaPrivateKey * privkey2;
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pubkey2;
static struct GNUNET_CRYPTO_ShortHashCode zone2;

static struct GNUNET_NAMESTORE_ZoneIterator *zi;
static int res;
static int returned_records;

struct GNUNET_CRYPTO_RsaSignature *sig_1;
char * s_name_1;
struct GNUNET_NAMESTORE_RecordData *s_rd_1;

struct GNUNET_CRYPTO_RsaSignature *sig_2;
char * s_name_2;
struct GNUNET_NAMESTORE_RecordData *s_rd_2;

struct GNUNET_CRYPTO_RsaSignature *sig_3;
char * s_name_3;
struct GNUNET_NAMESTORE_RecordData *s_rd_3;

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
  if (stopiteration_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (stopiteration_task);
    stopiteration_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (nsh != NULL)
    GNUNET_NAMESTORE_disconnect (nsh, GNUNET_YES);
  nsh = NULL;

  GNUNET_free_non_null(sig_1);
  GNUNET_free_non_null(sig_2);
  GNUNET_free_non_null(sig_3);
  GNUNET_free_non_null(s_name_1);
  GNUNET_free_non_null(s_name_2);
  GNUNET_free_non_null(s_name_3);

  if (s_rd_1 != NULL)
  {
    GNUNET_free ((void *)s_rd_1->data);
    GNUNET_free (s_rd_1);
  }
  if (s_rd_2 != NULL)
  {
    GNUNET_free ((void *)s_rd_2->data);
    GNUNET_free (s_rd_2);
  }
  if (s_rd_3 != NULL)
  {
    GNUNET_free ((void *)s_rd_3->data);
    GNUNET_free (s_rd_3);
  }

  if (privkey != NULL)
    GNUNET_CRYPTO_rsa_key_free (privkey);
  privkey = NULL;

  if (privkey2 != NULL)
    GNUNET_CRYPTO_rsa_key_free (privkey2);
  privkey2 = NULL;

  if (NULL != arm)
    stop_arm();

  res = 1;
}


static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (stopiteration_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (stopiteration_task);
    stopiteration_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (endbadly_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (privkey != NULL)
    GNUNET_CRYPTO_rsa_key_free (privkey);
  privkey = NULL;

  if (privkey2 != NULL)
    GNUNET_CRYPTO_rsa_key_free (privkey2);
  privkey2 = NULL;

  GNUNET_free (sig_1);
  GNUNET_free (sig_2);
  GNUNET_free (sig_3);
  GNUNET_free (s_name_1);
  GNUNET_free (s_name_2);
  GNUNET_free (s_name_3);
  if (s_rd_1 != NULL)
  {
    GNUNET_free ((void *)s_rd_1->data);
    GNUNET_free (s_rd_1);
  }
  if (s_rd_2 != NULL)
  {
    GNUNET_free ((void *)s_rd_2->data);
    GNUNET_free (s_rd_2);
  }
  if (s_rd_3 != NULL)
  {
    GNUNET_free ((void *)s_rd_3->data);
    GNUNET_free (s_rd_3);
  }

  if (nsh != NULL)
    GNUNET_NAMESTORE_disconnect (nsh, GNUNET_YES);
  nsh = NULL;


  if (NULL != arm)
    stop_arm();
}

void zone_proc (void *cls,
                const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                struct GNUNET_TIME_Absolute expire,
                const char *name,
                unsigned int rd_count,
                const struct GNUNET_NAMESTORE_RecordData *rd,
                const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  int failed = GNUNET_NO;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Callback for zone `%s'\n", GNUNET_short_h2s (&zone));
  if ((zone_key == NULL) &&  (name == NULL))
  {
    GNUNET_break (2 == returned_records);
    if (2 == returned_records)
      res = 0;
    else
      res = 1;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received last result, iteration done after %u records\n", returned_records);
    GNUNET_SCHEDULER_add_now (&end, NULL);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Comparing results name %s \n", name);
    if (0 == strcmp (name, s_name_1))
    {
      if (rd_count == 1)
      {
        if (GNUNET_YES != GNUNET_NAMESTORE_records_cmp(rd, s_rd_1))
        {
          failed = GNUNET_YES;
          GNUNET_break (0);
        }
      }
      else
      {
        failed = GNUNET_YES;
        GNUNET_break (0);
      }
      if (0 != memcmp (signature, sig_1, sizeof (struct GNUNET_CRYPTO_RsaSignature)))
      {
        failed = GNUNET_YES;
        GNUNET_break (0);
      }
    }
    else if (0 == strcmp (name, s_name_2))
    {
      if (rd_count == 1)
      {
        if (GNUNET_YES != GNUNET_NAMESTORE_records_cmp(rd, s_rd_2))
        {
          failed = GNUNET_YES;
          GNUNET_break (0);
        }
      }
      else
      {
        failed = GNUNET_YES;
        GNUNET_break (0);
      }
      if (0 != memcmp (signature, sig_2, sizeof (struct GNUNET_CRYPTO_RsaSignature)))
      {
        failed = GNUNET_YES;
        GNUNET_break (0);
      }
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Comparing result failed: got name `%s'\n", name);
      res = 1;
      GNUNET_break (0);
      GNUNET_SCHEDULER_add_now (&end, NULL);
    }

    if (failed == GNUNET_NO)
    {
      returned_records ++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Telling namestore to send the next result\n");
      GNUNET_NAMESTORE_zone_iterator_next (zi);
    }
    else
    {
      GNUNET_break (0);
      GNUNET_SCHEDULER_add_now (&end, NULL);
    }
  }
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

void
put_cont (void *cls, int32_t success, const char *emsg)
{
  static int c = 0;

  if (success == GNUNET_OK)
  {
    c++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created record %u \n", c);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to created records\n");
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
  }

  if (c == 3)
  {
    res = 1;
    returned_records = 0;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All records created, starting iteration over zone `%s'\n",
        GNUNET_short_h2s(&zone));
    zi = GNUNET_NAMESTORE_zone_iteration_start(nsh,
                                        &zone,
                                        GNUNET_NAMESTORE_RF_NONE,
                                        GNUNET_NAMESTORE_RF_NONE,
                                        zone_proc,
                                        &zone);
    if (zi == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to create zone iterator\n");
      GNUNET_break (0);
      GNUNET_SCHEDULER_cancel (endbadly_task);
      endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    }
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
    rd[c].expiration = GNUNET_TIME_absolute_get();
    rd[c].record_type = 1111;
    rd[c].data_size = 50;
    rd[c].data = GNUNET_malloc(50);
    memset ((char *) rd[c].data, 'a', 50);
  }
  return rd;
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  delete_existing_db(cfg);
  endbadly_task = GNUNET_SCHEDULER_add_delayed(TIMEOUT,&endbadly, NULL);

  char *hostkey_file;
  GNUNET_asprintf(&hostkey_file,"zonefiles%s%s",DIR_SEPARATOR_STR,
      "N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Using zonekey file `%s' \n", hostkey_file);
  privkey = GNUNET_CRYPTO_rsa_key_create_from_file(hostkey_file);
  GNUNET_free (hostkey_file);
  GNUNET_assert (privkey != NULL);
  GNUNET_CRYPTO_rsa_key_get_public(privkey, &pubkey);
  GNUNET_CRYPTO_short_hash (&pubkey, sizeof (pubkey), &zone);

  GNUNET_asprintf(&hostkey_file,"zonefiles%s%s",DIR_SEPARATOR_STR,
      "HGU0A0VCU334DN7F2I9UIUMVQMM7JMSD142LIMNUGTTV9R0CF4EG.zkey");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Using zonekey file `%s' \n", hostkey_file);
  privkey2 = GNUNET_CRYPTO_rsa_key_create_from_file(hostkey_file);
  GNUNET_free (hostkey_file);
  GNUNET_assert (privkey2 != NULL);
  GNUNET_CRYPTO_rsa_key_get_public(privkey2, &pubkey2);
  GNUNET_CRYPTO_short_hash (&pubkey2, sizeof (pubkey), &zone2);


  start_arm (cfgfile);
  GNUNET_assert (arm != NULL);

  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created record 1\n");

  GNUNET_asprintf(&s_name_1, "dummy1");
  s_rd_1 = create_record(1);
  sig_1 = GNUNET_NAMESTORE_create_signature(privkey, s_rd_1[0].expiration ,s_name_1, s_rd_1, 1);
  GNUNET_NAMESTORE_record_create(nsh, privkey, s_name_1, s_rd_1, &put_cont, NULL);


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created record 2 \n");
  GNUNET_asprintf(&s_name_2, "dummy2");
  s_rd_2 = create_record(1);

  sig_2 = GNUNET_NAMESTORE_create_signature(privkey, s_rd_2[0].expiration, s_name_2, s_rd_2, 1);
  GNUNET_NAMESTORE_record_create(nsh, privkey, s_name_2, s_rd_2, &put_cont, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created record 3\n");
  /* name in different zone */
  GNUNET_asprintf(&s_name_3, "dummy3");
  s_rd_3 = create_record(1);
  sig_3 = GNUNET_NAMESTORE_create_signature(privkey, s_rd_3[0].expiration, s_name_3, s_rd_3, 1);
  GNUNET_NAMESTORE_record_put (nsh, &pubkey2, s_name_3, GNUNET_TIME_UNIT_FOREVER_ABS, 1, s_rd_3, sig_3, &put_cont, NULL);
}

static int
check ()
{
  static char *const argv[] = { "test_namestore_api_zone_iteration",
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
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv, "test_namestore_api_zone_iteration",
                      "nohelp", options, &run, &res);
  return res;
}

int
main (int argc, char *argv[])
{
  int ret;

  ret = check ();

  return ret;
}

/* end of test_namestore_api_zone_iteration_specific_zone.c */
