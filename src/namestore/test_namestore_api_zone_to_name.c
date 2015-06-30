/*
     This file is part of GNUnet.
     Copyright (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file namestore/test_namestore_api_zone_to_name.c
 * @brief testcase for zone to name translation
 */
#include "platform.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"
#include "namestore.h"

#define RECORDS 5

#define TEST_RECORD_TYPE 1234

#define TEST_RECORD_DATALEN 123

#define TEST_RECORD_DATA 'a'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)


static struct GNUNET_NAMESTORE_Handle * nsh;

static struct GNUNET_SCHEDULER_Task * endbadly_task;

static struct GNUNET_CRYPTO_EcdsaPrivateKey * privkey;

static struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;

static struct GNUNET_TIME_Absolute expire;

static struct GNUNET_CRYPTO_ShortHashCode s_zone;

static struct GNUNET_CRYPTO_ShortHashCode s_zone_value;

static char * s_name;

static struct GNUNET_CRYPTO_EcdsaSignature *s_signature;

static int res;

static char *directory;

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
    GNUNET_free (privkey);
  privkey = NULL;
  res = 1;
}


static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (endbadly_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = NULL;
  }
  if (privkey != NULL)
    GNUNET_free (privkey);
  privkey = NULL;
  if (nsh != NULL)
    GNUNET_NAMESTORE_disconnect (nsh);
  nsh = NULL;
}


static void
zone_to_name_proc (void *cls,
		   const struct GNUNET_CRYPTO_EcdsaPublicKey *zone_key,
		   struct GNUNET_TIME_Absolute expire,
		   const char *n,
		   unsigned int rd_count,
		   const struct GNUNET_GNSRECORD_Data *rd,
		   const struct GNUNET_CRYPTO_EcdsaSignature *signature)
{
  int fail = GNUNET_NO;

  if ((zone_key == NULL) && (n == NULL) && (rd_count == 0) && (rd == NULL) && (signature == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No result found\n");
    res = 1;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result found: `%s'\n", n);
    if ((n == NULL) || (0 != strcmp(n, s_name)))
    {
      fail = GNUNET_YES;
      GNUNET_break (0);
    }
    if (rd_count != 1)
    {
      fail = GNUNET_YES;
      GNUNET_break (0);
    }
    if ((zone_key == NULL) || (0 != memcmp (zone_key, &pubkey, sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey))))
    {
      fail = GNUNET_YES;
      GNUNET_break (0);
    }
    if (fail == GNUNET_NO)
      res = 0;
    else
      res = 1;
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

    /* create initial record */
    GNUNET_NAMESTORE_zone_to_name (nsh, &s_zone, &s_zone_value, zone_to_name_proc, NULL);

  }
  else
  {
    res = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to put records for name `%s'\n", name);
    GNUNET_SCHEDULER_add_now(&end, NULL);
  }
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_TIME_Absolute et;

  directory = NULL;
  GNUNET_CONFIGURATION_get_value_string(cfg, "PATHS", "GNUNET_TEST_HOME", &directory);
  GNUNET_DISK_directory_remove (directory);

  endbadly_task = GNUNET_SCHEDULER_add_delayed(TIMEOUT,endbadly, NULL);
  GNUNET_asprintf (&s_name, "dummy");
  /* load privat key */
  char *hostkey_file;
  GNUNET_asprintf(&hostkey_file,"zonefiles%s%s",DIR_SEPARATOR_STR,
      "N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Using zonekey file `%s'\n",
              hostkey_file);
  privkey = GNUNET_CRYPTO_ecdsa_key_create_from_file(hostkey_file);
  GNUNET_free (hostkey_file);
  GNUNET_assert (privkey != NULL);
  /* get public key */
  GNUNET_CRYPTO_ecdsa_key_get_public(privkey, &pubkey);

  /* zone hash */
  GNUNET_CRYPTO_short_hash (&pubkey, sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey), &s_zone);
  GNUNET_CRYPTO_short_hash (s_name, strlen (s_name) + 1, &s_zone_value);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Using PKEY `%s' \n",
              GNUNET_NAMESTORE_short_h2s (&s_zone_value));

  struct GNUNET_GNSRECORD_Data rd;
  rd.expiration_time = GNUNET_TIME_absolute_get().abs_value_us;
  rd.record_type = GNUNET_GNSRECORD_TYPE_PKEY;
  rd.data_size = sizeof (struct GNUNET_CRYPTO_ShortHashCode);
  rd.data = GNUNET_malloc(sizeof (struct GNUNET_CRYPTO_ShortHashCode));
  rd.flags = 0;
  memcpy ((char *) rd.data, &s_zone_value, sizeof (struct GNUNET_CRYPTO_ShortHashCode));
  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);

  expire = GNUNET_TIME_absolute_get ();
  et.abs_value_us = rd.expiration_time;
  s_signature = GNUNET_NAMESTORE_create_signature(privkey, et, s_name, &rd, 1);
  GNUNET_NAMESTORE_record_put(nsh, &pubkey, s_name, expire, 1, &rd, s_signature, put_cont, NULL);

  GNUNET_free ((void *) rd.data);
}



int
main (int argc, char *argv[])
{
  res = 1;
  if (0 !=
      GNUNET_TESTING_peer_run ("test-namestore-api-zone-to-name",
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

/* end of test_namestore_api_zone_to_name.c */
