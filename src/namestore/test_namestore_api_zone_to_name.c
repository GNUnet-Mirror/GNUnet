/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
 * @file namestore/test_namestore_api_zone_to_name.c
 * @brief testcase for zone to name translation
 */
#include "platform.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"
#include "namestore.h"
#include "gnunet_dnsparser_lib.h"

#define TEST_RECORD_TYPE GNUNET_DNSPARSER_TYPE_TXT

#define RECORDS 5

#define TEST_RECORD_DATALEN 123

#define TEST_RECORD_DATA 'a'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)


static struct GNUNET_NAMESTORE_Handle *nsh;

static struct GNUNET_SCHEDULER_Task *endbadly_task;

static struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey;

static struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;

static struct GNUNET_CRYPTO_EcdsaPublicKey s_zone_value;

static char * s_name;

static int res;

static struct GNUNET_NAMESTORE_QueueEntry *qe;


/**
 * Re-establish the connection to the service.
 *
 * @param cls handle to use to re-connect.
 */
static void
endbadly (void *cls)
{
  (void) cls;
  GNUNET_SCHEDULER_shutdown ();
  res = 1;
}


static void
end (void *cls)
{
  if (NULL != qe)
  {
    GNUNET_NAMESTORE_cancel (qe);
    qe = NULL;
  }
  if (NULL != endbadly_task)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = NULL;
  }
  if (NULL != privkey)
  {
    GNUNET_free (privkey);
    privkey = NULL;
  }
  if (NULL != nsh)
  {
    GNUNET_NAMESTORE_disconnect (nsh);
    nsh = NULL;
  }
}


static void
zone_to_name_proc (void *cls,
		   const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
		   const char *n,
		   unsigned int rd_count,
		   const struct GNUNET_GNSRECORD_Data *rd)
{
  int fail = GNUNET_NO;

  qe = NULL;
  if ( (NULL == zone_key) &&
       (NULL == n) &&
       (0 == rd_count) &&
       (NULL == rd) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"No result found\n");
    res = 1;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Result found: `%s'\n",
		n);
    if ( (NULL == n) ||
	 (0 != strcmp (n,
		       s_name)))
    {
      fail = GNUNET_YES;
      GNUNET_break (0);
    }
    if (1 != rd_count)
    {
      fail = GNUNET_YES;
      GNUNET_break (0);
    }
    if ( (NULL == zone_key) ||
	 (0 != memcmp (zone_key,
		       privkey,
		       sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey))))
    {
      fail = GNUNET_YES;
      GNUNET_break (0);
    }
    if (fail == GNUNET_NO)
      res = 0;
    else
      res = 1;
  }
  GNUNET_SCHEDULER_add_now (&end,
			    NULL);
}


static void
error_cb (void *cls)
{
  (void) cls;
  qe = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
	      "Not found!\n");
  GNUNET_SCHEDULER_shutdown ();
  res = 2;
}


static void
put_cont (void *cls,
	  int32_t success,
	  const char *emsg)
{
  char *name = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Name store added record for `%s': %s\n",
	      name,
	      (success == GNUNET_OK) ? "SUCCESS" : emsg);
  if (success == GNUNET_OK)
  {
    res = 0;

    qe = GNUNET_NAMESTORE_zone_to_name (nsh,
					privkey,
					&s_zone_value,
					&error_cb,
					NULL,
					&zone_to_name_proc,
					NULL);
  }
  else
  {
    res = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to put records for name `%s'\n",
		name);
    GNUNET_SCHEDULER_add_now (&end,
			      NULL);
  }
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  (void) cls;
  (void) peer;
  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
						&endbadly,
						NULL);
  GNUNET_SCHEDULER_add_shutdown (&end,
				 NULL);
  GNUNET_asprintf (&s_name, "dummy");
  privkey = GNUNET_CRYPTO_ecdsa_key_create ();
  GNUNET_assert (NULL != privkey);
  /* get public key */
  GNUNET_CRYPTO_ecdsa_key_get_public (privkey,
				      &pubkey);

  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
			      &s_zone_value,
			      sizeof (s_zone_value));
  {
    struct GNUNET_GNSRECORD_Data rd;

    rd.expiration_time = GNUNET_TIME_absolute_get().abs_value_us;
    rd.record_type = GNUNET_GNSRECORD_TYPE_PKEY;
    rd.data_size = sizeof (s_zone_value);
    rd.data = &s_zone_value;
    rd.flags = 0;

    nsh = GNUNET_NAMESTORE_connect (cfg);
    GNUNET_break (NULL != nsh);
    GNUNET_NAMESTORE_records_store (nsh,
				    privkey,
				    s_name,
				    1,
				    &rd,
				    &put_cont,
				    NULL);
  }
}


#include "test_common.c"


int
main (int argc,
      char *argv[])
{
  const char *plugin_name;
  char *cfg_name;

  (void) argc;
  SETUP_CFG (plugin_name, cfg_name);
  res = 1;
  if (0 !=
      GNUNET_TESTING_peer_run ("test-namestore-api-zone-to-name",
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

/* end of test_namestore_api_zone_to_name.c */
