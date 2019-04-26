/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2018 GNUnet e.V.

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
 * @file namestore/test_namestore_api_monitoring.c
 * @brief testcase for zone monitoring functionality: monitor first, then add records
 */
#include "platform.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"
#include "namestore.h"
#include "gnunet_dnsparser_lib.h"

#define TEST_RECORD_TYPE GNUNET_DNSPARSER_TYPE_TXT



#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)


static struct GNUNET_NAMESTORE_Handle * nsh;

static struct GNUNET_SCHEDULER_Task * endbadly_task;

static struct GNUNET_CRYPTO_EcdsaPrivateKey * privkey;

static struct GNUNET_CRYPTO_EcdsaPrivateKey * privkey2;

static struct GNUNET_NAMESTORE_ZoneMonitor *zm;

static int res;

static char * s_name_1;

static struct GNUNET_GNSRECORD_Data *s_rd_1;

static char * s_name_2;

static struct GNUNET_GNSRECORD_Data *s_rd_2;

static char * s_name_3;

static struct GNUNET_GNSRECORD_Data *s_rd_3;

struct GNUNET_NAMESTORE_QueueEntry * ns_ops[3];


static void
do_shutdown ()
{
  if (NULL != zm)
  {
    GNUNET_NAMESTORE_zone_monitor_stop (zm);
    zm = NULL;
  }
  if (NULL != ns_ops[0])
  {
  	GNUNET_NAMESTORE_cancel(ns_ops[0]);
  	ns_ops[0] = NULL;
  }
  if (NULL != ns_ops[1])
  {
  	GNUNET_NAMESTORE_cancel(ns_ops[1]);
  	ns_ops[1] = NULL;
  }
  if (NULL != ns_ops[2])
  {
  	GNUNET_NAMESTORE_cancel(ns_ops[2]);
  	ns_ops[2] = NULL;
  }
  if (NULL != nsh)
  {
    GNUNET_NAMESTORE_disconnect (nsh);
    nsh = NULL;
  }
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

  if (NULL != privkey)
  {
    GNUNET_free (privkey);
    privkey = NULL;
  }
  if (NULL != privkey2)
  {
    GNUNET_free (privkey2);
    privkey2 = NULL;
  }
}


/**
 * Re-establish the connection to the service.
 *
 * @param cls handle to use to re-connect.
 */
static void
endbadly (void *cls)
{
  do_shutdown ();
  res = 1;
}


static void
end (void *cls)
{
  do_shutdown ();
  res = 0;
}


static void
zone_proc (void *cls,
	   const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
	   const char *name,
	   unsigned int rd_count,
	   const struct GNUNET_GNSRECORD_Data *rd)
{
  static int returned_records;
  static int fail = GNUNET_NO;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Comparing results name %s\n",
	      name);
  if (0 != GNUNET_memcmp (zone_key,
                   privkey))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  	      "Monitoring returned wrong zone key\n");
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    return;
  }

  if (0 == strcmp (name, s_name_1))
  {
    if (GNUNET_YES != GNUNET_GNSRECORD_records_cmp(rd, s_rd_1))
    {
      GNUNET_break (0);
    	fail = GNUNET_YES;
    }
  }
  else if (0 == strcmp (name, s_name_2))
  {
    if (GNUNET_YES != GNUNET_GNSRECORD_records_cmp(rd, s_rd_2))
    {
      GNUNET_break (0);
    	fail = GNUNET_YES;
    }
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
  	      "Invalid name %s\n",
                name);
    GNUNET_break (0);
    fail = GNUNET_YES;
  }
  GNUNET_NAMESTORE_zone_monitor_next (zm,
                                      1);
  if (2 == ++returned_records)
  {
    if (endbadly_task != NULL)
    {
      GNUNET_SCHEDULER_cancel (endbadly_task);
      endbadly_task = NULL;
    }
    if (GNUNET_YES == fail)
      GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    else
    	GNUNET_SCHEDULER_add_now (&end, NULL);
  }
}


static void
put_cont (void *cls,
	  int32_t success,
	  const char *emsg)
{
  static int c = 0;
  char *label = cls;

  if (0 == strcmp (label, s_name_1))
    ns_ops[0] = NULL;
  else if (0 == strcmp (label, s_name_2))
    ns_ops[1] = NULL;
  else if (0 == strcmp (label, s_name_3))
    ns_ops[2] = NULL;

  if (success == GNUNET_OK)
  {
    c++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Created record %u: `%s'\n",
                c,
                label);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to create record `%s'\n",
		label);
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly,
					      NULL);
  }
}


static struct GNUNET_GNSRECORD_Data *
create_record (unsigned int count)
{
  struct GNUNET_GNSRECORD_Data *rd;

  rd = GNUNET_new_array (count,
                         struct GNUNET_GNSRECORD_Data);
  for (unsigned int c = 0; c < count; c++)
  {
    rd[c].expiration_time = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_HOURS).abs_value_us;
    rd[c].record_type = TEST_RECORD_TYPE;
    rd[c].data_size = 50;
    rd[c].data = GNUNET_malloc(50);
    rd[c].flags = 0;
    memset ((char *) rd[c].data, 'a', 50);
  }
  return rd;
}


static void
fail_cb (void *cls)
{
  GNUNET_assert (0);
}


static void
sync_cb (void *cls)
{
  /* do nothing */
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  res = 1;
  privkey = GNUNET_CRYPTO_ecdsa_key_create ();
  GNUNET_assert (privkey != NULL);

  /* Start monitoring */
  zm = GNUNET_NAMESTORE_zone_monitor_start (cfg,
                                            privkey,
                                            GNUNET_YES,
                                            &fail_cb,
                                            NULL,
					    &zone_proc,
					    NULL,
                                            &sync_cb,
					    NULL);
  if (NULL == zm)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to create zone monitor\n");
    GNUNET_break (0);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    return;
  }

  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &endbadly, NULL);
  /* Connect to namestore */
  nsh = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == nsh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Connect to namestore\n");
    GNUNET_break (0);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    return;
  }

  privkey2 = GNUNET_CRYPTO_ecdsa_key_create ();
  GNUNET_assert (privkey2 != NULL);


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Created record 3\n");
  /* name in different zone */
  GNUNET_asprintf(&s_name_3, "dummy3");
  s_rd_3 = create_record(1);
  GNUNET_assert (NULL != (ns_ops[2] =
			  GNUNET_NAMESTORE_records_store (nsh,
							  privkey2,
							  s_name_3,
							  1,
							  s_rd_3,
							  &put_cont,
							  s_name_3)));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Created record 1\n");
  GNUNET_asprintf(&s_name_1, "dummy1");
  s_rd_1 = create_record(1);
  GNUNET_assert (NULL != (ns_ops[0] =
                          GNUNET_NAMESTORE_records_store (nsh,
                                                          privkey,
                                                          s_name_1,
                                                          1,
                                                          s_rd_1,
                                                          &put_cont,
                                                          s_name_1)));


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created record 2 \n");
  GNUNET_asprintf(&s_name_2, "dummy2");
  s_rd_2 = create_record(1);
  GNUNET_assert (NULL != (ns_ops[1] =
                          GNUNET_NAMESTORE_records_store (nsh,
                                                          privkey,
                                                          s_name_2,
                                                          1,
                                                          s_rd_2,
                                                          &put_cont,
                                                          s_name_2)));
}


#include "test_common.c"


int
main (int argc,
      char *argv[])
{
  const char *plugin_name;
  char *cfg_name;

  SETUP_CFG (plugin_name, cfg_name);
  res = 1;
  if (0 !=
      GNUNET_TESTING_peer_run ("test-namestore-api-monitoring",
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


/* end of test_namestore_api_monitoring.c */
