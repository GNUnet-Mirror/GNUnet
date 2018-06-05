/*
     This file is part of GNUnet.
     Copyright (C) 2013 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/
/**
 * @file namestore/test_namestore_api.c
 * @brief testcase for namestore_api.c to: remove record
 */
#include "platform.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"
#include "gnunet_dnsparser_lib.h"

#define TEST_RECORD_TYPE GNUNET_DNSPARSER_TYPE_TXT

#define TEST_RECORD_DATALEN 123

#define TEST_RECORD_DATA 'a'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)


static struct GNUNET_NAMESTORE_Handle *nsh;

static struct GNUNET_SCHEDULER_Task * endbadly_task;

static struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey;

static struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;

static int res;

static int removed;

static struct GNUNET_NAMESTORE_QueueEntry *nsqe;


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
 */
static void
endbadly (void *cls)
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
end (void *cls)
{
  cleanup ();
  res = 0;
}


static void
remove_cont (void *cls,
	     int32_t success,
	     const char *emsg)
{
  nsqe = NULL;
  if (GNUNET_YES != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Records could not be removed: `%s'\n"),
                emsg);
    if (NULL != endbadly_task)
      GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task =  GNUNET_SCHEDULER_add_now (&endbadly,
                                               NULL);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Records were removed, perform lookup\n");
  removed = GNUNET_YES;
  if (NULL != endbadly_task)
    GNUNET_SCHEDULER_cancel (endbadly_task);
  GNUNET_SCHEDULER_add_now (&end, NULL);
}


static void
put_cont (void *cls,
          int32_t success,
	  const char *emsg)
{
  const char *name = cls;

  GNUNET_assert (NULL != cls);
  if (GNUNET_SYSERR == success)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Namestore could not store record: `%s'\n",
		emsg);
    if (endbadly_task != NULL)
      GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task =  GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Name store added record for `%s': %s\n",
	      name,
	      (success == GNUNET_OK) ? "SUCCESS" : "FAIL");
  nsqe = GNUNET_NAMESTORE_records_store (nsh,
                                         privkey,
                                         name,
					 0, NULL,
                                         &remove_cont, (void *) name);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_GNSRECORD_Data rd;
  const char * name = "dummy.dummy.gnunet";

  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
						&endbadly,
                                                NULL);
  privkey = GNUNET_CRYPTO_ecdsa_key_create ();
  GNUNET_assert (privkey != NULL);
  GNUNET_CRYPTO_ecdsa_key_get_public (privkey,
                                      &pubkey);

  removed = GNUNET_NO;

  rd.expiration_time = GNUNET_TIME_absolute_get().abs_value_us;
  rd.record_type = TEST_RECORD_TYPE;
  rd.data_size = TEST_RECORD_DATALEN;
  rd.data = GNUNET_malloc (TEST_RECORD_DATALEN);
  rd.flags = 0;
  memset ((char *) rd.data,
          'a',
          TEST_RECORD_DATALEN);

  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);
  nsqe = GNUNET_NAMESTORE_records_store (nsh,
                                         privkey,
                                         name,
                                         1,
                                         &rd,
                                         &put_cont,
                                         (void *) name);
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
  const char *plugin_name;
  char *cfg_name;

  plugin_name = GNUNET_TESTING_get_testname_from_underscore (argv[0]);
  GNUNET_asprintf (&cfg_name,
                   "test_namestore_api_%s.conf",
                   plugin_name);
  GNUNET_DISK_purge_cfg_dir (cfg_name,
                             "GNUNET_TEST_HOME");
  res = 1;
  if (0 !=
      GNUNET_TESTING_peer_run ("test-namestore-api-remove",
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

/* end of test_namestore_api_remove.c */
