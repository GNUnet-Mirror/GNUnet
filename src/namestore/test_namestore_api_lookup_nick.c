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
 * @file namestore/test_namestore_api_store.c
 * @brief testcase for namestore_api.c: store a record
 */
#include "platform.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"

#define TEST_RECORD_TYPE 1234

#define TEST_RECORD_DATALEN 123

#define TEST_NICK "gnunettestnick"

#define TEST_RECORD_DATA 'a'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static struct GNUNET_NAMESTORE_Handle *nsh;

static GNUNET_SCHEDULER_TaskIdentifier endbadly_task;

static struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey;

static struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;

static int res;

static struct GNUNET_GNSRECORD_Data rd_orig;

static struct GNUNET_NAMESTORE_QueueEntry *nsqe;

//static const char * name = "dummy.dummy.gnunet";
static const char * name = "d";

static char *directory;

static void
cleanup ()
{
  GNUNET_free_non_null ((void *)rd_orig.data);
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
 * @param tc scheduler context
 */
static void
endbadly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
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
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  cleanup ();
  res = 0;
}

void lookup_it (void *cls,
                const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                const char *label,
                unsigned int rd_count,
                const struct GNUNET_GNSRECORD_Data *rd)
{
  nsqe = NULL;
  int c;
  int found_record = GNUNET_NO;
  int found_nick = GNUNET_NO;

  if (0 != memcmp(privkey, zone, sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey)))
  {
    GNUNET_break(0);
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL );
    return;
  }

  if (NULL == label)
  {
    GNUNET_break(0);
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL );
    return;
  }

  if (0 != strcmp (label, name))
  {
    GNUNET_break(0);
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL );
    return;
  }

  if (2 != rd_count)
  {
    GNUNET_break(0);
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL );
    return;
  }

  for (c = 0; c < rd_count; c++)
  {
    if (GNUNET_GNSRECORD_TYPE_NICK == rd[c].record_type)
    {
      if (rd[c].data_size != strlen(TEST_NICK)+1)
      {
        GNUNET_break(0);
        GNUNET_SCHEDULER_cancel (endbadly_task);
        endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL );
        return;
      }
      if (0 != (rd[c].flags & GNUNET_GNSRECORD_RF_PRIVATE))
      {
        GNUNET_break(0);
        GNUNET_SCHEDULER_cancel (endbadly_task);
        endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL );
        return;
      }
      if (0 != strcmp(rd[c].data, TEST_NICK))
      {
        GNUNET_SCHEDULER_cancel (endbadly_task);
        endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL );
        return;
      }
      found_nick = GNUNET_YES;
    }
    else
    {
      if (rd[c].record_type != TEST_RECORD_TYPE)
      {
        GNUNET_break(0);
        GNUNET_SCHEDULER_cancel (endbadly_task);
        endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL );
        return;
      }
      if (rd[c].data_size != TEST_RECORD_DATALEN)
      {
        GNUNET_break(0);
        GNUNET_SCHEDULER_cancel (endbadly_task);
        endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL );
        return;
      }
      if (0 != memcmp (rd[c].data, rd_orig.data, TEST_RECORD_DATALEN))
      {
        GNUNET_break(0);
        GNUNET_SCHEDULER_cancel (endbadly_task);
        endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL );
        return;
      }
      if (rd[c].flags != rd->flags)
      {
        GNUNET_break(0);
        GNUNET_SCHEDULER_cancel (endbadly_task);
        endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL );
        return;
      }
      found_record = GNUNET_YES;
    }

  }

  /* Done */
  if ((GNUNET_YES == found_nick) && (GNUNET_YES == found_record))
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_SCHEDULER_add_now (&end, NULL );
  }
  else
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_SCHEDULER_add_now (&endbadly, NULL );
  }
}


static void
put_cont (void *cls, int32_t success, const char *emsg)
{
  const char *name = cls;

  nsqe = NULL;
  GNUNET_assert (NULL != cls);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Name store added record for `%s': %s\n",
	      name,
	      (success == GNUNET_OK) ? "SUCCESS" : "FAIL");

  if (GNUNET_OK != success)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    return;
  }
  /* Lookup */
  nsqe = GNUNET_NAMESTORE_records_lookup (nsh, privkey, name, lookup_it, NULL);
}

static void
nick_cont (void *cls, int32_t success, const char *emsg)
{
  const char *name = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Nick added : %s\n",
              (success == GNUNET_OK) ? "SUCCESS" : "FAIL");

  rd_orig.expiration_time = GNUNET_TIME_absolute_get().abs_value_us;
  rd_orig.record_type = TEST_RECORD_TYPE;
  rd_orig.data_size = TEST_RECORD_DATALEN;
  rd_orig.data = GNUNET_malloc (TEST_RECORD_DATALEN);
  rd_orig.flags = 0;
  memset ((char *) rd_orig.data, 'a', TEST_RECORD_DATALEN);

  nsqe = GNUNET_NAMESTORE_records_store (nsh, privkey, name,
                                      1, &rd_orig, &put_cont, (void *) name);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  char *hostkey_file;

  directory = NULL;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string(cfg, "PATHS", "GNUNET_TEST_HOME", &directory));
  GNUNET_DISK_directory_remove (directory);

  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
						&endbadly, NULL);
  GNUNET_asprintf (&hostkey_file,
		   "zonefiles%s%s",
		   DIR_SEPARATOR_STR,
		   "N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Using zonekey file `%s' \n", hostkey_file);
  privkey = GNUNET_CRYPTO_ecdsa_key_create_from_file (hostkey_file);
  GNUNET_free (hostkey_file);
  GNUNET_assert (privkey != NULL);
  GNUNET_CRYPTO_ecdsa_key_get_public (privkey, &pubkey);

  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);

  nsqe = GNUNET_NAMESTORE_set_nick (nsh, privkey, TEST_NICK, &nick_cont, (void *) name);
  if (NULL == nsqe)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
  	      _("Namestore cannot store no block\n"));
  }
}


int
main (int argc, char *argv[])
{
  res = 1;
  if (0 !=
      GNUNET_TESTING_peer_run ("test-namestore-api",
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


/* end of test_namestore_api_store.c */
