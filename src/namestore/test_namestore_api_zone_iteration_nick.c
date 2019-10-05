/*
     This file is part of GNUnet.
     Copyright (C) 2013 GNUnet e.V.

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
 * @file namestore/test_namestore_api_zone_iteration.c
 * @brief testcase for zone iteration functionality: iterate all zones
 */
#include "platform.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"
#include "namestore.h"
#include "gnunet_dnsparser_lib.h"

#define TEST_RECORD_TYPE GNUNET_DNSPARSER_TYPE_TXT

#define ZONE_NICK_1 "nick1"
#define ZONE_NICK_2 "nick2"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)


static struct GNUNET_NAMESTORE_Handle *nsh;

static struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey;

static struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey2;

static struct GNUNET_NAMESTORE_ZoneIterator *zi;

static int res;

static int returned_records;

static char *s_name_1;

static struct GNUNET_GNSRECORD_Data *s_rd_1;

static char *s_name_2;

static struct GNUNET_GNSRECORD_Data *s_rd_2;

static char *s_name_3;

static struct GNUNET_GNSRECORD_Data *s_rd_3;

static struct GNUNET_NAMESTORE_QueueEntry *nsqe;


/**
 * Re-establish the connection to the service.
 *
 * @param cls handle to use to re-connect.
 * @param tc scheduler context
 */
static void
end (void *cls)
{
  if (NULL != zi)
  {
    GNUNET_NAMESTORE_zone_iteration_stop (zi);
    zi = NULL;
  }
  if (nsh != NULL)
  {
    GNUNET_NAMESTORE_disconnect (nsh);
    nsh = NULL;
  }
  GNUNET_free_non_null (s_name_1);
  GNUNET_free_non_null (s_name_2);
  GNUNET_free_non_null (s_name_3);

  if (s_rd_1 != NULL)
  {
    GNUNET_free ((void *) s_rd_1->data);
    GNUNET_free (s_rd_1);
  }
  if (s_rd_2 != NULL)
  {
    GNUNET_free ((void *) s_rd_2->data);
    GNUNET_free (s_rd_2);
  }
  if (s_rd_3 != NULL)
  {
    GNUNET_free ((void *) s_rd_3->data);
    GNUNET_free (s_rd_3);
  }

  if (privkey != NULL)
  {
    GNUNET_free (privkey);
    privkey = NULL;
  }
  if (privkey2 != NULL)
  {
    GNUNET_free (privkey2);
    privkey2 = NULL;
  }
}


static int
check_zone_1 (const char *label, unsigned int rd_count,
              const struct GNUNET_GNSRECORD_Data *rd)
{
  for (unsigned int c = 0; c < rd_count; c++)
  {
    if ((rd[c].record_type == GNUNET_GNSRECORD_TYPE_NICK) &&
        (0 != strcmp (rd[c].data, ZONE_NICK_1)))
    {
      GNUNET_break (0);
      return GNUNET_YES;
    }
  }
  return GNUNET_NO;
}


static int
check_zone_2 (const char *label,
              unsigned int rd_count,
              const struct GNUNET_GNSRECORD_Data *rd)
{
  for (unsigned int c = 0; c < rd_count; c++)
  {
    if ((rd[c].record_type == GNUNET_GNSRECORD_TYPE_NICK) &&
        (0 != strcmp (rd[c].data, ZONE_NICK_2)))
    {
      GNUNET_break (0);
      return GNUNET_YES;
    }
  }
  return GNUNET_NO;
}


static void
zone_proc_end (void *cls)
{
  zi = NULL;
  res = 0;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received last result, iteration done after receing %u results\n",
              returned_records);
  GNUNET_SCHEDULER_shutdown ();
}


static void
zone_proc (void *cls,
           const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
           const char *label,
           unsigned int rd_count,
           const struct GNUNET_GNSRECORD_Data *rd)
{
  int failed = GNUNET_NO;

  GNUNET_assert (NULL != zone);
  if (0 == GNUNET_memcmp (zone, privkey))
  {
    failed = check_zone_1 (label, rd_count, rd);
    if (GNUNET_YES == failed)
      GNUNET_break (0);
  }
  else if (0 == GNUNET_memcmp (zone, privkey2))
  {
    failed = check_zone_2 (label, rd_count, rd);
    if (GNUNET_YES == failed)
      GNUNET_break (0);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Received invalid zone\n");
    failed = GNUNET_YES;
    GNUNET_break (0);
  }

  if (failed == GNUNET_NO)
  {
    returned_records++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Telling namestore to send the next result\n");
    GNUNET_NAMESTORE_zone_iterator_next (zi,
                                         1);
  }
  else
  {
    GNUNET_break (0);
    res = 1;
    GNUNET_SCHEDULER_shutdown ();
  }
}


static void
fail_cb (void *cls)
{
  GNUNET_assert (0);
}


static void
put_cont (void *cls,
          int32_t success,
          const char *emsg)
{
  static int c = 0;

  if (success == GNUNET_OK)
  {
    c++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created record %u \n", c);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to created records: `%s'\n",
                emsg);
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (c == 3)
  {
    res = 1;
    returned_records = 0;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All records created, starting iteration over all zones \n");
    zi = GNUNET_NAMESTORE_zone_iteration_start (nsh,
                                                NULL,
                                                &fail_cb,
                                                NULL,
                                                &zone_proc,
                                                NULL,
                                                &zone_proc_end,
                                                NULL);
    if (zi == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to create zone iterator\n");
      GNUNET_break (0);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
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
    rd[c].expiration_time = GNUNET_TIME_relative_to_absolute (
      GNUNET_TIME_UNIT_HOURS).abs_value_us;
    rd[c].record_type = TEST_RECORD_TYPE;
    rd[c].data_size = 50;
    rd[c].data = GNUNET_malloc (50);
    rd[c].flags = 0;
    memset ((char *) rd[c].data, 'a', 50);
  }
  return rd;
}


static void
nick_2_cont (void *cls,
             int32_t success,
             const char *emsg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Nick added : %s\n",
              (success == GNUNET_OK) ? "SUCCESS" : "FAIL");

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created record 1\n");

  GNUNET_asprintf (&s_name_1, "dummy1");
  s_rd_1 = create_record (1);
  GNUNET_NAMESTORE_records_store (nsh, privkey, s_name_1,
                                  1, s_rd_1,
                                  &put_cont, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Created record 2 \n");
  GNUNET_asprintf (&s_name_2, "dummy2");
  s_rd_2 = create_record (1);
  GNUNET_NAMESTORE_records_store (nsh, privkey, s_name_2,
                                  1, s_rd_2, &put_cont, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Created record 3\n");

  /* name in different zone */
  GNUNET_asprintf (&s_name_3, "dummy3");
  s_rd_3 = create_record (1);
  GNUNET_NAMESTORE_records_store (nsh, privkey2, s_name_3,
                                  1, s_rd_3,
                                  &put_cont, NULL);
}


static void
nick_1_cont (void *cls, int32_t success, const char *emsg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Nick 1 added : %s\n",
              (success == GNUNET_OK) ? "SUCCESS" : "FAIL");

  nsqe = GNUNET_NAMESTORE_set_nick (nsh, privkey2, ZONE_NICK_2, &nick_2_cont,
                                    &privkey2);
  if (NULL == nsqe)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Namestore cannot store no block\n"));
  }
}


/**
 * Callback called from the zone iterator when we iterate over
 * the empty zone.  Check that we got no records and then
 * start the actual tests by filling the zone.
 */
static void
empty_zone_proc (void *cls,
                 const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                 const char *label,
                 unsigned int rd_count,
                 const struct GNUNET_GNSRECORD_Data *rd)
{
  GNUNET_assert (nsh == cls);

  if (NULL != zone)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Expected empty zone but received zone private key\n"));
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if ((NULL != label) || (NULL != rd) || (0 != rd_count))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Expected no zone content but received data\n"));
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_assert (0);
}


static void
empty_zone_end (void *cls)
{
  GNUNET_assert (nsh == cls);
  zi = NULL;
  privkey = GNUNET_CRYPTO_ecdsa_key_create ();
  GNUNET_assert (privkey != NULL);
  privkey2 = GNUNET_CRYPTO_ecdsa_key_create ();
  GNUNET_assert (privkey2 != NULL);

  nsqe = GNUNET_NAMESTORE_set_nick (nsh,
                                    privkey,
                                    ZONE_NICK_1,
                                    &nick_1_cont,
                                    &privkey);
  if (NULL == nsqe)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Namestore cannot store no block\n"));
  }
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);
  GNUNET_SCHEDULER_add_shutdown (&end,
                                 NULL);
  /* first, iterate over empty namestore */
  zi = GNUNET_NAMESTORE_zone_iteration_start (nsh,
                                              NULL,
                                              &fail_cb,
                                              NULL,
                                              &empty_zone_proc,
                                              nsh,
                                              &empty_zone_end,
                                              nsh);
  if (NULL == zi)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to create zone iterator\n");
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
  }
}


#include "test_common.c"


int
main (int argc, char *argv[])
{
  const char *plugin_name;
  char *cfg_name;

  SETUP_CFG (plugin_name, cfg_name);
  res = 1;
  if (0 !=
      GNUNET_TESTING_peer_run ("test-namestore-api-zone-iteration-nick",
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


/* end of test_namestore_api_zone_iteration.c */
