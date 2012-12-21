/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/test_ats_api_performance.c
 * @brief test adding addresses in automatic transport selection performance API
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet_testing_lib.h"
#include "ats.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static GNUNET_SCHEDULER_TaskIdentifier die_task;

struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_ATS_SchedulingHandle *atsh;
static struct GNUNET_ATS_PerformanceHandle *ph;
struct GNUNET_ATS_AddressListHandle* phal;

static int ret;

struct Address
{
  char *plugin;
  size_t plugin_len;

  void *addr;
  size_t addr_len;

  struct GNUNET_ATS_Information *ats;
  int ats_count;

  void *session;
};

struct PeerContext
{
  struct GNUNET_PeerIdentity id;

  struct Address *addr;
};



static struct PeerContext p[2];

static struct Address p0_addresses[2];
static struct Address p1_addresses[2];

struct GNUNET_HELLO_Address p0_ha[2];
struct GNUNET_HELLO_Address p1_ha[2];
struct GNUNET_HELLO_Address *s_ha[2];

static unsigned int stage = 0;

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Timeout in stage %u\n", stage);

  if (NULL != atsh)
  GNUNET_ATS_scheduling_done (atsh);
  if (phal != NULL)
    GNUNET_ATS_performance_list_addresses_cancel (phal);
  phal = NULL;
  if (ph != NULL)
    GNUNET_ATS_performance_done (ph);
  ph = NULL;

  GNUNET_free_non_null (p0_addresses[0].addr);
  GNUNET_free_non_null (p0_addresses[1].addr);
  GNUNET_free_non_null (p1_addresses[0].addr);
  GNUNET_free_non_null (p1_addresses[1].addr);

  ret = GNUNET_SYSERR;
}


static void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutting down\n");
  if (die_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != atsh)
  GNUNET_ATS_scheduling_done (atsh);
  if (phal != NULL)
    GNUNET_ATS_performance_list_addresses_cancel (phal);
  phal = NULL;
  if (ph != NULL)
    GNUNET_ATS_performance_done (ph);
  ph = NULL;

  GNUNET_free_non_null (p0_addresses[0].addr);
  GNUNET_free_non_null (p0_addresses[1].addr);
  GNUNET_free_non_null (p1_addresses[0].addr);
  GNUNET_free_non_null (p1_addresses[1].addr);

  ret = 0;
}

static void
test_performance_api (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

void all_active_addresses_peer_cb (void *cls,
                      const struct
                      GNUNET_HELLO_Address *
                      address,
                      struct
                      GNUNET_BANDWIDTH_Value32NBO
                      bandwidth_out,
                      struct
                      GNUNET_BANDWIDTH_Value32NBO
                      bandwidth_in,
                      const struct
                      GNUNET_ATS_Information *
                      ats, uint32_t ats_count)
{
  static int cb = 0;
  int fail = GNUNET_NO;

  if (address != NULL)
  {
    if (0 == memcmp (&address->peer, &p[0].id,
                     sizeof (struct GNUNET_PeerIdentity)))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
            "Did not expected callback for peer 0 address `%s', got address `%s'!\n",
            s_ha[0]->address, address->address);
        GNUNET_ATS_performance_list_addresses_cancel (phal);
        fail = GNUNET_YES;
    }

    if (0 == memcmp (&address->peer, &p[1].id,
                     sizeof (struct GNUNET_PeerIdentity)))
    {
        if (0 == strcmp(address->address, s_ha[1]->address))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Callback for peer 1 suggested address %s\n",
              s_ha[1]->address);
          cb ++;
        }
        else
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Expected callback for peer 1 address `%s', got address `%s'!\n",
              s_ha[1]->address, address->address);
          GNUNET_ATS_performance_list_addresses_cancel (phal);
          fail = GNUNET_YES;
        }
    }
  }
  if ((address == NULL) || (GNUNET_YES == fail))
  {
      phal = NULL;
      if ((1 == cb) && (GNUNET_NO == fail))
      {
        /* Received all addresses + terminator cb, next stage */
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Stage %i:  SUCCESS\n", stage);
        GNUNET_SCHEDULER_add_now (&test_performance_api, NULL);
        return;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %i:  FAIL\n", stage);
        GNUNET_SCHEDULER_add_now (&end, NULL);
        ret = 5;
        return;
      }
  }
}

void all_active_addresses_cb (void *cls,
                      const struct
                      GNUNET_HELLO_Address *
                      address,
                      struct
                      GNUNET_BANDWIDTH_Value32NBO
                      bandwidth_out,
                      struct
                      GNUNET_BANDWIDTH_Value32NBO
                      bandwidth_in,
                      const struct
                      GNUNET_ATS_Information *
                      ats, uint32_t ats_count)
{
  static int cb = 0;
  int fail = GNUNET_NO;

  if (address != NULL)
  {
    if (0 == memcmp (&address->peer, &p[0].id,
                     sizeof (struct GNUNET_PeerIdentity)))
    {
        if (0 == strcmp(address->address, s_ha[0]->address))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Callback for peer 0 suggested address %s\n",
              s_ha[0]->address);
          cb ++;
        }
        else
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Expected callback for peer 0 address `%s', got address `%s'!\n",
              s_ha[0]->address, address->address);
          GNUNET_ATS_performance_list_addresses_cancel (phal);
          fail = GNUNET_YES;
        }
    }

    if (0 == memcmp (&address->peer, &p[1].id,
                     sizeof (struct GNUNET_PeerIdentity)))
    {
        if (0 == strcmp(address->address, s_ha[1]->address))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Callback for peer 1 suggested address %s\n",
              s_ha[1]->address);
          cb ++;
        }
        else
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Expected callback for peer 1 address `%s', got address `%s'!\n",
              s_ha[1]->address, address->address);
          GNUNET_ATS_performance_list_addresses_cancel (phal);
          fail = GNUNET_YES;
        }
    }
  }
  if ((address == NULL) || (GNUNET_YES == fail))
  {
      phal = NULL;
      if ((2 == cb) && (GNUNET_NO == fail))
      {
        /* Received all addresses + terminator cb, next stage */
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Stage %i:  SUCCESS\n", stage);
        GNUNET_SCHEDULER_add_now (&test_performance_api, NULL);
        return;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %i:  FAIL\n", stage);
        GNUNET_SCHEDULER_add_now (&end, NULL);
        ret = 5;
        return;
      }
  }
}



void all_addresses_peer_cb (void *cls,
                      const struct
                      GNUNET_HELLO_Address *
                      address,
                      struct
                      GNUNET_BANDWIDTH_Value32NBO
                      bandwidth_out,
                      struct
                      GNUNET_BANDWIDTH_Value32NBO
                      bandwidth_in,
                      const struct
                      GNUNET_ATS_Information *
                      ats, uint32_t ats_count)
{
  static int cb = 0;
  int fail = GNUNET_NO;

  if (address != NULL)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
          "Callback for peer `%s'  address `%s'\n",
           GNUNET_i2s (&address->peer), address->address);

    if (0 != memcmp (&address->peer, &p[1].id,
                     sizeof (struct GNUNET_PeerIdentity)))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
            "Stage %i:  Received address for wrong peer\n", stage);
        GNUNET_ATS_performance_list_addresses_cancel (phal);
        fail = GNUNET_YES;
        ret = 4;
    }
    cb ++;
  }

  if ((NULL == address) || (fail))
  {
      phal = NULL;
      if ((2 == cb) && (GNUNET_NO == fail))
      {
        /* Received all addresses + terminator cb, next stage */
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Stage %i:  SUCCESS\n", stage);
        GNUNET_SCHEDULER_add_now (&test_performance_api, NULL);
        return;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %i:  FAIL\n", stage);
        GNUNET_SCHEDULER_add_now (&end, NULL);
        ret = 5;
        return;
      }
  }
}

void all_addresses_cb (void *cls,
                              const struct
                              GNUNET_HELLO_Address *
                              address,
                              struct
                              GNUNET_BANDWIDTH_Value32NBO
                              bandwidth_out,
                              struct
                              GNUNET_BANDWIDTH_Value32NBO
                              bandwidth_in,
                              const struct
                              GNUNET_ATS_Information *
                              ats, uint32_t ats_count)
{
  static int cb = 0;

  if (address != NULL)
  {
    if (0 == memcmp (&address->peer, &p[0].id,
                     sizeof (struct GNUNET_PeerIdentity)))
    {
      if (0 == strcmp(address->address, p0_addresses[0].addr))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Callback for peer 0 address 0\n");
        cb |= 1;
      }
      if (0 == strcmp(address->address, p0_addresses[1].addr))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Callback for peer 0 address 1\n");
        cb |= 2;
      }
    }
    if (0 == memcmp (&address->peer, &p[1].id,
                     sizeof (struct GNUNET_PeerIdentity)))
    {
        if (0 == strcmp(address->address, p1_addresses[0].addr))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Callback for peer 1 address 0\n");
          cb |= 4;
        }
        if (0 == strcmp(address->address, p1_addresses[1].addr))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Callback for peer 1 address 1\n");
          cb |= 8;
        }
    }
  }
  else
  {
      phal = NULL;
      if (((1 << 4) - 1) == cb)
      {
        /* Received all addresses + terminator cb, next stage */
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Stage %i:  SUCCESS\n", stage);
        GNUNET_SCHEDULER_add_now (&test_performance_api, NULL);
        return;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %i:  FAIL\n", stage);
        GNUNET_SCHEDULER_add_now (&end, NULL);
        ret = 3;
        return;
      }
  }
}

static void
test_performance_api (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL == ph)
    ph = GNUNET_ATS_performance_init (cfg, NULL, NULL);
  if (NULL == ph)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to initialize performance handle\n");
      ret = 2;
  }
  stage++;
  switch (stage) {
    case 1: /* Get all peers, all addresses */
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Run stage 1: \n");
      phal = GNUNET_ATS_performance_list_addresses (ph,
                                             NULL,
                                             GNUNET_YES,
                                             &all_addresses_cb, NULL);
      GNUNET_assert (NULL != phal);
      break;
    case 2: /* Get specific peer, all addresses */
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Run stage 2: \n");
      phal = GNUNET_ATS_performance_list_addresses (ph,
                                             &p[1].id,
                                             GNUNET_YES,
                                             &all_addresses_peer_cb, NULL);
      GNUNET_assert (NULL != phal);
      break;
    case 3: /* Get all peers, active addresses */
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Run stage 3: \n");
      phal = GNUNET_ATS_performance_list_addresses (ph,
                                             NULL,
                                             GNUNET_NO,
                                             &all_active_addresses_cb, NULL);
      GNUNET_assert (NULL != phal);
      break;
    case 4: /* Get specific peers, active addresses */
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Run stage 4: \n");
      phal = GNUNET_ATS_performance_list_addresses (ph,
                                             &p[1].id,
                                             GNUNET_NO,
                                             &all_active_addresses_peer_cb, NULL);
      GNUNET_assert (NULL != phal);
      break;
    default:
      /* done */
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "All tests successful, shutdown... \n");
      GNUNET_SCHEDULER_add_now (&end, NULL);
      return;
  }
}


static void
address_suggest_cb (void *cls, const struct GNUNET_HELLO_Address *address,
                    struct Session *session,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                    const struct GNUNET_ATS_Information *ats,
                    uint32_t ats_count)
{
  static int suggest_p0 = GNUNET_NO;
  static int suggest_p1 = GNUNET_NO;
  static int running = GNUNET_NO;

  if ((GNUNET_NO == suggest_p0) && (0 == memcmp (&address->peer, &p[0].id,
                   sizeof (struct GNUNET_PeerIdentity))))
  {
    suggest_p0 = GNUNET_YES;;

    if (s_ha[0] != NULL)
      GNUNET_free (s_ha[0]);
    s_ha[0] = GNUNET_HELLO_address_copy (address);
    GNUNET_ATS_suggest_address_cancel (atsh, &p[0].id);
  }
  if ((GNUNET_NO == suggest_p1) && (0 == memcmp (&address->peer, &p[1].id,
                   sizeof (struct GNUNET_PeerIdentity))))
  {
    suggest_p1 = GNUNET_YES;

    if (s_ha[1] != NULL)
      GNUNET_free (s_ha[1]);
    s_ha[1] = GNUNET_HELLO_address_copy (address);
    GNUNET_ATS_suggest_address_cancel (atsh, &p[1].id);
  }


  if ((GNUNET_NO == running) && (GNUNET_YES == suggest_p0) && (GNUNET_YES == suggest_p1))
  {
      running = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Have address suggestion for both peers\n");
      GNUNET_SCHEDULER_add_now (&test_performance_api, NULL);
  }

}


static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *mycfg,
     struct GNUNET_TESTING_Peer *peer)
{
  ret = 1;
  cfg = (struct GNUNET_CONFIGURATION_Handle *) mycfg;
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);


  /* set up peer 0 */
  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK,
                                    &p[0].id.hashPubKey);

  p0_addresses[0].plugin = "test";
  p0_addresses[0].session = NULL;
  p0_addresses[0].addr = GNUNET_strdup ("test_p0_a0");
  p0_addresses[0].addr_len = strlen (p0_addresses[0].addr) + 1;

  p0_ha[0].address = p0_addresses[0].addr;
  p0_ha[0].address_length = p0_addresses[0].addr_len;
  p0_ha[0].peer = p[0].id;
  p0_ha[0].transport_name = p0_addresses[0].plugin;

  p0_addresses[1].plugin = "test";
  p0_addresses[1].session = NULL;
  p0_addresses[1].addr = GNUNET_strdup ("test_p0_a1");
  p0_addresses[1].addr_len = strlen(p0_addresses[1].addr) + 1;

  p0_ha[1].address = p0_addresses[1].addr;
  p0_ha[1].address_length = p0_addresses[1].addr_len;
  p0_ha[1].peer = p[0].id;
  p0_ha[1].transport_name = p0_addresses[1].plugin;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created peer 0: `%s'\n",
              GNUNET_i2s (&p[0].id));

  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK,
                                    &p[1].id.hashPubKey);

  p1_addresses[0].plugin = "test";
  p1_addresses[0].session = NULL;
  p1_addresses[0].addr = GNUNET_strdup ("test_p1_a0");
  p1_addresses[0].addr_len = strlen(p1_addresses[0].addr) + 1;

  p1_ha[0].address = p1_addresses[0].addr;
  p1_ha[0].address_length = p1_addresses[0].addr_len;
  p1_ha[0].peer = p[1].id;
  p1_ha[0].transport_name = p1_addresses[0].plugin;

  p1_addresses[1].plugin = "test";
  p1_addresses[1].session = NULL;
  p1_addresses[1].addr = GNUNET_strdup ("test_p1_a1");
  p1_addresses[1].addr_len = strlen(p1_addresses[1].addr) + 1;

  p1_ha[1].address = p1_addresses[1].addr;
  p1_ha[1].address_length = p1_addresses[1].addr_len;
  p1_ha[1].peer = p[1].id;
  p1_ha[1].transport_name = p1_addresses[1].plugin;


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created peer 1: `%s'\n",
              GNUNET_i2s (&p[1].id));


  /* Add addresses */
  atsh = GNUNET_ATS_scheduling_init (cfg, &address_suggest_cb, NULL);
  if (atsh == NULL)
  {
    ret = GNUNET_SYSERR;
    end ();
    return;
  }

  GNUNET_ATS_address_add (atsh, &p0_ha[0], NULL, NULL, 0);
  GNUNET_ATS_address_add (atsh, &p0_ha[1], NULL, NULL, 0);

  GNUNET_ATS_address_add (atsh, &p1_ha[0], NULL, NULL, 0);
  GNUNET_ATS_address_add (atsh, &p1_ha[1], NULL, NULL, 0);


  GNUNET_ATS_suggest_address (atsh, &p[0].id);
  GNUNET_ATS_suggest_address (atsh, &p[1].id);
}


int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test_ats_api_performance",
				    "test_ats_api.conf",
				    &run, NULL))
    return 1;
  return ret;
}

/* end of file test_ats_api_performance.c */
