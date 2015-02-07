/*
     This file is part of GNUnet.
     Copyright (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/test_ats_mlp.c
 * @brief test for the MLP solver
 * @author Christian Grothoff
 * @author Matthias Wachs

 */
/**
 * @file ats/test_ats_api_scheduling_add_address.c
 * @brief test for ats proportional solver preference aging:
 * 	Add 2 addresses and set high preference for one. Expect higher bw for this
 * 	address, wait. Preferences should age and so bw assigned should decrease.
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet_testing_lib.h"
#include "ats.h"
#include "test_ats_api_common.h"

#define DEBUG_ATS_INFO GNUNET_NO

static struct GNUNET_SCHEDULER_Task * die_task;

/**
 * Scheduling handle
 */
static struct GNUNET_ATS_SchedulingHandle *sched_ats;

/**
 * Connectivity handle
 */
static struct GNUNET_ATS_ConnectivityHandle *connect_ats;

/**
 * Performance handle
 */
static struct GNUNET_ATS_PerformanceHandle *perf_ats;

/**
 * Return value
 */
static int ret;

/**
 * Test address
 */
static struct Test_Address test_addr[2];

/**
 * Test peer
 */
static struct PeerContext p[2];

/**
 * Connectivity suggestion handles.
 */
static struct GNUNET_ATS_ConnectivitySuggestHandle *sh[2];

/**
 * HELLO address
 */
static struct GNUNET_HELLO_Address test_hello_address[2];

/**
 * Session
 */
static void *test_session[2];

/**
 * Test ats info
 */
static struct GNUNET_ATS_Information test_ats_info[2];

/**
 * Test ats count
 */
static uint32_t test_ats_count;

/**
 * Configured WAN out quota
 */
static unsigned long long wan_quota_out;

/**
 * Configured WAN in quota
 */
static unsigned long long wan_quota_in;


static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Error! Shutting down\n");
  if (sched_ats != NULL)
  {
    GNUNET_ATS_scheduling_done (sched_ats);
    sched_ats = NULL;
  }
  if (NULL != connect_ats)
  {
    GNUNET_ATS_connectivity_done (connect_ats);
    connect_ats = NULL;
  }
  if (perf_ats != NULL)
  {
    GNUNET_ATS_performance_done (perf_ats);
    perf_ats = NULL;
  }
  free_test_address (&test_addr[0]);
  ret = GNUNET_SYSERR;
}


static void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutting down\n");
  if (die_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = NULL;
  }

  GNUNET_ATS_connectivity_suggest_cancel (sh[0]);
  GNUNET_ATS_connectivity_suggest_cancel (sh[1]);

  if (NULL != sched_ats)
  	GNUNET_ATS_scheduling_done (sched_ats);
  if (NULL != perf_ats)
  GNUNET_ATS_performance_done (perf_ats);
  sched_ats = NULL;
  perf_ats = NULL;
  free_test_address (&test_addr[0]);
  free_test_address (&test_addr[1]);
}


static void
address_suggest_cb (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_HELLO_Address *address,
                    struct Session *session,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                    const struct GNUNET_ATS_Information *atsi,
                    uint32_t ats_count)
{
  static int stage = 0;
  static int sug_p0 = GNUNET_NO;
  static int sug_p1 = GNUNET_NO;

  static uint32_t p0_last_bandwidth_out;
  static uint32_t p0_last_bandwidth_in;

  static uint32_t p1_last_bandwidth_out;
  static uint32_t p1_last_bandwidth_in;

  uint32_t cur_bandwidth_out = ntohl (bandwidth_out.value__);
  uint32_t cur_bandwidth_in = ntohl (bandwidth_in.value__);

  if (0 == stage)
  {
    /* Callback for initial suggestion */
    if (0 == memcmp (&address->peer, &p[0].id, sizeof (p[0].id)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Stage %u: Callback for peer 0 `%s': (in/out) %u/%u\n",
                  stage,
                  GNUNET_i2s (&address->peer),
                  (unsigned int) ntohl (bandwidth_in.value__),
                  (unsigned int) ntohl (bandwidth_out.value__));
      sug_p0 = GNUNET_YES;
      p0_last_bandwidth_out = ntohl(bandwidth_out.value__);
      p0_last_bandwidth_in = ntohl(bandwidth_in.value__);
    }
    if (0 == memcmp (&address->peer, &p[1].id, sizeof (p[1].id)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Stage %u: Callback for peer 1 `%s': (in/out) %u/%u\n",
                  stage,
                  GNUNET_i2s (&address->peer),
                  (unsigned int) ntohl (bandwidth_in.value__),
                  (unsigned int) ntohl (bandwidth_out.value__));
      sug_p1 = GNUNET_YES;
      p1_last_bandwidth_out = ntohl(bandwidth_out.value__);
      p1_last_bandwidth_in = ntohl(bandwidth_in.value__);
    }
    if ((GNUNET_YES == sug_p0) && (GNUNET_YES == sug_p1))
    {
      /* Changing preference for peer 0 */
      stage ++;
      GNUNET_ATS_performance_change_preference (perf_ats, &p[0].id, GNUNET_ATS_PREFERENCE_BANDWIDTH,(double) 1000, GNUNET_ATS_PREFERENCE_END);
      sug_p0 = GNUNET_NO;
      sug_p1 = GNUNET_NO;
      return;
    }
  }
  if (1 == stage)
  {
    /* Callback due to preference change */
    if (0 == memcmp (&address->peer, &p[0].id, sizeof (p[0].id)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Stage %u: Callback for peer 0 `%s': (in/out) %u/%u\n",
                  stage,
                  GNUNET_i2s (&address->peer),
                  (unsigned int) ntohl (bandwidth_in.value__),
                  (unsigned int) ntohl (bandwidth_out.value__));
      sug_p0 = GNUNET_YES;

      /* Peer 0 should get more bandwidth */
      if (cur_bandwidth_out <= p0_last_bandwidth_out)
        GNUNET_break (0);
      if (cur_bandwidth_in <= p0_last_bandwidth_in)
        GNUNET_break (0);
      p0_last_bandwidth_out = ntohl(bandwidth_out.value__);
      p0_last_bandwidth_in = ntohl(bandwidth_in.value__);
    }
    if (0 == memcmp (&address->peer, &p[1].id, sizeof (p[1].id)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Stage %u: Callback for peer 1 `%s': (in/out) %u/%u\n",
                  stage,
                  GNUNET_i2s (&address->peer),
                  (unsigned int) ntohl (bandwidth_in.value__),
                  (unsigned int) ntohl (bandwidth_out.value__));
      sug_p1 = GNUNET_YES;

      /* Peer 1 should get less bandwidth */
      if (cur_bandwidth_out >= p1_last_bandwidth_out)
      {
        GNUNET_break (0);
        goto error;
      }
      if (cur_bandwidth_in >= p1_last_bandwidth_in)
      {
        GNUNET_break (0);
        goto error;
      }
      p1_last_bandwidth_out = ntohl(bandwidth_out.value__);
      p1_last_bandwidth_in = ntohl(bandwidth_in.value__);
    }
    if ((GNUNET_YES == sug_p0) && (GNUNET_YES == sug_p1))
    {
      stage ++;
      sug_p0 = GNUNET_NO;
      sug_p1 = GNUNET_NO;
      return;
    }
  }
  if (2 == stage)
  {
    /* Callback due to preference aging */
    if (0 == memcmp (&address->peer, &p[0].id, sizeof (p[0].id)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Stage %u: Callback for peer 0 `%s': (in/out) %u/%u\n",
                  stage,
                  GNUNET_i2s (&address->peer),
                  (unsigned int) ntohl (bandwidth_in.value__),
                  (unsigned int) ntohl (bandwidth_out.value__));
      sug_p0 = GNUNET_YES;

      /* Peer 0 should get less bandwidth */
      if (cur_bandwidth_out <= p0_last_bandwidth_out)
        GNUNET_break (0);
      if (cur_bandwidth_in <= p0_last_bandwidth_in)
        GNUNET_break (0);
      p0_last_bandwidth_out = ntohl(bandwidth_out.value__);
      p0_last_bandwidth_in = ntohl(bandwidth_in.value__);
    }
    if (0 == memcmp (&address->peer, &p[1].id, sizeof (p[1].id)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Stage %u: Callback for peer 1 `%s': (in/out) %u/%u\n",
                  stage,
                  GNUNET_i2s (&address->peer),
                  (unsigned int) ntohl (bandwidth_in.value__),
                  (unsigned int) ntohl (bandwidth_out.value__));
      sug_p1 = GNUNET_YES;
      /* Peer 1 should get more bandwidth */
      if (cur_bandwidth_out <= p1_last_bandwidth_out)
      {
        GNUNET_break (0);
        goto error;
      }
      if (cur_bandwidth_in <= p1_last_bandwidth_in)
      {
        GNUNET_break (0);
        goto error;
      }
      p0_last_bandwidth_out = ntohl(bandwidth_out.value__);
      p0_last_bandwidth_in = ntohl(bandwidth_in.value__);
    }

    if ((GNUNET_YES == sug_p0) && (GNUNET_YES == sug_p1))
    {
      /* Done ! */
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Done!\n");
      stage ++;
      ret = 0;
      GNUNET_SCHEDULER_add_now (&end,NULL);
      return;
    }
  }
  return;

error:
  /* Error ! */
  ret = 1;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Error!\n");
  GNUNET_SCHEDULER_add_now (&end,NULL);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  char *quota_str;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string(cfg, "ats", "WAN_QUOTA_OUT", &quota_str))
  {
      fprintf (stderr, "Cannot load WAN outbound quota from configuration, exit!\n");
      ret = 1;
      return;
  }
  if  (GNUNET_SYSERR == GNUNET_STRINGS_fancy_size_to_bytes (quota_str, &wan_quota_out))
  {
      fprintf (stderr, "Cannot load WAN outbound quota from configuration, exit!\n");
      ret = 1;
      GNUNET_free (quota_str);
      return;
  }
  GNUNET_free (quota_str);
  quota_str = NULL;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string(cfg, "ats", "WAN_QUOTA_IN", &quota_str))
  {
      fprintf (stderr, "Cannot load WAN inbound quota from configuration, exit!\n");
      ret = 1;
      return;
  }
  if  (GNUNET_SYSERR == GNUNET_STRINGS_fancy_size_to_bytes (quota_str, &wan_quota_in))
  {
      fprintf (stderr, "Cannot load WAN inbound quota from configuration, exit!\n");
      GNUNET_free (quota_str);
      ret = 1;
      return;
  }
  GNUNET_free (quota_str);
  quota_str = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Configured WAN inbound quota: %llu\n", wan_quota_in);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Configured WAN outbound quota: %llu\n", wan_quota_out);


  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  /* Connect to ATS scheduling */
  connect_ats = GNUNET_ATS_connectivity_init (mycfg);
  sched_ats = GNUNET_ATS_scheduling_init (cfg, &address_suggest_cb, NULL);
  if (sched_ats == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not connect to ATS scheduling!\n");
    ret = 1;
    end ();
    return;
  }

  /* Connect to ATS performance */
  perf_ats = GNUNET_ATS_performance_init(cfg, NULL, NULL);
  if (sched_ats == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not connect to ATS scheduling!\n");
    ret = 1;
    end ();
    return;
  }


  /* Set up peer 0 */
  if (GNUNET_SYSERR == GNUNET_CRYPTO_hash_from_string(PEERID0, &p[0].id.hashPubKey))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not setup peer!\n");
      ret = GNUNET_SYSERR;
      end ();
      return;
  }

  GNUNET_assert (0 == strcmp (PEERID0, GNUNET_i2s_full (&p[0].id)));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created peer `%s'\n",
              GNUNET_i2s(&p[0].id));

  /* Set up peer 1*/
  if (GNUNET_SYSERR == GNUNET_CRYPTO_hash_from_string(PEERID1, &p[1].id.hashPubKey))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not setup peer!\n");
      ret = GNUNET_SYSERR;
      end ();
      return;
  }

  GNUNET_assert (0 == strcmp (PEERID1, GNUNET_i2s_full (&p[1].id)));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created peer `%s'\n",
              GNUNET_i2s(&p[1].id));

  /* Prepare ATS Information */
  test_ats_info[0].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  test_ats_info[0].value = htonl(GNUNET_ATS_NET_WAN);
  test_ats_info[1].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  test_ats_info[1].value = htonl(1);
  test_ats_count = 2;

  /* Peer 0: Adding address with session */
  test_session[0] = &test_addr[0];
  create_test_address (&test_addr[0], "test0", test_session[0], "test0", strlen ("test0") + 1);
  test_hello_address[0].peer = p[0].id;
  test_hello_address[0].transport_name = test_addr[0].plugin;
  test_hello_address[0].address = test_addr[0].addr;
  test_hello_address[0].address_length = test_addr[0].addr_len;
  GNUNET_ATS_address_add (sched_ats, &test_hello_address[0], test_session[0], test_ats_info, test_ats_count);

  /* Peer 1: Adding address with session */
  test_session[1] = &test_addr[1];
  create_test_address (&test_addr[1], "test1", test_session[1], "test1", strlen ("test1") + 1);
  test_hello_address[1].peer = p[1].id;
  test_hello_address[1].transport_name = test_addr[1].plugin;
  test_hello_address[1].address = test_addr[1].addr;
  test_hello_address[1].address_length = test_addr[1].addr_len;
  GNUNET_ATS_address_add (sched_ats, &test_hello_address[1], test_session[1], test_ats_info, test_ats_count);

  sh[0] = GNUNET_ATS_connectivity_suggest (connect_ats, &p[0].id);
  sh[1] = GNUNET_ATS_connectivity_suggest (connect_ats, &p[1].id);
}


int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test_ats_proportional_pref_aging",
                                    "test_ats_api.conf",
                                    &run, NULL))
    return 1;
  return ret;
}


/* end of file test_ats_simplistic_pref_aging.c */
