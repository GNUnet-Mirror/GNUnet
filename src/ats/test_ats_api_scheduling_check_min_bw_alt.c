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
 * @file ats/test_ats_mlp.c
 * @brief test for the MLP solver
 * @author Christian Grothoff
 * @author Matthias Wachs

 */
/**
 * @file ats/test_ats_api_scheduling_check_min_bw_alt.c
 * @brief alternative suggestion on network change if no bw is available
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet_testing_lib.h"
#include "ats.h"
#include "test_ats_api_common.h"

#define DEBUG_ATS_INFO GNUNET_NO

static GNUNET_SCHEDULER_TaskIdentifier die_task;

/**
 * Scheduling handle
 */
static struct GNUNET_ATS_SchedulingHandle *sched_ats;

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
 * HELLO address
 */
struct GNUNET_HELLO_Address test_hello_address[2];

/**
 * Session
 */
static void *test_session[2];

/**
 * Test ats info
 */
struct GNUNET_ATS_Information test_ats_info[2][2];

/**
 * Test ats count
 */
uint32_t test_ats_count;

/**
 * Configured WAN out quota
 */
unsigned long long wan_quota_out;

/**
 * Configured WAN in quota
 */
unsigned long long wan_quota_in;


static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;

  if (sched_ats != NULL)
    GNUNET_ATS_scheduling_done (sched_ats);
  free_test_address (&test_addr[0]);
  free_test_address (&test_addr[1]);
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
  GNUNET_ATS_scheduling_done (sched_ats);
  sched_ats = NULL;
  free_test_address (&test_addr[0]);
  free_test_address (&test_addr[1]);
}


static void
address_suggest_cb (void *cls, const struct GNUNET_HELLO_Address *address,
                    struct Session *session,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                    const struct GNUNET_ATS_Information *atsi,
                    uint32_t ats_count)
{
  static int stage = 0;
  unsigned int bw_in = ntohl(bandwidth_in.value__);
  unsigned int bw_out = ntohl(bandwidth_out.value__);

  if (0 == stage)
  {
    /* Initial suggestion for 1st address */
    if (GNUNET_OK == compare_addresses (address, session, &test_hello_address[0], test_session[0]))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Callback with correct address `%s'\n",
                    stage, GNUNET_i2s (&address->peer));
        ret = 0;
    }
    else
    {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Callback with invalid address `%s'\n",
            stage, GNUNET_i2s (&address->peer));
        ret = 1;
    }

    if (GNUNET_OK != compare_ats(atsi, ats_count, test_ats_info[0], test_ats_count))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: Callback with incorrect ats info \n");
      ret = 1;
    }

    if (bw_in > wan_quota_in)
    {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: Suggested WAN inbound quota %u bigger than allowed quota %llu \n",
            stage, bw_in, wan_quota_in);
        ret = 1;
    }
    else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Suggested WAN inbound quota %u, allowed quota %llu \n",
          stage, bw_in, wan_quota_in);

    if (bw_out > wan_quota_out)
    {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: Suggested WAN outbound quota %u bigger than allowed quota %llu \n",
            stage, bw_out, wan_quota_out);
        ret = 1;
    }
    else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Suggested WAN outbound quota %u, allowed quota %llu \n",
          stage, bw_out, wan_quota_out);

    if (1 == ret)
    {
      GNUNET_ATS_suggest_address_cancel (sched_ats, &p[0].id);
      GNUNET_SCHEDULER_add_now (&end, NULL);
      return;
    }

    p[0].bw_out_assigned = bw_out;
    p[0].bw_in_assigned = bw_in;
    stage ++;

    /* Add a 2nd address to give ATS an suggestion alternative */
    /* Prepare ATS Information */
    test_ats_info[1][0].type = htonl (GNUNET_ATS_NETWORK_TYPE);
    test_ats_info[1][0].value = htonl(GNUNET_ATS_NET_LAN);
    test_ats_info[1][1].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
    test_ats_info[1][1].value = htonl(1);
    test_ats_count = 2;

    /* Adding address with session */
    test_session[1] = &test_addr[1];
    create_test_address (&test_addr[1], "test1", test_session[1], "test1", strlen ("test1") + 1);
    test_hello_address[1].peer = p[0].id;
    test_hello_address[1].transport_name = test_addr[1].plugin;
    test_hello_address[1].address = test_addr[1].addr;
    test_hello_address[1].address_length = test_addr[1].addr_len;
    GNUNET_ATS_address_add (sched_ats, &test_hello_address[1], test_session[1],
        test_ats_info[1], test_ats_count);


    /* Changing 1st address to network with now bw available (WLAN) */
    test_ats_info[0][0].type = htonl (GNUNET_ATS_NETWORK_TYPE);
    test_ats_info[0][0].value = htonl(GNUNET_ATS_NET_WLAN);
    test_ats_info[0][1].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
    test_ats_info[0][1].value = htonl(1);
    test_ats_count = 2;

    GNUNET_ATS_address_update (sched_ats, &test_hello_address[0], test_session[0],
        test_ats_info[0], test_ats_count);
    return;
  }
  if (1 == stage)
  {
    /* Bandwidth update to (in/out) 0/0 for 1st address */
    if (GNUNET_OK == compare_addresses (address, session, &test_hello_address[0], test_session[0]))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Callback with correct address `%s'\n",
                    stage, GNUNET_i2s (&address->peer));
        ret = 0;
    }
    else
    {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Callback with invalid address `%s'\n",
            stage, GNUNET_i2s (&address->peer));
        ret = 1;
    }

    if (GNUNET_OK != compare_ats(atsi, ats_count, test_ats_info[0], test_ats_count))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: Callback with incorrect ats info \n");
      ret = 1;
    }

    if ((bw_in != 0) || (bw_out != 0))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: ATS did not set bandwidth to 0 but instead to %u/%u \n",
            stage, bw_in, wan_quota_in);
        ret = 1;
    }

    if (1 == ret)
    {
      GNUNET_ATS_suggest_address_cancel (sched_ats, &p[0].id);
      GNUNET_SCHEDULER_add_now (&end, NULL);
      return;
    }
    p[0].bw_out_assigned = bw_out;
    p[0].bw_in_assigned = bw_in;
    stage ++;
    return;
  }
  if (2 == stage)
  {
    /* Expecting suggestion of alternative 2nd address*/
    if (GNUNET_OK == compare_addresses (address, session, &test_hello_address[1], test_session[1]))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Callback with correct address `%s'\n",
                    stage, GNUNET_i2s (&address->peer));
        ret = 0;
    }
    else
    {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Callback with invalid address `%s'\n",
            stage, GNUNET_i2s (&address->peer));
        ret = 1;
    }

    if (GNUNET_OK != compare_ats(atsi, ats_count, test_ats_info[1], test_ats_count))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: Callback with incorrect ats info \n",
          stage);
      ret = 1;
    }

    if ((bw_in == 0) || (bw_out == 0))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: ATS did not set bandwidth correctly \n",
            stage);
        ret = 1;
    }

    if (1 == ret)
    {
      GNUNET_ATS_suggest_address_cancel (sched_ats, &p[0].id);
      GNUNET_SCHEDULER_add_now (&end, NULL);
      return;
    }

    GNUNET_ATS_suggest_address_cancel (sched_ats, &p[0].id);
    GNUNET_SCHEDULER_add_now (&end, NULL);
    ret = 0;
    return;
  }
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
  sched_ats = GNUNET_ATS_scheduling_init (cfg, &address_suggest_cb, NULL);
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
  test_ats_info[0][0].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  test_ats_info[0][0].value = htonl(GNUNET_ATS_NET_WAN);
  test_ats_info[0][1].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  test_ats_info[0][1].value = htonl(1);
  test_ats_count = 2;

  /* Adding address with session */
  test_session[0] = &test_addr[0];
  create_test_address (&test_addr[0], "test0", test_session[0], "test0", strlen ("test0") + 1);
  test_hello_address[0].peer = p[0].id;
  test_hello_address[0].transport_name = test_addr[0].plugin;
  test_hello_address[0].address = test_addr[0].addr;
  test_hello_address[0].address_length = test_addr[0].addr_len;
  GNUNET_ATS_address_add (sched_ats, &test_hello_address[0], test_session[0],
      test_ats_info[0], test_ats_count);

  GNUNET_ATS_suggest_address (sched_ats, &p[0].id);
}


int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test_ats_api_scheduling_check_min_bw_alt",
                                    "test_ats_api.conf",
                                    &run, NULL))
    return 1;
  return ret;
}


/* end of file test_ats_api_scheduling_check_min_bw_alt.c */
