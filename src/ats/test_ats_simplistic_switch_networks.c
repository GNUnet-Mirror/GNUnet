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
 * @file ats/test_ats_api_scheduling_update_address.c
 * @brief test updating networtk type of an address
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet_testing_lib.h"
#include "ats.h"
#include "test_ats_api_common.h"

#define BIG_M_STRING "unlimited"


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
static struct Test_Address test_addr;

/**
 * Test peer
 */
static struct PeerContext p;

/**
 * HELLO test address
 */

struct GNUNET_HELLO_Address test_hello_address;

/**
 * Test session
 */
static void *test_session;

/**
 * Test ats info
 */
struct GNUNET_ATS_Information test_ats_info[3];

/**
 * Test ats count
 */
uint32_t test_ats_count;

unsigned long long int quota_out[GNUNET_ATS_NetworkTypeCount];
unsigned long long int quota_in[GNUNET_ATS_NetworkTypeCount];

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;

  if (sched_ats != NULL)
    GNUNET_ATS_scheduling_done (sched_ats);
  free_test_address (&test_addr);
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
  free_test_address (&test_addr);
}

static uint32_t
find_ats_value (const struct GNUNET_ATS_Information *atsi,
                uint32_t ats_count,
                uint32_t value)
{
  int c;
  for (c = 0; c < ats_count; c ++)
  {
      if (ntohl(atsi[c].type) == value)
          return ntohl (atsi[c].value);
  }
  GNUNET_break (0);
  return UINT32_MAX;
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
  int level;
  char *text;
  if (0 == stage)
  {
    GNUNET_ATS_suggest_address_cancel (sched_ats, &p.id);
    if (GNUNET_OK == compare_addresses(address, session, &test_hello_address, test_session))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Callback for correct address `%s'\n",
                  stage, GNUNET_i2s (&address->peer));
      ret = 0;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: Callback with incorrect address `%s'\n",
                  stage, GNUNET_i2s (&address->peer));
      ret = 1;
      GNUNET_SCHEDULER_add_now (&end, NULL);
      return;
    }

    if (GNUNET_OK != compare_ats(atsi, ats_count, test_ats_info, test_ats_count))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: Callback with incorrect ats info \n", stage);
      ret = 1;
      GNUNET_SCHEDULER_add_now (&end, NULL);
      return;
    }

    if (ntohl(bandwidth_out.value__) == quota_out[GNUNET_ATS_NET_WAN])
    {
        level = GNUNET_ERROR_TYPE_DEBUG;
        text =  "correct";
        ret = 0;
    }
    else
    {
        level = GNUNET_ERROR_TYPE_ERROR;
        text = "wrong";
        ret = 1;
    }

    GNUNET_log (level, "Stage %u: WAN outbound quota out %s: Received %llu, configured %llu\n",
        stage,
        text,
        (unsigned long long int) ntohl(bandwidth_out.value__),
        quota_out[GNUNET_ATS_NET_WAN]);

    if (ntohl(bandwidth_in.value__) == quota_in[GNUNET_ATS_NET_WAN])
    {
        level = GNUNET_ERROR_TYPE_DEBUG;
        text =  "correct";
        ret = 0;
    }
    else
    {
        level = GNUNET_ERROR_TYPE_ERROR;
        text = "wrong";
        ret = 1;
    }

    GNUNET_log (level, "Stage %u: WAN inbound quota out %s: Received %llu, configured %llu\n",
        stage,
        text,
        (unsigned long long int) ntohl(bandwidth_out.value__),
        quota_out[GNUNET_ATS_NET_WAN]);

    if (GNUNET_ATS_NET_WAN != find_ats_value (atsi, ats_count, GNUNET_ATS_NETWORK_TYPE))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: Incorrect network type, exptected %s, got %s \n",
            stage,
            GNUNET_ATS_print_network_type(GNUNET_ATS_NET_WAN),
            GNUNET_ATS_print_network_type(find_ats_value (atsi, ats_count, GNUNET_ATS_NETWORK_TYPE)));
        ret = 1;
    }

    if (1 == ret)
    {
        GNUNET_SCHEDULER_add_now (&end, NULL);
        return;
    }

    /* Update address */
    /* Prepare ATS Information: change network */
    test_ats_info[0].type = htonl (GNUNET_ATS_NETWORK_TYPE);
    test_ats_info[0].value = htonl(GNUNET_ATS_NET_LAN);
    test_ats_info[1].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
    test_ats_info[1].value = htonl(3);
    test_ats_info[1].type = htonl (GNUNET_ATS_QUALITY_NET_DELAY);
    test_ats_info[1].value = htonl(30);
    test_ats_count = 2;

    GNUNET_ATS_address_update (sched_ats, &test_hello_address, test_session, test_ats_info, test_ats_count);

    /* Request address */
    GNUNET_ATS_suggest_address (sched_ats, &p.id);
    stage ++;
  }
  else if (1 == stage)
  {
      GNUNET_ATS_suggest_address_cancel (sched_ats, &p.id);
      if (GNUNET_OK == compare_addresses(address, session, &test_hello_address, test_session))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Callback with correct address `%s'\n", stage,
                    GNUNET_i2s (&address->peer));
        ret = 0;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: Callback with incorrect address `%s'\n", stage,
                    GNUNET_i2s (&address->peer));
        ret = 1;
      }

      if (GNUNET_OK != compare_ats(atsi, ats_count, test_ats_info, test_ats_count))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: Callback with incorrect ats info \n");
        ret = 1;
        GNUNET_SCHEDULER_add_now (&end, NULL);
        return;
      }

      if (ntohl(bandwidth_out.value__) == quota_out[GNUNET_ATS_NET_LAN])
      {
          level = GNUNET_ERROR_TYPE_DEBUG;
          text =  "correct";
          ret = 0;
      }
      else
      {
          level = GNUNET_ERROR_TYPE_ERROR;
          text = "wrong";
          ret = 1;
      }

      GNUNET_log (level, "Stage %u: LAN outbound quota out %s: Received %llu, configured %llu\n",
          stage,
          text,
          (unsigned long long int) ntohl(bandwidth_out.value__),
          quota_out[GNUNET_ATS_NET_LAN]);

      if (ntohl(bandwidth_in.value__) == quota_in[GNUNET_ATS_NET_LAN])
        {
            level = GNUNET_ERROR_TYPE_DEBUG;
            text =  "correct";
            ret = 0;
        }
        else
        {
            level = GNUNET_ERROR_TYPE_ERROR;
            text = "wrong";
            ret = 1;
        }

        GNUNET_log (level, "Stage %u: LAN inbound quota out %s: Received %llu, configured %llu\n",
            stage,
            text,
            (unsigned long long int) ntohl(bandwidth_out.value__),
            quota_out[GNUNET_ATS_NET_LAN]);

        if (GNUNET_ATS_NET_LAN != find_ats_value (atsi, ats_count, GNUNET_ATS_NETWORK_TYPE))
        {
            GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: Incorrect network type, exptected %s, got %s \n",
                stage,
                GNUNET_ATS_print_network_type(GNUNET_ATS_NET_LAN),
                GNUNET_ATS_print_network_type(find_ats_value (atsi, ats_count, GNUNET_ATS_NETWORK_TYPE)));
            ret = 1;
        }

      GNUNET_SCHEDULER_add_now (&end, NULL);
  }
}

static unsigned int
load_quotas (const struct GNUNET_CONFIGURATION_Handle *cfg, unsigned long long *out_dest, unsigned long long *in_dest, int dest_length)
{
  int quotas[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkType;
  char * entry_in = NULL;
  char * entry_out = NULL;
  char * quota_out_str;
  char * quota_in_str;
  int c;

  for (c = 0; (c < GNUNET_ATS_NetworkTypeCount) && (c < dest_length); c++)
  {
    in_dest[c] = 0;
    out_dest[c] = 0;
    switch (quotas[c]) {
      case GNUNET_ATS_NET_UNSPECIFIED:
        entry_out = "UNSPECIFIED_QUOTA_OUT";
        entry_in = "UNSPECIFIED_QUOTA_IN";
        break;
      case GNUNET_ATS_NET_LOOPBACK:
        entry_out = "LOOPBACK_QUOTA_OUT";
        entry_in = "LOOPBACK_QUOTA_IN";
        break;
      case GNUNET_ATS_NET_LAN:
        entry_out = "LAN_QUOTA_OUT";
        entry_in = "LAN_QUOTA_IN";
        break;
      case GNUNET_ATS_NET_WAN:
        entry_out = "WAN_QUOTA_OUT";
        entry_in = "WAN_QUOTA_IN";
        break;
      case GNUNET_ATS_NET_WLAN:
        entry_out = "WLAN_QUOTA_OUT";
        entry_in = "WLAN_QUOTA_IN";
        break;
      default:
        break;
    }

    if ((entry_in == NULL) || (entry_out == NULL))
      continue;

    /* quota out */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", entry_out, &quota_out_str))
    {
      if (0 == strcmp(quota_out_str, BIG_M_STRING) ||
          (GNUNET_SYSERR == GNUNET_STRINGS_fancy_size_to_bytes (quota_out_str, &out_dest[c])))
        out_dest[c] = UINT32_MAX;

      GNUNET_free (quota_out_str);
      quota_out_str = NULL;
    }
    else if (GNUNET_ATS_NET_UNSPECIFIED == quotas[c])
      out_dest[c] = UINT32_MAX;
    else
      out_dest[c] = UINT32_MAX;

    /* quota in */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", entry_in, &quota_in_str))
    {
      if (0 == strcmp(quota_in_str, BIG_M_STRING) ||
          (GNUNET_SYSERR == GNUNET_STRINGS_fancy_size_to_bytes (quota_in_str, &in_dest[c])))
        in_dest[c] = UINT32_MAX;

      GNUNET_free (quota_in_str);
      quota_in_str = NULL;
    }
    else if (GNUNET_ATS_NET_UNSPECIFIED == quotas[c])
    {
      in_dest[c] = UINT32_MAX;
    }
    else
    {
        in_dest[c] = UINT32_MAX;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Loaded quota: %s %u, %s %u\n", entry_in, in_dest[c], entry_out, out_dest[c]);

  }
  return GNUNET_ATS_NetworkTypeCount;
}

static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  load_quotas (cfg, quota_out, quota_in, GNUNET_ATS_NetworkTypeCount);

  /* Connect to ATS scheduling */
  sched_ats = GNUNET_ATS_scheduling_init (cfg, &address_suggest_cb, NULL);
  if (sched_ats == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not connect to ATS scheduling!\n");
    ret = 1;
    end ();
    return;
  }

  /* Set up peer */
  if (GNUNET_SYSERR == GNUNET_CRYPTO_hash_from_string(PEERID0, &p.id.hashPubKey))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not setup peer!\n");
      ret = GNUNET_SYSERR;
      end ();
      return;
  }

  GNUNET_assert (0 == strcmp (PEERID0, GNUNET_i2s_full (&p.id)));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created peer `%s'\n",
              GNUNET_i2s_full(&p.id));

  /* Prepare ATS Information */
  test_ats_info[0].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  test_ats_info[0].value = htonl(GNUNET_ATS_NET_WAN);
  test_ats_info[1].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  test_ats_info[1].value = htonl(1);
  test_ats_info[1].type = htonl (GNUNET_ATS_QUALITY_NET_DELAY);
  test_ats_info[1].value = htonl(10);
  test_ats_count = 2;

  /* Adding address without session */
  test_session = &test_addr;
  create_test_address (&test_addr, "test", &test_addr, "test", strlen ("test") + 1);
  test_hello_address.peer = p.id;
  test_hello_address.transport_name = test_addr.plugin;
  test_hello_address.address = test_addr.addr;
  test_hello_address.address_length = test_addr.addr_len;
  GNUNET_ATS_address_add (sched_ats, &test_hello_address, test_session, test_ats_info, test_ats_count);

  /* Request address */
  GNUNET_ATS_suggest_address (sched_ats, &p.id);
}


int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test_ats_api_scheduling_update_address",
                                    "test_ats_api.conf",
                                    &run, NULL))
    return 1;
  return ret;
}

/* end of file test_ats_api_scheduling_update_address.c */
