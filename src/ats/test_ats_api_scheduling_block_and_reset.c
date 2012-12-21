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
 * @file ats/test_ats_api_scheduling_reset_backoff.c
 * @brief test case for blocking suggests and blocking reset API
 *        measure duration of initial suggest, measure blocking duration,
 *        reset block, measure suggest, compare time
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet_testing_lib.h"
#include "ats.h"
#include "test_ats_api_common.h"

#define WAIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 10)

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static GNUNET_SCHEDULER_TaskIdentifier wait_task;

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
 * HELLO address
 */
struct GNUNET_HELLO_Address test_hello_address;

/**
 * Session
 */
static void *test_session;

/**
 * Test ats info
 */
struct GNUNET_ATS_Information test_ats_info[2];

/**
 * Test ats count
 */
uint32_t test_ats_count;


struct GNUNET_TIME_Absolute initial_start;

struct GNUNET_TIME_Relative initial_duration;

/**
 * Blocking start
 */
struct GNUNET_TIME_Absolute block_start;

struct GNUNET_TIME_Relative block_duration;

struct GNUNET_TIME_Absolute reset_block_start;

struct GNUNET_TIME_Relative reset_block_duration;

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;
  if (wait_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (wait_task);
    wait_task = GNUNET_SCHEDULER_NO_TASK;
  }
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
  if (wait_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (wait_task);
    wait_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_ATS_scheduling_done (sched_ats);
  sched_ats = NULL;
  free_test_address (&test_addr);
}

static void
request_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  wait_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_ATS_suggest_address (sched_ats, &p.id);
  wait_task = GNUNET_SCHEDULER_add_delayed (WAIT, &request_task, NULL);
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

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Stage %u\n", stage);
  if (3 == stage)
  {
      /* Suggestion after resetting block interval */
      reset_block_duration = GNUNET_TIME_absolute_get_difference(reset_block_start, GNUNET_TIME_absolute_get());
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Address suggestion after resetting blocking took about %llu ms!\n",
                  (long long unsigned int) reset_block_duration.rel_value);
      if ((block_duration.rel_value <= (initial_duration.rel_value * 3)) ||
          (initial_duration.rel_value <= (block_duration.rel_value * 3)))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "Address suggestion after resetting blocking (%llu ms) took about the same as initial suggestion (%llu ms)\n",
                    (long long unsigned int) reset_block_duration.rel_value,
                    (long long unsigned int) initial_duration.rel_value);
        ret = 0;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Address suggestion after resetting blocking (%llu ms) has too big difference to initial suggestion (%llu ms)\n",
                    (long long unsigned int) reset_block_duration.rel_value,
                    (long long unsigned int) initial_duration.rel_value);
        ret = 1;
        GNUNET_ATS_suggest_address_cancel (sched_ats, &p.id);
        GNUNET_SCHEDULER_add_now (&end, NULL);
        return;
      }

      if (((initial_duration.rel_value * 3) <= block_duration.rel_value ) &&
          ((reset_block_duration.rel_value * 3) <= block_duration.rel_value))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Address suggestion after resetting blocking (%llu ms) and initial suggestion (%llu ms) much faster than with blocking (%llu ms)\n",
                    (long long unsigned int) reset_block_duration.rel_value,
                    (long long unsigned int) initial_duration.rel_value,
                    (long long unsigned int) block_duration.rel_value);
        ret = 0;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Address suggestion after resetting blocking (%llu ms) and initial suggestion (%llu ms) not faster than with blocking (%llu ms)\n",
                    (long long unsigned int) reset_block_duration.rel_value,
                    (long long unsigned int) initial_duration.rel_value,
                    (long long unsigned int) block_duration.rel_value);
        ret = 1;
      }


      GNUNET_ATS_suggest_address_cancel (sched_ats, &p.id);
      GNUNET_SCHEDULER_add_now (&end, NULL);

  }
  if (2 == stage)
  {
      /* Suggestion after block*/
      block_duration = GNUNET_TIME_absolute_get_difference(block_start, GNUNET_TIME_absolute_get());
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Address suggestion was blocked for about %llu ms!\n",
                  (long long unsigned int) block_duration.rel_value);

      if (GNUNET_OK == compare_addresses (address, session, &test_hello_address, test_session))
      {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Callback with correct address `%s'\n", stage,
                      GNUNET_i2s (&address->peer));
          ret = 0;
      }
      else
      {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Callback with invalid address `%s'\n", stage,
                      GNUNET_i2s (&address->peer));
          GNUNET_ATS_suggest_address_cancel (sched_ats, &p.id);
          GNUNET_SCHEDULER_add_now (&end, NULL);
          ret = 1;
      }

      if (GNUNET_OK != compare_ats(atsi, ats_count, test_ats_info, test_ats_count))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: Callback with incorrect ats info \n");
        GNUNET_ATS_suggest_address_cancel (sched_ats, &p.id);
        GNUNET_SCHEDULER_add_now (&end, NULL);
        ret = 1;
      }
      stage ++;

      /* Reset block interval */
      GNUNET_ATS_reset_backoff (sched_ats, &address->peer);
      reset_block_start = GNUNET_TIME_absolute_get();
      GNUNET_ATS_suggest_address (sched_ats, &p.id);
  }
  if (1 == stage)
  {
    /* Initial suggestion */
    if (GNUNET_OK == compare_addresses (address, session, &test_hello_address, test_session))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Callback with correct address `%s'\n", stage,
                    GNUNET_i2s (&address->peer));
        ret = 0;
    }
    else
    {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Callback with invalid address `%s'\n", stage,
                    GNUNET_i2s (&address->peer));
        GNUNET_ATS_suggest_address_cancel (sched_ats, &p.id);
        GNUNET_SCHEDULER_add_now (&end, NULL);
        ret = 1;
    }

    if (GNUNET_OK != compare_ats(atsi, ats_count, test_ats_info, test_ats_count))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: Callback with incorrect ats info \n");
      GNUNET_ATS_suggest_address_cancel (sched_ats, &p.id);
      GNUNET_SCHEDULER_add_now (&end, NULL);
      ret = 1;
    }
    stage ++;
    initial_duration = GNUNET_TIME_absolute_get_difference(initial_start, GNUNET_TIME_absolute_get());
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Stage %u: Initial suggestion took about %llu ms\n", stage,
                (long long unsigned int) block_duration.rel_value);

    block_start = GNUNET_TIME_absolute_get();
    wait_task = GNUNET_SCHEDULER_add_delayed (WAIT, &request_task, NULL);
  }
  if (0 == stage)
  {
    /* Startup suggestion */
    if (GNUNET_OK == compare_addresses (address, session, &test_hello_address, test_session))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Callback with correct address `%s'\n", stage,
                    GNUNET_i2s (&address->peer));
        ret = 0;
    }
    else
    {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: Callback with invalid address `%s'\n", stage,
                    GNUNET_i2s (&address->peer));
        GNUNET_ATS_suggest_address_cancel (sched_ats, &p.id);
        GNUNET_SCHEDULER_add_now (&end, NULL);
        ret = 1;
    }

    if (GNUNET_OK != compare_ats(atsi, ats_count, test_ats_info, test_ats_count))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage %u: Callback with incorrect ats info \n");
      GNUNET_ATS_suggest_address_cancel (sched_ats, &p.id);
      GNUNET_SCHEDULER_add_now (&end, NULL);
      ret = 1;
    }
    stage ++;

    GNUNET_ATS_suggest_address_cancel (sched_ats, &p.id);

    initial_start = GNUNET_TIME_absolute_get();
    GNUNET_ATS_suggest_address (sched_ats, &p.id);
  }
}


static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{

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
  test_ats_count = 2;

  /* Adding address without session */
  test_session = &test_addr;
  create_test_address (&test_addr, "test", test_session, "test", strlen ("test") + 1);
  test_hello_address.peer = p.id;
  test_hello_address.transport_name = test_addr.plugin;
  test_hello_address.address = test_addr.addr;
  test_hello_address.address_length = test_addr.addr_len;
  GNUNET_ATS_address_add (sched_ats, &test_hello_address, test_session, test_ats_info, test_ats_count);

  initial_start = GNUNET_TIME_absolute_get();
  GNUNET_ATS_suggest_address (sched_ats, &p.id);
}


int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test_ats_api_scheduling_add_address",
                                    "test_ats_api.conf",
                                    &run, NULL))
    return 1;
  return ret;
}
/* end of file test_ats_api_scheduling_reset_backoff.c */
