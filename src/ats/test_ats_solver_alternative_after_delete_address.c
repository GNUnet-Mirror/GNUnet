/*
 This file is part of GNUnet.
 (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file ats/test_ats_solver_add_address.c
 * @brief solver test:  add 2 addresses, request address, delete, expect alternative
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_ats_service.h"
#include "test_ats_api_common.h"

/**
 * Timeout task
 */
static GNUNET_SCHEDULER_TaskIdentifier die_task;

/**
 * Statistics handle
 */
struct GNUNET_STATISTICS_Handle *stats;

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
 * Alternative test address
 */
static struct Test_Address alt_test_addr;

/**
 * Test peer
 */
static struct PeerContext p;

/**
 * HELLO address
 */
static struct GNUNET_HELLO_Address test_hello_address;

/**
 * HELLO address
 */
static struct GNUNET_HELLO_Address alt_test_hello_address;

/**
 * Session
 */
static void *test_session;

/**
 * Test ats info
 */
static struct GNUNET_ATS_Information test_ats_info[2];

/**
 * Test ats count
 */
static uint32_t test_ats_count;

/**
 * Test state
 */
int addresses_added = GNUNET_NO;

int first_address_suggested = GNUNET_NO;

int first_address_deleted = GNUNET_NO;

int second_address_deleted = GNUNET_NO;

int second_address_suggested = GNUNET_YES;

static struct GNUNET_HELLO_Address *first_suggestion = NULL;

static struct GNUNET_HELLO_Address *second_suggestion = NULL;


static int
stat_cb(void *cls, const char *subsystem, const char *name, uint64_t value,
        int is_persistent);

static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (die_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (NULL != sched_ats)
  {
    GNUNET_ATS_scheduling_done (sched_ats);
    sched_ats = NULL;
  }

  GNUNET_STATISTICS_watch_cancel (stats, "ats", "# addresses", &stat_cb, NULL);
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }

  free_test_address (&test_addr);
  GNUNET_free_non_null (first_suggestion);
  GNUNET_free_non_null (second_suggestion);
  ret = 0;
}


static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  die_task = GNUNET_SCHEDULER_NO_TASK;
  end ( NULL, NULL);
  ret = GNUNET_SYSERR;
}

static void
end_badly_now ()
{
  if (GNUNET_SCHEDULER_NO_TASK != die_task)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_SCHEDULER_add_now (&end_badly, NULL);
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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Received a sugggestion for peer `%s' : `%s'\n",
    GNUNET_i2s (&address->peer), (char *) address->address);

  if (GNUNET_NO == first_address_suggested)
  {
    if  (NULL == first_suggestion)
    {
      if ((NULL == address) || (NULL != session))
      {
        GNUNET_break (0);
        end_badly_now ();
        return;
      }
      if ((ntohl(bandwidth_in.value__) == 0) ||
          (ntohl(bandwidth_out.value__) == 0))
      {
        GNUNET_break (0);
        end_badly_now ();
        return;
      }

      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Received 1st sugggestion for peer `%s' : `%s'\n",
        GNUNET_i2s (&address->peer), (char *) address->address);

      first_suggestion = GNUNET_HELLO_address_copy (address);
      first_address_suggested = GNUNET_YES;


      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Deleting 1st address for peer `%s' : `%s'\n",
        GNUNET_i2s (&address->peer), (char *) address->address);
      GNUNET_ATS_address_destroyed (sched_ats, address, session);
      first_address_deleted = GNUNET_YES;

      return;
    }
  }
  if (GNUNET_YES == first_address_deleted)
  {
    if (NULL == second_suggestion)
    {
      if ((NULL == address) || (NULL != session))
      {
        GNUNET_break (0);
        end_badly_now ();
        return;
      }

      if (0 != memcmp (address->address, first_suggestion->address,
          (first_suggestion->address_length < address->address_length) ? first_suggestion->address_length : address->address_length))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Received 2nd sugggestion for peer `%s' : `%s'\n",
          GNUNET_i2s (&address->peer), (char *) address->address);
        second_suggestion = GNUNET_HELLO_address_copy (address);
        second_address_suggested = GNUNET_YES;

        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Deleting 2nd address for peer `%s' : `%s'\n",
          GNUNET_i2s (&address->peer), (char *) address->address);
        GNUNET_ATS_address_destroyed (sched_ats, address, session);
        second_address_deleted = GNUNET_YES;
        return;
      }
    }

  }
  if (GNUNET_YES == second_address_deleted)
  {
    /* Expecting disconnect */
    if ((ntohl(bandwidth_in.value__) == 0) &&
        (ntohl(bandwidth_out.value__) == 0))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "ATS tells me to disconnect\n");
      GNUNET_SCHEDULER_add_now (&end, NULL);
      return;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Expected disconnect but received address `%s' with bandwidth \n",
          (char *) address->address);
    }
  }
  return;
}


static int
stat_cb(void *cls, const char *subsystem,
        const char *name, uint64_t value,
        int is_persistent)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "ATS statistics: `%s' `%s' %llu\n",
      subsystem,name, value);
  if ((GNUNET_NO == addresses_added) && (value == 2))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "All addresses added, requesting....\n");
    /* We have 2 addresses, so we can request */
    addresses_added = GNUNET_YES;
    GNUNET_ATS_suggest_address (sched_ats, &p.id, NULL, NULL);
  }
  return GNUNET_OK;
}

static void
run (void *cls, const struct GNUNET_CONFIGURATION_Handle *mycfg,
    struct GNUNET_TESTING_Peer *peer)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);
  stats = GNUNET_STATISTICS_create ("ats", mycfg);
  GNUNET_STATISTICS_watch (stats, "ats", "# addresses", &stat_cb, NULL);


  /* Connect to ATS scheduling */
  sched_ats = GNUNET_ATS_scheduling_init (mycfg, &address_suggest_cb, NULL);
  if (sched_ats == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not connect to ATS scheduling!\n");
    end_badly_now ();
    return;
  }

  /* Set up peer */
  memset (&p.id, '1', sizeof (p.id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created peer `%s'\n",
              GNUNET_i2s_full(&p.id));

  /* Prepare ATS Information */
  test_ats_info[0].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  test_ats_info[0].value = htonl(GNUNET_ATS_NET_WAN);
  test_ats_info[1].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  test_ats_info[1].value = htonl(1);
  test_ats_count = 2;

  /* Adding address without session */
  test_session = NULL;
  create_test_address (&test_addr, "test", test_session, "test", strlen ("test") + 1);
  test_hello_address.peer = p.id;
  test_hello_address.transport_name = test_addr.plugin;
  test_hello_address.address = test_addr.addr;
  test_hello_address.address_length = test_addr.addr_len;

  /* Adding alternative address without session */
  test_session = NULL;
  create_test_address (&alt_test_addr, "test", test_session, "alt_test", strlen ("alt_test") + 1);
  alt_test_hello_address.peer = p.id;
  alt_test_hello_address.transport_name = alt_test_addr.plugin;
  alt_test_hello_address.address = alt_test_addr.addr;
  alt_test_hello_address.address_length = alt_test_addr.addr_len;


  /* Adding address */
  GNUNET_ATS_address_add (sched_ats, &test_hello_address, NULL, test_ats_info, test_ats_count);
  /* Adding alternative address */
  GNUNET_ATS_address_add (sched_ats, &alt_test_hello_address, NULL, test_ats_info, test_ats_count);
}


int
main (int argc, char *argv[])
{
  char *sep;
  char *src_filename = GNUNET_strdup (__FILE__);
  char *test_filename = GNUNET_strdup (argv[0]);
  char *config_file;
  char *solver;

  ret = 0;

  if (NULL == (sep  = (strstr (src_filename,".c"))))
  {
    GNUNET_break (0);
    return -1;
  }
  sep[0] = '\0';

  if (NULL != (sep = strstr (test_filename, ".exe")))
    sep[0] = '\0';

  if (NULL == (solver = strstr (test_filename, src_filename)))
  {
    GNUNET_break (0);
    return -1;
  }
  solver += strlen (src_filename) +1;

  if (0 == strcmp(solver, "proportional"))
  {
    config_file = "test_ats_solver_proportional.conf";
  }
  else if (0 == strcmp(solver, "mlp"))
  {
    config_file = "test_ats_solver_mlp.conf";
  }
  else if ((0 == strcmp(solver, "ril")))
  {
    config_file = "test_ats_solver_ril.conf";
  }
  else
  {
    GNUNET_break (0);
    GNUNET_free (src_filename);
    GNUNET_free (test_filename);
    return 1;
  }

  GNUNET_free (src_filename);
  GNUNET_free (test_filename);

  if (0 != GNUNET_TESTING_peer_run ("test-ats-solver",
      config_file, &run, NULL ))
    return GNUNET_SYSERR;

  return ret;
}

/* end of file test_ats_solver_add_address.c */
