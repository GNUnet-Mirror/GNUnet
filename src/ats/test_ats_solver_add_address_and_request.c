/*
  if (NULL == (perf_ats = GNUNET_ATS_performance_init (cfg, &ats_perf_cb, NULL)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Failed to connect to performance API\n");
    GNUNET_SCHEDULER_add_now (end_badly, NULL);
  }
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
 * @brief solver test:  add address, request address and wait for suggest
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


static int
stat_cb(void *cls, const char *subsystem, const char *name, uint64_t value,
        int is_persistent);

static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Done!\n");
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
address_suggest_cb (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_HELLO_Address *address,
                    struct Session *session,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                    const struct GNUNET_ATS_Information *atsi,
                    uint32_t ats_count)
{

  GNUNET_assert (NULL != address);
  GNUNET_assert (NULL == session);
  GNUNET_assert (ntohl(bandwidth_in.value__) > 0);
  GNUNET_assert (ntohl(bandwidth_out.value__) > 0);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Received sugggestion for peer `%s'\n",
      GNUNET_i2s (&address->peer));

  GNUNET_SCHEDULER_add_now (&end, NULL);
  return;
}


static int
stat_cb(void *cls, const char *subsystem,
        const char *name, uint64_t value,
        int is_persistent)
{

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "ATS statistics: `%s' `%s' %llu\n",
      subsystem,name, value);
  GNUNET_ATS_suggest_address (sched_ats, &p.id, NULL, NULL);
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
    GNUNET_SCHEDULER_add_now (&end_badly, NULL);
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

  /* Adding address */
  GNUNET_ATS_address_add (sched_ats, &test_hello_address, NULL, test_ats_info, test_ats_count);
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
