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
 * @file ats/test_ats_api_performance_monitor.c
 * @brief test performance API's address monitor feature
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet_testing_lib.h"
#include "ats.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
#define WAIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

static struct GNUNET_SCHEDULER_Task * die_task;

/**
 * Statistics handle
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Configuration handle
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * ATS scheduling handle
 */
static struct GNUNET_ATS_SchedulingHandle *sched_ats;

/**
 * ATS performance handle
 */
static struct GNUNET_ATS_PerformanceHandle *perf_ats;

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

static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
ats_perf_cb (void *cls,
            const struct GNUNET_HELLO_Address *address,
            int address_active,
            struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
            struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
            const struct GNUNET_ATS_Information *ats,
            uint32_t ats_count)
{
  static int peer0 = GNUNET_NO;
  static int peer1 = GNUNET_NO;
  static int done = GNUNET_NO;

  if (NULL == address)
    return;

  if (0 == memcmp (&address->peer, &p[0].id, sizeof (p[0].id)))
  {
    peer0 ++;
  }
  if (0 == memcmp (&address->peer, &p[1].id, sizeof (p[1].id)))
  {
    peer1 ++;
  }
  if ((2 == peer0) && (2 == peer1) && (GNUNET_NO == done))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
        "Done\n");
    done = GNUNET_YES;
    GNUNET_SCHEDULER_add_now (&end, NULL);

  }
}


static int
stat_cb(void *cls, const char *subsystem,
        const char *name, uint64_t value,
        int is_persistent)
{

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "ATS statistics: `%s' `%s' %llu\n",
      subsystem,name, value);
  if (4 == value)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
        "All addresses added\n");

    if (NULL == (perf_ats = GNUNET_ATS_performance_init (cfg, &ats_perf_cb, NULL)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
          "Failed to connect to performance API\n");
      GNUNET_SCHEDULER_add_now (end_badly, NULL);
    }
  }

  return GNUNET_OK;

}

static void
address_suggest_cb (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_HELLO_Address *address,
                    struct Session *session,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)

{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Did not expect suggestion callback!\n");
  GNUNET_SCHEDULER_add_now (&end_badly, NULL);
}


static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = NULL;
  end ( NULL, NULL);
  ret = GNUNET_SYSERR;
}

static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Shutting down\n");
  if (die_task != NULL )
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = NULL;
  }

  if (NULL != sched_ats)
  {
    GNUNET_ATS_scheduling_done (sched_ats);
    sched_ats = NULL;
  }

  if (NULL != perf_ats)
  {
    GNUNET_ATS_performance_done (perf_ats);
    perf_ats = NULL;
  }

  GNUNET_STATISTICS_watch_cancel (stats, "ats", "# addresses", &stat_cb, NULL);
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }


  GNUNET_free_non_null(p0_addresses[0].addr);
  GNUNET_free_non_null(p0_addresses[1].addr);
  GNUNET_free_non_null(p1_addresses[0].addr);
  GNUNET_free_non_null(p1_addresses[1].addr);

  ret = 0;
}

static void
run (void *cls, const struct GNUNET_CONFIGURATION_Handle *mycfg,
    struct GNUNET_TESTING_Peer *peer)
{
  ret = 1;
  cfg = (struct GNUNET_CONFIGURATION_Handle *) mycfg;
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL );

  stats = GNUNET_STATISTICS_create ("ats", cfg);
  GNUNET_STATISTICS_watch (stats, "ats", "# addresses", &stat_cb, NULL);

  /* set up peer 0 */
  memset (&p[0].id, '1', sizeof (p[0].id));
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
  p0_addresses[1].addr_len = strlen (p0_addresses[1].addr) + 1;

  p0_ha[1].address = p0_addresses[1].addr;
  p0_ha[1].address_length = p0_addresses[1].addr_len;
  p0_ha[1].peer = p[0].id;
  p0_ha[1].transport_name = p0_addresses[1].plugin;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Created peer 0: `%s'\n",
      GNUNET_i2s (&p[0].id));

  memset (&p[1].id, '2', sizeof (p[1].id));
  p1_addresses[0].plugin = "test";
  p1_addresses[0].session = NULL;
  p1_addresses[0].addr = GNUNET_strdup ("test_p1_a0");
  p1_addresses[0].addr_len = strlen (p1_addresses[0].addr) + 1;

  p1_ha[0].address = p1_addresses[0].addr;
  p1_ha[0].address_length = p1_addresses[0].addr_len;
  p1_ha[0].peer = p[1].id;
  p1_ha[0].transport_name = p1_addresses[0].plugin;

  p1_addresses[1].plugin = "test";
  p1_addresses[1].session = NULL;
  p1_addresses[1].addr = GNUNET_strdup ("test_p1_a1");
  p1_addresses[1].addr_len = strlen (p1_addresses[1].addr) + 1;

  p1_ha[1].address = p1_addresses[1].addr;
  p1_ha[1].address_length = p1_addresses[1].addr_len;
  p1_ha[1].peer = p[1].id;
  p1_ha[1].transport_name = p1_addresses[1].plugin;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Created peer 1: `%s'\n",
      GNUNET_i2s (&p[1].id));

  /* Add addresses */
  sched_ats = GNUNET_ATS_scheduling_init (cfg, &address_suggest_cb, NULL );
  if (sched_ats == NULL )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not setup peer!\n");
    GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }

  GNUNET_ATS_address_add (sched_ats, &p0_ha[0], NULL, NULL, 0);
  GNUNET_ATS_address_add (sched_ats, &p0_ha[1], NULL, NULL, 0);

  GNUNET_ATS_address_add (sched_ats, &p1_ha[0], NULL, NULL, 0);
  GNUNET_ATS_address_add (sched_ats, &p1_ha[1], NULL, NULL, 0);
}

int
main (int argc, char *argv[])
{
  if (0
      != GNUNET_TESTING_peer_run ("test_ats_api_performance",
          "test_ats_api.conf", &run, NULL ))
    return 1;
  return ret;
}

/* end of file test_ats_api_performance_monitor.c */
