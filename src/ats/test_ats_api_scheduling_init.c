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
 * @file ats/test_ats_api_scheduling_init.c
 * @brief test automatic transport selection scheduling API init/shutdown
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet_testing_lib.h"
#include "ats.h"
#include "test_ats_api_common.h"
/**
 * Timeout task
 */
static struct GNUNET_SCHEDULER_Task * die_task;

/**
 * Initial statistics get request handle
 */
struct GNUNET_STATISTICS_GetHandle *initial_get;

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


static void end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

static int
stat_cb(void *cls, const char *subsystem,
        const char *name, uint64_t value,
        int is_persistent)
{

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "ATS statistics: `%s' `%s' %llu\n",
      subsystem,name, value);
  if (0 == value)
  {
    GNUNET_SCHEDULER_add_now (&end, NULL);
  }
  return GNUNET_OK;
}

static int
dummy_stat (void *cls, const char *subsystem, const char *name, uint64_t value,
            int is_persistent)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Got dummy stat %s%s:%s = %llu\n",
              is_persistent ? "!" : " ", subsystem, name, value);
  return GNUNET_OK;
}

static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutting down\n");

  if (die_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = NULL;
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
  ret = 0;
}

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = NULL;
  end ( NULL, NULL);
  ret = GNUNET_SYSERR;
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
got_initial_value (void *cls, int success)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Got initial value\n");

  /* Connect to ATS scheduling */
  sched_ats = GNUNET_ATS_scheduling_init (cfg, &address_suggest_cb, NULL);
  GNUNET_CONFIGURATION_destroy (cfg);
  if (sched_ats == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not connect to ATS scheduling!\n");
    GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }
}

static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);
  stats = GNUNET_STATISTICS_create ("ats", cfg);
  GNUNET_STATISTICS_watch (stats, "ats", "# addresses", &stat_cb, NULL);

  initial_get = GNUNET_STATISTICS_get (stats, "ats", "# addresses", TIMEOUT,
                                       &got_initial_value, &dummy_stat,
                                       GNUNET_CONFIGURATION_dup (cfg));
}


int
main (int argc, char *argv[])
{
  ret = 0;
  if (0 != GNUNET_TESTING_peer_run ("test-ats-api",
                                    "test_ats_api.conf",
                                    &run, NULL))
    return 1;
  return ret;
}

/* end of file test_ats_api_scheduling_init.c */
