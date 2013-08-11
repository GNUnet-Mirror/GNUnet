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

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)
#define DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

static GNUNET_SCHEDULER_TaskIdentifier die_task;
static GNUNET_SCHEDULER_TaskIdentifier wait_task;

static struct GNUNET_ATS_SchedulingHandle *ats;

static int ret;

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_SCHEDULER_NO_TASK != wait_task)
  {
    GNUNET_SCHEDULER_cancel (wait_task);
    wait_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (ats != NULL)
  {
    GNUNET_ATS_scheduling_done (ats);
    ats = NULL;
  }
  ret = 1;
}

static void
end_badly_now ()
{
  if (die_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
  }
  die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
}

static void
delay (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static int v_delay = 5;
  static int v_cur = 0;

  if (v_cur < v_delay)
  {
    wait_task = GNUNET_SCHEDULER_NO_TASK;
    wait_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &delay, NULL);
    fprintf (stderr,".");
    v_cur ++;
    return;
  }

  fprintf (stderr,"\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown ATS\n");
  GNUNET_ATS_scheduling_done (ats);
  ats = NULL;
  if (die_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
  }
  ret = 0;
}

static void
address_suggest_cb (void *cls, const struct GNUNET_HELLO_Address *address,
                    struct Session *session,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                    const struct GNUNET_ATS_Information *ats,
                    uint32_t ats_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Received address without asking for it!\n");
  end_badly_now ();
}


static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  ret = 1;
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Initializing ATS\n");
  ats = GNUNET_ATS_scheduling_init (cfg, &address_suggest_cb, NULL);
  if (ats == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to initialize ATS\n");
    end_badly_now ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Waiting for %s\n", 
	      GNUNET_STRINGS_relative_time_to_string (DELAY,
						      GNUNET_YES));
  wait_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &delay, NULL);
}


int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test_ats_api_scheduling_init",
				    "test_ats_api.conf",
				    &run, NULL))
    return 1;
  return ret;
}

/* end of file test_ats_api_scheduling_init.c */
