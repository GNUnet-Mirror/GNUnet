/*
      This file is part of GNUnet
      (C) 2008--2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/test_testbed_api.c
 * @brief testcases for the testbed api
 * @author Sree Harsha Totakura <sreeharsha@totakura.in> 
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib-new.h"
#include "gnunet_testbed_service.h"


/**
 * Generic logging shortcut
 */
#define LOG(kind,...)				\
  GNUNET_log (kind, __VA_ARGS__)


/**
 * Our localhost
 */
static struct GNUNET_TESTBED_Host *host;

/**
 * The controller handle
 */
static struct GNUNET_TESTBED_Controller *c;

/**
 * A neighbouring host
 */
static struct GNUNET_TESTBED_Host *neighbour;

/**
 * Handle for neighbour registration
 */
static struct GNUNET_TESTBED_HostRegistrationHandle *reg_handle;

/**
 * Abort task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task_id;

/**
 * The testing result
 */
static int result;


/**
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (GNUNET_SCHEDULER_NO_TASK != abort_task_id)
    GNUNET_SCHEDULER_cancel (abort_task_id);
  if (NULL != reg_handle)
    GNUNET_TESTBED_cancel_registration (reg_handle);
  GNUNET_TESTBED_controller_disconnect (c);
  GNUNET_TESTBED_host_destroy (neighbour);
  GNUNET_TESTBED_host_destroy (host);
}


/**
 * abort task to run on test timed out
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_abort (void *cls, const const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG (GNUNET_ERROR_TYPE_WARNING, "Test timedout -- Aborting\n");
  abort_task_id = GNUNET_SCHEDULER_NO_TASK;
  do_shutdown (cls, tc);
}


/**
 * Signature of the event handler function called by the
 * respective event controller.
 *
 * @param cls closure
 * @param event information about the event
 */
static void 
controller_cb(void *cls, const struct GNUNET_TESTBED_EventInformation *event)
{
  GNUNET_break (0);
}


/**
 * Callback which will be called to after a host registration succeeded or failed
 *
 * @param cls the host which has been registered
 * @param emsg the error message; NULL if host registration is successful
 */
static void 
registration_comp (void *cls, const char *emsg)
{
  GNUNET_assert (cls == neighbour);
  reg_handle = NULL;
  result = GNUNET_YES;
  GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}


/**
 * Main point of test execution
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  uint64_t event_mask;

  host = GNUNET_TESTBED_host_create (NULL, NULL, 0);
  GNUNET_assert (NULL != host);
  event_mask ^= event_mask;	/* NULL out */
  event_mask |= (1L << GNUNET_TESTBED_ET_PEER_START);
  event_mask |= (1L << GNUNET_TESTBED_ET_PEER_STOP);
  event_mask |= (1L << GNUNET_TESTBED_ET_CONNECT);
  c = GNUNET_TESTBED_controller_connect (cfg, host, event_mask,
					 &controller_cb, NULL);
  GNUNET_assert (NULL != c);
  neighbour = GNUNET_TESTBED_host_create ("localhost", NULL, 0);
  GNUNET_assert (NULL != neighbour);
  reg_handle = 
    GNUNET_TESTBED_register_host (c, neighbour, &registration_comp, neighbour);
  GNUNET_assert (NULL != reg_handle);
  
  abort_task_id = GNUNET_SCHEDULER_add_delayed 
    (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 30), &do_abort, NULL);
}


/**
 * Main function
 */
int main (int argc, char **argv)
{
  result = GNUNET_SYSERR;
  if (0 != GNUNET_TESTING_service_run ("test_testbed_api",
				       "testbed",
				       "test_testbed_api.conf",
				       &run, NULL))
    return 1;
  else return (GNUNET_OK == result) ? 0 : 1;
}
