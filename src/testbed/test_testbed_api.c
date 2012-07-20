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
 * @author Sree Harsha Totakura
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
 * Relative time seconds shorthand
 */
#define TIME_REL_SECS(sec) \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, sec)

/**
 * Our localhost
 */
static struct GNUNET_TESTBED_Host *host;

/**
 * The controller process
 */
static struct GNUNET_TESTBED_ControllerProc *cp;

/**
 * The controller handle
 */
static struct GNUNET_TESTBED_Controller *controller;

/**
 * A neighbouring host
 */
static struct GNUNET_TESTBED_Host *neighbour;

/**
 * Handle for neighbour registration
 */
static struct GNUNET_TESTBED_HostRegistrationHandle *reg_handle;

/**
 * Handle for a peer
 */
static struct GNUNET_TESTBED_Peer *peer;

/**
 * Handle to configuration
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to operation
 */
static struct GNUNET_TESTBED_Operation *operation;

/**
 * Abort task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task;

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
  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  if (NULL != reg_handle)
    GNUNET_TESTBED_cancel_registration (reg_handle);
  GNUNET_TESTBED_controller_disconnect (controller);
  GNUNET_CONFIGURATION_destroy (cfg);
  if (NULL != cp)
    GNUNET_TESTBED_controller_stop (cp);
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
  abort_task = GNUNET_SCHEDULER_NO_TASK;
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
  switch (event->type)
  {
  case GNUNET_TESTBED_ET_OPERATION_FINISHED:
    GNUNET_assert (event->details.operation_finished.operation == operation);
    GNUNET_assert (NULL == event->details.operation_finished.op_cls);
    GNUNET_assert (NULL == event->details.operation_finished.emsg);
    GNUNET_assert (GNUNET_TESTBED_PIT_GENERIC ==
		   event->details.operation_finished.pit);
    GNUNET_assert (NULL == event->details.operation_finished.op_result.generic);
    break;
  case GNUNET_TESTBED_ET_PEER_START:
    GNUNET_assert (event->details.peer_start.host == host);
    GNUNET_assert (event->details.peer_start.peer == peer);
    operation = GNUNET_TESTBED_peer_stop (peer);
    break;
  case GNUNET_TESTBED_ET_PEER_STOP:
    GNUNET_assert (event->details.peer_stop.peer == peer);    
    result = GNUNET_YES;  
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    break;
  default:
    GNUNET_assert (0);		/* We should never reach this state */
  }
}


/**
 * Functions of this signature are called when a peer has been successfully
 * created
 *
 * @param cls the closure from GNUNET_TESTBED_peer_create()
 * @param peer the handle for the created peer; NULL on any error during
 *          creation
 * @param emsg NULL if peer is not NULL; else MAY contain the error description
 */
static void
peer_create_cb (void *cls,
		struct GNUNET_TESTBED_Peer *peer, const char *emsg)
{
  struct GNUNET_TESTBED_Peer **peer_ptr;
  
  peer_ptr = cls;
  GNUNET_assert (NULL != peer);
  GNUNET_assert (NULL != peer_ptr);
  *peer_ptr = peer;
  operation = GNUNET_TESTBED_peer_start (peer);
  GNUNET_assert (NULL != operation);
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
  operation = GNUNET_TESTBED_peer_create (controller, host, cfg, &peer_create_cb, &peer);
  GNUNET_assert (NULL != operation);
}


/**
 * Callback to signal successfull startup of the controller process
 *
 * @param cls the closure from GNUNET_TESTBED_controller_start()
 * @param cfg the configuration with which the controller has been started;
 *          NULL if status is not GNUNET_OK
 * @param status GNUNET_OK if the startup is successfull; GNUNET_SYSERR if not,
 *          GNUNET_TESTBED_controller_stop() shouldn't be called in this case
 */
static void 
status_cb (void *cls, 
	   const struct GNUNET_CONFIGURATION_Handle *cfg, int status)
{
  uint64_t event_mask;

  GNUNET_assert (GNUNET_OK == status);
  event_mask = 0;
  event_mask |= (1L << GNUNET_TESTBED_ET_PEER_START);
  event_mask |= (1L << GNUNET_TESTBED_ET_PEER_STOP);
  event_mask |= (1L << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1L << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  controller = GNUNET_TESTBED_controller_connect (cfg, host, event_mask,
                                                  &controller_cb, NULL);
  GNUNET_assert (NULL != controller);
  neighbour = GNUNET_TESTBED_host_create ("localhost", NULL, 0);
  GNUNET_assert (NULL != neighbour);
  reg_handle = 
    GNUNET_TESTBED_register_host (controller, neighbour, &registration_comp,
                                  neighbour);
  GNUNET_assert (NULL != reg_handle);
}



/**
 * Main run function. 
 *
 * @param cls NULL
 * @param args arguments passed to GNUNET_PROGRAM_run
 * @param cfgfile the path to configuration file
 * @param cfg the configuration file handle
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  host = GNUNET_TESTBED_host_create (NULL, NULL, 0);
  GNUNET_assert (NULL != host);
  cfg = GNUNET_CONFIGURATION_dup (config);
  cp = GNUNET_TESTBED_controller_start ("127.0.0.1", host, cfg, status_cb, NULL);
  abort_task = GNUNET_SCHEDULER_add_delayed 
    (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5), &do_abort, NULL);
}


/**
 * Main function
 */
int main (int argc, char **argv)
{
  int ret;

  char *const argv2[] = { "test_testbed_api",
                          "-c", "test_testbed_api.conf",
                          NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  result = GNUNET_SYSERR;
  ret = GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
			    "test_testbed_api", "nohelp", options, &run,
			    NULL);
  if ((GNUNET_OK != ret) || (GNUNET_OK != result))
    return 1;
  return 0;
}
