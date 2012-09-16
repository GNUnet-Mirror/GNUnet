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
 * @file testbed/test_testbed_api_2peers_1controller.c
 * @brief testcases for the testbed api: 2 peers are configured, started and
 *          connected together. The 2 peer reside on a single controller.
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
 * Peer context
 */
struct PeerContext
{
  /**
   * The peer handle
   */
  struct GNUNET_TESTBED_Peer *peer;

  /**
   * Operations involving this peer
   */
  struct GNUNET_TESTBED_Operation *operation;

  /**
   * set to GNUNET_YES when peer is started
   */
  int is_running;
};

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
 * peer 1
 */
static struct PeerContext peer1;

/**
 * peer2
 */
static struct PeerContext peer2;

/**
 * Handle to configuration
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to operations involving both peers
 */
static struct GNUNET_TESTBED_Operation *common_operation;

/**
 * Abort task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task;

/**
 * Delayed connect job identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier delayed_connect_task;

/**
 * Different stages in testing
 */
enum Stage
{

  /**
   * Initial stage
   */
  INIT,

  /**
   * peers are created
   */
  PEERS_CREATED,

  /**
   * peers are started
   */
  PEERS_STARTED,

  /**
   * peers are connected
   */
  PEERS_CONNECTED,

  /**
   * Peers are connected once again (this should not fail as they are already connected)
   */
  PEERS_CONNECTED_2,

  /**
   * peers are stopped
   */
  PEERS_STOPPED,

  /**
   * Final success stage
   */
  SUCCESS
};

/**
 * The testing result
 */
static enum Stage result;


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
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == delayed_connect_task);
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
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == delayed_connect_task);
  do_shutdown (cls, tc);
}


/**
 * Callback to be called when an operation is completed
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void 
op_comp_cb (void *cls, struct GNUNET_TESTBED_Operation *op, const char *emsg);


/**
 * task for delaying a connect
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_delayed_connect (void *cls, const const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  delayed_connect_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (NULL == common_operation);
  common_operation = GNUNET_TESTBED_overlay_connect (NULL, &op_comp_cb, NULL, 
						     peer1.peer, peer2.peer);
}


/**
 * Callback to be called when an operation is completed
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void 
op_comp_cb (void *cls, struct GNUNET_TESTBED_Operation *op, const char *emsg)
{
  GNUNET_assert (common_operation == op);
  switch(result)
  {
  case PEERS_STARTED:
    GNUNET_assert (NULL == peer1.operation);
    GNUNET_assert (NULL == peer2.operation);
    GNUNET_assert (NULL != common_operation);
    GNUNET_TESTBED_operation_done (common_operation);
    common_operation = NULL;
    result = PEERS_CONNECTED;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Peers connected\n");
    delayed_connect_task =
	GNUNET_SCHEDULER_add_delayed (TIME_REL_SECS (3),
				      &do_delayed_connect, NULL);
    break;
  case PEERS_CONNECTED:
    GNUNET_assert (NULL == peer1.operation);
    GNUNET_assert (NULL == peer2.operation);
    GNUNET_assert (NULL != common_operation);
    GNUNET_TESTBED_operation_done (common_operation);
    common_operation = NULL;
    result = PEERS_CONNECTED_2;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Peers connected again\n");
    peer1.operation = GNUNET_TESTBED_peer_stop (peer1.peer, NULL, NULL);
    peer2.operation = GNUNET_TESTBED_peer_stop (peer2.peer, NULL, NULL);
    break;
  default:
    GNUNET_assert (0);
  }
}


/**
 * Signature of the event handler function called by the
 * respective event controller.
 *
 * @param cls closure
 * @param event information about the event
 */
static void
controller_cb (void *cls, const struct GNUNET_TESTBED_EventInformation *event)
{
  switch (event->type)
  {
  case GNUNET_TESTBED_ET_OPERATION_FINISHED:   /* Will be reached when we destroy peers */
    GNUNET_assert (PEERS_STOPPED == result);
    GNUNET_assert (NULL == event->details.operation_finished.op_cls);
    GNUNET_assert (NULL == event->details.operation_finished.emsg);
    GNUNET_assert (NULL == event->details.operation_finished.generic);
    if (event->details.operation_finished.operation == peer1.operation)
    {
      GNUNET_TESTBED_operation_done (peer1.operation);
      peer1.operation = NULL;
      peer1.peer = NULL;
    }
    else if (event->details.operation_finished.operation == peer2.operation)
    {
      GNUNET_TESTBED_operation_done (peer2.operation);
      peer2.operation = NULL;
      peer2.peer = NULL;
    }
    else
      GNUNET_assert (0);
    if ((NULL == peer1.peer) && (NULL == peer2.peer))
    {
      result = SUCCESS;
      GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    }
    break;
  case GNUNET_TESTBED_ET_PEER_START:
    GNUNET_assert (INIT == result);
    GNUNET_assert (event->details.peer_start.host == host);
    if (event->details.peer_start.peer == peer1.peer)
    {
      peer1.is_running = GNUNET_YES;
      GNUNET_TESTBED_operation_done (peer1.operation);
      peer1.operation = NULL;
    }
    else if (event->details.peer_start.peer == peer2.peer)
    {
      peer2.is_running = GNUNET_YES;
      GNUNET_TESTBED_operation_done (peer2.operation);
      peer2.operation = NULL;
    }
    else
      GNUNET_assert (0);
    if ((GNUNET_YES == peer1.is_running) && (GNUNET_YES == peer2.is_running))
    {
      result = PEERS_STARTED;
      common_operation =
          GNUNET_TESTBED_overlay_connect (NULL, &op_comp_cb, NULL, peer1.peer,
					  peer2.peer);
    }
    break;
  case GNUNET_TESTBED_ET_PEER_STOP:
    GNUNET_assert (PEERS_CONNECTED_2 == result);
    if (event->details.peer_stop.peer == peer1.peer)
    {
      peer1.is_running = GNUNET_NO;
      GNUNET_TESTBED_operation_done (peer1.operation);
      peer1.operation = GNUNET_TESTBED_peer_destroy (peer1.peer);
    }
    else if (event->details.peer_stop.peer == peer2.peer)
    {
      peer2.is_running = GNUNET_NO;
      GNUNET_TESTBED_operation_done (peer2.operation);
      peer2.operation = GNUNET_TESTBED_peer_destroy (peer2.peer);
    }
    else
      GNUNET_assert (0);
    if ((GNUNET_NO == peer1.is_running) && (GNUNET_NO == peer2.is_running))
      result = PEERS_STOPPED;
    break;
  case GNUNET_TESTBED_ET_CONNECT:
    switch (result)
    {
    case PEERS_STARTED:
    case PEERS_CONNECTED:
      GNUNET_assert (NULL == peer1.operation);
      GNUNET_assert (NULL == peer2.operation);
      GNUNET_assert (NULL != common_operation);
      GNUNET_assert ((event->details.peer_connect.peer1 == peer1.peer) &&
		     (event->details.peer_connect.peer2 == peer2.peer));
      break;
    default:
      GNUNET_assert (0);
    }
    break;
  default:
    GNUNET_assert (0);
  };
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
peer_create_cb (void *cls, struct GNUNET_TESTBED_Peer *peer, const char *emsg)
{
  struct PeerContext *pc = cls;

  GNUNET_assert (NULL != pc->operation);
  GNUNET_assert (NULL != peer);
  GNUNET_assert (NULL == pc->peer);
  pc->peer = peer;
  GNUNET_TESTBED_operation_done (pc->operation);
  pc->operation = GNUNET_TESTBED_peer_start (pc->peer, NULL, NULL);
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
  peer1.operation =
      GNUNET_TESTBED_peer_create (controller, host, cfg, &peer_create_cb,
                                  &peer1);
  peer2.operation =
      GNUNET_TESTBED_peer_create (controller, host, cfg, &peer_create_cb,
                                  &peer2);
  GNUNET_assert (NULL != peer1.operation);
  GNUNET_assert (NULL != peer2.operation);
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
status_cb (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg, int status)
{
  uint64_t event_mask;

  GNUNET_assert (GNUNET_OK == status);
  event_mask = 0;
  event_mask |= (1L << GNUNET_TESTBED_ET_PEER_START);
  event_mask |= (1L << GNUNET_TESTBED_ET_PEER_STOP);
  event_mask |= (1L << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1L << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  controller =
      GNUNET_TESTBED_controller_connect (cfg, host, event_mask, &controller_cb,
                                         NULL);
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
  cp = GNUNET_TESTBED_controller_start ("127.0.0.1", host, cfg, status_cb,
                                        NULL);
  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MINUTES, 3), &do_abort,
                                    NULL);
}


/**
 * Main function
 */
int
main (int argc, char **argv)
{
  int ret;

  char *const argv2[] = { "test_testbed_api_2peers_1controller",
    "-c", "test_testbed_api.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  result = INIT;
  ret =
      GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                          "test_testbed_api_2peers_1controller", "nohelp",
                          options, &run, NULL);
  if ((GNUNET_OK != ret) || (SUCCESS != result))
    return 1;
  return 0;
}

/* end of test_testbed_api_2peers_1controller.c */
