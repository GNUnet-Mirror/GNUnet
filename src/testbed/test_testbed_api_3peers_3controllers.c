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
 * @file testbed/test_testbed_api_3peers_3controllers.c
 * @brief testcases for the testbed api: 3 peers are configured, started and
 *          connected together. Each peer resides on its own controller.
 * @author Sree Harsha Totakura
 */


/**
 * The testing architecture is:
 *                  A
 *                 / \
 *                /   \
 *               B === C 
 * A is the master controller and B, C are slave controllers. B links to C
 * laterally.
 * Peers are mapped to controllers in the following relations:
 *             Peer         Controller
 *               1              A
 *               2              B
 *               3              C
 *
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
 * The controller process of one controller
 */
static struct GNUNET_TESTBED_ControllerProc *cp1;

/**
 * A neighbouring host
 */
static struct GNUNET_TESTBED_Host *neighbour1;

/**
 * Another neighbouring host
 */
static struct GNUNET_TESTBED_Host *neighbour2;

/**
 * Handle for neighbour registration
 */
static struct GNUNET_TESTBED_HostRegistrationHandle *reg_handle;

/**
 * The controller handle of one controller
 */
static struct GNUNET_TESTBED_Controller *controller1;

/**
 * peer 1
 */
static struct PeerContext peer1;

/**
 * peer2
 */
static struct PeerContext peer2;

/**
 * peer3
 */
static struct PeerContext peer3;

/**
 * Handle to starting configuration
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to slave controller C's configuration, used to establish lateral link from
 * master controller
 */
static struct GNUNET_CONFIGURATION_Handle *cfg2;

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
   * Controller 1 has started
   */
  CONTROLLER1_UP,

  /**
   * peer1 is created
   */
  PEER1_CREATED,

  /**
   * peer1 is started
   */
  PEER1_STARTED,

  /**
   * Controller 2 has started
   */
  CONTROLLER2_UP,

  /**
   * peer2 is created
   */
  PEER2_CREATED,

  /**
   * peer2 is started
   */
  PEER2_STARTED,

  /**
   * Controller 3 has started
   */
  CONTROLLER3_UP,

  /**
   * Peer3 is created
   */
  PEER3_CREATED,

  /**
   * Peer3 started
   */
  PEER3_STARTED,

  /**
   * peer1 and peer2 are connected
   */
  PEERS_1_2_CONNECTED,

  /**
   * peer2 and peer3 are connected
   */
  PEERS_2_3_CONNECTED,

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
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == delayed_connect_task);
  if (NULL != reg_handle)
    GNUNET_TESTBED_cancel_registration (reg_handle);
  if (NULL != controller1)
    GNUNET_TESTBED_controller_disconnect (controller1);
  GNUNET_CONFIGURATION_destroy (cfg);
  if (NULL != cfg2)
    GNUNET_CONFIGURATION_destroy (cfg2);
  if (NULL != cp1)
    GNUNET_TESTBED_controller_stop (cp1);
  if (NULL != host)
    GNUNET_TESTBED_host_destroy (host);
  if (NULL != neighbour1)
    GNUNET_TESTBED_host_destroy (neighbour1);
  if (NULL != neighbour2)
    GNUNET_TESTBED_host_destroy (neighbour2);
}


/**
 * abort task to run on test timed out
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
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
do_delayed_connect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
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
  case PEER3_STARTED:
    GNUNET_assert (NULL == peer1.operation);
    GNUNET_assert (NULL == peer2.operation);
    GNUNET_assert (NULL != common_operation);
    GNUNET_TESTBED_operation_done (common_operation);
    common_operation = NULL;
    result = PEERS_1_2_CONNECTED;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Peers connected\n");
    common_operation = 
        GNUNET_TESTBED_overlay_connect (NULL, &op_comp_cb, NULL, peer2.peer,
					  peer3.peer);
    break;
  case PEERS_1_2_CONNECTED:
    GNUNET_assert (NULL != common_operation);
    GNUNET_TESTBED_operation_done (common_operation);
    common_operation = NULL;
    result = PEERS_2_3_CONNECTED;
    delayed_connect_task =
          GNUNET_SCHEDULER_add_delayed (TIME_REL_SECS (3),
                                        &do_delayed_connect, NULL);
    break;
  case PEERS_2_3_CONNECTED:
    GNUNET_assert (NULL == peer1.operation);
    GNUNET_assert (NULL == peer2.operation);
    GNUNET_assert (NULL != common_operation);
    GNUNET_TESTBED_operation_done (common_operation);
    common_operation = NULL;
    result = PEERS_CONNECTED_2;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Peers connected again\n");
    peer1.operation = GNUNET_TESTBED_peer_stop (peer1.peer, NULL, NULL);
    peer2.operation = GNUNET_TESTBED_peer_stop (peer2.peer, NULL, NULL);
    peer3.operation = GNUNET_TESTBED_peer_stop (peer3.peer, NULL, NULL);
    break;
  default:
    GNUNET_assert (0);
  }
}


/**
 * Functions of this signature are called when a peer has been successfully
 * created
 *
 * @param cls NULL
 * @param peer the handle for the created peer; NULL on any error during
 *          creation
 * @param emsg NULL if peer is not NULL; else MAY contain the error description
 */
static void
peer_create_cb (void *cls, struct GNUNET_TESTBED_Peer *peer, const char *emsg)
{
  switch (result)
  {
  case CONTROLLER1_UP:
    GNUNET_assert (NULL != peer1.operation);
    GNUNET_assert (NULL != peer);
    GNUNET_assert (NULL == peer1.peer);
    peer1.peer = peer;
    GNUNET_TESTBED_operation_done (peer1.operation);
    result = PEER1_CREATED;
    peer1.operation = GNUNET_TESTBED_peer_start (NULL, peer, NULL, NULL);
    break;
  case CONTROLLER2_UP:
    GNUNET_assert (NULL != peer2.operation);
    GNUNET_assert (NULL != peer);
    GNUNET_assert (NULL == peer2.peer);
    peer2.peer = peer;
    GNUNET_TESTBED_operation_done (peer2.operation);
    result = PEER2_CREATED;
    peer2.operation = GNUNET_TESTBED_peer_start (NULL, peer, NULL, NULL);
    break;
  case CONTROLLER3_UP:
    GNUNET_assert (NULL != peer3.operation);
    GNUNET_assert (NULL != peer);
    GNUNET_assert (NULL == peer3.peer);
    peer3.peer = peer;
    GNUNET_TESTBED_operation_done (peer3.operation);
    result = PEER3_CREATED;
    peer3.operation = GNUNET_TESTBED_peer_start (NULL, peer, NULL, NULL);
    break;
  default:
    GNUNET_assert (0);
  }  
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
status_cb (void *cls, const struct GNUNET_CONFIGURATION_Handle *config, int status);


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
  case GNUNET_TESTBED_ET_OPERATION_FINISHED:
    GNUNET_assert (NULL == event->details.operation_finished.op_cls);
    GNUNET_assert (NULL == event->details.operation_finished.emsg);
    switch (result)
    {      
    case PEERS_STOPPED:
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
      else if (event->details.operation_finished.operation == peer3.operation)
      {
        GNUNET_TESTBED_operation_done (peer3.operation);
        peer3.operation = NULL;
        peer3.peer = NULL;
      }
      else
        GNUNET_assert (0);
      if ((NULL == peer1.peer) && (NULL == peer2.peer) && (NULL == peer3.peer))
      {
        result = SUCCESS;
        GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
      }
      break;
    case PEER1_STARTED:
      GNUNET_assert (NULL == event->details.operation_finished.generic);
      GNUNET_assert (NULL != common_operation);
      GNUNET_TESTBED_operation_done (common_operation);
      common_operation = NULL;
      result = CONTROLLER2_UP;
      peer2.operation =
          GNUNET_TESTBED_peer_create (controller1, neighbour1, cfg,
                                      &peer_create_cb, NULL);
      GNUNET_assert (NULL != peer2.operation);
      break;
    case PEER2_STARTED:
      GNUNET_assert (NULL == event->details.operation_finished.generic);
      GNUNET_assert (NULL != common_operation);
      GNUNET_TESTBED_operation_done (common_operation);
      common_operation = NULL;
      result = CONTROLLER3_UP;
      peer3.operation =
          GNUNET_TESTBED_peer_create (controller1, neighbour2, cfg,
                                      &peer_create_cb, NULL);
      GNUNET_assert (NULL != peer3.operation);
      break;
    default:
      GNUNET_assert (0);
    }
    break;
  case GNUNET_TESTBED_ET_PEER_START:    
    switch (result)
    {
    case PEER1_CREATED:
      GNUNET_assert (event->details.peer_start.host == host);
      peer1.is_running = GNUNET_YES;
      GNUNET_TESTBED_operation_done (peer1.operation);
      peer1.operation = NULL;
      result = PEER1_STARTED;
      common_operation =
          GNUNET_TESTBED_controller_link (NULL, controller1, neighbour1, NULL, cfg,
                                          GNUNET_YES); 
      break;
    case PEER2_CREATED:
      GNUNET_assert (event->details.peer_start.host == neighbour1);
      peer2.is_running = GNUNET_YES;
      GNUNET_TESTBED_operation_done (peer2.operation);
      peer2.operation = NULL;
      result = PEER2_STARTED;
      GNUNET_assert (NULL == common_operation);              
      common_operation =
          GNUNET_TESTBED_controller_link (NULL, controller1, neighbour2, NULL, cfg,
                                          GNUNET_YES);
      GNUNET_assert (NULL != common_operation);
      break;
    case PEER3_CREATED:
      GNUNET_assert (event->details.peer_start.host == neighbour2);
      peer3.is_running = GNUNET_YES;
      GNUNET_TESTBED_operation_done (peer3.operation);
      peer3.operation = NULL;
      result = PEER3_STARTED;
      common_operation =
          GNUNET_TESTBED_overlay_connect (NULL, &op_comp_cb, NULL, peer2.peer,
                                          peer1.peer);
      break;
    default:
      GNUNET_assert (0);
    }    
    break;
  case GNUNET_TESTBED_ET_PEER_STOP:
    GNUNET_assert (PEERS_CONNECTED_2 == result);
    if (event->details.peer_stop.peer == peer1.peer)
    {
      peer1.is_running = GNUNET_NO;
      GNUNET_TESTBED_operation_done (peer1.operation);
    }
    else if (event->details.peer_stop.peer == peer2.peer)
    {
      peer2.is_running = GNUNET_NO;
      GNUNET_TESTBED_operation_done (peer2.operation);
    }
    else if (event->details.peer_stop.peer == peer3.peer)
    {
      peer3.is_running = GNUNET_NO;
      GNUNET_TESTBED_operation_done (peer3.operation);
    }
    else
      GNUNET_assert (0);
    if ((GNUNET_NO == peer1.is_running) &&
        (GNUNET_NO == peer2.is_running) &&
        (GNUNET_NO == peer3.is_running))
    {
      result = PEERS_STOPPED;
      peer1.operation = GNUNET_TESTBED_peer_destroy (peer1.peer);
      peer2.operation = GNUNET_TESTBED_peer_destroy (peer2.peer);
      peer3.operation = GNUNET_TESTBED_peer_destroy (peer3.peer);
    }
    break;
  case GNUNET_TESTBED_ET_CONNECT:
    GNUNET_assert (NULL == peer1.operation);
    GNUNET_assert (NULL == peer2.operation);
    GNUNET_assert (NULL == peer3.operation);
    switch (result)
    {
    case PEER3_STARTED:
      GNUNET_assert (NULL != common_operation);
      GNUNET_assert ((event->details.peer_connect.peer1 == peer2.peer) &&
        	     (event->details.peer_connect.peer2 == peer1.peer));
      break;
    case PEERS_2_3_CONNECTED:
      GNUNET_assert (NULL != common_operation);
      GNUNET_assert ((event->details.peer_connect.peer1 == peer1.peer) &&
        	     (event->details.peer_connect.peer2 == peer2.peer));
      break;
    case PEERS_1_2_CONNECTED: 
      GNUNET_assert (NULL != common_operation);
      GNUNET_assert ((event->details.peer_connect.peer1 == peer2.peer) &&
        	     (event->details.peer_connect.peer2 == peer3.peer));      
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
 * Callback which will be called to after a host registration succeeded or failed
 *
 * @param cls the host which has been registered
 * @param emsg the error message; NULL if host registration is successful
 */
static void
registration_comp (void *cls, const char *emsg)
{
  reg_handle = NULL;
  if (cls == neighbour1)
  {
    neighbour2 = GNUNET_TESTBED_host_create ("127.0.0.1", NULL, 0);
    GNUNET_assert (NULL != neighbour2);
    reg_handle =
        GNUNET_TESTBED_register_host (controller1, neighbour2, &registration_comp,
                                      neighbour2);
    GNUNET_assert (NULL != reg_handle);
    return;
  }
  GNUNET_assert (cls == neighbour2);
  peer1.operation =
      GNUNET_TESTBED_peer_create (controller1, host, cfg, &peer_create_cb,
                                  &peer1);
  GNUNET_assert (NULL != peer1.operation);  
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
status_cb (void *cls, const struct GNUNET_CONFIGURATION_Handle *config, int status)
{
  uint64_t event_mask;
  
  GNUNET_assert (GNUNET_OK == status);
  event_mask = 0;
  event_mask |= (1L << GNUNET_TESTBED_ET_PEER_START);
  event_mask |= (1L << GNUNET_TESTBED_ET_PEER_STOP);
  event_mask |= (1L << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1L << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  switch (result)
  {
  case INIT:
    controller1 =
        GNUNET_TESTBED_controller_connect (config, host, event_mask, &controller_cb,
                                           NULL);
    GNUNET_assert (NULL != controller1);
    result = CONTROLLER1_UP;
    neighbour1 = GNUNET_TESTBED_host_create ("127.0.0.1", NULL, 0);
    GNUNET_assert (NULL != neighbour1);
    reg_handle =
        GNUNET_TESTBED_register_host (controller1, neighbour1, &registration_comp,
                                      neighbour1);
    GNUNET_assert (NULL != reg_handle);
    break;
  default:
    GNUNET_assert (0);
  }  
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
  if (GNUNET_YES != GNUNET_TESTBED_is_host_habitable (host, config))
  {
    GNUNET_TESTBED_host_destroy (host);
    host = NULL;
    (void) PRINTF ("%s",
                   "Unable to run the test as this system is not configured "
                   "to use password less SSH logins to localhost.\n"
                   "Marking test as successful\n");
    result = SUCCESS;
    return;
  }
  cfg = GNUNET_CONFIGURATION_dup (config);
  cp1 = GNUNET_TESTBED_controller_start ("127.0.0.1", host, cfg, status_cb,
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
  char *const argv2[] = { "test_testbed_api_3peers_3controllers",
                          "-c", "test_testbed_api.conf",
                          NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  result = INIT;
  ret =
      GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                          "test_testbed_api_3peers_3controllers", "nohelp",
                          options, &run, NULL);
  if ((GNUNET_OK != ret) || (SUCCESS != result))
    return 1;
  return 0;
}

/* end of test_testbed_api_3peers_3controllers.c */
