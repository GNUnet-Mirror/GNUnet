/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
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
#include "gnunet_testing_lib.h"
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
 * The handle for whether a host is habitable or not
 */
struct GNUNET_TESTBED_HostHabitableCheckHandle *hc_handle;

/**
 * Abort task identifier
 */
static struct GNUNET_SCHEDULER_Task * abort_task;

/**
 * Delayed connect job identifier
 */
static struct GNUNET_SCHEDULER_Task * delayed_connect_task;

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
  SUCCESS,

  /**
   * Optional stage for marking test to be skipped
   */
  SKIP
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
  if (NULL != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  if (NULL != hc_handle)
    GNUNET_TESTBED_is_host_habitable_cancel (hc_handle);
  GNUNET_assert (NULL == delayed_connect_task);
  if (NULL != common_operation)
    GNUNET_TESTBED_operation_done (common_operation);
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
  abort_task = NULL;
  if (NULL != delayed_connect_task)
  {
    GNUNET_SCHEDULER_cancel (delayed_connect_task);
    delayed_connect_task = NULL;
  }
  do_shutdown (cls, tc);
}

static void
abort_test ()
{
  if (NULL != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
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
  delayed_connect_task = NULL;
  if (NULL != common_operation)
  {
    GNUNET_break (0);
    abort_test ();
    return;
  }
  common_operation =
      GNUNET_TESTBED_overlay_connect (NULL, &op_comp_cb, NULL, peer1.peer,
                                      peer2.peer);
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
  if (common_operation != op)
  {
    GNUNET_break (0);
    abort_test ();
    return;
  }

  switch (result)
  {
  case PEER3_STARTED:
  case PEERS_2_3_CONNECTED:
  case PEERS_1_2_CONNECTED:
    break;
  default:
    GNUNET_break (0);
    abort_test ();
    return;
  }
  if ((NULL != peer1.operation) || (NULL != peer2.operation) ||
      (NULL != peer3.operation))
  {
    GNUNET_break (0);
    abort_test ();
    return;
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
    if ((NULL == peer1.operation) || (NULL == peer) || (NULL != peer1.peer))
    {
      GNUNET_break (0);
      abort_test ();
      return;
    }
    peer1.peer = peer;
    GNUNET_TESTBED_operation_done (peer1.operation);
    result = PEER1_CREATED;
    peer1.operation = GNUNET_TESTBED_peer_start (NULL, peer, NULL, NULL);
    break;
  case CONTROLLER2_UP:
    if ((NULL == peer2.operation) || (NULL == peer) || (NULL != peer2.peer))
    {
      GNUNET_break (0);
      abort_test ();
      return;
    }
    peer2.peer = peer;
    GNUNET_TESTBED_operation_done (peer2.operation);
    result = PEER2_CREATED;
    peer2.operation = GNUNET_TESTBED_peer_start (NULL, peer, NULL, NULL);
    break;
  case CONTROLLER3_UP:
    if ((NULL == peer3.operation) || (NULL == peer) || (NULL != peer3.peer))
    {
      GNUNET_break (0);
      abort_test ();
      return;
    }
    peer3.peer = peer;
    GNUNET_TESTBED_operation_done (peer3.operation);
    result = PEER3_CREATED;
    peer3.operation = GNUNET_TESTBED_peer_start (NULL, peer, NULL, NULL);
    break;
  default:
    GNUNET_break (0);
    abort_test ();
    return;
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
  case GNUNET_TESTBED_ET_OPERATION_FINISHED:
    if ((NULL != event->op_cls) ||
        (NULL != event->details.operation_finished.emsg))
    {
      GNUNET_break (0);
      abort_test ();
      return;
    }
    switch (result)
    {
    case PEERS_STOPPED:
      if (NULL != event->details.operation_finished.generic)
      {
        GNUNET_break (0);
        abort_test ();
        return;
      }
      if (event->op == peer1.operation)
      {
        GNUNET_TESTBED_operation_done (peer1.operation);
        peer1.operation = NULL;
        peer1.peer = NULL;
      }
      else if (event->op == peer2.operation)
      {
        GNUNET_TESTBED_operation_done (peer2.operation);
        peer2.operation = NULL;
        peer2.peer = NULL;
      }
      else if (event->op == peer3.operation)
      {
        GNUNET_TESTBED_operation_done (peer3.operation);
        peer3.operation = NULL;
        peer3.peer = NULL;
      }
      else
      {
        GNUNET_break (0);
        abort_test ();
        return;
      }
      if ((NULL == peer1.peer) && (NULL == peer2.peer) && (NULL == peer3.peer))
      {
        result = SUCCESS;
        GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
      }
      break;
    case PEER1_STARTED:
      if ((NULL != event->details.operation_finished.generic) ||
          (NULL == common_operation))
      {
        GNUNET_break (0);
        abort_test ();
        return;
      }
      GNUNET_TESTBED_operation_done (common_operation);
      common_operation = NULL;
      result = CONTROLLER2_UP;
      peer2.operation =
          GNUNET_TESTBED_peer_create (controller1, neighbour1, cfg,
                                      &peer_create_cb, NULL);
      if (NULL == peer2.operation)
      {
        GNUNET_break (0);
        abort_test ();
        return;
      }
      break;
    case PEER2_STARTED:
      if ((NULL != event->details.operation_finished.generic) ||
          (NULL == common_operation))
      {
        GNUNET_break (0);
        abort_test ();
        return;
      }
      GNUNET_TESTBED_operation_done (common_operation);
      common_operation = NULL;
      result = CONTROLLER3_UP;
      peer3.operation =
          GNUNET_TESTBED_peer_create (controller1, neighbour2, cfg,
                                      &peer_create_cb, NULL);
      if (NULL == peer3.operation)
      {
        GNUNET_break (0);
        abort_test ();
        return;
      }
      break;
    default:
      GNUNET_break (0);
      abort_test ();
      return;
    }
    break;
  case GNUNET_TESTBED_ET_PEER_START:
    switch (result)
    {
    case PEER1_CREATED:
      if (event->details.peer_start.host != host)
      {
        GNUNET_break (0);
        abort_test ();
        return;
      }
      peer1.is_running = GNUNET_YES;
      GNUNET_TESTBED_operation_done (peer1.operation);
      peer1.operation = NULL;
      result = PEER1_STARTED;
      common_operation =
          GNUNET_TESTBED_controller_link (NULL, controller1, neighbour1, NULL,
                                          GNUNET_YES);
      break;
    case PEER2_CREATED:
      if (event->details.peer_start.host != neighbour1)
      {
        GNUNET_break (0);
        abort_test ();
        return;
      }
      peer2.is_running = GNUNET_YES;
      GNUNET_TESTBED_operation_done (peer2.operation);
      peer2.operation = NULL;
      result = PEER2_STARTED;
      if (NULL != common_operation)
      {
        GNUNET_break (0);
        abort_test ();
        return;
      }
      common_operation =
          GNUNET_TESTBED_controller_link (NULL, controller1, neighbour2, NULL,
                                          GNUNET_YES);
      if (NULL == common_operation)
      {
        GNUNET_break (0);
        abort_test ();
        return;
      }
      break;
    case PEER3_CREATED:
      if (event->details.peer_start.host != neighbour2)
      {
        GNUNET_break (0);
        abort_test ();
        return;
      }
      peer3.is_running = GNUNET_YES;
      GNUNET_TESTBED_operation_done (peer3.operation);
      peer3.operation = NULL;
      result = PEER3_STARTED;
      common_operation =
          GNUNET_TESTBED_overlay_connect (NULL, &op_comp_cb, NULL, peer2.peer,
                                          peer1.peer);
      break;
    default:
      GNUNET_break (0);
      abort_test ();
      return;
    }
    break;
  case GNUNET_TESTBED_ET_PEER_STOP:
    if (PEERS_CONNECTED_2 != result)
    {
      GNUNET_break (0);
      abort_test ();
      return;
    }
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
    {
      GNUNET_break (0);
      abort_test ();
      return;
    }
    if ((GNUNET_NO == peer1.is_running) && (GNUNET_NO == peer2.is_running) &&
        (GNUNET_NO == peer3.is_running))
    {
      result = PEERS_STOPPED;
      peer1.operation = GNUNET_TESTBED_peer_destroy (peer1.peer);
      peer2.operation = GNUNET_TESTBED_peer_destroy (peer2.peer);
      peer3.operation = GNUNET_TESTBED_peer_destroy (peer3.peer);
    }
    break;
  case GNUNET_TESTBED_ET_CONNECT:
    if ((NULL != peer1.operation) || (NULL != peer2.operation) ||
        (NULL != peer3.operation) || (NULL == common_operation))
    {
      GNUNET_break (0);
      abort_test ();
      return;
    }
    switch (result)
    {
    case PEER3_STARTED:
      if ((event->details.peer_connect.peer1 != peer2.peer) ||
          (event->details.peer_connect.peer2 != peer1.peer))
      {
        GNUNET_break (0);
        abort_test ();
        return;
      }
      GNUNET_TESTBED_operation_done (common_operation);
      common_operation = NULL;
      result = PEERS_1_2_CONNECTED;
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Peers connected\n");
      common_operation =
          GNUNET_TESTBED_overlay_connect (NULL, &op_comp_cb, NULL, peer2.peer,
                                          peer3.peer);
      break;
    case PEERS_1_2_CONNECTED:
      if ((event->details.peer_connect.peer1 != peer2.peer) ||
          (event->details.peer_connect.peer2 != peer3.peer))
      {
        GNUNET_break (0);
        abort_test ();
        return;
      }
      GNUNET_TESTBED_operation_done (common_operation);
      common_operation = NULL;
      result = PEERS_2_3_CONNECTED;
      delayed_connect_task =
          GNUNET_SCHEDULER_add_delayed (TIME_REL_SECS (3), &do_delayed_connect,
                                        NULL);
      break;
    case PEERS_2_3_CONNECTED:
      if ((event->details.peer_connect.peer1 != peer1.peer) ||
          (event->details.peer_connect.peer2 != peer2.peer))
      {
        GNUNET_break (0);
        abort_test ();
        return;
      }
      GNUNET_TESTBED_operation_done (common_operation);
      common_operation = NULL;
      result = PEERS_CONNECTED_2;
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Peers connected again\n");
      peer1.operation = GNUNET_TESTBED_peer_stop (NULL, peer1.peer, NULL, NULL);
      peer2.operation = GNUNET_TESTBED_peer_stop (NULL, peer2.peer, NULL, NULL);
      peer3.operation = GNUNET_TESTBED_peer_stop (NULL, peer3.peer, NULL, NULL);
      break;
    default:
      GNUNET_break (0);
      abort_test ();
      return;
    }
    break;
  default:
    GNUNET_break (0);
    abort_test ();
    return;
  }
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
    neighbour2 = GNUNET_TESTBED_host_create ("127.0.0.1", NULL, cfg, 0);
    if (NULL == neighbour2)
    {
      GNUNET_break (0);
      abort_test ();
      return;
    }
    reg_handle =
        GNUNET_TESTBED_register_host (controller1, neighbour2,
                                      &registration_comp, neighbour2);
    if (NULL == reg_handle)
    {
      GNUNET_break (0);
      abort_test ();
      return;
    }
    return;
  }
  if (cls != neighbour2)
  {
    GNUNET_break (0);
    abort_test ();
    return;
  }
  peer1.operation =
      GNUNET_TESTBED_peer_create (controller1, host, cfg, &peer_create_cb,
                                  &peer1);
  if (NULL == peer1.operation)
  {
    GNUNET_break (0);
    abort_test ();
    return;
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
status_cb (void *cls, const struct GNUNET_CONFIGURATION_Handle *config,
           int status)
{
  uint64_t event_mask;

  if (GNUNET_OK != status)
  {
    GNUNET_break (0);
    cp1 = NULL;
    abort_test ();
    return;
  }
  event_mask = 0;
  event_mask |= (1L << GNUNET_TESTBED_ET_PEER_START);
  event_mask |= (1L << GNUNET_TESTBED_ET_PEER_STOP);
  event_mask |= (1L << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1L << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  switch (result)
  {
  case INIT:
    controller1 =
        GNUNET_TESTBED_controller_connect (host, event_mask,
                                           &controller_cb, NULL);
    if (NULL == controller1)
    {
      GNUNET_break (0);
      abort_test ();
      return;
    }
    result = CONTROLLER1_UP;
    neighbour1 = GNUNET_TESTBED_host_create ("127.0.0.1", NULL, cfg, 0);
    if (NULL == neighbour1)
    {
      GNUNET_break (0);
      abort_test ();
      return;
    }
    reg_handle =
        GNUNET_TESTBED_register_host (controller1, neighbour1,
                                      &registration_comp, neighbour1);
    if (NULL == reg_handle)
    {
      GNUNET_break (0);
      abort_test ();
      return;
    }
    break;
  default:
    GNUNET_break (0);
    abort_test ();
    return;
  }
}


/**
 * Callbacks of this type are called by GNUNET_TESTBED_is_host_habitable to
 * inform whether the given host is habitable or not. The Handle returned by
 * GNUNET_TESTBED_is_host_habitable() is invalid after this callback is called
 *
 * @param cls NULL
 * @param host the host whose status is being reported; will be NULL if the host
 *          given to GNUNET_TESTBED_is_host_habitable() is NULL
 * @param status GNUNET_YES if it is habitable; GNUNET_NO if not
 */
static void
host_habitable_cb (void *cls, const struct GNUNET_TESTBED_Host *_host,
                   int status)
{
  hc_handle = NULL;
  if (GNUNET_NO == status)
  {
    (void) PRINTF ("%s",
                   "Unable to run the test as this system is not configured "
                   "to use password less SSH logins to localhost.\n"
                   "Skipping test\n");
    GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = NULL;
    (void) GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    result = SKIP;
    return;
  }
  cp1 =
      GNUNET_TESTBED_controller_start ("127.0.0.1", host, status_cb, NULL);
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
  cfg = GNUNET_CONFIGURATION_dup (config);
  host = GNUNET_TESTBED_host_create (NULL, NULL, cfg, 0);
  if (NULL == host)
  {
    GNUNET_break (0);
    abort_test ();
    return;
  }
  if (NULL ==
      (hc_handle =
       GNUNET_TESTBED_is_host_habitable (host, config, &host_habitable_cb,
                                         NULL)))
  {
    GNUNET_TESTBED_host_destroy (host);
    host = NULL;
    (void) PRINTF ("%s",
                   "Unable to run the test as this system is not configured "
                   "to use password less SSH logins to localhost.\n"
                   "Skipping test\n");
    result = SKIP;
    return;
  }
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
  if (GNUNET_OK != ret)
    return 1;
  switch (result)
  {
  case SUCCESS:
    return 0;
  case SKIP:
    return 77;                  /* Mark test as skipped */
  default:
    return 1;
  }
}

/* end of test_testbed_api_3peers_3controllers.c */
