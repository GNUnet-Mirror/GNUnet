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
 * @file testbed/test_testbed_api_controllerlink.c
 * @brief testcase for testing controller to subcontroller linking
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */


/**
 * The controller architecture we try to achieve in this test case:
 *
 *                    Master Controller
 *                    //             \\
 *                   //               \\
 *         Slave Controller 1---------Slave Controller 3
 *                  ||
 *                  ||
 *         Slave Controller 2
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
 * Debug logging shorthand
 */
#define LOG_DEBUG(...)				\
  LOG(GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

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
   * Master controller has started
   */
  MASTER_STARTED,

  /**
   * A peer has been created on master
   */
  MASTER_PEER_CREATE_SUCCESS,

  /**
   * Peer on master controller has been started successfully.
   */
  MASTER_PEER_START_SUCCESS,

  /**
   * The first slave has been registered at master controller
   */
  SLAVE1_REGISTERED,

  /**
   * The second slave has been registered at the master controller
   */
  SLAVE2_REGISTERED,

  /**
   * Link from master to slave 1 has been successfully created
   */
  SLAVE1_LINK_SUCCESS,

  /**
   * Peer create on slave 1 successful
   */
  SLAVE1_PEER_CREATE_SUCCESS,

  /**
   * Peer startup on slave 1 successful
   */
  SLAVE1_PEER_START_SUCCESS,

  /**
   * Link from slave 1 to slave 2 has been successfully created.
   */
  SLAVE2_LINK_SUCCESS,

  /**
   * Peer create on slave 2 successful
   */
  SLAVE2_PEER_CREATE_SUCCESS,

  /**
   * Peer on slave 1 successfully stopped
   */
  SLAVE1_PEER_STOP_SUCCESS,

  /**
   * Peer startup on slave 2 successful
   */
  SLAVE2_PEER_START_SUCCESS,

  /**
   * Try to connect peers on master and slave 2.
   */
  MASTER_SLAVE2_PEERS_CONNECTED,

  /**
   * Slave 3 has successfully registered
   */
  SLAVE3_REGISTERED,

  /**
   * Slave 3 has successfully started
   */
  SLAVE3_STARTED,

  /**
   * Peer created on slave 3
   */
  SLAVE3_PEER_CREATE_SUCCESS,

  /**
   * Peer started at slave 3
   */
  SLAVE3_PEER_START_SUCCESS,

  /**
   * Try to connect peers on slave2 and slave3
   */
  SLAVE2_SLAVE3_PEERS_CONNECTED,

  /**
   * Peer on slave 2 successfully stopped
   */
  SLAVE2_PEER_STOP_SUCCESS,

  /**
   * Peer destroy on slave 1 successful
   */
  SLAVE1_PEER_DESTROY_SUCCESS,

  /**
   * Peer destory on slave 2 successful
   */
  SLAVE2_PEER_DESTROY_SUCCESS,

  /**
   * The configuration of slave 3 is acquired
   */
  SLAVE3_GET_CONFIG_SUCCESS,

  /**
   * Slave 1 has linked to slave 3;
   */
  SLAVE3_LINK_SUCCESS,

  /**
   * Master peer destoryed.  Destory slave 3 peer
   */
  MASTER_PEER_DESTROY_SUCCESS,

  /**
   * Slave 3 peer destroyed.  Mark test as success
   */
  SUCCESS,

  /**
   * Marks test as skipped
   */
  SKIP
};

/**
 * Host for running master controller
 */
static struct GNUNET_TESTBED_Host *host;

/**
 * The master controller process
 */
static struct GNUNET_TESTBED_ControllerProc *cp;

/**
 * Handle to master controller
 */
static struct GNUNET_TESTBED_Controller *mc;

/**
 * Slave host for running slave controller
 */
static struct GNUNET_TESTBED_Host *slave;

/**
 * Another slave host for running another slave controller
 */
static struct GNUNET_TESTBED_Host *slave2;

/**
 * Host for slave 3
 */
static struct GNUNET_TESTBED_Host *slave3;

/**
 * Slave host registration handle
 */
static struct GNUNET_TESTBED_HostRegistrationHandle *rh;

/**
 * Handle to global configuration
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Configuration of slave 3 controller
 */
static struct GNUNET_CONFIGURATION_Handle *cfg3;

/**
 * Abort task
 */
static struct GNUNET_SCHEDULER_Task * abort_task;

/**
 * Operation handle for linking controllers
 */
static struct GNUNET_TESTBED_Operation *op;

/**
 * Handle to peer started at slave 1
 */
static struct GNUNET_TESTBED_Peer *slave1_peer;

/**
 * Handle to peer started at slave 2
 */
static struct GNUNET_TESTBED_Peer *slave2_peer;

/**
 * Handle to peer started at slave 2
 */
static struct GNUNET_TESTBED_Peer *slave3_peer;

/**
 * Handle to a peer started at master controller
 */
static struct GNUNET_TESTBED_Peer *master_peer;

/**
 * The handle for whether a host is habitable or not
 */
struct GNUNET_TESTBED_HostHabitableCheckHandle *hc_handle;

/**
 * The task handle for the delay task
 */
struct GNUNET_SCHEDULER_Task * delay_task_id;

/**
 * Event mask
 */
uint64_t event_mask;

/**
 * Global testing status
 */
static enum Stage result;

/**
 * shortcut to exit during failure
 */
#define FAIL_TEST(cond) do {                                    \
    if (!(cond)) {                                              \
      GNUNET_break(0);                                          \
      if (NULL != abort_task)               \
        GNUNET_SCHEDULER_cancel (abort_task);                   \
      abort_task = NULL;                    \
      GNUNET_SCHEDULER_add_now (do_shutdown, NULL);             \
      return;                                                   \
    }                                                          \
  } while (0)


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
  if (NULL != delay_task_id)
  {
    GNUNET_SCHEDULER_cancel (delay_task_id);
    delay_task_id = NULL;
  }
  if (NULL != hc_handle)
    GNUNET_TESTBED_is_host_habitable_cancel (hc_handle);
  if (NULL != mc)
    GNUNET_TESTBED_controller_disconnect (mc);
  if (NULL != cp)
    GNUNET_TESTBED_controller_stop (cp);
  if (NULL != slave3)
    GNUNET_TESTBED_host_destroy (slave3);
  if (NULL != slave2)
    GNUNET_TESTBED_host_destroy (slave2);
  if (NULL != slave)
    GNUNET_TESTBED_host_destroy (slave);
  if (NULL != host)
    GNUNET_TESTBED_host_destroy (host);
  if (NULL != cfg)
    GNUNET_CONFIGURATION_destroy (cfg);
  if (NULL != cfg3)
    GNUNET_CONFIGURATION_destroy (cfg3);
  if (NULL != rh)
    GNUNET_TESTBED_cancel_registration (rh);
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
  LOG (GNUNET_ERROR_TYPE_WARNING, "Aborting\n");
  abort_task = NULL;
  do_shutdown (cls, tc);
}


/**
 * Calls abort now
 *
 * @param
 * @return
 */
static void
do_abort_now (void *cls)
{
  if (NULL != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
}


/**
 * Callback which will be called to after a host registration succeeded or failed
 *
 * @param cls the host which has been registered
 * @param emsg the error message; NULL if host registration is successful
 */
static void
registration_cont (void *cls, const char *emsg);


/**
 * Task for inserting delay between tests
 *
 * @param
 * @return
 */
static void
delay_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  delay_task_id = NULL;
  switch (result)
  {
  case SLAVE2_PEER_CREATE_SUCCESS:
    op = GNUNET_TESTBED_peer_stop (NULL, slave1_peer, NULL, NULL);
    FAIL_TEST (NULL != op);
    break;
  case MASTER_SLAVE2_PEERS_CONNECTED:
    slave3 = GNUNET_TESTBED_host_create_with_id (3, "127.0.0.1", NULL, cfg, 0);
    rh = GNUNET_TESTBED_register_host (mc, slave3, &registration_cont, NULL);
    break;
  case SLAVE2_SLAVE3_PEERS_CONNECTED:
    op = GNUNET_TESTBED_peer_stop (NULL, slave2_peer, NULL, NULL);
    FAIL_TEST (NULL != op);
    break;
  default:
    FAIL_TEST (0);
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
peer_create_cb (void *cls, struct GNUNET_TESTBED_Peer *peer, const char *emsg)
{
  FAIL_TEST (NULL != peer);
  FAIL_TEST (NULL == emsg);
  switch (result)
  {
  case MASTER_STARTED:
    result = MASTER_PEER_CREATE_SUCCESS;
    master_peer = peer;
    GNUNET_TESTBED_operation_done (op);
    op = GNUNET_TESTBED_peer_start (NULL, master_peer, NULL, NULL);
    break;
  case SLAVE1_LINK_SUCCESS:
    result = SLAVE1_PEER_CREATE_SUCCESS;
    slave1_peer = peer;
    GNUNET_TESTBED_operation_done (op);
    op = GNUNET_TESTBED_peer_start (NULL, slave1_peer, NULL, NULL);
    break;
  case SLAVE2_LINK_SUCCESS:
    result = SLAVE2_PEER_CREATE_SUCCESS;
    slave2_peer = peer;
    GNUNET_TESTBED_operation_done (op);
    delay_task_id =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_SECONDS, 1),
                                      &delay_task,
                                      NULL);
    break;
  case SLAVE3_STARTED:
    result = SLAVE3_PEER_CREATE_SUCCESS;
    slave3_peer = peer;
    GNUNET_TESTBED_operation_done (op);
    op = GNUNET_TESTBED_peer_start (NULL, slave3_peer, NULL, NULL);
    break;
  default:
    FAIL_TEST (0);
  }
  FAIL_TEST (NULL != op);
}


/**
 * Checks the event if it is an operation finished event and if indicates a
 * successfull completion of operation
 *
 * @param event the event information to check
 */
static void
check_operation_success (const struct GNUNET_TESTBED_EventInformation *event)
{
  FAIL_TEST (NULL != event);
  FAIL_TEST (GNUNET_TESTBED_ET_OPERATION_FINISHED == event->type);
  FAIL_TEST (event->op == op);
  FAIL_TEST (NULL == event->op_cls);
  FAIL_TEST (NULL == event->details.operation_finished.emsg);
  FAIL_TEST (NULL == event->details.operation_finished.generic);
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
  switch (result)
  {
  case SLAVE2_REGISTERED:
    check_operation_success (event);
    GNUNET_TESTBED_operation_done (op);
    op = NULL;
    result = SLAVE1_LINK_SUCCESS;
    FAIL_TEST (NULL != slave2);
    FAIL_TEST (NULL != slave);
    op = GNUNET_TESTBED_peer_create (mc, slave, cfg, peer_create_cb, NULL);
    FAIL_TEST (NULL != op);
    break;
  case SLAVE1_PEER_START_SUCCESS:
    check_operation_success (event);
    GNUNET_TESTBED_operation_done (op);
    result = SLAVE2_LINK_SUCCESS;
    op = GNUNET_TESTBED_peer_create (mc, slave2, cfg, peer_create_cb, NULL);
    FAIL_TEST (NULL != op);
    break;
  case MASTER_PEER_CREATE_SUCCESS:
    FAIL_TEST (GNUNET_TESTBED_ET_PEER_START == event->type);
    FAIL_TEST (event->details.peer_start.host == host);
    FAIL_TEST (event->details.peer_start.peer == master_peer);
    GNUNET_TESTBED_operation_done (op);
    result = MASTER_PEER_START_SUCCESS;
    slave = GNUNET_TESTBED_host_create_with_id (1, "127.0.0.1", NULL, cfg, 0);
    FAIL_TEST (NULL != slave);
    rh = GNUNET_TESTBED_register_host (mc, slave, &registration_cont, NULL);
    FAIL_TEST (NULL != rh);
    break;
  case SLAVE1_PEER_CREATE_SUCCESS:
    FAIL_TEST (GNUNET_TESTBED_ET_PEER_START == event->type);
    FAIL_TEST (event->details.peer_start.host == slave);
    FAIL_TEST (event->details.peer_start.peer == slave1_peer);
    GNUNET_TESTBED_operation_done (op);
    result = SLAVE1_PEER_START_SUCCESS;
    op = GNUNET_TESTBED_controller_link (NULL, mc, slave2, slave, GNUNET_YES);
    break;
  case SLAVE2_PEER_CREATE_SUCCESS:
    FAIL_TEST (GNUNET_TESTBED_ET_PEER_STOP == event->type);
    FAIL_TEST (event->details.peer_stop.peer == slave1_peer);
    GNUNET_TESTBED_operation_done (op);
    result = SLAVE1_PEER_STOP_SUCCESS;
    op = GNUNET_TESTBED_peer_start (NULL, slave2_peer, NULL, NULL);
    FAIL_TEST (NULL != op);
    break;
  case SLAVE3_PEER_CREATE_SUCCESS:
    FAIL_TEST (GNUNET_TESTBED_ET_PEER_START == event->type);
    FAIL_TEST (event->details.peer_start.host == slave3);
    FAIL_TEST (event->details.peer_start.peer == slave3_peer);
    GNUNET_TESTBED_operation_done (op);
    result = SLAVE3_PEER_START_SUCCESS;
    sleep (1);
    LOG_DEBUG ("**************************************\n");
    op = GNUNET_TESTBED_overlay_connect (mc, NULL, NULL, slave2_peer,
                                         slave3_peer);
    FAIL_TEST (NULL != op);
    break;
  case SLAVE3_PEER_START_SUCCESS:
    FAIL_TEST (NULL != event);
    FAIL_TEST (GNUNET_TESTBED_ET_CONNECT == event->type);
    FAIL_TEST (event->details.peer_connect.peer1 == slave2_peer);
    FAIL_TEST (event->details.peer_connect.peer2 == slave3_peer);
    result = SLAVE2_SLAVE3_PEERS_CONNECTED;
    GNUNET_TESTBED_operation_done (op);
    op = NULL;
    delay_task_id =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_SECONDS, 1), &delay_task,
                                      NULL);
    break;
  case SLAVE1_PEER_STOP_SUCCESS:
    FAIL_TEST (GNUNET_TESTBED_ET_PEER_START == event->type);
    FAIL_TEST (event->details.peer_start.host == slave2);
    FAIL_TEST (event->details.peer_start.peer == slave2_peer);
    GNUNET_TESTBED_operation_done (op);
    result = SLAVE2_PEER_START_SUCCESS;
    op = GNUNET_TESTBED_overlay_connect (mc, NULL, NULL, master_peer,
                                         slave2_peer);
    break;
  case SLAVE2_PEER_START_SUCCESS:
    FAIL_TEST (NULL != event);
    FAIL_TEST (GNUNET_TESTBED_ET_CONNECT == event->type);
    FAIL_TEST (event->details.peer_connect.peer1 == master_peer);
    FAIL_TEST (event->details.peer_connect.peer2 == slave2_peer);
    result = MASTER_SLAVE2_PEERS_CONNECTED;
    GNUNET_TESTBED_operation_done (op);
    op = NULL;
    delay_task_id =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_SECONDS, 1), &delay_task,
                                      NULL);
    break;
  case SLAVE2_SLAVE3_PEERS_CONNECTED:
    FAIL_TEST (GNUNET_TESTBED_ET_PEER_STOP == event->type);
    FAIL_TEST (event->details.peer_stop.peer == slave2_peer);
    GNUNET_TESTBED_operation_done (op);
    result = SLAVE2_PEER_STOP_SUCCESS;
    op = GNUNET_TESTBED_peer_destroy (slave1_peer);
    FAIL_TEST (NULL != op);
    break;
  case SLAVE2_PEER_STOP_SUCCESS:
    check_operation_success (event);
    GNUNET_TESTBED_operation_done (op);
    result = SLAVE1_PEER_DESTROY_SUCCESS;
    op = GNUNET_TESTBED_peer_destroy (slave2_peer);
    FAIL_TEST (NULL != op);
    break;
  case SLAVE1_PEER_DESTROY_SUCCESS:
    check_operation_success (event);
    GNUNET_TESTBED_operation_done (op);
    op = NULL;
    result = SLAVE2_PEER_DESTROY_SUCCESS;
    op = GNUNET_TESTBED_get_slave_config (NULL, mc, slave3);
    FAIL_TEST (NULL != op);
    break;
  case SLAVE2_PEER_DESTROY_SUCCESS:
    FAIL_TEST (NULL != event);
    FAIL_TEST (GNUNET_TESTBED_ET_OPERATION_FINISHED == event->type);
    FAIL_TEST (event->op == op);
    FAIL_TEST (NULL == event->op_cls);
    FAIL_TEST (NULL == event->details.operation_finished.emsg);
    cfg3 = GNUNET_CONFIGURATION_dup (event->details.operation_finished.generic);
    GNUNET_TESTBED_operation_done (op);
    result = SLAVE3_GET_CONFIG_SUCCESS;
    op = GNUNET_TESTBED_controller_link (NULL, mc, slave3, slave, GNUNET_NO);
    break;
  case SLAVE3_REGISTERED:
    check_operation_success (event);
    GNUNET_TESTBED_operation_done (op);
    op = NULL;
    result = SLAVE3_STARTED;
    op = GNUNET_TESTBED_peer_create (mc, slave3, cfg, peer_create_cb, NULL);
    FAIL_TEST (NULL != op);
    break;
  case SLAVE3_GET_CONFIG_SUCCESS:
    result = SLAVE3_LINK_SUCCESS;
    GNUNET_TESTBED_operation_done (op);
    op = GNUNET_TESTBED_peer_destroy (master_peer);
    break;
  case SLAVE3_LINK_SUCCESS:
    check_operation_success (event);
    result = MASTER_PEER_DESTROY_SUCCESS;
    GNUNET_TESTBED_operation_done (op);
    op = GNUNET_TESTBED_peer_destroy (slave3_peer);
    break;
  case MASTER_PEER_DESTROY_SUCCESS:
    result = SUCCESS;
    GNUNET_TESTBED_operation_done (op);
    op = NULL;
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 1), &do_shutdown,
                                  NULL);
    break;
  default:
    FAIL_TEST (0);
  }
}


/**
 * Callback which will be called to after a host registration succeeded or failed
 *
 * @param cls the host which has been registered
 * @param emsg the error message; NULL if host registration is successful
 */
static void
registration_cont (void *cls, const char *emsg)
{
  rh = NULL;
  switch (result)
  {
  case MASTER_PEER_START_SUCCESS:
    FAIL_TEST (NULL == emsg);
    FAIL_TEST (NULL != mc);
    result = SLAVE1_REGISTERED;
    slave2 = GNUNET_TESTBED_host_create_with_id (2, "127.0.0.1", NULL, cfg, 0);
    FAIL_TEST (NULL != slave2);
    rh = GNUNET_TESTBED_register_host (mc, slave2, &registration_cont, NULL);
    FAIL_TEST (NULL != rh);
    break;
  case SLAVE1_REGISTERED:
    FAIL_TEST (NULL == emsg);
    FAIL_TEST (NULL != mc);
    result = SLAVE2_REGISTERED;
    FAIL_TEST (NULL != cfg);
    op = GNUNET_TESTBED_controller_link (NULL, mc, slave, NULL, GNUNET_YES);
    FAIL_TEST (NULL != op);
    break;
  case MASTER_SLAVE2_PEERS_CONNECTED:
    FAIL_TEST (NULL == emsg);
    FAIL_TEST (NULL != mc);
    FAIL_TEST (NULL == op);
    result = SLAVE3_REGISTERED;
    op = GNUNET_TESTBED_controller_link (NULL, mc, slave3, NULL, GNUNET_YES);
    FAIL_TEST (NULL != op);
    break;
  default:
    GNUNET_break (0);
    do_abort_now (NULL);
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
  switch (result)
  {
  case INIT:
    FAIL_TEST (GNUNET_OK == status);
    event_mask = 0;
    event_mask |= (1L << GNUNET_TESTBED_ET_PEER_START);
    event_mask |= (1L << GNUNET_TESTBED_ET_PEER_STOP);
    event_mask |= (1L << GNUNET_TESTBED_ET_CONNECT);
    event_mask |= (1L << GNUNET_TESTBED_ET_OPERATION_FINISHED);
    mc = GNUNET_TESTBED_controller_connect (host, event_mask,
                                            &controller_cb, NULL);
    FAIL_TEST (NULL != mc);
    result = MASTER_STARTED;
    op = GNUNET_TESTBED_peer_create (mc, host, cfg, peer_create_cb, NULL);
    FAIL_TEST (NULL != op);
    break;
  default:
    GNUNET_break (0);
    cp = NULL;
    do_abort_now (NULL);
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
  cp = GNUNET_TESTBED_controller_start ("127.0.0.1", host, status_cb,
                                        NULL);
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
  FAIL_TEST (NULL != host);
  if (NULL ==
      (hc_handle =
       GNUNET_TESTBED_is_host_habitable (host, config, &host_habitable_cb,
                                         NULL)))
  {
    GNUNET_TESTBED_host_destroy (host);
    GNUNET_CONFIGURATION_destroy (cfg);
    cfg = NULL;
    host = NULL;
    (void) PRINTF ("%s",
                   "Unable to run the test as this system is not configured "
                   "to use password less SSH logins to localhost.\n"
                   "Marking test as successful\n");
    result = SKIP;
    return;
  }
  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MINUTES, 5), &do_abort,
                                    NULL);
}


/**
 * Main function
 */
int
main (int argc, char **argv)
{
  char *const argv2[] = { "test_testbed_api_controllerlink",
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
                          "test_testbed_api_controllerlink", "nohelp", options,
                          &run, NULL);
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

/* end of test_testbed_api_controllerlink.c */
