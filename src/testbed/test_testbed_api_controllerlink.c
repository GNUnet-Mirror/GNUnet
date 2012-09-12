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
 * @file testbed/test_testbed_api_controllerlink.c
 * @brief testcase for testing controller to subcontroller linking
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
     * Link from slave 1 to slave 2 has been successfully created.
     */
  SLAVE2_LINK_SUCCESS,

    /**
     * Peer create on slave 1 successful
     */
  SLAVE1_PEER_CREATE_SUCCESS,

    /**
     * Peer create on slave 2 successful
     */
  SLAVE2_PEER_CREATE_SUCCESS,

    /**
     * Peer startup on slave 1 successful
     */
  SLAVE1_PEER_START_SUCCESS,

    /**
     * Peer on slave 1 successfully stopped
     */
  SLAVE1_PEER_STOP_SUCCESS,

    /**
     * Peer startup on slave 2 successful
     */
  SLAVE2_PEER_START_SUCCESS,

    /**
     * Peer on slave 2 successfully stopped
     */
  SLAVE2_PEER_STOP_SUCCESS,

    /**
     * Peer destroy on slave 1 successful
     */
  SLAVE1_PEER_DESTROY_SUCCESS,

    /**
     * Peer destory on slave 2 successful; Marks test as successful
     */
  SUCCESS
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
 * Slave host registration handle
 */
static struct GNUNET_TESTBED_HostRegistrationHandle *rh;

/**
 * Handle to global configuration
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Abort task
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task;

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
 * Event mask
 */
uint64_t event_mask;

/**
 * Global testing status
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
  if (NULL != slave2)
    GNUNET_TESTBED_host_destroy (slave2);
  if (NULL != slave)
    GNUNET_TESTBED_host_destroy (slave);
  if (NULL != host)
    GNUNET_TESTBED_host_destroy (host);
  if (NULL != mc)
    GNUNET_TESTBED_controller_disconnect (mc);
  if (NULL != cfg)
    GNUNET_CONFIGURATION_destroy (cfg);
  if (NULL != cp)
    GNUNET_TESTBED_controller_stop (cp);
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
  LOG (GNUNET_ERROR_TYPE_WARNING, "Test timedout -- Aborting\n");
  abort_task = GNUNET_SCHEDULER_NO_TASK;
  do_shutdown (cls, tc);
}


/**
 * Task for inserting delay between tests
 *
 * @param
 * @return
 */
static void
delay_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  switch (result)
  {
  case SLAVE1_PEER_START_SUCCESS:
    op = GNUNET_TESTBED_peer_stop (slave1_peer, NULL, NULL);
    GNUNET_assert (NULL != op);
    break;
  case SLAVE2_PEER_START_SUCCESS:
    op = GNUNET_TESTBED_peer_stop (slave2_peer, NULL, NULL);
    GNUNET_assert (NULL != op);
    break;
  default:
    GNUNET_assert (0);
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
  switch (result)
  {
  case SLAVE2_LINK_SUCCESS:
    GNUNET_assert (NULL != peer);
    GNUNET_assert (NULL == emsg);
    result = SLAVE1_PEER_CREATE_SUCCESS;
    slave1_peer = peer;
    GNUNET_TESTBED_operation_done (op);
    op = GNUNET_TESTBED_peer_create (mc, slave2, cfg, peer_create_cb, NULL);
    GNUNET_assert (NULL != op);
    break;
  case SLAVE1_PEER_CREATE_SUCCESS:
    GNUNET_assert (NULL != peer);
    GNUNET_assert (NULL == emsg);
    result = SLAVE2_PEER_CREATE_SUCCESS;
    slave2_peer = peer;
    GNUNET_TESTBED_operation_done (op);
    op = GNUNET_TESTBED_peer_start (slave1_peer, NULL, NULL);
    GNUNET_assert (NULL != op);
    break;
  default:
    GNUNET_assert (0);
  }
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
  GNUNET_assert (NULL != event);
  GNUNET_assert (GNUNET_TESTBED_ET_OPERATION_FINISHED == event->type);
  GNUNET_assert (event->details.operation_finished.operation == op);
  GNUNET_assert (NULL == event->details.operation_finished.op_cls);
  GNUNET_assert (NULL == event->details.operation_finished.emsg);
  GNUNET_assert (NULL == event->details.operation_finished.generic);
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
    GNUNET_assert (NULL != slave2);
    GNUNET_assert (NULL != slave);
    op = GNUNET_TESTBED_controller_link (mc, slave2, slave, cfg, GNUNET_YES);
    GNUNET_assert (NULL != op);
    break;
  case SLAVE1_LINK_SUCCESS:
    check_operation_success (event);
    GNUNET_TESTBED_operation_done (op);
    op = NULL;
    result = SLAVE2_LINK_SUCCESS;
    op = GNUNET_TESTBED_peer_create (mc, slave, cfg, peer_create_cb, NULL);
    GNUNET_assert (NULL != op);
    break;
  case SLAVE2_PEER_CREATE_SUCCESS:
    GNUNET_assert (GNUNET_TESTBED_ET_PEER_START == event->type);
    GNUNET_assert (event->details.peer_start.host == slave);
    GNUNET_assert (event->details.peer_start.peer == slave1_peer);
    GNUNET_TESTBED_operation_done (op);
    result = SLAVE1_PEER_START_SUCCESS;
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 1), &delay_task,
                                  NULL);
    break;
  case SLAVE1_PEER_START_SUCCESS:
    GNUNET_assert (GNUNET_TESTBED_ET_PEER_STOP == event->type);
    GNUNET_assert (event->details.peer_stop.peer == slave1_peer);
    GNUNET_TESTBED_operation_done (op);
    result = SLAVE1_PEER_STOP_SUCCESS;
    op = GNUNET_TESTBED_peer_start (slave2_peer, NULL, NULL);
    GNUNET_assert (NULL != op);
    break;
  case SLAVE1_PEER_STOP_SUCCESS:
    GNUNET_assert (GNUNET_TESTBED_ET_PEER_START == event->type);
    GNUNET_assert (event->details.peer_start.host == slave2);
    GNUNET_assert (event->details.peer_start.peer == slave2_peer);
    GNUNET_TESTBED_operation_done (op);
    result = SLAVE2_PEER_START_SUCCESS;
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 1), &delay_task,
                                  NULL);
    break;
  case SLAVE2_PEER_START_SUCCESS:
    GNUNET_assert (GNUNET_TESTBED_ET_PEER_STOP == event->type);
    GNUNET_assert (event->details.peer_stop.peer == slave2_peer);
    GNUNET_TESTBED_operation_done (op);
    result = SLAVE2_PEER_STOP_SUCCESS;
    op = GNUNET_TESTBED_peer_destroy (slave1_peer);
    GNUNET_assert (NULL != op);
    break;
  case SLAVE2_PEER_STOP_SUCCESS:
    check_operation_success (event);
    GNUNET_TESTBED_operation_done (op);
    result = SLAVE1_PEER_DESTROY_SUCCESS;
    op = GNUNET_TESTBED_peer_destroy (slave2_peer);
    GNUNET_assert (NULL != op);
    break;
  case SLAVE1_PEER_DESTROY_SUCCESS:
    check_operation_success (event);
    GNUNET_TESTBED_operation_done (op);
    result = SUCCESS;
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    break;
  default:
    GNUNET_assert (0);
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
  case MASTER_STARTED:
    GNUNET_assert (NULL == emsg);
    GNUNET_assert (NULL != mc);
    result = SLAVE1_REGISTERED;
    slave2 = GNUNET_TESTBED_host_create_with_id (2, "127.0.0.1", NULL, 0);
    GNUNET_assert (NULL != slave2);
    rh = GNUNET_TESTBED_register_host (mc, slave2, &registration_cont, NULL);
    GNUNET_assert (NULL != rh);
    break;
  case SLAVE1_REGISTERED:
    GNUNET_assert (NULL == emsg);
    GNUNET_assert (NULL != mc);
    result = SLAVE2_REGISTERED;
    GNUNET_assert (NULL != cfg);
    op = GNUNET_TESTBED_controller_link (mc, slave, NULL, cfg, GNUNET_YES);
    GNUNET_assert (NULL != op);
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
status_cb (void *cls, const struct GNUNET_CONFIGURATION_Handle *config,
           int status)
{
  switch (result)
  {
  case INIT:
    GNUNET_assert (GNUNET_OK == status);
    event_mask = 0;
    event_mask |= (1L << GNUNET_TESTBED_ET_PEER_START);
    event_mask |= (1L << GNUNET_TESTBED_ET_PEER_STOP);
    event_mask |= (1L << GNUNET_TESTBED_ET_CONNECT);
    event_mask |= (1L << GNUNET_TESTBED_ET_OPERATION_FINISHED);
    mc = GNUNET_TESTBED_controller_connect (config, host, event_mask,
                                            &controller_cb, NULL);
    GNUNET_assert (NULL != mc);
    result = MASTER_STARTED;
    slave = GNUNET_TESTBED_host_create_with_id (1, "127.0.0.1", NULL, 0);
    GNUNET_assert (NULL != slave);
    rh = GNUNET_TESTBED_register_host (mc, slave, &registration_cont, NULL);
    GNUNET_assert (NULL != rh);
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
  cfg = GNUNET_CONFIGURATION_dup (config);
  cp = GNUNET_TESTBED_controller_start ("127.0.0.1", host, cfg, status_cb,
                                        NULL);
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
  int ret;

  char *const argv2[] = { "test_testbed_api_controllerlink",
    "-c", "test_testbed_api.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  char *const remote_args[] = {
    "ssh", "-o", "BatchMode=yes", "127.0.0.1", "echo", "Hello", "World", NULL
  };
  struct GNUNET_OS_Process *auxp;
  enum GNUNET_OS_ProcessStatusType type;
  unsigned long code;

  auxp =
      GNUNET_OS_start_process_vap (GNUNET_NO, GNUNET_OS_INHERIT_STD_ALL, NULL,
                                   NULL, "ssh", remote_args);
  GNUNET_assert (NULL != auxp);
  do
  {
    ret = GNUNET_OS_process_status (auxp, &type, &code);
    GNUNET_assert (GNUNET_SYSERR != ret);
    (void) usleep (300);
  }
  while (GNUNET_NO == ret);
  GNUNET_OS_process_destroy (auxp);
  if (0 != code)
  {
    (void) printf ("Unable to run the test as this system is not configured "
                   "to use password less SSH logins to localhost.\n"
                   "Marking test as successful\n");
    return 0;
  }
  result = INIT;
  ret =
      GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                          "test_testbed_api_controllerlink", "nohelp", options,
                          &run, NULL);
  if ((GNUNET_OK != ret) || (SUCCESS != result))
    return 1;
  return 0;
}

/* end of test_testbed_api_controllerlink.c */

