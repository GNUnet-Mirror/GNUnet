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
#include "gnunet_arm_service.h"
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
 * Handle to peer's ARM service
 */
static struct GNUNET_ARM_Handle *arm_handle;

/**
 * Abort task identifier
 */
static struct GNUNET_SCHEDULER_Task * abort_task;

/**
 * The testing result
 */
static int result;


/**
 * Enumeration of sub testcases
 */
enum Test
{
    /**
     * Test cases which are not covered by the below ones
     */
  OTHER,

    /**
     * Test where we get a peer config from controller
     */
  PEER_GETCONFIG,

    /**
     * Test where we connect to a service running on the peer
     */
  PEER_SERVICE_CONNECT,

    /**
     * Test where we get a peer's identity from controller
     */
  PEER_DESTROY,
};

/**
 * Testing status
 */
static enum Test sub_test;

/**
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down...\n");
  if (NULL != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  if (NULL != reg_handle)
    GNUNET_TESTBED_cancel_registration (reg_handle);
  if (NULL != controller)
    GNUNET_TESTBED_controller_disconnect (controller);
  if (NULL != cfg)
    GNUNET_CONFIGURATION_destroy (cfg);
  if (NULL != cp)
    GNUNET_TESTBED_controller_stop (cp);
  if (NULL != neighbour)
    GNUNET_TESTBED_host_destroy (neighbour);
  if (NULL != host)
  GNUNET_TESTBED_host_destroy (host);
}


/**
 * shortcut to exit during failure
 */
#define FAIL_TEST(cond, ret) do {                                   \
    if (!(cond)) {                                              \
      GNUNET_break(0);                                          \
      if (NULL != abort_task)               \
        GNUNET_SCHEDULER_cancel (abort_task);                   \
      abort_task = NULL;                    \
      GNUNET_SCHEDULER_add_now (do_shutdown, NULL);             \
      ret;                                                   \
    }                                                          \
  } while (0)


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
  do_shutdown (cls, tc);
}


/**
 * Adapter function called to establish a connection to
 * a service.
 *
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
arm_connect_adapter (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  FAIL_TEST (NULL == cls, return NULL);
  FAIL_TEST (OTHER == sub_test, return NULL);
  sub_test = PEER_SERVICE_CONNECT;
  arm_handle = GNUNET_ARM_connect (cfg, NULL, NULL);
  return arm_handle;
}


/**
 * Adapter function called to destroy a connection to
 * a service.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
arm_disconnect_adapter (void *cls, void *op_result)
{
  FAIL_TEST (NULL != op_result, return);
  FAIL_TEST (op_result == arm_handle, return);
  GNUNET_ARM_disconnect_and_free (arm_handle);
  arm_handle = NULL;
  FAIL_TEST (PEER_SERVICE_CONNECT == sub_test, return);
  FAIL_TEST (NULL != operation, return);
  operation = GNUNET_TESTBED_peer_stop (NULL, peer, NULL, NULL);
  FAIL_TEST (NULL != operation, return);
}


/**
 * Callback to be called when a service connect operation is completed
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param ca_result the service handle returned from GNUNET_TESTBED_ConnectAdapter()
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
service_connect_comp_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
                         void *ca_result, const char *emsg)
{
  switch (sub_test)
  {
  case PEER_SERVICE_CONNECT:
    FAIL_TEST (operation == op, return);
    FAIL_TEST (NULL == emsg, return);
    FAIL_TEST (NULL == cls, return);
    FAIL_TEST (ca_result == arm_handle, return);
    GNUNET_TESTBED_operation_done (operation);  /* This results in call to
                                                 * disconnect adapter */
    break;
  default:
    FAIL_TEST (0, return);
  }
}



/**
 * Callback to be called when the requested peer information is available
 *
 * @param cb_cls the closure from GNUNET_TETSBED_peer_get_information()
 * @param op the operation this callback corresponds to
 * @param pinfo the result; will be NULL if the operation has failed
 * @param emsg error message if the operation has failed; will be NULL if the
 *          operation is successfull
 */
static void
peerinfo_cb (void *cb_cls, struct GNUNET_TESTBED_Operation *op,
             const struct GNUNET_TESTBED_PeerInformation *pinfo,
             const char *emsg)
{
  switch (sub_test)
  {
  case PEER_GETCONFIG:
    FAIL_TEST (NULL != pinfo, return);
    FAIL_TEST (NULL == emsg, return);
    FAIL_TEST (NULL == cb_cls, return);
    FAIL_TEST (operation == op, return);
    FAIL_TEST (GNUNET_TESTBED_PIT_CONFIGURATION == pinfo->pit, return);
    FAIL_TEST (NULL != pinfo->result.cfg, return);
    sub_test = PEER_DESTROY;
    GNUNET_TESTBED_operation_done (operation);
    operation = GNUNET_TESTBED_peer_destroy (peer);
    break;
  default:
    FAIL_TEST (0, return);
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
    switch (sub_test)
    {
    case PEER_DESTROY:
      FAIL_TEST (event->op == operation, return);
      FAIL_TEST (NULL == event->op_cls, return);
      FAIL_TEST (NULL == event->details.operation_finished.emsg, return);
      FAIL_TEST (NULL == event->details.operation_finished.generic, return);
      GNUNET_TESTBED_operation_done (operation);
      GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
      break;
    case PEER_SERVICE_CONNECT:
      FAIL_TEST (event->op == operation, return);
      FAIL_TEST (NULL == event->op_cls, return);
      FAIL_TEST (NULL == event->details.operation_finished.emsg, return);
      FAIL_TEST (NULL != arm_handle, return);
      FAIL_TEST (event->details.operation_finished.generic == arm_handle, return);
      break;
    default:
      FAIL_TEST (0, return);
      break;
    }
    break;
  case GNUNET_TESTBED_ET_PEER_START:
    FAIL_TEST (event->details.peer_start.host == host, return);
    FAIL_TEST (event->details.peer_start.peer == peer, return);
    FAIL_TEST (OTHER == sub_test, return);
    GNUNET_TESTBED_operation_done (operation);
    operation =
        GNUNET_TESTBED_service_connect (NULL, peer, "dht",
                                        &service_connect_comp_cb, NULL,
                                        &arm_connect_adapter,
                                        &arm_disconnect_adapter, NULL);
    FAIL_TEST (NULL != operation, return);
    break;
  case GNUNET_TESTBED_ET_PEER_STOP:
    FAIL_TEST (event->details.peer_stop.peer == peer, return);
    FAIL_TEST (PEER_SERVICE_CONNECT == sub_test, return);
    result = GNUNET_YES;
    sub_test = PEER_GETCONFIG;
    GNUNET_TESTBED_operation_done (operation);
    operation =
        GNUNET_TESTBED_peer_get_information (peer,
                                             GNUNET_TESTBED_PIT_CONFIGURATION,
                                             &peerinfo_cb, NULL);
    break;
  default:
    FAIL_TEST (0, return);          /* We should never reach this state */
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
  struct GNUNET_TESTBED_Peer **peer_ptr;

  peer_ptr = cls;
  FAIL_TEST (NULL != peer, return);
  FAIL_TEST (NULL != peer_ptr, return);
  *peer_ptr = peer;
  GNUNET_TESTBED_operation_done (operation);
  operation = GNUNET_TESTBED_peer_start (NULL, peer, NULL, NULL);
  FAIL_TEST (NULL != operation, return);
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
  FAIL_TEST (cls == neighbour, return);
  reg_handle = NULL;
  operation =
      GNUNET_TESTBED_peer_create (controller, host, cfg, &peer_create_cb,
                                  &peer);
  FAIL_TEST (NULL != operation, return);
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
status_cb (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg_, int status)
{
  uint64_t event_mask;

  if (GNUNET_OK != status)
  {
    cp = NULL;
    FAIL_TEST (0, return);
    return;
  }
  event_mask = 0;
  event_mask |= (1L << GNUNET_TESTBED_ET_PEER_START);
  event_mask |= (1L << GNUNET_TESTBED_ET_PEER_STOP);
  event_mask |= (1L << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1L << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  controller =
      GNUNET_TESTBED_controller_connect (host, event_mask, &controller_cb,
                                         NULL);
  FAIL_TEST (NULL != controller, return);
  neighbour = GNUNET_TESTBED_host_create ("localhost", NULL, cfg, 0);
  FAIL_TEST (NULL != neighbour, return);
  reg_handle =
      GNUNET_TESTBED_register_host (controller, neighbour, &registration_comp,
                                    neighbour);
  FAIL_TEST (NULL != reg_handle, return);
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
  FAIL_TEST (NULL != host, return);
  cp = GNUNET_TESTBED_controller_start ("127.0.0.1", host, status_cb,
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

  char *const argv2[] = { "test_testbed_api",
    "-c", "test_testbed_api.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  result = GNUNET_SYSERR;
  ret =
      GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                          "test_testbed_api", "nohelp", options, &run, NULL);
  if ((GNUNET_OK != ret) || (GNUNET_OK != result))
    return 1;
  return 0;
}

/* end of test_testbed_api.c */
