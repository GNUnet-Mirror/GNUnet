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
#include "gnunet_dht_service.h"
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
 * Handle to peer's DHT service
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Abort task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task;

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
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG (GNUNET_ERROR_TYPE_WARNING, "Test timedout -- Aborting\n");
  abort_task = GNUNET_SCHEDULER_NO_TASK;
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
dht_connect_adapter (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (NULL == cls);
  GNUNET_assert (OTHER == sub_test);
  sub_test = PEER_SERVICE_CONNECT;
  dht_handle = GNUNET_DHT_connect (cfg, 10);
  return dht_handle;
}


/**
 * Adapter function called to destroy a connection to
 * a service.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
dht_disconnect_adapter (void *cls, void *op_result)
{
  GNUNET_assert (NULL != op_result);
  GNUNET_assert (op_result == dht_handle);
  GNUNET_DHT_disconnect (dht_handle);
  dht_handle = NULL;
  GNUNET_assert (PEER_SERVICE_CONNECT == sub_test);
  GNUNET_assert (NULL != operation);
  operation = GNUNET_TESTBED_peer_stop (peer, NULL, NULL);
  GNUNET_assert (NULL != operation);
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
    GNUNET_assert (operation == op);
    GNUNET_assert (NULL == emsg);
    GNUNET_assert (NULL == cls);
    GNUNET_assert (ca_result == dht_handle);
    GNUNET_TESTBED_operation_done (operation);  /* This results in call to
                                                 * disconnect adapter */
    break;
  default:
    GNUNET_assert (0);
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
    GNUNET_assert (NULL != pinfo);
    GNUNET_assert (NULL == emsg);
    GNUNET_assert (NULL == cb_cls);
    GNUNET_assert (operation == op);
    GNUNET_assert (GNUNET_TESTBED_PIT_CONFIGURATION == pinfo->pit);
    GNUNET_assert (NULL != pinfo->result.cfg);
    sub_test = PEER_DESTROY;
    GNUNET_TESTBED_operation_done (operation);
    operation = GNUNET_TESTBED_peer_destroy (peer);
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
  case GNUNET_TESTBED_ET_OPERATION_FINISHED:
    switch (sub_test)
    {
    case PEER_DESTROY:
      GNUNET_assert (event->details.operation_finished.operation == operation);
      GNUNET_assert (NULL == event->details.operation_finished.op_cls);
      GNUNET_assert (NULL == event->details.operation_finished.emsg);
      GNUNET_assert (NULL == event->details.operation_finished.generic);
      GNUNET_TESTBED_operation_done (operation);
      GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
      break;
    case PEER_SERVICE_CONNECT:
      GNUNET_assert (event->details.operation_finished.operation == operation);
      GNUNET_assert (NULL == event->details.operation_finished.op_cls);
      GNUNET_assert (NULL == event->details.operation_finished.emsg);
      GNUNET_assert (NULL != dht_handle);
      GNUNET_assert (event->details.operation_finished.generic == dht_handle);
      break;
    default:
      GNUNET_assert (0);
      break;
    }
    break;
  case GNUNET_TESTBED_ET_PEER_START:
    GNUNET_assert (event->details.peer_start.host == host);
    GNUNET_assert (event->details.peer_start.peer == peer);
    GNUNET_assert (OTHER == sub_test);
    GNUNET_TESTBED_operation_done (operation);
    operation =
        GNUNET_TESTBED_service_connect (NULL, peer, "dht",
                                        &service_connect_comp_cb, NULL,
                                        &dht_connect_adapter,
                                        &dht_disconnect_adapter, NULL);
    GNUNET_assert (NULL != operation);
    break;
  case GNUNET_TESTBED_ET_PEER_STOP:
    GNUNET_assert (event->details.peer_stop.peer == peer);
    GNUNET_assert (PEER_SERVICE_CONNECT == sub_test);
    result = GNUNET_YES;
    sub_test = PEER_GETCONFIG;
    GNUNET_TESTBED_operation_done (operation);
    operation =
        GNUNET_TESTBED_peer_get_information (peer,
                                             GNUNET_TESTBED_PIT_CONFIGURATION,
                                             &peerinfo_cb, NULL);
    break;
  default:
    GNUNET_assert (0);          /* We should never reach this state */
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
  GNUNET_assert (NULL != peer);
  GNUNET_assert (NULL != peer_ptr);
  *peer_ptr = peer;
  GNUNET_TESTBED_operation_done (operation);
  operation = GNUNET_TESTBED_peer_start (NULL, peer, NULL, NULL);
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
  operation =
      GNUNET_TESTBED_peer_create (controller, host, cfg, &peer_create_cb,
                                  &peer);
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
