/*
     This file is part of GNUnet.
     Copyright (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file arm/test_exponential_backoff.c
 * @brief testcase for gnunet-service-arm.c
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"

#define LOG(...) GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

#define START_ARM GNUNET_YES

#define LOG_BACKOFF GNUNET_NO

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

#define SERVICE_TEST_TIMEOUT GNUNET_TIME_UNIT_FOREVER_REL

#define FIVE_MILLISECONDS GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 5)

#define SERVICE "do-nothing"

#define BINARY "mockup-service"

#define CFGFILENAME "test_arm_api_data2.conf"


static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_ARM_Handle *arm;

static struct GNUNET_ARM_MonitorHandle *mon;

static int ok = 1;

static int phase = 0;

static int trialCount;

static struct GNUNET_TIME_Absolute startedWaitingAt;

struct GNUNET_TIME_Relative waitedFor;

struct GNUNET_TIME_Relative waitedFor_prev;

#if LOG_BACKOFF
static FILE *killLogFilePtr;

static char *killLogFileName;
#endif


typedef void (*GNUNET_CLIENT_ShutdownTask) (void *cls, int reason);

/**
 * Context for handling the shutdown of a service.
 */
struct ShutdownContext
{
  /**
   * Connection to the service that is being shutdown.
   */
  struct GNUNET_CLIENT_Connection *sock;

  /**
   * Time allowed for shutdown to happen.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Task set up to cancel the shutdown request on timeout.
   */
  struct GNUNET_SCHEDULER_Task * cancel_task;

  /**
   * Task to call once shutdown complete
   */
  GNUNET_CLIENT_ShutdownTask cont;

  /**
   * Closure for shutdown continuation
   */
  void *cont_cls;

  /**
   * We received a confirmation that the service will shut down.
   */
  int confirmed;

};

/**
 * Handler receiving response to service shutdown requests.
 * We expect it to be called with NULL, since the service that
 * we are shutting down will just die without replying.
 *
 * @param cls closure
 * @param msg NULL, indicating socket closure.
 */
static void
service_shutdown_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct ShutdownContext *shutdown_ctx = cls;

  if (NULL == msg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Service shutdown complete.\n");
    if (shutdown_ctx->cont != NULL)
      shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_NO);

    GNUNET_SCHEDULER_cancel (shutdown_ctx->cancel_task);
    GNUNET_CLIENT_disconnect (shutdown_ctx->sock);
    GNUNET_free (shutdown_ctx);
    return;
  }
  GNUNET_assert (0);
}


/**
 * Shutting down took too long, cancel receive and return error.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
service_shutdown_cancel (void *cls,
			 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ShutdownContext *shutdown_ctx = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "service_shutdown_cancel called!\n");
  shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_SYSERR);
  GNUNET_CLIENT_disconnect (shutdown_ctx->sock);
  GNUNET_free (shutdown_ctx);
}


/**
 * If possible, write a shutdown message to the target
 * buffer and destroy the client connection.
 *
 * @param cls the "struct GNUNET_CLIENT_Connection" to destroy
 * @param size number of bytes available in buf
 * @param buf NULL on error, otherwise target buffer
 * @return number of bytes written to buf
 */
static size_t
write_shutdown (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *msg;
  struct ShutdownContext *shutdown_ctx = cls;

  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    LOG ("Failed to send a shutdown request\n");
    shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_SYSERR);
    GNUNET_CLIENT_disconnect (shutdown_ctx->sock);
    GNUNET_free (shutdown_ctx);
    return 0;			/* client disconnected */
  }

  GNUNET_CLIENT_receive (shutdown_ctx->sock, &service_shutdown_handler,
			 shutdown_ctx, GNUNET_TIME_UNIT_FOREVER_REL);
  shutdown_ctx->cancel_task = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_absolute_get_remaining (shutdown_ctx->timeout),
      &service_shutdown_cancel, shutdown_ctx);
  msg = (struct GNUNET_MessageHeader *) buf;
  msg->type = htons (GNUNET_MESSAGE_TYPE_ARM_STOP);
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  strcpy ((char *) &msg[1], SERVICE);
  LOG ("Sent a shutdown request\n");
  return sizeof (struct GNUNET_MessageHeader) + strlen (SERVICE) + 1;
}


/**
 * Request that the service should shutdown.
 * Afterwards, the connection will automatically be
 * disconnected.  Hence the "sock" should not
 * be used by the caller after this call
 * (calling this function frees "sock" after a while).
 *
 * @param sock the socket connected to the service
 * @param timeout how long to wait before giving up on transmission
 * @param cont continuation to call once the service is really down
 * @param cont_cls closure for continuation
 *
 */
static void
do_nothing_service_shutdown (struct GNUNET_CLIENT_Connection *sock,
		      struct GNUNET_TIME_Relative timeout,
		      GNUNET_CLIENT_ShutdownTask cont, void *cont_cls)
{
  struct ShutdownContext *shutdown_ctx;

  shutdown_ctx = GNUNET_new (struct ShutdownContext);
  shutdown_ctx->cont = cont;
  shutdown_ctx->cont_cls = cont_cls;
  shutdown_ctx->sock = sock;
  shutdown_ctx->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  GNUNET_CLIENT_notify_transmit_ready (sock,
				       sizeof (struct GNUNET_MessageHeader) + strlen (SERVICE) + 1,
				       timeout, GNUNET_NO, &write_shutdown,
				       shutdown_ctx);
}


static void
kill_task (void *cbData, const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
shutdown_cont (void *cls, int reason)
{
  if (GNUNET_NO != reason)
  {
    /* Re-try shutdown */
    LOG ("do-nothing didn't die, trying again\n");
    GNUNET_SCHEDULER_add_now (kill_task, NULL);
    return;
  }
  startedWaitingAt = GNUNET_TIME_absolute_get ();
  LOG ("do-nothing is dead, starting the countdown\n");
}


static void
kill_task (void *cbData, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static struct GNUNET_CLIENT_Connection *doNothingConnection = NULL;

  if (NULL != cbData)
  {
    waitedFor = GNUNET_TIME_absolute_get_duration (startedWaitingAt);
    LOG ("Waited for: %s\n",
	 GNUNET_STRINGS_relative_time_to_string (waitedFor, GNUNET_YES));
  }
  else
  {
    waitedFor.rel_value_us = 0;
  }
  /* Connect to the doNothing task */
  doNothingConnection = GNUNET_CLIENT_connect (SERVICE, cfg);
  GNUNET_assert (doNothingConnection != NULL);
  if (trialCount == 12)
    waitedFor_prev = waitedFor;
  else if (trialCount == 13)
  {
    GNUNET_CLIENT_disconnect (doNothingConnection);
    GNUNET_ARM_request_service_stop (arm, SERVICE, TIMEOUT, NULL, NULL);
    if (waitedFor_prev.rel_value_us >= waitedFor.rel_value_us)
      ok = 9;
    else
      ok = 0;
    trialCount += 1;
    return;
  }
  trialCount += 1;
  /* Use the created connection to kill the doNothingTask */
  do_nothing_service_shutdown (doNothingConnection,
      TIMEOUT, &shutdown_cont, NULL);
}


static void
trigger_disconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_ARM_disconnect_and_free (arm);
  GNUNET_ARM_monitor_disconnect_and_free (mon);
}


static void
arm_stop_cb (void *cls, enum GNUNET_ARM_RequestStatus status, const char *servicename, enum GNUNET_ARM_Result result)
{
  GNUNET_break (status == GNUNET_ARM_REQUEST_SENT_OK);
  GNUNET_break (result == GNUNET_ARM_RESULT_STOPPED);
  LOG ("ARM service stopped\n");
  GNUNET_SCHEDULER_add_now (trigger_disconnect, NULL);
}


static void
srv_status (void *cls, const char *service, enum GNUNET_ARM_ServiceStatus status)
{
  LOG ("Service %s is %u, phase %u\n", service, status, phase);
  if (status == GNUNET_ARM_SERVICE_MONITORING_STARTED)
  {
    phase++;
    GNUNET_ARM_request_service_start (arm, SERVICE,
        GNUNET_OS_INHERIT_STD_OUT_AND_ERR, TIMEOUT, NULL, NULL);
    return;
  }
  if (phase == 1)
  {
    GNUNET_break (status == GNUNET_ARM_SERVICE_STARTING);
    GNUNET_break (0 == strcasecmp (service, SERVICE));
    GNUNET_break (phase == 1);
    LOG ("do-nothing is starting\n");
    phase++;
    ok = 1;
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &kill_task, NULL);
  }
  else if ((phase == 2) && (strcasecmp (SERVICE, service) == 0))
  {
    /* We passively monitor ARM for status updates. ARM should tell us
     * when do-nothing dies (no need to run a service upness test ourselves).
     */
    if (status == GNUNET_ARM_SERVICE_STARTING)
    {
      LOG ("do-nothing is starting\n");
      GNUNET_SCHEDULER_add_now (kill_task, &ok);
    }
    else if ((status == GNUNET_ARM_SERVICE_STOPPED) && (trialCount == 14))
    {
      phase++;
      GNUNET_ARM_request_service_stop (arm, "arm", TIMEOUT, arm_stop_cb, NULL);
    }
  }
}


static void
arm_start_cb (void *cls, enum GNUNET_ARM_RequestStatus status, const char *servicename, enum GNUNET_ARM_Result result)
{
  GNUNET_break (status == GNUNET_ARM_REQUEST_SENT_OK);
  GNUNET_break (result == GNUNET_ARM_RESULT_STARTING);
  GNUNET_break (phase == 0);
  LOG ("Sent 'START' request for arm to ARM %s\n",
       (status == GNUNET_ARM_REQUEST_SENT_OK) ? "successfully" : "unsuccessfully");
}


static void
task (void *cls, char *const *args, const char *cfgfile,
      const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = c;
  arm = GNUNET_ARM_connect (cfg, NULL, NULL);
  if (NULL != arm)
  {
    mon = GNUNET_ARM_monitor (cfg, &srv_status, NULL);
    if (NULL != mon)
    {
#if START_ARM
      GNUNET_ARM_request_service_start (arm, "arm",
          GNUNET_OS_INHERIT_STD_OUT_AND_ERR, GNUNET_TIME_UNIT_ZERO, arm_start_cb, NULL);
#else
      arm_start_cb (NULL, arm, GNUNET_ARM_REQUEST_SENT_OK, "arm", GNUNET_ARM_SERVICE_STARTING);
#endif
    }
    else
    {
      GNUNET_ARM_disconnect_and_free (arm);
      arm = NULL;
    }
  }
}


static int
check ()
{
  char *const argv[] = {
    "test-exponential-backoff",
    "-c", CFGFILENAME,
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  /* Running ARM  and running the do_nothing task */
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
				     argv, "test-exponential-backoff",
				     "nohelp", options, &task, NULL));


  return ok;
}


#ifndef PATH_MAX
/**
 * Assumed maximum path length (for the log file name).
 */
#define PATH_MAX 4096
#endif


static int
init ()
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  char pwd[PATH_MAX];
  char *binary;

  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK != GNUNET_CONFIGURATION_parse (cfg,
                                               "test_arm_api_data.conf"))
    return GNUNET_SYSERR;
  if (NULL == getcwd (pwd, PATH_MAX))
    return GNUNET_SYSERR;
  GNUNET_assert (0 < GNUNET_asprintf (&binary, "%s/%s", pwd, BINARY));
  GNUNET_CONFIGURATION_set_value_string (cfg, SERVICE, "BINARY", binary);
  GNUNET_free (binary);
  if (GNUNET_OK != GNUNET_CONFIGURATION_write (cfg, CFGFILENAME))
  {
    GNUNET_CONFIGURATION_destroy (cfg);
    return GNUNET_SYSERR;
  }
  GNUNET_CONFIGURATION_destroy (cfg);

#if LOG_BACKOFF
  killLogFileName = GNUNET_DISK_mktemp ("exponential-backoff-waiting.log");
  if (NULL == (killLogFilePtr = FOPEN (killLogFileName, "w")))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "fopen",
				killLogFileName);
      GNUNET_free (killLogFileName);
      return GNUNET_SYSERR;
    }
#endif
  return GNUNET_OK;
}


static void
houseKeep ()
{
#if LOG_BACKOFF
  GNUNET_assert (0 == fclose (killLogFilePtr));
  GNUNET_free (killLogFileName);
#endif
  (void) unlink (CFGFILENAME);
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-exponential-backoff",
		    "WARNING",
		    NULL);

  if (GNUNET_OK != init ())
    return 1;
  ret = check ();
  houseKeep ();
  return ret;
}

/* end of test_exponential_backoff.c */
