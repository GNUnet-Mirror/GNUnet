/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file arm/test_exponential_backoff.c
 * @brief testcase for gnunet-service-arm.c
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_client_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_protocols.h"

#define VERBOSE GNUNET_NO

#define START_ARM GNUNET_YES

#define LOG_BACKOFF GNUNET_NO

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

#define SERVICE_TEST_TIMEOUT GNUNET_TIME_UNIT_FOREVER_REL

#define FIVE_MILLISECONDS GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 5)


static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_ARM_Handle *arm;

static int ok = 1;

static int trialCount;

static struct GNUNET_TIME_Absolute startedWaitingAt;

struct GNUNET_TIME_Relative waitedFor;

#if LOG_BACKOFF
static FILE *killLogFilePtr;

static char *killLogFileName;
#endif


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
  GNUNET_SCHEDULER_TaskIdentifier cancel_task;

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
 * First call with NULL: service misbehaving, or something.
 * First call with GNUNET_MESSAGE_TYPE_ARM_SHUTDOWN:
 *   - service will shutdown
 * Second call with NULL:
 *   - service has now really shut down.
 *
 * @param cls closure
 * @param msg NULL, indicating socket closure.
 */
static void
service_shutdown_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct ShutdownContext *shutdown_ctx = cls;

  if ((msg == NULL) && (shutdown_ctx->confirmed != GNUNET_YES))
    {
      /* Means the other side closed the connection and never confirmed a shutdown */
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  "Service handle shutdown before ACK!\n");
      if (shutdown_ctx->cont != NULL)
	shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_SYSERR);
      GNUNET_SCHEDULER_cancel (shutdown_ctx->cancel_task);
      GNUNET_CLIENT_disconnect (shutdown_ctx->sock, GNUNET_NO);
      GNUNET_free (shutdown_ctx);
    }
  else if ((msg == NULL) && (shutdown_ctx->confirmed == GNUNET_YES))
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Service shutdown complete.\n");
#endif
      if (shutdown_ctx->cont != NULL)
	shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_NO);

      GNUNET_SCHEDULER_cancel (shutdown_ctx->cancel_task);
      GNUNET_CLIENT_disconnect (shutdown_ctx->sock, GNUNET_NO);
      GNUNET_free (shutdown_ctx);
    }
  else
    {
      GNUNET_assert (ntohs (msg->size) ==
		     sizeof (struct GNUNET_MessageHeader));
      switch (ntohs (msg->type))
	{
	case GNUNET_MESSAGE_TYPE_ARM_SHUTDOWN:
#if VERBOSE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Received confirmation for service shutdown.\n");
#endif
	  shutdown_ctx->confirmed = GNUNET_YES;
	  GNUNET_CLIENT_receive (shutdown_ctx->sock,
				 &service_shutdown_handler, shutdown_ctx,
				 GNUNET_TIME_UNIT_FOREVER_REL);
	  break;
	default:		/* Fall through */
	  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		      "Service shutdown refused!\n");
	  if (shutdown_ctx->cont != NULL)
	    shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_YES);

	  GNUNET_SCHEDULER_cancel (shutdown_ctx->cancel_task);
	  GNUNET_CLIENT_disconnect (shutdown_ctx->sock, GNUNET_NO);
	  GNUNET_free (shutdown_ctx);
	  break;
	}
    }
}

/**
 * Shutting down took too long, cancel receive and return error.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
void
service_shutdown_cancel (void *cls,
			 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ShutdownContext *shutdown_ctx = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "service_shutdown_cancel called!\n");
  shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_SYSERR);
  GNUNET_CLIENT_disconnect (shutdown_ctx->sock, GNUNET_NO);
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
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  _("Failed to transmit shutdown request to client.\n"));
      shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_SYSERR);
      GNUNET_CLIENT_disconnect (shutdown_ctx->sock, GNUNET_NO);
      GNUNET_free (shutdown_ctx);
      return 0;			/* client disconnected */
    }

  GNUNET_CLIENT_receive (shutdown_ctx->sock, &service_shutdown_handler,
			 shutdown_ctx, GNUNET_TIME_UNIT_FOREVER_REL);
  shutdown_ctx->cancel_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
				  (shutdown_ctx->timeout),
				  &service_shutdown_cancel, shutdown_ctx);
  msg = (struct GNUNET_MessageHeader *) buf;
  msg->type = htons (GNUNET_MESSAGE_TYPE_ARM_SHUTDOWN);
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  return sizeof (struct GNUNET_MessageHeader);
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
arm_service_shutdown (struct GNUNET_CLIENT_Connection *sock,
		      struct GNUNET_TIME_Relative timeout,
		      GNUNET_CLIENT_ShutdownTask cont, void *cont_cls)
{
  struct ShutdownContext *shutdown_ctx;

  shutdown_ctx = GNUNET_malloc (sizeof (struct ShutdownContext));
  shutdown_ctx->cont = cont;
  shutdown_ctx->cont_cls = cont_cls;
  shutdown_ctx->sock = sock;
  shutdown_ctx->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  GNUNET_CLIENT_notify_transmit_ready (sock,
				       sizeof (struct GNUNET_MessageHeader),
				       timeout, GNUNET_NO, &write_shutdown,
				       shutdown_ctx);
}


static void
arm_notify_stop (void *cls, enum GNUNET_ARM_ProcessStatus status)
{
  GNUNET_assert ( (status == GNUNET_ARM_PROCESS_DOWN) ||
		  (status == GNUNET_ARM_PROCESS_ALREADY_DOWN) );
#if START_ARM
  GNUNET_ARM_stop_service (arm, "arm", TIMEOUT, NULL, NULL);
#endif
}


static void
kill_task (void *cbData, const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
do_nothing_notify (void *cls, enum GNUNET_ARM_ProcessStatus status)
{
  GNUNET_assert (status == GNUNET_ARM_PROCESS_STARTING);
  ok = 1;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &kill_task, NULL);
}

static void
arm_notify (void *cls, enum GNUNET_ARM_ProcessStatus status)
{
  GNUNET_assert (status == GNUNET_ARM_PROCESS_STARTING);
  GNUNET_ARM_start_service (arm, "do-nothing", TIMEOUT, &do_nothing_notify,
			    NULL);
}


static void
kill_task (void *cbData, const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
do_nothing_restarted_notify_task (void *cls,
				  const struct GNUNET_SCHEDULER_TaskContext
				  *tc)
{
  static char a;

  trialCount++;

#if LOG_BACKOFF
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    {
      FPRINTF (killLogFilePtr, "%d.Reason is shutdown!\n", trialCount);
    }
  else if ((tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT) != 0)
    {
      FPRINTF (killLogFilePtr, "%d.Reason is timeout!\n", trialCount);
    }
  else if ((tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE) != 0)
    {
      FPRINTF (killLogFilePtr, "%d.Service is running!\n", trialCount);
    }
#endif
  GNUNET_SCHEDULER_add_now (&kill_task, &a);
}


static void
do_test (void *cbData, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_CLIENT_service_test ("do-nothing", cfg, TIMEOUT,
			      &do_nothing_restarted_notify_task, NULL);
}


static void
shutdown_cont (void *cls, int reason)
{
  trialCount++;
  startedWaitingAt = GNUNET_TIME_absolute_get ();
  GNUNET_SCHEDULER_add_delayed (waitedFor, &do_test, NULL);
}


static void
kill_task (void *cbData, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static struct GNUNET_CLIENT_Connection *doNothingConnection = NULL;

  if (NULL != cbData)
    {
      waitedFor = GNUNET_TIME_absolute_get_duration (startedWaitingAt);

#if LOG_BACKOFF
      FPRINTF (killLogFilePtr, "Waited for: %llu ms\n",
	       (unsigned long long) waitedFor.rel_value);
#endif
    }
  else
    {
      waitedFor.rel_value = 0;
    }
  /* Connect to the doNothing task */
  doNothingConnection = GNUNET_CLIENT_connect ("do-nothing", cfg);
  GNUNET_assert (doNothingConnection != NULL);
  if (trialCount == 12)
    {
      GNUNET_CLIENT_disconnect (doNothingConnection, GNUNET_NO);
      GNUNET_ARM_stop_service (arm, "do-nothing", TIMEOUT, &arm_notify_stop,
			       NULL);
      ok = 0;
      return;
    }
  /* Use the created connection to kill the doNothingTask */
  arm_service_shutdown (doNothingConnection, TIMEOUT, &shutdown_cont, NULL);
}


static void
task (void *cls, char *const *args, const char *cfgfile,
      const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = c;

  arm = GNUNET_ARM_connect (cfg, NULL);
#if START_ARM
  GNUNET_ARM_start_service (arm, "arm", GNUNET_TIME_UNIT_ZERO, &arm_notify,
			    NULL);
#else
  arm_do_nothing (NULL, GNUNET_YES);
#endif
}


static int
check ()
{
  char *const argv[] = {
    "test-exponential-backoff",
    "-c", "test_arm_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
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

static int
init ()
{
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
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-exponential-backoff",
#if VERBOSE
		    "DEBUG",
#else
		    "WARNING",
#endif
		    NULL);

  init ();
  ret = check ();
  houseKeep ();
  return ret;
}

/* end of test_exponential_backoff.c */
