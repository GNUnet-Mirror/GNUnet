/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file arm/gnunet-arm.c
 * @brief arm for writing a tool
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_constants.h"
#include "gnunet_util_lib.h"

/**
 * Timeout for stopping services.  Long to give some services a real chance.
 */
#define STOP_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 1)

/**
 * Timeout for stopping ARM.  Extra-long since ARM needs to stop everyone else.
 */
#define STOP_TIMEOUT_ARM GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 2)

/**
 * Timeout for starting services, very short because of the strange way start works
 * (by checking if running before starting, so really this time is always waited on
 * startup (annoying)).
 */
#define START_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * Timeout for listing all running services.
 */
#define LIST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2)

/**
 * Set if we are to shutdown all services (including ARM).
 */
static int end;

/**
 * Set if we are to start default services (including ARM).
 */
static int start;

/**
 * Set if we are to stop/start default services (including ARM).
 */
static int restart;

/**
 * Set if we should delete configuration and temp directory on exit.
 */
static int delete;

/**
 * Set if we should not print status messages.
 */
static int quiet;

/**
 * Monitor ARM activity.
 */
static int monitor;

/**
 * Set if we should print a list of currently running services.
 */
static int list;

/**
 * Set to the name of a service to start.
 */
static char *init;

/**
 * Set to the name of a service to kill.
 */
static char *term;

/**
 * Set to the name of the config file used.
 */
static const char *config_file;

/**
 * Set to the directory where runtime files are stored.
 */
static char *dir;

/**
 * Final status code.
 */
static int ret;

/**
 * Connection with ARM.
 */
static struct GNUNET_ARM_Handle *h;

/**
 * Monitor connection with ARM.
 */
static struct GNUNET_ARM_MonitorHandle *m;

/**
 * Our configuration.
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Processing stage that we are in.  Simple counter.
 */
static unsigned int phase;

/**
 * User defined timestamp for completing operations.
 */
static struct GNUNET_TIME_Relative timeout;

/**
 * Do we want to give our stdout to gnunet-service-arm?
 */
static unsigned int no_stdout;

/**
 * Do we want to give our stderr to gnunet-service-arm?
 */
static unsigned int no_stderr;


/**
 * Attempts to delete configuration file and GNUNET_HOME
 * on ARM shutdown provided the end and delete options
 * were specified when gnunet-arm was run.
 */
static void
delete_files ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Will attempt to remove configuration file %s and service directory %s\n",
	      config_file, dir);

  if (0 != UNLINK (config_file))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to remove configuration file %s\n"),
                config_file);
  }
  if (GNUNET_OK != GNUNET_DISK_directory_remove (dir))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to remove servicehome directory %s\n"),
                dir);

  }
}


/**
 * Main continuation-passing-style loop.  Runs the various
 * jobs that we've been asked to do in order.
 *
 * @param cls closure, unused
 * @param tc context, unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != h)
  {
    GNUNET_ARM_disconnect_and_free (h);
    h = NULL;
  }
  if (NULL != m)
  {
    GNUNET_ARM_monitor_disconnect_and_free (m);
    m = NULL;
  }
  if ((GNUNET_YES == end) && (GNUNET_YES == delete))
    delete_files ();
  GNUNET_CONFIGURATION_destroy (cfg);
  cfg = NULL;
}


/**
 * Returns a string interpretation of 'rs'
 *
 * @param rs the request status from ARM
 * @return a string interpretation of the request status
 */
static const char *
req_string (enum GNUNET_ARM_RequestStatus rs)
{
  switch (rs)
  {
  case GNUNET_ARM_REQUEST_SENT_OK:
    return _("Message was sent successfully");
  case GNUNET_ARM_REQUEST_CONFIGURATION_ERROR:
    return _("Misconfiguration (can not connect to the ARM service)");
  case GNUNET_ARM_REQUEST_DISCONNECTED:
    return _("We disconnected from ARM before we could send a request");
  case GNUNET_ARM_REQUEST_BUSY:
    return _("ARM API is busy");
  case GNUNET_ARM_REQUEST_TOO_LONG:
    return _("Request does not fit into a message");
  case GNUNET_ARM_REQUEST_TIMEOUT:
    return _("Request timed out");
  }
  return _("Unknown request status");
}


/**
 * Returns a string interpretation of the 'result'
 *
 * @param result the arm result
 * @return a string interpretation
 */
static const char *
ret_string (enum GNUNET_ARM_Result result)
{
  switch (result)
  {
  case GNUNET_ARM_RESULT_STOPPED:
    return _("%s is stopped");
  case GNUNET_ARM_RESULT_STARTING:
    return _("%s is starting");
  case GNUNET_ARM_RESULT_STOPPING:
    return _("%s is stopping");
  case GNUNET_ARM_RESULT_IS_STARTING_ALREADY:
    return _("%s is starting already");
  case GNUNET_ARM_RESULT_IS_STOPPING_ALREADY:
    return _("%s is stopping already");
  case GNUNET_ARM_RESULT_IS_STARTED_ALREADY:
    return _("%s is started already");
  case GNUNET_ARM_RESULT_IS_STOPPED_ALREADY:
    return _("%s is stopped already");
  case GNUNET_ARM_RESULT_IS_NOT_KNOWN:
    return _("%s service is not known to ARM");
  case GNUNET_ARM_RESULT_START_FAILED:
    return _("%s service failed to start");
  case GNUNET_ARM_RESULT_IN_SHUTDOWN:
    return _("%s service cannot be started because ARM is shutting down");
  }
  return _("%.s Unknown result code.");
}


/**
 * Main task that runs our various operations in order.
 *
 * @param cls closure
 * @param tc scheudler context
 */
static void
action_loop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function called whenever we connect to or disconnect from ARM.
 * Termiantes the process if we fail to connect to the service on
 * our first attempt.
 *
 * @param cls closure
 * @param connected GNUNET_YES if connected, GNUNET_NO if disconnected,
 *                  GNUNET_SYSERR on error.
 */
static void
conn_status (void *cls,
	     int connected)
{
  static int once;

  if ( (GNUNET_SYSERR == connected) &&
       (0 == once) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Fatal error initializing ARM API.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  once = 1;
}


/**
 * We have requested ARM to be started, this function
 * is called with the result of the operation.  Informs the
 * use of the result; on success, we continue with the event
 * loop, on failure we terminate the process.
 *
 * @param cls closure unused
 * @param rs what happened to our request
 * @param service name of the service we tried to start ("arm")
 * @param result if the request was processed, this is the result
 *               according to ARM
 */
static void
start_callback (void *cls,
		enum GNUNET_ARM_RequestStatus rs, const char *service,
		enum GNUNET_ARM_Result result)
{
  char *msg;

  if (GNUNET_ARM_REQUEST_SENT_OK != rs)
  {
    GNUNET_asprintf (&msg, "%s", _("Failed to start the ARM service: %s\n"));
    FPRINTF (stdout, msg, req_string (rs));
    GNUNET_free (msg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if ( (GNUNET_ARM_RESULT_STARTING != result) &&
       (GNUNET_ARM_RESULT_IS_STARTED_ALREADY != result) )
  {
    GNUNET_asprintf (&msg, "%s", _("Failed to start the ARM service: %s\n"));
    FPRINTF (stdout, msg, ret_string (result));
    GNUNET_free (msg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ARM service [re]start successful\n");
  start = 0;
  GNUNET_SCHEDULER_add_now (action_loop, NULL);
}


/**
 * We have requested ARM to be stopped, this function
 * is called with the result of the operation.  Informs the
 * use of the result; on success, we continue with the event
 * loop, on failure we terminate the process.
 *
 * @param cls closure unused
 * @param rs what happened to our request
 * @param service name of the service we tried to start ("arm")
 * @param result if the request was processed, this is the result
 *               according to ARM
 */
static void
stop_callback (void *cls,
	       enum GNUNET_ARM_RequestStatus rs, const char *service,
	       enum GNUNET_ARM_Result result)
{
  char *msg;

  if (GNUNET_ARM_REQUEST_SENT_OK != rs)
  {
    GNUNET_asprintf (&msg, "%s",
		     _("Failed to send a stop request to the ARM service: %s\n"));
    FPRINTF (stdout, msg, req_string (rs));
    GNUNET_free (msg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if ((GNUNET_ARM_RESULT_STOPPING != result) &&
      (GNUNET_ARM_RESULT_STOPPED != result) &&
      (GNUNET_ARM_RESULT_IS_STOPPED_ALREADY != result))
  {
    GNUNET_asprintf (&msg, "%s", _("Failed to stop the ARM service: %s\n"));
    FPRINTF (stdout, msg, ret_string (result));
    GNUNET_free (msg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "ARM service shutdown successful\n");
  end = 0;
  if (restart)
  {
    restart = 0;
    start = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Initiating an ARM restart\n");
  }
  GNUNET_SCHEDULER_add_now (&action_loop, NULL);
}


/**
 * We have requested a service to be started, this function
 * is called with the result of the operation.  Informs the
 * use of the result; on success, we continue with the event
 * loop, on failure we terminate the process.
 *
 * @param cls closure unused
 * @param rs what happened to our request
 * @param service name of the service we tried to start
 * @param result if the request was processed, this is the result
 *               according to ARM
 */
static void
init_callback (void *cls,
	       enum GNUNET_ARM_RequestStatus rs, const char *service,
	       enum GNUNET_ARM_Result result)
{
  char *msg;

  if (GNUNET_ARM_REQUEST_SENT_OK != rs)
  {
    GNUNET_asprintf (&msg,
                     _("Failed to send a request to start the `%s' service: %%s\n"),
                     init);
    FPRINTF (stdout, msg, req_string (rs));
    GNUNET_free (msg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if ((GNUNET_ARM_RESULT_STARTING != result) &&
      (GNUNET_ARM_RESULT_IS_STARTED_ALREADY != result))
  {
    GNUNET_asprintf (&msg, _("Failed to start the `%s' service: %s\n"),
                     init, ret_string (result));
    FPRINTF (stdout, msg, service);
    GNUNET_free (msg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Service %s [re]started successfully\n",
	      init);
  GNUNET_free (init);
  init = NULL;
  GNUNET_SCHEDULER_add_now (&action_loop, NULL);
}


/**
 * We have requested a service to be stopped, this function
 * is called with the result of the operation.  Informs the
 * use of the result; on success, we continue with the event
 * loop, on failure we terminate the process.
 *
 * @param cls closure unused
 * @param rs what happened to our request
 * @param service name of the service we tried to start
 * @param result if the request was processed, this is the result
 *               according to ARM
 */
static void
term_callback (void *cls,
	       enum GNUNET_ARM_RequestStatus rs, const char *service,
	       enum GNUNET_ARM_Result result)
{
  char *msg;
  if (GNUNET_ARM_REQUEST_SENT_OK != rs)
  {
    GNUNET_asprintf (&msg,
                     _("Failed to send a request to kill the `%s' service: %%s\n"),
                     term);
    FPRINTF (stdout, msg, req_string (rs));
    GNUNET_free (msg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if ((GNUNET_ARM_RESULT_STOPPED != result) &&
      (GNUNET_ARM_RESULT_IS_STOPPED_ALREADY != result))
  {
    GNUNET_asprintf (&msg,
		     _("Failed to kill the `%s' service: %s\n"),
                     term, ret_string (result));
    FPRINTF (stdout, msg, service);
    GNUNET_free (msg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Service %s stopped successfully\n",
              term);
  GNUNET_free (term);
  term = NULL;
  GNUNET_SCHEDULER_add_now (&action_loop, NULL);
}


/**
 * Function called with the list of running services. Prints
 * the list to stdout, then starts the event loop again.
 * Prints an error message and terminates the process on errors.
 *
 * @param cls closure (unused)
 * @param rs request status (success, failure, etc.)
 * @param count number of services in the list
 * @param list list of services that are running
 */
static void
list_callback (void *cls,
	       enum GNUNET_ARM_RequestStatus rs, unsigned int count,
	       const char *const*list)
{
  unsigned int i;

  if (GNUNET_ARM_REQUEST_SENT_OK != rs)
  {
    char *msg;

    GNUNET_asprintf (&msg, "%s", _("Failed to request a list of services: %s\n"));
    FPRINTF (stdout, msg, req_string (rs));
    GNUNET_free (msg);
    ret = 3;
    GNUNET_SCHEDULER_shutdown ();
  }
  if (NULL == list)
  {
    FPRINTF (stderr, "%s", _("Error communicating with ARM. ARM not running?\n"));
    GNUNET_SCHEDULER_shutdown ();
    ret = 3;
    return;
  }
  FPRINTF (stdout, "%s", _("Running services:\n"));
  for (i = 0; i < count; i++)
    FPRINTF (stdout, "%s\n", list[i]);
  GNUNET_SCHEDULER_add_now (&action_loop, NULL);
}


/**
 * Main action loop.  Runs the various jobs that we've been asked to
 * do, in order.
 *
 * @param cls closure, unused
 * @param tc context, unused
 */
static void
action_loop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Running requested actions\n");
  while (1)
  {
    switch (phase++)
    {
    case 0:
      if (NULL != term)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Termination action\n");
        GNUNET_ARM_request_service_stop (h, term,
					 (0 == timeout.rel_value_us) ? STOP_TIMEOUT : timeout,
					 &term_callback, NULL);
	return;
      }
      break;
    case 1:
      if (end || restart)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "End action\n");
        GNUNET_ARM_request_service_stop (h, "arm",
					 (0 == timeout.rel_value_us) ? STOP_TIMEOUT_ARM : timeout,
					 &stop_callback, NULL);
        return;
      }
      break;
    case 2:
      if (start)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Start action\n");
        GNUNET_ARM_request_service_start (h, "arm",
            (no_stdout ? 0 : GNUNET_OS_INHERIT_STD_OUT) |
            (no_stderr ? 0 : GNUNET_OS_INHERIT_STD_ERR),
            (0 == timeout.rel_value_us) ? START_TIMEOUT: timeout,
            start_callback, NULL);
        return;
      }
      break;
    case 3:
      if (NULL != init)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Initialization action\n");
        GNUNET_ARM_request_service_start (h, init, GNUNET_OS_INHERIT_STD_NONE,
					  (0 == timeout.rel_value_us) ? STOP_TIMEOUT : timeout,
					  &init_callback, NULL);
        return;
      }
      break;
    case 4:
      if (list)
      {
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Going to list all running services controlled by ARM.\n");
        GNUNET_ARM_request_service_list (h,
					 (0 == timeout.rel_value_us) ? LIST_TIMEOUT : timeout,
					 &list_callback, &list);
	return;
      }
      break;
    case 5:
      if (monitor)
	{
	  if (! quiet)
	    fprintf (stderr,
		     _("Now only monitoring, press CTRL-C to stop.\n"));
	  quiet = 0; /* does not make sense to stay quiet in monitor mode at this time */
	  return; /* done with tasks, just monitor */
	}
      break;
    default:		/* last phase */
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }
}


/**
 * Function called when a service starts or stops.
 *
 * @param cls closure
 * @param service service name
 * @param status status of the service
 */
static void
srv_status (void *cls,
	    const char *service, enum GNUNET_ARM_ServiceStatus status)
{
  const char *msg;

  switch (status)
  {
  case GNUNET_ARM_SERVICE_MONITORING_STARTED:
    return; /* this should be done silently */
  case GNUNET_ARM_SERVICE_STOPPED:
    msg = _("Stopped %s.\n");
    break;
  case GNUNET_ARM_SERVICE_STARTING:
    msg = _("Starting %s...\n");
    break;
  case GNUNET_ARM_SERVICE_STOPPING:
    msg = _("Stopping %s...\n");
    break;
  default:
    msg = NULL;
    break;
  }
  if (! quiet)
    {
      if (NULL != msg)
	FPRINTF (stderr, msg, service);
      else
	FPRINTF (stderr, _("Unknown status %u for service %s.\n"), status, service);
    }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got service %s status %d\n", service, (int) status);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  char *armconfig;

  cfg = GNUNET_CONFIGURATION_dup (c);
  config_file = cfgfile;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "PATHS", "GNUNET_HOME", &dir))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       "PATHS", "GNUNET_HOME");
    return;
  }
  if (NULL != cfgfile)
  {
    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_filename (cfg, "arm", "CONFIG",
						 &armconfig))
    {
      GNUNET_CONFIGURATION_set_value_string (cfg, "arm", "CONFIG",
                                             cfgfile);
    }
    else
      GNUNET_free (armconfig);
  }
  if (NULL == (h = GNUNET_ARM_connect (cfg, &conn_status, NULL)))
    return;
  if (monitor)
    m = GNUNET_ARM_monitor (cfg, &srv_status, NULL);
  GNUNET_SCHEDULER_add_now (&action_loop, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&shutdown_task, NULL);
}


/**
 * The main function to obtain arm from gnunetd.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'e', "end", NULL, gettext_noop ("stop all GNUnet services"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &end},
    {'i', "init", "SERVICE", gettext_noop ("start a particular service"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &init},
    {'k', "kill", "SERVICE", gettext_noop ("stop a particular service"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &term},
    {'s', "start", NULL, gettext_noop ("start all GNUnet default services"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &start},
    {'r', "restart", NULL,
     gettext_noop ("stop and start all GNUnet default services"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &restart},
    {'d', "delete", NULL,
     gettext_noop ("delete config file and directory on exit"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &delete},
    {'m', "monitor", NULL,
     gettext_noop ("monitor ARM activities"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &monitor},
    {'q', "quiet", NULL, gettext_noop ("don't print status messages"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &quiet},
    {'T', "timeout", "MSECS",
     gettext_noop ("timeout in MSECS milliseconds for completing current operation"),
     GNUNET_YES, &GNUNET_GETOPT_set_relative_time, &timeout},
    {'I', "info", NULL, gettext_noop ("list currently running services"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &list},
    {'O', "no-stdout", NULL, gettext_noop ("don't let gnunet-service-arm inherit standard output"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &no_stdout},
    {'E', "no-stderr", NULL, gettext_noop ("don't let gnunet-service-arm inherit standard error"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &no_stderr},
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  if (GNUNET_OK ==
      GNUNET_PROGRAM_run (argc, argv, "gnunet-arm",
			  gettext_noop
			  ("Control services and the Automated Restart Manager (ARM)"),
			  options, &run, NULL))
    {
      GNUNET_free ((void *) argv);
      return ret;
    }
  GNUNET_free ((void*) argv);
  return 1;
}

/* end of gnunet-arm.c */
