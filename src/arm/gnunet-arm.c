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
 * @file arm/gnunet-arm.c
 * @brief arm for writing a tool
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_client_lib.h"
#include "gnunet_constants.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_time_lib.h"

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
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Processing stage that we are in.  Simple counter.
 */
static unsigned int phase;

/**
 * User defined timestamp for completing operations.
 */
static struct GNUNET_TIME_Relative timeout;


/**
 * Main continuation-passing-style loop.  Runs the various
 * jobs that we've been asked to do in order.
 *
 * @param cls closure, unused
 * @param tc context, unused
 */
static void
cps_loop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Callback invoked with the status of the last operation.  Reports to the
 * user and then runs the next phase in the FSM.
 *
 * @param cls pointer to "const char*" identifying service that was manipulated
 * @param result result of the operation
 */
static void
confirm_cb (void *cls, 
	    enum GNUNET_ARM_ProcessStatus result)
{
  const char *service = cls;

  switch (result)
  {
  case GNUNET_ARM_PROCESS_UNKNOWN:
    FPRINTF (stderr, _("Service `%s' is unknown to ARM.\n"), service);
    ret = 1;
    break;
  case GNUNET_ARM_PROCESS_DOWN:
    if (quiet != GNUNET_YES)
      FPRINTF (stdout, _("Service `%s' has been stopped.\n"), service);
    break;
  case GNUNET_ARM_PROCESS_ALREADY_RUNNING:
    FPRINTF (stderr, _("Service `%s' was already running.\n"), service);
    ret = 1;
    break;
  case GNUNET_ARM_PROCESS_STARTING:
    if (quiet != GNUNET_YES)
      FPRINTF (stdout, _("Service `%s' has been started.\n"), service);
    break;
  case GNUNET_ARM_PROCESS_ALREADY_STOPPING:
    FPRINTF (stderr, _("Service `%s' was already being stopped.\n"), service);
    ret = 1;
    break;
  case GNUNET_ARM_PROCESS_ALREADY_DOWN:
    FPRINTF (stderr, _("Service `%s' was already not running.\n"), service);
    ret = 1;
    break;
  case GNUNET_ARM_PROCESS_SHUTDOWN:
    FPRINTF (stderr, "%s", _("Request ignored as ARM is shutting down.\n"));
    ret = 1;
    break;
  case GNUNET_ARM_PROCESS_COMMUNICATION_ERROR:
    FPRINTF (stderr, "%s", _("Error communicating with ARM service.\n"));
    ret = 1;
    break;
  case GNUNET_ARM_PROCESS_COMMUNICATION_TIMEOUT:
    FPRINTF (stderr, "%s",  _("Timeout communicating with ARM service.\n"));
    ret = 1;
    break;
  case GNUNET_ARM_PROCESS_FAILURE:
    FPRINTF (stderr, "%s",  _("Operation failed.\n"));
    ret = 1;
    break;
  default:
    FPRINTF (stderr, "%s",  _("Unknown response code from ARM.\n"));
    break;
  }
  GNUNET_SCHEDULER_add_continuation (&cps_loop, NULL,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}

/**
 * Callback invoked with the list of running services.  
 * Reports to the user and then runs the next phase in the FSM.
 *
 * @param cls currently not used
 * @param result result of the operation
 * @param count number of running services
 * @param list copy of the list of running services
 */
static void
list_cb (void *cls, int result, unsigned int count, const char *const*list)
{
  unsigned int i;

  if ( (result != GNUNET_YES) || (NULL == list) )
  {
    FPRINTF (stderr, "%s", _("Error communicating with ARM. ARM not running?\n"));
    return;
  }
  FPRINTF (stdout, "%s", _("Running services:\n"));
  for (i=0; i<count; i++)
    FPRINTF (stdout, "%s\n", list[i]);
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
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = c;
  config_file = cfgfile;
  if (GNUNET_CONFIGURATION_get_value_string
      (cfg, "PATHS", "SERVICEHOME", &dir) != GNUNET_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _
		  ("Fatal configuration error: `%s' option in section `%s' missing.\n"),
		  "SERVICEHOME", "PATHS");
      return;
    }
  h = GNUNET_ARM_connect (cfg, NULL);
  if (h == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Fatal error initializing ARM API.\n"));
      ret = 1;
      return;
    }
  GNUNET_SCHEDULER_add_continuation (&cps_loop, NULL,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}

/**
 * Attempts to delete configuration file and SERVICEHOME
 * on arm shutdown provided the end and delete options
 * were specified when gnunet-arm was run.
 */
static void
delete_files ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Will attempt to remove configuration file %s and service directory %s\n",
	      config_file, dir);

  if (UNLINK (config_file) != 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Failed to remove configuration file %s\n"), config_file);
    }

  if (GNUNET_DISK_directory_remove (dir) != GNUNET_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Failed to remove servicehome directory %s\n"), dir);

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
cps_loop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  while (1)
    {
      switch (phase++)
	{
	case 0:
	  if (term != NULL)
	    {
	      GNUNET_ARM_stop_service (h, term,
				       (0 ==
					timeout.rel_value) ? STOP_TIMEOUT :
				       timeout, &confirm_cb, term);
	      return;
	    }
	  break;
	case 1:
	  if ((end) || (restart))
	    {
	      GNUNET_ARM_stop_service (h, "arm",
				       (0 ==
					timeout.rel_value) ? STOP_TIMEOUT_ARM
				       : timeout, &confirm_cb, "arm");
	      return;
	    }
	  break;
	case 2:
	  if (start)
	    {
	      GNUNET_ARM_start_service (h, "arm",
					(0 ==
					 timeout.rel_value) ? START_TIMEOUT :
					timeout, &confirm_cb, "arm");
	      return;
	    }
	  break;
	case 3:
	  if (init != NULL)
	    {
	      GNUNET_ARM_start_service (h, init,
					(0 ==
					 timeout.rel_value) ? START_TIMEOUT :
					timeout, &confirm_cb, init);
	      return;
	    }
	  break;
	case 4:
	  if (restart)
	    {
	      GNUNET_ARM_disconnect (h);
	      phase = 0;
	      end = 0;
	      start = 1;
	      restart = 0;
	      h = GNUNET_ARM_connect (cfg, NULL);
	      if (NULL == h)
		{
		  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			      _("Fatal error initializing ARM API.\n"));
		  ret = 1;
		  return;
		}
	      GNUNET_SCHEDULER_add_now (&cps_loop, NULL);
	      return;
	    }
	  break;
        case 5:
          if (list) {
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Going to list all running services controlled by ARM.\n");
  
              if (NULL == h) 
              {
               GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                              _("Fatal error initializing ARM API.\n"));
               return;
              }
              
              GNUNET_ARM_list_running_services (h, 
                                                (0 == 
                                                 timeout.rel_value) ? LIST_TIMEOUT : 
                                                 timeout, &list_cb, NULL);
            return;
          }
	  /* Fall through */
	default:		/* last phase */
	  GNUNET_ARM_disconnect (h);
	  if ((end == GNUNET_YES) && (delete == GNUNET_YES))
	    delete_files ();
	  return;
	}
    }
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
  static unsigned long long temp_timeout_ms;

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
    {'q', "quiet", NULL, gettext_noop ("don't print status messages"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &quiet},
    {'T', "timeout", NULL,
     gettext_noop ("timeout for completing current operation"),
     GNUNET_YES, &GNUNET_GETOPT_set_ulong, &temp_timeout_ms},
    {'I', "info", NULL, gettext_noop ("List currently running services"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &list},
    GNUNET_GETOPT_OPTION_END
  };

  if (temp_timeout_ms > 0)
    timeout.rel_value = temp_timeout_ms;

  if (GNUNET_OK ==
      GNUNET_PROGRAM_run (argc, argv, "gnunet-arm",
			  gettext_noop
			  ("Control services and the Automated Restart Manager (ARM)"),
			  options, &run, NULL))
    {
      return ret;
    }

  return 1;
}

/* end of gnunet-arm.c */
