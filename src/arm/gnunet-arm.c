/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_time_lib.h"

/**
 * Timeout for all operations.
 */
#define TIMEOUT  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Set if we are to shutdown all services (including ARM).
 */
static int end;

/**
 * Set if we are to start default services (including ARM).
 */
static int start;

/**
 * Set to the name of a service to start.
 */
static char *init;

/**
 * Set to the name of a service to kill.
 */
static char *term;

/**
 * Set to the name of a service to test.
 */
static char *test;

/**
 * Final status code.
 */
static int ret;


static void
confirm_cb (void *cls, int success)
{
  const char *service = cls;
  switch (success)
    {
    case GNUNET_OK:
      fprintf (stdout, _("Service `%s' is now running.\n"), service);
      break;
    case GNUNET_NO:
      fprintf (stdout, _("Service `%s' is not running.\n"), service);
      break;
    case GNUNET_SYSERR:
      fprintf (stdout,
               _("Error updating service `%s': ARM not running\n"), service);
      break;
    }
}


static void
confirm_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  const char *service = cls;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE))
    fprintf (stdout, _("Service `%s' is running.\n"), service);
  else
    fprintf (stdout, _("Service `%s' is not running.\n"), service);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param sched the scheduler to use
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     char *const *args,
     const char *cfgfile, struct GNUNET_CONFIGURATION_Handle *cfg)
{
  if (term != NULL)
    {
      GNUNET_ARM_stop_service (term, cfg, sched, TIMEOUT, &confirm_cb, term);
    }
  if (end)
    {
      GNUNET_ARM_stop_service ("arm",
                               cfg, sched, TIMEOUT, &confirm_cb, "arm");
    }
  if (start)
    {
      GNUNET_ARM_start_service ("arm",
                                cfg, sched, TIMEOUT, &confirm_cb, "arm");
    }
  if (init != NULL)
    {
      GNUNET_ARM_start_service (init, cfg, sched, TIMEOUT, &confirm_cb, init);
    }
  if (test != NULL)
    {
      GNUNET_CLIENT_service_test (sched,
                                  test, cfg, TIMEOUT, &confirm_task, test);
    }
}


/**
 * gnunet-arm command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'e', "end", NULL, gettext_noop ("stop all GNUnet services"),
   GNUNET_NO, &GNUNET_GETOPT_set_one, &end},
  {'i', "init", "SERVICE", gettext_noop ("start a particular service"),
   GNUNET_YES, &GNUNET_GETOPT_set_string, &init},
  {'k', "kill", "SERVICE", gettext_noop ("stop a particular service"),
   GNUNET_YES, &GNUNET_GETOPT_set_string, &term},
  {'s', "start", NULL, gettext_noop ("start all GNUnet default services"),
   GNUNET_NO, &GNUNET_GETOPT_set_one, &start},
  {'t', "test", "SERVICE",
   gettext_noop ("test if a particular service is running"),
   GNUNET_YES, &GNUNET_GETOPT_set_string, &test},
  GNUNET_GETOPT_OPTION_END
};


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
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-arm",
                              gettext_noop
                              ("Control services and the Automated Restart Manager (ARM)"),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-arm.c */
