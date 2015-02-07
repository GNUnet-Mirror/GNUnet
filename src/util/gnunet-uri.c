/*
     This file is part of GNUnet.
     Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file util/gnunet-uri.c
 * @brief tool to dispatch URIs to the appropriate GNUnet helper process
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"

/**
 * Handler exit code
 */
static long unsigned int exit_code = 1;

/**
 * Helper process we started.
 */
static struct GNUNET_OS_Process *p;

/**
 * Pipe used to communicate shutdown via signal.
 */
static struct GNUNET_DISK_PipeHandle *sigpipe;


/**
 * Task triggered whenever we receive a SIGCHLD (child
 * process died) or when user presses CTRL-C.
 *
 * @param cls closure, NULL
 * @param tc scheduler context
 */
static void
maint_child_death (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  enum GNUNET_OS_ProcessStatusType type;
  if ( (GNUNET_OK !=
	GNUNET_OS_process_status (p, &type, &exit_code)) ||
       (type != GNUNET_OS_PROCESS_EXITED) )
    GNUNET_break (0 == GNUNET_OS_process_kill (p, GNUNET_TERM_SIG));
  GNUNET_OS_process_destroy (p);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  const char *uri;
  const char *slash;
  char *subsystem;
  char *program;
  struct GNUNET_SCHEDULER_Task * rt;

  if (NULL == (uri = args[0]))
  {
    fprintf (stderr, _("No URI specified on command line\n"));
    return;
  }
  if (0 != strncasecmp ("gnunet://", uri, strlen ("gnunet://")))
  {
    fprintf (stderr, _("Invalid URI: does not start with `%s'\n"),
	     "gnunet://");
    return;
  }
  uri += strlen ("gnunet://");
  if (NULL == (slash = strchr (uri, '/')))
  {
    fprintf (stderr, _("Invalid URI: fails to specify subsystem\n"));
    return;
  }
  subsystem = GNUNET_strndup (uri, slash - uri);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
					     "uri",
					     subsystem,
					     &program))
  {
    fprintf (stderr, _("No handler known for subsystem `%s'\n"), subsystem);
    GNUNET_free (subsystem);
    return;
  }
  GNUNET_free (subsystem);
  rt = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
				       GNUNET_DISK_pipe_handle (sigpipe,
								GNUNET_DISK_PIPE_END_READ),
				       &maint_child_death, NULL);
  p = GNUNET_OS_start_process (GNUNET_NO, 0,
			       NULL, NULL, NULL,
			       program,
			       program,
			       args[0],
			       NULL);
  GNUNET_free (program);
  if (NULL == p)
    GNUNET_SCHEDULER_cancel (rt);
}


/**
 * Signal handler called for SIGCHLD.  Triggers the
 * respective handler by writing to the trigger pipe.
 */
static void
sighandler_child_death ()
{
  static char c;
  int old_errno = errno;	/* back-up errno */

  GNUNET_break (1 ==
		GNUNET_DISK_file_write (GNUNET_DISK_pipe_handle
					(sigpipe, GNUNET_DISK_PIPE_END_WRITE),
					&c, sizeof (c)));
  errno = old_errno;		/* restore errno */
}


/**
 * The main function to handle gnunet://-URIs.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  struct GNUNET_SIGNAL_Context *shc_chld;
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  sigpipe = GNUNET_DISK_pipe (GNUNET_NO, GNUNET_NO, GNUNET_NO, GNUNET_NO);
  GNUNET_assert (sigpipe != NULL);
  shc_chld =
    GNUNET_SIGNAL_handler_install (GNUNET_SIGCHLD, &sighandler_child_death);
  ret = GNUNET_PROGRAM_run (argc, argv, "gnunet-uri URI",
			    gettext_noop ("Perform default-actions for GNUnet URIs"),
			    options, &run, NULL);
  GNUNET_SIGNAL_handler_uninstall (shc_chld);
  shc_chld = NULL;
  GNUNET_DISK_pipe_close (sigpipe);
  sigpipe = NULL;
  GNUNET_free ((void *) argv);
  return ((GNUNET_OK == ret) && (0 == exit_code)) ? 0 : 1;
}

/* end of gnunet-uri.c */
