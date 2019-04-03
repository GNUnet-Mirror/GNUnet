/*
     This file is part of GNUnet.
     Copyright (C) 2013-2019 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/
/**
 * @file util/gnunet-qr.c
 * @author Hartmut Goebel (original implementation)
 * @author Martin Schanzenbach (integrate gnunet-uri)
 * @author Christian Grothoff (error handling)
 */
#include <stdio.h>
#include <zbar.h>
#include <stdbool.h>
#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(fmt, ...) if (verbose == true) printf(fmt, ## __VA_ARGS__)

/**
 * Video device to capture from. Sane default for GNU/Linux systems.
 */
static char* device = "/dev/video0";

/**
 * --verbose option
 */
static int verbose = false;

/**
 * --silent option
 */
static int silent = false;

/**
 * Handler exit code
 */
static long unsigned int exit_code = 1;

/**
 * Helper process we started.
 */
static struct GNUNET_OS_Process *p;


/**
 * Pipe used to communicate child death via signal.
 */
static struct GNUNET_DISK_PipeHandle *sigpipe;


/**
 * Task triggered whenever we receive a SIGCHLD (child
 * process died) or when user presses CTRL-C.
 *
 * @param cls closure, NULL
 */
static void
maint_child_death (void *cls)
{
  enum GNUNET_OS_ProcessStatusType type;

  if ( (GNUNET_OK !=
	GNUNET_OS_process_status (p, &type, &exit_code)) ||
       (type != GNUNET_OS_PROCESS_EXITED) )
    GNUNET_break (0 == GNUNET_OS_process_kill (p, GNUNET_TERM_SIG));
  GNUNET_OS_process_destroy (p);
}


/**
 * Dispatch URIs to the appropriate GNUnet helper process
 *
 * @param cls closure
 * @param uri uri to dispatch
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
gnunet_uri (void *cls,
            const char *uri,
            const char *cfgfile,
            const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  const char *orig_uri;
  const char *slash;
  char *subsystem;
  char *program;
  struct GNUNET_SCHEDULER_Task * rt;

  orig_uri = uri;
  if (0 != strncasecmp ("gnunet://", uri, strlen ("gnunet://"))) {
    fprintf (stderr,
	     _("Invalid URI: does not start with `%s'\n"),
	     "gnunet://");
    return;
  }
  uri += strlen ("gnunet://");
  if (NULL == (slash = strchr (uri, '/')))
  {
    fprintf (stderr,
             _("Invalid URI: fails to specify subsystem\n"));
    return;
  }
  subsystem = GNUNET_strndup (uri, slash - uri);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
					     "uri",
					     subsystem,
					     &program))
  {
    fprintf (stderr,
             _("No handler known for subsystem `%s'\n"),
             subsystem);
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
			       orig_uri,
			       NULL);
  GNUNET_free (program);
  if (NULL == p)
    GNUNET_SCHEDULER_cancel (rt);
}


/**
 * Obtain QR code 'symbol' from @a proc.
 *
 * @param proc zbar processor to use
 * @return NULL on error
 */
static const zbar_symbol_t *
get_symbol (zbar_processor_t *proc)
{
  const zbar_symbol_set_t* symbols;
  int rc;
  int n;

  if (0 !=
      zbar_processor_parse_config (proc, "enable"))
  {
    GNUNET_break (0);
    return NULL;
  }

  /* initialize the Processor */
  if (0 !=
      (rc = zbar_processor_init(proc, device, 1)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to open device `%s': %d\n",
                device,
                rc);
    return NULL;
  }

  /* enable the preview window */
  if ( (0 != (rc = zbar_processor_set_visible (proc, 1))) ||
       (0 != (rc = zbar_processor_set_active(proc, 1))) )
  {
    GNUNET_break (0);
    return NULL;
  }

  /* read at least one barcode (or until window closed) */
  LOG ("Capturing\n");
  n = zbar_process_one (proc, -1);

  /* hide the preview window */
  (void) zbar_processor_set_active (proc, 0);
  (void) zbar_processor_set_visible (proc, 0);
  if (-1 == n)
    return NULL; /* likely user closed the window */
  LOG ("Got %i images\n",
       n);
  /* extract results */
  symbols = zbar_processor_get_results (proc);
  if (NULL == symbols)
  {
    GNUNET_break (0);
    return NULL;
  }
  return zbar_symbol_set_first_symbol (symbols);
}


/**
 * Run zbar QR code parser.
 *
 * @return NULL on error, otherwise the URI that we found
 */
static char *
run_zbar ()
{
  zbar_processor_t *proc;
  const char *data;
  char *ret;
  const zbar_symbol_t* symbol;

  /* configure the Processor */
  proc = zbar_processor_create (1);
  if (NULL == proc)
  {
    GNUNET_break (0);
    return NULL;
  }

  symbol = get_symbol (proc);
  if (NULL == symbol)
  {
    zbar_processor_destroy (proc);
    return NULL;
  }
  data = zbar_symbol_get_data (symbol);
  if (NULL == data)
  {
    GNUNET_break (0);
    zbar_processor_destroy (proc);
    return NULL;
  }
  LOG ("Found %s \"%s\"\n",
       zbar_get_symbol_name (zbar_symbol_get_type(symbol)),
       data);
  ret = GNUNET_strdup (data);
  /* clean up */
  zbar_processor_destroy(proc);
  return ret;
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
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *data;

  data = run_zbar ();
  if (NULL == data)
    return;
  gnunet_uri (cls,
              data,
              cfgfile,
              cfg);
  if (exit_code != 0)
  {
    printf ("Failed to add URI %s\n",
            data);
  }
  else
  {
    printf ("Added URI %s\n",
            data);
  }
  GNUNET_free (data);
};


int
main (int argc, char *const *argv)
{
  int ret;
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_string ('d', "device", "DEVICE",
     gettext_noop ("use video-device DEVICE (default: /dev/video0"),
     &device),
    GNUNET_GETOPT_option_flag ('\0', "verbose",
     gettext_noop ("be verbose"),
     &verbose),
    GNUNET_GETOPT_option_flag ('s', "silent",
     gettext_noop ("do not show preview windows"),
			       &silent),
    GNUNET_GETOPT_OPTION_END
  };

  ret = GNUNET_PROGRAM_run (argc,
			    argv,
			    "gnunet-qr",
			    gettext_noop ("Scan a QR code using a video device and import the uri read"),
			    options, &run, NULL);
  return ((GNUNET_OK == ret) && (0 == exit_code)) ? 0 : 1;
}
