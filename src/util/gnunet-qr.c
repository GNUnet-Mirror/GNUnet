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

#include <stdio.h>
#include <zbar.h>
#include <stdbool.h>
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-qr-utils.h"

#define LOG(fmt, ...) if (verbose == true) printf(fmt, ## __VA_ARGS__)

// Command line options
// program exit code
static long unsigned int exit_code = 1;

static char* device = "/dev/video0";
static int verbose = false;
static int silent = false;

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
  /* create a Processor */
  LOG("Initializing\n");
  zbar_processor_t *proc = zbar_processor_create(1);

  // FIXME: Wrap all this into a function which returns an error on
  // failure. And here ensure the processor is destroyed at the end.

  /* configure the Processor */
  zbar_processor_parse_config(proc, "enable");

  /* initialize the Processor */
  LOG("Opening video device %s\n", device);
  // FIXME: error handling
  zbar_processor_init(proc, device, 1);

  /* enable the preview window */
  zbar_processor_set_visible(proc, 1);
  zbar_processor_set_active(proc, 1);

  /* keep scanning until user provides key/mouse input */
  //zbar_processor_user_wait(proc, -1);

  // read at least one barcode (or until window closed)
  LOG("Capturing\n");
  int n;
  n = zbar_process_one(proc, -1);
  LOG("Got %i images\n", n);
  // FIXME: Error handling (n = -1)

  // hide the preview window
  zbar_processor_set_active(proc, 0);
  zbar_processor_set_visible(proc, 0);

  // extract results
  const zbar_symbol_set_t* symbols = zbar_processor_get_results(proc);
  const zbar_symbol_t* symbol = zbar_symbol_set_first_symbol(symbols);

  if (symbol != NULL) {
    const char* data = zbar_symbol_get_data(symbol);
    LOG("Found %s \"%s\"\n",
	zbar_get_symbol_name(zbar_symbol_get_type(symbol)), data);

    if (configuration == NULL) {
      char* command_args[] = {"gnunet-uri", data, NULL };
      LOG("Running `gnunet-uri %s`\n", data);
      exit_code = fork_and_exec(BINDIR "gnunet-uri", command_args);
    } else {
      char* command_args[] = {"gnunet-uri", "-c", configuration, data, NULL };
      LOG("Running `gnunet-uri -c '%s' %s`\n", configuration, data);
      exit_code = fork_and_exec(BINDIR "gnunet-uri", command_args);
    };

    if (exit_code != 0) {
      printf("Failed to add URI %s\n", data);
    } else {
      printf("Added URI %s\n", data);
    }
  }

  /* clean up */
  zbar_processor_destroy(proc);
};


int
main (int argc, char *const *argv)
{
  static int ret;
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
