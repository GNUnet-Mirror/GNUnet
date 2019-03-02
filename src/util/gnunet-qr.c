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
#include <getopt.h>
#include "gnunet-qr-utils.h"

static const char *usage_note =
  "gnunet-qr\n"
  "Scan a QR code using a video device and import\n"
  "\n"
  "Arguments mandatory for long options are also mandatory for short options.\n"
  "  -c, --config FILENAME      use configuration file FILENAME\n"
  "  -d, --device DEVICE        use device DEVICE\n"
  "  -s, --silent               do not show preview windows\n"
  "  -h, --help                 print this help\n"
  "  -v, --verbose              be verbose\n"
  "Report bugs to gnunet-developers@gnu.org.\n"
  "\n"
  "GNUnet home page: https://gnunet.org/\n"
  "General help using GNU software: https://www.gnu.org/gethelp/\n";

#define LOG(fmt, ...) if (verbose == true) printf(fmt, ## __VA_ARGS__)

int main (int argc, char **argv)
{
  const char* configuration = NULL;
  const char* device = "/dev/video0";
  static bool verbose = false;
  static bool silent = false;

  static struct option long_options[] = {
      {"verbose", no_argument,       0, 'v'},
      {"silent",  no_argument,       0, 's'},
      {"help",    no_argument,       0, 'h'},
      {"config",  required_argument, 0, 'c'},
      {"device",  required_argument, 0, 'd'},
      {0, 0, 0, 0}
    };
  while (1) {
    int opt;
    opt = getopt_long (argc, argv, "c:hd:sv",
		     long_options, NULL);
    if (opt == -1)
      break;

    switch (opt) {
    case 'h':
      printf(usage_note);
      return 0;
    case 'c':
      configuration = optarg;
      break;
    case 'd':
      device = optarg;
      break;
    case 's':
      silent = true;
      break;
    case 'v':
      verbose = true;
      break;
    default:
      printf(usage_note);
      return 1;
    }
  }

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
  int rc = 1;

  const zbar_symbol_set_t* symbols = zbar_processor_get_results(proc);
  const zbar_symbol_t* symbol = zbar_symbol_set_first_symbol(symbols);

  if (symbol != NULL) {
    const char* data = zbar_symbol_get_data(symbol);
    LOG("Found %s \"%s\"\n",
	zbar_get_symbol_name(zbar_symbol_get_type(symbol)), data);

    if (configuration == NULL) {
      char* command_args[] = {"gnunet-uri", data, NULL };
      LOG("Running `gnunet-uri %s`\n", data);
      rc = fork_and_exec("gnunet-uri", command_args);
    } else {
      char* command_args[] = {"gnunet-uri", "-c", configuration, data, NULL };
      LOG("Running `gnunet-uri -c '%s' %s`\n", configuration, data);
      rc = fork_and_exec("gnunet-uri", command_args);
    };

    if (rc != 0) {
      printf("Failed to add URI %s\n", data);
    } else {
      printf("Added URI %s\n", data);
    }
  }

  /* clean up */
  zbar_processor_destroy(proc);

  return(rc);
}
