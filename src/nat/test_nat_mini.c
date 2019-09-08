/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2011 GNUnet e.V.

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
 * Testcase for port redirection and public IP address retrieval.
 * This test never fails, because there need to be a NAT box set up for tha *
 * @file nat/test_nat_mini.c
 * @brief Testcase for NAT library - mini
 * @author Christian Grothoff
 *
 * TODO: actually use ARM to start resolver service to make DNS work!
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_nat_lib.h"

/* Time to wait before stopping NAT, in seconds */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Function called on each address that the NAT service
 * believes to be valid for the transport.
 */
static void
addr_callback(void *cls, int add_remove,
              const struct sockaddr *addr,
              socklen_t addrlen,
              enum GNUNET_NAT_StatusCode ret)
{
  if (GNUNET_NAT_ERROR_SUCCESS == ret)
    {
      fprintf(stderr,
              "Address changed: %s `%s' (%u bytes)\n",
              add_remove == GNUNET_YES
              ? "added" : "removed",
              GNUNET_a2s(addr,
                         addrlen),
              (unsigned int)addrlen);
    }
  else
    ;
  //TODO: proper error handling!
}


/**
 * Function that terminates the test.
 */
static void
stop(void *cls)
{
  struct GNUNET_NAT_MiniHandle *mini = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Stopping NAT and quitting...\n");
  GNUNET_NAT_mini_map_stop(mini);
}

#define PORT 10000

/**
 * Main function run with scheduler.
 */
static void
run(void *cls, char *const *args, const char *cfgfile,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_NAT_MiniHandle *mini;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
             "Requesting NAT redirection for port %u...\n",
             PORT);
  mini = GNUNET_NAT_mini_map_start(PORT, GNUNET_YES /* tcp */,
                                   &addr_callback, NULL);
  if (NULL == mini)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Could not start UPnP interaction\n");
      return;
    }
  GNUNET_SCHEDULER_add_delayed(TIMEOUT, &stop, mini);
}


int
main(int argc, char *const argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  char *const argv_prog[] = {
    "test-nat-mini",
    "-c",
    "test_nat_data.conf",
    "-L",
    "WARNING",
    NULL
  };

  GNUNET_log_setup("test-nat-mini",
                   "WARNING",
                   NULL);

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
             "UPnP test for NAT library, timeout set to %s\n",
             GNUNET_STRINGS_relative_time_to_string(TIMEOUT,
                                                    GNUNET_YES));
  GNUNET_PROGRAM_run(5, argv_prog, "test-nat-mini", "nohelp", options, &run,
                     NULL);
  return 0;
}

/* end of test_nat_mini.c */
