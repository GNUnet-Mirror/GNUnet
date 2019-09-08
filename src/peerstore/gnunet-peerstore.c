/*
     This file is part of GNUnet.
     Copyright (C)

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
 * @file peerstore/gnunet-peerstore.c
 * @brief peerstore tool
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_peerstore_service.h"

static int ret;

/*
 * Handle to PEERSTORE service
 */
static struct GNUNET_PEERSTORE_Handle *peerstore_handle;


/**
 * Run on shutdown
 *
 * @param cls unused
 */
static void
shutdown_task(void *cls)
{
  if (NULL != peerstore_handle)
    {
      GNUNET_PEERSTORE_disconnect(peerstore_handle, GNUNET_YES);
      peerstore_handle = NULL;
    }
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
run(void *cls,
    char *const *args,
    const char *cfgfile,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_SCHEDULER_add_shutdown(&shutdown_task,
                                NULL);
  peerstore_handle = GNUNET_PEERSTORE_connect(cfg);
  GNUNET_assert(NULL != peerstore_handle);
  ret = 0;
}


/**
 * The main function to peerstore.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main(int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run(argc, argv, "gnunet-peerstore [options [value]]",
                             gettext_noop("peerstore"), options, &run,
                             NULL)) ? ret : 1;
}

/* end of gnunet-peerstore.c */
