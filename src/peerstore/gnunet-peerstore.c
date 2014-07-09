/*
     This file is part of GNUnet.
     (C)

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
struct GNUNET_PEERSTORE_Handle *peerstore_handle;

/**
 * Run on shutdown
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
shutdown_task (void *cls,
         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if(NULL != peerstore_handle)
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
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{

  peerstore_handle = NULL;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                  &shutdown_task,
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
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-peerstore [options [value]]",
                              gettext_noop
                              ("peerstore"),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-peerstore.c */
