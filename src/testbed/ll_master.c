/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/ll_master.c
 * @brief The load level master. Creates child processes through LoadLeveler
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include <llapi.h>

/**
 * LL job information
 */
static struct LL_job job_info;

/**
 * Exit status
 */
static int status;

/**
 * Main function that will be run.
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
  int ret;

  if (NULL == args[0])
  {
    fprintf (stderr, _("Job command file not given. Exiting\n"));
    return;
  }
  ret = llsubmit (args[0], NULL,        //char *monitor_program,
                  NULL,         //char *monitor_arg,
                  &job_info, LL_JOB_VERSION);
  if (0 != ret)
    return;
  status = GNUNET_OK;
}


/**
 * Main function
 *
 * @param argc the number of command line arguments
 * @param argv command line arg array
 * @return return code
 */
int
main (int argc, char **argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  status = GNUNET_SYSERR;
  ret =
      GNUNET_PROGRAM_run (argc, argv, "ll-master",
                          "LoadLeveler master process for starting child processes",
                          options, &run, NULL);
  if (GNUNET_OK != ret)
    return 1;
  return (GNUNET_OK == status) ? 0 : 1;
}
