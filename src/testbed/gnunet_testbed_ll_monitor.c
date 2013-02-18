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
 * @file testbed/ll_monitor.c
 * @brief The load level monitor process. This is called whenever a job event
 *          happens. This file is called with the following syntax:
 *          "monitor_program job_id user_arg state exit_status"
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_common.h"
#include <llapi.h>


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
  char *job_id;
  char *user_arg;
  char *state;
  char *exit_status;
  char *outfile;
  FILE *out;

  if (5 != argc)
  {
    fprintf (stderr, "Invalid number of arguments\n");
    return 1;
  }
  job_id = argv[1];
  user_arg = argv[2];
  state = argv[3];
  exit_status = argv[4];
  PRINTF ("Job id: %s\n", job_id);
  PRINTF ("\t User arg: %s \n", user_arg);
  PRINTF ("\t Job state: %s \n", state);
  PRINTF ("\t Exit status: %s \n", exit_status);

  if (-1 == asprintf (&outfile, "job-%s.status", job_id))
    return 1;
  out = fopen (outfile, "a");
  if (NULL == out)
    return 1;
  fprintf (out, "Job id: %s\n", job_id);
  fprintf (out, "\t User arg: %s \n", user_arg);
  fprintf (out, "\t Job state: %s \n", state);
  fprintf (out, "\t Exit status: %s \n", exit_status);
  fclose (out);
  return 0;
}
