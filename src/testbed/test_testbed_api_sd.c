/*
      This file is part of GNUnet
      (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_sd.c
 * @brief test cases for calculating standard deviation
 * @author Sree Harsha Totakura <sreeharsha@totakura.in> 
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "testbed_api_sd.h"

/**
 * Global return value
 */
static int ret;

/**
 * Main run function.
 *
 * @param cls NULL
 * @param args arguments passed to GNUNET_PROGRAM_run
 * @param cfgfile the path to configuration file
 * @param cfg the configuration file handle
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  struct SDHandle *h = GNUNET_TESTBED_SD_init_ (20);

  ret = 0;
  GNUNET_TESTBED_SD_add_data_ (h, 40);
  if (GNUNET_SYSERR != GNUNET_TESTBED_SD_deviation_factor_ (h, 10))
  {
    GNUNET_break (0);
    ret = 1;
    goto err;
  }
  GNUNET_TESTBED_SD_add_data_ (h, 30); 
  if (GNUNET_SYSERR == GNUNET_TESTBED_SD_deviation_factor_ (h, 80))
  {
    GNUNET_break (0);
    ret = 1;
    goto err;
  }
  GNUNET_TESTBED_SD_add_data_ (h, 40);
  if (0 != GNUNET_TESTBED_SD_deviation_factor_ (h, 10))
  {
    GNUNET_break (0);
    ret = 1;
    goto err;
  }
  GNUNET_TESTBED_SD_add_data_ (h, 10);
  GNUNET_TESTBED_SD_add_data_ (h, 30);
  if (3 != GNUNET_TESTBED_SD_deviation_factor_ (h, 60))
  {
    GNUNET_break (0);
    ret = 1;
    goto err;
  }

 err:
  GNUNET_TESTBED_SD_destroy_ (h);
}


/**
 * Main function
 */
int
main (int argc, char **argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int result;

  result = GNUNET_SYSERR;
  result =
      GNUNET_PROGRAM_run (argc, argv,
                          "test_testbed_api_sd", "nohelp", options, &run, NULL);
  if ((GNUNET_OK != result))
    return 1;
  return ret;
}

/* end of test_testbed_api_sd.c */
