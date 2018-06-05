/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.
 */


/**
 * @file testbed/testbed_api_sd.c
 * @brief test cases for calculating standard deviation
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
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
  int sd;

  ret = 0;
  GNUNET_TESTBED_SD_add_data_ (h, 40);
  if (GNUNET_SYSERR != GNUNET_TESTBED_SD_deviation_factor_ (h, 10, &sd))
  {
    GNUNET_break (0);
    ret = 1;
    goto err;
  }
  GNUNET_TESTBED_SD_add_data_ (h, 30);
  if (GNUNET_SYSERR == GNUNET_TESTBED_SD_deviation_factor_ (h, 80, &sd))
  {
    GNUNET_break (0);
    ret = 1;
    goto err;
  }
  GNUNET_TESTBED_SD_add_data_ (h, 40);
  if ((GNUNET_SYSERR == GNUNET_TESTBED_SD_deviation_factor_ (h, 30, &sd))
      || (-2 != sd))
  {
    GNUNET_break (0);
    ret = 1;
    goto err;
  }
  GNUNET_TESTBED_SD_add_data_ (h, 10);
  GNUNET_TESTBED_SD_add_data_ (h, 30);
  if ((GNUNET_SYSERR == GNUNET_TESTBED_SD_deviation_factor_ (h, 60, &sd))
      || (3 != sd))
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
