/*
      This file is part of GNUnet
      Copyright (C) 2008, 2009, 2012 Christian Grothoff (and other contributing authors)

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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
 */

/**
 * @file testing/test_testing_new_portreservation.c
 * @brief test case for testing port reservation routines from the new testing
 *          library API
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"

#define LOG(kind,...) \
  GNUNET_log (kind, __VA_ARGS__)

/**
 * The status of the test
 */
int status;

/**
 * Main point of test execution
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_TESTING_System *system;
  uint16_t new_port1;
  uint16_t new_port2;
  uint16_t old_port1;

  system = GNUNET_TESTING_system_create ("/tmp/gnunet-testing-new",
                                         "localhost", NULL, NULL);
  GNUNET_assert (NULL != system);
  new_port1 = GNUNET_TESTING_reserve_port (system);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
                "Reserved TCP port %u\n", new_port1);
  if (0 == new_port1)
    goto end;
  new_port2 = GNUNET_TESTING_reserve_port (system);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
                "Reserved TCP port %u\n", new_port2);
  if (0 == new_port2)
    goto end;
  GNUNET_assert (new_port1 != new_port2);
  GNUNET_TESTING_release_port (system, new_port1);
  old_port1 = new_port1;
  new_port1 = 0;
  new_port1 = GNUNET_TESTING_reserve_port (system);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Reserved TCP port %u\n", new_port1);
  GNUNET_assert (0 != new_port1);
  GNUNET_assert (old_port1 == new_port1);
  GNUNET_TESTING_release_port (system, new_port1);
  GNUNET_TESTING_release_port (system, new_port2);
  status = GNUNET_OK;

 end:
  GNUNET_TESTING_system_destroy (system, GNUNET_YES);
}


int main (int argc, char *argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  status = GNUNET_SYSERR;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc,
                          argv,
                          "test_testing_new_portreservation",
                          "test case for testing port reservation routines"
                          " from the new testing library API",
                          options,
                          &run,
                          NULL))
    return 1;
  return (GNUNET_OK == status) ? 0 : 1;
}

/* end of test_testing_portreservation.c */
