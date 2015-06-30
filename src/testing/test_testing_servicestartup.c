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
 * @file testing/test_testing_new_servicestartup.c
 * @brief test case for testing service startup using new testing API
 * @author Sree Harsha Totakura
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"


#define LOG(kind,...)                           \
  GNUNET_log (kind, __VA_ARGS__)


/**
 * Global test status
 */
static int test_success;


/**
 * The testing callback function
 *
 * @param cls NULL
 * @param cfg the configuration with which the current testing service is run
 */
static void
test_run (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
	  struct GNUNET_TESTING_Peer *peer)
{
  GNUNET_assert (NULL == cls);
  GNUNET_assert (NULL != cfg);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Service arm started successfully\n");
  test_success = GNUNET_YES;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * The main point of execution
 */
int main (int argc, char *argv[])
{
  test_success = GNUNET_NO;
  GNUNET_assert (0 == GNUNET_TESTING_service_run ("test-testing-servicestartup",
                                                  "arm",
                                                  "test_testing_defaults.conf",
                                                  &test_run,
                                                  NULL));
  return (GNUNET_YES == test_success) ? 0 : 1;
}

/* end of test_testing_servicestartup.c */

