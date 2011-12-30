/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @file util/test_common_logging.c
 * @brief testcase for the logging module
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_common.h"

static void
my_log (void *ctx, enum GNUNET_ErrorType kind, const char *component,
        const char *date, const char *msg)
{
  unsigned int *c = ctx;

  (*c)++;
}



int
main (int argc, char *argv[])
{
  unsigned int failureCount = 0;
  unsigned int logs = 0;

  if (0 != putenv ("GNUNET_FORCE_LOG="))
    FPRINTF (stderr, "Failed to putenv: %s\n", strerror (errno));
  GNUNET_log_setup ("test-common-logging", "DEBUG", "/dev/null");
  GNUNET_logger_add (&my_log, &logs);
  GNUNET_logger_add (&my_log, &logs);
  GNUNET_log (GNUNET_ERROR_TYPE_BULK, "Testing...\n");
  GNUNET_log (GNUNET_ERROR_TYPE_BULK, "Testing...\n");
  GNUNET_log (GNUNET_ERROR_TYPE_BULK, "Testing...\n");
  GNUNET_log (GNUNET_ERROR_TYPE_BULK, "Testing...\n");
  GNUNET_log (GNUNET_ERROR_TYPE_BULK, "Testing...\n");
  GNUNET_log (GNUNET_ERROR_TYPE_BULK, "Testing...\n");
  GNUNET_logger_remove (&my_log, &logs);
  GNUNET_log (GNUNET_ERROR_TYPE_BULK, "Flusher...\n");
  /* the last 6 calls should be merged (repated bulk messages!) */
  GNUNET_logger_remove (&my_log, &logs);
  if (logs != 4)
  {
    FPRINTF (stdout, "Expected 4 log calls, got %u\n", logs);
    failureCount++;
  }
  GNUNET_break (0 ==
                strcmp (_("ERROR"),
                        GNUNET_error_type_to_string (GNUNET_ERROR_TYPE_ERROR)));
  GNUNET_break (0 ==
                strcmp (_("WARNING"),
                        GNUNET_error_type_to_string
                        (GNUNET_ERROR_TYPE_WARNING)));
  GNUNET_break (0 ==
                strcmp (_("INFO"),
                        GNUNET_error_type_to_string (GNUNET_ERROR_TYPE_INFO)));
  GNUNET_break (0 ==
                strcmp (_("DEBUG"),
                        GNUNET_error_type_to_string (GNUNET_ERROR_TYPE_DEBUG)));
  GNUNET_log_setup ("test_common_logging", "WARNING", "/dev/null");
  logs = 0;
  GNUNET_logger_add (&my_log, &logs);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Checker...\n");
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Drop me...\n");
  GNUNET_logger_remove (&my_log, &logs);
  if (logs != 1)
  {
    FPRINTF (stdout, "Expected 1 log call, got %u\n", logs);
    failureCount++;
  }

  if (failureCount != 0)
  {
    FPRINTF (stdout, "%u TESTS FAILED!\n", failureCount);
    return -1;
  }
  return 0;
}                               /* end of main */

/* end of test_common_logging.c */
