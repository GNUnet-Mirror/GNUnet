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
 * @file util/test_common_logging_dummy.c
 * @brief dummy labrat for the testcase for the logging module (runtime
 * log level adjustment)
 * @author LRN
 */
#include "platform.h"
#undef GNUNET_EXTRA_LOGGING
#define GNUNET_EXTRA_LOGGING GNUNET_YES

#include "gnunet_common.h"
#include "gnunet_time_lib.h"
#include "gnunet_network_lib.h"

/**
 * Delay introduced between operations, useful for debugging.
 */
#define OUTPUT_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 0)

static void
my_log (void *ctx, enum GNUNET_ErrorType kind, const char *component,
        const char *date, const char *msg)
{
  if (strncmp ("test-common-logging-dummy", component, 25) != 0)
    return;
  FPRINTF (stdout, "%s", msg);
  fflush (stdout);
}

static int
expensive_func ()
{
  return GNUNET_NETWORK_socket_select (NULL, NULL, NULL, OUTPUT_DELAY);
}

#define pr(kind,lvl) {\
  struct GNUNET_TIME_Absolute t1, t2;\
  t1 = GNUNET_TIME_absolute_get ();\
  GNUNET_log (kind, "L%s %d\n", lvl, expensive_func());\
  t2 = GNUNET_TIME_absolute_get ();\
  printf ("1%s %llu\n", lvl,\
          (unsigned long long) GNUNET_TIME_absolute_get_difference (t1, t2).rel_value); \
}

#define pr2(kind,lvl) {\
  struct GNUNET_TIME_Absolute t1, t2;\
  t1 = GNUNET_TIME_absolute_get ();\
  GNUNET_log (kind, "L%s %d\n", lvl, expensive_func());\
  t2 = GNUNET_TIME_absolute_get ();\
  printf ("2%s %llu\n", lvl,\
          (unsigned long long) GNUNET_TIME_absolute_get_difference (t1, t2).rel_value); \
}

int
main (int argc, char *argv[])
{
  /* We set up logging with NULL level - will be overrided by
   * GNUNET_LOG or GNUNET_FORCE_LOG at runtime.
   */
  GNUNET_log_setup ("test-common-logging-dummy", NULL, "/dev/null");
  GNUNET_logger_add (&my_log, NULL);
  pr (GNUNET_ERROR_TYPE_ERROR, "ERROR");
  pr (GNUNET_ERROR_TYPE_WARNING, "WARNING");
  pr (GNUNET_ERROR_TYPE_INFO, "INFO");
  pr (GNUNET_ERROR_TYPE_DEBUG, "DEBUG");

  /* We set up logging with WARNING level - will onle be overrided by
   * GNUNET_FORCE_LOG at runtime.
   */
  GNUNET_log_setup ("test-common-logging-dummy", "WARNING", "/dev/null");
  pr2 (GNUNET_ERROR_TYPE_ERROR, "ERROR");
  pr2 (GNUNET_ERROR_TYPE_WARNING, "WARNING");
  pr2 (GNUNET_ERROR_TYPE_INFO, "INFO");
  pr2 (GNUNET_ERROR_TYPE_DEBUG, "DEBUG");
  return 0;
}                               /* end of main */

/* end of test_common_logging_dummy.c */
