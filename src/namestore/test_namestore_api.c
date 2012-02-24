/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file namestore/test_namestore_api.c
 * @brief testcase for namestore_api.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_namestore_service.h"

#define VERBOSE GNUNET_EXTRA_LOGGING

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

static struct GNUNET_NAMESTORE_Handle * nsh;

static GNUNET_SCHEDULER_TaskIdentifier endbadly_task;
static struct GNUNET_OS_Process *arm;

static int res;


static void
start_arm (const char *cfgname)
{
  arm = GNUNET_OS_start_process (NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm", "-c", cfgname,
#if VERBOSE_PEERS
                               "-L", "DEBUG",
#else
                               "-L", "ERROR",
#endif
                               NULL);
}

static void
stop_arm ()
{
  if (NULL != arm)
  {
    if (0 != GNUNET_OS_process_kill (arm, SIGTERM))
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    GNUNET_OS_process_wait (arm);
    GNUNET_OS_process_close (arm);
    arm = NULL;
  }
}

/**
 * Re-establish the connection to the service.
 *
 * @param cls handle to use to re-connect.
 * @param tc scheduler context
 */
static void
endbadly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (nsh != NULL)
    GNUNET_NAMESTORE_disconnect (nsh, GNUNET_YES);
  nsh = NULL;

  if (NULL != arm)
    stop_arm();

  res = 1;
}

/*
static void
end (void)
{
  if (endbadly_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (nsh != NULL)
    GNUNET_NAMESTORE_disconnect (nsh, GNUNET_YES);
  nsh = NULL;


  if (NULL != arm)
    stop_arm();

  res = 0;
}
*/


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  endbadly_task = GNUNET_SCHEDULER_add_delayed(TIMEOUT,endbadly, NULL);

  start_arm (cfgfile);
  GNUNET_assert (arm != NULL);

  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);

  //GNUNET_NAMESTORE_lookup_name (nsh, NULL, NULL, 0, NULL, NULL);

  //stop_arm ();
  //end ();
  res = 0;
}

static int
check ()
{
  static char *const argv[] = { "test-namestore-api",
    "-c",
    "test_namestore_api.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  res = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv, "test-namestore-api",
                      "nohelp", options, &run, &res);
  return res;
}

int
main (int argc, char *argv[])
{
  int ret;

  ret = check ();

  return ret;
}

/* end of test_namestore_api.c */
