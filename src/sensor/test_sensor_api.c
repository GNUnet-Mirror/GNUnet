/*
     This file is part of GNUnet.
     Copyright (C)

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
 * @file sensor/test_sensor_api.c
 * @brief testcase for sensor_api.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_sensor_service.h"

//FIXME:
static int ok = 1;


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  ok = 0;
}


static int
check ()
{
  char *const argv[] = { "test-sensor-api", NULL };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  struct GNUNET_OS_Process *proc;
  char *path = GNUNET_OS_get_libexec_binary_path ("gnunet-service-sensor");

  if (NULL == path)
  {
    fprintf (stderr, "Service executable not found `%s'\n",
             "gnunet-service-sensor");
    return -1;
  }

  proc =
      GNUNET_OS_start_process (GNUNET_NO, GNUNET_OS_INHERIT_STD_ALL, NULL, NULL,
                               NULL, path, "gnunet-service-sensor", NULL);

  GNUNET_free (path);
  GNUNET_assert (NULL != proc);
  GNUNET_PROGRAM_run (1, argv, "test-sensor-api", "nohelp", options, &run, &ok);
  if (0 != GNUNET_OS_process_kill (proc, SIGTERM))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    ok = 1;
  }
  GNUNET_OS_process_wait (proc);
  GNUNET_OS_process_destroy (proc);
  return ok;
}


int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test_statistics_api", "WARNING", NULL);
  return check ();
}

/* end of test_sensor_api.c */
