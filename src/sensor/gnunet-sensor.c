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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file sensor/gnunet-sensor.c
 * @brief sensor tool
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_sensor_service.h"

static int ret;

/**
 * option '-a'
 */
static int get_all;

/**
 * option '-g'
 */
static char *get_sensor;

/**
 * option '-f'
 */
static char *force_anomaly;

/*
 * Handle to sensor service
 */
static struct GNUNET_SENSOR_Handle *sensor_handle;

/**
 * Run on shutdown
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != sensor_handle)
  {
    GNUNET_SENSOR_disconnect (sensor_handle);
    sensor_handle = NULL;
  }
}


/**
 * Callback for getting sensor info from service
 *
 * @param cls not used
 * @param sensor brief information about sensor (NULL means end of transmission)
 * @param err_msg contains error string if any
 */
void
print_sensor_info (void *cls, const struct SensorInfoShort *sensor,
                   const char *err_msg)
{
  if (NULL != err_msg)
  {
    printf ("Error: %s\n", err_msg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (NULL == sensor)           /* no more sensors from service */
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  printf ("Name: %s\nVersion: %d.%d\n", sensor->name, sensor->version_major,
          sensor->version_minor);
  if (NULL != sensor->description)
    printf ("Description: %s\n", sensor->description);
  printf ("\n");
}


/**
 * Continuation called after a force anomaly request is sent.
 *
 * @param cls Closure (unused)
 * @param emsg Error message, NULL of no error
 */
void
force_anomaly_cont (void *cls, const char *emsg)
{
  if (NULL != emsg)
    printf ("Error: %s\n", emsg);
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Main function that will be run by the scheduler.
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
  sensor_handle = NULL;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  sensor_handle = GNUNET_SENSOR_connect (cfg);
  GNUNET_assert (NULL != sensor_handle);
  if (GNUNET_YES == get_all)
  {
    GNUNET_SENSOR_iterate (sensor_handle, GNUNET_TIME_UNIT_FOREVER_REL, NULL,
                           &print_sensor_info, NULL);
  }
  else if (NULL != get_sensor)
  {
    GNUNET_SENSOR_iterate (sensor_handle, GNUNET_TIME_UNIT_FOREVER_REL,
                           get_sensor, &print_sensor_info, NULL);
  }
  else if (NULL != force_anomaly)
  {
    GNUNET_SENSOR_force_anomaly (sensor_handle, "nse", GNUNET_YES,
                                 &force_anomaly_cont, NULL);
  }
  ret = 0;
}


/**
 * The main function to sensor.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'a', "all", NULL,
     gettext_noop ("Retrieve information about all defined sensors"),
     0, &GNUNET_GETOPT_set_one, &get_all},
    {'g', "get-sensor", NULL,
     gettext_noop ("Retrieve information about a single sensor"),
     1, &GNUNET_GETOPT_set_string, &get_sensor},
    {'f', "force-anomaly", NULL,
     gettext_noop ("Force an anomaly on a sensor, use only for testing"),
     1, &GNUNET_GETOPT_set_string, &force_anomaly},
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-sensor [options [value]]",
                              gettext_noop ("sensor"), options, &run,
                              NULL)) ? ret : 1;
}

/* end of gnunet-sensor.c */
