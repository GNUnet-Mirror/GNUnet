/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file mesh/test_mesh_api.c
 * @brief test mesh api: dummy test of callbacks
 * @author Bartlomiej Polot
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_mesh_service.h"

#define VERBOSE 1
#define VERBOSE_ARM 0

static struct GNUNET_OS_Process *arm_pid;
static struct GNUNET_MESH_Handle *mesh;
static struct GNUNET_MESH_Tunnel *t;
static int result;
static GNUNET_SCHEDULER_TaskIdentifier abort_task;
static GNUNET_SCHEDULER_TaskIdentifier test_task;

/**
 * Function is called whenever a message is received.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx place to store local state associated with the tunnel
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
callback (void *cls, struct GNUNET_MESH_Tunnel *tunnel, void **tunnel_ctx,
          const struct GNUNET_PeerIdentity *sender,
          const struct GNUNET_MessageHeader *message,
          const struct GNUNET_ATS_Information *atsi)
{
  return GNUNET_OK;
}

static struct GNUNET_MESH_MessageHandler handlers[] = { {&callback, 1, 0},
{NULL, 0, 0}
};


static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != t)
  {
    GNUNET_MESH_tunnel_destroy (t);
  }
  if (0 != abort_task)
  {
    GNUNET_SCHEDULER_cancel (abort_task);
  }
  if (NULL != mesh)
  {
    GNUNET_MESH_disconnect (mesh);
  }
  if (0 != GNUNET_OS_process_kill (arm_pid, SIGTERM))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  }
  GNUNET_assert (GNUNET_OK == GNUNET_OS_process_wait (arm_pid));
  GNUNET_OS_process_close (arm_pid);
}

static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 != test_task)
  {
    GNUNET_SCHEDULER_cancel (test_task);
  }
  result = GNUNET_SYSERR;
  abort_task = 0;
  do_shutdown (cls, tc);
}

static void
test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  static const GNUNET_MESH_ApplicationType app[] =
      { 1, 2, 3, 4, 5, 6, 7, 8, 0 };

  test_task = (GNUNET_SCHEDULER_TaskIdentifier) 0;
  mesh = GNUNET_MESH_connect (cfg, 10, NULL, NULL, NULL, handlers, app);
  if (NULL == mesh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "test: Couldn't connect to mesh :(\n");
    return;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: YAY! CONNECTED TO MESH :D\n");
  }

  t = GNUNET_MESH_tunnel_create (mesh, NULL, NULL, NULL, NULL);

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                (GNUNET_TIME_UNIT_SECONDS, 5), &do_shutdown,
                                NULL);
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_log_setup ("test_mesh_api",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  arm_pid =
      GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm",
#if VERBOSE_ARM
                               "-L", "DEBUG",
#endif
                               "-c", "test_mesh.conf", NULL);

  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 20), &do_abort,
                                    NULL);

  test_task = GNUNET_SCHEDULER_add_now (&test, (void *) cfg);

}


int
main (int argc, char *argv[])
{
  int ret;

  char *const argv2[] = { "test-mesh-api",
    "-c", "test_mesh.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  ret =
      GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                          "test-mesh-api", "nohelp", options, &run, NULL);

  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "run failed with error code %d\n",
                ret);
    return 1;
  }
  if (GNUNET_SYSERR == result)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "test failed\n");
    return 1;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test ok\n");
  return 0;
}
