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
 * @file transport/test_core_api_start_only.c
 * @brief testcase for core_api.c that only starts two peers,
 *        connects to the core service and shuts down again
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_arm_service.h"
#include "gnunet_core_service.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"

#define VERBOSE GNUNET_NO

#define TIMEOUT 5

#define START_ARM GNUNET_YES

#define MTYPE 12345

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CORE_Handle *ch;
  struct GNUNET_PeerIdentity id;
#if START_ARM
  struct GNUNET_OS_Process *arm_proc;
#endif
};

static struct PeerContext p1;

static struct PeerContext p2;

static GNUNET_SCHEDULER_TaskIdentifier timeout_task_id;

static int ok;

#if VERBOSE
#define OKPP do { ok++; FPRINTF (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif



static void
connect_notify (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_ATS_Information *atsi,
                unsigned int atsi_count)
{
}


static void
disconnect_notify (void *cls, const struct GNUNET_PeerIdentity *peer)
{
}


static int
inbound_notify (void *cls, const struct GNUNET_PeerIdentity *other,
                const struct GNUNET_MessageHeader *message,
                const struct GNUNET_ATS_Information *atsi,
                unsigned int atsi_count)
{
  return GNUNET_OK;
}


static int
outbound_notify (void *cls, const struct GNUNET_PeerIdentity *other,
                 const struct GNUNET_MessageHeader *message,
                 const struct GNUNET_ATS_Information *atsi,
                 unsigned int atsi_count)
{
  return GNUNET_OK;
}


static struct GNUNET_CORE_MessageHandler handlers[] = {
  {NULL, 0, 0}
};


static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_CORE_disconnect (p1.ch);
  p1.ch = NULL;
  GNUNET_CORE_disconnect (p2.ch);
  p2.ch = NULL;
  ok = 0;
}




static void
init_notify (void *cls, struct GNUNET_CORE_Handle *server,
             const struct GNUNET_PeerIdentity *my_identity)
{
  struct PeerContext *p = cls;

  GNUNET_assert (server != NULL);
  GNUNET_assert (p->ch == server);
  if (cls == &p1)
  {
    /* connect p2 */
    p2.ch =
        GNUNET_CORE_connect (p2.cfg, 1, &p2, &init_notify, &connect_notify,
                             &disconnect_notify, &inbound_notify, GNUNET_YES,
                             &outbound_notify, GNUNET_YES, handlers);
  }
  else
  {
    GNUNET_assert (cls == &p2);
    GNUNET_SCHEDULER_cancel (timeout_task_id);
    GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
  }
}


static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_proc =
    GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm",
#if VERBOSE
                               "-L", "DEBUG",
#endif
                               "-c", cfgname, NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
}


static void
timeout_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  FPRINTF (stderr, "%s",  "Timeout.\n");
  if (p1.ch != NULL)
  {
    GNUNET_CORE_disconnect (p1.ch);
    p1.ch = NULL;
  }
  if (p2.ch != NULL)
  {
    GNUNET_CORE_disconnect (p2.ch);
    p2.ch = NULL;
  }
  ok = 42;
}



static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (ok == 1);
  OKPP;
  setup_peer (&p1, "test_core_api_peer1.conf");
  setup_peer (&p2, "test_core_api_peer2.conf");
  timeout_task_id =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MINUTES, TIMEOUT),
                                    &timeout_task, NULL);
  p1.ch =
      GNUNET_CORE_connect (p1.cfg, 1, &p1, &init_notify, &connect_notify,
                           &disconnect_notify, &inbound_notify, GNUNET_YES,
                           &outbound_notify, GNUNET_YES, handlers);
}


static void
stop_arm (struct PeerContext *p)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping peer\n");
#if START_ARM
  if (0 != GNUNET_OS_process_kill (p->arm_proc, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  if (GNUNET_OS_process_wait (p->arm_proc) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ARM process %u stopped\n",
              GNUNET_OS_process_get_pid (p->arm_proc));
  GNUNET_OS_process_destroy (p->arm_proc);
  p->arm_proc = NULL;
#endif
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


static int
check ()
{
  char *const argv[] = { "test-core-api-start-only",
    "-c",
    "test_core_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-2");

  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "test-core-api-start-only", "nohelp", options, &run, &ok);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test finished\n");
  stop_arm (&p1);
  stop_arm (&p2);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-core-api-start-only",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-2");
  return ret;
}

/* end of test_core_api_start_only.c */
