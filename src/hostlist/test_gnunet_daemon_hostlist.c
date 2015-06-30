/*
     This file is part of GNUnet
     Copyright (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file hostlist/test_gnunet_daemon_hostlist.c
 * @brief test for gnunet_daemon_hostslist.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_transport_service.h"


/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 150)

static int ok;

static struct GNUNET_SCHEDULER_Task * timeout_task;

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_TRANSPORT_Handle *th;
  struct GNUNET_MessageHeader *hello;
  struct GNUNET_TRANSPORT_GetHelloHandle *ghh;
  struct GNUNET_OS_Process *arm_proc;
};

static struct PeerContext p1;

static struct PeerContext p2;


static void
clean_up (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (p1.th != NULL)
  {
    if (p1.ghh != NULL)
    {
      GNUNET_TRANSPORT_get_hello_cancel (p1.ghh);
      p1.ghh = NULL;
    }
    GNUNET_TRANSPORT_disconnect (p1.th);
    p1.th = NULL;
  }
  if (p2.th != NULL)
  {
    if (p2.ghh != NULL)
    {
      GNUNET_TRANSPORT_get_hello_cancel (p2.ghh);
      p2.ghh = NULL;
    }
    GNUNET_TRANSPORT_disconnect (p2.th);
    p2.th = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
}

/**
 * Timeout, give up.
 */
static void
timeout_error (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  timeout_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Timeout trying to connect peers, test failed.\n");
  clean_up (NULL, tc);
}


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param peer the peer that connected
 * @param latency current latency of the connection
 * @param distance in overlay hops, as given by transport plugin
 */
static void
notify_connect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  if (peer == NULL)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peers connected, shutting down.\n");
  ok = 0;
  if (timeout_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
  }
  GNUNET_SCHEDULER_add_now (&clean_up, NULL);
}


static void
process_hello (void *cls, const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *p = cls;

  GNUNET_TRANSPORT_get_hello_cancel (p->ghh);
  p->ghh = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received HELLO, starting hostlist service.\n");
}


static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  char *binary;

  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-service-arm");
  p->cfg = GNUNET_CONFIGURATION_create ();
  p->arm_proc =
    GNUNET_OS_start_process (GNUNET_YES, GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                             NULL, NULL, NULL,
                             binary,
                             "gnunet-service-arm",
                             "-c", cfgname, NULL);
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  p->th =
      GNUNET_TRANSPORT_connect (p->cfg, NULL, p, NULL, &notify_connect, NULL);
  GNUNET_assert (p->th != NULL);
  p->ghh = GNUNET_TRANSPORT_get_hello (p->th, &process_hello, p);
  GNUNET_free (binary);
}


static void
waitpid_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerContext *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Killing ARM process.\n");
  if (0 != GNUNET_OS_process_kill (p->arm_proc, GNUNET_TERM_SIG))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  if (GNUNET_OS_process_wait (p->arm_proc) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ARM process %u stopped\n",
              GNUNET_OS_process_get_pid (p->arm_proc));
  GNUNET_OS_process_destroy (p->arm_proc);
  p->arm_proc = NULL;
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


static void
stop_arm (struct PeerContext *p)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Asking ARM to stop core service\n");
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &waitpid_task, p);
}


/**
 * Try again to connect to transport service.
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  stop_arm (&p1);
  stop_arm (&p2);
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (ok == 1);
  ok++;
  timeout_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &timeout_error, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  setup_peer (&p1, "test_gnunet_daemon_hostlist_peer1.conf");
  setup_peer (&p2, "test_gnunet_daemon_hostlist_peer2.conf");
}


static int
check ()
{
  char *const argv[] = { "test-gnunet-daemon-hostlist",
    "-c", "test_gnunet_daemon_hostlist_data.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "test-gnunet-daemon-hostlist", "nohelp", options, &run,
                      &ok);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-hostlist-peer-1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-hostlist-peer-2");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-hostlist");
  GNUNET_log_setup ("test-gnunet-daemon-hostlist",
                    "WARNING",
                    NULL);
  ret = check ();
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-hostlist-peer-1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-hostlist-peer-2");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-hostlist");
  return ret;
}

/* end of test_gnunet_daemon_hostlist.c */
