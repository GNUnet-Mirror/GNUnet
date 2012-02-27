/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file core/test_core_api.c
 * @brief testcase for core_api.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_arm_service.h"
#include "gnunet_core_service.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_transport_service.h"

#define VERBOSE GNUNET_NO

#define START_ARM GNUNET_YES

#define MTYPE 12345

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CORE_Handle *ch;
  struct GNUNET_PeerIdentity id;
  struct GNUNET_TRANSPORT_Handle *th;
  struct GNUNET_TRANSPORT_GetHelloHandle *ghh;
  struct GNUNET_MessageHeader *hello;
  int connect_status;
#if START_ARM
  struct GNUNET_OS_Process *arm_proc;
#endif
};

static struct PeerContext p1;

static struct PeerContext p2;

static GNUNET_SCHEDULER_TaskIdentifier err_task;

static GNUNET_SCHEDULER_TaskIdentifier con_task;

static int ok;

#if VERBOSE
#define OKPP do { ok++; GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif


static void
process_hello (void *cls, const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received (my) `%s' from transport service\n", "HELLO");
  GNUNET_assert (message != NULL);
  if ((p == &p1) && (p2.th != NULL))
    GNUNET_TRANSPORT_offer_hello (p2.th, message, NULL, NULL);
  if ((p == &p2) && (p1.th != NULL))
    GNUNET_TRANSPORT_offer_hello (p1.th, message, NULL, NULL);
}


static void
terminate_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (ok == 6);
  GNUNET_CORE_disconnect (p1.ch);
  p1.ch = NULL;
  GNUNET_CORE_disconnect (p2.ch);
  p2.ch = NULL;
  GNUNET_TRANSPORT_get_hello_cancel (p1.ghh);
  p1.ghh = NULL;
  GNUNET_TRANSPORT_get_hello_cancel (p2.ghh);
  p2.ghh = NULL;
  GNUNET_TRANSPORT_disconnect (p1.th);
  p1.th = NULL;
  GNUNET_TRANSPORT_disconnect (p2.th);
  p2.th = NULL;
  if (GNUNET_SCHEDULER_NO_TASK != con_task)
  {
    GNUNET_SCHEDULER_cancel (con_task);
    con_task = GNUNET_SCHEDULER_NO_TASK;
  }
  ok = 0;
}


static void
terminate_task_error (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#if VERBOSE
  FPRINTF (stderr, "ENDING ANGRILY %u\n", ok);
#endif
  GNUNET_break (0);
  if (NULL != p1.ch)
  {
    GNUNET_CORE_disconnect (p1.ch);
    p1.ch = NULL;
  }
  if (NULL != p2.ch)
  {
    GNUNET_CORE_disconnect (p2.ch);
    p2.ch = NULL;
  }
  if (p1.th != NULL)
  {
    GNUNET_TRANSPORT_get_hello_cancel (p1.ghh);
    GNUNET_TRANSPORT_disconnect (p1.th);
    p1.th = NULL;
  }
  if (p2.th != NULL)
  {
    GNUNET_TRANSPORT_get_hello_cancel (p2.ghh);
    GNUNET_TRANSPORT_disconnect (p2.th);
    p2.th = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != con_task)
  {
    GNUNET_SCHEDULER_cancel (con_task);
    con_task = GNUNET_SCHEDULER_NO_TASK;
  }
  ok = 42;
}


static size_t
transmit_ready (void *cls, size_t size, void *buf)
{
  struct PeerContext *p = cls;
  struct GNUNET_MessageHeader *m;

  GNUNET_assert (ok == 4);
  OKPP;
  GNUNET_assert (p == &p1);
  GNUNET_assert (buf != NULL);
  m = (struct GNUNET_MessageHeader *) buf;
  m->type = htons (MTYPE);
  m->size = htons (sizeof (struct GNUNET_MessageHeader));
  return sizeof (struct GNUNET_MessageHeader);
}


static void
connect_notify (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_ATS_Information *atsi,
                unsigned int atsi_count)
{
  struct PeerContext *pc = cls;

  if (0 == memcmp (&pc->id, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  GNUNET_assert (pc->connect_status == 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypted connection established to peer `%4s'\n",
              GNUNET_i2s (peer));
  if (GNUNET_SCHEDULER_NO_TASK != con_task)
  {
    GNUNET_SCHEDULER_cancel (con_task);
    con_task = GNUNET_SCHEDULER_NO_TASK;
  }
  pc->connect_status = 1;
  if (pc == &p1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Asking core (1) for transmission to peer `%4s'\n",
                GNUNET_i2s (&p2.id));
    if (NULL ==
        GNUNET_CORE_notify_transmit_ready (p1.ch, GNUNET_YES, 0,
                                           GNUNET_TIME_relative_multiply
                                           (GNUNET_TIME_UNIT_SECONDS, 145),
                                           &p2.id,
                                           sizeof (struct GNUNET_MessageHeader),
                                           &transmit_ready, &p1))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "RECEIVED NULL when asking core (1) for transmission to peer `%4s'\n",
                  GNUNET_i2s (&p2.id));
    }
  }
}


static void
disconnect_notify (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *pc = cls;

  if (0 == memcmp (&pc->id, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  pc->connect_status = 0;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Encrypted connection to `%4s' cut\n",
              GNUNET_i2s (peer));
}


static int
inbound_notify (void *cls, const struct GNUNET_PeerIdentity *other,
                const struct GNUNET_MessageHeader *message,
                const struct GNUNET_ATS_Information *atsi,
                unsigned int atsi_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core provides inbound data from `%4s'.\n", GNUNET_i2s (other));
  return GNUNET_OK;
}


static int
outbound_notify (void *cls, const struct GNUNET_PeerIdentity *other,
                 const struct GNUNET_MessageHeader *message,
                 const struct GNUNET_ATS_Information *atsi,
                 unsigned int atsi_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core notifies about outbound data for `%4s'.\n",
              GNUNET_i2s (other));
  return GNUNET_OK;
}



static int
process_mtype (void *cls, const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_MessageHeader *message,
               const struct GNUNET_ATS_Information *atsi,
               unsigned int atsi_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Receiving message from `%4s'.\n",
              GNUNET_i2s (peer));
  GNUNET_assert (ok == 5);
  OKPP;
  GNUNET_SCHEDULER_cancel (err_task);
  err_task = GNUNET_SCHEDULER_add_now (&terminate_task, NULL);
  return GNUNET_OK;
}


static struct GNUNET_CORE_MessageHandler handlers[] = {
  {&process_mtype, MTYPE, sizeof (struct GNUNET_MessageHeader)},
  {NULL, 0, 0}
};


static void
connect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    con_task = GNUNET_SCHEDULER_NO_TASK;
    return;
  }
  con_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &connect_task,
                                    NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking transport (1) to connect to peer `%4s'\n",
              GNUNET_i2s (&p2.id));
  GNUNET_TRANSPORT_try_connect (p1.th, &p2.id);
}


static void
init_notify (void *cls, struct GNUNET_CORE_Handle *server,
             const struct GNUNET_PeerIdentity *my_identity)
{
  struct PeerContext *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Core connection to `%4s' established\n",
              GNUNET_i2s (my_identity));
  GNUNET_assert (server != NULL);
  p->id = *my_identity;
  p->ch = server;
  if (cls == &p1)
  {
    GNUNET_assert (ok == 2);
    OKPP;
    /* connect p2 */
    p2.ch =
        GNUNET_CORE_connect (p2.cfg, 1, &p2, &init_notify, &connect_notify,
                             &disconnect_notify, &inbound_notify, GNUNET_YES,
                             &outbound_notify, GNUNET_YES, handlers);
  }
  else
  {
    GNUNET_assert (ok == 3);
    OKPP;
    GNUNET_assert (cls == &p2);
    con_task = GNUNET_SCHEDULER_add_now (&connect_task, NULL);
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
  p->th = GNUNET_TRANSPORT_connect (p->cfg, NULL, p, NULL, NULL, NULL);
  GNUNET_assert (p->th != NULL);
  p->ghh = GNUNET_TRANSPORT_get_hello (p->th, &process_hello, p);
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (ok == 1);
  OKPP;
  setup_peer (&p1, "test_core_api_peer1.conf");
  setup_peer (&p2, "test_core_api_peer2.conf");
  err_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 300),
                                    &terminate_task_error, NULL);
  p1.ch =
      GNUNET_CORE_connect (p1.cfg, 1, &p1, &init_notify, &connect_notify,
                           &disconnect_notify, &inbound_notify, GNUNET_YES,
                           &outbound_notify, GNUNET_YES, handlers);
}


static void
stop_arm (struct PeerContext *p)
{
#if START_ARM
  if (0 != GNUNET_OS_process_kill (p->arm_proc, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  if (GNUNET_OS_process_wait (p->arm_proc) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ARM process %u stopped\n",
              GNUNET_OS_process_get_pid (p->arm_proc));
  GNUNET_OS_process_close (p->arm_proc);
  p->arm_proc = NULL;
#endif
  GNUNET_CONFIGURATION_destroy (p->cfg);
}

static int
check ()
{
  char *const argv[] = { "test-core-api",
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
  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "test-core-api", "nohelp", options, &run, &ok);
  stop_arm (&p1);
  stop_arm (&p2);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-core-api",
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

/* end of test_core_api.c */
