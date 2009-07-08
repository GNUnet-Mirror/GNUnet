/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 *
 * FIXME:
 * - make sure connect callback is invoked properly as well!
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

#define VERBOSE GNUNET_YES

#define START_ARM GNUNET_YES


/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

#define MTYPE 12345

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CORE_Handle *ch;
  struct GNUNET_PeerIdentity id;   
  struct GNUNET_TRANSPORT_Handle *th;
  struct GNUNET_MessageHeader *hello;
#if START_ARM
  pid_t arm_pid;
#endif
};

static struct PeerContext p1;

static struct PeerContext p2;

static struct GNUNET_SCHEDULER_Handle *sched;

static int ok;

#if VERBOSE
#define OKPP do { ok++; fprintf (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif



static void
terminate_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (ok == 6);
  GNUNET_CORE_disconnect (p1.ch);
  GNUNET_CORE_disconnect (p2.ch);
  GNUNET_TRANSPORT_disconnect (p1.th);
  GNUNET_TRANSPORT_disconnect (p2.th);
  GNUNET_ARM_stop_service ("core", p1.cfg, sched, TIMEOUT, NULL, NULL);
  GNUNET_ARM_stop_service ("core", p2.cfg, sched, TIMEOUT, NULL, NULL);
  ok = 0;
}


static void
connect_notify (void *cls,
                const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert ((ok == 5) || (ok == 6));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypted connection established to peer `%4s'\n",
              GNUNET_i2s (peer));
}


static void
disconnect_notify (void *cls,
                   const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypted connection to `%4s' cut\n", GNUNET_i2s (peer));
}


static unsigned int
bfc_callback (void *cls,
              const struct GNUNET_PeerIdentity *receiver,
              void *position, unsigned int padding)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core requests data for `%4s', I have none.\n",
              GNUNET_i2s (receiver));
  return 0;
}


static int
inbound_notify (void *cls,
                const struct GNUNET_PeerIdentity *other,
                const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core provides inbound data from `%4s'.\n", GNUNET_i2s (other));
  return GNUNET_OK;
}


static int
outbound_notify (void *cls,
                 const struct GNUNET_PeerIdentity *other,
                 const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core notifies about outbound data for `%4s'.\n",
              GNUNET_i2s (other));
  return GNUNET_OK;
}


static int
process_mtype (void *cls,
               const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Receiving message from `%4s'.\n", GNUNET_i2s (peer));
  GNUNET_assert (ok == 5);
  OKPP;
  GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_NO,
                                GNUNET_SCHEDULER_PRIORITY_KEEP,
                                GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
                                GNUNET_TIME_UNIT_ZERO, &terminate_task, NULL);
  return GNUNET_OK;
}


static struct GNUNET_CORE_MessageHandler handlers[] = {
  {&process_mtype, MTYPE, sizeof (struct GNUNET_MessageHeader)},
  {NULL, 0, 0}
};


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
init_notify (void *cls,
             struct GNUNET_CORE_Handle *server,
             const struct GNUNET_PeerIdentity *my_identity,
             const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{
  struct PeerContext *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core connection to `%4s' established\n",
              GNUNET_i2s (my_identity));
  GNUNET_assert (server != NULL);
  p->id = *my_identity;
  p->ch = server;
  if (cls == &p1)
    {
      GNUNET_assert (ok == 2);
      OKPP;
      /* connect p2 */
      GNUNET_CORE_connect (sched,
                           p2.cfg,
                           TIMEOUT,
                           &p2,
                           &init_notify,
                           &connect_notify,
                           &disconnect_notify,
                           &bfc_callback,
                           &inbound_notify,
                           GNUNET_YES,
                           &outbound_notify, GNUNET_YES, handlers);
    }
  else
    {
      GNUNET_assert (ok == 3);
      OKPP;
      GNUNET_assert (cls == &p2);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Asking core (1) for transmission to peer `%4s'\n",
                  GNUNET_i2s (&p2.id));
      GNUNET_CORE_notify_transmit_ready (p1.ch,
                                         0,
                                         TIMEOUT,
                                         &p2.id,
                                         sizeof (struct GNUNET_MessageHeader),
                                         &transmit_ready, &p1);

    }
}


static void
process_hello (void *cls,
               struct GNUNET_TIME_Relative latency,
               const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *p = cls;

  GNUNET_assert (peer != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received (my) `%s' from transport service of `%4s'\n",
              "HELLO", GNUNET_i2s (peer));
  GNUNET_assert (message != NULL);
  p->hello = GNUNET_malloc (ntohs (message->size));
  memcpy (p->hello, message, ntohs (message->size));
  if ((p == &p1) && (p2.th != NULL))
    GNUNET_TRANSPORT_offer_hello (p2.th, message);
  if ((p == &p2) && (p1.th != NULL))
    GNUNET_TRANSPORT_offer_hello (p1.th, message);

  if ((p == &p1) && (p2.hello != NULL))
    GNUNET_TRANSPORT_offer_hello (p1.th, p2.hello);
  if ((p == &p2) && (p1.hello != NULL))
    GNUNET_TRANSPORT_offer_hello (p2.th, p1.hello);
}



static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_pid = GNUNET_OS_start_process ("gnunet-service-arm",
                                        "gnunet-service-arm",
#if VERBOSE
                                        "-L", "DEBUG",
#endif
                                        "-c", cfgname, NULL);
  sleep (1);                    /* allow ARM to start */
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  GNUNET_ARM_start_service ("core", p->cfg, sched, TIMEOUT, NULL, NULL);
  p->th = GNUNET_TRANSPORT_connect (sched, p->cfg, p, NULL, NULL, NULL);
  GNUNET_assert (p->th != NULL);
  GNUNET_TRANSPORT_get_hello (p->th, TIMEOUT, &process_hello, p);
}


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile, struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (ok == 1);
  OKPP;
  sched = s;
  setup_peer (&p1, "test_core_api_peer1.conf");
  setup_peer (&p2, "test_core_api_peer2.conf");
  GNUNET_CORE_connect (sched,
                       p1.cfg,
                       TIMEOUT,
                       &p1,
                       &init_notify,
                       &connect_notify,
                       &disconnect_notify,
                       &bfc_callback,
                       &inbound_notify,
                       GNUNET_YES, &outbound_notify, GNUNET_YES, handlers);
}


static void
stop_arm (struct PeerContext *p)
{
#if START_ARM
  if (0 != PLIBC_KILL (p->arm_pid, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  if (GNUNET_OS_process_wait(p->arm_pid) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "ARM process %u stopped\n", p->arm_pid);
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
  // sleep (1); /* for 'make check': allow previous processes to fully terminate */
  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-core-api", "nohelp", options, &run, &ok);
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

  return ret;
}

/* end of test_core_api.c */
