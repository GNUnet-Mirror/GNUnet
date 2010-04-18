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

#define START_ARM GNUNET_YES


/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

#define MTYPE 12345

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CORE_Handle *ch;
  struct GNUNET_PeerIdentity id;
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
connect_notify (void *cls,
                const struct GNUNET_PeerIdentity *peer,
		struct GNUNET_TIME_Relative latency,
		uint32_t distance)
{
}


static void
disconnect_notify (void *cls,
                   const struct GNUNET_PeerIdentity *peer)
{
}


static int
inbound_notify (void *cls,
                const struct GNUNET_PeerIdentity *other,
                const struct GNUNET_MessageHeader *message,
		struct GNUNET_TIME_Relative latency,
		uint32_t distance)
{
  return GNUNET_OK;
}


static int
outbound_notify (void *cls,
                 const struct GNUNET_PeerIdentity *other,
                 const struct GNUNET_MessageHeader *message,
		 struct GNUNET_TIME_Relative latency,
		 uint32_t distance)
{
  return GNUNET_OK;
}


static struct GNUNET_CORE_MessageHandler handlers[] = {
  {NULL, 0, 0}
};



static void
init_notify (void *cls,
             struct GNUNET_CORE_Handle *server,
             const struct GNUNET_PeerIdentity *my_identity,
             const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{
  struct PeerContext *p = cls;

  GNUNET_assert (server != NULL);
  p->ch = server;
  if (cls == &p1)
    {
      /* connect p2 */
      GNUNET_CORE_connect (sched,
                           p2.cfg,
                           TIMEOUT,
                           &p2,
                           &init_notify,			 
                           &connect_notify,
                           &disconnect_notify,
                           &inbound_notify,
                           GNUNET_YES,
                           &outbound_notify, GNUNET_YES, handlers);
    }
  else
    {
      GNUNET_assert (cls == &p2);
      GNUNET_CORE_disconnect (p1.ch);
      GNUNET_CORE_disconnect (p2.ch);
      GNUNET_ARM_stop_services (p1.cfg, sched, "core", NULL);
      GNUNET_ARM_stop_services (p2.cfg, sched, "core", NULL);

      ok = 0;
    }
}


static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_pid = GNUNET_OS_start_process (NULL, NULL, "gnunet-service-arm",
                                        "gnunet-service-arm",
#if VERBOSE
                                        "-L", "DEBUG",
#endif
                                        "-c", cfgname, NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  GNUNET_ARM_start_services (p->cfg, sched, "core", NULL);
}


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile, 
     const struct GNUNET_CONFIGURATION_Handle *cfg)
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

/* end of test_core_api_start_only.c */
