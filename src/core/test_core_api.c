/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2015, 2016 GNUnet e.V.

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
 * @file core/test_core_api.c
 * @brief testcase for core_api.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_core_service.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_hello_service.h"
#include "gnunet_ats_service.h"

#define MTYPE 12345

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CORE_Handle *ch;
  struct GNUNET_PeerIdentity id;
  struct GNUNET_TRANSPORT_OfferHelloHandle *oh;
  struct GNUNET_TRANSPORT_HelloGetHandle *ghh;
  struct GNUNET_ATS_ConnectivityHandle *ats;
  struct GNUNET_ATS_ConnectivitySuggestHandle *ats_sh;
  struct GNUNET_MessageHeader *hello;
  int connect_status;
  struct GNUNET_OS_Process *arm_proc;
};

static struct PeerContext p1;

static struct PeerContext p2;

static struct GNUNET_SCHEDULER_Task *err_task;

static int ok;

#define OKPP do { ok++; GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)


static void
offer_hello_done (void *cls)
{
  struct PeerContext *p = cls;

  p->oh = NULL;
}


static void
process_hello (void *cls,
               const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received (my) HELLO from transport service\n");
  GNUNET_assert (message != NULL);
  if ((p == &p1) && (NULL == p2.oh))
    p2.oh = GNUNET_TRANSPORT_offer_hello (p2.cfg, message,
                                          &offer_hello_done,
                                          &p2);
  if ((p == &p2) && (NULL == p1.oh))
    p1.oh = GNUNET_TRANSPORT_offer_hello (p1.cfg,
                                          message,
                                          &offer_hello_done,
                                          &p1);
}


static void
terminate_peer (struct PeerContext *p)
{
  if (NULL != p->ch)
  {
    GNUNET_CORE_disconnect (p->ch);
    p->ch = NULL;
  }
  if (NULL != p->ghh)
  {
    GNUNET_TRANSPORT_hello_get_cancel (p->ghh);
    p->ghh = NULL;
  }
  if (NULL != p->oh)
  {
    GNUNET_TRANSPORT_offer_hello_cancel (p->oh);
    p->oh = NULL;
  }
  if (NULL != p->ats_sh)
  {
    GNUNET_ATS_connectivity_suggest_cancel (p->ats_sh);
    p->ats_sh = NULL;
  }
  if (NULL != p->ats)
  {
    GNUNET_ATS_connectivity_done (p->ats);
    p->ats = NULL;
  }
}


static void
terminate_task (void *cls)
{
  GNUNET_assert (ok == 6);
  terminate_peer (&p1);
  terminate_peer (&p2);
  ok = 0;
}


static void
terminate_task_error (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "ENDING ANGRILY %u\n",
              ok);
  GNUNET_break (0);
  terminate_peer (&p1);
  terminate_peer (&p2);
  ok = 42;
}


static void *
connect_notify (void *cls,
                const struct GNUNET_PeerIdentity *peer,
		struct GNUNET_MQ_Handle *mq)
{
  struct PeerContext *pc = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;

  if (0 == memcmp (&pc->id,
		   peer,
		   sizeof (struct GNUNET_PeerIdentity)))
    return (void *) peer;
  GNUNET_assert (pc->connect_status == 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypted connection established to peer `%s'\n",
              GNUNET_i2s (peer));
  pc->connect_status = 1;
  if (pc == &p1)
  {
    uint64_t flags;
    const void *extra;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Asking core (1) for transmission to peer `%s'\n",
                GNUNET_i2s (&p2.id));
    env = GNUNET_MQ_msg (msg,
			 MTYPE);
    /* enable corking for this test */
    extra = GNUNET_CORE_get_mq_options (GNUNET_YES,
					GNUNET_CORE_PRIO_BEST_EFFORT,
					&flags);
    GNUNET_MQ_env_set_options (env,
			       flags,
			       extra);
    /* now actually transmit message */
    GNUNET_assert (ok == 4);
    OKPP;
    GNUNET_MQ_send (mq,
		    env);
  }
  return (void *) peer;
}


static void
disconnect_notify (void *cls,
		   const struct GNUNET_PeerIdentity *peer,
		   void *internal_cls)
{
  struct PeerContext *pc = cls;

  if (0 == memcmp (&pc->id,
		   peer,
		   sizeof (struct GNUNET_PeerIdentity)))
    return;
  pc->connect_status = 0;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Encrypted connection to `%s' cut\n",
              GNUNET_i2s (peer));
}


static void
handle_test (void *cls,
	     const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_PeerIdentity *peer = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Receiving message from `%s'.\n",
              GNUNET_i2s (peer));
  GNUNET_assert (ok == 5);
  OKPP;
  GNUNET_SCHEDULER_cancel (err_task);
  err_task = GNUNET_SCHEDULER_add_now (&terminate_task,
				       NULL);
}


static void
init_notify (void *cls,
             const struct GNUNET_PeerIdentity *my_identity)
{
  struct PeerContext *p = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (test,
                             MTYPE,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_handler_end ()
  };

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core connection to `%s' established\n",
              GNUNET_i2s (my_identity));
  p->id = *my_identity;
  if (cls == &p1)
  {
    GNUNET_assert (ok == 2);
    OKPP;
    /* connect p2 */
    p2.ch = GNUNET_CORE_connect (p2.cfg,
				 &p2,
				 &init_notify,
				 &connect_notify,
				 &disconnect_notify,
				 handlers);
  }
  else
  {
    GNUNET_assert (ok == 3);
    OKPP;
    GNUNET_assert (cls == &p2);
    p1.ats_sh = GNUNET_ATS_connectivity_suggest (p1.ats,
                                                 &p2.id,
                                                 1);
  }
}


static void
setup_peer (struct PeerContext *p,
            const char *cfgname)
{
  char *binary;

  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-service-arm");
  p->cfg = GNUNET_CONFIGURATION_create ();
  p->arm_proc =
    GNUNET_OS_start_process (GNUNET_YES,
			     GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
			     NULL, NULL, NULL,
			     binary,
			     "gnunet-service-arm",
			     "-c",
			     cfgname,
			     NULL);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONFIGURATION_load (p->cfg,
					    cfgname));
  p->ats = GNUNET_ATS_connectivity_init (p->cfg);
  GNUNET_assert (NULL != p->ats);
  p->ghh = GNUNET_TRANSPORT_hello_get (p->cfg,
				       GNUNET_TRANSPORT_AC_ANY,
				       &process_hello,
				       p);
  GNUNET_free (binary);
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (test,
                             MTYPE,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_handler_end ()
  };

  GNUNET_assert (ok == 1);
  OKPP;
  setup_peer (&p1,
	      "test_core_api_peer1.conf");
  setup_peer (&p2,
	      "test_core_api_peer2.conf");
  err_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 300),
                                    &terminate_task_error, NULL);
  p1.ch =
      GNUNET_CORE_connect (p1.cfg,
			   &p1,
                           &init_notify,
                           &connect_notify,
                           &disconnect_notify,
                           handlers);
}


static void
stop_arm (struct PeerContext *p)
{
  if (0 != GNUNET_OS_process_kill (p->arm_proc,
				   GNUNET_TERM_SIG))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
			 "kill");
  if (GNUNET_OK !=
      GNUNET_OS_process_wait (p->arm_proc))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
			 "waitpid");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "ARM process %u stopped\n",
              GNUNET_OS_process_get_pid (p->arm_proc));
  GNUNET_OS_process_destroy (p->arm_proc);
  p->arm_proc = NULL;
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


int
main (int argc,
      char *argv1[])
{
  char *const argv[] = {
    "test-core-api",
    "-c",
    "test_core_api_data.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  ok = 1;
  GNUNET_log_setup ("test-core-api",
                    "WARNING",
                    NULL);
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
		      argv,
                      "test-core-api",
		      "nohelp",
		      options,
		      &run,
		      &ok);
  stop_arm (&p1);
  stop_arm (&p2);
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-2");

  return ok;
}

/* end of test_core_api.c */
