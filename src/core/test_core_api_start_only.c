/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/
/**
 * @file transport/test_core_api_start_only.c
 * @brief testcase for core_api.c that only starts two peers,
 *        connects to the core service and shuts down again
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_core_service.h"
#include "gnunet_util_lib.h"

#define TIMEOUT 5

#define MTYPE 12345

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CORE_Handle *ch;
  struct GNUNET_PeerIdentity id;
  struct GNUNET_OS_Process *arm_proc;
};

static struct PeerContext p1;

static struct PeerContext p2;

static struct GNUNET_SCHEDULER_Task *timeout_task_id;

static int ok;


static void *
connect_notify (void *cls,
		const struct GNUNET_PeerIdentity *peer,
		struct GNUNET_MQ_Handle *mq)
{
  return NULL;
}


static void
disconnect_notify (void *cls,
		   const struct GNUNET_PeerIdentity *peer,
		   void *internal_cls)
{
}


static struct GNUNET_MQ_MessageHandler handlers[] = {
  GNUNET_MQ_handler_end ()
};


static void
shutdown_task (void *cls)
{
  GNUNET_CORE_disconnect (p1.ch);
  p1.ch = NULL;
  GNUNET_CORE_disconnect (p2.ch);
  p2.ch = NULL;
  ok = 0;
}


static void
init_notify (void *cls,
             const struct GNUNET_PeerIdentity *my_identity)
{
  struct PeerContext *p = cls;

  if (p == &p1)
  {
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
    GNUNET_assert (p == &p2);
    GNUNET_SCHEDULER_cancel (timeout_task_id);
    timeout_task_id = NULL;
    GNUNET_SCHEDULER_add_now (&shutdown_task,
			      NULL);
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
			     "-c", cfgname,
			     NULL);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONFIGURATION_load (p->cfg,
					    cfgname));
  GNUNET_free (binary);
}


static void
timeout_task (void *cls)
{
  FPRINTF (stderr,
	   "%s",
	   "Timeout.\n");
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
  ok = 42;
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (ok == 1);
  ok++;
  setup_peer (&p1, "test_core_api_peer1.conf");
  setup_peer (&p2, "test_core_api_peer2.conf");
  timeout_task_id =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MINUTES,
				     TIMEOUT),
                                    &timeout_task,
				    NULL);
  p1.ch = GNUNET_CORE_connect (p1.cfg,
			       &p1,
			       &init_notify,
			       &connect_notify,
			       &disconnect_notify,
			       handlers);
}


static void
stop_arm (struct PeerContext *p)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Stopping peer\n");
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
              (unsigned int) GNUNET_OS_process_get_pid (p->arm_proc));
  GNUNET_OS_process_destroy (p->arm_proc);
  p->arm_proc = NULL;
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


static int
check ()
{
  char *const argv[] = {
    "test-core-api-start-only",
    "-c",
    "test_core_api_data.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-2");

  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
		      argv,
                      "test-core-api-start-only",
		      "nohelp",
		      options,
		      &run,
		      &ok);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Test finished\n");
  stop_arm (&p1);
  stop_arm (&p2);
  return ok;
}


int
main (int argc,
      char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-core-api-start-only",
                    "WARNING",
                    NULL);
  ret = check ();
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-2");
  return ret;
}

/* end of test_core_api_start_only.c */
