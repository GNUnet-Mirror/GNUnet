/*
     This file is part of GNUnet.
     (C) 2005, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/test_fs_namespace.c
 * @brief Test for fs_namespace.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_fs_service.h"

#define START_ARM GNUNET_YES

static struct GNUNET_SCHEDULER_Handle *sched;

static struct PeerContext p1;

static struct GNUNET_FS_Handle *fs;


struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_PeerIdentity id;   
#if START_ARM
  pid_t arm_pid;
#endif
};


static void *
progress_cb (void *cls, 
	     const struct GNUNET_FS_ProgressInfo *event)
{
  return NULL;
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
  GNUNET_ARM_start_services (p->cfg, sched, "core", NULL);
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


#if 0
static void
spcb (void *cls,
      const char *name,
      const GNUNET_HashCode * key)
{
}
#endif


static void
publish_cont (void *cls,
	      const struct GNUNET_FS_Uri *uri,
	      const char *emsg)
{
  struct GNUNET_FS_SearchContext *search;

  GNUNET_assert (NULL == emsg);
  fprintf (stderr, "Starting namespace search...\n");
  search = GNUNET_FS_search_start (fs, uri, 1);
}


static void
testNamespace ()
{
  struct GNUNET_FS_Namespace *ns;
  struct GNUNET_FS_Uri *adv;
  struct GNUNET_FS_Uri *rootUri;
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_TIME_Absolute expiration;

  expiration = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES);
  meta = GNUNET_CONTAINER_meta_data_create ();
  adv = GNUNET_FS_uri_ksk_create ("testNamespace", NULL);
  ns = GNUNET_FS_namespace_create (fs,
				   "testNamespace");
  rootUri = GNUNET_FS_namespace_advertise (fs,
					   ns,
					   meta,
					   1, 1,
					   expiration,
					   adv,
					   "root");
  GNUNET_assert (NULL != rootUri);
  GNUNET_FS_publish_sks (fs,
			 ns,
			 "this",
			 "next",
			 meta,
			 rootUri,
			 expiration,
			 1, 1,
			 GNUNET_FS_PUBLISH_OPTION_NONE,
			 &publish_cont,
			 NULL);
  GNUNET_CONTAINER_meta_data_destroy (meta);
}

#if 0
  fprintf (stderr, "Completed namespace search...\n");
  GNUNET_assert (GNUNET_OK == GNUNET_FS_namespace_delete (NULL, cfg, &pid));
  GNUNET_assert (GNUNET_SYSERR == GNUNET_FS_namespace_delete (NULL, cfg, &pid));
  GNUNET_FS_uri_destroy (rootURI);
  GNUNET_FS_uri_destroy (advURI);
  GNUNET_assert (match == 1);
  return 0;
}
#endif


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  sched = s;
  setup_peer (&p1, "test_fs_download_data.conf");
  fs = GNUNET_FS_start (sched,
			cfg,
			"test-fs-namespace",
			&progress_cb,
			NULL,
			GNUNET_FS_FLAGS_NONE,
			GNUNET_FS_OPTIONS_END);
  testNamespace ();
}


int
main (int argc, char *argv[])
{
  char *const argvx[] = { 
    "test-fs-namespace",
    "-c",
    "test_fs_namespace_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_log_setup ("test_fs_namespace", 
#if VERBOSE
		    "DEBUG",
#else
		    "WARNING",
#endif
		    NULL);
  GNUNET_PROGRAM_run ((sizeof (argvx) / sizeof (char *)) - 1,
                      argvx, "test-fs-namespace",
		      "nohelp", options, &run, NULL);
  stop_arm (&p1);
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-namespace/");
  return 0;
}



/* end of test_fs_namespace.c */
