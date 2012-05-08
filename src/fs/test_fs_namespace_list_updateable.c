/*
     This file is part of GNUnet.
     (C) 2005, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/test_fs_namespace_list_updateable.c
 * @brief Test for fs_namespace_list_updateable.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_fs_service.h"

#define VERBOSE GNUNET_NO

#define START_ARM GNUNET_YES

static struct PeerContext p1;

static struct GNUNET_FS_Handle *fs;

static int err;

static struct GNUNET_FS_Namespace *ns;

static struct GNUNET_CONTAINER_MetaData *meta;

static struct GNUNET_FS_Uri *uri_this;

static struct GNUNET_FS_Uri *uri_next;

static struct GNUNET_FS_BlockOptions bo;


struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
#if START_ARM
  struct GNUNET_OS_Process *arm_proc;
#endif
};


static void *
progress_cb (void *cls, const struct GNUNET_FS_ProgressInfo *event)
{
  return NULL;
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
stop_arm (struct PeerContext *p)
{
#if START_ARM
  if (NULL != p->arm_proc)
  {
    if (0 != GNUNET_OS_process_kill (p->arm_proc, SIGTERM))
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    if (GNUNET_OS_process_wait (p->arm_proc) != GNUNET_OK)
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ARM process %u stopped\n",
                GNUNET_OS_process_get_pid (p->arm_proc));
    GNUNET_OS_process_destroy (p->arm_proc);
    p->arm_proc = NULL;
  }
#endif
  if (uri_this != NULL)
    GNUNET_FS_uri_destroy (uri_this);
  if (uri_next != NULL)
    GNUNET_FS_uri_destroy (uri_next);
  if (ns != NULL)
    GNUNET_FS_namespace_delete (ns, GNUNET_NO);
  if (meta != NULL)
    GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_CONFIGURATION_destroy (p->cfg);
}



static void
check_next (void *cls, const char *last_id,
            const struct GNUNET_FS_Uri *last_uri,
            const struct GNUNET_CONTAINER_MetaData *last_meta,
            const char *next_id)
{
  GNUNET_break (0 == strcmp (last_id, "next"));
  GNUNET_break (0 == strcmp (next_id, "future"));
  err -= 4;
}


static void
check_this_next (void *cls, const char *last_id,
                 const struct GNUNET_FS_Uri *last_uri,
                 const struct GNUNET_CONTAINER_MetaData *last_meta,
                 const char *next_id)
{
  GNUNET_break (0 == strcmp (last_id, "this"));
  GNUNET_break (0 == strcmp (next_id, "next"));
  err -= 2;
  err += 4;
  GNUNET_FS_namespace_list_updateable (ns, next_id, &check_next, NULL);
}


static void
sks_cont_next (void *cls, const struct GNUNET_FS_Uri *uri, const char *emsg)
{
  GNUNET_assert (NULL == emsg);
  err += 2;
  GNUNET_FS_namespace_list_updateable (ns, NULL, &check_this_next, NULL);

}


static void
check_this (void *cls, const char *last_id,
            const struct GNUNET_FS_Uri *last_uri,
            const struct GNUNET_CONTAINER_MetaData *last_meta,
            const char *next_id)
{
  GNUNET_break (0 == strcmp (last_id, "this"));
  GNUNET_break (0 == strcmp (next_id, "next"));
  err -= 1;
}


static void
sks_cont_this (void *cls, const struct GNUNET_FS_Uri *uri, const char *emsg)
{

  GNUNET_assert (NULL == emsg);
  err = 1;
  GNUNET_FS_namespace_list_updateable (ns, NULL, &check_this, NULL);
  GNUNET_FS_publish_sks (fs, ns, "next", "future", meta, uri_next, &bo,
                         GNUNET_FS_PUBLISH_OPTION_NONE, &sks_cont_next, NULL);

}



static void
testNamespace ()
{

  ns = GNUNET_FS_namespace_create (fs, "testNamespace");
  GNUNET_assert (NULL != ns);
  bo.content_priority = 1;
  bo.anonymity_level = 1;
  bo.replication_level = 0;
  bo.expiration_time =
      GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES);
  meta = GNUNET_CONTAINER_meta_data_create ();

  uri_this =
      GNUNET_FS_uri_parse
      ("gnunet://fs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.42",
       NULL);
  uri_next =
      GNUNET_FS_uri_parse
      ("gnunet://fs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.43",
       NULL);
  GNUNET_FS_publish_sks (fs, ns, "this", "next", meta, uri_this, &bo,
                         GNUNET_FS_PUBLISH_OPTION_NONE, &sks_cont_this, NULL);
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  setup_peer (&p1, "test_fs_namespace_data.conf");
  fs = GNUNET_FS_start (cfg, "test-fs-namespace", &progress_cb, NULL,
                        GNUNET_FS_FLAGS_NONE, GNUNET_FS_OPTIONS_END);
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

  GNUNET_log_setup ("test_fs_namespace_list_updateable",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  GNUNET_PROGRAM_run ((sizeof (argvx) / sizeof (char *)) - 1, argvx,
                      "test-fs-namespace", "nohelp", options, &run, NULL);
  stop_arm (&p1);
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-namespace/");
  return err;
}


/* end of test_fs_namespace_list_updateable.c */
