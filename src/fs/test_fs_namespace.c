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
 *
 * TODO:
 * - add timeout task
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_fs_service.h"

#define VERBOSE GNUNET_NO

#define START_ARM GNUNET_YES

static struct GNUNET_SCHEDULER_Handle *sched;

static struct PeerContext p1;

static GNUNET_HashCode nsid;

static struct GNUNET_FS_Uri *sks_expect_uri;

static struct GNUNET_FS_Uri *ksk_expect_uri;

static struct GNUNET_FS_Handle *fs;

static struct GNUNET_FS_SearchContext *sks_search;

static struct GNUNET_FS_SearchContext *ksk_search;

static int update_started;

static int err;

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
#if START_ARM
  pid_t arm_pid;
#endif
};


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


static void
abort_ksk_search_task (void *cls,
		       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (ksk_search != NULL)
    {
      GNUNET_FS_search_stop (ksk_search);
      ksk_search = NULL;
      if (sks_search == NULL)
	{
	  GNUNET_FS_stop (fs);
	}
    }
}


static void
abort_sks_search_task (void *cls,
		       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_Namespace *ns;

  if (sks_search == NULL)
    return;
  GNUNET_FS_search_stop (sks_search); 
  sks_search = NULL;
  ns = GNUNET_FS_namespace_create (fs,
				   "testNamespace");
  GNUNET_assert (GNUNET_OK == GNUNET_FS_namespace_delete (ns, GNUNET_YES));
  if (ksk_search == NULL)
    {
      GNUNET_FS_stop (fs);
    }    
}


static void *
progress_cb (void *cls, 
	     const struct GNUNET_FS_ProgressInfo *event)
{
  switch (event->status)
    {
    case GNUNET_FS_STATUS_SEARCH_RESULT:
      if (sks_search == event->value.search.sc)
	{
	  if (! GNUNET_FS_uri_test_equal (sks_expect_uri,
					  event->value.search.specifics.result.uri))
	    {
	      fprintf (stderr,
		       "Wrong result for sks search!\n");
	      err = 1;
	    }
	  /* give system 1ms to initiate update search! */
	  GNUNET_SCHEDULER_add_delayed (sched,
					GNUNET_TIME_UNIT_MILLISECONDS,
					&abort_sks_search_task,
					NULL);
	}
      else if (ksk_search == event->value.search.sc)
	{
	  if (! GNUNET_FS_uri_test_equal (ksk_expect_uri,
					  event->value.search.specifics.result.uri))
	    {
	      fprintf (stderr,
		       "Wrong result for ksk search!\n");
	      err = 1;
	    }
	  GNUNET_SCHEDULER_add_continuation (sched,
					     &abort_ksk_search_task,
					     NULL,
					     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
	}
      else 
	{
	  fprintf (stderr,
		   "Unexpected search result received!\n");
	  GNUNET_break (0);
	}
      break;
    case GNUNET_FS_STATUS_SEARCH_ERROR:
      fprintf (stderr,
	       "Error searching file: %s\n",
	       event->value.search.specifics.error.message);
      if (sks_search == event->value.search.sc)
	GNUNET_SCHEDULER_add_continuation (sched,
					   &abort_sks_search_task,
					   NULL,
					   GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      else if (ksk_search == event->value.search.sc)
	GNUNET_SCHEDULER_add_continuation (sched,
					   &abort_ksk_search_task,
					   NULL,
					   GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      else
	GNUNET_break (0);
      break;
    case GNUNET_FS_STATUS_SEARCH_START:
      GNUNET_assert ( (NULL == event->value.search.cctx) ||
		      (0 == strcmp ("sks_search", event->value.search.cctx)) ||
		      (0 == strcmp ("ksk_search", event->value.search.cctx)));
      if (NULL == event->value.search.cctx)
	{
	  GNUNET_assert (0 == strcmp ("sks_search", event->value.search.pctx));
	  update_started = GNUNET_YES;
	}
      GNUNET_assert (1 == event->value.search.anonymity);
      break;
    case GNUNET_FS_STATUS_SEARCH_RESULT_STOPPED:
      return NULL;
    case GNUNET_FS_STATUS_SEARCH_STOPPED:
      return NULL;
    default:
      fprintf (stderr,
	       "Unexpected event: %d\n", 
	       event->status);
      break;
    }
  return event->value.search.cctx;
}


static void
publish_cont (void *cls,
	      const struct GNUNET_FS_Uri *ksk_uri,
	      const char *emsg)
{
  char *msg;
  struct GNUNET_FS_Uri *sks_uri;
  char sbuf[1024];
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  
  if (NULL != emsg)
    {
      fprintf (stderr, "Error publishing: %s\n", emsg);
      err = 1;
      GNUNET_FS_stop (fs);
      return;
    }  
  GNUNET_CRYPTO_hash_to_enc (&nsid,
			     &enc);
  GNUNET_snprintf (sbuf,
		   sizeof (sbuf),
		   "gnunet://fs/sks/%s/this",
		   &enc);
  sks_uri = GNUNET_FS_uri_parse (sbuf, &msg);
  if (msg != NULL)
    {
      fprintf (stderr, "failed to parse URI `%s': %s\n",
	       sbuf,
	       msg);
      err = 1;
      GNUNET_FS_stop (fs);
      GNUNET_free (msg);
      return;
    }
  ksk_search = GNUNET_FS_search_start (fs, ksk_uri, 1, GNUNET_FS_SEARCH_OPTION_NONE, "ksk_search");
  sks_search = GNUNET_FS_search_start (fs, sks_uri, 1, GNUNET_FS_SEARCH_OPTION_NONE, "sks_search");
  GNUNET_FS_uri_destroy (sks_uri);
}


static void
sks_cont (void *cls,
	  const struct GNUNET_FS_Uri *uri,
	  const char *emsg)
{
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_TIME_Absolute expiration;
  struct GNUNET_FS_Uri *ksk_uri;
  char * msg;

  expiration = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES);
  meta = GNUNET_CONTAINER_meta_data_create ();
  msg = NULL;
  ksk_uri = GNUNET_FS_uri_parse ("gnunet://fs/ksk/ns-search", &msg);
  GNUNET_assert (NULL == msg);
  ksk_expect_uri = GNUNET_FS_uri_dup (uri);
  GNUNET_FS_publish_ksk (fs,
			 ksk_uri,
			 meta,
			 uri,
			 expiration,
			 1, 1,
			 GNUNET_FS_PUBLISH_OPTION_NONE,
			 &publish_cont,
			 NULL);
  GNUNET_FS_uri_destroy (ksk_uri);
  GNUNET_CONTAINER_meta_data_destroy (meta);
}


static void
adv_cont (void *cls,
	  const struct GNUNET_FS_Uri *uri,
	  const char *emsg)
{
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_FS_Namespace *ns;
  struct GNUNET_TIME_Absolute expiration;

  if (NULL != emsg)
    {
      fprintf (stderr, "Error publishing: %s\n", emsg);
      err = 1;
      GNUNET_FS_stop (fs);
      return;
    }
  expiration = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES);
  ns = GNUNET_FS_namespace_create (fs,
				   "testNamespace");
  meta = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_assert (NULL == emsg);
  sks_expect_uri = GNUNET_FS_uri_dup (uri);
  GNUNET_FS_publish_sks (fs,
			 ns,
			 "this",
			 "next",
			 meta,
			 uri, /* FIXME: this is non-sense (use CHK URI!?) */
			 expiration,
			 1, 1,
			 GNUNET_FS_PUBLISH_OPTION_NONE,
			 &sks_cont,
			 NULL);
  GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_FS_namespace_delete (ns, GNUNET_NO);
}


static void
ns_iterator (void *cls,
	     const char *name,
	     const GNUNET_HashCode *id)
{
  int *ok = cls;

  if (0 != strcmp (name,
		   "testNamespace"))
    return;
  *ok = GNUNET_YES;
  nsid = *id;
}


static void
testNamespace ()
{
  struct GNUNET_FS_Namespace *ns;
  struct GNUNET_TIME_Absolute expiration;
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_FS_Uri *ksk_uri;
  int ok;

  ns = GNUNET_FS_namespace_create (fs,
				   "testNamespace");
  ok = GNUNET_NO;
  GNUNET_FS_namespace_list (fs, &ns_iterator, &ok);
  if (GNUNET_NO == ok)
    {
      fprintf (stderr, "namespace_list failed to find namespace!\n");
      GNUNET_FS_namespace_delete (ns, GNUNET_YES);
      GNUNET_FS_stop (fs);
      err = 1;
      return;
    }
  expiration = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES);
  meta = GNUNET_CONTAINER_meta_data_create ();
  ksk_uri = GNUNET_FS_uri_parse ("gnunet://fs/ksk/testnsa", NULL);
  GNUNET_FS_namespace_advertise (fs,
				 ksk_uri,
				 ns,
				 meta,
				 1, 1,
				 expiration,					   
				 "root",
				 &adv_cont, NULL);
  GNUNET_FS_uri_destroy (ksk_uri);
  GNUNET_FS_namespace_delete (ns, GNUNET_NO);
  GNUNET_CONTAINER_meta_data_destroy (meta);
}


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  sched = s;
  setup_peer (&p1, "test_fs_namespace_data.conf");
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
  if (GNUNET_YES != update_started)
    {
      fprintf (stderr,
	       "Update search never started!\n");
      err = 1;
    }
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-namespace/");
  return err;
}


/* end of test_fs_namespace.c */
