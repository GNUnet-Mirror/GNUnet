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
 * @file fs/test_fs_namespace.c
 * @brief Test for fs_namespace.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_fs_service.h"


static struct GNUNET_HashCode nsid;

static struct GNUNET_FS_Uri *sks_expect_uri;

static struct GNUNET_FS_Uri *ksk_expect_uri;

static struct GNUNET_FS_Handle *fs;

static struct GNUNET_FS_SearchContext *sks_search;

static struct GNUNET_FS_SearchContext *ksk_search;

static GNUNET_SCHEDULER_TaskIdentifier kill_task;

static GNUNET_SCHEDULER_TaskIdentifier kill_ncc_task;

struct GNUNET_FS_NamespaceCreationContext *ncc;

static int update_started;

static int err;

static int phase;

const struct GNUNET_CONFIGURATION_Handle *config;

static void ns_created (void *cls, struct GNUNET_FS_Namespace *ns, const char *emsg);

static void do_ncc_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
next_phase ()
{
  switch (phase)
  {
  case 0:
    phase += 1;
    FPRINTF (stderr, "%s",  "Testing asynchronous namespace creation\n");
    ncc = GNUNET_FS_namespace_create_start (fs, "testNamespace", ns_created, NULL);
    if (NULL == ncc)
    {
      FPRINTF (stderr, "%s",  "Failed to start asynchronous namespace creation\n");
      err = 1;
      next_phase ();
      return;
    }
    kill_ncc_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES, &do_ncc_timeout,
                                    NULL);
    break;
  case 1:
    FPRINTF (stderr, "%s",  "Shutting down FS\n");
    GNUNET_FS_stop (fs);
    if (GNUNET_SCHEDULER_NO_TASK != kill_task)
      GNUNET_SCHEDULER_cancel (kill_task);
    kill_task = GNUNET_SCHEDULER_NO_TASK;
  }
}

static void
abort_ksk_search_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL == ksk_search)
    return;
  FPRINTF (stderr, "%s",  "Stopping KSK search\n");
  GNUNET_FS_search_stop (ksk_search);
  ksk_search = NULL;
  if (sks_search == NULL)
    next_phase ();
}


static void
abort_sks_search_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_Namespace *ns;

  if (sks_search == NULL)
    return;
  FPRINTF (stderr, "%s",  "Stopping SKS search\n");
  GNUNET_FS_search_stop (sks_search);
  sks_search = NULL;
  ns = GNUNET_FS_namespace_create (fs, "testNamespace");
  GNUNET_assert (NULL != ns);
  GNUNET_assert (GNUNET_OK == GNUNET_FS_namespace_delete (ns, GNUNET_YES));
  if (ksk_search == NULL)
    next_phase ();
}


static void
do_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  FPRINTF (stderr, "%s",  "Operation timed out\n");
  kill_task = GNUNET_SCHEDULER_NO_TASK;
  abort_sks_search_task (NULL, tc);
  abort_ksk_search_task (NULL, tc);
}


static void *
progress_cb (void *cls, const struct GNUNET_FS_ProgressInfo *event)
{
  char *got;
  switch (event->status)
  {
  case GNUNET_FS_STATUS_SEARCH_RESULT:
    got = GNUNET_FS_uri_to_string (event->value.search.specifics.result.uri);
    FPRINTF (stderr, "Got a search result `%s'\n", got);
    if (sks_search == event->value.search.sc)
    {
      if (!GNUNET_FS_uri_test_equal
          (sks_expect_uri, event->value.search.specifics.result.uri))
      {
        char *expected;
        expected = GNUNET_FS_uri_to_string (sks_expect_uri);
        FPRINTF (stderr, "Wrong result for sks search! Expected:\n%s\nGot:\n%s\n", expected, got);
        GNUNET_free (expected);
        err = 1;
      }
      /* give system 1ms to initiate update search! */
      FPRINTF (stderr, "scheduling `%s'\n", "abort_sks_search_task");
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
                                    &abort_sks_search_task, NULL);
    }
    else if (ksk_search == event->value.search.sc)
    {
      if (!GNUNET_FS_uri_test_equal
          (ksk_expect_uri, event->value.search.specifics.result.uri))
      {
        char *expected;
        expected = GNUNET_FS_uri_to_string (ksk_expect_uri);
        FPRINTF (stderr, "Wrong result for ksk search! Expected:\n%s\nGot:\n%s\n", expected, got);
        GNUNET_free (expected);
        err = 1;
      }
      FPRINTF (stderr, "scheduling `%s'\n", "abort_ksk_search_task");
      GNUNET_SCHEDULER_add_continuation (&abort_ksk_search_task, NULL,
                                         GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    }
    else
    {
      FPRINTF (stderr, "Unexpected search result `%s' received!\n", got);
      GNUNET_break (0);
    }
    GNUNET_free (got);
    break;
  case GNUNET_FS_STATUS_SEARCH_ERROR:
    FPRINTF (stderr, "Error searching file: %s\n",
             event->value.search.specifics.error.message);
    if (sks_search == event->value.search.sc)
      GNUNET_SCHEDULER_add_continuation (&abort_sks_search_task, NULL,
                                         GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    else if (ksk_search == event->value.search.sc)
      GNUNET_SCHEDULER_add_continuation (&abort_ksk_search_task, NULL,
                                         GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    else
      GNUNET_break (0);
    break;
  case GNUNET_FS_STATUS_SEARCH_START:
    FPRINTF (stderr, "Search %s started\n", event->value.search.pctx);
    GNUNET_assert ((NULL == event->value.search.cctx) ||
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
    FPRINTF (stderr, "%s",  "Search result stopped\n");
    return NULL;
  case GNUNET_FS_STATUS_SEARCH_STOPPED:
    FPRINTF (stderr, "%s",  "Search stopped\n");
    return NULL;
  default:
    FPRINTF (stderr, "Unexpected event: %d\n", event->status);
    break;
  }
  return event->value.search.cctx;
}


static void
publish_cont (void *cls, const struct GNUNET_FS_Uri *ksk_uri, const char *emsg)
{
  char *msg;
  struct GNUNET_FS_Uri *sks_uri;
  char sbuf[1024];
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;

  if (NULL != emsg)
  {
    FPRINTF (stderr, "Error publishing ksk: %s\n", emsg);
    err = 1;
    GNUNET_FS_stop (fs);
    return;
  }
  FPRINTF (stderr, "%s",  "Published ksk\n");
  GNUNET_CRYPTO_hash_to_enc (&nsid, &enc);
  GNUNET_snprintf (sbuf, sizeof (sbuf), "gnunet://fs/sks/%s/this", &enc);
  sks_uri = GNUNET_FS_uri_parse (sbuf, &msg);
  if (NULL == sks_uri)
  {
    FPRINTF (stderr, "failed to parse URI `%s': %s\n", sbuf, msg);
    err = 1;
    GNUNET_FS_stop (fs);
    GNUNET_free_non_null (msg);
    return;
  }
  FPRINTF (stderr, "%s",  "Starting searches\n");
  ksk_search =
      GNUNET_FS_search_start (fs, ksk_uri, 1, GNUNET_FS_SEARCH_OPTION_NONE,
                              "ksk_search");
  sks_search =
      GNUNET_FS_search_start (fs, sks_uri, 1, GNUNET_FS_SEARCH_OPTION_NONE,
                              "sks_search");
  GNUNET_FS_uri_destroy (sks_uri);
}


static void
sks_cont (void *cls, const struct GNUNET_FS_Uri *uri, const char *emsg)
{
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_FS_Uri *ksk_uri;
  char *msg;
  struct GNUNET_FS_BlockOptions bo;
  char *suri;

  if (NULL == uri)
  {
    fprintf (stderr, "Error publishing sks: %s\n", emsg);
    err = 1;
    GNUNET_FS_stop (fs);
    return;
  }
  FPRINTF (stderr, "%s",  "Published sks\n");
  meta = GNUNET_CONTAINER_meta_data_create ();
  msg = NULL;
  GNUNET_asprintf (&suri, "gnunet://fs/ksk/ns-search%d", phase);
  ksk_uri = GNUNET_FS_uri_parse (suri, &msg);
  GNUNET_free (suri);
  GNUNET_assert (NULL == msg);
  ksk_expect_uri = GNUNET_FS_uri_dup (uri);
  bo.content_priority = 1;
  bo.anonymity_level = 1;
  bo.replication_level = 0;
  bo.expiration_time =
      GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES);
  GNUNET_FS_publish_ksk (fs, ksk_uri, meta, uri, &bo,
                         GNUNET_FS_PUBLISH_OPTION_NONE, &publish_cont, NULL);
  GNUNET_FS_uri_destroy (ksk_uri);
  GNUNET_CONTAINER_meta_data_destroy (meta);
}


static void
adv_cont (void *cls, const struct GNUNET_FS_Uri *uri, const char *emsg)
{
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_FS_Namespace *ns;
  struct GNUNET_FS_BlockOptions bo;

  if (NULL != emsg)
  {
    FPRINTF (stderr, "Error advertising: %s\n", emsg);
    err = 1;
    GNUNET_FS_stop (fs);
    return;
  }
  FPRINTF (stderr, "%s",  "Created an advertising\n");
  ns = GNUNET_FS_namespace_create (fs, "testNamespace");
  GNUNET_assert (NULL != ns);
  meta = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_assert (NULL == emsg);
  sks_expect_uri = GNUNET_FS_uri_dup (uri);
  bo.content_priority = 1;
  bo.anonymity_level = 1;
  bo.replication_level = 0;
  bo.expiration_time =
      GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES);
  GNUNET_FS_publish_sks (fs, ns, "this", "next", meta, uri,     /* FIXME: this is non-sense (use CHK URI!?) */
                         &bo, GNUNET_FS_PUBLISH_OPTION_NONE, &sks_cont, NULL);
  GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_FS_namespace_delete (ns, GNUNET_NO);
}


static void
ns_iterator (void *cls, const char *name, const struct GNUNET_HashCode * id)
{
  int *ok = cls;

  FPRINTF (stderr, "Namespace in the list: %s\n", name);
  if (0 != strcmp (name, "testNamespace"))
    return;
  *ok = GNUNET_YES;
  nsid = *id;
}

static void
testCreatedNamespace (struct GNUNET_FS_Namespace *ns)
{
  struct GNUNET_FS_BlockOptions bo;
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_FS_Uri *ksk_uri;
  int ok;
  char *uri;

  FPRINTF (stderr, "%s",  "Listing namespaces\n");
  ok = GNUNET_NO;
  GNUNET_FS_namespace_list (fs, &ns_iterator, &ok);
  if (GNUNET_NO == ok)
  {
    FPRINTF (stderr, "%s",  "namespace_list failed to find namespace!\n");
    GNUNET_FS_namespace_delete (ns, GNUNET_YES);
    GNUNET_FS_stop (fs);
    err = 1;
    return;
  }
  FPRINTF (stderr, "%s",  "Creating an advertising\n");
  meta = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_asprintf (&uri, "gnunet://fs/ksk/testnsa%d", phase);
  ksk_uri = GNUNET_FS_uri_parse (uri, NULL);
  GNUNET_free (uri);
  bo.content_priority = 1;
  bo.anonymity_level = 1;
  bo.replication_level = 0;
  bo.expiration_time =
      GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES);
  GNUNET_FS_namespace_advertise (fs, ksk_uri, ns, meta, &bo, "root", &adv_cont,
                                 NULL);
  GNUNET_FS_uri_destroy (ksk_uri);
  GNUNET_FS_namespace_delete (ns, GNUNET_NO);
  GNUNET_CONTAINER_meta_data_destroy (meta);
}

static void
do_ncc_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  FPRINTF (stderr, "%s",  "Asynchronous NS creation timed out\n");
  kill_ncc_task = GNUNET_SCHEDULER_NO_TASK;
  if (NULL == ncc)
    return;
  GNUNET_FS_namespace_create_stop (ncc);
  ncc = NULL;
  err = 1;
}

static void
ns_created (void *cls, struct GNUNET_FS_Namespace *ns, const char *emsg)
{
  if (GNUNET_SCHEDULER_NO_TASK != kill_ncc_task)
    GNUNET_SCHEDULER_cancel (kill_ncc_task);
  kill_ncc_task = GNUNET_SCHEDULER_NO_TASK;
  if (NULL == ns)
  {
    FPRINTF (stderr, "Asynchronous NS creation failed: %s\n", emsg);
    err = 1;
    return;
  }

  FPRINTF (stderr, "%s",  "Namespace created asynchronously\n");
  testCreatedNamespace (ns);
}

static void
testNamespace ()
{
  struct GNUNET_FS_Namespace *ns;

  FPRINTF (stderr, "%s",  "Testing synchronous namespace creation\n");
  ns = GNUNET_FS_namespace_create (fs, "testNamespace");
  GNUNET_assert (NULL != ns);
  testCreatedNamespace (ns);

  kill_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES, &do_timeout,
                                    NULL);
}


static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  config = cfg;
  fs = GNUNET_FS_start (cfg, "test-fs-namespace", &progress_cb, NULL,
                        GNUNET_FS_FLAGS_NONE, GNUNET_FS_OPTIONS_END);
  phase = 0;
  testNamespace ();
}


int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test-fs-namespace",
				    "test_fs_namespace_data.conf",
				    &run, NULL))
    return 1;
  return err;
}


/* end of test_fs_namespace.c */
