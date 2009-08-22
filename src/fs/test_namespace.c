/*
     This file is part of GNUnet.
     (C) 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/namespacetest.c
 * @brief Test for namespace.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "ecrs.h"

#define ABORT() { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); return 1; }
#define CHECK(c) { do { if (!(c)) ABORT(); } while(0); }

#define CHECKNAME "gnunet-namespace-test"

static struct GNUNET_GC_Configuration *cfg;

static int match;

static int
spcb (const GNUNET_ECRS_FileInfo * fi,
      const GNUNET_HashCode * key, int isRoot, void *closure)
{
  struct GNUNET_ECRS_URI *want = closure;

  if (GNUNET_ECRS_uri_test_equal (want, fi->uri))
    match = 1;
  else
    fprintf (stderr,
             "Namespace search returned unexpected result: \nHAVE: %s\nWANT: %s...\n",
             GNUNET_ECRS_uri_to_string (fi->uri),
             GNUNET_ECRS_uri_to_string (want));
  return GNUNET_OK;
}

static int
tt (void *unused)
{
  if (match == 1)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

static int
testNamespace ()
{
  GNUNET_HashCode pid;
  struct GNUNET_ECRS_URI *adv;
  struct GNUNET_ECRS_URI *advURI;
  struct GNUNET_ECRS_URI *rootURI;
  struct GNUNET_MetaData *meta;

  meta = GNUNET_meta_data_create ();
  adv = GNUNET_ECRS_keyword_string_to_uri (NULL, "testNamespace");
  rootURI =
    GNUNET_ECRS_namespace_create (NULL,
                                  cfg,
                                  meta,
                                  0, 0,
                                  GNUNET_get_time () +
                                  15 * GNUNET_CRON_MINUTES, adv, "root");
  CHECK (NULL != rootURI);
  GNUNET_ECRS_uri_get_namespace_from_sks (rootURI, &pid);
  advURI = GNUNET_ECRS_namespace_add_content (NULL, cfg, &pid, 1,       /* anonymity */
                                              1000,     /* priority */
                                              5 * GNUNET_CRON_MINUTES +
                                              GNUNET_get_time (),
                                              "this", "next", rootURI, meta);
  CHECK (NULL != advURI);
  fprintf (stderr, "Starting namespace search...\n");
  CHECK (GNUNET_OK == GNUNET_ECRS_search (NULL,
                                          cfg,
                                          advURI, 1, &spcb, rootURI, &tt,
                                          NULL));
  fprintf (stderr, "Completed namespace search...\n");
  CHECK (GNUNET_OK == GNUNET_ECRS_namespace_delete (NULL, cfg, &pid));
  CHECK (GNUNET_SYSERR == GNUNET_ECRS_namespace_delete (NULL, cfg, &pid));
  GNUNET_meta_data_destroy (meta);
  GNUNET_ECRS_uri_destroy (rootURI);
  GNUNET_ECRS_uri_destroy (advURI);
  CHECK (match == 1);
  return 0;
}

int
main (int argc, char *argv[])
{
  pid_t daemon;
  int failureCount = 0;

  GNUNET_disable_entropy_gathering ();
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  daemon = GNUNET_daemon_start (NULL, cfg, "peer.conf", GNUNET_NO);
  GNUNET_GE_ASSERT (NULL, daemon > 0);
  if (GNUNET_OK !=
      GNUNET_wait_for_daemon_running (NULL, cfg, 60 * GNUNET_CRON_SECONDS))
    {
      failureCount++;
    }
  else
    {
      GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);
      failureCount += testNamespace ();
    }
  GNUNET_GE_ASSERT (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));

  return (failureCount == 0) ? 0 : 1;
}

/* end of namespacetest.c */
