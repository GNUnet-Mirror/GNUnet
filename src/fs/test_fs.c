/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/basic_fsui_test.c
 * @brief testcase for fsui (upload-search-download-unindex)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"

#define DEBUG_VERBOSE GNUNET_EXTRA_LOGGING

#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GNUNET_GE_BREAK(NULL, 0); goto FAILURE; }

static char *
makeName (unsigned int i)
{
  char *fn;

  fn = GNUNET_malloc (strlen ("/tmp/gnunet-basic_fsui_test/BASIC_FSUI_TEST") +
                      14);
  GNUNET_snprintf (fn,
                   strlen ("/tmp/gnunet-basic_fsui_test/BASIC_FSUI_TEST") + 14,
                   "/tmp/gnunet-basic_fsui_test/BASIC_FSUI_TEST%u", i);
  GNUNET_disk_directory_create_for_file (NULL, fn);
  return fn;
}

static enum GNUNET_FSUI_EventType lastEvent;

static struct GNUNET_MetaData *search_meta;

static struct GNUNET_ECRS_URI *search_uri;

static struct GNUNET_FSUI_Context *ctx;

static void *
eventCallback (void *cls, const GNUNET_FSUI_Event * event)
{
  static char unused;

  switch (event->type)
  {
  case GNUNET_FSUI_search_resumed:
  case GNUNET_FSUI_download_resumed:
  case GNUNET_FSUI_upload_resumed:
  case GNUNET_FSUI_unindex_resumed:
    return &unused;
  case GNUNET_FSUI_search_result:
#if DEBUG_VERBOSE
    printf ("Received search result\n");
#endif
    search_uri = GNUNET_ECRS_uri_duplicate (event->data.SearchResult.fi.uri);
    search_meta = GNUNET_meta_data_duplicate (event->data.SearchResult.fi.meta);
    break;
  case GNUNET_FSUI_upload_completed:
#if DEBUG_VERBOSE
    printf ("Upload complete.\n");
#endif
    break;
  case GNUNET_FSUI_download_completed:
#if DEBUG_VERBOSE
    printf ("Download complete.\n");
#endif
    break;
  case GNUNET_FSUI_unindex_completed:
#if DEBUG_VERBOSE
    printf ("Unindex complete.\n");
#endif
    break;
  default:
    break;
  }
  lastEvent = event->type;
  return NULL;
}

#define START_DAEMON 1

int
main (int argc, char *argv[])
{
#if START_DAEMON
  struct GNUNET_OS_Process *daemon;
#endif
  int ok;
  struct GNUNET_ECRS_URI *uri;
  char *filename = NULL;

  char *keywords[] = {
    "fsui_foo",
    "fsui_bar",
  };
  char keyword[40];
  char *fn;
  int prog;
  struct GNUNET_MetaData *meta;
  struct GNUNET_ECRS_URI *kuri;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_FSUI_UploadList *upload = NULL;
  struct GNUNET_FSUI_SearchList *search = NULL;
  struct GNUNET_FSUI_UnindexList *unindex = NULL;
  struct GNUNET_FSUI_DownloadList *download = NULL;

  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
  {
    GNUNET_GC_free (cfg);
    return -1;
  }
#if START_DAEMON
  daemon = GNUNET_daemon_start (NULL, cfg, "peer.conf", GNUNET_NO);
  GNUNET_GE_ASSERT (NULL, daemon != NULL);
  CHECK (GNUNET_OK ==
         GNUNET_wait_for_daemon_running (NULL, cfg, 60 * GNUNET_CRON_SECONDS));
#endif
  GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);        /* give apps time to start */
  ok = GNUNET_YES;

  /* ACTUAL TEST CODE */
  ctx = GNUNET_FSUI_start (NULL, cfg, "basic_fsui_test", 32,    /* thread pool size */
                           GNUNET_NO,   /* no resume */
                           &eventCallback, NULL);
  CHECK (ctx != NULL);
  filename = makeName (42);
  GNUNET_disk_file_write (NULL, filename, "foo bar test!",
                          strlen ("foo bar test!"), "600");
  meta = GNUNET_meta_data_create ();
  kuri =
      GNUNET_ECRS_keyword_command_line_to_uri (NULL, 2,
                                               (const char **) keywords);
  /* upload */
  upload = GNUNET_FSUI_upload_start (ctx, filename, (GNUNET_FSUI_DirectoryScanCallback) & GNUNET_disk_directory_scan, NULL, 0,  /* anonymity */
                                     0, /* priority */
                                     GNUNET_YES, GNUNET_NO, GNUNET_NO,
                                     GNUNET_get_time () + 5 * GNUNET_CRON_HOURS,
                                     meta, kuri, kuri);
  CHECK (upload != NULL);
  GNUNET_ECRS_uri_destroy (kuri);
  GNUNET_meta_data_destroy (meta);
  prog = 0;
  while (lastEvent != GNUNET_FSUI_upload_completed)
  {
    prog++;
    CHECK (prog < 10000) GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
    if (GNUNET_shutdown_test () == GNUNET_YES)
      break;
  }

  /* search */
  GNUNET_snprintf (keyword, 40, "+%s +%s", keywords[0], keywords[1]);
  uri = GNUNET_ECRS_keyword_string_to_uri (NULL, keyword);
  search = GNUNET_FSUI_search_start (ctx, 0, uri);
  GNUNET_ECRS_uri_destroy (uri);
  CHECK (search != NULL);
  prog = 0;
  while (lastEvent != GNUNET_FSUI_search_result)
  {
    prog++;
    CHECK (prog < 10000);
    GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
    if (GNUNET_shutdown_test () == GNUNET_YES)
      break;
  }
  GNUNET_FSUI_search_abort (search);
  GNUNET_FSUI_search_stop (search);

  /* download */
  fn = makeName (43);
  download =
      GNUNET_FSUI_download_start (ctx, 0, GNUNET_NO, search_uri, search_meta,
                                  fn, NULL, NULL);
  GNUNET_free (fn);
  prog = 0;
  while (lastEvent != GNUNET_FSUI_download_completed)
  {
    prog++;
    CHECK (prog < 10000);
    GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
    if (GNUNET_shutdown_test () == GNUNET_YES)
      break;
  }
  GNUNET_FSUI_download_stop (download);
  download = NULL;
  GNUNET_ECRS_uri_destroy (search_uri);
  GNUNET_meta_data_destroy (search_meta);
  /* unindex */
  unindex = GNUNET_FSUI_unindex_start (ctx, filename);
  prog = 0;
  while (lastEvent != GNUNET_FSUI_unindex_completed)
  {
    prog++;
    CHECK (prog < 10000);
    GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
    if (GNUNET_shutdown_test () == GNUNET_YES)
      break;
  }
  if (lastEvent != GNUNET_FSUI_unindex_completed)
    GNUNET_FSUI_unindex_abort (unindex);
  GNUNET_FSUI_unindex_stop (unindex);


  /* END OF TEST CODE */
FAILURE:
  if (ctx != NULL)
    GNUNET_FSUI_stop (ctx);
  if (filename != NULL)
  {
    UNLINK (filename);
    GNUNET_free (filename);
  }
  if (download != NULL)
  {
    GNUNET_FSUI_download_abort (download);
    GNUNET_FSUI_download_stop (download);
  }
  filename = makeName (43);
  /* TODO: verify file 'filename(42)' == file 'filename(43)' */
  UNLINK (filename);
  GNUNET_free (filename);

#if START_DAEMON
  GNUNET_GE_ASSERT (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));
  GNUNET_OS_process_close (daemon);
#endif
  GNUNET_GC_free (cfg);

  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of basic_fsui_test.c */
