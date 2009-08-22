/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/search_persistence_test.c
 * @brief testcase for fsui download persistence for search
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"

#define DEBUG_VERBOSE GNUNET_NO

#define UPLOAD_PREFIX "/tmp/gnunet-fsui-search_persistence_test"

#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; }

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_FSUI_Context *ctx;
static struct GNUNET_FSUI_SearchList *search;
static int have_error;

static void *
eventCallback (void *cls, const GNUNET_FSUI_Event * event)
{
  switch (event->type)
    {
    case GNUNET_FSUI_search_suspended:
      search = NULL;
      break;
    case GNUNET_FSUI_search_resumed:
#if DEBUG_VERBOSE
      printf ("Search resuming\n");
#endif
      search = event->data.SearchResumed.sc.pos;
      break;
    case GNUNET_FSUI_search_result:
#if DEBUG_VERBOSE
      printf ("Received search result\n");
#endif
      break;
    case GNUNET_FSUI_upload_progress:
#if DEBUG_VERBOSE
      printf ("Upload is progressing (%llu/%llu)...\n",
              event->data.UploadProgress.completed,
              event->data.UploadProgress.total);
#endif
      break;
    case GNUNET_FSUI_upload_completed:
#if DEBUG_VERBOSE
      printf ("Upload complete.\n");
#endif
      break;
    case GNUNET_FSUI_unindex_progress:
#if DEBUG_VERBOSE
      printf ("Unindex is progressing (%llu/%llu)...\n",
              event->data.UnindexProgress.completed,
              event->data.UnindexProgress.total);
#endif
      break;
    case GNUNET_FSUI_unindex_completed:
#if DEBUG_VERBOSE
      printf ("Unindex complete.\n");
#endif
      break;
    case GNUNET_FSUI_unindex_error:
    case GNUNET_FSUI_upload_error:
    case GNUNET_FSUI_download_error:
      fprintf (stderr, "Received ERROR: %d\n", event->type);
      GNUNET_GE_BREAK (ectx, 0);
      break;
    case GNUNET_FSUI_download_aborted:
#if DEBUG_VERBOSE
      printf ("Received download aborted event.\n");
#endif
      break;
    case GNUNET_FSUI_unindex_suspended:
    case GNUNET_FSUI_upload_suspended:
#if DEBUG_VERBOSE
      fprintf (stderr, "Received SUSPENDING: %d\n", event->type);
#endif
      break;
    case GNUNET_FSUI_upload_started:
    case GNUNET_FSUI_upload_stopped:
    case GNUNET_FSUI_search_started:
    case GNUNET_FSUI_search_aborted:
    case GNUNET_FSUI_search_stopped:
    case GNUNET_FSUI_search_update:
    case GNUNET_FSUI_unindex_started:
    case GNUNET_FSUI_unindex_stopped:
      break;
    default:
      printf ("Unexpected event: %d\n", event->type);
      break;
    }
  return NULL;
}

#define FILESIZE (1024)

#define START_DAEMON 1

int
main (int argc, char *argv[])
{
#if START_DAEMON
  pid_t daemon;
#endif
  int ok;
  struct GNUNET_ECRS_URI *uri = NULL;
  char *keywords[] = {
    "down_foo",
    "down_bar",
  };
  char keyword[40];
  int prog;
  struct GNUNET_GC_Configuration *cfg;
  int suspendRestart = 0;


  ok = GNUNET_YES;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#if START_DAEMON
  daemon = GNUNET_daemon_start (NULL, cfg, "peer.conf", GNUNET_NO);
  GNUNET_GE_ASSERT (NULL, daemon > 0);
  CHECK (GNUNET_OK ==
         GNUNET_wait_for_daemon_running (NULL, cfg,
                                         30 * GNUNET_CRON_SECONDS));
  GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);        /* give apps time to start */
  /* ACTUAL TEST CODE */
#endif
  ctx = GNUNET_FSUI_start (NULL,
                           cfg, "search_persistence_test", 32, GNUNET_YES,
                           &eventCallback, NULL);
  CHECK (ctx != NULL);
  GNUNET_snprintf (keyword, 40, "+%s +%s", keywords[0], keywords[1]);
  uri = GNUNET_ECRS_keyword_string_to_uri (ectx, keyword);
  search = GNUNET_FSUI_search_start (ctx, 0, uri);
  CHECK (search != NULL);
  prog = 0;
  suspendRestart = 10;
  while (prog < 100)
    {
      prog++;
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if ((suspendRestart > 0)
          && (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 10) == 0))
        {
#if 1
#if DEBUG_VERBOSE
          printf ("Testing FSUI suspend-resume\n");
#endif
          GNUNET_FSUI_stop (ctx);       /* download possibly incomplete
                                           at this point, thus testing resume */
          CHECK (search == NULL);
          ctx = GNUNET_FSUI_start (NULL,
                                   cfg,
                                   "search_persistence_test", 32, GNUNET_YES,
                                   &eventCallback, NULL);
#if DEBUG_VERBOSE
          printf ("Resumed...\n");
#endif
#endif
          suspendRestart--;
        }
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  GNUNET_FSUI_search_abort (search);
  GNUNET_FSUI_search_stop (search);
  search = NULL;
  /* END OF TEST CODE */
FAILURE:
  if (ctx != NULL)
    GNUNET_FSUI_stop (ctx);
  if (uri != NULL)
    GNUNET_ECRS_uri_destroy (uri);

#if START_DAEMON
  GNUNET_GE_BREAK (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));
#endif
  GNUNET_GC_free (cfg);
  if (have_error)
    ok = GNUNET_NO;
  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of search_persistence_test.c */
