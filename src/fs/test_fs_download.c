/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/download_persistence_test.c
 * @brief testcase for fsui download persistence (upload-download)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"

#define DEBUG_VERBOSE GNUNET_NO

#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; }

static volatile int suspendRestart = 0;

static struct GNUNET_GE_Context *ectx;

static char *
makeName (unsigned int i)
{
  char *fn;

  fn =
    GNUNET_malloc (strlen
                   ("/tmp/gnunet-fsui-download_persistence_test/FSUITEST") +
                   14);
  GNUNET_snprintf (fn,
                   strlen
                   ("/tmp/gnunet-fsui-download_persistence_test/FSUITEST") +
                   14,
                   "/tmp/gnunet-fsui-download_persistence_test/FSUITEST%u",
                   i);
  GNUNET_disk_directory_create_for_file (NULL, fn);
  return fn;
}

static volatile enum GNUNET_FSUI_EventType lastEvent;
static volatile enum GNUNET_FSUI_EventType waitForEvent;
static volatile int download_done;
static struct GNUNET_FSUI_Context *ctx;
static struct GNUNET_ECRS_URI *upURI;
static struct GNUNET_FSUI_DownloadList *download;

static void *
eventCallback (void *cls, const GNUNET_FSUI_Event * event)
{
  switch (event->type)
    {
    case GNUNET_FSUI_download_suspended:
      download = NULL;
      break;
    case GNUNET_FSUI_download_resumed:
#if DEBUG_VERBOSE
      printf ("Download resuming\n");
#endif
      download = event->data.DownloadResumed.dc.pos;
      break;
    case GNUNET_FSUI_upload_progress:
#if DEBUG_VERBOSE > 1
      printf ("Upload is progressing (%llu/%llu)...\n",
              event->data.UploadProgress.completed,
              event->data.UploadProgress.total);
#endif
      break;
    case GNUNET_FSUI_upload_completed:
      upURI = GNUNET_ECRS_uri_duplicate (event->data.UploadCompleted.uri);
#if DEBUG_VERBOSE
      printf ("Upload complete.\n");
#endif
      break;
    case GNUNET_FSUI_download_completed:
#if DEBUG_VERBOSE
      printf ("Download complete.\n");
#endif
      download_done = 1;
      break;
    case GNUNET_FSUI_download_progress:
#if DEBUG_VERBOSE > 1
      printf ("Download is progressing (%llu/%llu)...\n",
              event->data.DownloadProgress.completed,
              event->data.DownloadProgress.total);
#endif
      break;
    case GNUNET_FSUI_unindex_progress:
#if DEBUG_VERBOSE > 1
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
    case GNUNET_FSUI_download_started:
    case GNUNET_FSUI_download_stopped:
    case GNUNET_FSUI_unindex_started:
    case GNUNET_FSUI_unindex_stopped:
      break;
    default:
      printf ("Unexpected event: %d\n", event->type);
      break;
    }
  if (lastEvent == waitForEvent)
    return NULL;                /* ignore all other events */
  lastEvent = event->type;
  return NULL;
}

#define FILESIZE (1024 * 1024 * 2)

#define START_DAEMON 1

int
main (int argc, char *argv[])
{
#if START_DAEMON
  pid_t daemon;
#endif
  int ok;
  int i;
  char *fn = NULL;
  char *keywords[] = {
    "down_foo",
    "down_bar",
  };
  int prog;
  char *buf;
  struct GNUNET_MetaData *meta = NULL;
  struct GNUNET_ECRS_URI *kuri = NULL;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_FSUI_UnindexList *unindex = NULL;
  struct GNUNET_FSUI_UploadList *upload = NULL;

  ok = GNUNET_YES;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#if START_DAEMON
  GNUNET_disk_directory_remove (NULL,
                                "/tmp/gnunet-fsui-download_persistence_test/");
  daemon = GNUNET_daemon_start (NULL, cfg, "peer.conf", GNUNET_NO);
  GNUNET_GE_ASSERT (NULL, daemon > 0);
  CHECK (GNUNET_OK ==
         GNUNET_wait_for_daemon_running (NULL, cfg,
                                         30 * GNUNET_CRON_SECONDS));
  GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);        /* give apps time to start */
  /* ACTUAL TEST CODE */
#endif
  ctx = GNUNET_FSUI_start (NULL,
                           cfg, "fsuidownload_persistence_test", 32,
                           GNUNET_YES, &eventCallback, NULL);
  CHECK (ctx != NULL);

  /* upload */
  fn = makeName (42);
  buf = GNUNET_malloc (FILESIZE);
  for (i = 0; i < FILESIZE; i++)
    buf[i] = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 256);
  GNUNET_disk_file_write (ectx, fn, buf, FILESIZE, "600");
  GNUNET_free (buf);
  meta = GNUNET_meta_data_create ();
  kuri =
    GNUNET_ECRS_keyword_command_line_to_uri (ectx, 2,
                                             (const char **) keywords);
  waitForEvent = GNUNET_FSUI_upload_completed;
  upload = GNUNET_FSUI_upload_start (ctx,
                                     fn,
                                     (GNUNET_FSUI_DirectoryScanCallback) &
                                     GNUNET_disk_directory_scan, NULL, 0, 0,
                                     GNUNET_YES, GNUNET_NO, GNUNET_NO,
                                     GNUNET_get_time () +
                                     5 * GNUNET_CRON_HOURS, meta, kuri, kuri);
  CHECK (upload != NULL);
  GNUNET_ECRS_uri_destroy (kuri);
  kuri = NULL;
  prog = 0;
  while (lastEvent != GNUNET_FSUI_upload_completed)
    {
      prog++;
      CHECK (prog < 5000);
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  GNUNET_FSUI_upload_stop (upload);

  /* download */
  waitForEvent = GNUNET_FSUI_download_completed;
  GNUNET_free (fn);
  fn = makeName (43);
  download_done = 0;
  download = GNUNET_FSUI_download_start (ctx,
                                         0,
                                         GNUNET_NO,
                                         upURI, meta, fn, NULL, NULL);
  CHECK (download != NULL);
  GNUNET_free (fn);
  suspendRestart = 4;
  prog = 0;
  while (download_done == 0)
    {
      prog++;
      CHECK (prog < 1000);
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if ((suspendRestart > 0)
          && (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 4) == 0))
        {
#if 1
#if DEBUG_VERBOSE
          printf ("Testing FSUI suspend-resume\n");
#endif
          GNUNET_FSUI_stop (ctx);       /* download possibly incomplete
                                           at this point, thus testing resume */
          ctx = GNUNET_FSUI_start (NULL,
                                   cfg,
                                   "fsuidownload_persistence_test",
                                   32, GNUNET_YES, &eventCallback, NULL);
#if DEBUG_VERBOSE
          printf ("Resumed...\n");
#endif
#endif
          suspendRestart--;
        }
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  GNUNET_FSUI_download_stop (download);
  download = NULL;

  /* unindex */
  waitForEvent = GNUNET_FSUI_unindex_completed;
  fn = makeName (42);
  unindex = GNUNET_FSUI_unindex_start (ctx, fn);
  CHECK (unindex != NULL);
  prog = 0;
  while (lastEvent != GNUNET_FSUI_unindex_completed)
    {
      prog++;
      CHECK (prog < 5000);
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      CHECK (lastEvent != GNUNET_FSUI_unindex_error);
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  CHECK (lastEvent == GNUNET_FSUI_unindex_completed);
  /* END OF TEST CODE */
FAILURE:
  if (meta != NULL)
    GNUNET_meta_data_destroy (meta);
  if (ctx != NULL)
    {
      if (unindex != NULL)
        GNUNET_FSUI_unindex_stop (unindex);
      if (download != NULL)
        GNUNET_FSUI_download_stop (download);
      GNUNET_FSUI_stop (ctx);
    }
  if (fn != NULL)
    {
      UNLINK (fn);
      GNUNET_free (fn);
    }
  if (kuri != NULL)
    GNUNET_ECRS_uri_destroy (kuri);
  fn = makeName (43);
  /* TODO: verify file 'fn(42)' == file 'fn(43)' */
  UNLINK (fn);
  GNUNET_free (fn);
  if (upURI != NULL)
    GNUNET_ECRS_uri_destroy (upURI);

#if START_DAEMON
  GNUNET_GE_BREAK (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));
#endif
  GNUNET_GC_free (cfg);
  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of download_persistence_test.c */
