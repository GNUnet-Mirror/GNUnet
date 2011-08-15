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
 * @file applications/fs/fsui/recursive_download_test.c
 * @brief testcase for fsui recursive upload-download
 * @author Christian Grothoff
 * @author Heikki Lindholm
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"

#define DEBUG_VERBOSE GNUNET_NO

#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; }

#define FILESIZE (1024 * 1024 * 2)
/* depth-first directory tree d=dir f=file .=end of level*/
#define DIRECTORY_TREE_SPEC "dddf.f.d"

static struct GNUNET_GE_Context *ectx;

static int download_done;

static char *
makeName (unsigned int i)
{
  char *fn;

  fn = GNUNET_malloc (strlen
                      ("/tmp/gnunet-fsui-recursive_download_test/FSUITEST") +
                      15);
  GNUNET_snprintf (fn,
                   strlen
                   ("/tmp/gnunet-fsui-recursive_download_test/FSUITEST") + 15,
                   "/tmp/gnunet-fsui-recursive_download_test/FSUITEST%u/", i);
  return fn;
}

static int
makeHierarchyHelper (const char *current, const char *tree, int index,
                     int check)
{
  unsigned int fi, i;
  int done;
  char *s, *buf;

  fi = 0;
  done = 0;
  while (!done && tree[index] != '\0')
  {
    s = GNUNET_malloc (strlen (current) + strlen (DIR_SEPARATOR_STR) + 14);
    GNUNET_snprintf (s, strlen (current) + strlen (DIR_SEPARATOR_STR) + 14,
                     "%s%s%u", current, DIR_SEPARATOR_STR, fi);
    switch (tree[index++])
    {
    case 'd':
      if (check)
      {
        if (GNUNET_disk_directory_test (NULL, s) == GNUNET_NO)
        {
          index = -1;
          done = 1;
        }
      }
      else
      {
        GNUNET_disk_directory_create (NULL, s);
      }
      if (!done)
        index = makeHierarchyHelper (s, tree, index, check);
      break;
    case 'f':
      if (check)
      {
        /* TODO: compare file contents */
        if (GNUNET_disk_directory_test (NULL, s) != GNUNET_NO)
        {
          index = -1;
          done = 1;
        }
      }
      else
      {
        buf = GNUNET_malloc (FILESIZE);
        for (i = 0; i < FILESIZE; i++)
          buf[i] = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 256);
        GNUNET_disk_file_write (ectx, s, buf, FILESIZE, "600");
        GNUNET_free (buf);
      }
      break;
    case '.':
      done = 1;
      break;
    default:
      break;
    }
    GNUNET_free (s);
    fi++;
  }
  return index;
}

static char *
makeHierarchy (unsigned int i, const char *tree)
{
  char *fn;

  fn = makeName (i);
  makeHierarchyHelper (fn, tree, 0, 0);
  return fn;
}

static int
checkHierarchy (unsigned int i, const char *tree)
{
  char *fn;
  int res;

  fn = makeName (i);
  if (GNUNET_disk_directory_test (NULL, fn) != GNUNET_YES)
  {
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  res = ((makeHierarchyHelper (fn, tree, 0, 1) == -1) ?
         GNUNET_SYSERR : GNUNET_OK);
  GNUNET_free (fn);
  return res;
}


static enum GNUNET_FSUI_EventType lastEvent;
static enum GNUNET_FSUI_EventType waitForEvent;
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
    download = event->data.DownloadResumed.dc.pos;
    break;
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
    printf ("Upload of `%s' complete.\n", event->data.UploadCompleted.filename);
#endif
    break;
  case GNUNET_FSUI_download_completed:
#if DEBUG_VERBOSE
    printf ("Download of `%s' complete.\n",
            event->data.DownloadCompleted.filename);
#endif
    if (checkHierarchy (43, DIRECTORY_TREE_SPEC) == GNUNET_OK)
      download_done = 1;
#if DEBUG_VERBOSE
    else
      printf ("Hierarchy check not successful yet...\n");
#endif
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
    fprintf (stderr, "Error unindexing: %s\n",
             event->data.UnindexError.message);
    break;
  case GNUNET_FSUI_upload_error:
    fprintf (stderr, "Error uploading: %s\n", event->data.UploadError.message);
    break;
  case GNUNET_FSUI_download_error:
    fprintf (stderr, "Error downloading: %s\n",
             event->data.DownloadError.message);
    break;
  case GNUNET_FSUI_download_aborted:
#if DEBUG_VERBOSE
    printf ("Received download aborted event.\n");
#endif
    break;
  case GNUNET_FSUI_unindex_suspended:
  case GNUNET_FSUI_upload_suspended:
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


#define START_DAEMON 1

int
main (int argc, char *argv[])
{
#if START_DAEMON
  struct GNUNET_OS_Process *daemon;
#endif
  int ok;
  char *fn = NULL;
  char *fn43 = NULL;

  char *keywords[] = {
    "down_foo",
    "down_bar",
  };
  int prog;
  struct GNUNET_MetaData *meta = NULL;
  struct GNUNET_ECRS_URI *kuri = NULL;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_FSUI_UploadList *upload = NULL;

  ok = GNUNET_YES;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
  {
    GNUNET_GC_free (cfg);
    return -1;
  }
  fprintf (stderr, "Setup...\n");
#if START_DAEMON
  GNUNET_disk_directory_remove (NULL,
                                "/tmp/gnunet-fsui-recursive_download_test/");
  daemon = GNUNET_daemon_start (NULL, cfg, "peer.conf", GNUNET_NO);
  GNUNET_GE_ASSERT (NULL, daemon != NULL);
  CHECK (GNUNET_OK ==
         GNUNET_wait_for_daemon_running (NULL, cfg, 30 * GNUNET_CRON_SECONDS));
  GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);        /* give apps time to start */
  /* ACTUAL TEST CODE */
#endif
  ctx = GNUNET_FSUI_start (NULL,
                           cfg, "fsuirecursive_download_test", 32, GNUNET_YES,
                           &eventCallback, NULL);
  CHECK (ctx != NULL);
  fn = makeHierarchy (42, DIRECTORY_TREE_SPEC);
  meta = GNUNET_meta_data_create ();
  kuri =
      GNUNET_ECRS_keyword_command_line_to_uri (ectx, 2,
                                               (const char **) keywords);
  fprintf (stderr, "Uploading...\n");
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
  upload = NULL;
  CHECK (upURI != NULL);

  fprintf (stderr, "Downloading...\n");
  waitForEvent = GNUNET_FSUI_download_completed;
  fn43 = makeName (43);
  download = GNUNET_FSUI_download_start (ctx,
                                         0,
                                         GNUNET_YES,
                                         upURI, meta, fn43, NULL, NULL);
  CHECK (download != NULL);
  GNUNET_free (fn43);
  fn43 = NULL;
  prog = 0;
  while (!download_done)
  {
    prog++;
    CHECK (prog < 5000);
    GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
    if (GNUNET_shutdown_test () == GNUNET_YES)
      break;
  }
FAILURE:
  fprintf (stderr, "Cleanup...\n");
  if (meta != NULL)
    GNUNET_meta_data_destroy (meta);
  if (ctx != NULL)
  {
    if (download != NULL)
      GNUNET_FSUI_download_stop (download);
    GNUNET_FSUI_stop (ctx);
  }
  if (fn != NULL)
  {
    GNUNET_disk_directory_remove (NULL, fn);
    GNUNET_free (fn);
  }
  if (kuri != NULL)
    GNUNET_ECRS_uri_destroy (kuri);
  fn43 = makeName (43);
  GNUNET_disk_directory_remove (NULL, fn43);
  GNUNET_free (fn43);
  if (upURI != NULL)
    GNUNET_ECRS_uri_destroy (upURI);

#if START_DAEMON
  GNUNET_GE_BREAK (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));
  GNUNET_OS_process_close (daemon);
  daemon = NULL;
#endif
  GNUNET_GC_free (cfg);
  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of recursive_download_test.c */
