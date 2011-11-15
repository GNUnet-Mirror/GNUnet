/*
     This file is part of GNUnet.
     (C) 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_test_lib.c
 * @brief library routines for testing FS publishing and downloading
 *        with multiple peers; this code is limited to flat files
 *        and no keywords (those functions can be tested with
 *        single-peer setups; this is for testing routing).
 * @author Christian Grothoff
 */
#include "platform.h"
#include "fs_api.h"
#include "fs_test_lib.h"
#include "gnunet_testing_lib.h"

#define CONNECT_ATTEMPTS 4

#define CONTENT_LIFETIME GNUNET_TIME_UNIT_HOURS

/**
 * Handle for a daemon started for testing FS.
 */
struct GNUNET_FS_TestDaemon
{

  /**
   * Global configuration, only stored in first test daemon,
   * otherwise NULL.
   */
  struct GNUNET_CONFIGURATION_Handle *gcfg;

  /**
   * Handle to the file sharing context using this daemon.
   */
  struct GNUNET_FS_Handle *fs;

  /**
   * Handle to the daemon via testing.
   */
  struct GNUNET_TESTING_Daemon *daemon;

  /**
   * Note that 'group' will be the same value for all of the
   * daemons started jointly.
   */
  struct GNUNET_TESTING_PeerGroup *group;

  /**
   * Configuration for accessing this peer.
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * ID of this peer.
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Function to call when upload is done.
   */
  GNUNET_FS_TEST_UriContinuation publish_cont;

  /**
   * Closure for publish_cont.
   */
  void *publish_cont_cls;

  /**
   * Task to abort publishing (timeout).
   */
  GNUNET_SCHEDULER_TaskIdentifier publish_timeout_task;

  /**
   * Seed for file generation.
   */
  uint32_t publish_seed;

  /**
   * Context for current publishing operation.
   */
  struct GNUNET_FS_PublishContext *publish_context;

  /**
   * Result URI.
   */
  struct GNUNET_FS_Uri *publish_uri;

  /**
   * Name of the temporary file used, or NULL for none.
   */
  char *publish_tmp_file;

  /**
   * Function to call when download is done.
   */
  GNUNET_SCHEDULER_Task download_cont;

  /**
   * Closure for download_cont.
   */
  void *download_cont_cls;

  /**
   * Seed for download verification.
   */
  uint32_t download_seed;

  /**
   * Task to abort downloading (timeout).
   */
  GNUNET_SCHEDULER_TaskIdentifier download_timeout_task;

  /**
   * Context for current download operation.
   */
  struct GNUNET_FS_DownloadContext *download_context;

  /**
   * Verbosity level of the current operation.
   */
  int verbose;


};

/**
 * Check whether peers successfully shut down.
 */
static void
shutdown_callback (void *cls, const char *emsg)
{
  struct GNUNET_CONFIGURATION_Handle *gcfg = cls;

  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Shutdown of peers failed: %s\n",
                emsg);
  }
  else
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All peers successfully shut down!\n");
#endif
  }
  if (gcfg != NULL)
    GNUNET_CONFIGURATION_destroy (gcfg);
}


static void
report_uri (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_TestDaemon *daemon = cls;
  GNUNET_FS_TEST_UriContinuation cont;
  struct GNUNET_FS_Uri *uri;

  GNUNET_FS_publish_stop (daemon->publish_context);
  daemon->publish_context = NULL;
  cont = daemon->publish_cont;
  daemon->publish_cont = NULL;
  uri = daemon->publish_uri;
  cont (daemon->publish_cont_cls, uri);
  GNUNET_FS_uri_destroy (uri);
}


static void
report_success (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_TestDaemon *daemon = cls;

  GNUNET_FS_download_stop (daemon->download_context, GNUNET_YES);
  daemon->download_context = NULL;
  GNUNET_SCHEDULER_add_continuation (daemon->download_cont,
                                     daemon->download_cont_cls,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
  daemon->download_cont = NULL;
}


static void *
progress_cb (void *cls, const struct GNUNET_FS_ProgressInfo *info)
{
  struct GNUNET_FS_TestDaemon *daemon = cls;

  switch (info->status)
  {
  case GNUNET_FS_STATUS_PUBLISH_COMPLETED:
    GNUNET_SCHEDULER_cancel (daemon->publish_timeout_task);
    daemon->publish_timeout_task = GNUNET_SCHEDULER_NO_TASK;
    daemon->publish_uri =
        GNUNET_FS_uri_dup (info->value.publish.specifics.completed.chk_uri);
    GNUNET_SCHEDULER_add_continuation (&report_uri, daemon,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    break;
  case GNUNET_FS_STATUS_PUBLISH_PROGRESS:
    if (daemon->verbose)
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Publishing at %llu/%llu bytes\n",
                  (unsigned long long) info->value.publish.completed,
                  (unsigned long long) info->value.publish.size);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_PROGRESS:
    if (daemon->verbose)
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Download at %llu/%llu bytes\n",
                  (unsigned long long) info->value.download.completed,
                  (unsigned long long) info->value.download.size);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_COMPLETED:
    GNUNET_SCHEDULER_cancel (daemon->download_timeout_task);
    daemon->download_timeout_task = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_SCHEDULER_add_continuation (&report_success, daemon,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_ACTIVE:
  case GNUNET_FS_STATUS_DOWNLOAD_INACTIVE:
    break;
    /* FIXME: monitor data correctness during download progress */
    /* FIXME: do performance reports given sufficient verbosity */
    /* FIXME: advance timeout task to "immediate" on error */
  default:
    break;
  }
  return NULL;
}


struct StartContext
{
  struct GNUNET_TIME_Relative timeout;
  unsigned int total;
  unsigned int have;
  struct GNUNET_FS_TestDaemon **daemons;
  GNUNET_SCHEDULER_Task cont;
  void *cont_cls;
  struct GNUNET_TESTING_PeerGroup *group;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;
};


static void
notify_running (void *cls, const struct GNUNET_PeerIdentity *id,
                const struct GNUNET_CONFIGURATION_Handle *cfg,
                struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  struct StartContext *sctx = cls;
  unsigned int i;

  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Failed to start daemon: %s\n"),
                emsg);
    return;
  }
  i = 0;
  while (i < sctx->total)
  {
    if (GNUNET_TESTING_daemon_get (sctx->group, i) == d)
      break;
    i++;
  }
  GNUNET_assert (i < sctx->total);
  GNUNET_assert (sctx->have < sctx->total);
  GNUNET_assert (sctx->daemons[i]->cfg == NULL);
  sctx->daemons[i]->cfg = GNUNET_CONFIGURATION_dup (cfg);
  sctx->daemons[i]->group = sctx->group;
  sctx->daemons[i]->daemon = d;
  sctx->daemons[i]->id = *id;
  sctx->have++;
  if (sctx->have == sctx->total)
  {
    GNUNET_SCHEDULER_add_continuation (sctx->cont, sctx->cont_cls,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    sctx->daemons[0]->gcfg = sctx->cfg;
    GNUNET_SCHEDULER_cancel (sctx->timeout_task);
    for (i = 0; i < sctx->total; i++)
    {
      sctx->daemons[i]->fs =
          GNUNET_FS_start (sctx->daemons[i]->cfg, "<tester>", &progress_cb,
                           sctx->daemons[i], GNUNET_FS_FLAGS_NONE,
                           GNUNET_FS_OPTIONS_END);
    }
    GNUNET_free (sctx);
  }
}


static void
start_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct StartContext *sctx = cls;
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Timeout while trying to start daemons\n");
  GNUNET_TESTING_daemons_stop (sctx->group,
                               GNUNET_TIME_relative_multiply
                               (GNUNET_TIME_UNIT_SECONDS, 30),
                               &shutdown_callback, NULL);
  for (i = 0; i < sctx->total; i++)
  {
    if (i < sctx->have)
      GNUNET_CONFIGURATION_destroy (sctx->daemons[i]->cfg);
    GNUNET_free (sctx->daemons[i]);
    sctx->daemons[i] = NULL;
  }
  GNUNET_CONFIGURATION_destroy (sctx->cfg);
  GNUNET_SCHEDULER_add_continuation (sctx->cont, sctx->cont_cls,
                                     GNUNET_SCHEDULER_REASON_TIMEOUT);
  GNUNET_free (sctx);
}


/**
 * Start daemons for testing.
 *
 * @param template_cfg_file configuration template to use
 * @param timeout if this operation cannot be completed within the
 *                given period, call the continuation with an error code
 * @param total number of daemons to start
 * @param daemons array of 'total' entries to be initialized
 *                (array must already be allocated, will be filled)
 * @param cont function to call when done
 * @param cont_cls closure for cont
 */
void
GNUNET_FS_TEST_daemons_start (const char *template_cfg_file,
                              struct GNUNET_TIME_Relative timeout,
                              unsigned int total,
                              struct GNUNET_FS_TestDaemon **daemons,
                              GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  struct StartContext *sctx;
  unsigned int i;

  GNUNET_assert (total > 0);
  sctx = GNUNET_malloc (sizeof (struct StartContext));
  sctx->daemons = daemons;
  sctx->total = total;
  sctx->cont = cont;
  sctx->cont_cls = cont_cls;
  sctx->cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK != GNUNET_CONFIGURATION_load (sctx->cfg, template_cfg_file))
  {
    GNUNET_break (0);
    GNUNET_CONFIGURATION_destroy (sctx->cfg);
    GNUNET_free (sctx);
    GNUNET_SCHEDULER_add_continuation (cont, cont_cls,
                                       GNUNET_SCHEDULER_REASON_TIMEOUT);
    return;
  }
  for (i = 0; i < total; i++)
    daemons[i] = GNUNET_malloc (sizeof (struct GNUNET_FS_TestDaemon));
  sctx->group = GNUNET_TESTING_daemons_start (sctx->cfg, total, total,  /* Outstanding connections */
                                              total,    /* Outstanding ssh connections */
                                              timeout, NULL, NULL,
                                              &notify_running, sctx, NULL, NULL,
                                              NULL);
  sctx->timeout_task =
      GNUNET_SCHEDULER_add_delayed (timeout, &start_timeout, sctx);
}


struct GNUNET_FS_TEST_ConnectContext
{
  GNUNET_SCHEDULER_Task cont;
  void *cont_cls;
  struct GNUNET_TESTING_ConnectContext *cc;
};


/**
 * Prototype of a function that will be called whenever
 * two daemons are connected by the testing library.
 *
 * @param cls closure
 * @param first peer id for first daemon
 * @param second peer id for the second daemon
 * @param distance distance between the connected peers
 * @param first_cfg config for the first daemon
 * @param second_cfg config for the second daemon
 * @param first_daemon handle for the first daemon
 * @param second_daemon handle for the second daemon
 * @param emsg error message (NULL on success)
 */
static void
notify_connection (void *cls, const struct GNUNET_PeerIdentity *first,
                   const struct GNUNET_PeerIdentity *second, uint32_t distance,
                   const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                   const struct GNUNET_CONFIGURATION_Handle *second_cfg,
                   struct GNUNET_TESTING_Daemon *first_daemon,
                   struct GNUNET_TESTING_Daemon *second_daemon,
                   const char *emsg)
{
  struct GNUNET_FS_TEST_ConnectContext *cc = cls;

  cc->cc = NULL;
  if (emsg != NULL)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Failed to connect peers: %s\n",
                emsg);
  GNUNET_SCHEDULER_add_continuation (cc->cont, cc->cont_cls,
                                     (emsg !=
                                      NULL) ? GNUNET_SCHEDULER_REASON_TIMEOUT :
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
  GNUNET_free (cc);
}


/**
 * Connect two daemons for testing.
 *
 * @param daemon1 first daemon to connect
 * @param daemon2 second first daemon to connect
 * @param timeout if this operation cannot be completed within the
 *                given period, call the continuation with an error code
 * @param cont function to call when done
 * @param cont_cls closure for cont
 */
struct GNUNET_FS_TEST_ConnectContext *
GNUNET_FS_TEST_daemons_connect (struct GNUNET_FS_TestDaemon *daemon1,
                                struct GNUNET_FS_TestDaemon *daemon2,
                                struct GNUNET_TIME_Relative timeout,
                                GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  struct GNUNET_FS_TEST_ConnectContext *ncc;

  ncc = GNUNET_malloc (sizeof (struct GNUNET_FS_TEST_ConnectContext));
  ncc->cont = cont;
  ncc->cont_cls = cont_cls;
  ncc->cc =
      GNUNET_TESTING_daemons_connect (daemon1->daemon, daemon2->daemon, timeout,
                                      CONNECT_ATTEMPTS, GNUNET_YES,
                                      &notify_connection, ncc);
  return ncc;
}


/**
 * Cancel connect operation.
 *
 * @param cc operation to cancel
 */
void
GNUNET_FS_TEST_daemons_connect_cancel (struct GNUNET_FS_TEST_ConnectContext *cc)
{
  GNUNET_TESTING_daemons_connect_cancel (cc->cc);
  GNUNET_free (cc);
}


/**
 * Obtain peer configuration used for testing.
 *
 * @param daemons array with the daemons
 * @param off which configuration to get
 * @return peer configuration
 */
const struct GNUNET_CONFIGURATION_Handle *
GNUNET_FS_TEST_get_configuration (struct GNUNET_FS_TestDaemon **daemons,
                                  unsigned int off)
{
  return daemons[off]->cfg;
}

/**
 * Obtain peer group used for testing.
 *
 * @param daemons array with the daemons (must contain at least one)
 * @return peer group
 */
struct GNUNET_TESTING_PeerGroup *
GNUNET_FS_TEST_get_group (struct GNUNET_FS_TestDaemon **daemons)
{
  return daemons[0]->group;
}


/**
 * Stop daemons used for testing.
 *
 * @param total number of daemons to stop
 * @param daemons array with the daemons (values will be clobbered)
 */
void
GNUNET_FS_TEST_daemons_stop (unsigned int total,
                             struct GNUNET_FS_TestDaemon **daemons)
{
  unsigned int i;
  struct GNUNET_TESTING_PeerGroup *pg;
  struct GNUNET_CONFIGURATION_Handle *gcfg;
  struct GNUNET_FS_TestDaemon *daemon;

  GNUNET_assert (total > 0);
  GNUNET_assert (daemons[0] != NULL);
  pg = daemons[0]->group;
  gcfg = daemons[0]->gcfg;
  for (i = 0; i < total; i++)
  {
    daemon = daemons[i];
    if (daemon->download_timeout_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (daemon->download_timeout_task);
      daemon->download_timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (daemon->publish_timeout_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (daemon->publish_timeout_task);
      daemon->publish_timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (NULL != daemon->download_context)
    {
      GNUNET_FS_download_stop (daemon->download_context, GNUNET_YES);
      daemon->download_context = NULL;
    }
    if (daemon->fs != NULL)
      GNUNET_FS_stop (daemon->fs);
    if (daemon->cfg != NULL)
      GNUNET_CONFIGURATION_destroy (daemon->cfg);
    if (NULL != daemon->publish_tmp_file)
    {
      GNUNET_break (GNUNET_OK ==
                    GNUNET_DISK_directory_remove (daemon->publish_tmp_file));
      GNUNET_free (daemon->publish_tmp_file);
      daemon->publish_tmp_file = NULL;
    }
    GNUNET_free (daemon);
    daemons[i] = NULL;
  }
  GNUNET_TESTING_daemons_stop (pg,
                               GNUNET_TIME_relative_multiply
                               (GNUNET_TIME_UNIT_SECONDS, 30),
                               &shutdown_callback, gcfg);
}


static void
publish_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_TestDaemon *daemon = cls;
  GNUNET_FS_TEST_UriContinuation cont;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Timeout while trying to publish data\n");
  cont = daemon->publish_cont;
  daemon->publish_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  daemon->publish_cont = NULL;
  GNUNET_FS_publish_stop (daemon->publish_context);
  daemon->publish_context = NULL;
  cont (daemon->publish_cont_cls, NULL);
}


static size_t
file_generator (void *cls, uint64_t offset, size_t max, void *buf, char **emsg)
{
  struct GNUNET_FS_TestDaemon *daemon = cls;
  uint64_t pos;
  uint8_t *cbuf = buf;
  int mod;

  if (emsg != NULL)
    *emsg = NULL;
  if (buf == NULL)
    return 0;
  for (pos = 0; pos < 8; pos++)
    cbuf[pos] = (uint8_t) (offset >> pos * 8);
  for (pos = 8; pos < max; pos++)
  {
    mod = (255 - (offset / 1024 / 32));
    if (mod == 0)
      mod = 1;
    cbuf[pos] = (uint8_t) ((offset * daemon->publish_seed) % mod);
  }
  return max;
}



/**
 * Publish a file at the given daemon.
 *
 * @param daemon where to publish
 * @param timeout if this operation cannot be completed within the
 *                given period, call the continuation with an error code
 * @param anonymity option for publication
 * @param do_index GNUNET_YES for index, GNUNET_NO for insertion,
 *                GNUNET_SYSERR for simulation
 * @param size size of the file to publish
 * @param seed seed to use for file generation
 * @param verbose how verbose to be in reporting
 * @param cont function to call when done
 * @param cont_cls closure for cont
 */
void
GNUNET_FS_TEST_publish (struct GNUNET_FS_TestDaemon *daemon,
                        struct GNUNET_TIME_Relative timeout, uint32_t anonymity,
                        int do_index, uint64_t size, uint32_t seed,
                        unsigned int verbose,
                        GNUNET_FS_TEST_UriContinuation cont, void *cont_cls)
{
  struct GNUNET_FS_FileInformation *fi;
  struct GNUNET_DISK_FileHandle *fh;
  char *emsg;
  uint64_t off;
  char buf[DBLOCK_SIZE];
  size_t bsize;
  struct GNUNET_FS_BlockOptions bo;

  GNUNET_assert (daemon->publish_cont == NULL);
  daemon->publish_cont = cont;
  daemon->publish_cont_cls = cont_cls;
  daemon->publish_seed = seed;
  daemon->verbose = verbose;
  bo.expiration_time = GNUNET_TIME_relative_to_absolute (CONTENT_LIFETIME);
  bo.anonymity_level = anonymity;
  bo.content_priority = 42;
  bo.replication_level = 1;
  if (GNUNET_YES == do_index)
  {
    GNUNET_assert (daemon->publish_tmp_file == NULL);
    daemon->publish_tmp_file = GNUNET_DISK_mktemp ("fs-test-publish-index");
    GNUNET_assert (daemon->publish_tmp_file != NULL);
    fh = GNUNET_DISK_file_open (daemon->publish_tmp_file,
                                GNUNET_DISK_OPEN_WRITE |
                                GNUNET_DISK_OPEN_CREATE,
                                GNUNET_DISK_PERM_USER_READ |
                                GNUNET_DISK_PERM_USER_WRITE);
    GNUNET_assert (NULL != fh);
    off = 0;
    while (off < size)
    {
      bsize = GNUNET_MIN (sizeof (buf), size - off);
      emsg = NULL;
      GNUNET_assert (bsize == file_generator (daemon, off, bsize, buf, &emsg));
      GNUNET_assert (emsg == NULL);
      GNUNET_assert (bsize == GNUNET_DISK_file_write (fh, buf, bsize));
      off += bsize;
    }
    GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));
    fi = GNUNET_FS_file_information_create_from_file (daemon->fs, daemon,
                                                      daemon->publish_tmp_file,
                                                      NULL, NULL, do_index,
                                                      &bo);
  }
  else
  {
    fi = GNUNET_FS_file_information_create_from_reader (daemon->fs, daemon,
                                                        size, &file_generator,
                                                        daemon, NULL, NULL,
                                                        do_index, &bo);
  }
  daemon->publish_context =
      GNUNET_FS_publish_start (daemon->fs, fi, NULL, NULL, NULL,
                               GNUNET_FS_PUBLISH_OPTION_NONE);
  daemon->publish_timeout_task =
      GNUNET_SCHEDULER_add_delayed (timeout, &publish_timeout, daemon);
}


static void
download_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_TestDaemon *daemon = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Timeout while trying to download file\n");
  daemon->download_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_FS_download_stop (daemon->download_context, GNUNET_YES);
  daemon->download_context = NULL;
  GNUNET_SCHEDULER_add_continuation (daemon->download_cont,
                                     daemon->download_cont_cls,
                                     GNUNET_SCHEDULER_REASON_TIMEOUT);
  daemon->download_cont = NULL;
}


/**
 * Perform test download.
 *
 * @param daemon which peer to download from
 * @param timeout if this operation cannot be completed within the
 *                given period, call the continuation with an error code
 * @param anonymity option for download
 * @param seed used for file validation
 * @param uri URI of file to download (CHK/LOC only)
 * @param verbose how verbose to be in reporting
 * @param cont function to call when done
 * @param cont_cls closure for cont
 */
void
GNUNET_FS_TEST_download (struct GNUNET_FS_TestDaemon *daemon,
                         struct GNUNET_TIME_Relative timeout,
                         uint32_t anonymity, uint32_t seed,
                         const struct GNUNET_FS_Uri *uri, unsigned int verbose,
                         GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  uint64_t size;

  GNUNET_assert (daemon->download_cont == NULL);
  size = GNUNET_FS_uri_chk_get_file_size (uri);
  daemon->verbose = verbose;
  daemon->download_cont = cont;
  daemon->download_cont_cls = cont_cls;
  daemon->download_seed = seed;
  daemon->download_context =
      GNUNET_FS_download_start (daemon->fs, uri, NULL, NULL, NULL, 0, size,
                                anonymity, GNUNET_FS_DOWNLOAD_OPTION_NONE, NULL,
                                NULL);
  daemon->download_timeout_task =
      GNUNET_SCHEDULER_add_delayed (timeout, &download_timeout, daemon);
}

/* end of test_fs_lib.c */
