/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2011, 2012 Christian Grothoff (and other contributing authors)

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
 * @brief library routines for testing FS publishing and downloading;
 *        this code is limited to flat files
 *        and no keywords (those functions can be tested with
 *        single-peer setups; this is for testing routing).
 * @author Christian Grothoff
 */
#include "platform.h"
#include "fs_api.h"
#include "fs_test_lib.h"


#define CONTENT_LIFETIME GNUNET_TIME_UNIT_HOURS


/**
 * Handle for a publishing operation started for testing FS.
 */
struct TestPublishOperation
{

  /**
   * Handle for the operation to connect to the peer's 'fs' service.
   */
  struct GNUNET_TESTBED_Operation *fs_op;

  /**
   * Handle to the file sharing context using this daemon.
   */
  struct GNUNET_FS_Handle *fs;

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
  struct GNUNET_SCHEDULER_Task * publish_timeout_task;

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
   * Size of the file.
   */
  uint64_t size;

  /**
   * Anonymity level used.
   */
  uint32_t anonymity;

  /**
   * Verbosity level of the current operation.
   */
  unsigned int verbose;

  /**
   * Are we testing indexing? (YES: index, NO: insert, SYSERR: simulate)
   */
  int do_index;
};


/**
 * Handle for a download operation started for testing FS.
 */
struct TestDownloadOperation
{

  /**
   * Handle for the operation to connect to the peer's 'fs' service.
   */
  struct GNUNET_TESTBED_Operation *fs_op;

  /**
   * Handle to the file sharing context using this daemon.
   */
  struct GNUNET_FS_Handle *fs;

  /**
   * Handle to the daemon via testing.
   */
  struct GNUNET_TESTING_Daemon *daemon;

  /**
   * Function to call when download is done.
   */
  GNUNET_SCHEDULER_TaskCallback download_cont;

  /**
   * Closure for download_cont.
   */
  void *download_cont_cls;

  /**
   * URI to download.
   */
  struct GNUNET_FS_Uri *uri;

  /**
   * Task to abort downloading (timeout).
   */
  struct GNUNET_SCHEDULER_Task * download_timeout_task;

  /**
   * Context for current download operation.
   */
  struct GNUNET_FS_DownloadContext *download_context;

  /**
   * Size of the file.
   */
  uint64_t size;

  /**
   * Anonymity level used.
   */
  uint32_t anonymity;

  /**
   * Seed for download verification.
   */
  uint32_t download_seed;

  /**
   * Verbosity level of the current operation.
   */
  unsigned int verbose;

};


/**
 * Task scheduled to report on the completion of our publish operation.
 *
 * @param cls the publish operation context
 * @param tc scheduler context (unused)
 */
static void
report_uri (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestPublishOperation *po = cls;

  GNUNET_FS_publish_stop (po->publish_context);
  GNUNET_TESTBED_operation_done (po->fs_op);
  po->publish_cont (po->publish_cont_cls,
		    po->publish_uri,
		    (GNUNET_YES == po->do_index)
		    ? po->publish_tmp_file
		    : NULL);
  GNUNET_FS_uri_destroy (po->publish_uri);
  if ( (GNUNET_YES != po->do_index) &&
       (NULL != po->publish_tmp_file) )
    (void) GNUNET_DISK_directory_remove (po->publish_tmp_file);
  GNUNET_free_non_null (po->publish_tmp_file);
  GNUNET_free (po);
}


/**
 * Task scheduled to run when publish operation times out.
 *
 * @param cls the publish operation context
 * @param tc scheduler context (unused)
 */
static void
publish_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestPublishOperation *po = cls;

  po->publish_timeout_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Timeout while trying to publish data\n");
  GNUNET_TESTBED_operation_done (po->fs_op);
  GNUNET_FS_publish_stop (po->publish_context);
  po->publish_cont (po->publish_cont_cls, NULL, NULL);
  (void) GNUNET_DISK_directory_remove (po->publish_tmp_file);
  GNUNET_free_non_null (po->publish_tmp_file);
  GNUNET_free (po);
}


/**
 * Progress callback for file-sharing events while publishing.
 *
 * @param cls the publish operation context
 * @param info information about the event
 */
static void *
publish_progress_cb (void *cls, const struct GNUNET_FS_ProgressInfo *info)
{
  struct TestPublishOperation *po = cls;

  switch (info->status)
  {
  case GNUNET_FS_STATUS_PUBLISH_COMPLETED:
    GNUNET_SCHEDULER_cancel (po->publish_timeout_task);
    po->publish_timeout_task = NULL;
    po->publish_uri =
        GNUNET_FS_uri_dup (info->value.publish.specifics.completed.chk_uri);
    GNUNET_SCHEDULER_add_continuation (&report_uri, po,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    break;
  case GNUNET_FS_STATUS_PUBLISH_PROGRESS:
    if (po->verbose)
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Publishing at %llu/%llu bytes\n",
                  (unsigned long long) info->value.publish.completed,
                  (unsigned long long) info->value.publish.size);
    break;
  case GNUNET_FS_STATUS_PUBLISH_PROGRESS_DIRECTORY:
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_PROGRESS:
    if (po->verbose)
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Download at %llu/%llu bytes\n",
                  (unsigned long long) info->value.download.completed,
                  (unsigned long long) info->value.download.size);
    break;
  default:
    break;
  }
  return NULL;
}


/**
 * Generate test data for publishing test.
 *
 * @param cls pointer to uint32_t with publishing seed
 * @param offset offset to generate data for
 * @param max maximum number of bytes to generate
 * @param buf where to write generated data
 * @param emsg where to store error message (unused)
 * @return number of bytes written to buf
 */
static size_t
file_generator (void *cls,
		uint64_t offset,
		size_t max,
		void *buf,
		char **emsg)
{
  uint32_t *publish_seed = cls;
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
    cbuf[pos] = (uint8_t) ((offset * (*publish_seed)) % mod);
  }
  return max;
}


/**
 * Connect adapter for publishing operation.
 *
 * @param cls the 'struct TestPublishOperation'
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
publish_connect_adapter (void *cls,
			 const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct TestPublishOperation *po = cls;

  return GNUNET_FS_start (cfg,
			  "fs-test-publish",
			  &publish_progress_cb, po,
			  GNUNET_FS_FLAGS_NONE,
			  GNUNET_FS_OPTIONS_END);
}


/**
 * Adapter function called to destroy connection to file-sharing service.
 *
 * @param cls the 'struct GNUNET_FS_Handle'
 * @param op_result unused (different for publish/download!)
 */
static void
fs_disconnect_adapter (void *cls,
		       void *op_result)
{
  struct GNUNET_FS_Handle *fs = op_result;

  GNUNET_FS_stop (fs);
}


/**
 * Callback to be called when testbed has connected to the fs service
 *
 * @param cls the 'struct TestPublishOperation'
 * @param op the operation that has been finished
 * @param ca_result the 'struct GNUNET_FS_Handle ' (NULL on error)
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
publish_fs_connect_complete_cb (void *cls,
				struct GNUNET_TESTBED_Operation *op,
				void *ca_result,
				const char *emsg)
{
  struct TestPublishOperation *po = cls;
  struct GNUNET_FS_FileInformation *fi;
  struct GNUNET_DISK_FileHandle *fh;
  char *em;
  uint64_t off;
  char buf[DBLOCK_SIZE];
  size_t bsize;
  struct GNUNET_FS_BlockOptions bo;

  if (NULL == ca_result)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to connect to FS for publishing: %s\n", emsg);
      po->publish_cont (po->publish_cont_cls,
			NULL, NULL);
      GNUNET_TESTBED_operation_done (po->fs_op);
      GNUNET_free (po);
      return;
    }
  po->fs = ca_result;

  bo.expiration_time = GNUNET_TIME_relative_to_absolute (CONTENT_LIFETIME);
  bo.anonymity_level = po->anonymity;
  bo.content_priority = 42;
  bo.replication_level = 1;
  if (GNUNET_YES == po->do_index)
  {
    po->publish_tmp_file = GNUNET_DISK_mktemp ("fs-test-publish-index");
    GNUNET_assert (po->publish_tmp_file != NULL);
    fh = GNUNET_DISK_file_open (po->publish_tmp_file,
                                GNUNET_DISK_OPEN_WRITE |
                                GNUNET_DISK_OPEN_CREATE,
                                GNUNET_DISK_PERM_USER_READ |
                                GNUNET_DISK_PERM_USER_WRITE);
    GNUNET_assert (NULL != fh);
    off = 0;
    while (off < po->size)
    {
      bsize = GNUNET_MIN (sizeof (buf), po->size - off);
      emsg = NULL;
      GNUNET_assert (bsize == file_generator (&po->publish_seed, off, bsize, buf, &em));
      GNUNET_assert (em == NULL);
      GNUNET_assert (bsize == GNUNET_DISK_file_write (fh, buf, bsize));
      off += bsize;
    }
    GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));
    fi = GNUNET_FS_file_information_create_from_file (po->fs, po,
                                                      po->publish_tmp_file,
                                                      NULL, NULL, po->do_index,
                                                      &bo);
    GNUNET_assert (NULL != fi);
  }
  else
  {
    fi = GNUNET_FS_file_information_create_from_reader (po->fs, po,
                                                        po->size,
							&file_generator, &po->publish_seed,
							NULL, NULL,
                                                        po->do_index, &bo);
    GNUNET_assert (NULL != fi);
  }
  po->publish_context =
    GNUNET_FS_publish_start (po->fs, fi, NULL, NULL, NULL,
			     GNUNET_FS_PUBLISH_OPTION_NONE);
}


/**
 * Publish a file at the given peer.
 *
 * @param peer where to publish
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
GNUNET_FS_TEST_publish (struct GNUNET_TESTBED_Peer *peer,
                        struct GNUNET_TIME_Relative timeout, uint32_t anonymity,
                        int do_index, uint64_t size, uint32_t seed,
                        unsigned int verbose,
                        GNUNET_FS_TEST_UriContinuation cont, void *cont_cls)
{
  struct TestPublishOperation *po;

  po = GNUNET_new (struct TestPublishOperation);
  po->publish_cont = cont;
  po->publish_cont_cls = cont_cls;
  po->publish_seed = seed;
  po->anonymity = anonymity;
  po->size = size;
  po->verbose = verbose;
  po->do_index = do_index;
  po->fs_op = GNUNET_TESTBED_service_connect (po,
					      peer,
					      "fs",
					      &publish_fs_connect_complete_cb,
					      po,
					      &publish_connect_adapter,
					      &fs_disconnect_adapter,
					      po);
  po->publish_timeout_task =
      GNUNET_SCHEDULER_add_delayed (timeout, &publish_timeout, po);
}


/* ************************** download ************************ */


/**
 * Task scheduled to run when download operation times out.
 *
 * @param cls the download operation context
 * @param tc scheduler context (unused)
 */
static void
download_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestDownloadOperation *dop = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Timeout while trying to download file\n");
  dop->download_timeout_task = NULL;
  GNUNET_FS_download_stop (dop->download_context, GNUNET_YES);
  GNUNET_SCHEDULER_add_continuation (dop->download_cont,
                                     dop->download_cont_cls,
                                     GNUNET_SCHEDULER_REASON_TIMEOUT);
  GNUNET_TESTBED_operation_done (dop->fs_op);
  GNUNET_FS_uri_destroy (dop->uri);
  GNUNET_free (dop);
}


/**
 * Task scheduled to report on the completion of our download operation.
 *
 * @param cls the download operation context
 * @param tc scheduler context (unused)
 */
static void
report_success (void *cls,
		const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestDownloadOperation *dop = cls;

  GNUNET_FS_download_stop (dop->download_context, GNUNET_YES);
  GNUNET_SCHEDULER_add_continuation (dop->download_cont,
                                     dop->download_cont_cls,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
  GNUNET_TESTBED_operation_done (dop->fs_op);
  GNUNET_FS_uri_destroy (dop->uri);
  GNUNET_free (dop);
}


/**
 * Progress callback for file-sharing events while downloading.
 *
 * @param cls the download operation context
 * @param info information about the event
 */
static void *
download_progress_cb (void *cls, const struct GNUNET_FS_ProgressInfo *info)
{
  struct TestDownloadOperation *dop = cls;

  switch (info->status)
  {
  case GNUNET_FS_STATUS_DOWNLOAD_PROGRESS:
    if (dop->verbose)
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Download at %llu/%llu bytes\n",
                  (unsigned long long) info->value.download.completed,
                  (unsigned long long) info->value.download.size);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_COMPLETED:
    GNUNET_SCHEDULER_cancel (dop->download_timeout_task);
    dop->download_timeout_task = NULL;
    GNUNET_SCHEDULER_add_continuation (&report_success, dop,
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


/**
 * Connect adapter for download operation.
 *
 * @param cls the 'struct TestDownloadOperation'
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
download_connect_adapter (void *cls,
			 const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct TestPublishOperation *po = cls;

  return GNUNET_FS_start (cfg,
			  "fs-test-download",
			  &download_progress_cb, po,
			  GNUNET_FS_FLAGS_NONE,
			  GNUNET_FS_OPTIONS_END);
}


/**
 * Callback to be called when testbed has connected to the fs service
 *
 * @param cls the 'struct TestPublishOperation'
 * @param op the operation that has been finished
 * @param ca_result the 'struct GNUNET_FS_Handle ' (NULL on error)
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
download_fs_connect_complete_cb (void *cls,
				 struct GNUNET_TESTBED_Operation *op,
				 void *ca_result,
				 const char *emsg)
{
  struct TestDownloadOperation *dop = cls;

  dop->fs = ca_result;
  GNUNET_assert (NULL != dop->fs);
  dop->download_context =
    GNUNET_FS_download_start (dop->fs, dop->uri, NULL, NULL, NULL, 0, dop->size,
			      dop->anonymity, GNUNET_FS_DOWNLOAD_OPTION_NONE,
			      NULL, NULL);
}


/**
 * Perform test download.
 *
 * @param peer which peer to download from
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
GNUNET_FS_TEST_download (struct GNUNET_TESTBED_Peer *peer,
                         struct GNUNET_TIME_Relative timeout,
                         uint32_t anonymity, uint32_t seed,
                         const struct GNUNET_FS_Uri *uri, unsigned int verbose,
                         GNUNET_SCHEDULER_TaskCallback cont, void *cont_cls)
{
  struct TestDownloadOperation *dop;

  dop = GNUNET_new (struct TestDownloadOperation);
  dop->uri = GNUNET_FS_uri_dup (uri);
  dop->size = GNUNET_FS_uri_chk_get_file_size (uri);
  dop->verbose = verbose;
  dop->anonymity = anonymity;
  dop->download_cont = cont;
  dop->download_cont_cls = cont_cls;
  dop->download_seed = seed;

  dop->fs_op = GNUNET_TESTBED_service_connect (dop,
					       peer,
					       "fs",
					       &download_fs_connect_complete_cb,
					       dop,
					       &download_connect_adapter,
					       &fs_disconnect_adapter,
					       dop);
  dop->download_timeout_task =
      GNUNET_SCHEDULER_add_delayed (timeout, &download_timeout, dop);
}


/* end of fs_test_lib.c */
