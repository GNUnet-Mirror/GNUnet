/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_publish.c
 * @brief publish a file or directory in GNUnet
 * @see https://gnunet.org/encoding
 * @author Krista Bennett
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "fs_api.h"
#include "fs_tree.h"


/**
 * Fill in all of the generic fields for
 * a publish event and call the callback.
 *
 * @param pi structure to fill in
 * @param pc overall publishing context
 * @param p file information for the file being published
 * @param offset where in the file are we so far
 * @return value returned from callback
 */
void *
GNUNET_FS_publish_make_status_ (struct GNUNET_FS_ProgressInfo *pi,
                                struct GNUNET_FS_PublishContext *pc,
                                const struct GNUNET_FS_FileInformation *p,
                                uint64_t offset)
{
  pi->value.publish.pc = pc;
  pi->value.publish.fi = p;
  pi->value.publish.cctx = p->client_info;
  pi->value.publish.pctx = (NULL == p->dir) ? NULL : p->dir->client_info;
  pi->value.publish.filename = p->filename;
  pi->value.publish.size =
      (p->is_directory == GNUNET_YES) ? p->data.dir.dir_size : p->data.file.file_size;
  pi->value.publish.eta =
      GNUNET_TIME_calculate_eta (p->start_time, offset, pi->value.publish.size);
  pi->value.publish.completed = offset;
  pi->value.publish.duration =
      GNUNET_TIME_absolute_get_duration (p->start_time);
  pi->value.publish.anonymity = p->bo.anonymity_level;
  return pc->h->upcb (pc->h->upcb_cls, pi);
}


/**
 * Cleanup the publish context, we're done with it.
 *
 * @param pc struct to clean up
 */
static void
publish_cleanup (struct GNUNET_FS_PublishContext *pc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up publish context (done!)\n");
  if (pc->fhc != NULL)
  {
    GNUNET_CRYPTO_hash_file_cancel (pc->fhc);
    pc->fhc = NULL;
  }
  GNUNET_FS_file_information_destroy (pc->fi, NULL, NULL);
  if (pc->namespace != NULL)
  {
    GNUNET_FS_namespace_delete (pc->namespace, GNUNET_NO);
    pc->namespace = NULL;
  }
  GNUNET_free_non_null (pc->nid);
  GNUNET_free_non_null (pc->nuid);
  GNUNET_free_non_null (pc->serialization);
  if (pc->dsh != NULL)
  {
    GNUNET_DATASTORE_disconnect (pc->dsh, GNUNET_NO);
    pc->dsh = NULL;
  }
  if (pc->client != NULL)
  {
    GNUNET_CLIENT_disconnect (pc->client, GNUNET_NO);
    pc->client = NULL;
  }
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == pc->upload_task);
  GNUNET_free (pc);
}


/**
 * Function called by the datastore API with
 * the result from the PUT request.
 *
 * @param cls the 'struct GNUNET_FS_PublishContext'
 * @param success GNUNET_OK on success
 * @param min_expiration minimum expiration time required for content to be stored
 * @param msg error message (or NULL)
 */
static void
ds_put_cont (void *cls, int success, 
	     struct GNUNET_TIME_Absolute min_expiration,
	     const char *msg)
{
  struct GNUNET_FS_PublishContext *pc = cls;
  struct GNUNET_FS_ProgressInfo pi;

  pc->qre = NULL;
  if (GNUNET_SYSERR == success)
  {
    GNUNET_asprintf (&pc->fi_pos->emsg, _("Publishing failed: %s"), msg);
    pi.status = GNUNET_FS_STATUS_PUBLISH_ERROR;
    pi.value.publish.eta = GNUNET_TIME_UNIT_FOREVER_REL;
    pi.value.publish.specifics.error.message = pc->fi_pos->emsg;
    pc->fi_pos->client_info =
        GNUNET_FS_publish_make_status_ (&pi, pc, pc->fi_pos, 0);
    if ((pc->fi_pos->is_directory != GNUNET_YES) &&
        (pc->fi_pos->filename != NULL) &&
        (pc->fi_pos->data.file.do_index == GNUNET_YES))
    {
      /* run unindex to clean up */
      GNUNET_FS_unindex_start (pc->h, pc->fi_pos->filename, NULL);
    }
  }
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == pc->upload_task);
  pc->upload_task =
      GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
                                          &GNUNET_FS_publish_main_, pc);
}


/**
 * Generate the callback that signals clients
 * that a file (or directory) has been completely
 * published.
 *
 * @param p the completed upload
 * @param pc context of the publication
 */
static void
signal_publish_completion (struct GNUNET_FS_FileInformation *p,
                           struct GNUNET_FS_PublishContext *pc)
{
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_PUBLISH_COMPLETED;
  pi.value.publish.eta = GNUNET_TIME_UNIT_ZERO;
  pi.value.publish.specifics.completed.chk_uri = p->chk_uri;
  p->client_info =
      GNUNET_FS_publish_make_status_ (&pi, pc, p,
                                      GNUNET_ntohll (p->chk_uri->data.
                                                     chk.file_length));
}


/**
 * Generate the callback that signals clients
 * that a file (or directory) has encountered
 * a problem during publication.
 *
 * @param p the upload that had trouble
 * @param pc context of the publication
 * @param emsg error message
 */
static void
signal_publish_error (struct GNUNET_FS_FileInformation *p,
                      struct GNUNET_FS_PublishContext *pc, const char *emsg)
{
  struct GNUNET_FS_ProgressInfo pi;

  p->emsg = GNUNET_strdup (emsg);
  pi.status = GNUNET_FS_STATUS_PUBLISH_ERROR;
  pi.value.publish.eta = GNUNET_TIME_UNIT_FOREVER_REL;
  pi.value.publish.specifics.error.message = emsg;
  p->client_info = GNUNET_FS_publish_make_status_ (&pi, pc, p, 0);
  if ((p->is_directory != GNUNET_YES) && (p->filename != NULL) &&
      (p->data.file.do_index == GNUNET_YES))
  {
    /* run unindex to clean up */
    GNUNET_FS_unindex_start (pc->h, p->filename, NULL);
  }

}


/**
 * Datastore returns from reservation cancel request.
 *
 * @param cls the 'struct GNUNET_FS_PublishContext'
 * @param success success code (not used)
 * @param min_expiration minimum expiration time required for content to be stored
 * @param msg error message (typically NULL, not used)
 */
static void
finish_release_reserve (void *cls, int success, 
			struct GNUNET_TIME_Absolute min_expiration,
			const char *msg)
{
  struct GNUNET_FS_PublishContext *pc = cls;

  pc->qre = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Releasing reserve done!\n");
  signal_publish_completion (pc->fi, pc);
  pc->all_done = GNUNET_YES;
  GNUNET_FS_publish_sync_ (pc);
}


/**
 * We've finished publishing the SBlock as part of a larger upload.
 * Check the result and complete the larger upload.
 *
 * @param cls the "struct GNUNET_FS_PublishContext*" of the larger upload
 * @param uri URI of the published SBlock
 * @param emsg NULL on success, otherwise error message
 */
static void
publish_sblocks_cont (void *cls, const struct GNUNET_FS_Uri *uri,
                      const char *emsg)
{
  struct GNUNET_FS_PublishContext *pc = cls;

  pc->sks_pc = NULL;
  if (NULL != emsg)
  {
    signal_publish_error (pc->fi, pc, emsg);
    GNUNET_FS_publish_sync_ (pc);
    return;
  }
  GNUNET_assert (pc->qre == NULL);
  if ((pc->dsh != NULL) && (pc->rid != 0))
  {
    pc->qre =
        GNUNET_DATASTORE_release_reserve (pc->dsh, pc->rid, UINT_MAX, UINT_MAX,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          &finish_release_reserve, pc);
  }
  else
  {
    finish_release_reserve (pc, GNUNET_OK, GNUNET_TIME_UNIT_ZERO_ABS, NULL);
  }
}


/**
 * We are almost done publishing the structure,
 * add SBlocks (if needed).
 *
 * @param pc overall upload data
 */
static void
publish_sblock (struct GNUNET_FS_PublishContext *pc)
{
  if (NULL != pc->namespace)
    pc->sks_pc = GNUNET_FS_publish_sks (pc->h, pc->namespace, pc->nid, pc->nuid,
					pc->fi->meta, pc->fi->chk_uri, &pc->fi->bo,
					pc->options, &publish_sblocks_cont, pc);
  else
    publish_sblocks_cont (pc, NULL, NULL);
}


/**
 * We've finished publishing a KBlock as part of a larger upload.
 * Check the result and continue the larger upload.
 *
 * @param cls the "struct GNUNET_FS_PublishContext*"
 *        of the larger upload
 * @param uri URI of the published blocks
 * @param emsg NULL on success, otherwise error message
 */
static void
publish_kblocks_cont (void *cls, const struct GNUNET_FS_Uri *uri,
                      const char *emsg)
{
  struct GNUNET_FS_PublishContext *pc = cls;
  struct GNUNET_FS_FileInformation *p = pc->fi_pos;

  pc->ksk_pc = NULL;
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Error uploading KSK blocks: %s\n",
                emsg);
    signal_publish_error (p, pc, emsg);
    GNUNET_FS_file_information_sync_ (p);
    GNUNET_FS_publish_sync_ (pc);
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == pc->upload_task);
    pc->upload_task =
      GNUNET_SCHEDULER_add_with_priority
      (GNUNET_SCHEDULER_PRIORITY_BACKGROUND, &GNUNET_FS_publish_main_, pc);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "KSK blocks published, moving on to next file\n");
  if (NULL != p->dir)
    signal_publish_completion (p, pc);
  /* move on to next file */
  if (NULL != p->next)
    pc->fi_pos = p->next;
  else
    pc->fi_pos = p->dir;
  GNUNET_FS_publish_sync_ (pc);
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == pc->upload_task);
  pc->upload_task =
      GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
                                          &GNUNET_FS_publish_main_, pc);
}


/**
 * Function called by the tree encoder to obtain
 * a block of plaintext data (for the lowest level
 * of the tree).
 *
 * @param cls our publishing context
 * @param offset identifies which block to get
 * @param max (maximum) number of bytes to get; returning
 *        fewer will also cause errors
 * @param buf where to copy the plaintext buffer
 * @param emsg location to store an error message (on error)
 * @return number of bytes copied to buf, 0 on error
 */
static size_t
block_reader (void *cls, uint64_t offset, size_t max, void *buf, char **emsg)
{
  struct GNUNET_FS_PublishContext *pc = cls;
  struct GNUNET_FS_FileInformation *p;
  size_t pt_size;
  const char *dd;

  p = pc->fi_pos;
  if (p->is_directory == GNUNET_YES)
  {
    pt_size = GNUNET_MIN (max, p->data.dir.dir_size - offset);
    dd = p->data.dir.dir_data;
    memcpy (buf, &dd[offset], pt_size);
  }
  else
  {
    pt_size = GNUNET_MIN (max, p->data.file.file_size - offset);
    if (pt_size == 0)
      return 0;                 /* calling reader with pt_size==0
                                 * might free buf, so don't! */
    if (pt_size !=
        p->data.file.reader (p->data.file.reader_cls, offset, pt_size, buf,
                             emsg))
      return 0;
  }
  return pt_size;
}


/**
 * The tree encoder has finished processing a
 * file.   Call it's finish method and deal with
 * the final result.
 *
 * @param cls our publishing context
 * @param tc scheduler's task context (not used)
 */
static void
encode_cont (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_PublishContext *pc = cls;
  struct GNUNET_FS_FileInformation *p;
  struct GNUNET_FS_ProgressInfo pi;
  char *emsg;
  uint64_t flen;

  p = pc->fi_pos;
  GNUNET_FS_tree_encoder_finish (p->te, &p->chk_uri, &emsg);
  p->te = NULL;
  GNUNET_FS_file_information_sync_ (p);
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Error during tree walk: %s\n", emsg);
    GNUNET_asprintf (&p->emsg, _("Publishing failed: %s"), emsg);
    GNUNET_free (emsg);
    pi.status = GNUNET_FS_STATUS_PUBLISH_ERROR;
    pi.value.publish.eta = GNUNET_TIME_UNIT_FOREVER_REL;
    pi.value.publish.specifics.error.message = p->emsg;
    p->client_info = GNUNET_FS_publish_make_status_ (&pi, pc, p, 0);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Finished with tree encoder\n");
  /* final progress event */
  flen = GNUNET_FS_uri_chk_get_file_size (p->chk_uri);
  pi.status = GNUNET_FS_STATUS_PUBLISH_PROGRESS;
  pi.value.publish.specifics.progress.data = NULL;
  pi.value.publish.specifics.progress.offset = flen;
  pi.value.publish.specifics.progress.data_len = 0;
  pi.value.publish.specifics.progress.depth = GNUNET_FS_compute_depth (flen);
  p->client_info = GNUNET_FS_publish_make_status_ (&pi, pc, p, flen);

  /* continue with main */
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == pc->upload_task);
  pc->upload_task =
      GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
                                          &GNUNET_FS_publish_main_, pc);
}


/**
 * Function called asking for the current (encoded)
 * block to be processed.  After processing the
 * client should either call "GNUNET_FS_tree_encode_next"
 * or (on error) "GNUNET_FS_tree_encode_finish".
 *
 * @param cls closure
 * @param chk content hash key for the block
 * @param offset offset of the block in the file
 * @param depth depth of the block in the file, 0 for DBLOCK
 * @param type type of the block (IBLOCK or DBLOCK)
 * @param block the (encrypted) block
 * @param block_size size of block (in bytes)
 */
static void
block_proc (void *cls, const struct ContentHashKey *chk, uint64_t offset,
            unsigned int depth, enum GNUNET_BLOCK_Type type, const void *block,
            uint16_t block_size)
{
  struct GNUNET_FS_PublishContext *pc = cls;
  struct GNUNET_FS_FileInformation *p;
  struct OnDemandBlock odb;

  p = pc->fi_pos;
  if (NULL == pc->dsh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Waiting for datastore connection\n");
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == pc->upload_task);
    pc->upload_task =
        GNUNET_SCHEDULER_add_with_priority
        (GNUNET_SCHEDULER_PRIORITY_BACKGROUND, &GNUNET_FS_publish_main_, pc);
    return;
  }

  if ((p->is_directory != GNUNET_YES) && (GNUNET_YES == p->data.file.do_index) &&
      (type == GNUNET_BLOCK_TYPE_FS_DBLOCK))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Indexing block `%s' for offset %llu with index size %u\n",
                GNUNET_h2s (&chk->query), (unsigned long long) offset,
                sizeof (struct OnDemandBlock));
    odb.offset = GNUNET_htonll (offset);
    odb.file_id = p->data.file.file_id;
    GNUNET_assert (pc->qre == NULL);
    pc->qre =
        GNUNET_DATASTORE_put (pc->dsh, (p->is_directory == GNUNET_YES) ? 0 : pc->rid,
                              &chk->query, sizeof (struct OnDemandBlock), &odb,
                              GNUNET_BLOCK_TYPE_FS_ONDEMAND,
                              p->bo.content_priority, p->bo.anonymity_level,
                              p->bo.replication_level, p->bo.expiration_time,
                              -2, 1, GNUNET_CONSTANTS_SERVICE_TIMEOUT,
                              &ds_put_cont, pc);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Publishing block `%s' for offset %llu with size %u\n",
              GNUNET_h2s (&chk->query), (unsigned long long) offset,
              (unsigned int) block_size);
  GNUNET_assert (pc->qre == NULL);
  pc->qre =
      GNUNET_DATASTORE_put (pc->dsh, (p->is_directory == GNUNET_YES) ? 0 : pc->rid,
                            &chk->query, block_size, block, type,
                            p->bo.content_priority, p->bo.anonymity_level,
                            p->bo.replication_level, p->bo.expiration_time, -2,
                            1, GNUNET_CONSTANTS_SERVICE_TIMEOUT, &ds_put_cont,
                            pc);
}


/**
 * Function called with information about our
 * progress in computing the tree encoding.
 *
 * @param cls closure
 * @param offset where are we in the file
 * @param pt_block plaintext of the currently processed block
 * @param pt_size size of pt_block
 * @param depth depth of the block in the tree, 0 for DBLOCK
 */
static void
progress_proc (void *cls, uint64_t offset, const void *pt_block, size_t pt_size,
               unsigned int depth)
{
  struct GNUNET_FS_PublishContext *pc = cls;
  struct GNUNET_FS_FileInformation *p;
  struct GNUNET_FS_ProgressInfo pi;

  p = pc->fi_pos;
  pi.status = GNUNET_FS_STATUS_PUBLISH_PROGRESS;
  pi.value.publish.specifics.progress.data = pt_block;
  pi.value.publish.specifics.progress.offset = offset;
  pi.value.publish.specifics.progress.data_len = pt_size;
  pi.value.publish.specifics.progress.depth = depth;
  p->client_info = GNUNET_FS_publish_make_status_ (&pi, pc, p, offset);
}


/**
 * We are uploading a file or directory; load (if necessary) the next
 * block into memory, encrypt it and send it to the FS service.  Then
 * continue with the main task.
 *
 * @param pc overall upload data
 */
static void
publish_content (struct GNUNET_FS_PublishContext *pc)
{
  struct GNUNET_FS_FileInformation *p;
  char *emsg;
  struct GNUNET_FS_DirectoryBuilder *db;
  struct GNUNET_FS_FileInformation *dirpos;
  void *raw_data;
  uint64_t size;

  p = pc->fi_pos;
  GNUNET_assert (p != NULL);
  if (NULL == p->te)
  {
    if (p->is_directory == GNUNET_YES)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating directory\n");
      db = GNUNET_FS_directory_builder_create (p->meta);
      dirpos = p->data.dir.entries;
      while (NULL != dirpos)
      {
        if (dirpos->is_directory == GNUNET_YES)
        {
          raw_data = dirpos->data.dir.dir_data;
          dirpos->data.dir.dir_data = NULL;
        }
        else
        {
          raw_data = NULL;
          if ((dirpos->data.file.file_size < MAX_INLINE_SIZE) &&
              (dirpos->data.file.file_size > 0))
          {
            raw_data = GNUNET_malloc (dirpos->data.file.file_size);
            emsg = NULL;
            if (dirpos->data.file.file_size !=
                dirpos->data.file.reader (dirpos->data.file.reader_cls, 0,
                                          dirpos->data.file.file_size, raw_data,
                                          &emsg))
            {
              GNUNET_free_non_null (emsg);
              GNUNET_free (raw_data);
              raw_data = NULL;
            }
          }
        }
        GNUNET_FS_directory_builder_add (db, dirpos->chk_uri, dirpos->meta,
                                         raw_data);
        GNUNET_free_non_null (raw_data);
        dirpos = dirpos->next;
      }
      GNUNET_free_non_null (p->data.dir.dir_data);
      p->data.dir.dir_data = NULL;
      p->data.dir.dir_size = 0;
      GNUNET_FS_directory_builder_finish (db, &p->data.dir.dir_size,
                                          &p->data.dir.dir_data);
      GNUNET_FS_file_information_sync_ (p);
    }
    size = (p->is_directory == GNUNET_YES) ? p->data.dir.dir_size : p->data.file.file_size;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating tree encoder\n");
    p->te =
        GNUNET_FS_tree_encoder_create (pc->h, size, pc, &block_reader,
                                       &block_proc, &progress_proc,
                                       &encode_cont);

  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Processing next block from tree\n");
  GNUNET_FS_tree_encoder_next (p->te);
}


/**
 * Process the response (or lack thereof) from
 * the "fs" service to our 'start index' request.
 *
 * @param cls closure (of type "struct GNUNET_FS_PublishContext*"_)
 * @param msg the response we got
 */
static void
process_index_start_response (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_FS_PublishContext *pc = cls;
  struct GNUNET_FS_FileInformation *p;
  const char *emsg;
  uint16_t msize;

  GNUNET_CLIENT_disconnect (pc->client, GNUNET_NO);
  pc->client = NULL;
  p = pc->fi_pos;
  if (msg == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Can not index file `%s': %s.  Will try to insert instead.\n"),
                p->filename,
                _("timeout on index-start request to `fs' service"));
    p->data.file.do_index = GNUNET_NO;
    GNUNET_FS_file_information_sync_ (p);
    publish_content (pc);
    return;
  }
  if (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_FS_INDEX_START_OK)
  {
    msize = ntohs (msg->size);
    emsg = (const char *) &msg[1];
    if ((msize <= sizeof (struct GNUNET_MessageHeader)) ||
        (emsg[msize - sizeof (struct GNUNET_MessageHeader) - 1] != '\0'))
      emsg = gettext_noop ("unknown error");
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Can not index file `%s': %s.  Will try to insert instead.\n"),
                p->filename, gettext (emsg));
    p->data.file.do_index = GNUNET_NO;
    GNUNET_FS_file_information_sync_ (p);
    publish_content (pc);
    return;
  }
  p->data.file.index_start_confirmed = GNUNET_YES;
  /* success! continue with indexing */
  GNUNET_FS_file_information_sync_ (p);
  publish_content (pc);
}


/**
 * Function called once the hash computation over an
 * indexed file has completed.
 *
 * @param cls closure, our publishing context
 * @param res resulting hash, NULL on error
 */
static void
hash_for_index_cb (void *cls, const GNUNET_HashCode * res)
{
  struct GNUNET_FS_PublishContext *pc = cls;
  struct GNUNET_FS_FileInformation *p;
  struct IndexStartMessage *ism;
  size_t slen;
  struct GNUNET_CLIENT_Connection *client;
  uint64_t dev;
  uint64_t ino;
  char *fn;

  pc->fhc = NULL;
  p = pc->fi_pos;
  if (NULL == res)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Can not index file `%s': %s.  Will try to insert instead.\n"),
                p->filename, _("failed to compute hash"));
    p->data.file.do_index = GNUNET_NO;
    GNUNET_FS_file_information_sync_ (p);
    publish_content (pc);
    return;
  }
  if (GNUNET_YES == p->data.file.index_start_confirmed)
  {
    publish_content (pc);
    return;
  }
  fn = GNUNET_STRINGS_filename_expand (p->filename);
  GNUNET_assert (fn != NULL);
  slen = strlen (fn) + 1;
  if (slen >=
      GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (struct IndexStartMessage))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Can not index file `%s': %s.  Will try to insert instead.\n"),
                fn, _("filename too long"));
    GNUNET_free (fn);
    p->data.file.do_index = GNUNET_NO;
    GNUNET_FS_file_information_sync_ (p);
    publish_content (pc);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Hash of indexed file `%s' is `%s'\n",
              p->filename, GNUNET_h2s (res));
  if (0 != (pc->options & GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY))
  {
    p->data.file.file_id = *res;
    p->data.file.have_hash = GNUNET_YES;
    p->data.file.index_start_confirmed = GNUNET_YES;
    GNUNET_FS_file_information_sync_ (p);
    publish_content (pc);
    GNUNET_free (fn);
    return;
  }
  client = GNUNET_CLIENT_connect ("fs", pc->h->cfg);
  if (NULL == client)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Can not index file `%s': %s.  Will try to insert instead.\n"),
                p->filename, _("could not connect to `fs' service"));
    p->data.file.do_index = GNUNET_NO;
    publish_content (pc);
    GNUNET_free (fn);
    return;
  }
  if (p->data.file.have_hash != GNUNET_YES)
  {
    p->data.file.file_id = *res;
    p->data.file.have_hash = GNUNET_YES;
    GNUNET_FS_file_information_sync_ (p);
  }
  ism = GNUNET_malloc (sizeof (struct IndexStartMessage) + slen);
  ism->header.size = htons (sizeof (struct IndexStartMessage) + slen);
  ism->header.type = htons (GNUNET_MESSAGE_TYPE_FS_INDEX_START);
  if (GNUNET_OK == GNUNET_DISK_file_get_identifiers (p->filename, &dev, &ino))
  {
    ism->device = GNUNET_htonll (dev);
    ism->inode = GNUNET_htonll (ino);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _("Failed to get file identifiers for `%s'\n"), p->filename);
  }
  ism->file_id = *res;
  memcpy (&ism[1], fn, slen);
  GNUNET_free (fn);
  pc->client = client;
  GNUNET_break (GNUNET_YES ==
                GNUNET_CLIENT_transmit_and_get_response (client, &ism->header,
                                                         GNUNET_TIME_UNIT_FOREVER_REL,
                                                         GNUNET_YES,
                                                         &process_index_start_response,
                                                         pc));
  GNUNET_free (ism);
}


/**
 * Main function that performs the upload.
 *
 * @param cls "struct GNUNET_FS_PublishContext" identifies the upload
 * @param tc task context
 */
void
GNUNET_FS_publish_main_ (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_PublishContext *pc = cls;
  struct GNUNET_FS_ProgressInfo pi;
  struct GNUNET_FS_FileInformation *p;
  struct GNUNET_FS_Uri *loc;
  char *fn;

  pc->upload_task = GNUNET_SCHEDULER_NO_TASK;
  p = pc->fi_pos;
  if (NULL == p)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Publishing complete, now publishing SKS and KSK blocks.\n");
    /* upload of entire hierarchy complete,
     * publish namespace entries */
    GNUNET_FS_publish_sync_ (pc);
    publish_sblock (pc);
    return;
  }
  /* find starting position */
  while ((p->is_directory == GNUNET_YES) && (NULL != p->data.dir.entries) && (NULL == p->emsg)
         && (NULL == p->data.dir.entries->chk_uri))
  {
    p = p->data.dir.entries;
    pc->fi_pos = p;
    GNUNET_FS_publish_sync_ (pc);
  }
  /* abort on error */
  if (NULL != p->emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Error uploading: %s\n", p->emsg);
    /* error with current file, abort all
     * related files as well! */
    while (NULL != p->dir)
    {
      fn = GNUNET_CONTAINER_meta_data_get_by_type (p->meta,
                                                   EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME);
      p = p->dir;
      if (fn != NULL)
      {
        GNUNET_asprintf (&p->emsg, _("Recursive upload failed at `%s': %s"), fn,
                         p->emsg);
        GNUNET_free (fn);
      }
      else
      {
        GNUNET_asprintf (&p->emsg, _("Recursive upload failed: %s"), p->emsg);
      }
      pi.status = GNUNET_FS_STATUS_PUBLISH_ERROR;
      pi.value.publish.eta = GNUNET_TIME_UNIT_FOREVER_REL;
      pi.value.publish.specifics.error.message = p->emsg;
      p->client_info = GNUNET_FS_publish_make_status_ (&pi, pc, p, 0);
    }
    pc->all_done = GNUNET_YES;
    GNUNET_FS_publish_sync_ (pc);
    return;
  }
  /* handle completion */
  if (NULL != p->chk_uri)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "File upload complete, now publishing KSK blocks.\n");
    if (0 == p->bo.anonymity_level)
    {
      /* zero anonymity, box CHK URI in LOC URI */
      loc =
          GNUNET_FS_uri_loc_create (p->chk_uri, pc->h->cfg,
                                    p->bo.expiration_time);
      GNUNET_FS_uri_destroy (p->chk_uri);
      p->chk_uri = loc;
    }
    GNUNET_FS_publish_sync_ (pc);
    /* upload of "p" complete, publish KBlocks! */
    if (p->keywords != NULL)
    {
      pc->ksk_pc = GNUNET_FS_publish_ksk (pc->h, p->keywords, p->meta, p->chk_uri, &p->bo,
					  pc->options, &publish_kblocks_cont, pc);
    }
    else
    {
      publish_kblocks_cont (pc, p->chk_uri, NULL);
    }
    return;
  }
  if ((p->is_directory != GNUNET_YES) && (p->data.file.do_index))
  {
    if (NULL == p->filename)
    {
      p->data.file.do_index = GNUNET_NO;
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Can not index file `%s': %s.  Will try to insert instead.\n"),
                  "<no-name>", _("needs to be an actual file"));
      GNUNET_FS_file_information_sync_ (p);
      publish_content (pc);
      return;
    }
    if (p->data.file.have_hash)
    {
      hash_for_index_cb (pc, &p->data.file.file_id);
    }
    else
    {
      p->start_time = GNUNET_TIME_absolute_get ();
      pc->fhc =
          GNUNET_CRYPTO_hash_file (GNUNET_SCHEDULER_PRIORITY_IDLE, p->filename,
                                   HASHING_BLOCKSIZE, &hash_for_index_cb, pc);
    }
    return;
  }
  publish_content (pc);
}


/**
 * Signal the FS's progress function that we are starting
 * an upload.
 *
 * @param cls closure (of type "struct GNUNET_FS_PublishContext*")
 * @param fi the entry in the publish-structure
 * @param length length of the file or directory
 * @param meta metadata for the file or directory (can be modified)
 * @param uri pointer to the keywords that will be used for this entry (can be modified)
 * @param bo block options
 * @param do_index should we index?
 * @param client_info pointer to client context set upon creation (can be modified)
 * @return GNUNET_OK to continue (always)
 */
static int
fip_signal_start (void *cls, struct GNUNET_FS_FileInformation *fi,
                  uint64_t length, struct GNUNET_CONTAINER_MetaData *meta,
                  struct GNUNET_FS_Uri **uri, struct GNUNET_FS_BlockOptions *bo,
                  int *do_index, void **client_info)
{
  struct GNUNET_FS_PublishContext *pc = cls;
  struct GNUNET_FS_ProgressInfo pi;
  unsigned int kc;
  uint64_t left;

  if (GNUNET_YES == pc->skip_next_fi_callback)
  {
    pc->skip_next_fi_callback = GNUNET_NO;
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting publish operation\n");
  if (*do_index)
  {
    /* space for on-demand blocks */
    pc->reserve_space +=
        ((length + DBLOCK_SIZE -
          1) / DBLOCK_SIZE) * sizeof (struct OnDemandBlock);
  }
  else
  {
    /* space for DBlocks */
    pc->reserve_space += length;
  }
  /* entries for IBlocks and DBlocks, space for IBlocks */
  left = length;
  while (1)
  {
    left = (left + DBLOCK_SIZE - 1) / DBLOCK_SIZE;
    pc->reserve_entries += left;
    if (left <= 1)
      break;
    left = left * sizeof (struct ContentHashKey);
    pc->reserve_space += left;
  }
  pc->reserve_entries++;
  /* entries and space for keywords */
  if (NULL != *uri)
  {
    kc = GNUNET_FS_uri_ksk_get_keyword_count (*uri);
    pc->reserve_entries += kc;
    pc->reserve_space += GNUNET_SERVER_MAX_MESSAGE_SIZE * kc;
  }
  pi.status = GNUNET_FS_STATUS_PUBLISH_START;
  *client_info = GNUNET_FS_publish_make_status_ (&pi, pc, fi, 0);
  GNUNET_FS_file_information_sync_ (fi);
  if (GNUNET_YES == GNUNET_FS_meta_data_test_for_directory (meta)
      && (fi->dir != NULL))
  {
    /* process entries in directory */
    pc->skip_next_fi_callback = GNUNET_YES;
    GNUNET_FS_file_information_inspect (fi, &fip_signal_start, pc);
  }
  return GNUNET_OK;
}


/**
 * Signal the FS's progress function that we are suspending
 * an upload.
 *
 * @param cls closure (of type "struct GNUNET_FS_PublishContext*")
 * @param fi the entry in the publish-structure
 * @param length length of the file or directory
 * @param meta metadata for the file or directory (can be modified)
 * @param uri pointer to the keywords that will be used for this entry (can be modified)
 * @param bo block options
 * @param do_index should we index?
 * @param client_info pointer to client context set upon creation (can be modified)
 * @return GNUNET_OK to continue (always)
 */
static int
fip_signal_suspend (void *cls, struct GNUNET_FS_FileInformation *fi,
                    uint64_t length, struct GNUNET_CONTAINER_MetaData *meta,
                    struct GNUNET_FS_Uri **uri,
                    struct GNUNET_FS_BlockOptions *bo, int *do_index,
                    void **client_info)
{
  struct GNUNET_FS_PublishContext *pc = cls;
  struct GNUNET_FS_ProgressInfo pi;
  uint64_t off;

  if (GNUNET_YES == pc->skip_next_fi_callback)
  {
    pc->skip_next_fi_callback = GNUNET_NO;
    return GNUNET_OK;
  }
  if (GNUNET_YES == GNUNET_FS_meta_data_test_for_directory (meta))
  {
    /* process entries in directory */
    pc->skip_next_fi_callback = GNUNET_YES;
    GNUNET_FS_file_information_inspect (fi, &fip_signal_suspend, pc);
  }
  if (NULL != pc->ksk_pc)
  {
    GNUNET_FS_publish_ksk_cancel (pc->ksk_pc);
    pc->ksk_pc = NULL;
  }
  if (NULL != pc->sks_pc)
  {
    GNUNET_FS_publish_sks_cancel (pc->sks_pc);
    pc->sks_pc = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Suspending publish operation\n");
  GNUNET_free_non_null (fi->serialization);
  fi->serialization = NULL;
  off = (fi->chk_uri == NULL) ? 0 : length;
  pi.status = GNUNET_FS_STATUS_PUBLISH_SUSPEND;
  GNUNET_break (NULL == GNUNET_FS_publish_make_status_ (&pi, pc, fi, off));
  *client_info = NULL;
  if (NULL != pc->qre)
  {
    GNUNET_DATASTORE_cancel (pc->qre);
    pc->qre = NULL;
  }
  if (NULL != pc->dsh)
  {
    GNUNET_DATASTORE_disconnect (pc->dsh, GNUNET_NO);
    pc->dsh = NULL;
  }
  pc->rid = 0;
  return GNUNET_OK;
}


/**
 * Create SUSPEND event for the given publish operation
 * and then clean up our state (without stop signal).
 *
 * @param cls the 'struct GNUNET_FS_PublishContext' to signal for
 */
void
GNUNET_FS_publish_signal_suspend_ (void *cls)
{
  struct GNUNET_FS_PublishContext *pc = cls;

  if (GNUNET_SCHEDULER_NO_TASK != pc->upload_task)
  {
    GNUNET_SCHEDULER_cancel (pc->upload_task);
    pc->upload_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_FS_file_information_inspect (pc->fi, &fip_signal_suspend, pc);
  GNUNET_FS_end_top (pc->h, pc->top);
  pc->top = NULL;
  publish_cleanup (pc);
}


/**
 * We have gotten a reply for our space reservation request.
 * Either fail (insufficient space) or start publishing for good.
 *
 * @param cls the 'struct GNUNET_FS_PublishContext*'
 * @param success positive reservation ID on success
 * @param min_expiration minimum expiration time required for content to be stored
 * @param msg error message on error, otherwise NULL
 */
static void
finish_reserve (void *cls, int success, 
		struct GNUNET_TIME_Absolute min_expiration,
		const char *msg)
{
  struct GNUNET_FS_PublishContext *pc = cls;

  pc->qre = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Reservation complete (%d)!\n", success);
  if ((msg != NULL) || (success <= 0))
  {
    GNUNET_asprintf (&pc->fi->emsg, _("Insufficient space for publishing: %s"),
                     msg);
    signal_publish_error (pc->fi, pc, pc->fi->emsg);
    return;
  }
  pc->rid = success;
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == pc->upload_task);
  pc->upload_task =
      GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
                                          &GNUNET_FS_publish_main_, pc);
}


/**
 * Publish a file or directory.
 *
 * @param h handle to the file sharing subsystem
 * @param fi information about the file or directory structure to publish
 * @param namespace namespace to publish the file in, NULL for no namespace
 * @param nid identifier to use for the publishd content in the namespace
 *        (can be NULL, must be NULL if namespace is NULL)
 * @param nuid update-identifier that will be used for future updates
 *        (can be NULL, must be NULL if namespace or nid is NULL)
 * @param options options for the publication
 * @return context that can be used to control the publish operation
 */
struct GNUNET_FS_PublishContext *
GNUNET_FS_publish_start (struct GNUNET_FS_Handle *h,
                         struct GNUNET_FS_FileInformation *fi,
                         struct GNUNET_FS_Namespace *namespace, const char *nid,
                         const char *nuid,
                         enum GNUNET_FS_PublishOptions options)
{
  struct GNUNET_FS_PublishContext *ret;
  struct GNUNET_DATASTORE_Handle *dsh;

  GNUNET_assert (NULL != h);
  if (0 == (options & GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY))
  {
    dsh = GNUNET_DATASTORE_connect (h->cfg);
    if (NULL == dsh)
      return NULL;
  }
  else
  {
    dsh = NULL;
  }
  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_PublishContext));
  ret->dsh = dsh;
  ret->h = h;
  ret->fi = fi;
  ret->namespace = namespace;
  ret->options = options;
  if (namespace != NULL)
  {
    namespace->rc++;
    GNUNET_assert (NULL != nid);
    ret->nid = GNUNET_strdup (nid);
    if (NULL != nuid)
      ret->nuid = GNUNET_strdup (nuid);
  }
  /* signal start */
  GNUNET_FS_file_information_inspect (ret->fi, &fip_signal_start, ret);
  ret->fi_pos = ret->fi;
  ret->top = GNUNET_FS_make_top (h, &GNUNET_FS_publish_signal_suspend_, ret);
  GNUNET_FS_publish_sync_ (ret);
  if (NULL != ret->dsh)
  {
    GNUNET_assert (NULL == ret->qre);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _
                ("Reserving space for %u entries and %llu bytes for publication\n"),
                (unsigned int) ret->reserve_entries,
                (unsigned long long) ret->reserve_space);
    ret->qre =
        GNUNET_DATASTORE_reserve (ret->dsh, ret->reserve_space,
                                  ret->reserve_entries, UINT_MAX, UINT_MAX,
                                  GNUNET_TIME_UNIT_FOREVER_REL, &finish_reserve,
                                  ret);
  }
  else
  {
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == ret->upload_task);
    ret->upload_task =
        GNUNET_SCHEDULER_add_with_priority
        (GNUNET_SCHEDULER_PRIORITY_BACKGROUND, &GNUNET_FS_publish_main_, ret);
  }
  return ret;
}


/**
 * Signal the FS's progress function that we are stopping
 * an upload.
 *
 * @param cls closure (of type "struct GNUNET_FS_PublishContext*")
 * @param fi the entry in the publish-structure
 * @param length length of the file or directory
 * @param meta metadata for the file or directory (can be modified)
 * @param uri pointer to the keywords that will be used for this entry (can be modified)
 * @param bo block options (can be modified)
 * @param do_index should we index?
 * @param client_info pointer to client context set upon creation (can be modified)
 * @return GNUNET_OK to continue (always)
 */
static int
fip_signal_stop (void *cls, struct GNUNET_FS_FileInformation *fi,
                 uint64_t length, struct GNUNET_CONTAINER_MetaData *meta,
                 struct GNUNET_FS_Uri **uri, struct GNUNET_FS_BlockOptions *bo,
                 int *do_index, void **client_info)
{
  struct GNUNET_FS_PublishContext *pc = cls;
  struct GNUNET_FS_ProgressInfo pi;
  uint64_t off;

  if (GNUNET_YES == pc->skip_next_fi_callback)
  {
    pc->skip_next_fi_callback = GNUNET_NO;
    return GNUNET_OK;
  }
  if (GNUNET_YES == GNUNET_FS_meta_data_test_for_directory (meta))
  {
    /* process entries in directory first */
    pc->skip_next_fi_callback = GNUNET_YES;
    GNUNET_FS_file_information_inspect (fi, &fip_signal_stop, pc);
  }
  if (fi->serialization != NULL)
  {
    GNUNET_FS_remove_sync_file_ (pc->h, GNUNET_FS_SYNC_PATH_FILE_INFO,
                                 fi->serialization);
    GNUNET_free (fi->serialization);
    fi->serialization = NULL;
  }
  off = (fi->chk_uri == NULL) ? 0 : length;
  pi.status = GNUNET_FS_STATUS_PUBLISH_STOPPED;
  GNUNET_break (NULL == GNUNET_FS_publish_make_status_ (&pi, pc, fi, off));
  *client_info = NULL;
  return GNUNET_OK;
}


/**
 * Stop an upload.  Will abort incomplete uploads (but
 * not remove blocks that have already been publishd) or
 * simply clean up the state for completed uploads.
 * Must NOT be called from within the event callback!
 *
 * @param pc context for the upload to stop
 */
void
GNUNET_FS_publish_stop (struct GNUNET_FS_PublishContext *pc)
{
  struct GNUNET_FS_ProgressInfo pi;
  uint64_t off;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Publish stop called\n");
  GNUNET_FS_end_top (pc->h, pc->top);
  if (NULL != pc->ksk_pc)
  {
    GNUNET_FS_publish_ksk_cancel (pc->ksk_pc);
    pc->ksk_pc = NULL;
  }
  if (NULL != pc->sks_pc)
  {
    GNUNET_FS_publish_sks_cancel (pc->sks_pc);
    pc->sks_pc = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != pc->upload_task)
  {
    GNUNET_SCHEDULER_cancel (pc->upload_task);
    pc->upload_task = GNUNET_SCHEDULER_NO_TASK;
  }
  pc->skip_next_fi_callback = GNUNET_YES;
  GNUNET_FS_file_information_inspect (pc->fi, &fip_signal_stop, pc);

  if (pc->fi->serialization != NULL)
  {
    GNUNET_FS_remove_sync_file_ (pc->h, GNUNET_FS_SYNC_PATH_FILE_INFO,
                                 pc->fi->serialization);
    GNUNET_free (pc->fi->serialization);
    pc->fi->serialization = NULL;
  }
  off = (pc->fi->chk_uri == NULL) ? 0 : GNUNET_ntohll (pc->fi->chk_uri->data.chk.file_length);

  if (pc->serialization != NULL)
  {
    GNUNET_FS_remove_sync_file_ (pc->h, GNUNET_FS_SYNC_PATH_MASTER_PUBLISH,
                                 pc->serialization);
    GNUNET_free (pc->serialization);
    pc->serialization = NULL;
  }
  if (NULL != pc->qre)
  {
    GNUNET_DATASTORE_cancel (pc->qre);
    pc->qre = NULL;
  }
  pi.status = GNUNET_FS_STATUS_PUBLISH_STOPPED;
  GNUNET_break (NULL == GNUNET_FS_publish_make_status_ (&pi, pc, pc->fi, off));
  publish_cleanup (pc);
}



/* end of fs_publish.c */
