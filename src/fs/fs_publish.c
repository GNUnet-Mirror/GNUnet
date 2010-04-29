/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_publish.c
 * @brief publish a file or directory in GNUnet
 * @see http://gnunet.org/encoding.php3
 * @author Krista Bennett
 * @author Christian Grothoff
 *
 * TODO:
 * - indexing cleanup: unindex on failure (can wait)
 * - persistence support (can wait)
 * - datastore reservation support (optimization)
 * - location URIs (publish with anonymity-level zero)
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "fs.h"
#include "fs_tree.h"

#define DEBUG_PUBLISH GNUNET_NO


/**
 * Context for "ds_put_cont".
 */
struct PutContCtx
{
  /**
   * Current publishing context.
   */
  struct GNUNET_FS_PublishContext *sc;

  /**
   * Specific file with the block.
   */
  struct GNUNET_FS_FileInformation *p;

  /**
   * Function to run next, if any (can be NULL).
   */
  GNUNET_SCHEDULER_Task cont;

  /**
   * Closure for cont.
   */
  void *cont_cls;
};


/**
 * Fill in all of the generic fields for 
 * a publish event and call the callback.
 *
 * @param pi structure to fill in
 * @param sc overall publishing context
 * @param p file information for the file being published
 * @param offset where in the file are we so far
 * @return value returned from callback
 */
void *
GNUNET_FS_publish_make_status_ (struct GNUNET_FS_ProgressInfo *pi,
				struct GNUNET_FS_PublishContext *sc,
				const struct GNUNET_FS_FileInformation *p,
				uint64_t offset)
{
  pi->value.publish.sc = sc;
  pi->value.publish.fi = p;
  pi->value.publish.cctx
    = p->client_info;
  pi->value.publish.pctx
    = (NULL == p->dir) ? NULL : p->dir->client_info;
  pi->value.publish.filename = p->filename;
  pi->value.publish.size 
    = (p->is_directory) ? p->data.dir.dir_size : p->data.file.file_size;
  pi->value.publish.eta 
    = GNUNET_TIME_calculate_eta (p->start_time,
				 offset,
				 pi->value.publish.size);
  pi->value.publish.completed = offset;
  pi->value.publish.duration = GNUNET_TIME_absolute_get_duration (p->start_time);
  pi->value.publish.anonymity = p->anonymity;
  return sc->h->upcb (sc->h->upcb_cls,
		      pi);
}


/**
 * Cleanup the publish context, we're done with it.
 *
 * @param pc struct to clean up after
 */
static void
publish_cleanup (struct GNUNET_FS_PublishContext *pc)
{
  GNUNET_FS_file_information_destroy (pc->fi, NULL, NULL);
  if (pc->namespace != NULL)
    GNUNET_FS_namespace_delete (pc->namespace, GNUNET_NO);
  GNUNET_free_non_null (pc->nid);  
  GNUNET_free_non_null (pc->nuid);
  GNUNET_free_non_null (pc->serialization);
  GNUNET_DATASTORE_disconnect (pc->dsh, GNUNET_NO);
  if (pc->client != NULL)
    GNUNET_CLIENT_disconnect (pc->client, GNUNET_NO);
  GNUNET_free (pc);
}


/**
 * Function called by the datastore API with
 * the result from the PUT request.
 *
 * @param cls our closure
 * @param success GNUNET_OK on success
 * @param msg error message (or NULL)
 */
static void
ds_put_cont (void *cls,
	     int success,
 	     const char *msg)
{
  struct PutContCtx *pcc = cls;
  struct GNUNET_FS_ProgressInfo pi;

  if (GNUNET_SYSERR == pcc->sc->in_network_wait)
    {
      /* we were aborted in the meantime,
	 finish shutdown! */
      publish_cleanup (pcc->sc);
      return;
    }
  GNUNET_assert (GNUNET_YES == pcc->sc->in_network_wait);
  pcc->sc->in_network_wait = GNUNET_NO;
  if (GNUNET_OK != success)
    {
      GNUNET_asprintf (&pcc->p->emsg, 
		       _("Upload failed: %s"),
		       msg);
      GNUNET_FS_file_information_sync (pcc->p);
      pi.status = GNUNET_FS_STATUS_PUBLISH_ERROR;
      pi.value.publish.eta = GNUNET_TIME_UNIT_FOREVER_REL;
      pi.value.publish.specifics.error.message = pcc->p->emsg;
      pcc->p->client_info = GNUNET_FS_publish_make_status_ (&pi, pcc->sc, pcc->p, 0);
    }
  GNUNET_FS_file_information_sync (pcc->p);
  if (NULL != pcc->cont)
    pcc->sc->upload_task 
      = GNUNET_SCHEDULER_add_with_priority (pcc->sc->h->sched,
					    GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
					    pcc->cont,
					    pcc->cont_cls);
  GNUNET_free (pcc);
}


/**
 * Generate the callback that signals clients
 * that a file (or directory) has been completely
 * published.
 *
 * @param p the completed upload
 * @param sc context of the publication
 */
static void 
signal_publish_completion (struct GNUNET_FS_FileInformation *p,
			   struct GNUNET_FS_PublishContext *sc)
{
  struct GNUNET_FS_ProgressInfo pi;
  
  pi.status = GNUNET_FS_STATUS_PUBLISH_COMPLETED;
  pi.value.publish.eta = GNUNET_TIME_UNIT_ZERO;
  pi.value.publish.specifics.completed.chk_uri = p->chk_uri;
  p->client_info = GNUNET_FS_publish_make_status_ (&pi, sc, p,
					GNUNET_ntohll (p->chk_uri->data.chk.file_length));
}


/**
 * Generate the callback that signals clients
 * that a file (or directory) has encountered
 * a problem during publication.
 *
 * @param p the upload that had trouble
 * @param sc context of the publication
 * @param emsg error message
 */
static void 
signal_publish_error (struct GNUNET_FS_FileInformation *p,
		      struct GNUNET_FS_PublishContext *sc,
		      const char *emsg)
{
  struct GNUNET_FS_ProgressInfo pi;
  
  p->emsg = GNUNET_strdup (emsg);
  pi.status = GNUNET_FS_STATUS_PUBLISH_ERROR;
  pi.value.publish.eta = GNUNET_TIME_UNIT_FOREVER_REL;
  pi.value.publish.specifics.error.message =emsg;
  p->client_info = GNUNET_FS_publish_make_status_ (&pi, sc, p, 0);
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
publish_sblocks_cont (void *cls,
		      const struct GNUNET_FS_Uri *uri,
		      const char *emsg)
{
  struct GNUNET_FS_PublishContext *sc = cls;
  if (NULL != emsg)
    {
      signal_publish_error (sc->fi,
			    sc,
			    emsg);
      return;
    }  
  // FIXME: release the datastore reserve here!
  signal_publish_completion (sc->fi, sc);
  sc->all_done = GNUNET_YES;
}


/**
 * We are almost done publishing the structure,
 * add SBlocks (if needed).
 *
 * @param sc overall upload data
 */
static void
publish_sblock (struct GNUNET_FS_PublishContext *sc)
{
  if (NULL != sc->namespace)
    GNUNET_FS_publish_sks (sc->h,
			   sc->namespace,
			   sc->nid,
			   sc->nuid,
			   sc->fi->meta,
			   sc->fi->chk_uri,
			   sc->fi->expirationTime,
			   sc->fi->anonymity,
			   sc->fi->priority,
			   sc->options,
			   &publish_sblocks_cont,
			   sc);
  else
    publish_sblocks_cont (sc, NULL, NULL);
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
publish_kblocks_cont (void *cls,
		      const struct GNUNET_FS_Uri *uri,
		      const char *emsg)
{
  struct GNUNET_FS_PublishContext *sc = cls;
  struct GNUNET_FS_FileInformation *p = sc->fi_pos;

  if (NULL != emsg)
    {
      signal_publish_error (p, sc, emsg);
      sc->upload_task 
	= GNUNET_SCHEDULER_add_with_priority (sc->h->sched,
					      GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
					      &GNUNET_FS_publish_main_,
					      sc);
      return;
    }
  GNUNET_FS_file_information_sync (p);
  if (NULL != p->dir)
    signal_publish_completion (p, sc);
  /* move on to next file */
  if (NULL != p->next)
    sc->fi_pos = p->next;
  else
    sc->fi_pos = p->dir;
  sc->upload_task 
    = GNUNET_SCHEDULER_add_with_priority (sc->h->sched,
					  GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
					  &GNUNET_FS_publish_main_,
					  sc);
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
block_reader (void *cls,
	      uint64_t offset,
	      size_t max, 
	      void *buf,
	      char **emsg)
{
  struct GNUNET_FS_PublishContext *sc = cls;
  struct GNUNET_FS_FileInformation *p;
  size_t pt_size;
  const char *dd;

  p = sc->fi_pos;
  if (p->is_directory)
    {
      pt_size = GNUNET_MIN(max,
			   p->data.dir.dir_size - offset);
      dd = p->data.dir.dir_data;
      memcpy (buf,
	      &dd[offset],
	      pt_size);
    }
  else
    {
      pt_size = GNUNET_MIN(max,
			   p->data.file.file_size - offset);
      if (pt_size == 0)
	return 0; /* calling reader with pt_size==0 
		     might free buf, so don't! */
      if (pt_size !=
	  p->data.file.reader (p->data.file.reader_cls,
			       offset,
			       pt_size,
			       buf,
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
encode_cont (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_PublishContext *sc = cls;
  struct GNUNET_FS_FileInformation *p;
  struct GNUNET_FS_ProgressInfo pi;
  char *emsg;
  
  p = sc->fi_pos;
  GNUNET_FS_tree_encoder_finish (p->te,
				 &p->chk_uri,
				 &emsg);
  p->te = NULL;
  if (NULL != emsg)
    {
      GNUNET_asprintf (&p->emsg, 
		       _("Upload failed: %s"),
		       emsg);
      GNUNET_free (emsg);
      GNUNET_FS_file_information_sync (p);
      pi.status = GNUNET_FS_STATUS_PUBLISH_ERROR;
      pi.value.publish.eta = GNUNET_TIME_UNIT_FOREVER_REL;
      pi.value.publish.specifics.error.message = p->emsg;
      p->client_info =  GNUNET_FS_publish_make_status_ (&pi, sc, p, 0);
    }
  /* continue with main */
  sc->upload_task 
    = GNUNET_SCHEDULER_add_with_priority (sc->h->sched,
					  GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
					  &GNUNET_FS_publish_main_,
					  sc);
}


/**
 * Function called asking for the current (encoded)
 * block to be processed.  After processing the
 * client should either call "GNUNET_FS_tree_encode_next"
 * or (on error) "GNUNET_FS_tree_encode_finish".
 *
 * @param cls closure
 * @param query the query for the block (key for lookup in the datastore)
 * @param offset offset of the block in the file
 * @param type type of the block (IBLOCK or DBLOCK)
 * @param block the (encrypted) block
 * @param block_size size of block (in bytes)
 */
static void 
block_proc (void *cls,
	    const GNUNET_HashCode *query,
	    uint64_t offset,
	    enum GNUNET_BLOCK_Type type,
	    const void *block,
	    uint16_t block_size)
{
  struct GNUNET_FS_PublishContext *sc = cls;
  struct GNUNET_FS_FileInformation *p;
  struct PutContCtx * dpc_cls;
  struct OnDemandBlock odb;

  p = sc->fi_pos;
  if (NULL == sc->dsh)
    {
      sc->upload_task
	= GNUNET_SCHEDULER_add_with_priority (sc->h->sched,
					      GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
					      &GNUNET_FS_publish_main_,
					      sc);
      return;
    }
  
  GNUNET_assert (GNUNET_NO == sc->in_network_wait);
  sc->in_network_wait = GNUNET_YES;
  dpc_cls = GNUNET_malloc(sizeof(struct PutContCtx));
  dpc_cls->cont = &GNUNET_FS_publish_main_;
  dpc_cls->cont_cls = sc;
  dpc_cls->sc = sc;
  dpc_cls->p = p;
  if ( (! p->is_directory) &&
       (GNUNET_YES == p->data.file.do_index) &&
       (type == GNUNET_BLOCK_TYPE_DBLOCK) )
    {
#if DEBUG_PUBLISH
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Indexing block `%s' for offset %llu with index size %u\n",
		  GNUNET_h2s (query),
		  (unsigned long long) offset,
		  sizeof (struct OnDemandBlock));
#endif
      odb.offset = GNUNET_htonll (offset);
      odb.file_id = p->data.file.file_id;
      GNUNET_DATASTORE_put (sc->dsh,
			    sc->rid,
			    query,
			    sizeof(struct OnDemandBlock),
			    &odb,
			    GNUNET_BLOCK_TYPE_ONDEMAND,
			    p->priority,
			    p->anonymity,
			    p->expirationTime,
			    GNUNET_CONSTANTS_SERVICE_TIMEOUT,
			    &ds_put_cont,
			    dpc_cls);	  
      return;
    }
#if DEBUG_PUBLISH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Publishing block `%s' for offset %llu with size %u\n",
	      GNUNET_h2s (query),
	      (unsigned long long) offset,
	      (unsigned int) block_size);
#endif
  GNUNET_DATASTORE_put (sc->dsh,
			sc->rid,
			query,
			block_size,
			block,
			type,
			p->priority,
			p->anonymity,
			p->expirationTime,
			GNUNET_CONSTANTS_SERVICE_TIMEOUT,
			&ds_put_cont,
			dpc_cls);
}


/**
 * Function called with information about our
 * progress in computing the tree encoding.
 *
 * @param cls closure
 * @param offset where are we in the file
 * @param pt_block plaintext of the currently processed block
 * @param pt_size size of pt_block
 * @param depth depth of the block in the tree
 */
static void 
progress_proc (void *cls,
	       uint64_t offset,
	       const void *pt_block,
	       size_t pt_size,
	       unsigned int depth)
{		       
  struct GNUNET_FS_PublishContext *sc = cls;
  struct GNUNET_FS_FileInformation *p;
  struct GNUNET_FS_ProgressInfo pi;

  p = sc->fi_pos;
  pi.status = GNUNET_FS_STATUS_PUBLISH_PROGRESS;
  pi.value.publish.specifics.progress.data = pt_block;
  pi.value.publish.specifics.progress.offset = offset;
  pi.value.publish.specifics.progress.data_len = pt_size;
  pi.value.publish.specifics.progress.depth = depth;
  p->client_info = GNUNET_FS_publish_make_status_ (&pi, sc, p, offset);
}


/**
 * We are uploading a file or directory; load (if necessary) the next
 * block into memory, encrypt it and send it to the FS service.  Then
 * continue with the main task.
 *
 * @param sc overall upload data
 */
static void
publish_content (struct GNUNET_FS_PublishContext *sc) 
{
  struct GNUNET_FS_FileInformation *p;
  char *emsg;
  struct GNUNET_FS_DirectoryBuilder *db;
  struct GNUNET_FS_FileInformation *dirpos;
  void *raw_data;
  uint64_t size;

  p = sc->fi_pos;
  if (NULL == p->te)
    {
      if (p->is_directory)
	{
	  db = GNUNET_FS_directory_builder_create (p->meta);
	  dirpos = p->data.dir.entries;
	  while (NULL != dirpos)
	    {
	      if (dirpos->is_directory)
		{
		  raw_data = dirpos->data.dir.dir_data;
		  dirpos->data.dir.dir_data = NULL;
		}
	      else
		{
		  raw_data = NULL;
		  if ( (dirpos->data.file.file_size < MAX_INLINE_SIZE) &&
		       (dirpos->data.file.file_size > 0) )
		    {
		      raw_data = GNUNET_malloc (dirpos->data.file.file_size);
		      emsg = NULL;
		      if (dirpos->data.file.file_size !=
			  dirpos->data.file.reader (dirpos->data.file.reader_cls,
						    0,
						    dirpos->data.file.file_size,
						    raw_data,
						    &emsg))
			{
			  GNUNET_free_non_null (emsg);
			  GNUNET_free (raw_data);
			  raw_data = NULL;
			} 
		    }
		}
	      GNUNET_FS_directory_builder_add (db,
					       dirpos->chk_uri,
					       dirpos->meta,
					       raw_data);
	      GNUNET_free_non_null (raw_data);
	      dirpos = dirpos->next;
	    }
	  GNUNET_FS_directory_builder_finish (db,
					      &p->data.dir.dir_size,
					      &p->data.dir.dir_data);
	}
      size = (p->is_directory) 
	? p->data.dir.dir_size 
	: p->data.file.file_size;
      p->te = GNUNET_FS_tree_encoder_create (sc->h,
					     size,
					     sc,
					     &block_reader,
					     &block_proc,
					     &progress_proc,
					     &encode_cont);

    }
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
process_index_start_response (void *cls,
			      const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_FS_PublishContext *sc = cls;
  struct GNUNET_FS_FileInformation *p;
  const char *emsg;
  uint16_t msize;

  GNUNET_CLIENT_disconnect (sc->client, GNUNET_NO);
  sc->client = NULL;
  p = sc->fi_pos;
  if (msg == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Can not index file `%s': %s.  Will try to insert instead.\n"),
		  p->filename,
		  _("timeout on index-start request to `fs' service"));
      p->data.file.do_index = GNUNET_NO;
      publish_content (sc);
      return;
    }
  if (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_FS_INDEX_START_OK)
    {
      msize = ntohs (msg->size);
      emsg = (const char *) &msg[1];
      if ( (msize <= sizeof (struct GNUNET_MessageHeader)) ||
	   (emsg[msize - sizeof(struct GNUNET_MessageHeader) - 1] != '\0') )
	emsg = gettext_noop ("unknown error");
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Can not index file `%s': %s.  Will try to insert instead.\n"),
		  p->filename,
		  gettext (emsg));
      p->data.file.do_index = GNUNET_NO;
      publish_content (sc);
      return;
    }
  p->data.file.index_start_confirmed = GNUNET_YES;
  /* success! continue with indexing */
  publish_content (sc);
}


/**
 * Function called once the hash computation over an
 * indexed file has completed.
 *
 * @param cls closure, our publishing context
 * @param res resulting hash, NULL on error
 */
static void 
hash_for_index_cb (void *cls,
		   const GNUNET_HashCode *
		   res)
{
  struct GNUNET_FS_PublishContext *sc = cls;
  struct GNUNET_FS_FileInformation *p;
  struct IndexStartMessage *ism;
  size_t slen;
  struct GNUNET_CLIENT_Connection *client;
  uint32_t dev;
  uint64_t ino;
  char *fn;

  p = sc->fi_pos;
  if (NULL == res) 
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Can not index file `%s': %s.  Will try to insert instead.\n"),
		  p->filename,
		  _("failed to compute hash"));
      p->data.file.do_index = GNUNET_NO;
      publish_content (sc);
      return;
    }
  if (GNUNET_YES == p->data.file.index_start_confirmed)
    {
      publish_content (sc);
      return;
    }
  fn = GNUNET_STRINGS_filename_expand (p->filename);
  slen = strlen (fn) + 1;
  if (slen > GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof(struct IndexStartMessage))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Can not index file `%s': %s.  Will try to insert instead.\n"),
		  fn,
		  _("filename too long"));
      GNUNET_free (fn);
      p->data.file.do_index = GNUNET_NO;
      publish_content (sc);
      return;
    }
#if DEBUG_PUBLISH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Hash of indexed file `%s' is `%s'\n",
	      p->data.file.filename,
	      GNUNET_h2s (res));
#endif
  client = GNUNET_CLIENT_connect (sc->h->sched,
				  "fs",
				  sc->h->cfg);
  if (NULL == client)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Can not index file `%s': %s.  Will try to insert instead.\n"),
		  p->filename,
		  _("could not connect to `fs' service"));
      p->data.file.do_index = GNUNET_NO;
      publish_content (sc);
      GNUNET_free (fn);
      return;
    }
  p->data.file.file_id = *res;
  p->data.file.have_hash = GNUNET_YES;
  ism = GNUNET_malloc (sizeof(struct IndexStartMessage) +
		       slen);
  ism->header.size = htons(sizeof(struct IndexStartMessage) +
			   slen);
  ism->header.type = htons(GNUNET_MESSAGE_TYPE_FS_INDEX_START);
  if (GNUNET_OK ==
      GNUNET_DISK_file_get_identifiers (p->filename,
					&dev,
					&ino))
    {
      ism->device = htonl (dev);
      ism->inode = GNUNET_htonll(ino);
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Failed to get file identifiers for `%s'\n"),
		  p->filename);
    }
  ism->file_id = *res;
  memcpy (&ism[1],
	  fn,
	  slen);
  GNUNET_free (fn);
  sc->client = client;
  GNUNET_break (GNUNET_YES ==
		GNUNET_CLIENT_transmit_and_get_response (client,
							 &ism->header,
							 GNUNET_TIME_UNIT_FOREVER_REL,
							 GNUNET_YES,
							 &process_index_start_response,
							 sc));
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
  struct GNUNET_FS_PublishContext *sc = cls;
  struct GNUNET_FS_ProgressInfo pi;
  struct GNUNET_FS_FileInformation *p;
  char *fn;

  sc->upload_task = GNUNET_SCHEDULER_NO_TASK;  
  p = sc->fi_pos;
  if (NULL == p)
    {
      /* upload of entire hierarchy complete,
	 publish namespace entries */
      publish_sblock (sc);
      return;
    }
  /* find starting position */
  while ( (p->is_directory) &&
	  (NULL != p->data.dir.entries) &&
	  (NULL == p->emsg) &&
	  (NULL == p->data.dir.entries->chk_uri) )
    {
      p = p->data.dir.entries;
      sc->fi_pos = p;
    }
  /* abort on error */
  if (NULL != p->emsg)
    {
      /* error with current file, abort all
	 related files as well! */
      while (NULL != p->dir)
	{
	  fn = GNUNET_CONTAINER_meta_data_get_by_type (p->meta,
						       EXTRACTOR_METATYPE_FILENAME);
	  p = p->dir;
	  if (fn != NULL)
	    {
	      GNUNET_asprintf (&p->emsg, 
			       _("Recursive upload failed at `%s': %s"),
			       fn,
			       p->emsg);
	      GNUNET_free (fn);
	    }
	  else
	    {
	      GNUNET_asprintf (&p->emsg, 
			       _("Recursive upload failed: %s"),
			       p->emsg);	      
	    }
	  GNUNET_FS_file_information_sync (p);
	  pi.status = GNUNET_FS_STATUS_PUBLISH_ERROR;
	  pi.value.publish.eta = GNUNET_TIME_UNIT_FOREVER_REL;
	  pi.value.publish.specifics.error.message = p->emsg;
	  p->client_info = GNUNET_FS_publish_make_status_ (&pi, sc, p, 0);
	}
      sc->all_done = GNUNET_YES;
      return;
    }
  /* handle completion */
  if (NULL != p->chk_uri)
    {
      /* upload of "p" complete, publish KBlocks! */
      if (p->keywords != NULL)
	{
	  GNUNET_FS_publish_ksk (sc->h,
				 p->keywords,
				 p->meta,
				 p->chk_uri,
				 p->expirationTime,
				 p->anonymity,
				 p->priority,
				 sc->options,
				 &publish_kblocks_cont,
				 sc);
	}
      else
	{
	  publish_kblocks_cont (sc,
				p->chk_uri,
				NULL);
	}
      return;
    }
  if ( (!p->is_directory) &&
       (p->data.file.do_index) )
    {
      if (NULL == p->filename)
	{
	  p->data.file.do_index = GNUNET_NO;
	  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		      _("Can not index file `%s': %s.  Will try to insert instead.\n"),
		      "<no-name>",
		      _("needs to be an actual file"));
	  publish_content (sc);
	  return;
	}      
      if (p->data.file.have_hash)
	hash_for_index_cb (sc,
			   &p->data.file.file_id);
      else
	{
	  p->start_time = GNUNET_TIME_absolute_get ();
	  GNUNET_CRYPTO_hash_file (sc->h->sched,
				   GNUNET_SCHEDULER_PRIORITY_IDLE,
				   p->filename,
				   HASHING_BLOCKSIZE,
				   &hash_for_index_cb,
				   sc);
	}
      return;
    }
  publish_content (sc);
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
 * @param anonymity pointer to selected anonymity level (can be modified)
 * @param priority pointer to selected priority (can be modified)
 * @param expirationTime pointer to selected expiration time (can be modified)
 * @param client_info pointer to client context set upon creation (can be modified)
 * @return GNUNET_OK to continue (always)
 */
static int
fip_signal_start(void *cls,
		 struct GNUNET_FS_FileInformation *fi,
		 uint64_t length,
		 struct GNUNET_CONTAINER_MetaData *meta,
		 struct GNUNET_FS_Uri **uri,
		 uint32_t *anonymity,
		 uint32_t *priority,
		 struct GNUNET_TIME_Absolute *expirationTime,
		 void **client_info)
{
  struct GNUNET_FS_PublishContext *sc = cls;
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_PUBLISH_START;
  *client_info = GNUNET_FS_publish_make_status_ (&pi, sc, fi, 0);
  return GNUNET_OK;
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
			 struct GNUNET_FS_Namespace *namespace,
			 const char *nid,
			 const char *nuid,
			 enum GNUNET_FS_PublishOptions options)
{
  struct GNUNET_FS_PublishContext *ret;
  struct GNUNET_DATASTORE_Handle *dsh;

  if (0 == (options & GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY))
    {
      dsh = GNUNET_DATASTORE_connect (h->cfg,
				      h->sched);
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
  if (namespace != NULL)
    {
      namespace->rc++;
      GNUNET_assert (NULL != nid);
      ret->nid = GNUNET_strdup (nid);
      if (NULL != nuid)
	ret->nuid = GNUNET_strdup (nuid);
    }
  // FIXME: make upload persistent!

  /* signal start */
  GNUNET_FS_file_information_inspect (ret->fi,
				      &fip_signal_start,
				      ret);
  ret->fi_pos = ret->fi;

  // FIXME: calculate space needed for "fi"
  // and reserve as first task (then trigger
  // "publish_main" from that continuation)!
  ret->upload_task 
    = GNUNET_SCHEDULER_add_with_priority (h->sched,
					  GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
					  &GNUNET_FS_publish_main_,
					  ret);
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
 * @param anonymity pointer to selected anonymity level (can be modified)
 * @param priority pointer to selected priority (can be modified)
 * @param expirationTime pointer to selected expiration time (can be modified)
 * @param client_info pointer to client context set upon creation (can be modified)
 * @return GNUNET_OK to continue (always)
 */
static int
fip_signal_stop(void *cls,
		struct GNUNET_FS_FileInformation *fi,
		uint64_t length,
		struct GNUNET_CONTAINER_MetaData *meta,
		struct GNUNET_FS_Uri **uri,
		uint32_t *anonymity,
		uint32_t *priority,
		struct GNUNET_TIME_Absolute *expirationTime,
		void **client_info)
{
  struct GNUNET_FS_PublishContext*sc = cls;
  struct GNUNET_FS_ProgressInfo pi;
  uint64_t off;

  if (fi->serialization != NULL) 
    {
      if (0 != UNLINK (fi->serialization))
	{
	  GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
				    "unlink",
				    fi->serialization); 
	}
      GNUNET_free (fi->serialization);
      fi->serialization = NULL;
    }
  off = (fi->chk_uri == NULL) ? 0 : length;
  pi.status = GNUNET_FS_STATUS_PUBLISH_STOPPED;
  GNUNET_break (NULL == GNUNET_FS_publish_make_status_ (&pi, sc, fi, off));
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
  if (GNUNET_SCHEDULER_NO_TASK != pc->upload_task)
    GNUNET_SCHEDULER_cancel (pc->h->sched, pc->upload_task);
  if (pc->serialization != NULL) 
    {
      if (0 != UNLINK (pc->serialization))
	GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
				  "unlink",
				  pc->serialization);          
      GNUNET_free (pc->serialization);
      pc->serialization = NULL;
    }
  GNUNET_FS_file_information_inspect (pc->fi,
				      &fip_signal_stop,
				      pc);
  if (GNUNET_YES == pc->in_network_wait)
    {
      pc->in_network_wait = GNUNET_SYSERR;
      return;
    }
  publish_cleanup (pc);
}


/**
 * Context for the KSK publication.
 */
struct PublishKskContext
{

  /**
   * Keywords to use.
   */
  struct GNUNET_FS_Uri *ksk_uri;

  /**
   * Global FS context.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * The master block that we are sending
   * (in plaintext), has "mdsize+slen" more
   * bytes than the struct would suggest.
   */
  struct KBlock *kb;

  /**
   * Buffer of the same size as "kb" for
   * the encrypted version.
   */ 
  struct KBlock *cpy;

  /**
   * Handle to the datastore, NULL if we are just
   * simulating.
   */
  struct GNUNET_DATASTORE_Handle *dsh;

  /**
   * Function to call once we're done.
   */
  GNUNET_FS_PublishContinuation cont;

  /**
   * Closure for cont.
   */ 
  void *cont_cls;

  /**
   * When should the KBlocks expire?
   */
  struct GNUNET_TIME_Absolute expirationTime;

  /**
   * Size of the serialized metadata.
   */
  ssize_t mdsize;

  /**
   * Size of the (CHK) URI as a string.
   */
  size_t slen;

  /**
   * Keyword that we are currently processing.
   */
  unsigned int i;

  /**
   * Anonymity level for the KBlocks.
   */
  uint32_t anonymity;

  /**
   * Priority for the KBlocks.
   */
  uint32_t priority;
};


/**
 * Continuation of "GNUNET_FS_publish_ksk" that performs
 * the actual publishing operation (iterating over all
 * of the keywords).
 *
 * @param cls closure of type "struct PublishKskContext*"
 * @param tc unused
 */
static void
publish_ksk_cont (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function called by the datastore API with
 * the result from the PUT request.
 *
 * @param cls closure of type "struct PublishKskContext*"
 * @param success GNUNET_OK on success
 * @param msg error message (or NULL)
 */
static void
kb_put_cont (void *cls,
	     int success,
 	     const char *msg)
{
  struct PublishKskContext *pkc = cls;

  if (GNUNET_OK != success)
    {
      GNUNET_DATASTORE_disconnect (pkc->dsh, GNUNET_NO);
      GNUNET_free (pkc->cpy);
      GNUNET_free (pkc->kb);
      pkc->cont (pkc->cont_cls,
		 NULL,
		 msg);
      GNUNET_FS_uri_destroy (pkc->ksk_uri);
      GNUNET_free (pkc);
      return;
    }
  GNUNET_SCHEDULER_add_continuation (pkc->h->sched,
				     &publish_ksk_cont,
				     pkc,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


/**
 * Continuation of "GNUNET_FS_publish_ksk" that performs the actual
 * publishing operation (iterating over all of the keywords).
 *
 * @param cls closure of type "struct PublishKskContext*"
 * @param tc unused
 */
static void
publish_ksk_cont (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PublishKskContext *pkc = cls;
  const char *keyword;
  GNUNET_HashCode key;
  GNUNET_HashCode query;
  struct GNUNET_CRYPTO_AesSessionKey skey;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  struct GNUNET_CRYPTO_RsaPrivateKey *pk;


  if ( (pkc->i == pkc->ksk_uri->data.ksk.keywordCount) ||
       (NULL == pkc->dsh) )
    {
      if (NULL != pkc->dsh)
	GNUNET_DATASTORE_disconnect (pkc->dsh, GNUNET_NO);
      GNUNET_free (pkc->cpy);
      GNUNET_free (pkc->kb);
      pkc->cont (pkc->cont_cls,
		 pkc->ksk_uri,
		 NULL);
      GNUNET_FS_uri_destroy (pkc->ksk_uri);
      GNUNET_free (pkc);
      return;
    }
  keyword = pkc->ksk_uri->data.ksk.keywords[pkc->i++];
  /* first character of keyword indicates if it is
     mandatory or not -- ignore for hashing */
  GNUNET_CRYPTO_hash (&keyword[1], strlen (&keyword[1]), &key);
  GNUNET_CRYPTO_hash_to_aes_key (&key, &skey, &iv);
  GNUNET_CRYPTO_aes_encrypt (&pkc->kb[1],
			     pkc->slen + pkc->mdsize,
			     &skey,
			     &iv,
			     &pkc->cpy[1]);
  pk = GNUNET_CRYPTO_rsa_key_create_from_hash (&key);
  GNUNET_CRYPTO_rsa_key_get_public (pk, &pkc->cpy->keyspace);
  GNUNET_CRYPTO_hash (&pkc->cpy->keyspace,
		      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
		      &query);
  GNUNET_assert (GNUNET_OK == 
		 GNUNET_CRYPTO_rsa_sign (pk,
					 &pkc->cpy->purpose,
					 &pkc->cpy->signature));
  GNUNET_CRYPTO_rsa_key_free (pk);
  GNUNET_DATASTORE_put (pkc->dsh,
			0,
			&query,
			pkc->mdsize + 
			sizeof (struct KBlock) + 
			pkc->slen,
			pkc->cpy,
			GNUNET_BLOCK_TYPE_KBLOCK, 
			pkc->priority,
			pkc->anonymity,
			pkc->expirationTime,
			GNUNET_CONSTANTS_SERVICE_TIMEOUT,
			&kb_put_cont,
			pkc);
}


/**
 * Publish a CHK under various keywords on GNUnet.
 *
 * @param h handle to the file sharing subsystem
 * @param ksk_uri keywords to use
 * @param meta metadata to use
 * @param uri URI to refer to in the KBlock
 * @param expirationTime when the KBlock expires
 * @param anonymity anonymity level for the KBlock
 * @param priority priority for the KBlock
 * @param options publication options
 * @param cont continuation
 * @param cont_cls closure for cont
 */
void
GNUNET_FS_publish_ksk (struct GNUNET_FS_Handle *h,
		       const struct GNUNET_FS_Uri *ksk_uri,
		       const struct GNUNET_CONTAINER_MetaData *meta,
		       const struct GNUNET_FS_Uri *uri,
		       struct GNUNET_TIME_Absolute expirationTime,
		       uint32_t anonymity,
		       uint32_t priority,
		       enum GNUNET_FS_PublishOptions options,
		       GNUNET_FS_PublishContinuation cont,
		       void *cont_cls)
{
  struct PublishKskContext *pkc;
  char *uris;
  size_t size;
  char *kbe;
  char *sptr;

  pkc = GNUNET_malloc (sizeof (struct PublishKskContext));
  pkc->h = h;
  pkc->expirationTime = expirationTime;
  pkc->anonymity = anonymity;
  pkc->priority = priority;
  pkc->cont = cont;
  pkc->cont_cls = cont_cls;
  if (0 == (options & GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY))
    {
      pkc->dsh = GNUNET_DATASTORE_connect (h->cfg,
					   h->sched);
      if (pkc->dsh == NULL)
	{
	  cont (cont_cls, NULL, _("Could not connect to datastore."));
	  GNUNET_free (pkc);
	  return;
	}
    }
  if (meta == NULL)
    pkc->mdsize = 0;
  else
    pkc->mdsize = GNUNET_CONTAINER_meta_data_get_serialized_size (meta);
  GNUNET_assert (pkc->mdsize >= 0);
  uris = GNUNET_FS_uri_to_string (uri);
  pkc->slen = strlen (uris) + 1;
  size = pkc->mdsize + sizeof (struct KBlock) + pkc->slen;
  if (size > MAX_KBLOCK_SIZE)
    {
      size = MAX_KBLOCK_SIZE;
      pkc->mdsize = size - sizeof (struct KBlock) - pkc->slen;
    }
  pkc->kb = GNUNET_malloc (size);
  kbe = (char *) &pkc->kb[1];
  memcpy (kbe, uris, pkc->slen);
  GNUNET_free (uris);
  sptr = &kbe[pkc->slen];
  if (meta != NULL)
    pkc->mdsize = GNUNET_CONTAINER_meta_data_serialize (meta,
							&sptr,
							pkc->mdsize,
							GNUNET_CONTAINER_META_DATA_SERIALIZE_PART);
  if (pkc->mdsize == -1)
    {
      GNUNET_break (0);
      GNUNET_free (pkc->kb);
      if (pkc->dsh != NULL)
	GNUNET_DATASTORE_disconnect (pkc->dsh, GNUNET_NO);
      cont (cont_cls, NULL, _("Internal error."));
      GNUNET_free (pkc);
      return;
    }
  size = sizeof (struct KBlock) + pkc->slen + pkc->mdsize;

  pkc->cpy = GNUNET_malloc (size);
  pkc->cpy->purpose.size = htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) + 
				  sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) +
				  pkc->mdsize + 
				  pkc->slen);
  pkc->cpy->purpose.purpose = htonl(GNUNET_SIGNATURE_PURPOSE_FS_KBLOCK);
  pkc->ksk_uri = GNUNET_FS_uri_dup (ksk_uri);
  GNUNET_SCHEDULER_add_continuation (h->sched,
				     &publish_ksk_cont,
				     pkc,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


/**
 * Context for the SKS publication.
 */
struct PublishSksContext
{

  /**
   * Global FS context.
   */
  struct GNUNET_FS_Uri *uri;

  /**
   * Handle to the datastore.
   */
  struct GNUNET_DATASTORE_Handle *dsh;

  /**
   * Function to call once we're done.
   */
  GNUNET_FS_PublishContinuation cont;

  /**
   * Closure for cont.
   */ 
  void *cont_cls;

};


/**
 * Function called by the datastore API with
 * the result from the PUT (SBlock) request.
 *
 * @param cls closure of type "struct PublishSksContext*"
 * @param success GNUNET_OK on success
 * @param msg error message (or NULL)
 */
static void
sb_put_cont (void *cls,
	     int success,
 	     const char *msg)
{
  struct PublishSksContext *psc = cls;

  if (NULL != psc->dsh)
    GNUNET_DATASTORE_disconnect (psc->dsh, GNUNET_NO);
  if (GNUNET_OK != success)
    psc->cont (psc->cont_cls,
	       NULL,
	       msg);
  else
    psc->cont (psc->cont_cls,
	       psc->uri,
	       NULL);
  GNUNET_FS_uri_destroy (psc->uri);
  GNUNET_free (psc);
}


/**
 * Publish an SBlock on GNUnet.
 *
 * @param h handle to the file sharing subsystem
 * @param namespace namespace to publish in
 * @param identifier identifier to use
 * @param update update identifier to use
 * @param meta metadata to use
 * @param uri URI to refer to in the SBlock
 * @param expirationTime when the SBlock expires
 * @param anonymity anonymity level for the SBlock
 * @param priority priority for the SBlock
 * @param options publication options
 * @param cont continuation
 * @param cont_cls closure for cont
 */
void
GNUNET_FS_publish_sks (struct GNUNET_FS_Handle *h,
		       struct GNUNET_FS_Namespace *namespace,
		       const char *identifier,
		       const char *update,
		       const struct GNUNET_CONTAINER_MetaData *meta,
		       const struct GNUNET_FS_Uri *uri,
		       struct GNUNET_TIME_Absolute expirationTime,
		       uint32_t anonymity,
		       uint32_t priority,
		       enum GNUNET_FS_PublishOptions options,
		       GNUNET_FS_PublishContinuation cont,
		       void *cont_cls)
{
  struct PublishSksContext *psc;
  struct GNUNET_CRYPTO_AesSessionKey sk;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  struct GNUNET_FS_Uri *sks_uri;
  char *uris;
  size_t size;
  size_t slen;
  size_t nidlen;
  size_t idlen;
  ssize_t mdsize;
  struct SBlock *sb;
  struct SBlock *sb_enc;
  char *dest;
  struct GNUNET_CONTAINER_MetaData *mmeta;
  GNUNET_HashCode key;         /* hash of thisId = key */
  GNUNET_HashCode id;          /* hash of hc = identifier */
  GNUNET_HashCode query;       /* id ^ nsid = DB query */

  if (NULL == meta)
    mmeta = GNUNET_CONTAINER_meta_data_create ();
  else
    mmeta = GNUNET_CONTAINER_meta_data_duplicate (meta);
  uris = GNUNET_FS_uri_to_string (uri);
  slen = strlen (uris) + 1;
  idlen = strlen (identifier);
  if (update == NULL)
    update = "";
  nidlen = strlen (update) + 1;
  mdsize = GNUNET_CONTAINER_meta_data_get_serialized_size (mmeta);
  size = sizeof (struct SBlock) + slen + nidlen + mdsize;
  if (size > MAX_SBLOCK_SIZE)
    {
      size = MAX_SBLOCK_SIZE;
      mdsize = size - (sizeof (struct SBlock) + slen + nidlen);
    }
  sb = GNUNET_malloc (sizeof (struct SBlock) + size);
  dest = (char *) &sb[1];
  memcpy (dest, update, nidlen);
  dest += nidlen;
  memcpy (dest, uris, slen);
  dest += slen;
  mdsize = GNUNET_CONTAINER_meta_data_serialize (mmeta,
						 &dest,
						 mdsize, 
						 GNUNET_CONTAINER_META_DATA_SERIALIZE_PART);
  GNUNET_CONTAINER_meta_data_destroy (mmeta);
  if (mdsize == -1)
    {
      GNUNET_break (0);
      GNUNET_free (uris);
      GNUNET_free (sb);
      cont (cont_cls,
	    NULL,
	    _("Internal error."));
      return;
    }
  size = sizeof (struct SBlock) + mdsize + slen + nidlen;
  sb_enc = GNUNET_malloc (size);
  GNUNET_CRYPTO_hash (identifier, idlen, &key);
  GNUNET_CRYPTO_hash (&key, sizeof (GNUNET_HashCode), &id);
  sks_uri = GNUNET_malloc (sizeof (struct GNUNET_FS_Uri));
  sks_uri->type = sks;
  GNUNET_CRYPTO_rsa_key_get_public (namespace->key, &sb_enc->subspace);
  GNUNET_CRYPTO_hash (&sb_enc->subspace,
		      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
		      &sks_uri->data.sks.namespace);
  sks_uri->data.sks.identifier = GNUNET_strdup (identifier);
  GNUNET_CRYPTO_hash_xor (&id, 
			  &sks_uri->data.sks.namespace, 
			  &sb_enc->identifier);
  GNUNET_CRYPTO_hash_to_aes_key (&key, &sk, &iv);
  GNUNET_CRYPTO_aes_encrypt (&sb[1],
			     size - sizeof (struct SBlock),
			     &sk,
			     &iv,
			     &sb_enc[1]);
  sb_enc->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_FS_SBLOCK);
  sb_enc->purpose.size = htonl(slen + mdsize + nidlen
			       + sizeof(struct SBlock)
			       - sizeof(struct GNUNET_CRYPTO_RsaSignature));
  GNUNET_assert (GNUNET_OK == 
		 GNUNET_CRYPTO_rsa_sign (namespace->key,
					 &sb_enc->purpose,
					 &sb_enc->signature));
  psc = GNUNET_malloc (sizeof(struct PublishSksContext));
  psc->uri = sks_uri;
  psc->cont = cont;
  psc->cont_cls = cont_cls;
  if (0 != (options & GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY))
    {
      GNUNET_free (sb_enc);
      GNUNET_free (sb);
      sb_put_cont (psc,
		   GNUNET_OK,
		   NULL);
      return;
    }
  psc->dsh = GNUNET_DATASTORE_connect (h->cfg, h->sched);
  if (NULL == psc->dsh)
    {
      GNUNET_free (sb_enc);
      GNUNET_free (sb);
      sb_put_cont (psc,
		   GNUNET_NO,
		   _("Failed to connect to datastore."));
      return;
    }
  GNUNET_CRYPTO_hash_xor (&sks_uri->data.sks.namespace,
			  &id,
			  &query);  
  GNUNET_DATASTORE_put (psc->dsh,
			0,
			&sb_enc->identifier,
			size,
			sb_enc,
			GNUNET_BLOCK_TYPE_SBLOCK, 
			priority,
			anonymity,
			expirationTime,
			GNUNET_CONSTANTS_SERVICE_TIMEOUT,
			&sb_put_cont,
			psc);

  GNUNET_free (sb);
  GNUNET_free (sb_enc);
}

/* end of fs_publish.c */
