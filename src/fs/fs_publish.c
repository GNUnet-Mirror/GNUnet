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
  pi->value.publish.pc = sc;
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
 * @param cls struct to clean up after
 * @param tc scheduler context
 */
static void
publish_cleanup (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_PublishContext *pc = cls;

  if (pc->fhc != NULL)
    {
      GNUNET_CRYPTO_hash_file_cancel (pc->fhc);
      pc->fhc = NULL;
    }
  GNUNET_FS_file_information_destroy (pc->fi, NULL, NULL);
  if (pc->namespace != NULL)
    GNUNET_FS_namespace_delete (pc->namespace, GNUNET_NO);
  GNUNET_free_non_null (pc->nid);  
  GNUNET_free_non_null (pc->nuid);
  GNUNET_free_non_null (pc->serialization);
  if (pc->dsh != NULL)
    {
      GNUNET_DATASTORE_disconnect (pc->dsh, GNUNET_NO);
      pc->dsh = NULL;
    }
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
      /* we were aborted in the meantime, finish shutdown! */
      GNUNET_SCHEDULER_add_continuation (&publish_cleanup,
					 pcc->sc,
					 GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      GNUNET_free (pcc);
      return;
    }
  GNUNET_assert (GNUNET_YES == pcc->sc->in_network_wait);
  pcc->sc->in_network_wait = GNUNET_NO;
  if (GNUNET_OK != success)
    {
      GNUNET_asprintf (&pcc->p->emsg, 
		       _("Publishing failed: %s"),
		       msg);
      pi.status = GNUNET_FS_STATUS_PUBLISH_ERROR;
      pi.value.publish.eta = GNUNET_TIME_UNIT_FOREVER_REL;
      pi.value.publish.specifics.error.message = pcc->p->emsg;
      pcc->p->client_info = GNUNET_FS_publish_make_status_ (&pi, pcc->sc, pcc->p, 0);
      if ( (pcc->p->is_directory == GNUNET_NO) &&
	   (pcc->p->filename != NULL) &&
	   (pcc->p->data.file.do_index == GNUNET_YES) )
	{
	  /* run unindex to clean up */
	  GNUNET_FS_unindex_start (pcc->sc->h,
				   pcc->p->filename,
				   NULL);
	}	   
    }
  if (NULL != pcc->cont)
    pcc->sc->upload_task 
      = GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
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
  if ( (p->is_directory == GNUNET_NO) &&
       (p->filename != NULL) &&
       (p->data.file.do_index == GNUNET_YES) )
    {
      /* run unindex to clean up */
      GNUNET_FS_unindex_start (sc->h,
			       p->filename,
			       NULL);
    }	   
  
}


/**
 * Datastore returns from reservation cancel request.
 * 
 * @param cls the 'struct GNUNET_FS_PublishContext'
 * @param success success code (not used)
 * @param msg error message (typically NULL, not used)
 */
static void
finish_release_reserve (void *cls,
			int success,
			const char *msg)
{
  struct GNUNET_FS_PublishContext *pc = cls;

  pc->qre = NULL;
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
publish_sblocks_cont (void *cls,
		      const struct GNUNET_FS_Uri *uri,
		      const char *emsg)
{
  struct GNUNET_FS_PublishContext *pc = cls;
  if (NULL != emsg)
    {
      signal_publish_error (pc->fi,
			    pc,
			    emsg);
      GNUNET_FS_publish_sync_ (pc);
      return;
    }  
  GNUNET_assert (pc->qre == NULL);
  if ( (pc->dsh != NULL) &&
       (pc->rid != 0) )
    {
      pc->qre = GNUNET_DATASTORE_release_reserve (pc->dsh,
						  pc->rid,
						  UINT_MAX,
						  UINT_MAX,
						  GNUNET_TIME_UNIT_FOREVER_REL,
						  &finish_release_reserve,
						  pc);
    }
  else
    {
      finish_release_reserve (pc, GNUNET_OK, NULL);
    }
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
  struct GNUNET_FS_PublishContext *pc = cls;
  struct GNUNET_FS_FileInformation *p = pc->fi_pos;

  if (NULL != emsg)
    {
#if DEBUG_PUBLISH
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Error uploading KSK blocks: %s\n",
		  emsg);
#endif
      signal_publish_error (p, pc, emsg);
      GNUNET_FS_file_information_sync_ (p);
      GNUNET_FS_publish_sync_ (pc);
      pc->upload_task 
	= GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
					      &GNUNET_FS_publish_main_,
					      pc);
      return;
    }
#if DEBUG_PUBLISH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "KSK blocks published, moving on to next file\n");
#endif
  if (NULL != p->dir)
    signal_publish_completion (p, pc);    
  /* move on to next file */
  if (NULL != p->next)
    pc->fi_pos = p->next;
  else
    pc->fi_pos = p->dir;
  GNUNET_FS_publish_sync_ (pc);
  pc->upload_task 
    = GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
					  &GNUNET_FS_publish_main_,
					  pc);
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
  uint64_t flen;

  p = sc->fi_pos;
  GNUNET_FS_tree_encoder_finish (p->te,
				 &p->chk_uri,
				 &emsg);
  p->te = NULL;
  if (NULL != emsg)
    {
#if DEBUG_PUBLISH
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Error during tree walk: %s\n",
		  emsg);
#endif
      GNUNET_asprintf (&p->emsg, 
		       _("Publishing failed: %s"),
		       emsg);
      GNUNET_free (emsg);
      pi.status = GNUNET_FS_STATUS_PUBLISH_ERROR;
      pi.value.publish.eta = GNUNET_TIME_UNIT_FOREVER_REL;
      pi.value.publish.specifics.error.message = p->emsg;
      p->client_info =  GNUNET_FS_publish_make_status_ (&pi, sc, p, 0);
    }
#if DEBUG_PUBLISH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Finished with tree encoder\n");
#endif  
  /* final progress event */
  flen = GNUNET_FS_uri_chk_get_file_size (p->chk_uri);
  pi.status = GNUNET_FS_STATUS_PUBLISH_PROGRESS;
  pi.value.publish.specifics.progress.data = NULL;
  pi.value.publish.specifics.progress.offset = flen;
  pi.value.publish.specifics.progress.data_len = 0;
  pi.value.publish.specifics.progress.depth = GNUNET_FS_compute_depth (flen);
  p->client_info = GNUNET_FS_publish_make_status_ (&pi, sc, p, flen);

  /* continue with main */
  sc->upload_task 
    = GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
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
 * @param chk content hash key for the block 
 * @param offset offset of the block in the file
 * @param depth depth of the block in the file, 0 for DBLOCK
 * @param type type of the block (IBLOCK or DBLOCK)
 * @param block the (encrypted) block
 * @param block_size size of block (in bytes)
 */
static void 
block_proc (void *cls,
	    const struct ContentHashKey *chk,
	    uint64_t offset,
	    unsigned int depth, 
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
#if DEBUG_PUBLISH
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Waiting for datastore connection\n");
#endif
      sc->upload_task
	= GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
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
       (type == GNUNET_BLOCK_TYPE_FS_DBLOCK) )
    {
#if DEBUG_PUBLISH
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Indexing block `%s' for offset %llu with index size %u\n",
		  GNUNET_h2s (&chk->query),
		  (unsigned long long) offset,
		  sizeof (struct OnDemandBlock));
#endif
      odb.offset = GNUNET_htonll (offset);
      odb.file_id = p->data.file.file_id;
      GNUNET_DATASTORE_put (sc->dsh,
			    (p->is_directory) ? 0 : sc->rid,
			    &chk->query,
			    sizeof (struct OnDemandBlock),
			    &odb,
			    GNUNET_BLOCK_TYPE_FS_ONDEMAND,
			    p->priority,
			    p->anonymity,
			    p->expirationTime,
			    -2, 1,
			    GNUNET_CONSTANTS_SERVICE_TIMEOUT,
			    &ds_put_cont,
			    dpc_cls);	  
      return;
    }
#if DEBUG_PUBLISH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Publishing block `%s' for offset %llu with size %u\n",
	      GNUNET_h2s (&chk->query),
	      (unsigned long long) offset,
	      (unsigned int) block_size);
#endif
  GNUNET_DATASTORE_put (sc->dsh,
			(p->is_directory) ? 0 : sc->rid,
			&chk->query,
			block_size,
			block,
			type,
			p->priority,
			p->anonymity,
			p->expirationTime,
			-2, 1,
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
 * @param depth depth of the block in the tree, 0 for DBLOCK
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
  GNUNET_assert (p != NULL);
  if (NULL == p->te)
    {
      if (p->is_directory)
	{
#if DEBUG_PUBLISH
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Creating directory\n");
#endif
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
	  GNUNET_FS_file_information_sync_ (p);
	}
      size = (p->is_directory) 
	? p->data.dir.dir_size 
	: p->data.file.file_size;
#if DEBUG_PUBLISH
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Creating tree encoder\n");
#endif
      p->te = GNUNET_FS_tree_encoder_create (sc->h,
					     size,
					     sc,
					     &block_reader,
					     &block_proc,
					     &progress_proc,
					     &encode_cont);

    }
#if DEBUG_PUBLISH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Processing next block from tree\n");
#endif
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
      GNUNET_FS_file_information_sync_ (p);
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
      GNUNET_FS_file_information_sync_ (p);
      publish_content (sc);
      return;
    }
  p->data.file.index_start_confirmed = GNUNET_YES;
  /* success! continue with indexing */
  GNUNET_FS_file_information_sync_ (p);
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
  uint64_t dev;
  uint64_t ino;
  char *fn;

  sc->fhc = NULL;
  p = sc->fi_pos;
  if (NULL == res) 
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Can not index file `%s': %s.  Will try to insert instead.\n"),
		  p->filename,
		  _("failed to compute hash"));
      p->data.file.do_index = GNUNET_NO;
      GNUNET_FS_file_information_sync_ (p);
      publish_content (sc);
      return;
    }
  if (GNUNET_YES == p->data.file.index_start_confirmed)
    {
      publish_content (sc);
      return;
    }
  fn = GNUNET_STRINGS_filename_expand (p->filename);
  GNUNET_assert (fn != NULL);
  slen = strlen (fn) + 1;
  if (slen >= GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof(struct IndexStartMessage))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Can not index file `%s': %s.  Will try to insert instead.\n"),
		  fn,
		  _("filename too long"));
      GNUNET_free (fn);
      p->data.file.do_index = GNUNET_NO;
      GNUNET_FS_file_information_sync_ (p);
      publish_content (sc);
      return;
    }
#if DEBUG_PUBLISH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Hash of indexed file `%s' is `%s'\n",
	      p->filename,
	      GNUNET_h2s (res));
#endif
  if (0 != (sc->options & GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY))
    {
      p->data.file.file_id = *res;
      p->data.file.have_hash = GNUNET_YES;
      p->data.file.index_start_confirmed = GNUNET_YES;
      GNUNET_FS_file_information_sync_ (p);
      publish_content (sc);
      GNUNET_free (fn);
      return;
    }
  client = GNUNET_CLIENT_connect ("fs",
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
  if (p->data.file.have_hash != GNUNET_YES)
    {
      p->data.file.file_id = *res;
      p->data.file.have_hash = GNUNET_YES;
      GNUNET_FS_file_information_sync_ (p);
    }
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
      ism->device = GNUNET_htonll (dev);
      ism->inode = GNUNET_htonll(ino);
    }
#if DEBUG_PUBLISH
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  _("Failed to get file identifiers for `%s'\n"),
		  p->filename);
    }
#endif
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
  struct GNUNET_FS_PublishContext *pc = cls;
  struct GNUNET_FS_ProgressInfo pi;
  struct GNUNET_FS_FileInformation *p;
  struct GNUNET_FS_Uri *loc;
  char *fn;

  pc->upload_task = GNUNET_SCHEDULER_NO_TASK;  
  p = pc->fi_pos;
  if (NULL == p)
    {
#if DEBUG_PUBLISH
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Publishing complete, now publishing SKS and KSK blocks.\n");
#endif
      /* upload of entire hierarchy complete,
	 publish namespace entries */
      GNUNET_FS_publish_sync_ (pc);
      publish_sblock (pc);
      return;
    }
  /* find starting position */
  while ( (p->is_directory) &&
	  (NULL != p->data.dir.entries) &&
	  (NULL == p->emsg) &&
	  (NULL == p->data.dir.entries->chk_uri) )
    {
      p = p->data.dir.entries;
      pc->fi_pos = p;
      GNUNET_FS_publish_sync_ (pc);
    }
  /* abort on error */
  if (NULL != p->emsg)
    {
#if DEBUG_PUBLISH
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Error uploading: %s\n",
		  p->emsg);
#endif
      /* error with current file, abort all
	 related files as well! */
      while (NULL != p->dir)
	{
	  fn = GNUNET_CONTAINER_meta_data_get_by_type (p->meta,
						       EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME);
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
#if DEBUG_PUBLISH
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "File upload complete, now publishing KSK blocks.\n");
#endif
      if (0 == p->anonymity)
	{
	  /* zero anonymity, box CHK URI in LOC URI */
	  loc = GNUNET_FS_uri_loc_create (p->chk_uri,
					  pc->h->cfg,
					  p->expirationTime);
	  GNUNET_FS_uri_destroy (p->chk_uri);
	  p->chk_uri = loc;
	}
      GNUNET_FS_publish_sync_ (pc);
      /* upload of "p" complete, publish KBlocks! */
      if (p->keywords != NULL)
	{
	  GNUNET_FS_publish_ksk (pc->h,
				 p->keywords,
				 p->meta,
				 p->chk_uri,
				 p->expirationTime,
				 p->anonymity,
				 p->priority,
				 pc->options,
				 &publish_kblocks_cont,
				 pc);
	}
      else
	{
	  publish_kblocks_cont (pc,
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
	  GNUNET_FS_file_information_sync_ (p);
	  publish_content (pc);
	  return;
	}      
      if (p->data.file.have_hash)
	{
	  hash_for_index_cb (pc,
			     &p->data.file.file_id);
	}
      else
	{
	  p->start_time = GNUNET_TIME_absolute_get ();
	  pc->fhc = GNUNET_CRYPTO_hash_file (GNUNET_SCHEDULER_PRIORITY_IDLE,
					     p->filename,
					     HASHING_BLOCKSIZE,
					     &hash_for_index_cb,
					     pc);
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
 * @param anonymity pointer to selected anonymity level (can be modified)
 * @param priority pointer to selected priority (can be modified)
 * @param do_index should we index?
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
		 int *do_index,
		 struct GNUNET_TIME_Absolute *expirationTime,
		 void **client_info)
{
  struct GNUNET_FS_PublishContext *sc = cls;
  struct GNUNET_FS_ProgressInfo pi;
  unsigned int kc;
  uint64_t left;

  if (*do_index)
    {
      /* space for on-demand blocks */
      sc->reserve_space += ((length + DBLOCK_SIZE - 1) / DBLOCK_SIZE) * sizeof (struct OnDemandBlock);
    }
  else
    {
      /* space for DBlocks */
      sc->reserve_space += length;
    }
  /* entries for IBlocks and DBlocks, space for IBlocks */
  left = length;
  while (1)
    {
      left = (left + DBLOCK_SIZE - 1) / DBLOCK_SIZE;
      sc->reserve_entries += left;
      if (left <= 1)
	break;
      left = left * sizeof (struct ContentHashKey);
      sc->reserve_space += left;
    }
  sc->reserve_entries++;
  /* entries and space for keywords */
  if (NULL != *uri)
    {
      kc = GNUNET_FS_uri_ksk_get_keyword_count (*uri);
      sc->reserve_entries += kc;
      sc->reserve_space += GNUNET_SERVER_MAX_MESSAGE_SIZE * kc;
    }  
  pi.status = GNUNET_FS_STATUS_PUBLISH_START;
  *client_info = GNUNET_FS_publish_make_status_ (&pi, sc, fi, 0);
  GNUNET_FS_file_information_sync_ (fi);
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
 * @param anonymity pointer to selected anonymity level (can be modified)
 * @param priority pointer to selected priority (can be modified)
 * @param do_index should we index?
 * @param expirationTime pointer to selected expiration time (can be modified)
 * @param client_info pointer to client context set upon creation (can be modified)
 * @return GNUNET_OK to continue (always)
 */
static int
fip_signal_suspend(void *cls,
		   struct GNUNET_FS_FileInformation *fi,
		   uint64_t length,
		   struct GNUNET_CONTAINER_MetaData *meta,
		   struct GNUNET_FS_Uri **uri,
		   uint32_t *anonymity,
		   uint32_t *priority,
		   int *do_index,
		   struct GNUNET_TIME_Absolute *expirationTime,
		   void **client_info)
{
  struct GNUNET_FS_PublishContext*sc = cls;
  struct GNUNET_FS_ProgressInfo pi;
  uint64_t off;

  GNUNET_free_non_null (fi->serialization);
  fi->serialization = NULL;    
  off = (fi->chk_uri == NULL) ? 0 : length;
  pi.status = GNUNET_FS_STATUS_PUBLISH_SUSPEND;
  GNUNET_break (NULL == GNUNET_FS_publish_make_status_ (&pi, sc, fi, off));
  *client_info = NULL;
  if (NULL != sc->dsh)
    {
      GNUNET_DATASTORE_disconnect (sc->dsh, GNUNET_NO);
      sc->dsh = NULL;
    }
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
  GNUNET_FS_file_information_inspect (pc->fi,
				      &fip_signal_suspend,
				      pc);
  GNUNET_FS_end_top (pc->h, pc->top);
  publish_cleanup (pc, NULL);
}


/**
 * We have gotten a reply for our space reservation request.
 * Either fail (insufficient space) or start publishing for good.
 * 
 * @param cls the 'struct GNUNET_FS_PublishContext*'
 * @param success positive reservation ID on success
 * @param msg error message on error, otherwise NULL
 */
static void
finish_reserve (void *cls,
		int success,
		const char *msg)
{
  struct GNUNET_FS_PublishContext *pc = cls;

  pc->qre = NULL;
  if ( (msg != NULL) ||
       (success <= 0) )
    {
      GNUNET_asprintf (&pc->fi->emsg, 
		       _("Insufficient space for publishing: %s"),
		       msg);
      signal_publish_error (pc->fi,
			    pc,
			    pc->fi->emsg);
      return;
    }
  pc->rid = success;
  pc->upload_task 
    = GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
					  &GNUNET_FS_publish_main_,
					  pc);
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
  GNUNET_FS_file_information_inspect (ret->fi,
				      &fip_signal_start,
				      ret);
  ret->fi_pos = ret->fi;
  ret->top = GNUNET_FS_make_top (h, &GNUNET_FS_publish_signal_suspend_, ret);
  GNUNET_FS_publish_sync_ (ret);
  if (NULL != ret->dsh)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("Reserving space for %u entries and %llu bytes for publication\n"),
		  (unsigned int) ret->reserve_entries,
		  (unsigned long long) ret->reserve_space);
      ret->qre = GNUNET_DATASTORE_reserve (ret->dsh,
					   ret->reserve_space,
					   ret->reserve_entries,
					   UINT_MAX,
					   UINT_MAX,
					   GNUNET_TIME_UNIT_FOREVER_REL,
					   &finish_reserve,
					   ret);
    }
  else
    {
      ret->upload_task 
	= GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
					      &GNUNET_FS_publish_main_,
					      ret);
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
 * @param anonymity pointer to selected anonymity level (can be modified)
 * @param priority pointer to selected priority (can be modified)
 * @param do_index should we index?
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
		int *do_index,
		struct GNUNET_TIME_Absolute *expirationTime,
		void **client_info)
{
  struct GNUNET_FS_PublishContext*sc = cls;
  struct GNUNET_FS_ProgressInfo pi;
  uint64_t off;

  if (fi->serialization != NULL) 
    {
      GNUNET_FS_remove_sync_file_ (sc->h,
				   GNUNET_FS_SYNC_PATH_FILE_INFO,
				   fi->serialization);
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
  GNUNET_FS_end_top (pc->h, pc->top);
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
  if (GNUNET_SCHEDULER_NO_TASK != pc->upload_task)
    {
      GNUNET_SCHEDULER_cancel (pc->upload_task);
      pc->upload_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (pc->serialization != NULL) 
    {
      GNUNET_FS_remove_sync_file_ (pc->h, GNUNET_FS_SYNC_PATH_MASTER_PUBLISH, pc->serialization);
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
  publish_cleanup (pc, NULL);
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
      if (NULL != pkc->dsh)
	{
	  GNUNET_DATASTORE_disconnect (pkc->dsh, GNUNET_NO);
	  pkc->dsh = NULL;
	}
      GNUNET_free (pkc->cpy);
      GNUNET_free (pkc->kb);
      pkc->cont (pkc->cont_cls,
		 NULL,
		 msg);
      GNUNET_FS_uri_destroy (pkc->ksk_uri);
      GNUNET_free (pkc);
      return;
    }
  GNUNET_SCHEDULER_add_continuation (&publish_ksk_cont,
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
	{
	  GNUNET_DATASTORE_disconnect (pkc->dsh, GNUNET_NO);
	  pkc->dsh = NULL;
	}
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
#if DEBUG_PUBLISH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Publishing under keyword `%s'\n",
	      keyword);
#endif
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
  GNUNET_assert (NULL != pk);
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
			GNUNET_BLOCK_TYPE_FS_KBLOCK, 
			pkc->priority,
			pkc->anonymity,
			pkc->expirationTime,
			-2, 1,
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

  GNUNET_assert (NULL != uri);
  pkc = GNUNET_malloc (sizeof (struct PublishKskContext));
  pkc->h = h;
  pkc->expirationTime = expirationTime;
  pkc->anonymity = anonymity;
  pkc->priority = priority;
  pkc->cont = cont;
  pkc->cont_cls = cont_cls;
  if (0 == (options & GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY))
    {
      pkc->dsh = GNUNET_DATASTORE_connect (h->cfg);
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
	{
	  GNUNET_DATASTORE_disconnect (pkc->dsh, GNUNET_NO);
	  pkc->dsh = NULL;
	}
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
  GNUNET_SCHEDULER_add_continuation (&publish_ksk_cont,
				     pkc,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


/* end of fs_publish.c */
