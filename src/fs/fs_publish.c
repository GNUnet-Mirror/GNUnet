/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * - KBlocks
 * - SBlocks
 * - indexing support
 * - code-sharing with unindex (can wait)
 * - persistence support (can wait)
 * - datastore reservation support (optimization)
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "fs.h"

#define DEBUG_PUBLISH GNUNET_YES

/**
 * Main function that performs the upload.
 * @param cls "struct GNUNET_FS_PublishContext" identifies the upload
 * @param tc task context
 */
static void
do_upload (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Context for "ds_put_cont".
 */
struct PutContCtx
{
  /**
   * Publishing context for which the datastore
   * PUT request was executed.
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
};


/**
 * Fill in all of the generic fields for 
 * a publish event.
 *
 * @param pc structure to fill in
 * @param sc overall publishing context
 * @param p file information for the file being published
 */
static void
make_publish_status (struct GNUNET_FS_ProgressInfo *pi,
		     struct GNUNET_FS_PublishContext *sc,
		     const struct GNUNET_FS_FileInformation *p)
{
  pi->value.publish.sc = sc;
  pi->value.publish.fi = p;
  pi->value.publish.cctx
    = p->client_info;
  pi->value.publish.pctx
    = (NULL == p->dir) ? NULL : p->dir->client_info;
  pi->value.publish.size
    = (p->is_directory) ? p->data.dir.dir_size : p->data.file.file_size;
  pi->value.publish.eta 
    = GNUNET_TIME_calculate_eta (p->start_time,
				 p->publish_offset,
				 pi->value.publish.size);
  pi->value.publish.duration = GNUNET_TIME_absolute_get_duration (p->start_time);
  pi->value.publish.completed = p->publish_offset;
  pi->value.publish.anonymity = p->anonymity;
}


/**
 * Cleanup the publish context, we're done
 * with it.
 *
 * @param pc struct to clean up after
 */
static void
publish_cleanup (struct GNUNET_FS_PublishContext *sc)
{
  GNUNET_FS_file_information_destroy (sc->fi, NULL, NULL);
  GNUNET_FS_namespace_delete (sc->namespace, GNUNET_NO);
  GNUNET_free_non_null (sc->nid);  
  GNUNET_free_non_null (sc->nuid);
  GNUNET_DATASTORE_disconnect (sc->dsh, GNUNET_NO);
  GNUNET_free (sc);
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
      make_publish_status (&pi, pcc->sc, pcc->p);
      pi.value.publish.eta = GNUNET_TIME_UNIT_FOREVER_REL;
      pi.value.publish.specifics.error.message = pcc->p->emsg;
      pcc->p->client_info
	= pcc->sc->h->upcb (pcc->sc->h->upcb_cls,
			    &pi);
      return;
    }
  GNUNET_FS_file_information_sync (pcc->p);
  if (NULL != pcc->cont)
    pcc->sc->upload_task 
      = GNUNET_SCHEDULER_add_delayed (pcc->sc->h->sched,
				      GNUNET_NO,
				      GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
				      GNUNET_SCHEDULER_NO_TASK,
				      GNUNET_TIME_UNIT_ZERO,
				      pcc->cont,
				      pcc->sc);
  GNUNET_free (pcc);
}


/**
 * We need to publish a specific block.  Do it.  Then continue with
 * the main task.
 *
 * @param sc overall upload data
 * @param p file that the block belongs to (needed for options!)
 * @param query what the block should be indexed under
 * @param blk encoded block to publish
 * @param blk_size size of the block
 * @param blk_type type of the block
 * @param cont function to run when done
 */
static void
publish_block (struct GNUNET_FS_PublishContext *sc,
	       struct GNUNET_FS_FileInformation *p,
	       const GNUNET_HashCode *query,
	       const void* blk,
	       uint16_t blk_size,
	       uint32_t blk_type,
	       GNUNET_SCHEDULER_Task cont)
{
  struct PutContCtx * dpc_cls;

  dpc_cls = GNUNET_malloc(sizeof(struct PutContCtx));
  dpc_cls->cont = cont;
  dpc_cls->sc = sc;
  dpc_cls->p = p;
  GNUNET_assert (GNUNET_NO == sc->in_network_wait);
  sc->in_network_wait = GNUNET_YES;
  GNUNET_DATASTORE_put (sc->dsh,
			sc->rid,
			query,
			blk_size,
			blk,
			blk_type,
			p->priority,
			p->anonymity,
			p->expirationTime,
			GNUNET_CONSTANTS_SERVICE_TIMEOUT,
			&ds_put_cont,
			dpc_cls);
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
  make_publish_status (&pi, sc, p);
  pi.value.publish.eta = GNUNET_TIME_UNIT_ZERO;
  pi.value.publish.specifics.completed.chk_uri = p->chk_uri;
  p->client_info
    = sc->h->upcb (sc->h->upcb_cls,
		  &pi);
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
  struct GNUNET_FS_FileInformation *p;
  p = sc->fi;
  
  if (NULL != sc->namespace)
    GNUNET_FS_publish_sks (sc->h,
			   sc->namespace,
			   sc->nid,
			   sc->nuid,
			   p->meta,
			   p->chk_uri,
			   p->expirationTime,
			   p->anonymity,
			   p->priority);
  // FIXME: release the datastore reserve here!
  signal_publish_completion (p, sc);
}


/**
 * We have uploaded a file or directory; now publish
 * the KBlocks in the global keyword space so that
 * it can be found.  Then continue with the
 * main task.
 *
 * @param sc overall upload data
 * @param p specific file or directory for which kblocks
 *          should be created
 */
static void
publish_kblocks (struct GNUNET_FS_PublishContext *sc,
		 struct GNUNET_FS_FileInformation *p)
{
  unsigned int i;

  // FIXME: use cps here instead...
  for (i=0;i<p->keywords->data.ksk.keywordCount;i++)
    GNUNET_FS_publish_ksk (sc->h,
			   p->keywords->data.ksk.keywords[i],
			   p->meta,
			   p->chk_uri,
			   p->expirationTime,
			   p->anonymity,
			   p->priority);
  GNUNET_FS_file_information_sync (p);
  if (NULL != p->dir)
    signal_publish_completion (p, sc);
  sc->upload_task 
    = GNUNET_SCHEDULER_add_delayed (sc->h->sched,
				    GNUNET_NO,
				    GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
				    GNUNET_SCHEDULER_NO_TASK,
				    GNUNET_TIME_UNIT_ZERO,
				    &do_upload,
				    sc);
}


/**
 * Compute the depth of the CHK tree.
 *
 * @param flen file length for which to compute the depth
 * @return depth of the tree
 */
static unsigned int
compute_depth (uint64_t flen)
{
  unsigned int treeDepth;
  uint64_t fl;

  treeDepth = 1;
  fl = GNUNET_FS_DBLOCK_SIZE;
  while (fl < flen)
    {
      treeDepth++;
      if (fl * GNUNET_FS_CHK_PER_INODE < fl)
        {
          /* integer overflow, this is a HUGE file... */
          return treeDepth;
        }
      fl = fl * GNUNET_FS_CHK_PER_INODE;
    }
  return treeDepth;
}


/**
 * Compute the size of the current IBlock.
 *
 * @param height height of the IBlock in the tree (aka overall
 *               number of tree levels minus depth); 0 == DBlock
 * @param offset current offset in the overall file
 * @return size of the corresponding IBlock
 */
static uint16_t 
compute_iblock_size (unsigned int height,
		     uint64_t offset)
{
  unsigned int ret;
  unsigned int i;
  uint64_t mod;
  uint64_t bds;

  GNUNET_assert (height > 0);
  bds = GNUNET_FS_DBLOCK_SIZE; /* number of bytes each CHK at level "i"
				  corresponds to */
  for (i=0;i<height;i++)
    bds *= GNUNET_FS_CHK_PER_INODE;
  mod = offset % bds;
  if (0 == mod)
    {
      /* we were triggered at the end of a full block */
      ret = GNUNET_FS_CHK_PER_INODE;
    }
  else
    {
      /* we were triggered at the end of the file */
      bds /= GNUNET_FS_CHK_PER_INODE;
      ret = mod / bds;
      if (0 != mod % bds)
	ret++; 
    }
  return (uint16_t) (ret * sizeof(struct ContentHashKey));
}


/**
 * Compute the offset of the CHK for the
 * current block in the IBlock above.
 *
 * @param height height of the IBlock in the tree (aka overall
 *               number of tree levels minus depth); 0 == DBlock
 * @param offset current offset in the overall file
 * @return (array of CHKs') offset in the above IBlock
 */
static unsigned int
compute_chk_offset (unsigned int height,
		    uint64_t offset)
{
  uint64_t bds;
  unsigned int ret;
  unsigned int i;

  bds = GNUNET_FS_DBLOCK_SIZE; /* number of bytes each CHK at level "i"
				  corresponds to */
  for (i=0;i<height;i++)
    bds *= GNUNET_FS_CHK_PER_INODE;
  GNUNET_assert (0 == (offset % bds));
  ret = offset / bds;
  return ret % GNUNET_FS_CHK_PER_INODE; 
}


/**
 * We are uploading a file or directory; load (if necessary) the next
 * block into memory, encrypt it and send it to the FS service.  Then
 * continue with the main task.
 *
 * @param sc overall upload data
 * @param p specific file or directory for which kblocks
 *          should be created
 */
static void
publish_content (struct GNUNET_FS_PublishContext *sc,
		 struct GNUNET_FS_FileInformation *p)
{
  struct GNUNET_FS_ProgressInfo pi;
  struct ContentHashKey *mychk;
  const void *pt_block;
  uint16_t pt_size;
  char *emsg;
  char iob[GNUNET_FS_DBLOCK_SIZE];
  char enc[GNUNET_FS_DBLOCK_SIZE];
  struct GNUNET_CRYPTO_AesSessionKey sk;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  uint64_t size;
  unsigned int off;
  struct GNUNET_FS_DirectoryBuilder *db;
  struct GNUNET_FS_FileInformation *dirpos;
  void *raw_data;
  char *dd;

  // FIXME: figure out how to share this code
  // with unindex!
  size = (p->is_directory) ? p->data.dir.dir_size : p->data.file.file_size;
  if (NULL == p->chk_tree)
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
		  if ( (dirpos->data.file.file_size < GNUNET_FS_MAX_INLINE_SIZE) &&
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
	  size = p->data.dir.dir_size;
	}
      p->chk_tree_depth = compute_depth (size);
      p->chk_tree = GNUNET_malloc (p->chk_tree_depth * 
				   sizeof (struct ContentHashKey) *
				   GNUNET_FS_CHK_PER_INODE);
      p->current_depth = p->chk_tree_depth;
    }
  if (p->current_depth == p->chk_tree_depth)
    {
      if (p->is_directory)
	{
	  pt_size = GNUNET_MIN(GNUNET_FS_DBLOCK_SIZE,
			       p->data.dir.dir_size - p->publish_offset);
	  dd = p->data.dir.dir_data;
	  pt_block = &dd[p->publish_offset];
	}
      else
	{
	  pt_size = GNUNET_MIN(GNUNET_FS_DBLOCK_SIZE,
			       p->data.file.file_size - p->publish_offset);
	  emsg = NULL;
	  if (pt_size !=
	      p->data.file.reader (p->data.file.reader_cls,
				   p->publish_offset,
				   pt_size,
				   iob,
				   &emsg))
	    {
	      GNUNET_asprintf (&p->emsg, 
			       _("Upload failed: %s"),
			       emsg);
	      GNUNET_free (emsg);
	      GNUNET_FS_file_information_sync (p);
	      pi.status = GNUNET_FS_STATUS_PUBLISH_ERROR;
	      make_publish_status (&pi, sc, p);
	      pi.value.publish.eta = GNUNET_TIME_UNIT_FOREVER_REL;
	      pi.value.publish.specifics.error.message = p->emsg;
	      p->client_info
		= sc->h->upcb (sc->h->upcb_cls,
			       &pi);
	      /* continue with main (to propagate error up) */
	      sc->upload_task 
		= GNUNET_SCHEDULER_add_delayed (sc->h->sched,
						GNUNET_NO,
						GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
						GNUNET_SCHEDULER_NO_TASK,
						GNUNET_TIME_UNIT_ZERO,
						&do_upload,
						sc);
	      return;
	    }
	  pt_block = iob;
	}
    }
  else
    {
      pt_size = compute_iblock_size (p->chk_tree_depth - p->current_depth,
				     p->publish_offset); 
      pt_block = &p->chk_tree[p->current_depth *
			      GNUNET_FS_CHK_PER_INODE];
    }
  off = compute_chk_offset (p->chk_tree_depth - p->current_depth,
			    p->publish_offset);
  mychk = &p->chk_tree[(p->current_depth-1)*GNUNET_FS_CHK_PER_INODE+off];
  GNUNET_CRYPTO_hash (pt_block, pt_size, &mychk->key);
  GNUNET_CRYPTO_hash_to_aes_key (&mychk->key, &sk, &iv);
  GNUNET_CRYPTO_aes_encrypt (pt_block,
			     pt_size,
			     &sk,
			     &iv,
			     enc);
  // NOTE: this call (and progress below) is all that really differs
  // between publish/unindex!  Parameterize & move this code!
  // FIXME: something around here would need to change
  // for indexing!
  publish_block (sc, p, 
		 &mychk->query,
		 enc, 
		 pt_size, 
		 (p->current_depth == p->chk_tree_depth) 
		 ? GNUNET_DATASTORE_BLOCKTYPE_DBLOCK 
		 : GNUNET_DATASTORE_BLOCKTYPE_IBLOCK,
		 &do_upload);
  if (p->current_depth == p->chk_tree_depth)
    {
      pi.status = GNUNET_FS_STATUS_PUBLISH_PROGRESS;
      make_publish_status (&pi, sc, p);
      pi.value.publish.specifics.progress.data = pt_block;
      pi.value.publish.specifics.progress.offset = p->publish_offset;
      pi.value.publish.specifics.progress.data_len = pt_size;
      p->client_info 
	= sc->h->upcb (sc->h->upcb_cls,
		       &pi);
    }
  GNUNET_CRYPTO_hash (enc, pt_size, &mychk->query);
  if (p->current_depth == p->chk_tree_depth) 
    { 
      p->publish_offset += pt_size;
      if ( (p->publish_offset == size) ||
	   (0 == p->publish_offset % (GNUNET_FS_CHK_PER_INODE * GNUNET_FS_DBLOCK_SIZE) ) )
	p->current_depth--;
    }
  else
    {
      if ( (off == GNUNET_FS_CHK_PER_INODE) ||
	   (p->publish_offset == size) )
	p->current_depth--;
      else
	p->current_depth = p->chk_tree_depth;
    }
  if (0 == p->current_depth)
    {
      p->chk_uri = GNUNET_malloc (sizeof(struct GNUNET_FS_Uri));
      p->chk_uri->type = chk;
      p->chk_uri->data.chk.chk = p->chk_tree[0];
      p->chk_uri->data.chk.file_length = size;
      GNUNET_free (p->chk_tree);
      p->chk_tree = NULL;
    }
}


/**
 * Main function that performs the upload.
 * @param cls "struct GNUNET_FS_PublishContext" identifies the upload
 * @param tc task context
 */
static void
do_upload (void *cls,
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
  if (NULL != p->emsg)
    {
      /* error with current file, abort all
	 related files as well! */
      while (NULL != p->dir)
	{
	  fn = GNUNET_CONTAINER_meta_data_get_by_type (p->meta,
						       EXTRACTOR_FILENAME);
	  p = p->dir;
	  GNUNET_asprintf (&p->emsg, 
			   _("Recursive upload failed at `%s'"),
			   fn);
	  GNUNET_free (fn);
	  GNUNET_FS_file_information_sync (p);
	  pi.status = GNUNET_FS_STATUS_PUBLISH_ERROR;
	  make_publish_status (&pi, sc, p);
	  pi.value.publish.eta = GNUNET_TIME_UNIT_FOREVER_REL;
	  pi.value.publish.specifics.error.message = p->emsg;
	  p->client_info
	    = sc->h->upcb (sc->h->upcb_cls,
			   &pi);
	}
      return;
    }
  if (NULL != p->chk_uri)
    {
      /* move on to next file */
      if (NULL != p->next)
	sc->fi_pos = p->next;
      else
	sc->fi_pos = p->dir;
      /* upload of "p" complete, publish KBlocks! */
      publish_kblocks (sc, p);
      return;
    }
  if ( (!p->is_directory) &&
       (p->data.file.do_index) )
    {
      // FIXME: need to pre-compute hash over
      // the entire file and ask FS to prepare
      // for indexing!
      return;
    }
  publish_content (sc, p);
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
		 unsigned int *anonymity,
		 unsigned int *priority,
		 struct GNUNET_TIME_Absolute *expirationTime,
		 void **client_info)
{
  struct GNUNET_FS_PublishContext *sc = cls;
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_PUBLISH_START;
  make_publish_status (&pi, sc, fi);
  *client_info = sc->h->upcb (sc->h->upcb_cls,
			      &pi);
  return GNUNET_OK;
}


/**
 * Publish a file or directory.
 *
 * @param h handle to the file sharing subsystem
 * @param ctx initial value to use for the '*ctx'
 *        in the callback (for the GNUNET_FS_STATUS_PUBLISH_START event).
 * @param fi information about the file or directory structure to publish
 * @param namespace namespace to publish the file in, NULL for no namespace
 * @param nid identifier to use for the publishd content in the namespace
 *        (can be NULL, must be NULL if namespace is NULL)
 * @param nuid update-identifier that will be used for future updates 
 *        (can be NULL, must be NULL if namespace or nid is NULL)
 * @return context that can be used to control the publish operation
 */
struct GNUNET_FS_PublishContext *
GNUNET_FS_publish_start (struct GNUNET_FS_Handle *h,
			 void *ctx,
			 struct GNUNET_FS_FileInformation *fi,
			 struct GNUNET_FS_Namespace *namespace,
			 const char *nid,
			 const char *nuid)
{
  struct GNUNET_FS_PublishContext *ret;
  struct GNUNET_FS_FileInformation *p;
  struct GNUNET_DATASTORE_Handle *dsh;

  dsh = GNUNET_DATASTORE_connect (h->cfg,
				  h->sched);
  if (NULL == dsh)
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_PublishContext));
  ret->dsh = dsh;
  ret->h = h;
  ret->client_ctx = ctx;
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
  /* find first leaf, DFS */
  p = ret->fi;
  while ( (p->is_directory) &&
	  (NULL != p->data.dir.entries) )
    p = p->data.dir.entries;	      
  ret->fi_pos = p;

  // FIXME: calculate space needed for "fi"
  // and reserve as first task (then trigger
  // "do_upload" from that continuation)!
  ret->upload_task 
    = GNUNET_SCHEDULER_add_delayed (h->sched,
				    GNUNET_NO,
				    GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
				    GNUNET_SCHEDULER_NO_TASK,
				    GNUNET_TIME_UNIT_ZERO,
				    &do_upload,
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
		unsigned int *anonymity,
		unsigned int *priority,
		struct GNUNET_TIME_Absolute *expirationTime,
		void **client_info)
{
  struct GNUNET_FS_PublishContext*sc = cls;
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_PUBLISH_STOPPED;
  make_publish_status (&pi, sc, fi);
  GNUNET_break (NULL ==
		sc->h->upcb (sc->h->upcb_cls,
			     &pi));
  *client_info = NULL;
  return GNUNET_OK;
}


/**
 * Stop an upload.  Will abort incomplete uploads (but 
 * not remove blocks that have already been publishd) or
 * simply clean up the state for completed uploads.
 *
 * @param sc context for the upload to stop
 */
void 
GNUNET_FS_publish_stop (struct GNUNET_FS_PublishContext *sc)
{
  if (GNUNET_SCHEDULER_NO_TASK != sc->upload_task)
    GNUNET_SCHEDULER_cancel (sc->h->sched, sc->upload_task);
  // FIXME: remove from persistence DB (?) --- think more about
  //        shutdown / persistent-resume APIs!!!
  GNUNET_FS_file_information_inspect (sc->fi,
				      &fip_signal_stop,
				      sc);
  if (GNUNET_YES == sc->in_network_wait)
    {
      sc->in_network_wait = GNUNET_SYSERR;
      return;
    }
  publish_cleanup (sc);
}


/**
 * Publish a KBlock on GNUnet.
 *
 * @param h handle to the file sharing subsystem
 * @param keyword keyword to use
 * @param meta metadata to use
 * @param uri URI to refer to in the KBlock
 * @param expirationTime when the KBlock expires
 * @param anonymity anonymity level for the KBlock
 * @param priority priority for the KBlock
 */
// FIXME: cps this one
void
GNUNET_FS_publish_ksk (struct GNUNET_FS_Handle *h,
		       const char *keyword,
		       struct GNUNET_CONTAINER_MetaData *meta,
		       struct GNUNET_FS_Uri *uri,
		       struct GNUNET_TIME_Absolute expirationTime,
		       unsigned int anonymity,
		       unsigned int priority)
{
  // FIXME!
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
 */
// FIXME: cps this one
void
GNUNET_FS_publish_sks (struct GNUNET_FS_Handle *h,
		       struct GNUNET_FS_Namespace *namespace,
		       const char *identifier,
		       const char *update,
		       struct GNUNET_CONTAINER_MetaData *meta,
		       struct GNUNET_FS_Uri *uri,
		       struct GNUNET_TIME_Absolute expirationTime,
		       unsigned int anonymity,
		       unsigned int priority)
{		 
  // FIXME
}

/* end of fs_publish.c */
