/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_unindex.c
 * @author Krista Grothoff
 * @author Christian Grothoff
 * @brief Unindex file.
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_fs_service.h"
#include "gnunet_protocols.h"
#include "fs.h"
#include "fs_tree.h"


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
unindex_reader (void *cls,
		uint64_t offset,
		size_t max, 
		void *buf,
		char **emsg)
{
  struct GNUNET_FS_UnindexContext *uc = cls;
  size_t pt_size;

  pt_size = GNUNET_MIN(max,
		       uc->file_size - offset);
  if (offset != 
      GNUNET_DISK_file_seek (uc->fh, offset, GNUNET_DISK_SEEK_SET))
    {
      *emsg = GNUNET_strdup (_("Failed to find given position in file"));
      return 0;
    }
  if (pt_size !=
      GNUNET_DISK_file_read (uc->fh,
			     buf,
			     pt_size))
    {
      *emsg = GNUNET_strdup (_("Failed to read file"));
      return 0;
    }
  return pt_size;
}


/**
 * Fill in all of the generic fields for 
 * an unindex event.
 *
 * @param pi structure to fill in
 * @param uc overall unindex context
 * @param offset where we are in the file (for progress)
 */
static void
make_unindex_status (struct GNUNET_FS_ProgressInfo *pi,
		     struct GNUNET_FS_UnindexContext *uc,
		     uint64_t offset)
{
  pi->value.unindex.uc = uc;
  pi->value.unindex.cctx = uc->client_info;
  pi->value.unindex.filename = uc->filename;
  pi->value.unindex.size = uc->file_size;
  pi->value.unindex.eta 
    = GNUNET_TIME_calculate_eta (uc->start_time,
				 offset,
				 uc->file_size);
  pi->value.publish.duration = GNUNET_TIME_absolute_get_duration (uc->start_time);
  pi->value.publish.completed = offset;
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
unindex_progress (void *cls,
		  uint64_t offset,
		  const void *pt_block,
		  size_t pt_size,
		  unsigned int depth)
{
  struct GNUNET_FS_UnindexContext *uc = cls;
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_UNINDEX_PROGRESS;
  make_unindex_status (&pi, uc, offset);
  pi.value.unindex.specifics.progress.data = pt_block;
  pi.value.unindex.specifics.progress.offset = offset;
  pi.value.unindex.specifics.progress.data_len = pt_size;
  pi.value.unindex.specifics.progress.depth = depth;
  uc->client_info 
    = uc->h->upcb (uc->h->upcb_cls,
		   &pi);
}
					       

/**
 * We've encountered an error during
 * unindexing.  Signal the client.
 *
 * @param uc context for the failed unindexing operation
 * @param emsg the error message
 */
static void
signal_unindex_error (struct GNUNET_FS_UnindexContext *uc,
		      const char *emsg)
{
  struct GNUNET_FS_ProgressInfo pi;
  
  pi.status = GNUNET_FS_STATUS_UNINDEX_ERROR;
  make_unindex_status (&pi, uc, 0);
  pi.value.unindex.eta = GNUNET_TIME_UNIT_FOREVER_REL;
  pi.value.unindex.specifics.error.message = emsg;
  uc->client_info
    = uc->h->upcb (uc->h->upcb_cls,
		   &pi);
}


/**
 * Continuation called to notify client about result of the
 * datastore removal operation.
 *
 * @param cls closure
 * @param success GNUNET_SYSERR on failure
 * @param msg NULL on success, otherwise an error message
 */
static void
process_cont (void *cls,
	      int success,
	      const char *msg)
{
  struct GNUNET_FS_UnindexContext *uc = cls;
  if (success == GNUNET_SYSERR)
    {
      signal_unindex_error (uc,
			    msg);
      return;
    }
  
  GNUNET_FS_tree_encoder_next (uc->tc);
}


/**
 * Function called asking for the current (encoded)
 * block to be processed.  After processing the
 * client should either call "GNUNET_FS_tree_encode_next"
 * or (on error) "GNUNET_FS_tree_encode_finish".
 *
 * @param cls closure
 * @param query the query for the block (key for lookup in the datastore)
 * @param offset offset of the block
 * @param type type of the block (IBLOCK or DBLOCK)
 * @param block the (encrypted) block
 * @param block_size size of block (in bytes)
 */
static void 
unindex_process (void *cls,
		 const GNUNET_HashCode *query,
		 uint64_t offset,
		 uint32_t type,
		 const void *block,
		 uint16_t block_size)
{
  struct GNUNET_FS_UnindexContext *uc = cls;
  uint32_t size;
  const void *data;
  struct OnDemandBlock odb;

  if (type != GNUNET_DATASTORE_BLOCKTYPE_DBLOCK)
    {
      size = block_size;
      data = block;
    }
  else /* on-demand encoded DBLOCK */
    {
      size = sizeof(struct OnDemandBlock);
      odb.offset = offset;
      odb.file_id = uc->file_id;
      data = &odb;
    }
  GNUNET_DATASTORE_remove (uc->dsh,
			   query,
			   size,
			   data,
			   &process_cont,
			   uc,
			   GNUNET_CONSTANTS_SERVICE_TIMEOUT);
}


/**
 * Function called when the tree encoder has
 * processed all blocks.  Clean up.
 *
 * @param cls our unindexing context
 * @param tc not used
 */
static void
unindex_finish (void *cls,
		const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_UnindexContext *uc = cls;
  char *emsg;
  struct GNUNET_FS_Uri *uri;
  struct GNUNET_FS_ProgressInfo pi;

  GNUNET_FS_tree_encoder_finish (uc->tc,
				 &uri,
				 &emsg);
  if (uri != NULL)
    GNUNET_FS_uri_destroy (uri);
  GNUNET_DISK_file_close (uc->fh);
  uc->fh = NULL;
  GNUNET_DATASTORE_disconnect (uc->dsh, GNUNET_NO);
  uc->dsh = NULL;
  if (emsg != NULL)
    {
      signal_unindex_error (uc, emsg);
      GNUNET_free (emsg);
    }
  else
    {   
      pi.status = GNUNET_FS_STATUS_UNINDEX_COMPLETED;
      make_unindex_status (&pi, uc, uc->file_size);
      pi.value.unindex.eta = GNUNET_TIME_UNIT_ZERO;
      uc->client_info
	= uc->h->upcb (uc->h->upcb_cls,
		       &pi);
    }
}


/**
 * Function called with the response from the
 * FS service to our unindexing request.
 *
 * @param cls closure, unindex context
 * @param msg NULL on timeout, otherwise the response
 */
static void
process_fs_response (void *cls,
		     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_FS_UnindexContext *uc = cls;

  GNUNET_CLIENT_disconnect (uc->client);
  uc->client = NULL;
  if (uc->state != UNINDEX_STATE_FS_NOTIFY) 
    {
      GNUNET_FS_unindex_stop (uc);
      return;
    }
  if (NULL == msg)
    {
      uc->state = UNINDEX_STATE_ERROR;
      signal_unindex_error (uc, 
			    _("Timeout waiting for `fs' service."));
      return;
    }
  if (ntohs(msg->type) != GNUNET_MESSAGE_TYPE_FS_UNINDEX_OK)
    {
      uc->state = UNINDEX_STATE_ERROR;
      signal_unindex_error (uc, 
			    _("Invalid response from `fs' service."));
      return;      
    }
  uc->state = UNINDEX_STATE_DS_REMOVE;
  uc->dsh = GNUNET_DATASTORE_connect (uc->h->cfg,
				      uc->h->sched);
  if (NULL == uc->dsh)
    {
      uc->state = UNINDEX_STATE_ERROR;
      signal_unindex_error (uc, 
			    _("Failed to connect to `datastore' service."));
      return;
    }
  uc->fh = GNUNET_DISK_file_open (uc->filename,
				  GNUNET_DISK_OPEN_READ,
				  GNUNET_DISK_PERM_NONE);
  if (NULL == uc->fh)
    {
      GNUNET_DATASTORE_disconnect (uc->dsh, GNUNET_NO);
      uc->dsh = NULL;
      uc->state = UNINDEX_STATE_ERROR;
      signal_unindex_error (uc, 
			    _("Failed to open file for unindexing."));
      return;
    }
  uc->tc = GNUNET_FS_tree_encoder_create (uc->h,
					  uc->file_size,
					  uc,
					  &unindex_reader,
					  &unindex_process,
					  &unindex_progress,
					  &unindex_finish);
  GNUNET_FS_tree_encoder_next (uc->tc);
}


/**
 * Function called once the hash of the file
 * that is being unindexed has been computed.
 *
 * @param cls closure, unindex context
 * @param file_id computed hash, NULL on error
 */
static void 
process_hash (void *cls,
	      const GNUNET_HashCode *file_id)
{
  struct GNUNET_FS_UnindexContext *uc = cls;
  struct UnindexMessage req;

  if (uc->state != UNINDEX_STATE_HASHING) 
    {
      GNUNET_FS_unindex_stop (uc);
      return;
    }
  if (file_id == NULL)
    {
      uc->state = UNINDEX_STATE_ERROR;
      signal_unindex_error (uc, 
			    _("Failed to compute hash of file."));
      return;
    }
  uc->file_id = *file_id;
  uc->state = UNINDEX_STATE_FS_NOTIFY;
  uc->client = GNUNET_CLIENT_connect (uc->h->sched,
				      "fs",
				      uc->h->cfg);
  req.header.size = htons (sizeof (struct UnindexMessage));
  req.header.type = htons (GNUNET_MESSAGE_TYPE_FS_UNINDEX);
  req.reserved = 0;
  req.file_id = *file_id;
  GNUNET_CLIENT_transmit_and_get_response (uc->client,
					   &req.header,
					   GNUNET_CONSTANTS_SERVICE_TIMEOUT,
					   GNUNET_YES,
					   &process_fs_response,
					   uc);
}


/**
 * Unindex a file.
 *
 * @param h handle to the file sharing subsystem
 * @param filename file to unindex
 * @param cctx initial value for the client context
 * @return NULL on error, otherwise handle 
 */
struct GNUNET_FS_UnindexContext *
GNUNET_FS_unindex_start (struct GNUNET_FS_Handle *h,
			 const char *filename,
			 void *cctx)
{
  struct GNUNET_FS_UnindexContext *ret;
  struct GNUNET_FS_ProgressInfo pi;
  uint64_t size;

  if (GNUNET_OK !=
      GNUNET_DISK_file_size (filename,
			     &size,
			     GNUNET_YES))
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_UnindexContext));
  ret->h = h;
  ret->filename = GNUNET_strdup (filename);
  ret->start_time = GNUNET_TIME_absolute_get ();
  ret->file_size = size;
  ret->client_info = cctx;

  // FIXME: make persistent!
  pi.status = GNUNET_FS_STATUS_UNINDEX_START;
  make_unindex_status (&pi, ret, 0);
  pi.value.unindex.eta = GNUNET_TIME_UNIT_FOREVER_REL;
  ret->client_info
    = h->upcb (h->upcb_cls,
	       &pi);
  GNUNET_CRYPTO_hash_file (h->sched,
			   GNUNET_SCHEDULER_PRIORITY_IDLE,
			   GNUNET_NO,
			   filename,
			   HASHING_BLOCKSIZE,
			   &process_hash,
			   ret);
  return ret;
}


/**
 * Clean up after completion of an unindex operation.
 *
 * @param uc handle
 */
void
GNUNET_FS_unindex_stop (struct GNUNET_FS_UnindexContext *uc)
{  
  struct GNUNET_FS_ProgressInfo pi;

  if ( (uc->state != UNINDEX_STATE_COMPLETE) &&
       (uc->state != UNINDEX_STATE_ERROR) )
    {
      uc->state = UNINDEX_STATE_ABORTED;
      return;
    }
  // FIXME: make unpersistent!
  make_unindex_status (&pi, uc, 
		       (uc->state == UNINDEX_STATE_COMPLETE)
		       ? uc->file_size : 0);
  pi.status = GNUNET_FS_STATUS_UNINDEX_STOPPED;
  pi.value.unindex.eta = GNUNET_TIME_UNIT_ZERO;
  uc->client_info
    = uc->h->upcb (uc->h->upcb_cls,
		   &pi);
  GNUNET_break (NULL == uc->client_info);
  GNUNET_free (uc->filename);
  GNUNET_free (uc);
}

/* end of fs_unindex.c */
