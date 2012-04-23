/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_unindex.c
 * @author Krista Grothoff
 * @author Christian Grothoff
 * @brief Unindex file.
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_fs_service.h"
#include "gnunet_protocols.h"
#include "fs_api.h"
#include "fs_tree.h"
#include "block_fs.h"


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
unindex_reader (void *cls, uint64_t offset, size_t max, void *buf, char **emsg)
{
  struct GNUNET_FS_UnindexContext *uc = cls;
  size_t pt_size;

  pt_size = GNUNET_MIN (max, uc->file_size - offset);
  if (offset != GNUNET_DISK_file_seek (uc->fh, offset, GNUNET_DISK_SEEK_SET))
  {
    *emsg = GNUNET_strdup (_("Failed to find given position in file"));
    return 0;
  }
  if (pt_size != GNUNET_DISK_file_read (uc->fh, buf, pt_size))
  {
    *emsg = GNUNET_strdup (_("Failed to read file"));
    return 0;
  }
  return pt_size;
}


/**
 * Fill in all of the generic fields for
 * an unindex event and call the callback.
 *
 * @param pi structure to fill in
 * @param uc overall unindex context
 * @param offset where we are in the file (for progress)
 */
void
GNUNET_FS_unindex_make_status_ (struct GNUNET_FS_ProgressInfo *pi,
                                struct GNUNET_FS_UnindexContext *uc,
                                uint64_t offset)
{
  pi->value.unindex.uc = uc;
  pi->value.unindex.cctx = uc->client_info;
  pi->value.unindex.filename = uc->filename;
  pi->value.unindex.size = uc->file_size;
  pi->value.unindex.eta =
      GNUNET_TIME_calculate_eta (uc->start_time, offset, uc->file_size);
  pi->value.unindex.duration =
      GNUNET_TIME_absolute_get_duration (uc->start_time);
  pi->value.unindex.completed = offset;
  uc->client_info = uc->h->upcb (uc->h->upcb_cls, pi);

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
unindex_progress (void *cls, uint64_t offset, const void *pt_block,
                  size_t pt_size, unsigned int depth)
{
  struct GNUNET_FS_UnindexContext *uc = cls;
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_UNINDEX_PROGRESS;
  pi.value.unindex.specifics.progress.data = pt_block;
  pi.value.unindex.specifics.progress.offset = offset;
  pi.value.unindex.specifics.progress.data_len = pt_size;
  pi.value.unindex.specifics.progress.depth = depth;
  GNUNET_FS_unindex_make_status_ (&pi, uc, offset);
}


/**
 * We've encountered an error during
 * unindexing.  Signal the client.
 *
 * @param uc context for the failed unindexing operation
 */
static void
signal_unindex_error (struct GNUNET_FS_UnindexContext *uc)
{
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_UNINDEX_ERROR;
  pi.value.unindex.eta = GNUNET_TIME_UNIT_FOREVER_REL;
  pi.value.unindex.specifics.error.message = uc->emsg;
  GNUNET_FS_unindex_make_status_ (&pi, uc, 0);
}


/**
 * Continuation called to notify client about result of the
 * datastore removal operation.
 *
 * @param cls closure
 * @param success GNUNET_SYSERR on failure
 * @param min_expiration minimum expiration time required for content to be stored
 * @param msg NULL on success, otherwise an error message
 */
static void
process_cont (void *cls, int success, struct GNUNET_TIME_Absolute min_expiration, const char *msg)
{
  struct GNUNET_FS_UnindexContext *uc = cls;

  if (success == GNUNET_SYSERR)
  {
    uc->emsg = GNUNET_strdup (msg);
    signal_unindex_error (uc);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Datastore REMOVE operation succeeded\n");
  GNUNET_FS_tree_encoder_next (uc->tc);
}


/**
 * Function called asking for the current (encoded)
 * block to be processed.  After processing the
 * client should either call "GNUNET_FS_tree_encode_next"
 * or (on error) "GNUNET_FS_tree_encode_finish".
 *
 * @param cls closure
 * @param chk content hash key for the block (key for lookup in the datastore)
 * @param offset offset of the block
 * @param depth depth of the block, 0 for DBLOCK
 * @param type type of the block (IBLOCK or DBLOCK)
 * @param block the (encrypted) block
 * @param block_size size of block (in bytes)
 */
static void
unindex_process (void *cls, const struct ContentHashKey *chk, uint64_t offset,
                 unsigned int depth, enum GNUNET_BLOCK_Type type,
                 const void *block, uint16_t block_size)
{
  struct GNUNET_FS_UnindexContext *uc = cls;
  uint32_t size;
  const void *data;
  struct OnDemandBlock odb;

  if (type != GNUNET_BLOCK_TYPE_FS_DBLOCK)
  {
    size = block_size;
    data = block;
  }
  else                          /* on-demand encoded DBLOCK */
  {
    size = sizeof (struct OnDemandBlock);
    odb.offset = GNUNET_htonll (offset);
    odb.file_id = uc->file_id;
    data = &odb;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending REMOVE request to DATASTORE service\n");
  GNUNET_DATASTORE_remove (uc->dsh, &chk->query, size, data, -2, 1,
                           GNUNET_CONSTANTS_SERVICE_TIMEOUT, &process_cont, uc);
  uc->chk = *chk;
}


/**
 * Function called with the response from the
 * FS service to our unindexing request.
 *
 * @param cls closure, unindex context
 * @param msg NULL on timeout, otherwise the response
 */
static void
process_fs_response (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_FS_UnindexContext *uc = cls;
  struct GNUNET_FS_ProgressInfo pi;

  if (uc->client != NULL)
  {
    GNUNET_CLIENT_disconnect (uc->client);
    uc->client = NULL;
  }
  if (uc->state != UNINDEX_STATE_FS_NOTIFY)
  {
    uc->state = UNINDEX_STATE_ERROR;
    uc->emsg =
        GNUNET_strdup (_("Unexpected time for a response from `fs' service."));
    GNUNET_FS_unindex_sync_ (uc);
    signal_unindex_error (uc);
    return;
  }
  if (NULL == msg)
  {
    uc->state = UNINDEX_STATE_ERROR;
    uc->emsg = GNUNET_strdup (_("Timeout waiting for `fs' service."));
    GNUNET_FS_unindex_sync_ (uc);
    signal_unindex_error (uc);
    return;
  }
  if (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_FS_UNINDEX_OK)
  {
    uc->state = UNINDEX_STATE_ERROR;
    uc->emsg = GNUNET_strdup (_("Invalid response from `fs' service."));
    GNUNET_FS_unindex_sync_ (uc);
    signal_unindex_error (uc);
    return;
  }
  uc->state = UNINDEX_STATE_COMPLETE;
  pi.status = GNUNET_FS_STATUS_UNINDEX_COMPLETED;
  pi.value.unindex.eta = GNUNET_TIME_UNIT_ZERO;
  GNUNET_FS_unindex_sync_ (uc);
  GNUNET_FS_unindex_make_status_ (&pi, uc, uc->file_size);
}


/**
 * Function called when we are done with removing KBlocks.
 * Disconnect from datastore and notify FS service about
 * the unindex event.
 *
 * @param uc our unindexing context
 */
static void
unindex_finish (struct GNUNET_FS_UnindexContext *uc)
{
  char *emsg;
  struct GNUNET_FS_Uri *uri;
  struct UnindexMessage req;

  /* generate final progress message */
  unindex_progress (uc, uc->file_size, NULL, 0, 0);
  GNUNET_FS_tree_encoder_finish (uc->tc, &uri, &emsg);
  uc->tc = NULL;
  if (uri != NULL)
    GNUNET_FS_uri_destroy (uri);
  GNUNET_DISK_file_close (uc->fh);
  uc->fh = NULL;
  GNUNET_DATASTORE_disconnect (uc->dsh, GNUNET_NO);
  uc->dsh = NULL;
  uc->state = UNINDEX_STATE_FS_NOTIFY;
  GNUNET_FS_unindex_sync_ (uc);
  uc->client = GNUNET_CLIENT_connect ("fs", uc->h->cfg);
  if (uc->client == NULL)
  {
    uc->state = UNINDEX_STATE_ERROR;
    uc->emsg =
        GNUNET_strdup (_("Failed to connect to FS service for unindexing."));
    GNUNET_FS_unindex_sync_ (uc);
    signal_unindex_error (uc);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending UNINDEX message to FS service\n");
  req.header.size = htons (sizeof (struct UnindexMessage));
  req.header.type = htons (GNUNET_MESSAGE_TYPE_FS_UNINDEX);
  req.reserved = 0;
  req.file_id = uc->file_id;
  GNUNET_break (GNUNET_OK ==
                GNUNET_CLIENT_transmit_and_get_response (uc->client,
                                                         &req.header,
                                                         GNUNET_CONSTANTS_SERVICE_TIMEOUT,
                                                         GNUNET_YES,
                                                         &process_fs_response,
                                                         uc));
}



/**
 * Function called by the directory scanner as we extract keywords
 * that we will need to remove KBlocks.
 *
 * @param cls the 'struct GNUNET_FS_UnindexContext *'
 * @param filename which file we are making progress on
 * @param is_directory GNUNET_YES if this is a directory,
 *                     GNUNET_NO if this is a file
 *                     GNUNET_SYSERR if it is neither (or unknown)
 * @param reason kind of progress we are making
 */
static void
unindex_directory_scan_cb (void *cls, 
			   const char *filename, 
			   int is_directory,
			   enum GNUNET_FS_DirScannerProgressUpdateReason reason)
{
  struct GNUNET_FS_UnindexContext *uc = cls;
  static struct GNUNET_FS_ShareTreeItem * directory_scan_result;

  switch (reason)
  {
  case GNUNET_FS_DIRSCANNER_FINISHED:
    directory_scan_result = GNUNET_FS_directory_scan_get_result (uc->dscan);
    uc->dscan = NULL;
    if (NULL != directory_scan_result->ksk_uri)
    {
      uc->ksk_uri = GNUNET_FS_uri_dup (directory_scan_result->ksk_uri);
      uc->state = UNINDEX_STATE_DS_REMOVE_KBLOCKS;
      uc->emsg = GNUNET_strdup (_("Failed to get KSKs from directory scan."));
      GNUNET_FS_unindex_sync_ (uc);
      GNUNET_FS_unindex_do_remove_kblocks_ (uc);
    }
    else
    {
      unindex_finish (uc);
    }
    GNUNET_FS_share_tree_free (directory_scan_result);
    break;
  case GNUNET_FS_DIRSCANNER_INTERNAL_ERROR:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Internal error scanning `%s'.\n"),
		uc->filename);
    break;
  default:
    break;
  }

}


/**
 * If necessary, connect to the datastore and remove the KBlocks.
 *
 * @param uc context for the unindex operation.
 */
void
GNUNET_FS_unindex_do_extract_keywords_ (struct GNUNET_FS_UnindexContext *uc)
{
  char *ex;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (uc->h->cfg, "FS", "EXTRACTORS", &ex))
    ex = NULL;
  uc->dscan = GNUNET_FS_directory_scan_start (uc->filename,
					      GNUNET_NO, ex,
					      &unindex_directory_scan_cb, 
					      uc);
  GNUNET_free_non_null (ex);
}


/**
 * Continuation called to notify client about result of the remove
 * operation for the KBlock.
 *
 * @param cls the 'struct GNUNET_FS_UnindexContext *' 
 * @param success GNUNET_SYSERR on failure (including timeout/queue drop)
 *                GNUNET_NO if content was already there
 *                GNUNET_YES (or other positive value) on success
 * @param min_expiration minimum expiration time required for 0-priority content to be stored
 *                by the datacache at this time, zero for unknown, forever if we have no
 *                space for 0-priority content
 * @param msg NULL on success, otherwise an error message
 */
static void
continue_after_remove (void *cls,
		       int32_t success,
		       struct GNUNET_TIME_Absolute min_expiration,
		       const char *msg)
{
  struct GNUNET_FS_UnindexContext *uc = cls;

  uc->dqe = NULL;
  if (success != GNUNET_YES)  
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to remove KBlock: %s\n"),
		msg);  
  uc->ksk_offset++;
  GNUNET_FS_unindex_do_remove_kblocks_ (uc);
}


/**
 * Function called from datastore with result from us looking for
 * a KBlock.  There are four cases:
 * 1) no result, means we move on to the next keyword
 * 2) UID is the same as the first UID, means we move on to next keyword
 * 3) KBlock for a different CHK, means we keep looking for more
 * 4) KBlock is for our CHK, means we remove the block and then move
 *           on to the next keyword
 *
 * @param cls the 'struct GNUNET_FS_UnindexContext *'
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
static void
process_kblock_for_unindex (void *cls,
			    const GNUNET_HashCode * key,
			    size_t size, const void *data,
			    enum GNUNET_BLOCK_Type type,
			    uint32_t priority,
			    uint32_t anonymity,
			    struct GNUNET_TIME_Absolute
			    expiration, uint64_t uid)
{
  struct GNUNET_FS_UnindexContext *uc = cls;
  const struct KBlock *kb;
  struct GNUNET_FS_Uri *chk_uri;

  uc->dqe = NULL;
  if (NULL == data)
  {
    /* no result */
    uc->ksk_offset++;
    GNUNET_FS_unindex_do_remove_kblocks_ (uc);
    return;
  }
  if (0 == uc->first_uid)
  {
    /* remember UID of first result to detect cycles */
    uc->first_uid = uid;    
  }
  else if (uid == uc->first_uid)
  {
    /* no more additional results */
    uc->ksk_offset++;
    GNUNET_FS_unindex_do_remove_kblocks_ (uc);
    return;  
  }
  GNUNET_assert (GNUNET_BLOCK_TYPE_FS_KBLOCK == type);
  if (size < sizeof (struct KBlock))
  {
    GNUNET_break (0);
    goto get_next;
  }
  kb = data;
  {
    char pt[size - sizeof (struct KBlock)];  
    struct GNUNET_CRYPTO_AesSessionKey skey;
    struct GNUNET_CRYPTO_AesInitializationVector iv;
 
    GNUNET_CRYPTO_hash_to_aes_key (&uc->key, &skey, &iv);
    if (-1 ==
	GNUNET_CRYPTO_aes_decrypt (&kb[1], size - sizeof (struct KBlock), &skey,
				   &iv, pt))
    {
      GNUNET_break (0);
      goto get_next;
    }       
    if (NULL == memchr (pt, 0, sizeof (pt)))
    {
      GNUNET_break (0);
      goto get_next;
    }
    chk_uri = GNUNET_FS_uri_parse (pt, NULL);
    if (NULL == chk_uri)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to parse URI `%s' from KBlock!\n"),
		  pt);
      GNUNET_break (0);
      goto get_next;
    }
  }
  if (0 != memcmp (&uc->chk,
		   &chk_uri->data.chk.chk,
		   sizeof (struct ContentHashKey)))
  {
    /* different CHK, ignore */
    GNUNET_FS_uri_destroy (chk_uri);
    goto get_next;
  }
  GNUNET_FS_uri_destroy (chk_uri);
  /* matches! */
  uc->dqe = GNUNET_DATASTORE_remove (uc->dsh,
				     key, size, data,
				     0 /* priority */, 1 /* queue size */,
				     GNUNET_TIME_UNIT_FOREVER_REL,
				     &continue_after_remove,
				     uc);
  return;
 get_next:
  uc->dqe = GNUNET_DATASTORE_get_key (uc->dsh,
				      uc->roff++,
				      &uc->query,
				      GNUNET_BLOCK_TYPE_FS_KBLOCK,
				      0 /* priority */, 1 /* queue size */,
				      GNUNET_TIME_UNIT_FOREVER_REL,
				      &process_kblock_for_unindex,
				      uc);
}


/**
 * If necessary, connect to the datastore and remove the KBlocks.
 *
 * @param uc context for the unindex operation.
 */
void
GNUNET_FS_unindex_do_remove_kblocks_ (struct GNUNET_FS_UnindexContext *uc)
{
  const char *keyword;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;
  struct GNUNET_CRYPTO_RsaPrivateKey *pk;

  if (NULL == uc->dsh)
    uc->dsh = GNUNET_DATASTORE_connect (uc->h->cfg);
  if (NULL == uc->dsh)
  {
    uc->state = UNINDEX_STATE_ERROR;
    uc->emsg = GNUNET_strdup (_("Failed to connect to `datastore' service."));
    GNUNET_FS_unindex_sync_ (uc);
    signal_unindex_error (uc);
    return;
  }
  if ( (NULL == uc->ksk_uri) ||
       (uc->ksk_offset >= uc->ksk_uri->data.ksk.keywordCount) )
  {
    unindex_finish (uc);
    return;
  }
  /* FIXME: code duplication with fs_search.c here... */
  keyword = &uc->ksk_uri->data.ksk.keywords[uc->ksk_offset][1];
  GNUNET_CRYPTO_hash (keyword, strlen (keyword), &uc->key);
  pk = GNUNET_CRYPTO_rsa_key_create_from_hash (&uc->key);
  GNUNET_assert (pk != NULL);
  GNUNET_CRYPTO_rsa_key_get_public (pk, &pub);
  GNUNET_CRYPTO_rsa_key_free (pk);
  GNUNET_CRYPTO_hash (&pub,
		      sizeof (struct
			      GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
		      &uc->query);
  uc->first_uid = 0;
  uc->dqe = GNUNET_DATASTORE_get_key (uc->dsh,
				      uc->roff++,
				      &uc->query,
				      GNUNET_BLOCK_TYPE_FS_KBLOCK,
				      0 /* priority */, 1 /* queue size */,
				      GNUNET_TIME_UNIT_FOREVER_REL,
				      &process_kblock_for_unindex,
				      uc);
}


/**
 * Function called when the tree encoder has
 * processed all blocks.  Clean up.
 *
 * @param cls our unindexing context
 * @param tc not used
 */
static void
unindex_extract_keywords (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_UnindexContext *uc = cls;

  uc->state = UNINDEX_STATE_EXTRACT_KEYWORDS;
  GNUNET_FS_unindex_sync_ (uc);
  GNUNET_FS_unindex_do_extract_keywords_ (uc);
}


/**
 * Connect to the datastore and remove the blocks.
 *
 * @param uc context for the unindex operation.
 */
void
GNUNET_FS_unindex_do_remove_ (struct GNUNET_FS_UnindexContext *uc)
{
  if (NULL == uc->dsh)
    uc->dsh = GNUNET_DATASTORE_connect (uc->h->cfg);
  if (NULL == uc->dsh)
  {
    uc->state = UNINDEX_STATE_ERROR;
    uc->emsg = GNUNET_strdup (_("Failed to connect to `datastore' service."));
    GNUNET_FS_unindex_sync_ (uc);
    signal_unindex_error (uc);
    return;
  }
  uc->fh =
      GNUNET_DISK_file_open (uc->filename, GNUNET_DISK_OPEN_READ,
                             GNUNET_DISK_PERM_NONE);
  if (NULL == uc->fh)
  {
    GNUNET_DATASTORE_disconnect (uc->dsh, GNUNET_NO);
    uc->dsh = NULL;
    uc->state = UNINDEX_STATE_ERROR;
    uc->emsg = GNUNET_strdup (_("Failed to open file for unindexing."));
    GNUNET_FS_unindex_sync_ (uc);
    signal_unindex_error (uc);
    return;
  }
  uc->tc =
      GNUNET_FS_tree_encoder_create (uc->h, uc->file_size, uc, &unindex_reader,
                                     &unindex_process, &unindex_progress,
                                     &unindex_extract_keywords);
  GNUNET_FS_tree_encoder_next (uc->tc);
}


/**
 * Function called once the hash of the file
 * that is being unindexed has been computed.
 *
 * @param cls closure, unindex context
 * @param file_id computed hash, NULL on error
 */
void
GNUNET_FS_unindex_process_hash_ (void *cls, const GNUNET_HashCode * file_id)
{
  struct GNUNET_FS_UnindexContext *uc = cls;

  uc->fhc = NULL;
  if (uc->state != UNINDEX_STATE_HASHING)
  {
    GNUNET_FS_unindex_stop (uc);
    return;
  }
  if (file_id == NULL)
  {
    uc->state = UNINDEX_STATE_ERROR;
    uc->emsg = GNUNET_strdup (_("Failed to compute hash of file."));
    GNUNET_FS_unindex_sync_ (uc);
    signal_unindex_error (uc);
    return;
  }
  uc->file_id = *file_id;
  uc->state = UNINDEX_STATE_DS_REMOVE;
  GNUNET_FS_unindex_sync_ (uc);
  GNUNET_FS_unindex_do_remove_ (uc);
}


/**
 * Create SUSPEND event for the given unindex operation
 * and then clean up our state (without stop signal).
 *
 * @param cls the 'struct GNUNET_FS_UnindexContext' to signal for
 */
void
GNUNET_FS_unindex_signal_suspend_ (void *cls)
{
  struct GNUNET_FS_UnindexContext *uc = cls;
  struct GNUNET_FS_ProgressInfo pi;

  /* FIXME: lots of duplication with unindex_stop here! */
  if (uc->dscan != NULL)
  {
    GNUNET_FS_directory_scan_abort (uc->dscan);
    uc->dscan = NULL;
  }
  if (NULL != uc->dqe)
  {
    GNUNET_DATASTORE_cancel (uc->dqe);
    uc->dqe = NULL;
  }
  if (uc->fhc != NULL)
  {
    GNUNET_CRYPTO_hash_file_cancel (uc->fhc);
    uc->fhc = NULL;
  }
  if (NULL != uc->ksk_uri)
  {
    GNUNET_FS_uri_destroy (uc->ksk_uri);
    uc->ksk_uri = NULL;
  }
  if (uc->client != NULL)
  {
    GNUNET_CLIENT_disconnect (uc->client);
    uc->client = NULL;
  }
  if (NULL != uc->dsh)
  {
    GNUNET_DATASTORE_disconnect (uc->dsh, GNUNET_NO);
    uc->dsh = NULL;
  }
  if (NULL != uc->tc)
  {
    GNUNET_FS_tree_encoder_finish (uc->tc, NULL, NULL);
    uc->tc = NULL;
  }
  if (uc->fh != NULL)
  {
    GNUNET_DISK_file_close (uc->fh);
    uc->fh = NULL;
  }
  GNUNET_FS_end_top (uc->h, uc->top);
  pi.status = GNUNET_FS_STATUS_UNINDEX_SUSPEND;
  GNUNET_FS_unindex_make_status_ (&pi, uc,
                                  (uc->state ==
                                   UNINDEX_STATE_COMPLETE) ? uc->file_size : 0);
  GNUNET_break (NULL == uc->client_info);
  GNUNET_free (uc->filename);
  GNUNET_free_non_null (uc->serialization);
  GNUNET_free_non_null (uc->emsg);
  GNUNET_free (uc);
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
GNUNET_FS_unindex_start (struct GNUNET_FS_Handle *h, const char *filename,
                         void *cctx)
{
  struct GNUNET_FS_UnindexContext *ret;
  struct GNUNET_FS_ProgressInfo pi;
  uint64_t size;

  if (GNUNET_OK != GNUNET_DISK_file_size (filename, &size, GNUNET_YES, GNUNET_YES))
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_UnindexContext));
  ret->h = h;
  ret->filename = GNUNET_strdup (filename);
  ret->start_time = GNUNET_TIME_absolute_get ();
  ret->file_size = size;
  ret->client_info = cctx;
  GNUNET_FS_unindex_sync_ (ret);
  pi.status = GNUNET_FS_STATUS_UNINDEX_START;
  pi.value.unindex.eta = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_FS_unindex_make_status_ (&pi, ret, 0);
  ret->fhc =
      GNUNET_CRYPTO_hash_file (GNUNET_SCHEDULER_PRIORITY_IDLE, filename,
                               HASHING_BLOCKSIZE,
                               &GNUNET_FS_unindex_process_hash_, ret);
  ret->top = GNUNET_FS_make_top (h, &GNUNET_FS_unindex_signal_suspend_, ret);
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

  if (uc->dscan != NULL)
  {
    GNUNET_FS_directory_scan_abort (uc->dscan);
    uc->dscan = NULL;
  }
  if (NULL != uc->dqe)
  {
    GNUNET_DATASTORE_cancel (uc->dqe);
    uc->dqe = NULL;
  }
  if (uc->fhc != NULL)
  {
    GNUNET_CRYPTO_hash_file_cancel (uc->fhc);
    uc->fhc = NULL;
  }
  if (uc->client != NULL)
  {
    GNUNET_CLIENT_disconnect (uc->client);
    uc->client = NULL;
  }
  if (NULL != uc->dsh)
  {
    GNUNET_DATASTORE_disconnect (uc->dsh, GNUNET_NO);
    uc->dsh = NULL;
  }
  if (NULL != uc->ksk_uri)
  {
    GNUNET_FS_uri_destroy (uc->ksk_uri);
    uc->ksk_uri = NULL;
  }
  if (NULL != uc->tc)
  {
    GNUNET_FS_tree_encoder_finish (uc->tc, NULL, NULL);
    uc->tc = NULL;
  }
  if (uc->fh != NULL)
  {
    GNUNET_DISK_file_close (uc->fh);
    uc->fh = NULL;
  }
  GNUNET_FS_end_top (uc->h, uc->top);
  if (uc->serialization != NULL)
  {
    GNUNET_FS_remove_sync_file_ (uc->h, GNUNET_FS_SYNC_PATH_MASTER_UNINDEX,
                                 uc->serialization);
    GNUNET_free (uc->serialization);
    uc->serialization = NULL;
  }
  pi.status = GNUNET_FS_STATUS_UNINDEX_STOPPED;
  pi.value.unindex.eta = GNUNET_TIME_UNIT_ZERO;
  GNUNET_FS_unindex_make_status_ (&pi, uc,
                                  (uc->state ==
                                   UNINDEX_STATE_COMPLETE) ? uc->file_size : 0);
  GNUNET_break (NULL == uc->client_info);
  GNUNET_free_non_null (uc->emsg);
  GNUNET_free (uc->filename);
  GNUNET_free (uc);
}

/* end of fs_unindex.c */
