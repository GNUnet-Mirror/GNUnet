/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_download.c
 * @brief download methods
 * @author Christian Grothoff
 *
 * TODO:
 * - process replies
 * - callback signaling
 * - check if blocks exist already 
 * - location URI suppport (can wait)
 * - persistence (can wait)
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_fs_service.h"
#include "fs.h"
#include "fs_tree.h"

#define DEBUG_DOWNLOAD GNUNET_YES


/**
 * Schedule the download of the specified
 * block in the tree.
 *
 * @param dc overall download this block belongs to
 * @param chk content-hash-key of the block
 * @param offset offset of the block in the file
 *         (for IBlocks, the offset is the lowest
 *          offset of any DBlock in the subtree under
 *          the IBlock)
 * @param depth depth of the block, 0 is the root of the tree
 */
static void
schedule_block_download (struct GNUNET_FS_DownloadContext *dc,
			 const struct ContentHashKey *chk,
			 uint64_t offset,
			 unsigned int depth)
{
  struct DownloadRequest *sm;

  // FIXME: check if block exists on disk!
  sm = GNUNET_malloc (sizeof (struct DownloadRequest));
  sm->chk = *chk;
  sm->offset = offset;
  sm->depth = depth;
  sm->is_pending = GNUNET_YES;
  sm->next = dc->pending;
  dc->pending = sm;
  GNUNET_CONTAINER_multihashmap_put (dc->active,
				     &chk->query,
				     sm,
				     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
}


/**
 * We've lost our connection with the FS service.
 * Re-establish it and re-transmit all of our
 * pending requests.
 *
 * @param dc download context that is having trouble
 */
static void
try_reconnect (struct GNUNET_FS_DownloadContext *dc);


/**
 * Process a search result.
 *
 * @param sc our search context
 * @param type type of the result
 * @param data the (encrypted) response
 * @param size size of data
 */
static void
process_result (struct GNUNET_FS_DownloadContext *dc,
		uint32_t type,
		const void *data,
		size_t size)
{
  GNUNET_HashCode query;
  struct DownloadRequest *sm;
  struct GNUNET_CRYPTO_AesSessionKey skey;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  char pt[size];

  GNUNET_CRYPTO_hash (data, size, &query);
  sm = GNUNET_CONTAINER_multihashmap_get (dc->active,
					  &query);
  if (NULL == sm)
    {
      GNUNET_break (0);
      return;
    }
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (dc->active,
						       &query,
						       sm));
  GNUNET_CRYPTO_hash_to_aes_key (&sm->chk.key, &skey, &iv);
  GNUNET_CRYPTO_aes_decrypt (data,
			     size,
			     &skey,
			     &iv,
			     pt);
  // FIXME: save to disk
  // FIXME: make persistent
  // FIXME: call progress callback
  // FIXME: trigger next block (if applicable)  
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void 
receive_results (void *cls,
		 const struct GNUNET_MessageHeader * msg)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  const struct ContentMessage *cm;
  uint16_t msize;

  if ( (NULL == msg) ||
       (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_FS_CONTENT) ||
       (ntohs (msg->size) <= sizeof (struct ContentMessage)) )
    {
      try_reconnect (dc);
      return;
    }
  msize = ntohs (msg->size);
  cm = (const struct ContentMessage*) msg;
  process_result (dc, 
		  ntohl (cm->type),
		  &cm[1],
		  msize - sizeof (struct ContentMessage));
  /* continue receiving */
  GNUNET_CLIENT_receive (dc->client,
			 &receive_results,
			 dc,
			 GNUNET_TIME_UNIT_FOREVER_REL);
}



/**
 * We're ready to transmit a search request to the
 * file-sharing service.  Do it.  If there is 
 * more than one request pending, try to send 
 * multiple or request another transmission.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_download_request (void *cls,
			   size_t size, 
			   void *buf)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  size_t msize;
  struct SearchMessage *sm;

  if (NULL == buf)
    {
      try_reconnect (dc);
      return 0;
    }
  GNUNET_assert (size >= sizeof (struct SearchMessage));
  msize = 0;
  sm = buf;
  while ( (dc->pending == NULL) &&
	  (size > msize + sizeof (struct SearchMessage)) )
    {
      memset (sm, 0, sizeof (struct SearchMessage));
      sm->header.size = htons (sizeof (struct SearchMessage));
      sm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_START_SEARCH);
      sm->anonymity_level = htonl (dc->anonymity);
      sm->target = dc->target.hashPubKey;
      sm->query = dc->pending->chk.query;
      dc->pending->is_pending = GNUNET_NO;
      dc->pending = dc->pending->next;
      msize += sizeof (struct SearchMessage);
      sm++;
    }
  return msize;
}


/**
 * Reconnect to the FS service and transmit
 * our queries NOW.
 *
 * @param cls our download context
 * @param tc unused
 */
static void
do_reconnect (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  struct GNUNET_CLIENT_Connection *client;
  
  dc->task = GNUNET_SCHEDULER_NO_TASK;
  client = GNUNET_CLIENT_connect (dc->h->sched,
				  "fs",
				  dc->h->cfg);
  if (NULL == client)
    {
      try_reconnect (dc);
      return;
    }
  dc->client = client;
  GNUNET_CLIENT_notify_transmit_ready (client,
				       sizeof (struct SearchMessage),
                                       GNUNET_CONSTANTS_SERVICE_TIMEOUT,
				       &transmit_download_request,
				       dc);  
  GNUNET_CLIENT_receive (client,
			 &receive_results,
			 dc,
			 GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Add entries that are not yet pending back to
 * the pending list.
 *
 * @param cls our download context
 * @param key unused
 * @param entry entry of type "struct DownloadRequest"
 * @return GNUNET_OK
 */
static int
retry_entry (void *cls,
	     const GNUNET_HashCode *key,
	     void *entry)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  struct DownloadRequest *dr = entry;

  if (! dr->is_pending)
    {
      dr->next = dc->pending;
      dr->is_pending = GNUNET_YES;
      dc->pending = entry;
    }
  return GNUNET_OK;
}


/**
 * We've lost our connection with the FS service.
 * Re-establish it and re-transmit all of our
 * pending requests.
 *
 * @param dc download context that is having trouble
 */
static void
try_reconnect (struct GNUNET_FS_DownloadContext *dc)
{
  
  if (NULL != dc->client)
    {
      GNUNET_CONTAINER_multihashmap_iterate (dc->active,
					     &retry_entry,
					     dc);
      GNUNET_CLIENT_disconnect (dc->client);
      dc->client = NULL;
    }
  dc->task
    = GNUNET_SCHEDULER_add_delayed (dc->h->sched,
				    GNUNET_NO,
				    GNUNET_SCHEDULER_PRIORITY_IDLE,
				    GNUNET_SCHEDULER_NO_TASK,
				    GNUNET_TIME_UNIT_SECONDS,
				    &do_reconnect,
				    dc);
}


/**
 * Download parts of a file.  Note that this will store
 * the blocks at the respective offset in the given file.  Also, the
 * download is still using the blocking of the underlying FS
 * encoding.  As a result, the download may *write* outside of the
 * given boundaries (if offset and length do not match the 32k FS
 * block boundaries). <p>
 *
 * This function should be used to focus a download towards a
 * particular portion of the file (optimization), not to strictly
 * limit the download to exactly those bytes.
 *
 * @param h handle to the file sharing subsystem
 * @param uri the URI of the file (determines what to download); CHK or LOC URI
 * @param filename where to store the file, maybe NULL (then no file is
 *        created on disk and data must be grabbed from the callbacks)
 * @param offset at what offset should we start the download (typically 0)
 * @param length how many bytes should be downloaded starting at offset
 * @param anonymity anonymity level to use for the download
 * @param options various options
 * @param parent parent download to associate this download with (use NULL
 *        for top-level downloads; useful for manually-triggered recursive downloads)
 * @return context that can be used to control this download
 */
struct GNUNET_FS_DownloadContext *
GNUNET_FS_file_download_start (struct GNUNET_FS_Handle *h,
			       const struct GNUNET_FS_Uri *uri,
			       const char *filename,
			       uint64_t offset,
			       uint64_t length,
			       uint32_t anonymity,
			       enum GNUNET_FS_DownloadOptions options,
			       struct GNUNET_FS_DownloadContext *parent)
{
  struct GNUNET_FS_DownloadContext *dc;
  struct GNUNET_CLIENT_Connection *client;

  client = GNUNET_CLIENT_connect (h->sched,
				  "fs",
				  h->cfg);
  if (NULL == client)
    return NULL;
  // FIXME: add support for "loc" URIs!
  GNUNET_assert (GNUNET_FS_uri_test_chk (uri));
  if ( (dc->offset + dc->length < dc->offset) ||
       (dc->offset + dc->length > uri->data.chk.file_length) )
    {
      GNUNET_break (0);
      return NULL;
    }
  dc = GNUNET_malloc (sizeof(struct GNUNET_FS_DownloadContext));
  dc->h = h;
  dc->client = client;
  dc->parent = parent;
  dc->uri = GNUNET_FS_uri_dup (uri);
  if (NULL != filename)
    {
      dc->filename = GNUNET_strdup (filename);
      dc->handle = GNUNET_DISK_file_open (filename, 
					  GNUNET_DISK_OPEN_READWRITE | 
					  GNUNET_DISK_OPEN_CREATE,
					  GNUNET_DISK_PERM_USER_READ |
					  GNUNET_DISK_PERM_USER_WRITE |
					  GNUNET_DISK_PERM_GROUP_READ |
					  GNUNET_DISK_PERM_OTHER_READ);
      if (dc->handle == NULL)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _("Download failed: could not open file `%s': %s\n"),
		      dc->filename,
		      STRERROR (errno));
	  GNUNET_FS_uri_destroy (dc->uri);
	  GNUNET_free (dc->filename);
	  GNUNET_CLIENT_disconnect (dc->client);
	  GNUNET_free (dc);
	  return NULL;
	}
    }
  // FIXME: set "dc->target" for LOC uris!
  dc->offset = offset;
  dc->length = length;
  dc->anonymity = anonymity;
  dc->options = options;
  dc->active = GNUNET_CONTAINER_multihashmap_create (1 + (length / DBLOCK_SIZE));
  dc->treedepth = GNUNET_FS_compute_depth (GNUNET_ntohll(dc->uri->data.chk.file_length));
  // FIXME: make persistent
  schedule_block_download (dc, 
			   &dc->uri->data.chk.chk,
			   0, 
			   0);
  GNUNET_CLIENT_notify_transmit_ready (client,
				       sizeof (struct SearchMessage),
                                       GNUNET_CONSTANTS_SERVICE_TIMEOUT,
				       &transmit_download_request,
				       dc);  
  GNUNET_CLIENT_receive (client,
			 &receive_results,
			 dc,
			 GNUNET_TIME_UNIT_FOREVER_REL);
  // FIXME: signal download start
  return dc;
}


/**
 * Free entries in the map.
 *
 * @param cls unused (NULL)
 * @param key unused
 * @param entry entry of type "struct DownloadRequest" which is freed
 * @return GNUNET_OK
 */
static int
free_entry (void *cls,
	    const GNUNET_HashCode *key,
	    void *entry)
{
  GNUNET_free (entry);
  return GNUNET_OK;
}


/**
 * Stop a download (aborts if download is incomplete).
 *
 * @param dc handle for the download
 * @param do_delete delete files of incomplete downloads
 */
void
GNUNET_FS_file_download_stop (struct GNUNET_FS_DownloadContext *dc,
			      int do_delete)
{
  // FIXME: make unpersistent
  // FIXME: signal download end
  
  if (GNUNET_SCHEDULER_NO_TASK != dc->task)
    GNUNET_SCHEDULER_cancel (dc->h->sched,
			     dc->task);
  if (NULL != dc->client)
    GNUNET_CLIENT_disconnect (dc->client);
  GNUNET_CONTAINER_multihashmap_iterate (dc->active,
					 &free_entry,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (dc->active);
  if (dc->filename != NULL)
    {
      GNUNET_DISK_file_close (dc->handle);
      if ( (dc->completed != dc->length) &&
	   (GNUNET_YES == do_delete) )
	{
	  if (0 != UNLINK (dc->filename))
	    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
				      "unlink",
				      dc->filename);
	}
      GNUNET_free (dc->filename);
    }
  GNUNET_FS_uri_destroy (dc->uri);
  GNUNET_free (dc);
}


















#if 0

/**
 * Compute how many bytes of data are stored in
 * this node.
 */
static unsigned int
get_node_size (const struct Node *node)
{
  unsigned int i;
  unsigned int ret;
  unsigned long long rsize;
  unsigned long long spos;
  unsigned long long epos;

  GNUNET_GE_ASSERT (node->ctx->ectx, node->offset < node->ctx->total);
  if (node->level == 0)
    {
      ret = GNUNET_ECRS_DBLOCK_SIZE;
      if (node->offset + (unsigned long long) ret > node->ctx->total)
        ret = (unsigned int) (node->ctx->total - node->offset);
#if DEBUG_DOWNLOAD
      GNUNET_GE_LOG (node->ctx->rm->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Node at offset %llu and level %d has size %u\n",
                     node->offset, node->level, ret);
#endif
      return ret;
    }
  rsize = GNUNET_ECRS_DBLOCK_SIZE;
  for (i = 0; i < node->level - 1; i++)
    rsize *= GNUNET_ECRS_CHK_PER_INODE;
  spos = rsize * (node->offset / sizeof (GNUNET_EC_ContentHashKey));
  epos = spos + rsize * GNUNET_ECRS_CHK_PER_INODE;
  if (epos > node->ctx->total)
    epos = node->ctx->total;
  ret = (epos - spos) / rsize;
  if (ret * rsize < epos - spos)
    ret++;                      /* need to round up! */
#if DEBUG_DOWNLOAD
  GNUNET_GE_LOG (node->ctx->rm->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Node at offset %llu and level %d has size %u\n",
                 node->offset, node->level,
                 ret * sizeof (GNUNET_EC_ContentHashKey));
#endif
  return ret * sizeof (GNUNET_EC_ContentHashKey);
}

/**
 * Check if self block is already present on the drive.  If the block
 * is a dblock and present, the ProgressModel is notified. If the
 * block is present and it is an iblock, downloading the children is
 * triggered.
 *
 * Also checks if the block is within the range of blocks
 * that we are supposed to download.  If not, the method
 * returns as if the block is present but does NOT signal
 * progress.
 *
 * @param node that is checked for presence
 * @return GNUNET_YES if present, GNUNET_NO if not.
 */
static int
check_node_present (const struct Node *node)
{
  int res;
  int ret;
  char *data;
  unsigned int size;
  GNUNET_HashCode hc;

  size = get_node_size (node);
  /* first check if node is within range.
     For now, keeping it simple, we only do
     this for level-0 nodes */
  if ((node->level == 0) &&
      ((node->offset + size < node->ctx->offset) ||
       (node->offset >= node->ctx->offset + node->ctx->length)))
    return GNUNET_YES;
  data = GNUNET_malloc (size);
  ret = GNUNET_NO;
  res = read_from_files (node->ctx, node->level, node->offset, data, size);
  if (res == size)
    {
      GNUNET_hash (data, size, &hc);
      if (0 == memcmp (&hc, &node->chk.key, sizeof (GNUNET_HashCode)))
        {
          notify_client_about_progress (node, data, size);
          if (node->level > 0)
            iblock_download_children (node, data, size);
          ret = GNUNET_YES;
        }
    }
  GNUNET_free (data);
  return ret;
}

/**
 * DOWNLOAD children of this GNUNET_EC_IBlock.
 *
 * @param node the node that should be downloaded
 */
static void
iblock_download_children (const struct Node *node,
                          const char *data, unsigned int size)
{
  struct GNUNET_GE_Context *ectx = node->ctx->ectx;
  int i;
  struct Node *child;
  unsigned int childcount;
  const GNUNET_EC_ContentHashKey *chks;
  unsigned int levelSize;
  unsigned long long baseOffset;

  GNUNET_GE_ASSERT (ectx, node->level > 0);
  childcount = size / sizeof (GNUNET_EC_ContentHashKey);
  if (size != childcount * sizeof (GNUNET_EC_ContentHashKey))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return;
    }
  if (node->level == 1)
    {
      levelSize = GNUNET_ECRS_DBLOCK_SIZE;
      baseOffset =
        node->offset / sizeof (GNUNET_EC_ContentHashKey) *
        GNUNET_ECRS_DBLOCK_SIZE;
    }
  else
    {
      levelSize =
        sizeof (GNUNET_EC_ContentHashKey) * GNUNET_ECRS_CHK_PER_INODE;
      baseOffset = node->offset * GNUNET_ECRS_CHK_PER_INODE;
    }
  chks = (const GNUNET_EC_ContentHashKey *) data;
  for (i = 0; i < childcount; i++)
    {
      child = GNUNET_malloc (sizeof (struct Node));
      child->ctx = node->ctx;
      child->chk = chks[i];
      child->offset = baseOffset + i * levelSize;
      GNUNET_GE_ASSERT (ectx, child->offset < node->ctx->total);
      child->level = node->level - 1;
      GNUNET_GE_ASSERT (ectx, (child->level != 0) ||
                        ((child->offset % GNUNET_ECRS_DBLOCK_SIZE) == 0));
      if (GNUNET_NO == check_node_present (child))
        add_request (child);
      else
        GNUNET_free (child);    /* done already! */
    }
}

#endif


/* end of fs_download.c */
