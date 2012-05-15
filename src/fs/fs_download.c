/*
     This file is part of GNUnet.
     (C) 2001-2012 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_download.c
 * @brief download methods
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_fs_service.h"
#include "fs_api.h"
#include "fs_tree.h"


/**
 * Determine if the given download (options and meta data) should cause
 * use to try to do a recursive download.
 */
static int
is_recursive_download (struct GNUNET_FS_DownloadContext *dc)
{
  return (0 != (dc->options & GNUNET_FS_DOWNLOAD_OPTION_RECURSIVE)) &&
      ((GNUNET_YES == GNUNET_FS_meta_data_test_for_directory (dc->meta)) ||
       ((NULL == dc->meta) &&
        ((NULL == dc->filename) ||
         ((strlen (dc->filename) >= strlen (GNUNET_FS_DIRECTORY_EXT)) &&
          (NULL !=
           strstr (dc->filename + strlen (dc->filename) -
                   strlen (GNUNET_FS_DIRECTORY_EXT),
                   GNUNET_FS_DIRECTORY_EXT))))));
}


/**
 * We're storing the IBLOCKS after the DBLOCKS on disk (so that we
 * only have to truncate the file once we're done).
 *
 * Given the offset of a block (with respect to the DBLOCKS) and its
 * depth, return the offset where we would store this block in the
 * file.
 *
 * @param fsize overall file size
 * @param off offset of the block in the file
 * @param depth depth of the block in the tree, 0 for DBLOCK
 * @return off for DBLOCKS (depth == treedepth),
 *         otherwise an offset past the end
 *         of the file that does not overlap
 *         with the range for any other block
 */
static uint64_t
compute_disk_offset (uint64_t fsize, uint64_t off, unsigned int depth)
{
  unsigned int i;
  uint64_t lsize;               /* what is the size of all IBlocks for depth "i"? */
  uint64_t loff;                /* where do IBlocks for depth "i" start? */
  unsigned int ioff;            /* which IBlock corresponds to "off" at depth "i"? */

  if (0 == depth)
    return off;
  /* first IBlocks start at the end of file, rounded up
   * to full DBLOCK_SIZE */
  loff = ((fsize + DBLOCK_SIZE - 1) / DBLOCK_SIZE) * DBLOCK_SIZE;
  lsize =
      ((fsize + DBLOCK_SIZE -
        1) / DBLOCK_SIZE) * sizeof (struct ContentHashKey);
  GNUNET_assert (0 == (off % DBLOCK_SIZE));
  ioff = (off / DBLOCK_SIZE);
  for (i = 1; i < depth; i++)
  {
    loff += lsize;
    lsize = (lsize + CHK_PER_INODE - 1) / CHK_PER_INODE;
    GNUNET_assert (lsize > 0);
    GNUNET_assert (0 == (ioff % CHK_PER_INODE));
    ioff /= CHK_PER_INODE;
  }
  return loff + ioff * sizeof (struct ContentHashKey);
}


/**
 * Fill in all of the generic fields for a download event and call the
 * callback.
 *
 * @param pi structure to fill in
 * @param dc overall download context
 */
void
GNUNET_FS_download_make_status_ (struct GNUNET_FS_ProgressInfo *pi,
                                 struct GNUNET_FS_DownloadContext *dc)
{
  pi->value.download.dc = dc;
  pi->value.download.cctx = dc->client_info;
  pi->value.download.pctx =
      (NULL == dc->parent) ? NULL : dc->parent->client_info;
  pi->value.download.sctx =
      (NULL == dc->search) ? NULL : dc->search->client_info;
  pi->value.download.uri = dc->uri;
  pi->value.download.filename = dc->filename;
  pi->value.download.size = dc->length;
  /* FIXME: Fix duration calculation to account for pauses */
  pi->value.download.duration =
      GNUNET_TIME_absolute_get_duration (dc->start_time);
  pi->value.download.completed = dc->completed;
  pi->value.download.anonymity = dc->anonymity;
  pi->value.download.eta =
      GNUNET_TIME_calculate_eta (dc->start_time, dc->completed, dc->length);
  pi->value.download.is_active = (NULL == dc->client) ? GNUNET_NO : GNUNET_YES;
  if (0 == (dc->options & GNUNET_FS_DOWNLOAD_IS_PROBE))
    dc->client_info = dc->h->upcb (dc->h->upcb_cls, pi);
  else
    dc->client_info = GNUNET_FS_search_probe_progress_ (NULL, pi);
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
transmit_download_request (void *cls, size_t size, void *buf);


/**
 * Closure for iterator processing results.
 */
struct ProcessResultClosure
{

  /**
   * Hash of data.
   */
  GNUNET_HashCode query;

  /**
   * Data found in P2P network.
   */
  const void *data;

  /**
   * Our download context.
   */
  struct GNUNET_FS_DownloadContext *dc;

  /**
   * Number of bytes in data.
   */
  size_t size;

  /**
   * Type of data.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Flag to indicate if this block should be stored on disk.
   */
  int do_store;

  /**
   * When did we last transmit the request?
   */
  struct GNUNET_TIME_Absolute last_transmission;

};


/**
 * Iterator over entries in the pending requests in the 'active' map for the
 * reply that we just got.
 *
 * @param cls closure (our 'struct ProcessResultClosure')
 * @param key query for the given value / request
 * @param value value in the hash map (a 'struct DownloadRequest')
 * @return GNUNET_YES (we should continue to iterate); unless serious error
 */
static int
process_result_with_request (void *cls, const GNUNET_HashCode * key,
                             void *value);


/**
 * We've found a matching block without downloading it.
 * Encrypt it and pass it to our "receive" function as
 * if we had received it from the network.
 *
 * @param dc download in question
 * @param chk request this relates to
 * @param dr request details
 * @param block plaintext data matching request
 * @param len number of bytes in block
 * @param do_store should we still store the block on disk?
 * @return GNUNET_OK on success
 */
static int
encrypt_existing_match (struct GNUNET_FS_DownloadContext *dc,
                        const struct ContentHashKey *chk,
                        struct DownloadRequest *dr, const char *block,
                        size_t len, int do_store)
{
  struct ProcessResultClosure prc;
  char enc[len];
  struct GNUNET_CRYPTO_AesSessionKey sk;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  GNUNET_HashCode query;

  GNUNET_CRYPTO_hash_to_aes_key (&chk->key, &sk, &iv);
  if (-1 == GNUNET_CRYPTO_aes_encrypt (block, len, &sk, &iv, enc))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_hash (enc, len, &query);
  if (0 != memcmp (&query, &chk->query, sizeof (GNUNET_HashCode)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Matching %u byte block for `%s' at offset %llu already present, no need for download!\n",
	      (unsigned int) len,
              dc->filename, (unsigned long long) dr->offset);
  /* already got it! */
  prc.dc = dc;
  prc.data = enc;
  prc.size = len;
  prc.type =
      (0 ==
       dr->depth) ? GNUNET_BLOCK_TYPE_FS_DBLOCK : GNUNET_BLOCK_TYPE_FS_IBLOCK;
  prc.query = chk->query;
  prc.do_store = do_store;
  prc.last_transmission = GNUNET_TIME_UNIT_FOREVER_ABS;
  process_result_with_request (&prc, &chk->key, dr);
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
try_reconnect (struct GNUNET_FS_DownloadContext *dc);


/**
 * We found an entry in a directory.  Check if the respective child
 * already exists and if not create the respective child download.
 *
 * @param cls the parent download
 * @param filename name of the file in the directory
 * @param uri URI of the file (CHK or LOC)
 * @param meta meta data of the file
 * @param length number of bytes in data
 * @param data contents of the file (or NULL if they were not inlined)
 */
static void
trigger_recursive_download (void *cls, const char *filename,
                            const struct GNUNET_FS_Uri *uri,
                            const struct GNUNET_CONTAINER_MetaData *meta,
                            size_t length, const void *data);


/**
 * We're done downloading a directory.  Open the file and
 * trigger all of the (remaining) child downloads.
 *
 * @param dc context of download that just completed
 */
static void
full_recursive_download (struct GNUNET_FS_DownloadContext *dc)
{
  size_t size;
  uint64_t size64;
  void *data;
  struct GNUNET_DISK_FileHandle *h;
  struct GNUNET_DISK_MapHandle *m;

  size64 = GNUNET_FS_uri_chk_get_file_size (dc->uri);
  size = (size_t) size64;
  if (size64 != (uint64_t) size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Recursive downloads of directories larger than 4 GB are not supported on 32-bit systems\n"));
    return;
  }
  if (NULL != dc->filename)
  {
    h = GNUNET_DISK_file_open (dc->filename, GNUNET_DISK_OPEN_READ,
                               GNUNET_DISK_PERM_NONE);
  }
  else
  {
    GNUNET_assert (NULL != dc->temp_filename);
    h = GNUNET_DISK_file_open (dc->temp_filename, GNUNET_DISK_OPEN_READ,
                               GNUNET_DISK_PERM_NONE);
  }
  if (NULL == h)
    return;                     /* oops */
  data = GNUNET_DISK_file_map (h, &m, GNUNET_DISK_MAP_TYPE_READ, size);
  if (NULL == data)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Directory too large for system address space\n"));
  }
  else
  {
    GNUNET_FS_directory_list_contents (size, data, 0,
                                       &trigger_recursive_download, dc);
    GNUNET_DISK_file_unmap (m);
  }
  GNUNET_DISK_file_close (h);
  if (NULL == dc->filename)
  {
    if (0 != UNLINK (dc->temp_filename))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink",
                                dc->temp_filename);
    GNUNET_free (dc->temp_filename);
    dc->temp_filename = NULL;
  }
}


/**
 * Check if all child-downloads have completed (or trigger them if
 * necessary) and once we're completely done, signal completion (and
 * possibly recurse to parent).  This function MUST be called when the
 * download of a file itself is done or when the download of a file is
 * done and then later a direct child download has completed (and
 * hence this download may complete itself).
 *
 * @param dc download to check for completion of children
 */
static void
check_completed (struct GNUNET_FS_DownloadContext *dc)
{
  struct GNUNET_FS_ProgressInfo pi;
  struct GNUNET_FS_DownloadContext *pos;

  /* first, check if we need to download children */
  if ((NULL == dc->child_head) && (is_recursive_download (dc)))
    full_recursive_download (dc);
  /* then, check if children are done already */
  for (pos = dc->child_head; NULL != pos; pos = pos->next)
  {
    if ((pos->emsg == NULL) && (pos->completed < pos->length))
      return;                   /* not done yet */
    if ((pos->child_head != NULL) && (pos->has_finished != GNUNET_YES))
      return;                   /* not transitively done yet */
  }
  /* All of our children are done, so mark this download done */
  dc->has_finished = GNUNET_YES;
  if (NULL != dc->job_queue)
  {
    GNUNET_FS_dequeue_ (dc->job_queue);
    dc->job_queue = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != dc->task)
  {
    GNUNET_SCHEDULER_cancel (dc->task);
    dc->task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != dc->rfh)
  {
    GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (dc->rfh));
    dc->rfh = NULL;
  }
  GNUNET_FS_download_sync_ (dc);

  /* signal completion */
  pi.status = GNUNET_FS_STATUS_DOWNLOAD_COMPLETED;
  GNUNET_FS_download_make_status_ (&pi, dc);

  /* let parent know */
  if (NULL != dc->parent)
    check_completed (dc->parent);
}


/**
 * We got a block of plaintext data (from the meta data).
 * Try it for upward reconstruction of the data.  On success,
 * the top-level block will move to state BRS_DOWNLOAD_UP.
 *
 * @param dc context for the download
 * @param dr download request to match against
 * @param data plaintext data, starting from the beginning of the file
 * @param data_len number of bytes in data
 */
static void
try_match_block (struct GNUNET_FS_DownloadContext *dc,
                 struct DownloadRequest *dr, const char *data, size_t data_len)
{
  struct GNUNET_FS_ProgressInfo pi;
  unsigned int i;
  char enc[DBLOCK_SIZE];
  struct ContentHashKey chks[CHK_PER_INODE];
  struct ContentHashKey in_chk;
  struct GNUNET_CRYPTO_AesSessionKey sk;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  size_t dlen;
  struct DownloadRequest *drc;
  struct GNUNET_DISK_FileHandle *fh;
  int complete;
  const char *fn;
  const char *odata;
  size_t odata_len;

  odata = data;
  odata_len = data_len;
  if (BRS_DOWNLOAD_UP == dr->state)
    return;
  if (dr->depth > 0)
  {
    complete = GNUNET_YES;
    for (i = 0; i < dr->num_children; i++)
    {
      drc = dr->children[i];
      try_match_block (dc, drc, data, data_len);
      if (drc->state != BRS_RECONSTRUCT_META_UP)
        complete = GNUNET_NO;
      else
        chks[i] = drc->chk;
    }
    if (GNUNET_YES != complete)
      return;
    data = (const char *) chks;
    dlen = dr->num_children * sizeof (struct ContentHashKey);
  }
  else
  {
    if (dr->offset > data_len)
      return;                   /* oops */
    dlen = GNUNET_MIN (data_len - dr->offset, DBLOCK_SIZE);
  }
  GNUNET_CRYPTO_hash (&data[dr->offset], dlen, &in_chk.key);
  GNUNET_CRYPTO_hash_to_aes_key (&in_chk.key, &sk, &iv);
  if (-1 == GNUNET_CRYPTO_aes_encrypt (&data[dr->offset], dlen, &sk, &iv, enc))
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_CRYPTO_hash (enc, dlen, &in_chk.query);
  switch (dr->state)
  {
  case BRS_INIT:
    dr->chk = in_chk;
    dr->state = BRS_RECONSTRUCT_META_UP;
    break;
  case BRS_CHK_SET:
    if (0 != memcmp (&in_chk, &dr->chk, sizeof (struct ContentHashKey)))
    {
      /* other peer provided bogus meta data */
      GNUNET_break_op (0);
      break;
    }
    /* write block to disk */
    fn = (NULL != dc->filename) ? dc->filename : dc->temp_filename;
    fh = GNUNET_DISK_file_open (fn,
                                GNUNET_DISK_OPEN_READWRITE |
                                GNUNET_DISK_OPEN_CREATE |
                                GNUNET_DISK_OPEN_TRUNCATE,
                                GNUNET_DISK_PERM_USER_READ |
                                GNUNET_DISK_PERM_USER_WRITE |
                                GNUNET_DISK_PERM_GROUP_READ |
                                GNUNET_DISK_PERM_OTHER_READ);
    if (NULL == fh)
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", fn);
      GNUNET_asprintf (&dc->emsg, _("Failed to open file `%s' for writing"),
                       fn);
      GNUNET_DISK_file_close (fh);
      dr->state = BRS_ERROR;
      pi.status = GNUNET_FS_STATUS_DOWNLOAD_ERROR;
      pi.value.download.specifics.error.message = dc->emsg;
      GNUNET_FS_download_make_status_ (&pi, dc);
      return;
    }
    if (data_len != GNUNET_DISK_file_write (fh, odata, odata_len))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "write", fn);
      GNUNET_asprintf (&dc->emsg, _("Failed to open file `%s' for writing"),
                       fn);
      GNUNET_DISK_file_close (fh);
      dr->state = BRS_ERROR;
      pi.status = GNUNET_FS_STATUS_DOWNLOAD_ERROR;
      pi.value.download.specifics.error.message = dc->emsg;
      GNUNET_FS_download_make_status_ (&pi, dc);
      return;
    }
    GNUNET_DISK_file_close (fh);
    /* signal success */
    dr->state = BRS_DOWNLOAD_UP;
    dc->completed = dc->length;
    GNUNET_FS_download_sync_ (dc);
    pi.status = GNUNET_FS_STATUS_DOWNLOAD_PROGRESS;
    pi.value.download.specifics.progress.data = data;
    pi.value.download.specifics.progress.offset = 0;
    pi.value.download.specifics.progress.data_len = dlen;
    pi.value.download.specifics.progress.depth = 0;
    pi.value.download.specifics.progress.trust_offered = 0;
    pi.value.download.specifics.progress.block_download_duration = GNUNET_TIME_UNIT_ZERO;
    GNUNET_FS_download_make_status_ (&pi, dc);
    if ((NULL != dc->filename) &&
        (0 !=
         truncate (dc->filename,
                   GNUNET_ntohll (dc->uri->data.chk.file_length))))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "truncate",
                                dc->filename);
    check_completed (dc);
    break;
  default:
    /* how did we get here? */
    GNUNET_break (0);
    break;
  }
}


/**
 * Type of a function that libextractor calls for each
 * meta data item found.  If we find full data meta data,
 * call 'try_match_block' on it.
 *
 * @param cls our 'struct GNUNET_FS_DownloadContext*'
 * @param plugin_name name of the plugin that produced this value;
 *        special values can be used (i.e. '&lt;zlib&gt;' for zlib being
 *        used in the main libextractor library and yielding
 *        meta data).
 * @param type libextractor-type describing the meta data
 * @param format basic format information about data
 * @param data_mime_type mime-type of data (not of the original file);
 *        can be NULL (if mime-type is not known)
 * @param data actual meta-data found
 * @param data_len number of bytes in data
 * @return 0 to continue extracting, 1 to abort
 */
static int
match_full_data (void *cls, const char *plugin_name,
                 enum EXTRACTOR_MetaType type, enum EXTRACTOR_MetaFormat format,
                 const char *data_mime_type, const char *data, size_t data_len)
{
  struct GNUNET_FS_DownloadContext *dc = cls;

  if (EXTRACTOR_METATYPE_GNUNET_FULL_DATA != type)
    return 0;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found %u bytes of FD!\n",
              (unsigned int) data_len);
  if (GNUNET_FS_uri_chk_get_file_size (dc->uri) != data_len)
  {
    GNUNET_break_op (0);
    return 1;                   /* bogus meta data */
  }
  try_match_block (dc, dc->top_request, data, data_len);
  return 1;
}


/**
 * Set the state of the given download request to
 * BRS_DOWNLOAD_UP and propagate it up the tree.
 *
 * @param dr download request that is done
 */
static void
propagate_up (struct DownloadRequest *dr)
{
  unsigned int i;

  do
  {
    dr->state = BRS_DOWNLOAD_UP;
    dr = dr->parent;
    if (NULL == dr)
      break;
    for (i = 0; i < dr->num_children; i++)
      if (dr->children[i]->state != BRS_DOWNLOAD_UP)
        break;
  }
  while (i == dr->num_children);
}


/**
 * Try top-down reconstruction.  Before, the given request node
 * must have the state BRS_CHK_SET.  Afterwards, more nodes may
 * have that state or advanced to BRS_DOWNLOAD_DOWN or even
 * BRS_DOWNLOAD_UP.  It is also possible to get BRS_ERROR on the
 * top level.
 *
 * @param dc overall download this block belongs to
 * @param dr block to reconstruct
 */
static void
try_top_down_reconstruction (struct GNUNET_FS_DownloadContext *dc,
                             struct DownloadRequest *dr)
{
  uint64_t off;
  char block[DBLOCK_SIZE];
  GNUNET_HashCode key;
  uint64_t total;
  size_t len;
  unsigned int i;
  struct DownloadRequest *drc;
  uint64_t child_block_size;
  const struct ContentHashKey *chks;
  int up_done;

  GNUNET_assert (NULL != dc->rfh);
  GNUNET_assert (BRS_CHK_SET == dr->state);
  total = GNUNET_FS_uri_chk_get_file_size (dc->uri);
  GNUNET_assert (dr->depth < dc->treedepth);
  len = GNUNET_FS_tree_calculate_block_size (total, dr->offset, dr->depth);
  GNUNET_assert (len <= DBLOCK_SIZE);
  off = compute_disk_offset (total, dr->offset, dr->depth);
  if (dc->old_file_size < off + len)
    return;                     /* failure */
  if (off != GNUNET_DISK_file_seek (dc->rfh, off, GNUNET_DISK_SEEK_SET))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "seek", dc->filename);
    return;                     /* failure */
  }
  if (len != GNUNET_DISK_file_read (dc->rfh, block, len))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "read", dc->filename);
    return;                     /* failure */
  }
  GNUNET_CRYPTO_hash (block, len, &key);
  if (0 != memcmp (&key, &dr->chk.key, sizeof (GNUNET_HashCode)))
    return;                     /* mismatch */
  if (GNUNET_OK !=
      encrypt_existing_match (dc, &dr->chk, dr, block, len, GNUNET_NO))
  {
    /* hash matches but encrypted block does not, really bad */
    dr->state = BRS_ERROR;
    /* propagate up */
    while (NULL != dr->parent)
    {
      dr = dr->parent;
      dr->state = BRS_ERROR;
    }
    return;
  }
  /* block matches */
  dr->state = BRS_DOWNLOAD_DOWN;

  /* set CHKs for children */
  up_done = GNUNET_YES;
  chks = (const struct ContentHashKey *) block;
  for (i = 0; i < dr->num_children; i++)
  {
    drc = dr->children[i];
    GNUNET_assert (drc->offset >= dr->offset);
    child_block_size = GNUNET_FS_tree_compute_tree_size (drc->depth);
    GNUNET_assert (0 == (drc->offset - dr->offset) % child_block_size);     
    if (BRS_INIT == drc->state)
    {
      drc->state = BRS_CHK_SET;
      drc->chk = chks[drc->chk_idx];
      try_top_down_reconstruction (dc, drc);
    }
    if (BRS_DOWNLOAD_UP != drc->state)
      up_done = GNUNET_NO;      /* children not all done */
  }
  if (GNUNET_YES == up_done)
    propagate_up (dr);          /* children all done (or no children...) */
}


/**
 * Schedule the download of the specified block in the tree.
 *
 * @param dc overall download this block belongs to
 * @param dr request to schedule
 */
static void
schedule_block_download (struct GNUNET_FS_DownloadContext *dc,
                         struct DownloadRequest *dr)
{
  unsigned int i;

  switch (dr->state)
  {
  case BRS_INIT:
    GNUNET_assert (0);
    break;
  case BRS_RECONSTRUCT_DOWN:
    GNUNET_assert (0);
    break;
  case BRS_RECONSTRUCT_META_UP:
    GNUNET_assert (0);
    break;
  case BRS_RECONSTRUCT_UP:
    GNUNET_assert (0);
    break;
  case BRS_CHK_SET:
    /* normal case, start download */
    break;
  case BRS_DOWNLOAD_DOWN:
    for (i = 0; i < dr->num_children; i++)
      schedule_block_download (dc, dr->children[i]);
    return;
  case BRS_DOWNLOAD_UP:
    /* We're done! */
    return;
  case BRS_ERROR:
    GNUNET_break (0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Scheduling download at offset %llu and depth %u for `%s'\n",
              (unsigned long long) dr->offset, dr->depth,
              GNUNET_h2s (&dr->chk.query));
  if (GNUNET_NO !=
      GNUNET_CONTAINER_multihashmap_contains_value (dc->active, &dr->chk.query,
                                                    dr))
    return;                     /* already active */
  GNUNET_CONTAINER_multihashmap_put (dc->active, &dr->chk.query, dr,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  if (NULL == dc->client)
    return;                     /* download not active */
  GNUNET_CONTAINER_DLL_insert (dc->pending_head, dc->pending_tail, dr);
  dr->is_pending = GNUNET_YES;
  if (NULL == dc->th)
    dc->th =
        GNUNET_CLIENT_notify_transmit_ready (dc->client,
                                             sizeof (struct SearchMessage),
                                             GNUNET_CONSTANTS_SERVICE_TIMEOUT,
                                             GNUNET_NO,
                                             &transmit_download_request, dc);
}


#define GNUNET_FS_URI_CHK_PREFIX GNUNET_FS_URI_PREFIX GNUNET_FS_URI_CHK_INFIX

/**
 * We found an entry in a directory.  Check if the respective child
 * already exists and if not create the respective child download.
 *
 * @param cls the parent download
 * @param filename name of the file in the directory
 * @param uri URI of the file (CHK or LOC)
 * @param meta meta data of the file
 * @param length number of bytes in data
 * @param data contents of the file (or NULL if they were not inlined)
 */
static void
trigger_recursive_download (void *cls, const char *filename,
                            const struct GNUNET_FS_Uri *uri,
                            const struct GNUNET_CONTAINER_MetaData *meta,
                            size_t length, const void *data)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  struct GNUNET_FS_DownloadContext *cpos;
  char *temp_name;
  char *fn;
  char *us;
  char *ext;
  char *dn;
  char *pos;
  char *full_name;
  char *sfn;

  if (NULL == uri)
    return;                     /* entry for the directory itself */
  cpos = dc->child_head;
  while (NULL != cpos)
  {
    if ((GNUNET_FS_uri_test_equal (uri, cpos->uri)) ||
        ((NULL != filename) && (0 == strcmp (cpos->filename, filename))))
      break;
    cpos = cpos->next;
  }
  if (NULL != cpos)
    return;                     /* already exists */
  fn = NULL;
  if (NULL == filename)
  {
    fn = GNUNET_FS_meta_data_suggest_filename (meta);
    if (NULL == fn)
    {
      us = GNUNET_FS_uri_to_string (uri);
      fn = GNUNET_strdup (&us[strlen (GNUNET_FS_URI_CHK_PREFIX)]);
      GNUNET_free (us);
    }
    else if ('.' == fn[0])
    {
      ext = fn;
      us = GNUNET_FS_uri_to_string (uri);
      GNUNET_asprintf (&fn, "%s%s", &us[strlen (GNUNET_FS_URI_CHK_PREFIX)],
                       ext);
      GNUNET_free (ext);
      GNUNET_free (us);
    }
    /* change '\' to '/' (this should have happened
     * during insertion, but malicious peers may
     * not have done this) */
    while (NULL != (pos = strstr (fn, "\\")))
      *pos = '/';
    /* remove '../' everywhere (again, well-behaved
     * peers don't do this, but don't trust that
     * we did not get something nasty) */
    while (NULL != (pos = strstr (fn, "../")))
    {
      pos[0] = '_';
      pos[1] = '_';
      pos[2] = '_';
    }
    filename = fn;
  }
  if (NULL == dc->filename)
  {
    full_name = NULL;
  }
  else
  {
    dn = GNUNET_strdup (dc->filename);
    GNUNET_break ((strlen (dn) >= strlen (GNUNET_FS_DIRECTORY_EXT)) &&
                  (NULL !=
                   strstr (dn + strlen (dn) - strlen (GNUNET_FS_DIRECTORY_EXT),
                           GNUNET_FS_DIRECTORY_EXT)));
    sfn = GNUNET_strdup (filename);
    while ((strlen (sfn) > 0) && ('/' == filename[strlen (sfn) - 1]))
      sfn[strlen (sfn) - 1] = '\0';
    if ((strlen (dn) >= strlen (GNUNET_FS_DIRECTORY_EXT)) &&
        (NULL !=
         strstr (dn + strlen (dn) - strlen (GNUNET_FS_DIRECTORY_EXT),
                 GNUNET_FS_DIRECTORY_EXT)))
      dn[strlen (dn) - strlen (GNUNET_FS_DIRECTORY_EXT)] = '\0';
    if ((GNUNET_YES == GNUNET_FS_meta_data_test_for_directory (meta)) &&
        ((strlen (filename) < strlen (GNUNET_FS_DIRECTORY_EXT)) ||
         (NULL ==
          strstr (filename + strlen (filename) -
                  strlen (GNUNET_FS_DIRECTORY_EXT), GNUNET_FS_DIRECTORY_EXT))))
    {
      GNUNET_asprintf (&full_name, "%s%s%s%s", dn, DIR_SEPARATOR_STR, sfn,
                       GNUNET_FS_DIRECTORY_EXT);
    }
    else
    {
      GNUNET_asprintf (&full_name, "%s%s%s", dn, DIR_SEPARATOR_STR, sfn);
    }
    GNUNET_free (sfn);
    GNUNET_free (dn);
  }
  if ((NULL != full_name) &&
      (GNUNET_OK != GNUNET_DISK_directory_create_for_file (full_name)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Failed to create directory for recursive download of `%s'\n"),
                full_name);
    GNUNET_free (full_name);
    GNUNET_free_non_null (fn);
    return;
  }

  temp_name = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Triggering recursive download of size %llu with %u bytes MD\n",
              (unsigned long long) GNUNET_FS_uri_chk_get_file_size (uri),
              (unsigned int)
              GNUNET_CONTAINER_meta_data_get_serialized_size (meta));
  GNUNET_FS_download_start (dc->h, uri, meta, full_name, temp_name, 0,
                            GNUNET_FS_uri_chk_get_file_size (uri),
                            dc->anonymity, dc->options, NULL, dc);
  GNUNET_free_non_null (full_name);
  GNUNET_free_non_null (temp_name);
  GNUNET_free_non_null (fn);
}


/**
 * (recursively) free download request structure
 *
 * @param dr request to free
 */
void
GNUNET_FS_free_download_request_ (struct DownloadRequest *dr)
{
  unsigned int i;

  if (NULL == dr)
    return;
  for (i = 0; i < dr->num_children; i++)
    GNUNET_FS_free_download_request_ (dr->children[i]);
  GNUNET_free_non_null (dr->children);
  GNUNET_free (dr);
}


/**
 * Iterator over entries in the pending requests in the 'active' map for the
 * reply that we just got.
 *
 * @param cls closure (our 'struct ProcessResultClosure')
 * @param key query for the given value / request
 * @param value value in the hash map (a 'struct DownloadRequest')
 * @return GNUNET_YES (we should continue to iterate); unless serious error
 */
static int
process_result_with_request (void *cls, const GNUNET_HashCode * key,
                             void *value)
{
  struct ProcessResultClosure *prc = cls;
  struct DownloadRequest *dr = value;
  struct GNUNET_FS_DownloadContext *dc = prc->dc;
  struct DownloadRequest *drc;
  struct GNUNET_DISK_FileHandle *fh = NULL;
  struct GNUNET_CRYPTO_AesSessionKey skey;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  char pt[prc->size];
  struct GNUNET_FS_ProgressInfo pi;
  uint64_t off;
  size_t bs;
  size_t app;
  int i;
  struct ContentHashKey *chkarr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received %u byte block `%s' matching pending request at depth %u and offset %llu/%llu\n",
	      (unsigned int) prc->size,
              GNUNET_h2s (key), dr->depth, (unsigned long long) dr->offset,
              (unsigned long long) GNUNET_ntohll (dc->uri->data.
                                                  chk.file_length));
  bs = GNUNET_FS_tree_calculate_block_size (GNUNET_ntohll
                                            (dc->uri->data.chk.file_length),
                                            dr->offset, dr->depth);
  if (prc->size != bs)
  {
    GNUNET_asprintf (&dc->emsg,
                     _
                     ("Internal error or bogus download URI (expected %u bytes at depth %u and offset %llu/%llu, got %u bytes)"),
                     bs, dr->depth, (unsigned long long) dr->offset,
                     (unsigned long long) GNUNET_ntohll (dc->uri->data.
                                                         chk.file_length),
                     prc->size);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "%s\n", dc->emsg);
    while (NULL != dr->parent)
    {
      dr->state = BRS_ERROR;
      dr = dr->parent;
    }
    dr->state = BRS_ERROR;
    goto signal_error;
  }

  (void) GNUNET_CONTAINER_multihashmap_remove (dc->active, &prc->query, dr);
  if (GNUNET_YES == dr->is_pending)
  {
    GNUNET_CONTAINER_DLL_remove (dc->pending_head, dc->pending_tail, dr);
    dr->is_pending = GNUNET_NO;
  }

  GNUNET_CRYPTO_hash_to_aes_key (&dr->chk.key, &skey, &iv);
  if (-1 == GNUNET_CRYPTO_aes_decrypt (prc->data, prc->size, &skey, &iv, pt))
  {
    GNUNET_break (0);
    dc->emsg = GNUNET_strdup (_("internal error decrypting content"));
    goto signal_error;
  }
  off =
      compute_disk_offset (GNUNET_ntohll (dc->uri->data.chk.file_length),
                           dr->offset, dr->depth);
  /* save to disk */
  if ((GNUNET_YES == prc->do_store) &&
      ((NULL != dc->filename) || (is_recursive_download (dc))) &&
      ((dr->depth == dc->treedepth) ||
       (0 == (dc->options & GNUNET_FS_DOWNLOAD_NO_TEMPORARIES))))
  {
    fh = GNUNET_DISK_file_open (NULL != dc->filename
				? dc->filename : dc->temp_filename,
                                GNUNET_DISK_OPEN_READWRITE |
                                GNUNET_DISK_OPEN_CREATE,
                                GNUNET_DISK_PERM_USER_READ |
                                GNUNET_DISK_PERM_USER_WRITE |
                                GNUNET_DISK_PERM_GROUP_READ |
                                GNUNET_DISK_PERM_OTHER_READ);
    if (NULL == fh)
    {
      GNUNET_asprintf (&dc->emsg,
                       _("Download failed: could not open file `%s': %s"),
                       dc->filename, STRERROR (errno));
      goto signal_error;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Saving decrypted block to disk at offset %llu\n",
                (unsigned long long) off);
    if ((off != GNUNET_DISK_file_seek (fh, off, GNUNET_DISK_SEEK_SET)))
    {
      GNUNET_asprintf (&dc->emsg,
                       _("Failed to seek to offset %llu in file `%s': %s"),
                       (unsigned long long) off, dc->filename,
                       STRERROR (errno));
      goto signal_error;
    }
    if (prc->size != GNUNET_DISK_file_write (fh, pt, prc->size))
    {
      GNUNET_asprintf (&dc->emsg,
                       _
                       ("Failed to write block of %u bytes at offset %llu in file `%s': %s"),
                       (unsigned int) prc->size, (unsigned long long) off,
                       dc->filename, STRERROR (errno));
      goto signal_error;
    }
    GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fh));
    fh = NULL;
  }

  if (0 == dr->depth)
  {
    /* DBLOCK, update progress and try recursion if applicable */
    app = prc->size;
    if (dr->offset < dc->offset)
    {
      /* starting offset begins in the middle of pt,
       * do not count first bytes as progress */
      GNUNET_assert (app > (dc->offset - dr->offset));
      app -= (dc->offset - dr->offset);
    }
    if (dr->offset + prc->size > dc->offset + dc->length)
    {
      /* end of block is after relevant range,
       * do not count last bytes as progress */
      GNUNET_assert (app >
                     (dr->offset + prc->size) - (dc->offset + dc->length));
      app -= (dr->offset + prc->size) - (dc->offset + dc->length);
    }
    dc->completed += app;

    /* do recursive download if option is set and either meta data
     * says it is a directory or if no meta data is given AND filename
     * ends in '.gnd' (top-level case) */
    if (is_recursive_download (dc))
      GNUNET_FS_directory_list_contents (prc->size, pt, off,
                                         &trigger_recursive_download, dc);
  }
  GNUNET_assert (dc->completed <= dc->length);
  dr->state = BRS_DOWNLOAD_DOWN;
  pi.status = GNUNET_FS_STATUS_DOWNLOAD_PROGRESS;
  pi.value.download.specifics.progress.data = pt;
  pi.value.download.specifics.progress.offset = dr->offset;
  pi.value.download.specifics.progress.data_len = prc->size;
  pi.value.download.specifics.progress.depth = dr->depth;
  pi.value.download.specifics.progress.trust_offered = 0;
  if (prc->last_transmission.abs_value != GNUNET_TIME_UNIT_FOREVER_ABS.abs_value)
    pi.value.download.specifics.progress.block_download_duration 
      = GNUNET_TIME_absolute_get_duration (prc->last_transmission);
  else
    pi.value.download.specifics.progress.block_download_duration
      = GNUNET_TIME_UNIT_ZERO; /* found locally */
  GNUNET_FS_download_make_status_ (&pi, dc);
  if (0 == dr->depth)
    propagate_up (dr);

  if (dc->completed == dc->length)
  {
    /* download completed, signal */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Download completed, truncating file to desired length %llu\n",
                (unsigned long long) GNUNET_ntohll (dc->uri->data.
                                                    chk.file_length));
    /* truncate file to size (since we store IBlocks at the end) */
    if (NULL != dc->filename)
    {
      if (0 !=
          truncate (dc->filename,
                    GNUNET_ntohll (dc->uri->data.chk.file_length)))
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "truncate",
                                  dc->filename);
    }
    GNUNET_assert (0 == dr->depth);
    check_completed (dc);
  }
  if (0 == dr->depth)
  {
    /* bottom of the tree, no child downloads possible, just sync */
    GNUNET_FS_download_sync_ (dc);
    return GNUNET_YES;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Triggering downloads of children (this block was at depth %u and offset %llu)\n",
              dr->depth, (unsigned long long) dr->offset);
  GNUNET_assert (0 == (prc->size % sizeof (struct ContentHashKey)));
  chkarr = (struct ContentHashKey *) pt;
  for (i = dr->num_children - 1; i >= 0; i--)
  {
    drc = dr->children[i];
    switch (drc->state)
    {
    case BRS_INIT:
      if ((drc->chk_idx + 1) * sizeof (struct ContentHashKey) > prc->size)
      {
	/* 'chkarr' does not have enough space for this chk_idx;
	   internal error! */
	GNUNET_break (0);
	dc->emsg = GNUNET_strdup (_("internal error decoding tree"));
	goto signal_error;
      }
      drc->chk = chkarr[drc->chk_idx];
      drc->state = BRS_CHK_SET;
      if (GNUNET_YES == dc->issue_requests)
	schedule_block_download (dc, drc);
      break;
    case BRS_RECONSTRUCT_DOWN:
      GNUNET_assert (0);
      break;
    case BRS_RECONSTRUCT_META_UP:
      GNUNET_assert (0);
      break;
    case BRS_RECONSTRUCT_UP:
      GNUNET_assert (0);
      break;
    case BRS_CHK_SET:
      GNUNET_assert (0);
      break;
    case BRS_DOWNLOAD_DOWN:
      GNUNET_assert (0);
      break;
    case BRS_DOWNLOAD_UP:
      GNUNET_assert (0);
      break;
    case BRS_ERROR:
      GNUNET_assert (0);
      break;
    default:
      GNUNET_assert (0);
      break;
    }
  }
  GNUNET_FS_download_sync_ (dc);
  return GNUNET_YES;

signal_error:
  if (NULL != fh)
    GNUNET_DISK_file_close (fh);
  pi.status = GNUNET_FS_STATUS_DOWNLOAD_ERROR;
  pi.value.download.specifics.error.message = dc->emsg;
  GNUNET_FS_download_make_status_ (&pi, dc);
  /* abort all pending requests */
  if (NULL != dc->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (dc->th);
    dc->th = NULL;
  }
  GNUNET_CLIENT_disconnect (dc->client);
  dc->in_receive = GNUNET_NO;
  dc->client = NULL;
  GNUNET_FS_free_download_request_ (dc->top_request);
  dc->top_request = NULL;
  GNUNET_CONTAINER_multihashmap_destroy (dc->active);
  dc->active = NULL;
  dc->pending_head = NULL;
  dc->pending_tail = NULL;
  GNUNET_FS_download_sync_ (dc);
  return GNUNET_NO;
}


/**
 * Process a download result.
 *
 * @param dc our download context
 * @param type type of the result
 * @param last_transmission when was this block requested the last time? (FOREVER if unknown/not applicable)
 * @param data the (encrypted) response
 * @param size size of data
 */
static void
process_result (struct GNUNET_FS_DownloadContext *dc,
                enum GNUNET_BLOCK_Type type,
                struct GNUNET_TIME_Absolute last_transmission,
                const void *data, size_t size)
{
  struct ProcessResultClosure prc;

  prc.dc = dc;
  prc.data = data;
  prc.size = size;
  prc.type = type;
  prc.do_store = GNUNET_YES;
  prc.last_transmission = last_transmission;
  GNUNET_CRYPTO_hash (data, size, &prc.query);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received result for query `%s' from `%s'-service\n",
              GNUNET_h2s (&prc.query), "FS");
  GNUNET_CONTAINER_multihashmap_get_multiple (dc->active, &prc.query,
                                              &process_result_with_request,
                                              &prc);
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
receive_results (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  const struct ClientPutMessage *cm;
  uint16_t msize;

  if ((NULL == msg) || (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_FS_PUT) ||
      (sizeof (struct ClientPutMessage) > ntohs (msg->size)))
  {
    GNUNET_break (NULL == msg);
    try_reconnect (dc);
    return;
  }
  msize = ntohs (msg->size);
  cm = (const struct ClientPutMessage *) msg;
  process_result (dc, ntohl (cm->type),
                  GNUNET_TIME_absolute_ntoh (cm->last_transmission), &cm[1],
                  msize - sizeof (struct ClientPutMessage));
  if (NULL == dc->client)
    return;                     /* fatal error */
  /* continue receiving */
  GNUNET_CLIENT_receive (dc->client, &receive_results, dc,
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
transmit_download_request (void *cls, size_t size, void *buf)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  size_t msize;
  struct SearchMessage *sm;
  struct DownloadRequest *dr;

  dc->th = NULL;
  if (NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transmitting download request failed, trying to reconnect\n");
    try_reconnect (dc);
    return 0;
  }
  GNUNET_assert (size >= sizeof (struct SearchMessage));
  msize = 0;
  sm = buf;
  while ((NULL != (dr = dc->pending_head)) &&
         (size >= msize + sizeof (struct SearchMessage)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transmitting download request for `%s' to `%s'-service\n",
                GNUNET_h2s (&dr->chk.query), "FS");
    memset (sm, 0, sizeof (struct SearchMessage));
    sm->header.size = htons (sizeof (struct SearchMessage));
    sm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_START_SEARCH);
    if (0 != (dc->options & GNUNET_FS_DOWNLOAD_OPTION_LOOPBACK_ONLY))
      sm->options = htonl (GNUNET_FS_SEARCH_OPTION_LOOPBACK_ONLY);
    else
      sm->options = htonl (GNUNET_FS_SEARCH_OPTION_NONE);
    if (0 == dr->depth)
      sm->type = htonl (GNUNET_BLOCK_TYPE_FS_DBLOCK);
    else
      sm->type = htonl (GNUNET_BLOCK_TYPE_FS_IBLOCK);
    sm->anonymity_level = htonl (dc->anonymity);
    sm->target = dc->target.hashPubKey;
    sm->query = dr->chk.query;
    GNUNET_CONTAINER_DLL_remove (dc->pending_head, dc->pending_tail, dr);
    dr->is_pending = GNUNET_NO;
    msize += sizeof (struct SearchMessage);
    sm++;
  }
  if (NULL != dc->pending_head)
  {
    dc->th =
        GNUNET_CLIENT_notify_transmit_ready (dc->client,
                                             sizeof (struct SearchMessage),
                                             GNUNET_CONSTANTS_SERVICE_TIMEOUT,
                                             GNUNET_NO,
                                             &transmit_download_request, dc);
    GNUNET_assert (NULL != dc->th);
  }
  if (GNUNET_NO == dc->in_receive)
  {
    dc->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (dc->client, &receive_results, dc,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }
  return msize;
}


/**
 * Reconnect to the FS service and transmit our queries NOW.
 *
 * @param cls our download context
 * @param tc unused
 */
static void
do_reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  struct GNUNET_CLIENT_Connection *client;

  dc->task = GNUNET_SCHEDULER_NO_TASK;
  client = GNUNET_CLIENT_connect ("fs", dc->h->cfg);
  if (NULL == client)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Connecting to `%s'-service failed, will try again.\n", "FS");
    try_reconnect (dc);
    return;
  }
  dc->client = client;
  if (NULL != dc->pending_head)
  {
    dc->th =
        GNUNET_CLIENT_notify_transmit_ready (client,
                                             sizeof (struct SearchMessage),
                                             GNUNET_CONSTANTS_SERVICE_TIMEOUT,
                                             GNUNET_NO,
                                             &transmit_download_request, dc);
    GNUNET_assert (NULL != dc->th);
  }
}


/**
 * Add entries to the pending list.
 *
 * @param cls our download context
 * @param key unused
 * @param entry entry of type "struct DownloadRequest"
 * @return GNUNET_OK
 */
static int
retry_entry (void *cls, const GNUNET_HashCode * key, void *entry)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  struct DownloadRequest *dr = entry;

  dr->next = NULL;
  dr->prev = NULL;
  GNUNET_CONTAINER_DLL_insert (dc->pending_head, dc->pending_tail, dr);
  dr->is_pending = GNUNET_YES;
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Moving all requests back to pending list\n");
    if (NULL != dc->th)
    {
      GNUNET_CLIENT_notify_transmit_ready_cancel (dc->th);
      dc->th = NULL;
    }
    /* full reset of the pending list */
    dc->pending_head = NULL;
    dc->pending_tail = NULL;
    GNUNET_CONTAINER_multihashmap_iterate (dc->active, &retry_entry, dc);
    GNUNET_CLIENT_disconnect (dc->client);
    dc->in_receive = GNUNET_NO;
    dc->client = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Will try to reconnect in 1s\n");
  dc->task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &do_reconnect,
                                    dc);
}


/**
 * We're allowed to ask the FS service for our blocks.  Start the download.
 *
 * @param cls the 'struct GNUNET_FS_DownloadContext'
 * @param client handle to use for communcation with FS (we must destroy it!)
 */
static void
activate_fs_download (void *cls, struct GNUNET_CLIENT_Connection *client)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  struct GNUNET_FS_ProgressInfo pi;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Download activated\n");
  GNUNET_assert (NULL != client);
  GNUNET_assert (NULL == dc->client);
  GNUNET_assert (NULL == dc->th);
  dc->client = client;
  pi.status = GNUNET_FS_STATUS_DOWNLOAD_ACTIVE;
  GNUNET_FS_download_make_status_ (&pi, dc);
  dc->pending_head = NULL;
  dc->pending_tail = NULL;
  GNUNET_CONTAINER_multihashmap_iterate (dc->active, &retry_entry, dc);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking for transmission to FS service\n");
  if (NULL != dc->pending_head)
  {
    dc->th =
        GNUNET_CLIENT_notify_transmit_ready (dc->client,
                                             sizeof (struct SearchMessage),
                                             GNUNET_CONSTANTS_SERVICE_TIMEOUT,
                                             GNUNET_NO,
                                             &transmit_download_request, dc);
    GNUNET_assert (NULL != dc->th);
  }
}


/**
 * We must stop to ask the FS service for our blocks.  Pause the download.
 *
 * @param cls the 'struct GNUNET_FS_DownloadContext'
 */
static void
deactivate_fs_download (void *cls)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  struct GNUNET_FS_ProgressInfo pi;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Download deactivated\n");
  if (NULL != dc->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (dc->th);
    dc->th = NULL;
  }
  if (NULL != dc->client)
  {
    GNUNET_CLIENT_disconnect (dc->client);
    dc->in_receive = GNUNET_NO;
    dc->client = NULL;
  }
  dc->pending_head = NULL;
  dc->pending_tail = NULL;
  pi.status = GNUNET_FS_STATUS_DOWNLOAD_INACTIVE;
  GNUNET_FS_download_make_status_ (&pi, dc);
}


/**
 * (recursively) Create a download request structure.
 *
 * @param parent parent of the current entry
 * @param chk_idx index of the chk for this block in the parent block
 * @param depth depth of the current entry, 0 are the DBLOCKs,
 *              top level block is 'dc->treedepth - 1'
 * @param dr_offset offset in the original file this block maps to
 *              (as in, offset of the first byte of the first DBLOCK
 *               in the subtree rooted in the returned download request tree)
 * @param file_start_offset desired starting offset for the download
 *             in the original file; requesting tree should not contain
 *             DBLOCKs prior to the file_start_offset
 * @param desired_length desired number of bytes the user wanted to access
 *        (from file_start_offset).  Resulting tree should not contain
 *        DBLOCKs after file_start_offset + file_length.
 * @return download request tree for the given range of DBLOCKs at
 *         the specified depth
 */
static struct DownloadRequest *
create_download_request (struct DownloadRequest *parent, 
			 unsigned int chk_idx,
			 unsigned int depth,
                         uint64_t dr_offset, uint64_t file_start_offset,
                         uint64_t desired_length)
{
  struct DownloadRequest *dr;
  unsigned int i;
  unsigned int head_skip;
  uint64_t child_block_size;

  dr = GNUNET_malloc (sizeof (struct DownloadRequest));
  dr->parent = parent;
  dr->depth = depth;
  dr->offset = dr_offset;
  dr->chk_idx = chk_idx;
  if (0 == depth)
    return dr;
  child_block_size = GNUNET_FS_tree_compute_tree_size (depth - 1);
  
  /* calculate how many blocks at this level are not interesting
   * from the start (rounded down), either because of the requested
   * file offset or because this IBlock is further along */
  if (dr_offset < file_start_offset)
    head_skip = file_start_offset / child_block_size;
  else
    head_skip = 0;
  
  /* calculate index of last block at this level that is interesting (rounded up) */
  dr->num_children = (file_start_offset + desired_length - dr_offset) / child_block_size;
  if (dr->num_children * child_block_size <
      file_start_offset + desired_length - dr_offset)
    dr->num_children++;       /* round up */
  dr->num_children -= head_skip;
  if (dr->num_children > CHK_PER_INODE)
    dr->num_children = CHK_PER_INODE; /* cap at max */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Block at offset %llu and depth %u has %u children\n",
	      (unsigned long long) dr_offset,
	      depth,
	      dr->num_children);
  
  /* now we can get the total number of *interesting* children for this block */

  /* why else would we have gotten here to begin with? (that'd be a bad logic error) */
  GNUNET_assert (dr->num_children > 0);
  
  dr->children =
    GNUNET_malloc (dr->num_children * sizeof (struct DownloadRequest *));
  for (i = 0; i < dr->num_children; i++)
    dr->children[i] =
      create_download_request (dr, i + head_skip, depth - 1,
			       dr_offset + (i + head_skip) * child_block_size,
			       file_start_offset, desired_length);
  return dr;
}


/**
 * Continuation after a possible attempt to reconstruct
 * the current IBlock from the existing file.
 *
 * @param cls the 'struct ReconstructContext'
 * @param tc scheduler context
 */
static void
reconstruct_cont (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_DownloadContext *dc = cls;

  /* clean up state from tree encoder */  
  if (dc->task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (dc->task);
    dc->task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != dc->rfh)
  {
    GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (dc->rfh));
    dc->rfh = NULL;
  }
  /* start "normal" download */
  dc->issue_requests = GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting normal download\n");
  schedule_block_download (dc, dc->top_request);
}


/**
 * Task requesting the next block from the tree encoder.
 *
 * @param cls the 'struct GNUJNET_FS_DownloadContext' we're processing
 * @param tc task context
 */
static void
get_next_block (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_DownloadContext *dc = cls;

  dc->task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_FS_tree_encoder_next (dc->te);
}


/**
 * Function called asking for the current (encoded)
 * block to be processed.  After processing the
 * client should either call "GNUNET_FS_tree_encode_next"
 * or (on error) "GNUNET_FS_tree_encode_finish".
 *
 * This function checks if the content on disk matches
 * the expected content based on the URI.
 *
 * @param cls closure
 * @param chk content hash key for the block
 * @param offset offset of the block
 * @param depth depth of the block, 0 for DBLOCK
 * @param type type of the block (IBLOCK or DBLOCK)
 * @param block the (encrypted) block
 * @param block_size size of block (in bytes)
 */
static void
reconstruct_cb (void *cls, const struct ContentHashKey *chk, uint64_t offset,
                unsigned int depth, enum GNUNET_BLOCK_Type type,
                const void *block, uint16_t block_size)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  struct GNUNET_FS_ProgressInfo pi;
  struct DownloadRequest *dr;
  uint64_t blen;
  unsigned int chld;

  /* find corresponding request entry */
  dr = dc->top_request;
  while (dr->depth > depth)
  {
    GNUNET_assert (dr->num_children > 0);
    blen = GNUNET_FS_tree_compute_tree_size (dr->depth - 1);
    chld = (offset - dr->offset) / blen;
    if (chld < dr->children[0]->chk_idx)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Block %u < %u irrelevant for our range\n",
		  chld,
		  dr->children[0]->chk_idx);
      dc->task = GNUNET_SCHEDULER_add_now (&get_next_block, dc);
      return; /* irrelevant block */
    }
    if (chld > dr->children[dr->num_children-1]->chk_idx)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Block %u > %u irrelevant for our range\n",
		  chld,
		  dr->children[dr->num_children-1]->chk_idx);
      dc->task = GNUNET_SCHEDULER_add_now (&get_next_block, dc);
      return; /* irrelevant block */
    }
    dr = dr->children[chld - dr->children[0]->chk_idx];
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Matched TE block with request at offset %llu and depth %u in state %d\n",
	      (unsigned long long) dr->offset,
	      dr->depth,
	      dr->state);
  /* FIXME: this code needs more testing and might
     need to handle more states... */
  switch (dr->state)
  {
  case BRS_INIT:
    break;
  case BRS_RECONSTRUCT_DOWN:
    break;
  case BRS_RECONSTRUCT_META_UP:
    break;
  case BRS_RECONSTRUCT_UP:
    break;
  case BRS_CHK_SET:
    if (0 == memcmp (chk, &dr->chk, sizeof (struct ContentHashKey)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Reconstruction succeeded, can use block at offset %llu, depth %u\n",
		  (unsigned long long) offset,
		  depth);
      /* block matches, hence tree below matches;
       * this request is done! */
      dr->state = BRS_DOWNLOAD_UP;
      (void) GNUNET_CONTAINER_multihashmap_remove (dc->active, &dr->chk.query, dr);
      if (GNUNET_YES == dr->is_pending)
      {
	GNUNET_break (0); /* how did we get here? */
	GNUNET_CONTAINER_DLL_remove (dc->pending_head, dc->pending_tail, dr);
	dr->is_pending = GNUNET_NO;
      }
      /* calculate how many bytes of payload this block
       * corresponds to */
      blen = GNUNET_FS_tree_compute_tree_size (dr->depth);
      /* how many of those bytes are in the requested range? */
      blen = GNUNET_MIN (blen, dc->length + dc->offset - dr->offset);
      /* signal progress */
      dc->completed += blen;
      pi.status = GNUNET_FS_STATUS_DOWNLOAD_PROGRESS;
      pi.value.download.specifics.progress.data = NULL;
      pi.value.download.specifics.progress.offset = offset;
      pi.value.download.specifics.progress.data_len = 0;
      pi.value.download.specifics.progress.depth = 0;
      pi.value.download.specifics.progress.trust_offered = 0;
      pi.value.download.specifics.progress.block_download_duration = GNUNET_TIME_UNIT_ZERO;
      GNUNET_FS_download_make_status_ (&pi, dc);
      /* FIXME: duplicated code from 'process_result_with_request - refactor */
      if (dc->completed == dc->length)
      {
	/* download completed, signal */
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Download completed, truncating file to desired length %llu\n",
		    (unsigned long long) GNUNET_ntohll (dc->uri->data.
							chk.file_length));
	/* truncate file to size (since we store IBlocks at the end) */
	if (NULL != dc->filename)
	{
	  if (0 !=
	      truncate (dc->filename,
			GNUNET_ntohll (dc->uri->data.chk.file_length)))
	    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "truncate",
				      dc->filename);
	}
      }
    }
    else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Reconstruction failed, need to download block at offset %llu, depth %u\n",
		  (unsigned long long) offset,
		  depth);
    break;
  case BRS_DOWNLOAD_DOWN:
    break;
  case BRS_DOWNLOAD_UP:
    break;
  case BRS_ERROR:
    break;
  default:
    GNUNET_assert (0);
    break;
  }
  dc->task = GNUNET_SCHEDULER_add_now (&get_next_block, dc);
  if ((dr == dc->top_request) && (dr->state == BRS_DOWNLOAD_UP))
    check_completed (dc);
}


/**
 * Function called by the tree encoder to obtain a block of plaintext
 * data (for the lowest level of the tree).
 *
 * @param cls our 'struct ReconstructContext'
 * @param offset identifies which block to get
 * @param max (maximum) number of bytes to get; returning
 *        fewer will also cause errors
 * @param buf where to copy the plaintext buffer
 * @param emsg location to store an error message (on error)
 * @return number of bytes copied to buf, 0 on error
 */
static size_t
fh_reader (void *cls, uint64_t offset, size_t max, void *buf, char **emsg)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  struct GNUNET_DISK_FileHandle *fh = dc->rfh;
  ssize_t ret;

  if (NULL != emsg)
    *emsg = NULL;
  if (offset != GNUNET_DISK_file_seek (fh, offset, GNUNET_DISK_SEEK_SET))
  {
    if (NULL != emsg)
      *emsg = GNUNET_strdup (strerror (errno));
    return 0;
  }
  ret = GNUNET_DISK_file_read (fh, buf, max);
  if (ret < 0)
  {
    if (NULL != emsg)
      *emsg = GNUNET_strdup (strerror (errno));
    return 0;
  }
  return ret;
}


/**
 * Task that creates the initial (top-level) download
 * request for the file.
 *
 * @param cls the 'struct GNUNET_FS_DownloadContext'
 * @param tc scheduler context
 */
void
GNUNET_FS_download_start_task_ (void *cls,
                                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  struct GNUNET_FS_ProgressInfo pi;
  struct GNUNET_DISK_FileHandle *fh;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Start task running...\n");
  dc->task = GNUNET_SCHEDULER_NO_TASK;
  if (0 == dc->length)
  {
    /* no bytes required! */
    if (NULL != dc->filename)
    {
      fh = GNUNET_DISK_file_open (dc->filename,
                                  GNUNET_DISK_OPEN_READWRITE |
                                  GNUNET_DISK_OPEN_CREATE |
                                  ((0 ==
                                    GNUNET_FS_uri_chk_get_file_size (dc->uri)) ?
                                   GNUNET_DISK_OPEN_TRUNCATE : 0),
                                  GNUNET_DISK_PERM_USER_READ |
                                  GNUNET_DISK_PERM_USER_WRITE |
                                  GNUNET_DISK_PERM_GROUP_READ |
                                  GNUNET_DISK_PERM_OTHER_READ);
      GNUNET_DISK_file_close (fh);
    }
    GNUNET_FS_download_sync_ (dc);
    pi.status = GNUNET_FS_STATUS_DOWNLOAD_START;
    pi.value.download.specifics.start.meta = dc->meta;
    GNUNET_FS_download_make_status_ (&pi, dc);
    check_completed (dc);
    return;
  }
  if (NULL != dc->emsg)
    return;
  if (NULL == dc->top_request)
  {
    dc->top_request =
      create_download_request (NULL, 0, dc->treedepth - 1, 0, dc->offset,
			       dc->length);
    dc->top_request->state = BRS_CHK_SET;
    dc->top_request->chk =
        (dc->uri->type ==
         chk) ? dc->uri->data.chk.chk : dc->uri->data.loc.fi.chk;
    /* signal start */
    GNUNET_FS_download_sync_ (dc);
    if (NULL != dc->search)
      GNUNET_FS_search_result_sync_ (dc->search);
    pi.status = GNUNET_FS_STATUS_DOWNLOAD_START;
    pi.value.download.specifics.start.meta = dc->meta;
    GNUNET_FS_download_make_status_ (&pi, dc);
  }
  GNUNET_FS_download_start_downloading_ (dc);
  /* attempt reconstruction from disk */
  if (GNUNET_YES == GNUNET_DISK_file_test (dc->filename))
    dc->rfh =
        GNUNET_DISK_file_open (dc->filename, GNUNET_DISK_OPEN_READ,
                               GNUNET_DISK_PERM_NONE);
  if (dc->top_request->state == BRS_CHK_SET)
  {
    if (NULL != dc->rfh)
    {
      /* first, try top-down */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Trying top-down reconstruction for `%s'\n", dc->filename);
      try_top_down_reconstruction (dc, dc->top_request);
      switch (dc->top_request->state)
      {
      case BRS_CHK_SET:
        break;                  /* normal */
      case BRS_DOWNLOAD_DOWN:
        break;                  /* normal, some blocks already down */
      case BRS_DOWNLOAD_UP:
        /* already done entirely, party! */
        if (NULL != dc->rfh)
        {
          /* avoid hanging on to file handle longer than
           * necessary */
          GNUNET_DISK_file_close (dc->rfh);
          dc->rfh = NULL;
        }
        return;
      case BRS_ERROR:
        GNUNET_asprintf (&dc->emsg, _("Invalid URI"));
        GNUNET_FS_download_sync_ (dc);
        pi.status = GNUNET_FS_STATUS_DOWNLOAD_ERROR;
        pi.value.download.specifics.error.message = dc->emsg;
        GNUNET_FS_download_make_status_ (&pi, dc);
        return;
      default:
        GNUNET_assert (0);
        break;
      }
    }
  }
  /* attempt reconstruction from meta data */
  if ((GNUNET_FS_uri_chk_get_file_size (dc->uri) <= MAX_INLINE_SIZE) &&
      (NULL != dc->meta))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Trying to find embedded meta data for download of size %llu with %u bytes MD\n",
                (unsigned long long) GNUNET_FS_uri_chk_get_file_size (dc->uri),
                (unsigned int)
                GNUNET_CONTAINER_meta_data_get_serialized_size (dc->meta));
    GNUNET_CONTAINER_meta_data_iterate (dc->meta, &match_full_data, dc);
    if (BRS_DOWNLOAD_UP == dc->top_request->state)
    {
      if (NULL != dc->rfh)
      {
        /* avoid hanging on to file handle longer than
         * necessary */
        GNUNET_DISK_file_close (dc->rfh);
        dc->rfh = NULL;
      }
      return;                   /* finished, status update was already done for us */
    }
  }
  if (NULL != dc->rfh)
  {
    /* finally, actually run bottom-up */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Trying bottom-up reconstruction of file `%s'\n", dc->filename);
    dc->te =
      GNUNET_FS_tree_encoder_create (dc->h, 
				     GNUNET_FS_uri_chk_get_file_size (dc->uri),
				     dc, &fh_reader,
				     &reconstruct_cb, NULL,
				     &reconstruct_cont);
    dc->task = GNUNET_SCHEDULER_add_now (&get_next_block, dc);
  }
  else
  {
    /* simple, top-level download */
    dc->issue_requests = GNUNET_YES;
    schedule_block_download (dc, dc->top_request);
  }
  if (BRS_DOWNLOAD_UP == dc->top_request->state)
    check_completed (dc);
}


/**
 * Create SUSPEND event for the given download operation
 * and then clean up our state (without stop signal).
 *
 * @param cls the 'struct GNUNET_FS_DownloadContext' to signal for
 */
void
GNUNET_FS_download_signal_suspend_ (void *cls)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  struct GNUNET_FS_ProgressInfo pi;

  if (NULL != dc->top)
    GNUNET_FS_end_top (dc->h, dc->top);
  while (NULL != dc->child_head)
    GNUNET_FS_download_signal_suspend_ (dc->child_head);
  if (NULL != dc->search)
  {
    dc->search->download = NULL;
    dc->search = NULL;
  }
  if (NULL != dc->job_queue)
  {
    GNUNET_FS_dequeue_ (dc->job_queue);
    dc->job_queue = NULL;
  }
  if (NULL != dc->parent)
    GNUNET_CONTAINER_DLL_remove (dc->parent->child_head, dc->parent->child_tail,
                                 dc);
  if (GNUNET_SCHEDULER_NO_TASK != dc->task)
  {
    GNUNET_SCHEDULER_cancel (dc->task);
    dc->task = GNUNET_SCHEDULER_NO_TASK;
  }
  pi.status = GNUNET_FS_STATUS_DOWNLOAD_SUSPEND;
  GNUNET_FS_download_make_status_ (&pi, dc);
  if (NULL != dc->te)
  {
    GNUNET_FS_tree_encoder_finish (dc->te, NULL, NULL);
    dc->te = NULL;
  }
  if (NULL != dc->rfh)
  {
    GNUNET_DISK_file_close (dc->rfh);
    dc->rfh = NULL;
  }
  GNUNET_FS_free_download_request_ (dc->top_request);
  if (NULL != dc->active)
  {
    GNUNET_CONTAINER_multihashmap_destroy (dc->active);
    dc->active = NULL;
  }
  GNUNET_free_non_null (dc->filename);
  GNUNET_CONTAINER_meta_data_destroy (dc->meta);
  GNUNET_FS_uri_destroy (dc->uri);
  GNUNET_free_non_null (dc->temp_filename);
  GNUNET_free_non_null (dc->serialization);
  GNUNET_free (dc);
}


/**
 * Helper function to setup the download context.
 *
 * @param h handle to the file sharing subsystem
 * @param uri the URI of the file (determines what to download); CHK or LOC URI
 * @param meta known metadata for the file (can be NULL)
 * @param filename where to store the file, maybe NULL (then no file is
 *        created on disk and data must be grabbed from the callbacks)
 * @param tempname where to store temporary file data, not used if filename is non-NULL;
 *        can be NULL (in which case we will pick a name if needed); the temporary file
 *        may already exist, in which case we will try to use the data that is there and
 *        if it is not what is desired, will overwrite it
 * @param offset at what offset should we start the download (typically 0)
 * @param length how many bytes should be downloaded starting at offset
 * @param anonymity anonymity level to use for the download
 * @param options various options
 * @param cctx initial value for the client context for this download
 * @return context that can be used to control this download
 */
struct GNUNET_FS_DownloadContext *
create_download_context (struct GNUNET_FS_Handle *h,
			 const struct GNUNET_FS_Uri *uri,
			 const struct GNUNET_CONTAINER_MetaData *meta,
			 const char *filename, const char *tempname,
			 uint64_t offset, uint64_t length, uint32_t anonymity,
			 enum GNUNET_FS_DownloadOptions options, void *cctx)
{
  struct GNUNET_FS_DownloadContext *dc;

  GNUNET_assert (GNUNET_FS_uri_test_chk (uri) || GNUNET_FS_uri_test_loc (uri));
  if ((offset + length < offset) ||
      (offset + length > GNUNET_FS_uri_chk_get_file_size (uri)))
  {
    GNUNET_break (0);
    return NULL;
  }
  dc = GNUNET_malloc (sizeof (struct GNUNET_FS_DownloadContext));
  dc->h = h;
  dc->uri = GNUNET_FS_uri_dup (uri);
  dc->meta = GNUNET_CONTAINER_meta_data_duplicate (meta);
  dc->client_info = cctx;
  dc->start_time = GNUNET_TIME_absolute_get ();
  if (NULL != filename)
  {
    dc->filename = GNUNET_strdup (filename);
    if (GNUNET_YES == GNUNET_DISK_file_test (filename))
      GNUNET_break (GNUNET_OK == GNUNET_DISK_file_size (filename, &dc->old_file_size, GNUNET_YES, GNUNET_YES));
  }
  if (GNUNET_FS_uri_test_loc (dc->uri))
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_FS_uri_loc_get_peer_identity (dc->uri, &dc->target));
  dc->offset = offset;
  dc->length = length;
  dc->anonymity = anonymity;
  dc->options = options;
  dc->active =
      GNUNET_CONTAINER_multihashmap_create (1 + 2 * (length / DBLOCK_SIZE));
  dc->treedepth =
      GNUNET_FS_compute_depth (GNUNET_FS_uri_chk_get_file_size (dc->uri));
  if ((NULL == filename) && (is_recursive_download (dc)))
  {
    if (NULL != tempname)
      dc->temp_filename = GNUNET_strdup (tempname);
    else
      dc->temp_filename = GNUNET_DISK_mktemp ("gnunet-directory-download-tmp");
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Starting download `%s' of %llu bytes with tree depth %u\n",
	      filename,
	      (unsigned long long) length,
              dc->treedepth);
  dc->task = GNUNET_SCHEDULER_add_now (&GNUNET_FS_download_start_task_, dc);
  return dc;
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
 * @param meta known metadata for the file (can be NULL)
 * @param filename where to store the file, maybe NULL (then no file is
 *        created on disk and data must be grabbed from the callbacks)
 * @param tempname where to store temporary file data, not used if filename is non-NULL;
 *        can be NULL (in which case we will pick a name if needed); the temporary file
 *        may already exist, in which case we will try to use the data that is there and
 *        if it is not what is desired, will overwrite it
 * @param offset at what offset should we start the download (typically 0)
 * @param length how many bytes should be downloaded starting at offset
 * @param anonymity anonymity level to use for the download
 * @param options various options
 * @param cctx initial value for the client context for this download
 * @param parent parent download to associate this download with (use NULL
 *        for top-level downloads; useful for manually-triggered recursive downloads)
 * @return context that can be used to control this download
 */
struct GNUNET_FS_DownloadContext *
GNUNET_FS_download_start (struct GNUNET_FS_Handle *h,
                          const struct GNUNET_FS_Uri *uri,
                          const struct GNUNET_CONTAINER_MetaData *meta,
                          const char *filename, const char *tempname,
                          uint64_t offset, uint64_t length, uint32_t anonymity,
                          enum GNUNET_FS_DownloadOptions options, void *cctx,
                          struct GNUNET_FS_DownloadContext *parent)
{
  struct GNUNET_FS_DownloadContext *dc;

  dc = create_download_context (h, uri, meta, filename, tempname,
				offset, length, anonymity, options, cctx);
  if (NULL == dc)
    return NULL;
  dc->parent = parent;
  if (NULL != parent)
    GNUNET_CONTAINER_DLL_insert (parent->child_head, parent->child_tail, dc);
  else
    dc->top =
        GNUNET_FS_make_top (dc->h, &GNUNET_FS_download_signal_suspend_, dc);
  return dc;
}


/**
 * Download parts of a file based on a search result.  The download
 * will be associated with the search result (and the association
 * will be preserved when serializing/deserializing the state).
 * If the search is stopped, the download will not be aborted but
 * be 'promoted' to a stand-alone download.
 *
 * As with the other download function, this will store
 * the blocks at the respective offset in the given file.  Also, the
 * download is still using the blocking of the underlying FS
 * encoding.  As a result, the download may *write* outside of the
 * given boundaries (if offset and length do not match the 32k FS
 * block boundaries). <p>
 *
 * The given range can be used to focus a download towards a
 * particular portion of the file (optimization), not to strictly
 * limit the download to exactly those bytes.
 *
 * @param h handle to the file sharing subsystem
 * @param sr the search result to use for the download (determines uri and
 *        meta data and associations)
 * @param filename where to store the file, maybe NULL (then no file is
 *        created on disk and data must be grabbed from the callbacks)
 * @param tempname where to store temporary file data, not used if filename is non-NULL;
 *        can be NULL (in which case we will pick a name if needed); the temporary file
 *        may already exist, in which case we will try to use the data that is there and
 *        if it is not what is desired, will overwrite it
 * @param offset at what offset should we start the download (typically 0)
 * @param length how many bytes should be downloaded starting at offset
 * @param anonymity anonymity level to use for the download
 * @param options various download options
 * @param cctx initial value for the client context for this download
 * @return context that can be used to control this download
 */
struct GNUNET_FS_DownloadContext *
GNUNET_FS_download_start_from_search (struct GNUNET_FS_Handle *h,
                                      struct GNUNET_FS_SearchResult *sr,
                                      const char *filename,
                                      const char *tempname, uint64_t offset,
                                      uint64_t length, uint32_t anonymity,
                                      enum GNUNET_FS_DownloadOptions options,
                                      void *cctx)
{
  struct GNUNET_FS_DownloadContext *dc;

  if ((NULL == sr) || (NULL != sr->download))
  {
    GNUNET_break (0);
    return NULL;
  }
  dc = create_download_context (h, sr->uri, sr->meta, filename, tempname,
				offset, length, anonymity, options, cctx);
  if (NULL == dc)
    return NULL;
  dc->search = sr;
  sr->download = dc;
  if (NULL != sr->probe_ctx)
  {
    GNUNET_FS_download_stop (sr->probe_ctx, GNUNET_YES);
    sr->probe_ctx = NULL;
  }
  return dc;
}


/**
 * Start the downloading process (by entering the queue).
 *
 * @param dc our download context
 */
void
GNUNET_FS_download_start_downloading_ (struct GNUNET_FS_DownloadContext *dc)
{
  if (dc->completed == dc->length)
    return;
  GNUNET_assert (NULL == dc->job_queue);
  dc->job_queue =
      GNUNET_FS_queue_ (dc->h, &activate_fs_download, &deactivate_fs_download,
                        dc, (dc->length + DBLOCK_SIZE - 1) / DBLOCK_SIZE,
			(0 == (dc->options & GNUNET_FS_DOWNLOAD_IS_PROBE))
			? GNUNET_FS_QUEUE_PRIORITY_NORMAL 
			: GNUNET_FS_QUEUE_PRIORITY_PROBE);
}


/**
 * Stop a download (aborts if download is incomplete).
 *
 * @param dc handle for the download
 * @param do_delete delete files of incomplete downloads
 */
void
GNUNET_FS_download_stop (struct GNUNET_FS_DownloadContext *dc, int do_delete)
{
  struct GNUNET_FS_ProgressInfo pi;
  int have_children;
  int search_was_null;

  if (NULL != dc->top)
    GNUNET_FS_end_top (dc->h, dc->top);
  if (GNUNET_SCHEDULER_NO_TASK != dc->task)
  {
    GNUNET_SCHEDULER_cancel (dc->task);
    dc->task = GNUNET_SCHEDULER_NO_TASK;
  }
  search_was_null = (NULL == dc->search);
  if (NULL != dc->search)
  {
    dc->search->download = NULL;
    GNUNET_FS_search_result_sync_ (dc->search);
    dc->search = NULL;
  }
  if (NULL != dc->job_queue)
  {
    GNUNET_FS_dequeue_ (dc->job_queue);
    dc->job_queue = NULL;
  }
  if (NULL != dc->te)
  {
    GNUNET_FS_tree_encoder_finish (dc->te, NULL, NULL);
    dc->te = NULL;
  }
  have_children = (NULL != dc->child_head) ? GNUNET_YES : GNUNET_NO;
  while (NULL != dc->child_head)
    GNUNET_FS_download_stop (dc->child_head, do_delete);
  if (NULL != dc->parent)
    GNUNET_CONTAINER_DLL_remove (dc->parent->child_head, dc->parent->child_tail,
                                 dc);
  if (NULL != dc->serialization)
    GNUNET_FS_remove_sync_file_ (dc->h,
                                 ((NULL != dc->parent) ||
                                  (! search_was_null)) ? GNUNET_FS_SYNC_PATH_CHILD_DOWNLOAD :
                                 GNUNET_FS_SYNC_PATH_MASTER_DOWNLOAD,
                                 dc->serialization);
  if ((GNUNET_YES == have_children) && (NULL == dc->parent))
    GNUNET_FS_remove_sync_dir_ (dc->h,
                                (! search_was_null) ? GNUNET_FS_SYNC_PATH_CHILD_DOWNLOAD :
                                GNUNET_FS_SYNC_PATH_MASTER_DOWNLOAD,
                                dc->serialization);
  pi.status = GNUNET_FS_STATUS_DOWNLOAD_STOPPED;
  GNUNET_FS_download_make_status_ (&pi, dc);
  GNUNET_FS_free_download_request_ (dc->top_request);
  dc->top_request = NULL;
  if (NULL != dc->active)
  {
    GNUNET_CONTAINER_multihashmap_destroy (dc->active);
    dc->active = NULL;
  }
  if (NULL != dc->filename)
  {
    if ((dc->completed != dc->length) && (GNUNET_YES == do_delete))
    {
      if (0 != UNLINK (dc->filename))
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink",
                                  dc->filename);
    }
    GNUNET_free (dc->filename);
  }
  GNUNET_CONTAINER_meta_data_destroy (dc->meta);
  GNUNET_FS_uri_destroy (dc->uri);
  if (NULL != dc->temp_filename)
  {
    if (0 != UNLINK (dc->temp_filename))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "unlink",
                                dc->temp_filename);
    GNUNET_free (dc->temp_filename);
  }
  GNUNET_free_non_null (dc->serialization);
  GNUNET_free (dc);
}

/* end of fs_download.c */
