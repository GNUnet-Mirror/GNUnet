/*
     This file is part of GNUnet.
     (C) 2009-2011 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_tree.c
 * @brief Merkle-tree-ish-CHK file encoding for GNUnet
 * @see http://gnunet.org/encoding.php3
 * @author Krista Bennett
 * @author Christian Grothoff
 */
#include "platform.h"
#include "fs_tree.h"


/**
 * Context for an ECRS-based file encoder that computes
 * the Merkle-ish-CHK tree.
 */
struct GNUNET_FS_TreeEncoder
{

  /**
   * Global FS context.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * Closure for all callbacks.
   */
  void *cls;

  /**
   * Function to call on encrypted blocks.
   */
  GNUNET_FS_TreeBlockProcessor proc;

  /**
   * Function to call with progress information.
   */
  GNUNET_FS_TreeProgressCallback progress;

  /**
   * Function to call to receive input data.
   */
  GNUNET_FS_DataReader reader;

  /**
   * Function to call once we're done with processing.
   */
  GNUNET_SCHEDULER_Task cont;

  /**
   * Set to an error message (if we had an error).
   */
  char *emsg;

  /**
   * Set to the URI (upon successful completion)
   */
  struct GNUNET_FS_Uri *uri;

  /**
   * Overall file size.
   */
  uint64_t size;

  /**
   * How far are we?
   */
  uint64_t publish_offset;

  /**
   * How deep are we?  Depth 0 is for the DBLOCKs.
   */
  unsigned int current_depth;

  /**
   * How deep is the tree? Always > 0.
   */
  unsigned int chk_tree_depth;

  /**
   * In-memory cache of the current CHK tree.
   * This struct will contain the CHK values
   * from the root to the currently processed
   * node in the tree as identified by
   * "current_depth" and "publish_offset".
   * The "chktree" will be initially NULL,
   * then allocated to a sufficient number of
   * entries for the size of the file and
   * finally freed once the upload is complete.
   */
  struct ContentHashKey *chk_tree;

  /**
   * Are we currently in 'GNUNET_FS_tree_encoder_next'?
   * Flag used to prevent recursion.
   */
  int in_next;
};


/**
 * Compute the depth of the CHK tree.
 *
 * @param flen file length for which to compute the depth
 * @return depth of the tree, always > 0.  A depth of 1 means only a DBLOCK.
 */
unsigned int
GNUNET_FS_compute_depth (uint64_t flen)
{
  unsigned int treeDepth;
  uint64_t fl;

  treeDepth = 1;
  fl = DBLOCK_SIZE;
  while (fl < flen)
  {
    treeDepth++;
    if (fl * CHK_PER_INODE < fl)
    {
      /* integer overflow, this is a HUGE file... */
      return treeDepth;
    }
    fl = fl * CHK_PER_INODE;
  }
  return treeDepth;
}


/**
 * Calculate how many bytes of payload a block tree of the given
 * depth MAY correspond to at most (this function ignores the fact that
 * some blocks will only be present partially due to the total file
 * size cutting some blocks off at the end).
 *
 * @param depth depth of the block.  depth==0 is a DBLOCK.
 * @return number of bytes of payload a subtree of this depth may correspond to
 */
uint64_t
GNUNET_FS_tree_compute_tree_size (unsigned int depth)
{
  uint64_t rsize;
  unsigned int i;

  rsize = DBLOCK_SIZE;
  for (i = 0; i < depth; i++)
    rsize *= CHK_PER_INODE;
  return rsize;
}


/**
 * Compute the size of the current IBLOCK.  The encoder is
 * triggering the calculation of the size of an IBLOCK at the
 * *end* (hence end_offset) of its construction.  The IBLOCK
 * maybe a full or a partial IBLOCK, and this function is to
 * calculate how long it should be.
 *
 * @param depth depth of the IBlock in the tree, 0 would be a DBLOCK,
 *        must be > 0 (this function is for IBLOCKs only!)
 * @param end_offset current offset in the payload (!) of the overall file,
 *        must be > 0 (since this function is called at the
 *        end of a block).
 * @return size of the corresponding IBlock
 */
static uint16_t
GNUNET_FS_tree_compute_iblock_size (unsigned int depth, uint64_t end_offset)
{
  unsigned int ret;
  uint64_t mod;
  uint64_t bds;

  GNUNET_assert (depth > 0);
  GNUNET_assert (end_offset > 0);
  bds = GNUNET_FS_tree_compute_tree_size (depth);
  mod = end_offset % bds;
  if (0 == mod)
  {
    /* we were triggered at the end of a full block */
    ret = CHK_PER_INODE;
  }
  else
  {
    /* we were triggered at the end of the file */
    bds /= CHK_PER_INODE;
    ret = mod / bds;
    if (0 != mod % bds)
      ret++;
  }
  return (uint16_t) (ret * sizeof (struct ContentHashKey));
}


/**
 * Compute how many bytes of data should be stored in
 * the specified block.
 *
 * @param fsize overall file size, must be > 0.
 * @param offset offset in the original data corresponding
 *         to the beginning of the tree induced by the block;
 *         must be <= fsize
 * @param depth depth of the node in the tree, 0 for DBLOCK
 * @return number of bytes stored in this node
 */
size_t
GNUNET_FS_tree_calculate_block_size (uint64_t fsize, uint64_t offset,
                                     unsigned int depth)
{
  size_t ret;
  uint64_t rsize;
  uint64_t epos;
  unsigned int chks;

  GNUNET_assert (fsize > 0);
  GNUNET_assert (offset <= fsize);
  if (depth == 0)
  {
    ret = DBLOCK_SIZE;
    if ((offset + ret > fsize) || (offset + ret < offset))
      ret = (size_t) (fsize - offset);
    return ret;
  }

  rsize = GNUNET_FS_tree_compute_tree_size (depth - 1);
  epos = offset + rsize * CHK_PER_INODE;
  if ((epos < offset) || (epos > fsize))
    epos = fsize;
  /* round up when computing #CHKs in our IBlock */
  chks = (epos - offset + rsize - 1) / rsize;
  GNUNET_assert (chks <= CHK_PER_INODE);
  return chks * sizeof (struct ContentHashKey);
}


/**
 * Initialize a tree encoder.  This function will call "proc" and
 * "progress" on each block in the tree.  Once all blocks have been
 * processed, "cont" will be scheduled.  The "reader" will be called
 * to obtain the (plaintext) blocks for the file.  Note that this
 * function will not actually call "proc".  The client must
 * call "GNUNET_FS_tree_encoder_next" to trigger encryption (and
 * calling of "proc") for the each block.
 *
 * @param h the global FS context
 * @param size overall size of the file to encode
 * @param cls closure for reader, proc, progress and cont
 * @param reader function to call to read plaintext data
 * @param proc function to call on each encrypted block
 * @param progress function to call with progress information
 * @param cont function to call when done
 */
struct GNUNET_FS_TreeEncoder *
GNUNET_FS_tree_encoder_create (struct GNUNET_FS_Handle *h, uint64_t size,
                               void *cls, GNUNET_FS_DataReader reader,
                               GNUNET_FS_TreeBlockProcessor proc,
                               GNUNET_FS_TreeProgressCallback progress,
                               GNUNET_SCHEDULER_Task cont)
{
  struct GNUNET_FS_TreeEncoder *te;

  te = GNUNET_malloc (sizeof (struct GNUNET_FS_TreeEncoder));
  te->h = h;
  te->size = size;
  te->cls = cls;
  te->reader = reader;
  te->proc = proc;
  te->progress = progress;
  te->cont = cont;
  te->chk_tree_depth = GNUNET_FS_compute_depth (size);
  te->chk_tree =
      GNUNET_malloc (te->chk_tree_depth * CHK_PER_INODE *
                     sizeof (struct ContentHashKey));
  return te;
}


/**
 * Compute the offset of the CHK for the
 * current block in the IBlock above.
 *
 * @param depth depth of the IBlock in the tree (aka overall
 *               number of tree levels minus depth); 0 == DBlock
 * @param end_offset current offset in the overall file,
 *               at the *beginning* of the block for DBLOCKs (depth==0),
 *               otherwise at the *end* of the block (exclusive)
 * @return (array of CHKs') offset in the above IBlock
 */
static unsigned int
compute_chk_offset (unsigned int depth, uint64_t end_offset)
{
  uint64_t bds;
  unsigned int ret;

  bds = GNUNET_FS_tree_compute_tree_size (depth);
  if (depth > 0)
    end_offset--;               /* round down since for depth > 0 offset is at the END of the block */
  ret = end_offset / bds;
  return ret % CHK_PER_INODE;
}


/**
 * Encrypt the next block of the file (and call proc and progress
 * accordingly; or of course "cont" if we have already completed
 * encoding of the entire file).
 *
 * @param te tree encoder to use
 */
void
GNUNET_FS_tree_encoder_next (struct GNUNET_FS_TreeEncoder *te)
{
  struct ContentHashKey *mychk;
  const void *pt_block;
  uint16_t pt_size;
  char iob[DBLOCK_SIZE];
  char enc[DBLOCK_SIZE];
  struct GNUNET_CRYPTO_AesSessionKey sk;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  unsigned int off;

  GNUNET_assert (GNUNET_NO == te->in_next);
  te->in_next = GNUNET_YES;
  if (te->chk_tree_depth == te->current_depth)
  {
    off = CHK_PER_INODE * (te->chk_tree_depth - 1);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "TE done, reading CHK `%s' from %u\n",
                GNUNET_h2s (&te->chk_tree[off].query), off);
    te->uri = GNUNET_malloc (sizeof (struct GNUNET_FS_Uri));
    te->uri->type = chk;
    te->uri->data.chk.chk = te->chk_tree[off];
    te->uri->data.chk.file_length = GNUNET_htonll (te->size);
    te->in_next = GNUNET_NO;
    te->cont (te->cls, NULL);
    return;
  }
  if (0 == te->current_depth)
  {
    /* read DBLOCK */
    pt_size = GNUNET_MIN (DBLOCK_SIZE, te->size - te->publish_offset);
    if (pt_size !=
        te->reader (te->cls, te->publish_offset, pt_size, iob, &te->emsg))
    {
      te->cont (te->cls, NULL);
      te->in_next = GNUNET_NO;
      return;
    }
    pt_block = iob;
  }
  else
  {
    pt_size =
        GNUNET_FS_tree_compute_iblock_size (te->current_depth,
                                            te->publish_offset);
    pt_block = &te->chk_tree[(te->current_depth - 1) * CHK_PER_INODE];
  }
  off = compute_chk_offset (te->current_depth, te->publish_offset);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "TE is at offset %llu and depth %u with block size %u and target-CHK-offset %u\n",
              (unsigned long long) te->publish_offset, te->current_depth,
              (unsigned int) pt_size, (unsigned int) off);
  mychk = &te->chk_tree[te->current_depth * CHK_PER_INODE + off];
  GNUNET_CRYPTO_hash (pt_block, pt_size, &mychk->key);
  GNUNET_CRYPTO_hash_to_aes_key (&mychk->key, &sk, &iv);
  GNUNET_CRYPTO_aes_encrypt (pt_block, pt_size, &sk, &iv, enc);
  GNUNET_CRYPTO_hash (enc, pt_size, &mychk->query);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "TE calculates query to be `%s', stored at %u\n",
              GNUNET_h2s (&mychk->query),
              te->current_depth * CHK_PER_INODE + off);
  if (NULL != te->proc)
    te->proc (te->cls, mychk, te->publish_offset, te->current_depth,
              (0 ==
               te->current_depth) ? GNUNET_BLOCK_TYPE_FS_DBLOCK :
              GNUNET_BLOCK_TYPE_FS_IBLOCK, enc, pt_size);
  if (NULL != te->progress)
    te->progress (te->cls, te->publish_offset, pt_block, pt_size,
                  te->current_depth);
  if (0 == te->current_depth)
  {
    te->publish_offset += pt_size;
    if ((te->publish_offset == te->size) ||
        (0 == te->publish_offset % (CHK_PER_INODE * DBLOCK_SIZE)))
      te->current_depth++;
  }
  else
  {
    if ((off == CHK_PER_INODE) || (te->publish_offset == te->size))
      te->current_depth++;
    else
      te->current_depth = 0;
  }
  te->in_next = GNUNET_NO;
}


/**
 * Clean up a tree encoder and return information
 * about the resulting URI or an error message.
 *
 * @param te the tree encoder to clean up
 * @param uri set to the resulting URI (if encoding finished)
 * @param emsg set to an error message (if an error occured
 *        within the tree encoder; if this function is called
 *        prior to completion and prior to an internal error,
 *        both "*uri" and "*emsg" will be set to NULL).
 */
void
GNUNET_FS_tree_encoder_finish (struct GNUNET_FS_TreeEncoder *te,
                               struct GNUNET_FS_Uri **uri, char **emsg)
{
  GNUNET_assert (GNUNET_NO == te->in_next);
  if (uri != NULL)
    *uri = te->uri;
  else if (NULL != te->uri)
    GNUNET_FS_uri_destroy (te->uri);
  if (emsg != NULL)
    *emsg = te->emsg;
  else
    GNUNET_free_non_null (te->emsg);
  GNUNET_free (te->chk_tree);
  GNUNET_free (te);
}

/* end of fs_tree.c */
