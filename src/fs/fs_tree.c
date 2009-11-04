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
 * @file fs/fs_tree.c
 * @brief Merkle-tree-ish-CHK file encoding for GNUnet
 * @see http://gnunet.org/encoding.php3
 * @author Krista Bennett
 * @author Christian Grothoff
 *
 * TODO:
 * - decide if this API should be made public (gnunet_fs_service.h)
 *   or remain "internal" (but with exported symbols?)
 */
#include "platform.h"
#include "fs_tree.h"

#define DEBUG_TREE GNUNET_NO

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
   * How deep are we?
   */
  unsigned int current_depth;

  /**
   * How deep is the tree?
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

};


/**
 * Compute the depth of the CHK tree.
 *
 * @param flen file length for which to compute the depth
 * @return depth of the tree
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
GNUNET_FS_tree_encoder_create (struct GNUNET_FS_Handle *h,
			       uint64_t size,
			       void *cls,
			       GNUNET_FS_DataReader reader,
			       GNUNET_FS_TreeBlockProcessor proc,
			       GNUNET_FS_TreeProgressCallback progress,
			       GNUNET_SCHEDULER_Task cont)
{
  struct GNUNET_FS_TreeEncoder *te;
  
  GNUNET_assert (size > 0);
  te = GNUNET_malloc (sizeof (struct GNUNET_FS_TreeEncoder));
  te->h = h;
  te->size = size;
  te->cls = cls;
  te->reader = reader;
  te->proc = proc;
  te->progress = progress;
  te->cont = cont;
  te->chk_tree_depth = GNUNET_FS_compute_depth (size);
  te->current_depth = te->chk_tree_depth;
  te->chk_tree = GNUNET_malloc (te->chk_tree_depth *
				CHK_PER_INODE *
				sizeof (struct ContentHashKey));
  return te;
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
  bds = DBLOCK_SIZE; /* number of bytes each CHK at level "i"
				  corresponds to */
  for (i=0;i<height;i++)
    bds *= CHK_PER_INODE;
  mod = offset % bds;
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

  bds = DBLOCK_SIZE; /* number of bytes each CHK at level "i"
				  corresponds to */
  for (i=0;i<height;i++)
    bds *= CHK_PER_INODE;
  ret = offset / bds;
  return ret % CHK_PER_INODE; 
}


/**
 * Encrypt the next block of the file (and 
 * call proc and progress accordingly; or 
 * of course "cont" if we have already completed
 * encoding of the entire file).
 *
 * @param te tree encoder to use
 */
void GNUNET_FS_tree_encoder_next (struct GNUNET_FS_TreeEncoder * te)
{
  struct ContentHashKey *mychk;
  const void *pt_block;
  uint16_t pt_size;
  char iob[DBLOCK_SIZE];
  char enc[DBLOCK_SIZE];
  struct GNUNET_CRYPTO_AesSessionKey sk;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  unsigned int off;

  if (te->current_depth == te->chk_tree_depth)
    {
      pt_size = GNUNET_MIN(DBLOCK_SIZE,
			   te->size - te->publish_offset);
      if (pt_size !=
	  te->reader (te->cls,
		      te->publish_offset,
		      pt_size,
		      iob,
		      &te->emsg))
	{
	  GNUNET_SCHEDULER_add_continuation (te->h->sched,
					     te->cont,
					     te->cls,
					     GNUNET_SCHEDULER_REASON_TIMEOUT);
	  return;
	}
      pt_block = iob;
    }
  else
    {
      pt_size = compute_iblock_size (te->chk_tree_depth - te->current_depth,
				     te->publish_offset); 
      pt_block = &te->chk_tree[te->current_depth *
			       CHK_PER_INODE];
    }
  if (0 == te->current_depth)
    {
      te->uri = GNUNET_malloc (sizeof(struct GNUNET_FS_Uri));
      te->uri->type = chk;
      te->uri->data.chk.chk = te->chk_tree[0];
      te->uri->data.chk.file_length = GNUNET_htonll (te->size);
      GNUNET_SCHEDULER_add_continuation (te->h->sched,
					 te->cont,
					 te->cls,
					 GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      return;
    }
  off = compute_chk_offset (te->chk_tree_depth - te->current_depth,
			    te->publish_offset);
#if DEBUG_TREE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "TE is at offset %llu and depth %u with block size %u and target-CHK-offset %u\n",
	      (unsigned long long) te->publish_offset,
	      te->current_depth,
	      (unsigned int) pt_size,
	      (unsigned int) off);
#endif
  mychk = &te->chk_tree[(te->current_depth-1)*CHK_PER_INODE+off];
  GNUNET_CRYPTO_hash (pt_block, pt_size, &mychk->key);
  GNUNET_CRYPTO_hash_to_aes_key (&mychk->key, &sk, &iv);
  GNUNET_CRYPTO_aes_encrypt (pt_block,
			     pt_size,
			     &sk,
			     &iv,
			     enc);
  GNUNET_CRYPTO_hash (enc, pt_size, &mychk->query);
#if DEBUG_TREE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "TE calculates query to be `%s'\n",
	      GNUNET_h2s (&mychk->query));
#endif
  if (NULL != te->proc)
    te->proc (te->cls,
	      &mychk->query,
	      te->publish_offset,
	      (te->current_depth == te->chk_tree_depth) 
	      ? GNUNET_DATASTORE_BLOCKTYPE_DBLOCK 
	      : GNUNET_DATASTORE_BLOCKTYPE_IBLOCK,
	      enc,
	      pt_size);
  if (NULL != te->progress)
    te->progress (te->cls,
		  te->publish_offset,
		  pt_block,
		  pt_size,
		  te->current_depth);
  if (te->current_depth == te->chk_tree_depth) 
    { 
      te->publish_offset += pt_size;
      if ( (te->publish_offset == te->size) ||
	   (0 == te->publish_offset % (CHK_PER_INODE * DBLOCK_SIZE) ) )
	te->current_depth--;
    }
  else
    {
      if ( (off == CHK_PER_INODE) ||
	   (te->publish_offset == te->size) )
	te->current_depth--;
      else
	te->current_depth = te->chk_tree_depth;
    }
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
void GNUNET_FS_tree_encoder_finish (struct GNUNET_FS_TreeEncoder * te,
				    struct GNUNET_FS_Uri **uri,
				    char **emsg)
{
  *uri = te->uri;
  *emsg = te->emsg;
  GNUNET_free (te->chk_tree);
  GNUNET_free (te);
}

/* end of fs_tree.c */
