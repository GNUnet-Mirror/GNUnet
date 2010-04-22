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
 * @file fs/fs_tree.h
 * @brief Merkle-tree-ish-CHK file encoding for GNUnet
 * @see http://gnunet.org/encoding.php3
 * @author Krista Bennett
 * @author Christian Grothoff
 *
 * TODO:
 * - decide if this API should be made public (gnunet_fs_service.h)
 *   or remain "internal" (but with exported symbols?)
 */
#ifndef GNUNET_FS_TREE_H
#define GNUNET_FS_TREE_H

#include "fs.h"

/**
 * Compute the depth of the CHK tree.
 *
 * @param flen file length for which to compute the depth
 * @return depth of the tree
 */
unsigned int
GNUNET_FS_compute_depth (uint64_t flen);


/**
 * Context for an ECRS-based file encoder that computes
 * the Merkle-ish-CHK tree.
 */
struct GNUNET_FS_TreeEncoder;


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
typedef void (*GNUNET_FS_TreeBlockProcessor)(void *cls,
					     const GNUNET_HashCode *query,
					     uint64_t offset,
					     uint32_t type,
					     const void *block,
					     uint16_t block_size);
					     

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
typedef void (*GNUNET_FS_TreeProgressCallback)(void *cls,
					       uint64_t offset,
					       const void *pt_block,
					       size_t pt_size,
					       unsigned int depth);
					       

/**
 * Initialize a tree encoder.  This function will call "proc" and
 * "progress" on each block in the tree.  Once all blocks have been
 * processed, "cont" will be scheduled.  The "reader" will be called
 * to obtain the (plaintext) blocks for the file.  Note that this
 * function will actually never call "proc"; the "proc" function must
 * be triggered by calling "GNUNET_FS_tree_encoder_next" to trigger
 * encryption (and calling of "proc") for each block.
 *
 * @param h the global FS context
 * @param size overall size of the file to encode
 * @param cls closure for reader, proc, progress and cont
 * @param reader function to call to read plaintext data
 * @param proc function to call on each encrypted block
 * @param progress function to call with progress information 
 * @param cont function to call when done
 * @return tree encoder context
 */
struct GNUNET_FS_TreeEncoder *
GNUNET_FS_tree_encoder_create (struct GNUNET_FS_Handle *h,
			       uint64_t size,
			       void *cls,
			       GNUNET_FS_DataReader reader,
			       GNUNET_FS_TreeBlockProcessor proc,
			       GNUNET_FS_TreeProgressCallback progress,
			       GNUNET_SCHEDULER_Task cont);


/**
 * Encrypt the next block of the file (and 
 * call proc and progress accordingly; or 
 * of course "cont" if we have already completed
 * encoding of the entire file).
 *
 * @param te tree encoder to use
 */
void GNUNET_FS_tree_encoder_next (struct GNUNET_FS_TreeEncoder * te);


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
				    char **emsg);


/**
 * Compute the size of the current IBlock.
 *
 * @param height height of the IBlock in the tree (aka overall
 *               number of tree levels minus depth); 0 == DBlock
 * @param offset current offset in the overall file
 * @return size of the corresponding IBlock
 */
uint16_t 
GNUNET_FS_tree_compute_iblock_size (unsigned int height,
				    uint64_t offset);


/**
 * Compute how many bytes of data should be stored in
 * the specified node.
 *
 * @param fsize overall file size
 * @param totaldepth depth of the entire tree
 * @param offset offset of the node
 * @param depth depth of the node
 * @return number of bytes stored in this node
 */
size_t
GNUNET_FS_tree_calculate_block_size (uint64_t fsize,
				     unsigned int totaldepth,
				     uint64_t offset,
				     unsigned int depth);


#if 0
/* the functions below will be needed for persistence
   but are not yet implemented -- FIXME... */
/**
 * Get data that would be needed to resume
 * the encoding later.
 * 
 * @param te encoding to resume
 * @param data set to the resume data
 * @param size set to the size of the resume data
 */
void GNUNET_FS_tree_encoder_resume_get_data (const struct GNUNET_FS_TreeEncoder * te,
					     void **data,
					     size_t *size);


/**
 * Reset tree encoder to point previously
 * obtained for resuming.
 * 
 * @param te encoding to resume
 * @param data the resume data
 * @param size the size of the resume data
 */
void GNUNET_FS_tree_encoder_resume (struct GNUNET_FS_TreeEncoder * te,
				    const void *data,
				    size_t size);
#endif

#endif

/* end of fs_tree.h */
