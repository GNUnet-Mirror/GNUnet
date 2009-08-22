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
 * @file fs/fs_directory.c
 * @brief Helper functions for building directories.
 * @author Christian Grothoff
 *
 * TODO:
 * - add support for embedded file data (use padding room!)
 * - add directory builder API to gnunet_fs_service
 * - modify directory builder API to support incremental
 *   generation of directories (to allow directories that
 *   would not fit into memory to be created)
 * - modify directory processor API to support incremental
 *   iteration over FULL directories (without missing entries)
 *   to allow access to directories that do not fit entirely
 *   into memory
 */
#include "platform.h"
#include "gnunet_fs_service.h"
#include "fs.h"


/**
 * Does the meta-data claim that this is a directory?
 * Checks if the mime-type is that of a GNUnet directory.
 *
 * @return GNUNET_YES if it is, GNUNET_NO if it is not, GNUNET_SYSERR if
 *  we have no mime-type information (treat as 'GNUNET_NO')
 */
int 
GNUNET_FS_meta_data_test_for_directory (const struct GNUNET_CONTAINER_MetaData *md)
{
  char *mime;
  int ret;
  
  mime = GNUNET_CONTAINER_meta_data_get_by_type (md, EXTRACTOR_MIMETYPE);
  if (mime == NULL)
    return GNUNET_SYSERR;
  ret = (0 == strcmp (mime, GNUNET_FS_DIRECTORY_MIME)) ? GNUNET_YES : GNUNET_NO;
  GNUNET_free (mime);
  return ret; 
}


/**
 * Set the MIMETYPE information for the given
 * metadata to "application/gnunet-directory".
 * 
 * @param md metadata to add mimetype to
 */
void
GNUNET_FS_meta_data_make_directory (struct GNUNET_CONTAINER_MetaData *md)
{
  char *mime;
  
  mime = GNUNET_CONTAINER_meta_data_get_by_type (md, EXTRACTOR_MIMETYPE);
  if (mime != NULL)
    {
      GNUNET_break (0 == strcmp (mime,
				 GNUNET_FS_DIRECTORY_MIME));
      GNUNET_free (mime);
      return;
    }
  GNUNET_CONTAINER_meta_data_insert (md, 
				     EXTRACTOR_MIMETYPE,
				     GNUNET_FS_DIRECTORY_MIME);
}


/**
 * Iterate over all entries in a directory.  Note that directories
 * are structured such that it is possible to iterate over the
 * individual blocks as well as over the entire directory.  Thus
 * a client can call this function on the buffer in the
 * GNUNET_FS_ProgressCallback.  Also, directories can optionally
 * include the contents of (small) files embedded in the directory
 * itself; for those files, the processor may be given the
 * contents of the file directly by this function.
 * <p>
 *
 * Note that this function maybe called on parts of directories.  Thus
 * parser errors should not be reported _at all_ (with GNUNET_break).
 * Still, if some entries can be recovered despite these parsing
 * errors, the function should try to do this.
 *
 * @param size number of bytes in data
 * @param data pointer to the beginning of the directory
 * @param offset offset of data in the directory
 * @param dep function to call on each entry
 * @param dep_cls closure for dep
 */
void 
GNUNET_FS_directory_list_contents (size_t size,
				   const void *data,
				   uint64_t offset,
				   GNUNET_FS_DirectoryEntryProcessor dep, 
				   void *dep_cls)
{
  const char *cdata = data;
  char *emsg;
  uint64_t pos;
  uint64_t align;
  uint32_t mdSize;
  uint64_t epos;
  struct GNUNET_FS_Uri *uri;
  struct GNUNET_CONTAINER_MetaData *md;
  char *filename;

  pos = offset;
  if ( (pos == 0) && 
       (size >= 8 + sizeof (uint32_t)) &&
       (0 == memcmp (cdata, GNUNET_FS_DIRECTORY_MAGIC, 8)) )
    {
      memcpy (&mdSize, &cdata[8], sizeof (uint32_t));
      mdSize = ntohl (mdSize);
      if (mdSize > size - 8 - sizeof (uint32_t))
	{
	  /* invalid size */
	  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		      _("Not a GNUnet directory.\n"));
	  return;
	}
      md = GNUNET_CONTAINER_meta_data_deserialize (&cdata[8 +
							 sizeof (uint32_t)],
						   mdSize);
      if (md == NULL)
        {
          GNUNET_break (0);
          return; /* malformed ! */
        }
      dep (dep_cls,
	   NULL,
	   NULL,				
	   md,
	   0,
	   NULL);
      GNUNET_CONTAINER_meta_data_destroy (md);
      pos = 8 + sizeof (uint32_t) + mdSize;
    }
  while (pos < size)
    {
      /* find end of URI */
      if (cdata[pos] == '\0')
        {
          /* URI is never empty, must be end of block,
             skip to next alignment */
          align =
            ((pos / GNUNET_FS_DBLOCK_SIZE) + 1) * GNUNET_FS_DBLOCK_SIZE;
          if (align == pos)
            {
              /* if we were already aligned, still skip a block! */
              align += GNUNET_FS_DBLOCK_SIZE;
            }
          pos = align;
          if (pos >= size)
            {
              /* malformed - or partial download... */
              break;
            }
        }
      epos = pos;
      while ((epos < size) && (cdata[epos] != '\0'))
        epos++;
      if (epos >= size)
        return;   /* malformed - or partial download */
      
      uri = GNUNET_FS_uri_parse (&cdata[pos], &emsg);
      pos = epos + 1;
      if (uri == NULL)
        {
	  GNUNET_free (emsg);
          pos--;                /* go back to '\0' to force going to next alignment */
          continue;
        }
      if (GNUNET_FS_uri_test_ksk (uri))
        {
          GNUNET_FS_uri_destroy (uri);
          GNUNET_break (0);
          return; /* illegal in directory! */
        }

      memcpy (&mdSize, &cdata[pos], sizeof (uint32_t));
      mdSize = ntohl (mdSize);
      pos += sizeof (uint32_t);
      if (pos + mdSize > size)
        {
          GNUNET_FS_uri_destroy (uri);
          return; /* malformed - or partial download */
        }

      md = GNUNET_CONTAINER_meta_data_deserialize (&cdata[pos], mdSize);
      if (md == NULL)
        {
          GNUNET_FS_uri_destroy (uri);
          GNUNET_break (0);
          return; /* malformed ! */
        }
      pos += mdSize;
      /* FIXME: add support for embedded data */
      filename = GNUNET_CONTAINER_meta_data_get_by_type (md,
							 EXTRACTOR_FILENAME);
      if (dep != NULL) 
         dep (dep_cls,
	      filename,
	      uri,
	      md,
	      0,
	      NULL);
      GNUNET_free_non_null (filename);
      GNUNET_CONTAINER_meta_data_destroy (md);
      GNUNET_FS_uri_destroy (uri);
    }
}


void
GNUNET_FS_directory_create ()
{
}


#if 0


/**
 * Given the start and end position of a block of
 * data, return the end position of that data
 * after alignment to the GNUNET_FS_DBLOCK_SIZE.
 */
static uint64_t
do_align (uint64_t start_position, 
	  uint64_t end_position)
{
  uint64_t align;
  
  align = (end_position / GNUNET_FS_DBLOCK_SIZE) * GNUNET_FS_DBLOCK_SIZE;
  if ((start_position < align) && (end_position > align))
    return align + end_position - start_position;
  return end_position;
}


/**
 * Compute a permuation of the blocks to
 * minimize the cost of alignment.  Greedy packer.
 *
 * @param start starting position for the first block
 * @param count size of the two arrays
 * @param sizes the sizes of the individual blocks
 * @param perm the permutation of the blocks (updated)
 */
static void
block_align (uint64_t start,
             unsigned int count, 
	     const uint64_t *sizes,
	     unsigned int *perm)
{
  unsigned int i;
  unsigned int j;
  unsigned int tmp;
  unsigned int best;
  int64_t badness;
  uint64_t cpos;
  uint64_t cend;
  int64_t cbad;
  unsigned int cval;

  cpos = start;
  for (i = 0; i < count; i++)
    {
      start = cpos;
      badness = 0x7FFFFFFF;
      best = -1;
      for (j = i; j < count; j++)
        {
          cval = perm[j];
          cend = cpos + sizes[cval];
          if (cpos % GNUNET_FS_DBLOCK_SIZE == 0)
            {
              /* prefer placing the largest blocks first */
              cbad = -(cend % GNUNET_FS_DBLOCK_SIZE);
            }
          else
            {
              if (cpos / GNUNET_FS_DBLOCK_SIZE ==
                  cend / GNUNET_FS_DBLOCK_SIZE)
                {
                  /* Data fits into the same block! Prefer small left-overs! */
                  cbad =
                    GNUNET_FS_DBLOCK_SIZE - cend % GNUNET_FS_DBLOCK_SIZE;
                }
              else
                {
                  /* Would have to waste space to re-align, add big factor, this
                     case is a real loss (proportional to space wasted)! */
                  cbad =
                    GNUNET_FS_DBLOCK_SIZE * (GNUNET_FS_DBLOCK_SIZE -
					     cpos %
					     GNUNET_FS_DBLOCK_SIZE);
                }
            }
          if (cbad < badness)
            {
              best = j;
              badness = cbad;
            }
        }
      tmp = perm[i];
      perm[i] = perm[best];
      perm[best] = tmp;
      cpos += sizes[perm[i]];
      cpos = do_align (start, cpos);
    }
}


/**
 * Create a directory.  We allow packing more than one variable
 * size entry into one block (and an entry could also span more
 * than one block), but an entry that is smaller than a single
 * block will never cross the block boundary.  This is done to
 * allow processing entries of a directory already even if the
 * download is still partial.<p>
 *
 * The first block begins with the directories MAGIC signature,
 * followed by the meta-data about the directory itself.<p>
 *
 * After that, the directory consists of block-aligned pairs
 * of URIs (0-terminated strings) and serialized meta-data.
 *
 * @param data pointer set to the beginning of the directory
 * @param len set to number of bytes in data
 * @param count number of entries in uris and mds
 * @param uris URIs of the files in the directory
 * @param mds meta-data for the files (must match
 *        respective values at same offset in in uris)
 * @param mdir meta-data for the directory
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_FS_directory_create (char **data,
			    size_t *len,
			    unsigned int count,
			    const struct GNUNET_FS_Uri **uris,
			    const struct GNUNET_CONTAINER_MetaData **mds,
			    const struct GNUNET_CONTAINER_MetaData *mdir)
{
  unsigned int i;
  unsigned int j;
  uint64_t psize;
  uint64_t size;
  uint64_t pos;
  char **ucs;
  int ret;
  uint64_t *sizes;
  unsigned int *perm;

  for (i = 0; i < count; i++)
    {
      if (GNUNET_FS_uri_test_ksk (fis[i].uri))
        {
          GNUNET_break (0);
          return GNUNET_SYSERR; /* illegal in directory! */
        }
    }
  ucs = GNUNET_malloc (sizeof (char *) * count);
  size = 8 + sizeof (unsigned int);
  size += GNUNET_meta_data_get_serialized_size (meta, GNUNET_SERIALIZE_FULL);
  sizes = GNUNET_malloc (count * sizeof (unsigned long long));
  perm = GNUNET_malloc (count * sizeof (int));
  for (i = 0; i < count; i++)
    {
      perm[i] = i;
      ucs[i] = GNUNET_FS_uri_to_string (fis[i].uri);
      GNUNET_assert (ucs[i] != NULL);
      psize =
        GNUNET_meta_data_get_serialized_size (fis[i].meta,
                                              GNUNET_SERIALIZE_FULL);
      if (psize == -1)
        {
          GNUNET_break (0);
          GNUNET_free (sizes);
          GNUNET_free (perm);
          while (i >= 0)
            GNUNET_free (ucs[i--]);
          GNUNET_free (ucs);
          return GNUNET_SYSERR;
        }
      sizes[i] = psize + sizeof (unsigned int) + strlen (ucs[i]) + 1;
    }
  /* permutate entries to minimize alignment cost */
  block_align (size, count, sizes, perm);

  /* compute final size with alignment */
  for (i = 0; i < count; i++)
    {
      psize = size;
      size += sizes[perm[i]];
      size = do_align (psize, size);
    }
  *len = size;
  *data = GNUNET_malloc (size);
  memset (*data, 0, size);

  pos = 8;
  memcpy (*data, GNUNET_DIRECTORY_MAGIC, 8);

  ret = GNUNET_CONTAINER_meta_data_serialize (meta,
					      &(*data)[pos +
						       sizeof (unsigned int)],
					      size - pos - sizeof (unsigned int),
					      GNUNET_SERIALIZE_FULL);
  GNUNET_assert (ret != GNUNET_SYSERR);
  ret = htonl (ret);
  memcpy (&(*data)[pos], &ret, sizeof (unsigned int));
  pos += ntohl (ret) + sizeof (unsigned int);

  for (j = 0; j < count; j++)
    {
      i = perm[j];
      psize = pos;
      pos += sizes[i];
      pos = do_align (psize, pos);
      pos -= sizes[i];          /* go back to beginning */
      memcpy (&(*data)[pos], ucs[i], strlen (ucs[i]) + 1);
      pos += strlen (ucs[i]) + 1;
      GNUNET_free (ucs[i]);
      ret = GNUNET_CONTAINER_meta_data_serialize (mds[i],
						  &(*data)[pos +
							   sizeof (unsigned int)],
						  size - pos -
						  sizeof (unsigned int),
						  GNUNET_SERIALIZE_FULL);
      GNUNET_assert (ret != GNUNET_SYSERR);
      ret = htonl (ret);
      memcpy (&(*data)[pos], &ret, sizeof (unsigned int));
      pos += ntohl (ret) + sizeof (unsigned int);
    }
  GNUNET_free (sizes);
  GNUNET_free (perm);
  GNUNET_free (ucs);
  GNUNET_assert (pos == size);
  return GNUNET_OK;
}


#endif 

/* end of fs_directory.c */
