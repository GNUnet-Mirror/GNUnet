/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * - location URI suppport (can wait, easy)
 * - different priority for scheduling probe downloads?
 * - check if iblocks can be computed from existing blocks (can wait, hard)
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_fs_service.h"
#include "fs.h"
#include "fs_tree.h"

#define DEBUG_DOWNLOAD GNUNET_NO

/**
 * Determine if the given download (options and meta data) should cause
 * use to try to do a recursive download.
 */
static int
is_recursive_download (struct GNUNET_FS_DownloadContext *dc)
{
  return  (0 != (dc->options & GNUNET_FS_DOWNLOAD_OPTION_RECURSIVE)) &&
    ( (GNUNET_YES == GNUNET_FS_meta_data_test_for_directory (dc->meta)) ||
      ( (dc->meta == NULL) &&
	( (NULL == dc->filename) ||	       
	  ( (strlen (dc->filename) >= strlen (GNUNET_FS_DIRECTORY_EXT)) &&
	    (NULL !=
	     strstr (dc->filename + strlen(dc->filename) - strlen(GNUNET_FS_DIRECTORY_EXT),
		     GNUNET_FS_DIRECTORY_EXT)) ) ) ) );		     
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
 * @param depth depth of the block in the tree
 * @param treedepth maximum depth of the tree
 * @return off for DBLOCKS (depth == treedepth),
 *         otherwise an offset past the end
 *         of the file that does not overlap
 *         with the range for any other block
 */
static uint64_t
compute_disk_offset (uint64_t fsize,
		     uint64_t off,
		     unsigned int depth,
		     unsigned int treedepth)
{
  unsigned int i;
  uint64_t lsize; /* what is the size of all IBlocks for depth "i"? */
  uint64_t loff; /* where do IBlocks for depth "i" start? */
  unsigned int ioff; /* which IBlock corresponds to "off" at depth "i"? */
  
  if (depth == treedepth)
    return off;
  /* first IBlocks start at the end of file, rounded up
     to full DBLOCK_SIZE */
  loff = ((fsize + DBLOCK_SIZE - 1) / DBLOCK_SIZE) * DBLOCK_SIZE;
  lsize = ( (fsize + DBLOCK_SIZE-1) / DBLOCK_SIZE) * sizeof (struct ContentHashKey);
  GNUNET_assert (0 == (off % DBLOCK_SIZE));
  ioff = (off / DBLOCK_SIZE);
  for (i=treedepth-1;i>depth;i--)
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
 * Given a file of the specified treedepth and a block at the given
 * offset and depth, calculate the offset for the CHK at the given
 * index.
 *
 * @param offset the offset of the first
 *        DBLOCK in the subtree of the 
 *        identified IBLOCK
 * @param depth the depth of the IBLOCK in the tree
 * @param treedepth overall depth of the tree
 * @param k which CHK in the IBLOCK are we 
 *        talking about
 * @return offset if k=0, otherwise an appropriately
 *         larger value (i.e., if depth = treedepth-1,
 *         the returned value should be offset+DBLOCK_SIZE)
 */
static uint64_t
compute_dblock_offset (uint64_t offset,
		       unsigned int depth,
		       unsigned int treedepth,
		       unsigned int k)
{
  unsigned int i;
  uint64_t lsize; /* what is the size of the sum of all DBlocks 
		     that a CHK at depth i corresponds to? */

  if (depth == treedepth)
    return offset;
  lsize = DBLOCK_SIZE;
  for (i=treedepth-1;i>depth;i--)
    lsize *= CHK_PER_INODE;
  return offset + k * lsize;
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
  pi->value.download.cctx
    = dc->client_info;
  pi->value.download.pctx
    = (dc->parent == NULL) ? NULL : dc->parent->client_info;
  pi->value.download.sctx
    = (dc->search == NULL) ? NULL : dc->search->client_info;
  pi->value.download.uri 
    = dc->uri;
  pi->value.download.filename
    = dc->filename;
  pi->value.download.size
    = dc->length;
  pi->value.download.duration
    = GNUNET_TIME_absolute_get_duration (dc->start_time);
  pi->value.download.completed
    = dc->completed;
  pi->value.download.anonymity
    = dc->anonymity;
  pi->value.download.eta
    = GNUNET_TIME_calculate_eta (dc->start_time,
				 dc->completed,
				 dc->length);
  if (0 == (dc->options & GNUNET_FS_DOWNLOAD_IS_PROBE))
    dc->client_info = dc->h->upcb (dc->h->upcb_cls,
				   pi);
  else
    dc->client_info = GNUNET_FS_search_probe_progress_ (NULL,
							pi);
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
			   void *buf);


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
process_result_with_request (void *cls,
			     const GNUNET_HashCode * key,
			     void *value);



/**
 * Schedule the download of the specified block in the tree.
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
  uint64_t total;
  uint64_t off;
  size_t len;
  char block[DBLOCK_SIZE];
  GNUNET_HashCode key;
  struct ProcessResultClosure prc;
  struct GNUNET_DISK_FileHandle *fh;

#if DEBUG_DOWNLOAD
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Scheduling download at offset %llu and depth %u for `%s'\n",
	      (unsigned long long) offset,
	      depth,
	      GNUNET_h2s (&chk->query));
#endif
  total = GNUNET_ntohll (dc->uri->data.chk.file_length);
  off = compute_disk_offset (total,
			     offset,
			     depth,
			     dc->treedepth);
  len = GNUNET_FS_tree_calculate_block_size (total,
					     dc->treedepth,
					     offset,
					     depth);
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
  fh = NULL;
  if ( (dc->old_file_size > off) &&
       (dc->filename != NULL) )    
    fh = GNUNET_DISK_file_open (dc->filename,
				GNUNET_DISK_OPEN_READ,
				GNUNET_DISK_PERM_NONE);    
  if ( (fh != NULL) &&
       (off  == 
	GNUNET_DISK_file_seek (fh,
			       off,
			       GNUNET_DISK_SEEK_SET) ) &&
       (len == 
	GNUNET_DISK_file_read (fh,
			       block,
			       len)) )
    {
      GNUNET_CRYPTO_hash (block, len, &key);
      if (0 == memcmp (&key,
		       &chk->key,
		       sizeof (GNUNET_HashCode)))
	{
	  char enc[len];
	  struct GNUNET_CRYPTO_AesSessionKey sk;
	  struct GNUNET_CRYPTO_AesInitializationVector iv;
	  GNUNET_HashCode query;

	  GNUNET_CRYPTO_hash_to_aes_key (&key, &sk, &iv);
	  GNUNET_CRYPTO_aes_encrypt (block, len,
				     &sk,
				     &iv,
				     enc);
	  GNUNET_CRYPTO_hash (enc, len, &query);
	  if (0 == memcmp (&query,
			   &chk->query,
			   sizeof (GNUNET_HashCode)))
	    {
	      /* already got it! */
	      prc.dc = dc;
	      prc.data = enc;
	      prc.size = len;
	      prc.type = (dc->treedepth == depth) 
		? GNUNET_BLOCK_TYPE_DBLOCK 
		: GNUNET_BLOCK_TYPE_IBLOCK;
	      prc.query = chk->query;
	      prc.do_store = GNUNET_NO; /* useless */
	      process_result_with_request (&prc,
					   &key,
					   sm);
	    }
	  else
	    {
	      GNUNET_break_op (0);
	    }
	  GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fh));
	  return;
	}
    }
  if (fh != NULL)
    GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fh));
  if (depth < dc->treedepth)
    {
      // FIXME: try if we could
      // reconstitute this IBLOCK
      // from the existing blocks on disk (can wait)
      // (read block(s), encode, compare with
      // query; if matches, simply return)
    }

  if ( (dc->th == NULL) &&
       (dc->client != NULL) )
    dc->th = GNUNET_CLIENT_notify_transmit_ready (dc->client,
						  sizeof (struct SearchMessage),
						  GNUNET_CONSTANTS_SERVICE_TIMEOUT,
						  GNUNET_NO,
						  &transmit_download_request,
						  dc);
}



/**
 * Suggest a filename based on given metadata.
 * 
 * @param md given meta data
 * @return NULL if meta data is useless for suggesting a filename
 */
char *
GNUNET_FS_meta_data_suggest_filename (const struct GNUNET_CONTAINER_MetaData *md)
{
  static const char *mimeMap[][2] = {
    {"application/bz2", ".bz2"},
    {"application/gnunet-directory", ".gnd"},
    {"application/java", ".class"},
    {"application/msword", ".doc"},
    {"application/ogg", ".ogg"},
    {"application/pdf", ".pdf"},
    {"application/pgp-keys", ".key"},
    {"application/pgp-signature", ".pgp"},
    {"application/postscript", ".ps"},
    {"application/rar", ".rar"},
    {"application/rtf", ".rtf"},
    {"application/xml", ".xml"},
    {"application/x-debian-package", ".deb"},
    {"application/x-dvi", ".dvi"},
    {"applixation/x-flac", ".flac"},
    {"applixation/x-gzip", ".gz"},
    {"application/x-java-archive", ".jar"},
    {"application/x-java-vm", ".class"},
    {"application/x-python-code", ".pyc"},
    {"application/x-redhat-package-manager", ".rpm"},
    {"application/x-rpm", ".rpm"},
    {"application/x-tar", ".tar"},
    {"application/x-tex-pk", ".pk"},
    {"application/x-texinfo", ".texinfo"},
    {"application/x-xcf", ".xcf"},
    {"application/x-xfig", ".xfig"},
    {"application/zip", ".zip"},
    
    {"audio/midi", ".midi"},
    {"audio/mpeg", ".mp3"},
    {"audio/real", ".rm"},
    {"audio/x-wav", ".wav"},
    
    {"image/gif", ".gif"},
    {"image/jpeg", ".jpg"},
    {"image/pcx", ".pcx"},
    {"image/png", ".png"},
    {"image/tiff", ".tiff"},
    {"image/x-ms-bmp", ".bmp"},
    {"image/x-xpixmap", ".xpm"},
    
    {"text/css", ".css"},
    {"text/html", ".html"},
    {"text/plain", ".txt"},
    {"text/rtf", ".rtf"},
    {"text/x-c++hdr", ".h++"},
    {"text/x-c++src", ".c++"},
    {"text/x-chdr", ".h"},
    {"text/x-csrc", ".c"},
    {"text/x-java", ".java"},
    {"text/x-moc", ".moc"},
    {"text/x-pascal", ".pas"},
    {"text/x-perl", ".pl"},
    {"text/x-python", ".py"},
    {"text/x-tex", ".tex"},
    
    {"video/avi", ".avi"},
    {"video/mpeg", ".mpeg"},
    {"video/quicktime", ".qt"},
    {"video/real", ".rm"},
    {"video/x-msvideo", ".avi"},
    {NULL, NULL},
  };
  char *ret;
  unsigned int i;
  char *mime;
  char *base;
  const char *ext;

  ret = GNUNET_CONTAINER_meta_data_get_by_type (md,
						EXTRACTOR_METATYPE_FILENAME);
  if (ret != NULL)
    return ret;  
  ext = NULL;
  mime = GNUNET_CONTAINER_meta_data_get_by_type (md,
						 EXTRACTOR_METATYPE_MIMETYPE);
  if (mime != NULL)
    {
      i = 0;
      while ( (mimeMap[i][0] != NULL) && 
	      (0 != strcmp (mime, mimeMap[i][0])))
        i++;
      if (mimeMap[i][1] == NULL)
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | 
		    GNUNET_ERROR_TYPE_BULK,
		    _("Did not find mime type `%s' in extension list.\n"),
		    mime);
      else
	ext = mimeMap[i][1];
      GNUNET_free (mime);
    }
  base = GNUNET_CONTAINER_meta_data_get_first_by_types (md,
							EXTRACTOR_METATYPE_TITLE,
							EXTRACTOR_METATYPE_BOOK_TITLE,
							EXTRACTOR_METATYPE_ORIGINAL_TITLE,
							EXTRACTOR_METATYPE_PACKAGE_NAME,
							EXTRACTOR_METATYPE_URL,
							EXTRACTOR_METATYPE_URI, 
							EXTRACTOR_METATYPE_DESCRIPTION,
							EXTRACTOR_METATYPE_ISRC,
							EXTRACTOR_METATYPE_JOURNAL_NAME,
							EXTRACTOR_METATYPE_AUTHOR_NAME,
							EXTRACTOR_METATYPE_SUBJECT,
							EXTRACTOR_METATYPE_ALBUM,
							EXTRACTOR_METATYPE_ARTIST,
							EXTRACTOR_METATYPE_KEYWORDS,
							EXTRACTOR_METATYPE_COMMENT,
							EXTRACTOR_METATYPE_UNKNOWN,
							-1);
  if ( (base == NULL) &&
       (ext == NULL) )
    return NULL;
  if (base == NULL)
    return GNUNET_strdup (ext);
  if (ext == NULL)
    return base;
  GNUNET_asprintf (&ret,
		   "%s%s",
		   base,
		   ext);
  GNUNET_free (base);
  return ret;
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
trigger_recursive_download (void *cls,
			    const char *filename,
			    const struct GNUNET_FS_Uri *uri,
			    const struct GNUNET_CONTAINER_MetaData *meta,
			    size_t length,
			    const void *data);


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
		  _("Recursive downloads of directories larger than 4 GB are not supported on 32-bit systems\n"));
      return;
    }
  if (dc->filename != NULL)
    {
      h = GNUNET_DISK_file_open (dc->filename,
				 GNUNET_DISK_OPEN_READ,
				 GNUNET_DISK_PERM_NONE);
    }
  else
    {
      GNUNET_assert (dc->temp_filename != NULL);
      h = GNUNET_DISK_file_open (dc->temp_filename,
				 GNUNET_DISK_OPEN_READ,
				 GNUNET_DISK_PERM_NONE);
    }
  if (h == NULL)
    return; /* oops */
  data = GNUNET_DISK_file_map (h, &m, GNUNET_DISK_MAP_TYPE_READ, size);
  if (data == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Directory too large for system address space\n"));
    }
  else
    {
      GNUNET_FS_directory_list_contents (size,
					 data,
					 0,
					 &trigger_recursive_download,
					 dc);         
      GNUNET_DISK_file_unmap (m);
    }
  GNUNET_DISK_file_close (h);
  if (dc->filename == NULL)
    {
      if (0 != UNLINK (dc->temp_filename))
	GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
				  "unlink",
				  dc->temp_filename);
      GNUNET_free (dc->temp_filename);
      dc->temp_filename = NULL;
    }
}


/**
 * Check if all child-downloads have completed and
 * if so, signal completion (and possibly recurse to
 * parent).
 */
static void
check_completed (struct GNUNET_FS_DownloadContext *dc)
{
  struct GNUNET_FS_ProgressInfo pi;
  struct GNUNET_FS_DownloadContext *pos;

  pos = dc->child_head;
  while (pos != NULL)
    {
      if ( (pos->emsg == NULL) &&
	   (pos->completed < pos->length) )
	return; /* not done yet */
      if ( (pos->child_head != NULL) &&
	   (pos->has_finished != GNUNET_YES) )
	return; /* not transitively done yet */
      pos = pos->next;
    }
  dc->has_finished = GNUNET_YES;
  GNUNET_FS_download_sync_ (dc);
  /* signal completion */
  pi.status = GNUNET_FS_STATUS_DOWNLOAD_COMPLETED;
  GNUNET_FS_download_make_status_ (&pi, dc);
  if (dc->parent != NULL)
    check_completed (dc->parent);  
}


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
trigger_recursive_download (void *cls,
			    const char *filename,
			    const struct GNUNET_FS_Uri *uri,
			    const struct GNUNET_CONTAINER_MetaData *meta,
			    size_t length,
			    const void *data)
{
  struct GNUNET_FS_DownloadContext *dc = cls;  
  struct GNUNET_FS_DownloadContext *cpos;
  struct GNUNET_DISK_FileHandle *fh;
  char *temp_name;
  const char *real_name;
  char *fn;
  char *us;
  char *ext;
  char *dn;
  char *full_name;

  if (NULL == uri)
    return; /* entry for the directory itself */
  cpos = dc->child_head;
  while (cpos != NULL)
    {
      if ( (GNUNET_FS_uri_test_equal (uri,
				      cpos->uri)) ||
	   ( (filename != NULL) &&
	     (0 == strcmp (cpos->filename,
			   filename)) ) )
	break;	
      cpos = cpos->next;
    }
  if (cpos != NULL)
    return; /* already exists */
  fn = NULL;
  if (NULL == filename)
    {
      fn = GNUNET_FS_meta_data_suggest_filename (meta);      
      if (fn == NULL)
	{
	  us = GNUNET_FS_uri_to_string (uri);
	  fn = GNUNET_strdup (&us [strlen (GNUNET_FS_URI_PREFIX 
					   GNUNET_FS_URI_CHK_INFIX)]);
	  GNUNET_free (us);
	}
      else if (fn[0] == '.')
	{
	  ext = fn;
	  us = GNUNET_FS_uri_to_string (uri);
	  GNUNET_asprintf (&fn,
			   "%s%s",
			   &us[strlen (GNUNET_FS_URI_PREFIX 
				       GNUNET_FS_URI_CHK_INFIX)], ext);
	  GNUNET_free (ext);
	  GNUNET_free (us);
	}
      filename = fn;
    }
  if (dc->filename == NULL)
    {
      full_name = NULL;
    }
  else
    {
      dn = GNUNET_strdup (dc->filename);
      GNUNET_break ( (strlen (dn) >= strlen (GNUNET_FS_DIRECTORY_EXT)) &&
		     (NULL !=
		      strstr (dn + strlen(dn) - strlen(GNUNET_FS_DIRECTORY_EXT),
			      GNUNET_FS_DIRECTORY_EXT)) );
      if ( (strlen (dn) >= strlen (GNUNET_FS_DIRECTORY_EXT)) &&
	   (NULL !=
	    strstr (dn + strlen(dn) - strlen(GNUNET_FS_DIRECTORY_EXT),
		    GNUNET_FS_DIRECTORY_EXT)) )      
	dn[strlen(dn) - strlen (GNUNET_FS_DIRECTORY_EXT)] = '\0';      
      if ( (GNUNET_YES == GNUNET_FS_meta_data_test_for_directory (meta)) &&
	   ( (strlen (filename) < strlen (GNUNET_FS_DIRECTORY_EXT)) ||
	     (NULL ==
	      strstr (filename + strlen(filename) - strlen(GNUNET_FS_DIRECTORY_EXT),
		      GNUNET_FS_DIRECTORY_EXT)) ) )
	{
	  GNUNET_asprintf (&full_name,
			   "%s%s%s%s",
			   dn,
			   DIR_SEPARATOR_STR,
			   filename,
			   GNUNET_FS_DIRECTORY_EXT);
	}
      else
	{
	  GNUNET_asprintf (&full_name,
			   "%s%s%s",
			   dn,
			   DIR_SEPARATOR_STR,
			   filename);
	}
      GNUNET_free (dn);
    }
  if ( (full_name != NULL) &&
       (GNUNET_OK !=
	GNUNET_DISK_directory_create_for_file (full_name)) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to create directory for recursive download of `%s'\n"),
		  full_name);
      GNUNET_free (full_name);
      GNUNET_free_non_null (fn);
      return;
    }

  temp_name = NULL;
  if ( (data != NULL) &&
       (GNUNET_FS_uri_chk_get_file_size (uri) == length) )
    {
      if (full_name == NULL)
	{
	  temp_name = GNUNET_DISK_mktemp ("gnunet-directory-download-tmp");
	  real_name = temp_name;
	}
      else
	{
	  real_name = full_name;
	}
      /* write to disk, then trigger normal download which will instantly progress to completion */
      fh = GNUNET_DISK_file_open (real_name,
				  GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_TRUNCATE | GNUNET_DISK_OPEN_CREATE,
				  GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
      if (fh == NULL)
	{
	  GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
				    "open",
				    real_name);	      
	  GNUNET_free (full_name);
	  GNUNET_free_non_null (fn);
	  return;
	}
      if (length != 
	  GNUNET_DISK_file_write (fh,
				  data,
				  length))
	{
	  GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
				    "write",
				    full_name);	      
	}
      GNUNET_DISK_file_close (fh);
    }
  GNUNET_FS_download_start (dc->h,
			    uri,
			    meta,
			    full_name, temp_name,
			    0,
			    GNUNET_FS_uri_chk_get_file_size (uri),
			    dc->anonymity,
			    dc->options,
			    NULL,
			    dc);
  GNUNET_free_non_null (full_name);
  GNUNET_free_non_null (temp_name);
  GNUNET_free_non_null (fn);
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
 * Iterator over entries in the pending requests in the 'active' map for the
 * reply that we just got.
 *
 * @param cls closure (our 'struct ProcessResultClosure')
 * @param key query for the given value / request
 * @param value value in the hash map (a 'struct DownloadRequest')
 * @return GNUNET_YES (we should continue to iterate); unless serious error
 */
static int
process_result_with_request (void *cls,
			     const GNUNET_HashCode * key,
			     void *value)
{
  struct ProcessResultClosure *prc = cls;
  struct DownloadRequest *sm = value;
  struct DownloadRequest *ppos;
  struct DownloadRequest *pprev;
  struct GNUNET_DISK_FileHandle *fh;
  struct GNUNET_FS_DownloadContext *dc = prc->dc;
  struct GNUNET_CRYPTO_AesSessionKey skey;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  char pt[prc->size];
  struct GNUNET_FS_ProgressInfo pi;
  uint64_t off;
  size_t bs;
  size_t app;
  int i;
  struct ContentHashKey *chk;

  fh = NULL;
  bs = GNUNET_FS_tree_calculate_block_size (GNUNET_ntohll (dc->uri->data.chk.file_length),
					    dc->treedepth,
					    sm->offset,
					    sm->depth);
  if (prc->size != bs)
    {
#if DEBUG_DOWNLOAD
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Internal error or bogus download URI (expected %u bytes, got %u)\n",
		  bs,
		  prc->size);
#endif
      dc->emsg = GNUNET_strdup ("Internal error or bogus download URI");
      goto signal_error;
    }
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (dc->active,
						       &prc->query,
						       sm));
  /* if this request is on the pending list, remove it! */
  pprev = NULL;
  ppos = dc->pending;
  while (ppos != NULL)
    {
      if (ppos == sm)
	{
	  if (pprev == NULL)
	    dc->pending = ppos->next;
	  else
	    pprev->next = ppos->next;
	  break;
	}
      pprev = ppos;
      ppos = ppos->next;
    }
  GNUNET_CRYPTO_hash_to_aes_key (&sm->chk.key, &skey, &iv);
  GNUNET_CRYPTO_aes_decrypt (prc->data,
			     prc->size,
			     &skey,
			     &iv,
			     pt);
  off = compute_disk_offset (GNUNET_ntohll (dc->uri->data.chk.file_length),
			     sm->offset,
			     sm->depth,
			     dc->treedepth);
  /* save to disk */
  if ( ( GNUNET_YES == prc->do_store) &&
       ( (dc->filename != NULL) ||
	 (is_recursive_download (dc)) ) &&
       ( (sm->depth == dc->treedepth) ||
	 (0 == (dc->options & GNUNET_FS_DOWNLOAD_NO_TEMPORARIES)) ) )
    {
      fh = GNUNET_DISK_file_open (dc->filename != NULL 
				  ? dc->filename 
				  : dc->temp_filename, 
				  GNUNET_DISK_OPEN_READWRITE | 
				  GNUNET_DISK_OPEN_CREATE,
				  GNUNET_DISK_PERM_USER_READ |
				  GNUNET_DISK_PERM_USER_WRITE |
				  GNUNET_DISK_PERM_GROUP_READ |
				  GNUNET_DISK_PERM_OTHER_READ);
    }
  if ( (NULL == fh) &&
       (GNUNET_YES == prc->do_store) &&
       ( (dc->filename != NULL) ||
	 (is_recursive_download (dc)) ) &&
       ( (sm->depth == dc->treedepth) ||
	 (0 == (dc->options & GNUNET_FS_DOWNLOAD_NO_TEMPORARIES)) ) )
    {
      GNUNET_asprintf (&dc->emsg,
		       _("Download failed: could not open file `%s': %s\n"),
		       dc->filename,
		       STRERROR (errno));
      goto signal_error;
    }
  if (fh != NULL)
    {
#if DEBUG_DOWNLOAD
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Saving decrypted block to disk at offset %llu\n",
		  (unsigned long long) off);
#endif
      if ( (off  != 
	    GNUNET_DISK_file_seek (fh,
				   off,
				   GNUNET_DISK_SEEK_SET) ) )
	{
	  GNUNET_asprintf (&dc->emsg,
			   _("Failed to seek to offset %llu in file `%s': %s\n"),
			   (unsigned long long) off,
			   dc->filename,
			   STRERROR (errno));
	  goto signal_error;
	}
      if (prc->size !=
	  GNUNET_DISK_file_write (fh,
				  pt,
				  prc->size))
	{
	  GNUNET_asprintf (&dc->emsg,
			   _("Failed to write block of %u bytes at offset %llu in file `%s': %s\n"),
			   (unsigned int) prc->size,
			   (unsigned long long) off,
			   dc->filename,
			   STRERROR (errno));
	  goto signal_error;
	}
      GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fh));
      fh = NULL;
    }
  if (sm->depth == dc->treedepth) 
    {
      app = prc->size;
      if (sm->offset < dc->offset)
	{
	  /* starting offset begins in the middle of pt,
	     do not count first bytes as progress */
	  GNUNET_assert (app > (dc->offset - sm->offset));
	  app -= (dc->offset - sm->offset);	  
	}
      if (sm->offset + prc->size > dc->offset + dc->length)
	{
	  /* end of block is after relevant range,
	     do not count last bytes as progress */
	  GNUNET_assert (app > (sm->offset + prc->size) - (dc->offset + dc->length));
	  app -= (sm->offset + prc->size) - (dc->offset + dc->length);
	}
      dc->completed += app;

      /* do recursive download if option is set and either meta data
	 says it is a directory or if no meta data is given AND filename 
	 ends in '.gnd' (top-level case) */
      if (is_recursive_download (dc))
	GNUNET_FS_directory_list_contents (prc->size,
					   pt,
					   off,
					   &trigger_recursive_download,
					   dc);         
	    
    }
  pi.status = GNUNET_FS_STATUS_DOWNLOAD_PROGRESS;
  pi.value.download.specifics.progress.data = pt;
  pi.value.download.specifics.progress.offset = sm->offset;
  pi.value.download.specifics.progress.data_len = prc->size;
  pi.value.download.specifics.progress.depth = sm->depth;
  GNUNET_FS_download_make_status_ (&pi, dc);
  GNUNET_assert (dc->completed <= dc->length);
  if (dc->completed == dc->length)
    {
#if DEBUG_DOWNLOAD
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Download completed, truncating file to desired length %llu\n",
		  (unsigned long long) GNUNET_ntohll (dc->uri->data.chk.file_length));
#endif
      /* truncate file to size (since we store IBlocks at the end) */
      if (dc->filename != NULL)
	{
	  if (0 != truncate (dc->filename,
			     GNUNET_ntohll (dc->uri->data.chk.file_length)))
	    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
				      "truncate",
				      dc->filename);
	}
      if (dc->job_queue != NULL)
	{
	  GNUNET_FS_dequeue_ (dc->job_queue);
	  dc->job_queue = NULL;
	}
      if (is_recursive_download (dc))
	full_recursive_download (dc);
      if (dc->child_head == NULL)
	{
	  /* signal completion */
	  pi.status = GNUNET_FS_STATUS_DOWNLOAD_COMPLETED;
	  GNUNET_FS_download_make_status_ (&pi, dc);
	  if (dc->parent != NULL)
	    check_completed (dc->parent);
	}
      GNUNET_assert (sm->depth == dc->treedepth);
    }
  if (sm->depth == dc->treedepth) 
    {
      GNUNET_FS_download_sync_ (dc);
      GNUNET_free (sm);      
      return GNUNET_YES;
    }
#if DEBUG_DOWNLOAD
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Triggering downloads of children (this block was at depth %u and offset %llu)\n",
	      sm->depth,
	      (unsigned long long) sm->offset);
#endif
  GNUNET_assert (0 == (prc->size % sizeof(struct ContentHashKey)));
  chk = (struct ContentHashKey*) pt;
  for (i=(prc->size / sizeof(struct ContentHashKey))-1;i>=0;i--)
    {
      off = compute_dblock_offset (sm->offset,
				   sm->depth,
				   dc->treedepth,
				   i);
      if ( (off + DBLOCK_SIZE >= dc->offset) &&
	   (off < dc->offset + dc->length) ) 
	schedule_block_download (dc,
				 &chk[i],
				 off,
				 sm->depth + 1);
    }
  GNUNET_free (sm);
  GNUNET_FS_download_sync_ (dc);
  return GNUNET_YES;

 signal_error:
  if (fh != NULL)
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
  GNUNET_CLIENT_disconnect (dc->client, GNUNET_NO);
  GNUNET_CONTAINER_multihashmap_iterate (dc->active,
					 &free_entry,
					 NULL);
  dc->pending = NULL;
  dc->client = NULL;
  GNUNET_free (sm);
  GNUNET_FS_download_sync_ (dc);
  return GNUNET_NO;
}


/**
 * Process a download result.
 *
 * @param dc our download context
 * @param type type of the result
 * @param data the (encrypted) response
 * @param size size of data
 */
static void
process_result (struct GNUNET_FS_DownloadContext *dc,
		enum GNUNET_BLOCK_Type type,
		const void *data,
		size_t size)
{
  struct ProcessResultClosure prc;

  prc.dc = dc;
  prc.data = data;
  prc.size = size;
  prc.type = type;
  prc.do_store = GNUNET_YES;
  GNUNET_CRYPTO_hash (data, size, &prc.query);
#if DEBUG_DOWNLOAD
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received result for query `%s' from `%s'-service\n",
	      GNUNET_h2s (&prc.query),
	      "FS");
#endif
  GNUNET_CONTAINER_multihashmap_get_multiple (dc->active,
					      &prc.query,
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
receive_results (void *cls,
		 const struct GNUNET_MessageHeader * msg)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  const struct PutMessage *cm;
  uint16_t msize;

  if ( (NULL == msg) ||
       (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_FS_PUT) ||
       (sizeof (struct PutMessage) > ntohs(msg->size)) )
    {
      GNUNET_break (msg == NULL);	
      try_reconnect (dc);
      return;
    }
  msize = ntohs(msg->size);
  cm = (const struct PutMessage*) msg;
  process_result (dc, 
		  ntohl (cm->type),
		  &cm[1],
		  msize - sizeof (struct PutMessage));
  if (dc->client == NULL)
    return; /* fatal error */
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

  dc->th = NULL;
  if (NULL == buf)
    {
      try_reconnect (dc);
      return 0;
    }
  GNUNET_assert (size >= sizeof (struct SearchMessage));
  msize = 0;
  sm = buf;
  while ( (dc->pending != NULL) &&
	  (size > msize + sizeof (struct SearchMessage)) )
    {
#if DEBUG_DOWNLOAD
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Transmitting download request for `%s' to `%s'-service\n",
		  GNUNET_h2s (&dc->pending->chk.query),
		  "FS");
#endif
      memset (sm, 0, sizeof (struct SearchMessage));
      sm->header.size = htons (sizeof (struct SearchMessage));
      sm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_START_SEARCH);
      if (0 != (dc->options & GNUNET_FS_DOWNLOAD_OPTION_LOOPBACK_ONLY))
	sm->options = htonl (1);
      else
	sm->options = htonl (0);      
      if (dc->pending->depth == dc->treedepth)
	sm->type = htonl (GNUNET_BLOCK_TYPE_DBLOCK);
      else
	sm->type = htonl (GNUNET_BLOCK_TYPE_IBLOCK);
      sm->anonymity_level = htonl (dc->anonymity);
      sm->target = dc->target.hashPubKey;
      sm->query = dc->pending->chk.query;
      dc->pending->is_pending = GNUNET_NO;
      dc->pending = dc->pending->next;
      msize += sizeof (struct SearchMessage);
      sm++;
    }
  if (dc->pending != NULL)
    dc->th = GNUNET_CLIENT_notify_transmit_ready (dc->client,
						  sizeof (struct SearchMessage),
						  GNUNET_CONSTANTS_SERVICE_TIMEOUT,
						  GNUNET_NO,
						  &transmit_download_request,
						  dc); 
  return msize;
}


/**
 * Reconnect to the FS service and transmit our queries NOW.
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
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  "Connecting to `%s'-service failed, will try again.\n",
		  "FS");
      try_reconnect (dc);
      return;
    }
  dc->client = client;
  dc->th = GNUNET_CLIENT_notify_transmit_ready (client,
						sizeof (struct SearchMessage),
						GNUNET_CONSTANTS_SERVICE_TIMEOUT,
						GNUNET_NO,
						&transmit_download_request,
						dc);  
  GNUNET_CLIENT_receive (client,
			 &receive_results,
			 dc,
			 GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Add entries that are not yet pending back to the pending list.
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
      if (NULL != dc->th)
	{
	  GNUNET_CLIENT_notify_transmit_ready_cancel (dc->th);
	  dc->th = NULL;
	}
      GNUNET_CONTAINER_multihashmap_iterate (dc->active,
					     &retry_entry,
					     dc);
      GNUNET_CLIENT_disconnect (dc->client, GNUNET_NO);
      dc->client = NULL;
    }
  dc->task
    = GNUNET_SCHEDULER_add_delayed (dc->h->sched,
				    GNUNET_TIME_UNIT_SECONDS,
				    &do_reconnect,
				    dc);
}



/**
 * We're allowed to ask the FS service for our blocks.  Start the download.
 *
 * @param cls the 'struct GNUNET_FS_DownloadContext'
 * @param client handle to use for communcation with FS (we must destroy it!)
 */
static void
activate_fs_download (void *cls,
		      struct GNUNET_CLIENT_Connection *client)
{
  struct GNUNET_FS_DownloadContext *dc = cls;
  struct GNUNET_FS_ProgressInfo pi;

  GNUNET_assert (NULL != client);
  dc->client = client;
  GNUNET_CLIENT_receive (client,
			 &receive_results,
			 dc,
			 GNUNET_TIME_UNIT_FOREVER_REL);
  pi.status = GNUNET_FS_STATUS_DOWNLOAD_ACTIVE;
  GNUNET_FS_download_make_status_ (&pi, dc);
  GNUNET_CONTAINER_multihashmap_iterate (dc->active,
					 &retry_entry,
					 dc);
  if ( (dc->th == NULL) &&
       (dc->client != NULL) )
    dc->th = GNUNET_CLIENT_notify_transmit_ready (dc->client,
						  sizeof (struct SearchMessage),
						  GNUNET_CONSTANTS_SERVICE_TIMEOUT,
						  GNUNET_NO,
						  &transmit_download_request,
						  dc);
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
  
  if (NULL != dc->th)
    {
      GNUNET_CLIENT_notify_transmit_ready_cancel (dc->th);
      dc->th = NULL;
    }
  if (NULL != dc->client)
    {
      GNUNET_CLIENT_disconnect (dc->client, GNUNET_NO);
      dc->client = NULL;
    }
  pi.status = GNUNET_FS_STATUS_DOWNLOAD_INACTIVE;
  GNUNET_FS_download_make_status_ (&pi, dc);
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
  
  if (dc->top != NULL)
    GNUNET_FS_end_top (dc->h, dc->top);
  while (NULL != dc->child_head)
    GNUNET_FS_download_signal_suspend_ (dc->child_head);  
  if (dc->search != NULL)
    {
      dc->search->download = NULL;
      dc->search = NULL;
    }
  if (dc->job_queue != NULL)
    {
      GNUNET_FS_dequeue_ (dc->job_queue);
      dc->job_queue = NULL;
    }
  if (dc->parent != NULL)
    GNUNET_CONTAINER_DLL_remove (dc->parent->child_head,
				 dc->parent->child_tail,
				 dc);  
  pi.status = GNUNET_FS_STATUS_DOWNLOAD_SUSPEND;
  GNUNET_FS_download_make_status_ (&pi, dc);
  if (GNUNET_SCHEDULER_NO_TASK != dc->task)
    GNUNET_SCHEDULER_cancel (dc->h->sched,
			     dc->task);
  GNUNET_CONTAINER_multihashmap_iterate (dc->active,
					 &free_entry,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (dc->active);
  GNUNET_free_non_null (dc->filename);
  GNUNET_CONTAINER_meta_data_destroy (dc->meta);
  GNUNET_FS_uri_destroy (dc->uri);
  GNUNET_free_non_null (dc->temp_filename);
  GNUNET_free_non_null (dc->serialization);
  GNUNET_free (dc);
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
			  const char *filename,
			  const char *tempname,
			  uint64_t offset,
			  uint64_t length,
			  uint32_t anonymity,
			  enum GNUNET_FS_DownloadOptions options,
			  void *cctx,
			  struct GNUNET_FS_DownloadContext *parent)
{
  struct GNUNET_FS_ProgressInfo pi;
  struct GNUNET_FS_DownloadContext *dc;

  GNUNET_assert (GNUNET_FS_uri_test_chk (uri));
  if ( (offset + length < offset) ||
       (offset + length > uri->data.chk.file_length) )
    {      
      GNUNET_break (0);
      return NULL;
    }
#if DEBUG_DOWNLOAD
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting download `%s' of %llu bytes\n",
	      filename,
	      (unsigned long long) length);
#endif
  dc = GNUNET_malloc (sizeof(struct GNUNET_FS_DownloadContext));
  dc->h = h;
  dc->parent = parent;
  if (parent != NULL)
    {
      GNUNET_CONTAINER_DLL_insert (parent->child_head,
				   parent->child_tail,
				   dc);
    }
  dc->uri = GNUNET_FS_uri_dup (uri);
  dc->meta = GNUNET_CONTAINER_meta_data_duplicate (meta);
  dc->client_info = cctx;
  dc->start_time = GNUNET_TIME_absolute_get ();
  if (NULL != filename)
    {
      dc->filename = GNUNET_strdup (filename);
      if (GNUNET_YES == GNUNET_DISK_file_test (filename))
	GNUNET_DISK_file_size (filename,
			       &dc->old_file_size,
			       GNUNET_YES);
    }
  if (GNUNET_FS_uri_test_loc (dc->uri))
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_FS_uri_loc_get_peer_identity (dc->uri,
							&dc->target));
  dc->offset = offset;
  dc->length = length;
  dc->anonymity = anonymity;
  dc->options = options;
  dc->active = GNUNET_CONTAINER_multihashmap_create (1 + 2 * (length / DBLOCK_SIZE));
  dc->treedepth = GNUNET_FS_compute_depth (GNUNET_ntohll(dc->uri->data.chk.file_length));
  if ( (filename == NULL) &&
       (is_recursive_download (dc) ) )
    {
      if (tempname != NULL)
	dc->temp_filename = GNUNET_strdup (tempname);
      else
	dc->temp_filename = GNUNET_DISK_mktemp ("gnunet-directory-download-tmp");    
    }

#if DEBUG_DOWNLOAD
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Download tree has depth %u\n",
	      dc->treedepth);
#endif
  if (parent == NULL)
    dc->top = GNUNET_FS_make_top (dc->h,
				  &GNUNET_FS_download_signal_suspend_,
				  dc);
  pi.status = GNUNET_FS_STATUS_DOWNLOAD_START;
  pi.value.download.specifics.start.meta = meta;
  GNUNET_FS_download_make_status_ (&pi, dc);
  schedule_block_download (dc, 
			   &dc->uri->data.chk.chk,
			   0, 
			   1 /* 0 == CHK, 1 == top */); 
  GNUNET_FS_download_sync_ (dc);
  GNUNET_FS_download_start_downloading_ (dc);
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
				      const char *tempname,
				      uint64_t offset,
				      uint64_t length,
				      uint32_t anonymity,
				      enum GNUNET_FS_DownloadOptions options,
				      void *cctx)
{
  struct GNUNET_FS_ProgressInfo pi;
  struct GNUNET_FS_DownloadContext *dc;

  if (sr->download != NULL)
    {
      GNUNET_break (0);
      return NULL;
    }
  GNUNET_assert (GNUNET_FS_uri_test_chk (sr->uri));
  if ( (offset + length < offset) ||
       (offset + length > sr->uri->data.chk.file_length) )
    {      
      GNUNET_break (0);
      return NULL;
    }
#if DEBUG_DOWNLOAD
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting download `%s' of %llu bytes\n",
	      filename,
	      (unsigned long long) length);
#endif
  dc = GNUNET_malloc (sizeof(struct GNUNET_FS_DownloadContext));
  dc->h = h;
  dc->search = sr;
  sr->download = dc;
  if (sr->probe_ctx != NULL)
    {
      GNUNET_FS_download_stop (sr->probe_ctx, GNUNET_YES);
      sr->probe_ctx = NULL;      
    }
  dc->uri = GNUNET_FS_uri_dup (sr->uri);
  dc->meta = GNUNET_CONTAINER_meta_data_duplicate (sr->meta);
  dc->client_info = cctx;
  dc->start_time = GNUNET_TIME_absolute_get ();
  if (NULL != filename)
    {
      dc->filename = GNUNET_strdup (filename);
      if (GNUNET_YES == GNUNET_DISK_file_test (filename))
	GNUNET_DISK_file_size (filename,
			       &dc->old_file_size,
			       GNUNET_YES);
    }
  if (GNUNET_FS_uri_test_loc (dc->uri))
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_FS_uri_loc_get_peer_identity (dc->uri,
							&dc->target));
  dc->offset = offset;
  dc->length = length;
  dc->anonymity = anonymity;
  dc->options = options;
  dc->active = GNUNET_CONTAINER_multihashmap_create (1 + 2 * (length / DBLOCK_SIZE));
  dc->treedepth = GNUNET_FS_compute_depth (GNUNET_ntohll(dc->uri->data.chk.file_length));
  if ( (filename == NULL) &&
       (is_recursive_download (dc) ) )
    {
      if (tempname != NULL)
	dc->temp_filename = GNUNET_strdup (tempname);
      else
	dc->temp_filename = GNUNET_DISK_mktemp ("gnunet-directory-download-tmp");    
    }

#if DEBUG_DOWNLOAD
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Download tree has depth %u\n",
	      dc->treedepth);
#endif
  pi.status = GNUNET_FS_STATUS_DOWNLOAD_START;
  pi.value.download.specifics.start.meta = dc->meta;
  GNUNET_FS_download_make_status_ (&pi, dc);
  schedule_block_download (dc, 
			   &dc->uri->data.chk.chk,
			   0, 
			   1 /* 0 == CHK, 1 == top */); 
  GNUNET_FS_download_sync_ (dc);
  GNUNET_FS_download_start_downloading_ (dc);
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
  dc->job_queue = GNUNET_FS_queue_ (dc->h, 
				    &activate_fs_download,
				    &deactivate_fs_download,
				    dc,
				    (dc->length + DBLOCK_SIZE-1) / DBLOCK_SIZE);
}


/**
 * Stop a download (aborts if download is incomplete).
 *
 * @param dc handle for the download
 * @param do_delete delete files of incomplete downloads
 */
void
GNUNET_FS_download_stop (struct GNUNET_FS_DownloadContext *dc,
			 int do_delete)
{
  struct GNUNET_FS_ProgressInfo pi;
  int have_children;

  if (dc->top != NULL)
    GNUNET_FS_end_top (dc->h, dc->top);
  if (dc->search != NULL)
    {
      dc->search->download = NULL;
      dc->search = NULL;
    }
  if (dc->job_queue != NULL)
    {
      GNUNET_FS_dequeue_ (dc->job_queue);
      dc->job_queue = NULL;
    }
  have_children = (NULL != dc->child_head) ? GNUNET_YES : GNUNET_NO;
  while (NULL != dc->child_head)
    GNUNET_FS_download_stop (dc->child_head, 
			     do_delete);
  if (dc->parent != NULL)
    GNUNET_CONTAINER_DLL_remove (dc->parent->child_head,
				 dc->parent->child_tail,
				 dc);  
  if (dc->serialization != NULL)
    GNUNET_FS_remove_sync_file_ (dc->h,
				 ( (dc->parent != NULL)  || (dc->search != NULL) )
				 ? GNUNET_FS_SYNC_PATH_CHILD_DOWNLOAD 
				 : GNUNET_FS_SYNC_PATH_MASTER_DOWNLOAD , 
				 dc->serialization);
  if ( (GNUNET_YES == have_children) &&
       (dc->parent == NULL) )
    GNUNET_FS_remove_sync_dir_ (dc->h, 
				(dc->search != NULL) 
				? GNUNET_FS_SYNC_PATH_CHILD_DOWNLOAD 
				: GNUNET_FS_SYNC_PATH_MASTER_DOWNLOAD,
				dc->serialization);  
  pi.status = GNUNET_FS_STATUS_DOWNLOAD_STOPPED;
  GNUNET_FS_download_make_status_ (&pi, dc);
  if (GNUNET_SCHEDULER_NO_TASK != dc->task)
    GNUNET_SCHEDULER_cancel (dc->h->sched,
			     dc->task);
  GNUNET_CONTAINER_multihashmap_iterate (dc->active,
					 &free_entry,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (dc->active);
  if (dc->filename != NULL)
    {
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
  GNUNET_CONTAINER_meta_data_destroy (dc->meta);
  GNUNET_FS_uri_destroy (dc->uri);
  if (NULL != dc->temp_filename)
    {
      if (0 != UNLINK (dc->temp_filename))
	GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
				  "unlink",
				  dc->temp_filename);
      GNUNET_free (dc->temp_filename);
    }
  GNUNET_free_non_null (dc->serialization);
  GNUNET_free (dc);
}

/* end of fs_download.c */
