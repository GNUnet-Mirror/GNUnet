/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file src/fs/gnunet-helper-fs-publish.c
 * @brief Tool to help extract meta data asynchronously
 * @author Christian Grothoff
 *
 * This program will scan a directory for files with meta data
 * and report the results to stdout.
 */
#include "platform.h"
#include "gnunet_fs_service.h"


/**
 * A node of a directory tree.
 */
struct ScanTreeNode
{

  /**
   * This is a doubly-linked list
   */
  struct ScanTreeNode *next;

  /**
   * This is a doubly-linked list
   */
  struct ScanTreeNode *prev;

  /**
   * Parent of this node, NULL for top-level entries.
   */
  struct ScanTreeNode *parent;

  /**
   * This is a doubly-linked tree
   * NULL for files and empty directories
   */
  struct ScanTreeNode *children_head;

  /**
   * This is a doubly-linked tree
   * NULL for files and empty directories
   */
  struct ScanTreeNode *children_tail;

  /**
   * Name of the file/directory
   */
  char *filename;

  /**
   * Size of the file (if it is a file), in bytes.
   * At the moment it is set to 0 for directories.
   */
  uint64_t file_size;

  /**
   * GNUNET_YES if this is a directory
   */
  int is_directory;

};


/**
 * List of libextractor plugins to use for extracting.
 */
static struct EXTRACTOR_PluginList *plugins;


/**
 * Add meta data that libextractor finds to our meta data
 * container.
 *
 * @param cls closure, our meta data container
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
 * @return always 0 to continue extracting
 */
static int
add_to_md (void *cls, const char *plugin_name, enum EXTRACTOR_MetaType type,
           enum EXTRACTOR_MetaFormat format, const char *data_mime_type,
           const char *data, size_t data_len)
{
  struct GNUNET_CONTAINER_MetaData *md = cls;

  (void) GNUNET_CONTAINER_meta_data_insert (md, plugin_name, type, format,
                                            data_mime_type, data, data_len);
  return 0;
}


/**
 * Free memory of the 'tree' structure
 *
 * @param tree tree to free
 */
static void 
free_tree (struct ScanTreeNode *tree)
{
  struct ScanTreeNode *pos;

  while (NULL != (pos = tree->children_head))
    free_tree (pos);
  if (NULL != tree->parent)
    GNUNET_CONTAINER_DLL_remove (tree->parent->children_head,
				 tree->parent->children_tail,
				 tree);				 
  GNUNET_free (tree->filename);
  GNUNET_free (tree);
}


/**
 * Write 'size' bytes from 'buf' into 'out'.
 *
 * @param buf buffer with data to write
 * @param size number of bytes to write
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
write_all (const void *buf,
	   size_t size)
{
  const char *cbuf = buf;
  size_t total;
  ssize_t wr;

  total = 0;
  do
  {
    wr = write (1,
		&cbuf[total],
		size - total);
    if (wr > 0)
      total += wr;
  } while ( (wr > 0) && (total < size) );
  if (wr <= 0)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Failed to write to stdout: %s\n",
		strerror (errno));
  return (total == size) ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Write message to the master process.
 *
 * @param message_type message type to use
 * @param data data to append, NULL for none
 * @param data_length number of bytes in data
 * @return GNUNET_SYSERR to stop scanning (the pipe was broken somehow)
 */
static int
write_message (uint16_t message_type,
	       const char *data,
	       size_t data_length)
{
  struct GNUNET_MessageHeader hdr;

#if 0
  fprintf (stderr, "Helper sends %u-byte message of type %u\n",
	   (unsigned int) (sizeof (struct GNUNET_MessageHeader) + data_length),
	   (unsigned int) message_type);
#endif
  hdr.type = htons (message_type);
  hdr.size = htons (sizeof (struct GNUNET_MessageHeader) + data_length);
  if ( (GNUNET_OK !=
	write_all (&hdr,
		   sizeof (hdr))) ||
       (GNUNET_OK !=
	write_all (data,
		   data_length)) )
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Function called to (recursively) add all of the files in the
 * directory to the tree.  Called by the directory scanner to initiate
 * the scan.  Does NOT yet add any metadata.
 *
 * @param filename file or directory to scan
 * @param dst where to store the resulting share tree item;
 *         NULL is stored in 'dst' upon recoverable errors (GNUNET_OK is returned)
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
preprocess_file (const char *filename,
		 struct ScanTreeNode **dst);


/**
 * Closure for the 'scan_callback'
 */
struct RecursionContext
{
  /**
   * Parent to add the files to.
   */
  struct ScanTreeNode *parent;

  /**
   * Flag to set to GNUNET_YES on serious errors.
   */
  int stop;
};


/**
 * Function called by the directory iterator to (recursively) add all
 * of the files in the directory to the tree.  Called by the directory
 * scanner to initiate the scan.  Does NOT yet add any metadata.
 *
 * @param cls the 'struct RecursionContext'
 * @param filename file or directory to scan
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
scan_callback (void *cls,
	       const char *filename)
{
  struct RecursionContext *rc = cls;
  struct ScanTreeNode *chld;

  if (GNUNET_OK !=
      preprocess_file (filename,
		       &chld))
  {
    rc->stop = GNUNET_YES;
    return GNUNET_SYSERR;
  }
  if (NULL == chld)
    return GNUNET_OK;
  chld->parent = rc->parent;
  GNUNET_CONTAINER_DLL_insert (rc->parent->children_head,
			       rc->parent->children_tail,
			       chld);
  return GNUNET_OK;
}


/**
 * Function called to (recursively) add all of the files in the
 * directory to the tree.  Called by the directory scanner to initiate
 * the scan.  Does NOT yet add any metadata.
 *
 * @param filename file or directory to scan
 * @param dst where to store the resulting share tree item;
 *         NULL is stored in 'dst' upon recoverable errors (GNUNET_OK is returned) 
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
preprocess_file (const char *filename,
		 struct ScanTreeNode **dst)
{
  struct ScanTreeNode *item;
  struct stat sbuf;
  uint64_t fsize = 0;

  if ((0 != STAT (filename, &sbuf)) ||
      ((!S_ISDIR (sbuf.st_mode)) && (GNUNET_OK != GNUNET_DISK_file_size (
      filename, &fsize, GNUNET_NO, GNUNET_YES))))
  {
    /* If the file doesn't exist (or is not stat-able for any other reason)
       skip it (but report it), but do continue. */
    if (GNUNET_OK !=
	write_message (GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_SKIP_FILE,
		       filename, strlen (filename) + 1))
      return GNUNET_SYSERR;
    /* recoverable error, store 'NULL' in *dst */
    *dst = NULL;
    return GNUNET_OK;
  }

  /* Report the progress */
  if (GNUNET_OK !=
      write_message (S_ISDIR (sbuf.st_mode) 
		     ? GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_PROGRESS_DIRECTORY
		     : GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_PROGRESS_FILE,
		     filename, strlen (filename) + 1))
    return GNUNET_SYSERR;
  item = GNUNET_malloc (sizeof (struct ScanTreeNode));
  item->filename = GNUNET_strdup (filename);
  item->is_directory = (S_ISDIR (sbuf.st_mode)) ? GNUNET_YES : GNUNET_NO;
  item->file_size = fsize;
  if (GNUNET_YES == item->is_directory)
  {
    struct RecursionContext rc;

    rc.parent = item;
    rc.stop = GNUNET_NO;
    GNUNET_DISK_directory_scan (filename, 
				&scan_callback, 
				&rc);    
    if ( (GNUNET_YES == rc.stop) ||
	 (GNUNET_OK !=
	  write_message (GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_PROGRESS_DIRECTORY,
			 "..", 3)) )
    {
      free_tree (item);
      return GNUNET_SYSERR;
    }
  }
  *dst = item;
  return GNUNET_OK;
}


/**
 * Extract metadata from files.
 *
 * @param item entry we are processing
 * @return GNUNET_OK on success, GNUNET_SYSERR on fatal errors
 */
static int
extract_files (struct ScanTreeNode *item)
{  
  struct GNUNET_CONTAINER_MetaData *meta;
  ssize_t size;
  size_t slen;

  if (GNUNET_YES == item->is_directory)
  {
    /* for directories, we simply only descent, no extraction, no
       progress reporting */
    struct ScanTreeNode *pos;

    for (pos = item->children_head; NULL != pos; pos = pos->next)
      if (GNUNET_OK !=
	  extract_files (pos))
	return GNUNET_SYSERR;
    return GNUNET_OK;
  }
  
  /* this is the expensive operation, *afterwards* we'll check for aborts */
  meta = GNUNET_CONTAINER_meta_data_create ();
  if (NULL != plugins)
    EXTRACTOR_extract (plugins, item->filename, NULL, 0, &add_to_md, meta);
  slen = strlen (item->filename) + 1;
  size = GNUNET_CONTAINER_meta_data_get_serialized_size (meta);
  if (-1 == size)
  {
    /* no meta data */
    GNUNET_CONTAINER_meta_data_destroy (meta);
    if (GNUNET_OK !=
	write_message (GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_META_DATA,
		       item->filename, slen))
      return GNUNET_SYSERR;    
    return GNUNET_OK;
  }
  {
    char buf[size + slen];
    char *dst = &buf[slen];
    
    memcpy (buf, item->filename, slen);
    size = GNUNET_CONTAINER_meta_data_serialize (meta,
						 &dst, size,
						 GNUNET_CONTAINER_META_DATA_SERIALIZE_PART);
    if (size < 0)
    {
      GNUNET_break (0);
      size = 0;
    }
    GNUNET_CONTAINER_meta_data_destroy (meta);
    if (GNUNET_OK !=
	write_message (GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_META_DATA,
		       buf, 
		       slen + size))
      return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Main function of the helper process to extract meta data.
 *
 * @param argc should be 3
 * @param argv [0] our binary name
 *             [1] name of the file or directory to process
 *             [2] "-" to disable extraction, NULL for defaults,
 *                 otherwise custom plugins to load from LE
 * @return 0 on success
 */
int main(int argc,
	 char **argv)
{
  const char *filename_expanded;
  const char *ex;
  struct ScanTreeNode *root;

#if WINDOWS
  /* We're using stdout to communicate binary data back to the parent; use
   * binary mode.
   */
  _setmode (1, _O_BINARY);
#endif

  /* parse command line */
  if ( (3 != argc) && (2 != argc) )
  {
    FPRINTF (stderr, 
	     "%s",
	     "gnunet-helper-fs-publish needs exactly one or two arguments\n");
    return 1;
  }
  filename_expanded = argv[1];
  ex = argv[2];
  if ( (NULL == ex) ||
       (0 != strcmp (ex, "-")) )
  {
    plugins = EXTRACTOR_plugin_add_defaults (EXTRACTOR_OPTION_DEFAULT_POLICY);
    if (NULL != ex)
      plugins = EXTRACTOR_plugin_add_config (plugins, ex,
					     EXTRACTOR_OPTION_DEFAULT_POLICY);
  }

  /* scan tree to find out how much work there is to be done */
  if (GNUNET_OK != preprocess_file (filename_expanded, 
				    &root))
  {
    (void) write_message (GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_ERROR, NULL, 0);
    return 2;
  }
  /* signal that we're done counting files, so that a percentage of 
     progress can now be calculated */
  if (GNUNET_OK !=
      write_message (GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_COUNTING_DONE, NULL, 0))
    return 3;  
  if (NULL != root)
  {
    if (GNUNET_OK !=
	extract_files (root))
    {
      (void) write_message (GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_ERROR, NULL, 0);
      free_tree (root);
      return 4;
    }
    free_tree (root);
  }
  /* enable "clean" shutdown by telling parent that we are done */
  (void) write_message (GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_FINISHED, NULL, 0);
  if (NULL != plugins)
    EXTRACTOR_plugin_remove_all (plugins);

  return 0;
}

/* end of gnunet-helper-fs-publish.c */

