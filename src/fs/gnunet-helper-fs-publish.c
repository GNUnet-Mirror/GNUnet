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
 * List of libextractor plugins to use for extracting.
 */
static struct EXTRACTOR_PluginList *plugins;


#if 0
/**
 * Write 'size' bytes from 'buf' into 'out'.
 *
 * @param in pipe to write to
 * @param buf buffer with data to write
 * @param size number of bytes to write
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
write_all (const struct GNUNET_DISK_FileHandle *out,
	   const void *buf,
	   size_t size)
{
  const char *cbuf = buf;
  size_t total;
  ssize_t wr;

  total = 0;
  do
  {
    wr = GNUNET_DISK_file_write (out,
				 &cbuf[total],
				 size - total);
    if (wr > 0)
      total += wr;
  } while ( (wr > 0) && (total < size) );
  if (wr <= 0)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Failed to write to inter thread communication pipe: %s\n",
		strerror (errno));
  return (total == size) ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Write progress message.
 *
 * @param ds
 * @param filename name of the file to transmit, never NULL
 * @param is_directory GNUNET_YES for directory, GNUNET_NO for file, GNUNET_SYSERR for neither
 * @param reason reason for the progress call
 * @return GNUNET_SYSERR to stop scanning (the pipe was broken somehow)
 */
static int
write_progress (struct GNUNET_FS_DirScanner *ds,
		const char *filename,
		int is_directory, 
		enum GNUNET_FS_DirScannerProgressUpdateReason reason)
{
  size_t slen;

  slen = strlen (filename) + 1;
  if ( (GNUNET_OK !=
	write_all (ds->progress_write,
		   &reason,
		   sizeof (reason))) ||
       (GNUNET_OK !=
	write_all (ds->progress_write,
		   &slen,
		   sizeof (slen))) ||
       (GNUNET_OK !=
	write_all (ds->progress_write,
		   filename,
		   slen)) ||
       (GNUNET_OK !=
	write_all (ds->progress_write,
		   &is_directory,
		   sizeof (is_directory))) )
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Function called to (recursively) add all of the files in the
 * directory to the tree.  Called by the directory scanner to initiate
 * the scan.  Does NOT yet add any metadata.
 *
 * @param ds directory scanner context to use
 * @param filename file or directory to scan
 * @param dst where to store the resulting share tree item
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
preprocess_file (struct GNUNET_FS_DirScanner *ds,
		 const char *filename,
		 struct GNUNET_FS_ShareTreeItem **dst);


/**
 * Closure for the 'scan_callback'
 */
struct RecursionContext
{
  /**
   * Global scanner context.
   */
  struct GNUNET_FS_DirScanner *ds;

  /**
   * Parent to add the files to.
   */
  struct GNUNET_FS_ShareTreeItem *parent;

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
  struct GNUNET_FS_ShareTreeItem *chld;

  if (GNUNET_OK !=
      preprocess_file (rc->ds,
		       filename,
		       &chld))
  {
    rc->stop = GNUNET_YES;
    return GNUNET_SYSERR;
  }
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
 * @param ds directory scanner context to use
 * @param filename file or directory to scan
 * @param dst where to store the resulting share tree item
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
preprocess_file (struct GNUNET_FS_DirScanner *ds,
		 const char *filename,
		 struct GNUNET_FS_ShareTreeItem **dst)
{
  struct GNUNET_FS_ShareTreeItem *item;
  struct stat sbuf;

  if (0 != STAT (filename, &sbuf))
  {
    /* If the file doesn't exist (or is not stat-able for any other reason)
       skip it (but report it), but do continue. */
    if (GNUNET_OK !=
	write_progress (ds, filename, GNUNET_SYSERR,
			GNUNET_FS_DIRSCANNER_DOES_NOT_EXIST))
      return GNUNET_SYSERR;
    return GNUNET_OK;
  }

  /* Report the progress */
  if (GNUNET_OK !=
      write_progress (ds, 
		      filename, 
		      S_ISDIR (sbuf.st_mode) ? GNUNET_YES : GNUNET_NO,
		      GNUNET_FS_DIRSCANNER_FILE_START))
    return GNUNET_SYSERR;
  item = GNUNET_malloc (sizeof (struct GNUNET_FS_ShareTreeItem));
  item->meta = GNUNET_CONTAINER_meta_data_create ();
  item->filename = GNUNET_strdup (filename);
  item->short_filename = GNUNET_strdup (GNUNET_STRINGS_get_short_name (filename));
  item->is_directory = (S_ISDIR (sbuf.st_mode)) ? GNUNET_YES : GNUNET_NO;
  item->file_size = (uint64_t) sbuf.st_size;
  if (item->is_directory)
  {
    struct RecursionContext rc;

    rc.parent = item;
    rc.ds = ds;
    rc.stop = GNUNET_NO;
    GNUNET_DISK_directory_scan (filename, 
				&scan_callback, 
				&rc);    
    if ( (rc.stop == GNUNET_YES) ||
	 (GNUNET_OK != 
	  test_thread_stop (ds)) )
    {
      GNUNET_FS_share_tree_free (item);
      return GNUNET_SYSERR;
    }
  }
  /* Report the progress */
  if (GNUNET_OK !=
      write_progress (ds, 
		      filename, 
		      S_ISDIR (sbuf.st_mode) ? GNUNET_YES : GNUNET_NO,
		      GNUNET_FS_DIRSCANNER_SUBTREE_COUNTED))
  {
    GNUNET_FS_share_tree_free (item);
    return GNUNET_SYSERR;
  }
  *dst = item;
  return GNUNET_OK;
}


/**
 * Extract metadata from files.
 *
 * @param ds directory scanner context
 * @param item entry we are processing
 * @return GNUNET_OK on success, GNUNET_SYSERR on fatal errors
 */
static int
extract_files (struct GNUNET_FS_DirScanner *ds,
	       struct GNUNET_FS_ShareTreeItem *item)
{  
  if (item->is_directory)
  {
    /* for directories, we simply only descent, no extraction, no
       progress reporting */
    struct GNUNET_FS_ShareTreeItem *pos;

    for (pos = item->children_head; NULL != pos; pos = pos->next)
      if (GNUNET_OK !=
	  extract_files (ds, pos))
	return GNUNET_SYSERR;
    return GNUNET_OK;
  }
  
  /* this is the expensive operation, *afterwards* we'll check for aborts */
  fprintf (stderr, "\tCalling extract on `%s'\n", item->filename);
  GNUNET_FS_meta_data_extract_from_file (item->meta, 
					 item->filename,
					 ds->plugins);
  fprintf (stderr, "\tExtract `%s' done\n", item->filename);

  /* having full filenames is too dangerous; always make sure we clean them up */
  GNUNET_CONTAINER_meta_data_delete (item->meta, 
				     EXTRACTOR_METATYPE_FILENAME,
				     NULL, 0);
  GNUNET_CONTAINER_meta_data_insert (item->meta, "<libgnunetfs>",
                                     EXTRACTOR_METATYPE_FILENAME,
                                     EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                     item->short_filename, 
				     strlen (item->short_filename) + 1);
  /* check for abort */
  if (GNUNET_OK != 
      test_thread_stop (ds))
    return GNUNET_SYSERR;

  /* Report the progress */
  if (GNUNET_OK !=
      write_progress (ds, 
		      item->filename, 
		      GNUNET_NO,
		      GNUNET_FS_DIRSCANNER_EXTRACT_FINISHED))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

#endif


int main(int argc,
	 char **argv)
{
  const char *filename_expanded;
  const char *ex;

  if (argc < 3)
  {
    FPRINTF (stderr, 
	     "%s",
	     "gnunet-helper-fs-publish needs at least two arguments\n");
    return 1;
  }
  filename_expanded = argv[1];
  ex = argv[2];
  if (0 != strcmp (ex, "-"))
  {
    plugins = EXTRACTOR_plugin_add_defaults (EXTRACTOR_OPTION_DEFAULT_POLICY);
    if (NULL != ex)
      plugins = EXTRACTOR_plugin_add_config (plugins, ex,
					     EXTRACTOR_OPTION_DEFAULT_POLICY);
  }

#if 0
  if (GNUNET_OK != preprocess_file (filename_expanded, 
				    &toplevel))
  {
    (void) write_progress (ds, "", GNUNET_SYSERR, GNUNET_FS_DIRSCANNER_INTERNAL_ERROR);
    GNUNET_DISK_pipe_close_end (ds->progress_pipe, GNUNET_DISK_PIPE_END_WRITE);
    return 2;
  }
  if (GNUNET_OK !=
      write_progress (ds, "", GNUNET_SYSERR, GNUNET_FS_DIRSCANNER_ALL_COUNTED))
  {
    return 3;
  }
  if (GNUNET_OK !=
      extract_files (ds, ds->toplevel))
  {
    (void) write_progress (ds, "", GNUNET_SYSERR, GNUNET_FS_DIRSCANNER_INTERNAL_ERROR);
    return 4;
  }
  (void) write_progress (ds, "", GNUNET_SYSERR, GNUNET_FS_DIRSCANNER_FINISHED);
#endif
  if (NULL != plugins)
    EXTRACTOR_plugin_remove_all (plugins);

  return 0;
}
