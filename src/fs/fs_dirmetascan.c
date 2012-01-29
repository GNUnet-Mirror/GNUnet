/*
     This file is part of GNUnet
     (C) 2005-2012 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_dirmetascan.c
 * @brief code to asynchronously build a 'struct GNUNET_FS_ShareTreeItem'
 *        from an on-disk directory for publishing; use the 'gnunet-helper-fs-publish'.
 * @author LRN
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_fs_service.h"
#include "gnunet_scheduler_lib.h"
#include <pthread.h>


/**
 * An opaque structure a pointer to which is returned to the
 * caller to be used to control the scanner.
 */
struct GNUNET_FS_DirScanner
{

  /**
   * Helper process.
   */
  struct GNUNET_HELPER_Handle *helper;

  /**
   * Expanded filename (as given by the scan initiator).
   * The scanner thread stores a copy here, and frees it when it finishes.
   */
  char *filename_expanded;

  /**
   * Second argument to helper process.
   */
  char *ex_arg;
  
  /**
   * The function that will be called every time there's a progress
   * message.
   */
  GNUNET_FS_DirScannerProgressCallback progress_callback;
  
  /**
   * A closure for progress_callback.
   */
  void *progress_callback_cls;

  /**
   * After the scan is finished, it will contain a pointer to the
   * top-level directory entry in the directory tree built by the
   * scanner.  Must only be manipulated by the thread for the
   * duration of the thread's runtime.
   */
  struct GNUNET_FS_ShareTreeItem *toplevel;

};



/**
 * Abort the scan.
 *
 * @param ds directory scanner structure
 */
void
GNUNET_FS_directory_scan_abort (struct GNUNET_FS_DirScanner *ds)
{
  /* terminate helper */
  GNUNET_HELPER_stop (ds->helper);

  /* free resources */
  if (NULL != ds->toplevel)
    GNUNET_FS_share_tree_free (ds->toplevel);
  GNUNET_free (ds->ex_arg);
  GNUNET_free (ds->filename_expanded);
  GNUNET_free (ds);
}


/**
 * Obtain the result of the scan after the scan has signalled
 * completion.  Must not be called prior to completion.  The 'ds' is
 * freed as part of this call.
 *
 * @param ds directory scanner structure
 * @return the results of the scan (a directory tree)
 */
struct GNUNET_FS_ShareTreeItem *
GNUNET_FS_directory_scan_get_result (struct GNUNET_FS_DirScanner *ds)
{
  struct GNUNET_FS_ShareTreeItem *result;

  /* check that we're actually done */
  GNUNET_assert (NULL == ds->helper);
  /* preserve result */
  result = ds->toplevel;
  ds->toplevel = NULL; 
  GNUNET_FS_directory_scan_abort (ds);
  return result;
}


/**
 * Called every time there is data to read from the scanner.
 * Calls the scanner progress handler.
 *
 * @param cls the closure (directory scanner object)
 * @param client always NULL
 * @param msg message from the helper process
 */
static void
process_helper_msgs (void *cls, 
		     void *client,
		     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_FS_DirScanner *ds = cls;
  ds++;
#if 0
  enum GNUNET_FS_DirScannerProgressUpdateReason reason;
  size_t filename_len;
  int is_directory;
  char *filename;

  /* Process message. If message is malformed or can't be read, end the scanner */
  /* read successfully, notify client about progress */
  ds->progress_callback (ds->progress_callback_cls, 
			 ds, 
			 filename,
			 is_directory, 
			 reason);
  GNUNET_free (filename);


  /* having full filenames is too dangerous; always make sure we clean them up */
  item->short_filename = GNUNET_strdup (GNUNET_STRINGS_get_short_name (filename));

  GNUNET_CONTAINER_meta_data_delete (item->meta, 
				     EXTRACTOR_METATYPE_FILENAME,
				     NULL, 0);
  GNUNET_CONTAINER_meta_data_insert (item->meta, "<libgnunetfs>",
                                     EXTRACTOR_METATYPE_FILENAME,
                                     EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                     item->short_filename, 
				     strlen (item->short_filename) + 1);
#endif
}


/**
 * Start a directory scanner thread.
 *
 * @param filename name of the directory to scan
 * @param GNUNET_YES to not to run libextractor on files (only build a tree)
 * @param ex if not NULL, must be a list of extra plugins for extractor
 * @param cb the callback to call when there are scanning progress messages
 * @param cb_cls closure for 'cb'
 * @return directory scanner object to be used for controlling the scanner
 */
struct GNUNET_FS_DirScanner *
GNUNET_FS_directory_scan_start (const char *filename,
				int disable_extractor, const char *ex,
				GNUNET_FS_DirScannerProgressCallback cb, 
				void *cb_cls)
{
  struct stat sbuf;
  char *filename_expanded;
  struct GNUNET_FS_DirScanner *ds;
  char *args[4];

  if (0 != STAT (filename, &sbuf))
    return NULL;
  filename_expanded = GNUNET_STRINGS_filename_expand (filename);
  if (NULL == filename_expanded)
    return NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting to scan directory `%s'\n",
	      filename_expanded);
  ds = GNUNET_malloc (sizeof (struct GNUNET_FS_DirScanner));
  ds->progress_callback = cb;
  ds->progress_callback_cls = cb_cls;
  ds->filename_expanded = filename_expanded;
  ds->ex_arg = GNUNET_strdup ((disable_extractor) ? "-" : ex);
  args[0] = "gnunet-helper-fs-publish";
  args[1] = ds->filename_expanded;
  args[2] = ds->ex_arg;
  args[3] = NULL;
  ds->helper = GNUNET_HELPER_start ("gnunet-helper-fs-publish",
				    args,
				    &process_helper_msgs,
				    ds);
  if (NULL == ds->helper)
  {
    GNUNET_free (filename_expanded);
    GNUNET_free (ds);
    return NULL;
  }
  return ds;
}


/* end of fs_dirmetascan.c */
