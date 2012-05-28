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
   * scanner. 
   */
  struct GNUNET_FS_ShareTreeItem *toplevel;

  /**
   * Current position during processing.
   */
  struct GNUNET_FS_ShareTreeItem *pos;

  /**
   * Task scheduled when we are done.
   */
  GNUNET_SCHEDULER_TaskIdentifier stop_task;

  /**
   * Arguments for helper.
   */
  char *args[4];

};



/**
 * Abort the scan.  Must not be called from within the progress_callback
 * function.
 *
 * @param ds directory scanner structure
 */
void
GNUNET_FS_directory_scan_abort (struct GNUNET_FS_DirScanner *ds)
{
  /* terminate helper */
  if (NULL != ds->helper)
    GNUNET_HELPER_stop (ds->helper);
  
  /* free resources */
  if (NULL != ds->toplevel)
    GNUNET_FS_share_tree_free (ds->toplevel);
  if (GNUNET_SCHEDULER_NO_TASK != ds->stop_task)
    GNUNET_SCHEDULER_cancel (ds->stop_task);
  GNUNET_free_non_null (ds->ex_arg);
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
 * Move in the directory from the given position to the next file
 * in DFS traversal.
 *
 * @param pos current position
 * @return next file, NULL for none
 */
static struct GNUNET_FS_ShareTreeItem *
advance (struct GNUNET_FS_ShareTreeItem *pos)
{
  int moved;
  
  GNUNET_assert (NULL != pos);
  moved = 0; /* must not terminate, even on file, otherwise "normal" */
  while ( (pos->is_directory == GNUNET_YES) ||
	  (0 == moved) )
  {
    if ( (moved != -1) &&
	 (NULL != pos->children_head) )
    {
      pos = pos->children_head;
      moved = 1; /* can terminate if file */
      continue;
    }
    if (NULL != pos->next)
    {
      pos = pos->next;
      moved = 1; /* can terminate if file */
      continue;
    }
    if (NULL != pos->parent)
    {
      pos = pos->parent;
      moved = -1; /* force move to 'next' or 'parent' */
      continue;
    }
    /* no more options, end of traversal */
    return NULL;
  }
  return pos;
}


/**
 * Add another child node to the tree.
 *
 * @param parent parent of the child, NULL for top level
 * @param filename name of the file or directory
 * @param is_directory GNUNET_YES for directories
 * @return new entry that was just created
 */
static struct GNUNET_FS_ShareTreeItem *
expand_tree (struct GNUNET_FS_ShareTreeItem *parent,
	     const char *filename,
	     int is_directory)
{
  struct GNUNET_FS_ShareTreeItem *chld;
  size_t slen;

  chld = GNUNET_malloc (sizeof (struct GNUNET_FS_ShareTreeItem));
  chld->parent = parent;
  chld->filename = GNUNET_strdup (filename);
  GNUNET_asprintf (&chld->short_filename,
		   "%s%s",
		   GNUNET_STRINGS_get_short_name (filename),
		   is_directory == GNUNET_YES ? "/" : "");
  /* make sure we do not end with '//' */
  slen = strlen (chld->short_filename);
  if ( (slen >= 2) &&
       (chld->short_filename[slen-1] == '/') &&
       (chld->short_filename[slen-2] == '/') )
    chld->short_filename[slen-1] = '\0';
  chld->is_directory = is_directory;
  if (NULL != parent)
      GNUNET_CONTAINER_DLL_insert (parent->children_head,
				   parent->children_tail,
				   chld);  
  return chld;
}


/**
 * Task run last to shut everything down.
 *
 * @param cls the 'struct GNUNET_FS_DirScanner'
 * @param tc unused
 */
static void
finish_scan (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_DirScanner *ds = cls;

  ds->stop_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_HELPER_stop (ds->helper);
  ds->helper = NULL;
  ds->progress_callback (ds->progress_callback_cls, 
			 NULL, GNUNET_SYSERR,
			 GNUNET_FS_DIRSCANNER_FINISHED);    
}


/**
 * Called every time there is data to read from the scanner.
 * Calls the scanner progress handler.
 *
 * @param cls the closure (directory scanner object)
 * @param client always NULL
 * @param msg message from the helper process
 */
static int
process_helper_msgs (void *cls, 
		     void *client,
		     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_FS_DirScanner *ds = cls;
  const char *filename;
  size_t left;

#if 0
  fprintf (stderr, "DMS parses %u-byte message of type %u\n",
	   (unsigned int) ntohs (msg->size),
	   (unsigned int) ntohs (msg->type));
#endif
  left = ntohs (msg->size) - sizeof (struct GNUNET_MessageHeader);
  filename = (const char*) &msg[1];
  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_PROGRESS_FILE:
    if (filename[left-1] != '\0')
    {
      GNUNET_break (0);
      break;
    }
    ds->progress_callback (ds->progress_callback_cls, 
			   filename, GNUNET_NO,
			   GNUNET_FS_DIRSCANNER_FILE_START);
    if (NULL == ds->toplevel)
      ds->toplevel = expand_tree (ds->pos,
				  filename, GNUNET_NO);
    else
      (void) expand_tree (ds->pos,
			  filename, GNUNET_NO);
    return GNUNET_OK;
  case GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_PROGRESS_DIRECTORY:
    if (filename[left-1] != '\0')
    {
      GNUNET_break (0);
      break;
    }
    if (0 == strcmp ("..", filename))
    {
      if (NULL == ds->pos)
      {
	GNUNET_break (0);
	break;
      }
      ds->pos = ds->pos->parent;
      return GNUNET_OK;
    }
    ds->progress_callback (ds->progress_callback_cls, 
			   filename, GNUNET_YES,
			   GNUNET_FS_DIRSCANNER_FILE_START);
    ds->pos = expand_tree (ds->pos,
			   filename, GNUNET_YES);
    if (NULL == ds->toplevel)
      ds->toplevel = ds->pos;
    return GNUNET_OK;
  case GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_ERROR:
    break;
  case GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_SKIP_FILE:
    if ('\0' != filename[left-1])
      break;
    ds->progress_callback (ds->progress_callback_cls, 
			   filename, GNUNET_SYSERR,
			   GNUNET_FS_DIRSCANNER_FILE_IGNORED);
    return GNUNET_OK;
  case GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_COUNTING_DONE:
    if (0 != left)
    {
      GNUNET_break (0);
      break;
    }
    if (NULL == ds->toplevel)
    {
      GNUNET_break (0);
      break;
    }
    ds->progress_callback (ds->progress_callback_cls, 
			   NULL, GNUNET_SYSERR,
			   GNUNET_FS_DIRSCANNER_ALL_COUNTED);
    ds->pos = ds->toplevel;
    if (GNUNET_YES == ds->pos->is_directory)
      ds->pos = advance (ds->pos);
    return GNUNET_OK;
  case GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_META_DATA:
    {
      size_t nlen;
      const char *end;
      
      if (NULL == ds->pos)
      {
	GNUNET_break (0);
	break;
      }
      end = memchr (filename, 0, left);
      if (NULL == end)
      {
	GNUNET_break (0);
	break;
      }
      end++;
      nlen = end - filename;
      left -= nlen;
      if (0 != strcmp (filename,
		       ds->pos->filename))
      {
	GNUNET_break (0);
	break;
      }
      ds->progress_callback (ds->progress_callback_cls, 
			     filename, GNUNET_YES,
			     GNUNET_FS_DIRSCANNER_EXTRACT_FINISHED);
      if (0 < left)
      {
	ds->pos->meta = GNUNET_CONTAINER_meta_data_deserialize (end, left);
	if (NULL == ds->pos->meta)
	{
	  GNUNET_break (0);
	  break;
	}
	/* having full filenames is too dangerous; always make sure we clean them up */
	GNUNET_CONTAINER_meta_data_delete (ds->pos->meta, 
					   EXTRACTOR_METATYPE_FILENAME,
					   NULL, 0);
	/* instead, put in our 'safer' original filename */
	GNUNET_CONTAINER_meta_data_insert (ds->pos->meta, "<libgnunetfs>",
					   EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME,
					   EXTRACTOR_METAFORMAT_UTF8, "text/plain",
					   ds->pos->short_filename, 
					   strlen (ds->pos->short_filename) + 1);
      }
      ds->pos->ksk_uri = GNUNET_FS_uri_ksk_create_from_meta_data (ds->pos->meta);
      ds->pos = advance (ds->pos);      
      return GNUNET_OK;
    }
  case GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_FINISHED:
    if (NULL != ds->pos)
    {
      GNUNET_break (0);
      break;
    }
    if (0 != left)
    {
      GNUNET_break (0);
      break;
    }   
    if (NULL == ds->toplevel)
    {
      GNUNET_break (0);
      break;
    }
    ds->stop_task = GNUNET_SCHEDULER_add_now (&finish_scan,
					      ds);
    return GNUNET_OK;
  default:
    GNUNET_break (0);
    break;
  }
  ds->progress_callback (ds->progress_callback_cls, 
			 NULL, GNUNET_SYSERR,
			 GNUNET_FS_DIRSCANNER_INTERNAL_ERROR);
  return GNUNET_OK;
}


/**
 * Start a directory scanner thread.
 *
 * @param filename name of the directory to scan
 * @param disable_extractor GNUNET_YES to not to run libextractor on files (only build a tree)
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
  if (disable_extractor)  
    ds->ex_arg = GNUNET_strdup ("-");
  else 
    ds->ex_arg = (NULL != ex) ? GNUNET_strdup (ex) : NULL;
  ds->args[0] = "gnunet-helper-fs-publish";
  ds->args[1] = ds->filename_expanded;
  ds->args[2] = ds->ex_arg;
  ds->args[3] = NULL;
  ds->helper = GNUNET_HELPER_start ("gnunet-helper-fs-publish",
				    ds->args,
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
