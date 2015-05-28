/*
     This file is part of GNUnet.
     Copyright (C) 2001--2013 Christian Grothoff (and other contributing authors)

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
 * @file util/disk_iterator.c
 * @brief asynchronous iteration over a directory
 * @author Christian Grothoff
 * @author Nils Durner
 */


/**
 * Opaque handle used for iterating over a directory.
 */
struct GNUNET_DISK_DirectoryIterator
{

  /**
   * Function to call on directory entries.
   */
  GNUNET_DISK_DirectoryIteratorCallback callback;

  /**
   * Closure for @e callback.
   */
  void *callback_cls;

  /**
   * Reference to directory.
   */
  DIR *directory;

  /**
   * Directory name.
   */
  char *dirname;

  /**
   * Next filename to process.
   */
  char *next_name;

  /**
   * Our priority.
   */
  enum GNUNET_SCHEDULER_Priority priority;

};


/**
 * Task used by the directory iterator.
 */
static void
directory_iterator_task (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DISK_DirectoryIterator *iter = cls;
  char *name;

  name = iter->next_name;
  GNUNET_assert (name != NULL);
  iter->next_name = NULL;
  iter->callback (iter->callback_cls, iter, name, iter->dirname);
  GNUNET_free (name);
}


/**
 * This function must be called during the DiskIteratorCallback
 * (exactly once) to schedule the task to process the next
 * filename in the directory (if there is one).
 *
 * @param iter opaque handle for the iterator
 * @param can set to #GNUNET_YES to terminate the iteration early
 * @return #GNUNET_YES if iteration will continue,
 *         #GNUNET_NO if this was the last entry (and iteration is complete),
 *         #GNUNET_SYSERR if abort was YES
 */
int
GNUNET_DISK_directory_iterator_next (struct GNUNET_DISK_DirectoryIterator *iter,
                                     int can)
{
  struct dirent *finfo;

  GNUNET_assert (iter->next_name == NULL);
  if (can == GNUNET_YES)
  {
    CLOSEDIR (iter->directory);
    GNUNET_free (iter->dirname);
    GNUNET_free (iter);
    return GNUNET_SYSERR;
  }
  while (NULL != (finfo = READDIR (iter->directory)))
  {
    if ((0 == strcmp (finfo->d_name, ".")) ||
        (0 == strcmp (finfo->d_name, "..")))
      continue;
    GNUNET_asprintf (&iter->next_name, "%s%s%s", iter->dirname,
                     DIR_SEPARATOR_STR, finfo->d_name);
    break;
  }
  if (finfo == NULL)
  {
    GNUNET_DISK_directory_iterator_next (iter, GNUNET_YES);
    return GNUNET_NO;
  }
  GNUNET_SCHEDULER_add_with_priority (iter->priority, &directory_iterator_task,
                                      iter);
  return GNUNET_YES;
}


/**
 * Scan a directory for files using the scheduler to run a task for
 * each entry.  The name of the directory must be expanded first (!).
 * If a scheduler does not need to be used, GNUNET_DISK_directory_scan
 * may provide a simpler API.
 *
 * @param prio priority to use
 * @param dir_name the name of the directory
 * @param callback the method to call for each file
 * @param callback_cls closure for @a callback
 * @return #GNUNET_YES if directory is not empty and @a callback
 *         will be called later, #GNUNET_NO otherwise, #GNUNET_SYSERR on error.
 */
int
GNUNET_DISK_directory_iterator_start (enum GNUNET_SCHEDULER_Priority prio,
                                      const char *dir_name,
                                      GNUNET_DISK_DirectoryIteratorCallback
                                      callback, void *callback_cls)
{
  struct GNUNET_DISK_DirectoryIterator *di;

  di = GNUNET_new (struct GNUNET_DISK_DirectoryIterator);
  di->callback = callback;
  di->callback_cls = callback_cls;
  di->directory = OPENDIR (dir_name);
  if (di->directory == NULL)
  {
    GNUNET_free (di);
    callback (callback_cls, NULL, NULL, NULL);
    return GNUNET_SYSERR;
  }
  di->dirname = GNUNET_strdup (dir_name);
  di->priority = prio;
  return GNUNET_DISK_directory_iterator_next (di, GNUNET_NO);
}

/* end of disk_iterator */
