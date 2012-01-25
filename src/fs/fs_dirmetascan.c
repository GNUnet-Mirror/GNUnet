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

#include "platform.h"
#include "gnunet_fs_service.h"
#include "gnunet_scheduler_lib.h"
#include <pthread.h>

/**
 * Entry for each unique keyword to track how often
 * it occured.  Contains the keyword and the counter.
 */
struct KeywordCounter
{

  /**
   * Keyword that was found.
   */
  const char *value;

  /**
   * How many files have this keyword?
   */
  unsigned int count;

  /**
   * This is a doubly-linked list
   */
  struct KeywordCounter *prev;

  /**
   * This is a doubly-linked list
   */
  struct KeywordCounter *next;
};

/**
 * Aggregate information we keep for meta data in each directory.
 */
struct MetaCounter
{
  /**
   * The actual meta data.
   */
  const char *data;

  /**
   * Number of bytes in 'data'.
   */
  size_t data_size;

  /**
   * Name of the plugin that provided that piece of metadata
   */
  const char *plugin_name;

  /**
   * Type of the data
   */
  enum EXTRACTOR_MetaType type;

  /**
   * Format of the data
   */
  enum EXTRACTOR_MetaFormat format;

  /**
   * MIME-type of the metadata itself
   */
  const char *data_mime_type;

  /**
   * How many files have meta entries matching this value?
   * (type and format do not have to match).
   */
  unsigned int count;

  /**
   * This is a doubly-linked list
   */
  struct MetaCounter *prev;

  /**
   * This is a doubly-linked list
   */
  struct MetaCounter *next;
};

struct AddDirContext;

/**
 * A structure used to hold a pointer to the tree item that is being
 * processed.
 * Needed to avoid changing the context for every recursive call.
 */
struct AddDirStack
{
  /**
   * Context pointer
   */
  struct AddDirContext *adc;

  /**
   * Parent directory
   */
  struct GNUNET_FS_ShareTreeItem *parent;
};

/**
 * Execution context for 'add_dir'
 * Owned by the initiator thread.
 */
struct AddDirContext
{
  /**
   * After the scan is finished, it will contain a pointer to the
   * top-level directory entry in the directory tree built by the
   * scanner.
   */
  struct GNUNET_FS_ShareTreeItem *toplevel;

  /**
   * Expanded filename (as given by the scan initiator).
   * The scanner thread stores a copy here, and frees it when it finishes.
   */
  char *filename_expanded;

  /**
   * A pipe end to read signals from.
   * Owned by the initiator thread.
   */
  const struct GNUNET_DISK_FileHandle *stop_read;

  /**
   * 1 if the scanner should stop, 0 otherwise. Set in response
   * to communication errors or when the initiator wants the scanning
   * process to stop.
   */
  char do_stop;

  /**
   * Handle of the pipe end into which the progress messages are written
   * The pipe is owned by the initiator thread, and there's no way to
   * close this end without having access to the pipe, so it won't
   * be closed by the scanner thread.
   * The initiator MUST keep it alive until the scanner thread is finished.
   */
  const struct GNUNET_DISK_FileHandle *progress_write;


  /**
   * List of libextractor plugins to use for extracting.
   * Initialized when the scan starts, removed when it finishes.
   */
  struct EXTRACTOR_PluginList *plugins;
};

/**
 * An opaque structure a pointer to which is returned to the
 * caller to be used to control the scanner.
 */
struct GNUNET_FS_DirScanner
{
  /**
   * A pipe end to read signals from.
   * Owned by the initiator thread.
   */
  const struct GNUNET_DISK_FileHandle *stop_write;
  
  /**
   * A pipe transfer signals to the scanner.
   * Owned by the initiator thread.
   */
  struct GNUNET_DISK_PipeHandle *stop_pipe;

 /**
  * A thread object for the scanner thread.
  * Owned by the initiator thread.
  */
#if WINDOWS
  HANDLE thread;
#else
  pthread_t thread;
#endif

 /**
  * A task for reading progress messages from the scanner.
  */
  GNUNET_SCHEDULER_TaskIdentifier progress_read_task;

 /**
  * The end of the pipe that is used to read progress messages.
  */
  const struct GNUNET_DISK_FileHandle *progress_read;

 /**
  * The pipe that is used to read progress messages.
  * Owned (along with both of its ends) by the initiator thread.
  * Only closed after the scanner thread is finished.
  */
  struct GNUNET_DISK_PipeHandle *progress_pipe;

 /**
  * The function that will be called every time there's a progress
  * message.
  */
  GNUNET_FS_DirScannerProgressCallback progress_callback;

 /**
  * A closure for progress_callback.
  */
  void *cls;

 /**
  * A pointer to the context of the scanner.
  * Owned by the initiator thread.
  * Initiator thread shouldn't touch it until the scanner thread
  * is finished.
  */
  struct AddDirContext *adc;
};

/**
 * A structure that forms a singly-linked list that serves as a stack
 * for metadata-processing function.
 */
struct ProcessMetadataStackItem
{
 /**
  * A pointer to metadata-processing context.
  * The same in every stack item.
  */
  struct GNUNET_FS_ProcessMetadataContext *ctx;

 /**
  * This is a singly-linked list. A pointer to its end is kept, and
  * this pointer is used to walk it backwards.
  */
  struct ProcessMetadataStackItem *parent;

  /**
   * Map from the hash over the keyword to an 'struct KeywordCounter *'
   * counter that says how often this keyword was
   * encountered in the current directory.
   */
  struct GNUNET_CONTAINER_MultiHashMap *keywordcounter;

  /**
   * Map from the hash over the metadata to an 'struct MetaCounter *'
   * counter that says how often this metadata was
   * encountered in the current directory.
   */
  struct GNUNET_CONTAINER_MultiHashMap *metacounter;

  /**
   * Number of files in the current directory.
   */
  unsigned int dir_entry_count;

  /**
   * Keywords to exclude from using for KSK since they'll be associated
   * with the parent as well.  NULL for nothing blocked.
   */
  struct GNUNET_FS_Uri *exclude_ksk;

 /**
  * A share tree item that is being processed.
  */
  struct GNUNET_FS_ShareTreeItem *item;

 /**
  * Set to GNUNET_YES to indicate that the directory pointer by 'item'
  * was processed, and we should move on to the next.
  * Otherwise the directory will be recursed into.
  */
  int end_directory;

};

/**
 * The structure to keep the state of metadata processing
 */
struct GNUNET_FS_ProcessMetadataContext
{
 /**
  * The top of the stack.
  */
  struct ProcessMetadataStackItem *stack;

 /**
  * Callback to invoke when processing is finished
  */
  GNUNET_SCHEDULER_Task cb;

 /**
  * Closure for 'cb'
  */
  void *cls;

 /**
  * Toplevel directory item of the tree to process.
  */
  struct GNUNET_FS_ShareTreeItem *toplevel;
};

/**
 * Called every now and then by the scanner.
 * Checks the synchronization privitive.
 * Returns 1 if the scanner should stop, 0 otherwise.
 */
static int
should_stop (struct AddDirContext *adc)
{
  errno = 0;
  char c;
  if (GNUNET_DISK_file_read_non_blocking (adc->stop_read, &c, 1) == 1
      || errno != EAGAIN)
  {
    adc->do_stop = 1;
  }
  return adc->do_stop;
}

/**
 * Write progress message.
 * Format is:
 * "reason", "filename length", "filename", "directory flag"
 * If filename is NULL, filename is not written, and its length
 * is written as 0, and nothing else is written. It signals the initiator
 * thread that the scanner is finished, and that it can now join its thread.
 *
 * Also checks if the initiator thread wants the scanner to stop,
 * Returns 1 to stop scanning (if the signal was received, or
 * if the pipe was broken somehow), 0 otherwise.
 */
static int
write_progress (struct AddDirContext *adc, const char *filename,
    char is_directory, enum GNUNET_FS_DirScannerProgressUpdateReason reason)
{
  size_t filename_len;
  ssize_t wr;
  size_t total_write;
  if ((adc->do_stop || should_stop (adc)) && reason != GNUNET_DIR_SCANNER_ASKED_TO_STOP
      && reason != GNUNET_DIR_SCANNER_FINISHED)
    return 1;
  total_write = 0;
  wr = 1;
  while ((wr > 0 || errno == EAGAIN) && total_write < sizeof (reason))
  {
    wr = GNUNET_DISK_file_write_blocking (adc->progress_write,
      &((char *)&reason)[total_write], sizeof (reason) - total_write);
    if (wr > 0)
      total_write += wr;
  }
  if (sizeof (reason) != total_write)
    return adc->do_stop = 1;
  if (filename)
    filename_len = strlen (filename) + 1;
  else
    filename_len = 0;
  total_write = 0;
  wr = 1;
  while ((wr > 0 || errno == EAGAIN) && total_write < sizeof (size_t))
  {
    wr = GNUNET_DISK_file_write_blocking (adc->progress_write,
      &((char *)&filename_len)[total_write], sizeof (size_t) - total_write);
    if (wr > 0)
      total_write += wr;
  }
  if (sizeof (size_t) != total_write)
    return adc->do_stop = 1;
  if (filename)
  {
    total_write = 0;
    wr = 1;
    while ((wr > 0 || errno == EAGAIN) && total_write < filename_len)
    {
      wr = GNUNET_DISK_file_write_blocking (adc->progress_write,
        &((char *)filename)[total_write], filename_len - total_write);
      if (wr > 0)
        total_write += wr;
    }
    if (filename_len != total_write)
      return adc->do_stop = 1;
    total_write = 0;
    wr = 1;
    while ((wr > 0 || errno == EAGAIN) && total_write < sizeof (char))
    {
      wr = GNUNET_DISK_file_write_blocking (adc->progress_write,
        &((char *)&is_directory)[total_write], sizeof (char) - total_write);
      if (wr > 0)
        total_write += wr;
    }
    if (sizeof (char) != total_write)
      return adc->do_stop = 1;
  }
  return 0;
}

/**
 * Add the given keyword to the
 * keyword statistics tracker.
 *
 * @param cls closure (user-defined)
 * @param keyword the keyword to count
 * @param is_mandatory ignored
 * @return always GNUNET_OK
 */
static int
add_to_keyword_counter (void *cls, const char *keyword, int is_mandatory)
{
  struct GNUNET_CONTAINER_MultiHashMap *mcm = cls;
  struct KeywordCounter *cnt, *first_cnt;
  GNUNET_HashCode hc;
  size_t klen;

  klen = strlen (keyword) + 1;
  GNUNET_CRYPTO_hash (keyword, klen - 1, &hc);
  /* Since the map might contain multiple values per keyword, we only
   * store one value, and attach all other to it, forming a linked list.
   * Somewhat easier than retrieving multiple items via callback.
   */
  first_cnt = GNUNET_CONTAINER_multihashmap_get (mcm, &hc);
  for (cnt = first_cnt; cnt && strcmp (cnt->value, keyword) != 0; cnt = cnt->next);
  if (cnt == NULL)
  {
    cnt = GNUNET_malloc (sizeof (struct KeywordCounter) + klen);
    cnt->value = (const char *) &cnt[1];
    memcpy (&cnt[1], keyword, klen);
    if (first_cnt != NULL)
    {
      if (first_cnt->prev != NULL)
      {
        first_cnt->prev->next = cnt;
        cnt->prev = first_cnt->prev;
      }
      first_cnt->prev = cnt;
      cnt->next = first_cnt;
    }
    else
      GNUNET_CONTAINER_multihashmap_put (mcm, &hc, cnt,
          GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  }
  cnt->count++;
  return GNUNET_OK;
}

/**
 * Type of a function that libextractor calls for each
 * meta data item found.
 *
 * @param cls the container multihashmap to update
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
 * @return GNUNET_OK to continue extracting / iterating
 */
static int
add_to_meta_counter (void *cls, const char *plugin_name,
                enum EXTRACTOR_MetaType type, enum EXTRACTOR_MetaFormat format,
                const char *data_mime_type, const char *data, size_t data_len)
{
  struct GNUNET_CONTAINER_MultiHashMap *map = cls;
  GNUNET_HashCode key;
  struct MetaCounter *cnt, *first_cnt;

  GNUNET_CRYPTO_hash (data, data_len, &key);
  first_cnt = GNUNET_CONTAINER_multihashmap_get (map, &key);
  for (cnt = first_cnt; cnt
      && cnt->data_size != data_len
      && memcmp (cnt->data, data, cnt->data_size) != 0; cnt = cnt->next);
  if (cnt == NULL)
  {
    cnt = GNUNET_malloc (sizeof (struct MetaCounter));
    cnt->data = data;
    cnt->data_size = data_len;
    cnt->plugin_name = plugin_name;
    cnt->type = type;
    cnt->format = format;
    cnt->data_mime_type = data_mime_type;

    if (first_cnt != NULL)
    {
      if (first_cnt->prev != NULL)
      {
        first_cnt->prev->next = cnt;
        cnt->prev = first_cnt->prev;
      }
      first_cnt->prev = cnt;
      cnt->next = first_cnt;
    }
    else
      GNUNET_CONTAINER_multihashmap_put (map, &key, cnt,
          GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  }
  cnt->count++;
  return 0;
}

/**
 * Allocates a struct GNUNET_FS_ShareTreeItem and adds it to its parent.
 */
static struct GNUNET_FS_ShareTreeItem *
make_item (struct GNUNET_FS_ShareTreeItem *parent)
{
  struct GNUNET_FS_ShareTreeItem *item;
  item = GNUNET_malloc (sizeof (struct GNUNET_FS_ShareTreeItem));

  item->parent = parent;
  if (parent)
    GNUNET_CONTAINER_DLL_insert (parent->children_head, parent->children_tail,
        item);
  return item;
}

/**
 * Extract metadata from a file and add it to the share tree
 *
 * @param ads context to modify
 * @param filename name of the file to process
 */
static void
extract_file (struct AddDirStack *ads, const char *filename)
{
  struct GNUNET_FS_ShareTreeItem *item;
  const char *short_fn;

  item = make_item (ads->parent);

  GNUNET_DISK_file_size (filename, &item->file_size, GNUNET_YES);
  item->is_directory = GNUNET_NO;

  item->meta = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_FS_meta_data_extract_from_file (item->meta, filename,
      ads->adc->plugins);
  GNUNET_CONTAINER_meta_data_delete (item->meta, EXTRACTOR_METATYPE_FILENAME,
      NULL, 0);
  short_fn = GNUNET_STRINGS_get_short_name (filename);

  item->filename = GNUNET_strdup (filename);
  item->short_filename = GNUNET_strdup (short_fn);

  GNUNET_CONTAINER_meta_data_insert (item->meta, "<libgnunetfs>",
                                     EXTRACTOR_METATYPE_FILENAME,
                                     EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                     short_fn, strlen (short_fn) + 1);
  if (ads->parent == NULL)
  {
    /* we're finished with the scan, make sure caller gets the top-level
     * directory pointer
     */
    ads->adc->toplevel = item;
  }
}

/**
 * Remove the keyword from the ksk URI.
 *
 * @param cls the ksk uri
 * @param keyword the word to remove
 * @param is_mandatory ignored
 * @return always GNUNET_OK
 */
static int
remove_keyword (void *cls, const char *keyword, int is_mandatory)
{
  struct GNUNET_FS_Uri *ksk = cls;

  GNUNET_FS_uri_ksk_remove_keyword (ksk, keyword);
  return GNUNET_OK;
}

/**
 * Remove keywords from current directory's children, if they are
 * in the exluded keywords list of that directory.
 *
 * @param cls the ksk uri
 * @param keyword the word to remove
 * @param is_mandatory ignored
 * @return always GNUNET_OK
 */
static int
remove_keywords (struct ProcessMetadataStackItem *stack, struct GNUNET_FS_ShareTreeItem *dir)
{
  struct GNUNET_FS_ShareTreeItem *item;

  for (item = dir->children_head; item; item = item->next)
  {
    if (stack->exclude_ksk != NULL)
      GNUNET_FS_uri_ksk_get_keywords (stack->exclude_ksk, &remove_keyword, item->ksk_uri);
  }
  return GNUNET_OK;
}

/**
 * Context passed to 'migrate_and_drop'.
 */
struct KeywordProcessContext
{
  /**
   * All the keywords we migrated to the parent.
   */
  struct GNUNET_FS_Uri *ksk;

  /**
   * How often does a keyword have to occur to be
   * migrated to the parent?
   */
  unsigned int threshold;
};

/**
 * Context passed to 'migrate_and_drop'.
 */
struct MetaProcessContext
{
  /**
   * All the metadata we copy to the parent.
   */
  struct GNUNET_CONTAINER_MetaData *meta;

  /**
   * How often does a metadata have to occur to be
   * migrated to the parent?
   */
  unsigned int threshold;
};


/**
 * Move "frequent" keywords over to the
 * target ksk uri, free the counters.
 *
 */
static int
migrate_and_drop (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct KeywordProcessContext *kpc = cls;
  struct KeywordCounter *counter = value;

  if (counter->count >= kpc->threshold && counter->count > 1)
  {
    GNUNET_FS_uri_ksk_add_keyword (kpc->ksk, counter->value, GNUNET_NO);
  }
  GNUNET_free (counter);
  return GNUNET_YES;
}
/**
 * Copy "frequent" metadata items over to the
 * target metadata container, free the counters.
 *
 */
static int
migrate_and_drop_metadata (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct MetaProcessContext *mpc = cls;
  struct MetaCounter *counter = value;

  if (counter->count >= mpc->threshold && counter->count > 1)
  {
    GNUNET_CONTAINER_meta_data_insert (mpc->meta,
                                   counter->plugin_name,
                                   counter->type,
                                   counter->format,
                                   counter->data_mime_type, counter->data,
                                   counter->data_size);
  }
  GNUNET_free (counter);
  return GNUNET_YES;
}

/**
 * Go over the collected keywords from all entries in the
 * directory and push common keywords up one level (by
 * adding it to the returned struct). Do the same for metadata.
 * Destroys keywordcounter and metacoutner for current directory.
 *
 * @param adc collection of child meta data
 * @param exclude_ksk pointer to where moveable keywords will be stored
 * @param copy_meta pointer to where copyable metadata will be stored
 */
static void
process_keywords_and_metadata (struct ProcessMetadataStackItem *stack,
    struct GNUNET_FS_Uri **exclude_ksk,
    struct GNUNET_CONTAINER_MetaData **copy_meta)
{
  struct KeywordProcessContext kpc;
  struct MetaProcessContext mpc;
  struct GNUNET_CONTAINER_MetaData *tmp;

  /* Surprisingly, it's impossible to create a ksk with 0 keywords directly.
   * But we can create one from an empty metadata set
   */
  tmp = GNUNET_CONTAINER_meta_data_create ();
  kpc.ksk = GNUNET_FS_uri_ksk_create_from_meta_data (tmp);
  GNUNET_CONTAINER_meta_data_destroy (tmp);
  mpc.meta = GNUNET_CONTAINER_meta_data_create ();

  kpc.threshold = mpc.threshold = (stack->dir_entry_count + 1) / 2; /* 50% */

  GNUNET_CONTAINER_multihashmap_iterate (stack->keywordcounter,
      &migrate_and_drop, &kpc);
  GNUNET_CONTAINER_multihashmap_iterate (stack->metacounter,
      &migrate_and_drop_metadata, &mpc);

  GNUNET_CONTAINER_multihashmap_destroy (stack->keywordcounter);
  GNUNET_CONTAINER_multihashmap_destroy (stack->metacounter);
  *exclude_ksk = kpc.ksk;
  *copy_meta = mpc.meta;
}

/**
 * Function called by the directory iterator to
 * (recursively) add all of the files in the
 * directory to the tree.
 * Called by the directory scanner to initiate the
 * scan.
 * TODO: find a way to make it non-recursive.
 *
 * @param cls the 'struct AddDirStack *' we're in
 * @param filename file or directory to scan
 */
static int
scan_directory (void *cls, const char *filename)
{
  struct AddDirStack *ads = cls, recurse_ads;
  struct AddDirContext *adc = ads->adc;
  struct stat sbuf;
  struct GNUNET_FS_ShareTreeItem *item;
  const char *short_fn;
  int do_stop = 0;

  /* Wrap up fast */
  if (adc->do_stop)
    return GNUNET_SYSERR;

  /* If the file doesn't exist (or is not statable for any other reason,
   * skip it, and report it.
   */
  if (0 != STAT (filename, &sbuf))
  {
    do_stop = write_progress (adc, filename, S_ISDIR (sbuf.st_mode),
      GNUNET_DIR_SCANNER_DOES_NOT_EXIST);
    if (do_stop)
      return GNUNET_SYSERR;
    return GNUNET_OK;
  }

  /* Report the progress */
  do_stop = write_progress (adc, filename, S_ISDIR (sbuf.st_mode),
    GNUNET_DIR_SCANNER_NEW_FILE);
  if (do_stop)
  {
    /* We were asked to stop, acknowledge that and return */
    (void) write_progress (adc, filename, S_ISDIR (sbuf.st_mode),
      GNUNET_DIR_SCANNER_ASKED_TO_STOP);
    return GNUNET_SYSERR;
  }

  if (!S_ISDIR (sbuf.st_mode))
    extract_file (ads, filename);
  else
  {
    item = make_item (ads->parent);
    item->meta = GNUNET_CONTAINER_meta_data_create ();

    item->is_directory = GNUNET_YES;

    recurse_ads.adc = adc;
    recurse_ads.parent = item;

    /* recurse into directory */
    GNUNET_DISK_directory_scan (filename, &scan_directory, &recurse_ads);

    short_fn = GNUNET_STRINGS_get_short_name (filename);

    item->filename = GNUNET_strdup (filename);
    item->short_filename = GNUNET_strdup (short_fn);

    if (ads->parent == NULL)
    {
      /* we're finished with the scan, make sure caller gets the top-level
       * directory pointer
       */
      adc->toplevel = item;
    }
  }
  return GNUNET_OK;
}

/**
 * Signals the scanner to finish the scan as fast as possible.
 * Does not block.
 * Can close the pipe if asked to, but that is only used by the
 * internal call to this function during cleanup. The client
 * must understand the consequences of closing the pipe too early.
 *
 * @param ds directory scanner structure
 * @param close_pipe GNUNET_YES to close
 */
void
GNUNET_FS_directory_scan_finish (struct GNUNET_FS_DirScanner *ds,
    int close_pipe)
{
  char c = 1;
  GNUNET_DISK_file_write (ds->stop_write, &c, 1);

  if (close_pipe)
  {
    if (ds->progress_read_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (ds->progress_read_task);
      ds->progress_read_task = GNUNET_SCHEDULER_NO_TASK;
    }
    GNUNET_DISK_pipe_close_end (ds->progress_pipe, GNUNET_DISK_PIPE_END_READ);
    ds->progress_read = NULL;
  }
}

/**
 * Signals the scanner thread to finish (in case it isn't finishing
 * already) and joins the scanner thread. Closes the pipes, frees the
 * scanner contexts (both of them), returns the results of the scan.
 * Results are valid (and have to be freed) even if the scanner had
 * an error or was rushed to finish prematurely.
 * Blocks until the scanner is finished.
 *
 * @param ds directory scanner structure
 * @return the results of the scan (a directory tree)
 */
struct GNUNET_FS_ShareTreeItem *
GNUNET_FS_directory_scan_cleanup (struct GNUNET_FS_DirScanner *ds)
{
  struct GNUNET_FS_ShareTreeItem *result;

  GNUNET_FS_directory_scan_finish (ds, GNUNET_YES);
#if WINDOWS
  WaitForSingleObject (ds->thread, INFINITE);
  CloseHandle (ds->thread);
#else
  pthread_join (ds->thread, NULL);
  pthread_detach (ds->thread);
#endif

  GNUNET_DISK_pipe_close (ds->stop_pipe);
  GNUNET_DISK_pipe_close (ds->progress_pipe);
  result = ds->adc->toplevel;
  GNUNET_free (ds->adc);
  GNUNET_free (ds);
  return result;
}

/**
 * The function from which the scanner thread starts
 */
#if WINDOWS
DWORD
#else
static void *
#endif
run_directory_scan_thread (void *cls)
{
  struct AddDirContext *adc = cls;
  struct AddDirStack ads;
  ads.adc = adc;
  ads.parent = NULL;
  scan_directory (&ads, adc->filename_expanded);
  GNUNET_free (adc->filename_expanded);
  if (adc->plugins != NULL)
    EXTRACTOR_plugin_remove_all (adc->plugins);
  /* Tell the initiator that we're finished, it can now join the thread */
  write_progress (adc, NULL, 0, GNUNET_DIR_SCANNER_FINISHED);
  return 0;
}

/**
 * Called every time there is data to read from the scanner.
 * Calls the scanner progress handler.
 *
 * @param cls the closure (directory scanner object)
 * @param tc task context in which the task is running
 */
static void
read_progress_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_DirScanner *ds;
  int end_it = 0;
  enum GNUNET_FS_DirScannerProgressUpdateReason reason;
  ssize_t rd;
  ssize_t total_read;

  size_t filename_len;
  char is_directory;
  char *filename;

  ds = cls;

  ds->progress_read_task = GNUNET_SCHEDULER_NO_TASK;

  if (!(tc->reason & GNUNET_SCHEDULER_REASON_READ_READY))
  {
    ds->progress_callback (ds->cls, ds, NULL, 0, GNUNET_DIR_SCANNER_SHUTDOWN);
    return;
  }

  /* Read one message. If message is malformed or can't be read, end the scanner */
  total_read = rd = GNUNET_DISK_file_read (ds->progress_read, &reason, sizeof (reason));
  while (rd > 0 && total_read < sizeof (reason))
  {
    rd = GNUNET_DISK_file_read (ds->progress_read,
        &((char *) &reason)[total_read],
        sizeof (reason) - total_read);
    if (rd > 0)
      total_read += rd;
  }
  if (total_read != sizeof (reason)
      || reason <= GNUNET_DIR_SCANNER_FIRST
      || reason >= GNUNET_DIR_SCANNER_LAST)
  {
    end_it = 1;
    reason = GNUNET_DIR_SCANNER_PROTOCOL_ERROR;
  }

  if (!end_it)
  {
    total_read = rd = GNUNET_DISK_file_read (ds->progress_read, &filename_len,
        sizeof (size_t));
    while (rd > 0 && total_read < sizeof (size_t))
    {
      rd = GNUNET_DISK_file_read (ds->progress_read,
          &((char *) &filename_len)[total_read],
          sizeof (size_t) - total_read);
      if (rd > 0)
        total_read += rd;
    }
    if (rd != sizeof (size_t))
    {
      end_it = 1;
      reason = GNUNET_DIR_SCANNER_PROTOCOL_ERROR;
    }
  }
  if (!end_it)
  {
    if (filename_len == 0)
      end_it = 1;
    else if (filename_len > PATH_MAX)
    {
      end_it = 1;
      reason = GNUNET_DIR_SCANNER_PROTOCOL_ERROR;
    }
  }
  if (!end_it)
  {
    filename = GNUNET_malloc (filename_len);
    total_read = rd = GNUNET_DISK_file_read (ds->progress_read, filename,
        filename_len);
    while (rd > 0 && total_read < filename_len)
    {
      rd = GNUNET_DISK_file_read (ds->progress_read, &filename[total_read],
          filename_len - total_read);
      if (rd > 0)
        total_read += rd;
    }
    if (rd != filename_len)
    {
      GNUNET_free (filename);
      reason = GNUNET_DIR_SCANNER_PROTOCOL_ERROR;
      end_it = 1;
    }
  }
  if (!end_it && filename_len > 0)
  {
    total_read = rd = GNUNET_DISK_file_read (ds->progress_read, &is_directory,
        sizeof (char));
    while (rd > 0 && total_read < sizeof (char))
    {
      rd = GNUNET_DISK_file_read (ds->progress_read, &(&is_directory)[total_read],
          sizeof (char) - total_read);
      if (rd > 0)
        total_read += rd;
    }
    if (rd != sizeof (char))
    {
      GNUNET_free (filename);
      reason = GNUNET_DIR_SCANNER_PROTOCOL_ERROR;
      end_it = 1;
    }
  }
  if (!end_it)
  {
    end_it = ds->progress_callback (ds->cls, ds, (const char *) filename, is_directory, reason);
    GNUNET_free (filename);
    if (!end_it)
    {
      ds->progress_read_task = GNUNET_SCHEDULER_add_read_file (
          GNUNET_TIME_UNIT_FOREVER_REL, ds->progress_read, &read_progress_task,
          cls);
    }
  }
  else
  {
    ds->progress_callback (ds->cls, ds, NULL, 0, reason);
  }
}


/**
 * Start a directory scanner thread.
 *
 * @param filename name of the directory to scan
 * @param GNUNET_YES to not to run libextractor on files (only build a tree)
 * @param ex if not NULL, must be a list of extra plugins for extractor
 * @param cb the callback to call when there are scanning progress messages
 * @param cls closure for 'cb'
 * @return directory scanner object to be used for controlling the scanner
 */
struct GNUNET_FS_DirScanner *
GNUNET_FS_directory_scan_start (const char *filename,
    int disable_extractor, const char *ex,
    GNUNET_FS_DirScannerProgressCallback cb, void *cls)
{
  struct stat sbuf;
  struct AddDirContext *adc;
  char *filename_expanded;
  struct GNUNET_FS_DirScanner *ds;
  struct GNUNET_DISK_PipeHandle *progress_pipe;
  int ok;

  if (0 != STAT (filename, &sbuf))
    return NULL;

  /* scan_directory() is guaranteed to be given expanded filenames,
   * so expand we will!
   */
  filename_expanded = GNUNET_STRINGS_filename_expand (filename);
  if (filename_expanded == NULL)
    return NULL;

  progress_pipe = GNUNET_DISK_pipe (GNUNET_NO, GNUNET_NO, GNUNET_NO, GNUNET_NO);
  if (progress_pipe == NULL)
  {
    GNUNET_free (filename_expanded);
    return NULL;
  }

  adc = GNUNET_malloc (sizeof (struct AddDirContext));

  ds = GNUNET_malloc (sizeof (struct GNUNET_FS_DirScanner));

  ds->adc = adc;

  ds->stop_pipe = GNUNET_DISK_pipe (GNUNET_NO, GNUNET_NO, GNUNET_NO, GNUNET_NO);
  if (ds->stop_pipe == NULL)
  {
    GNUNET_free (adc);
    GNUNET_free (ds);
    GNUNET_free (filename_expanded);
    GNUNET_DISK_pipe_close (progress_pipe);
    return NULL;
  }
  ds->stop_write = GNUNET_DISK_pipe_handle (ds->stop_pipe,
      GNUNET_DISK_PIPE_END_WRITE);
  adc->stop_read = GNUNET_DISK_pipe_handle (ds->stop_pipe,
      GNUNET_DISK_PIPE_END_READ);

  adc->plugins = NULL;
  if (!disable_extractor)
  {
    adc->plugins = EXTRACTOR_plugin_add_defaults (
        EXTRACTOR_OPTION_DEFAULT_POLICY);
    if (ex && strlen (ex) > 0)
      adc->plugins = EXTRACTOR_plugin_add_config (adc->plugins, ex,
          EXTRACTOR_OPTION_DEFAULT_POLICY);
  }

  adc->filename_expanded = filename_expanded;
  adc->progress_write = GNUNET_DISK_pipe_handle (progress_pipe,
      GNUNET_DISK_PIPE_END_WRITE);


  ds->progress_read = GNUNET_DISK_pipe_handle (progress_pipe,
      GNUNET_DISK_PIPE_END_READ);

#if WINDOWS
  ds->thread = CreateThread (NULL, 0,
      (LPTHREAD_START_ROUTINE) &run_directory_scan_thread, (LPVOID) adc,
      0, NULL);
  ok = ds->thread != NULL;
#else
  ok = !pthread_create (&ds->thread, NULL, &run_directory_scan_thread,
      (void *) adc);
#endif
  if (!ok)
  {
    GNUNET_free (adc);
    GNUNET_free (filename_expanded);
    GNUNET_DISK_pipe_close (progress_pipe);
    GNUNET_free (ds);
    return NULL;
  }

  ds->progress_callback = cb;
  ds->cls = cls;
  ds->adc = adc;
  ds->progress_pipe = progress_pipe;

  ds->progress_read_task = GNUNET_SCHEDULER_add_read_file (
      GNUNET_TIME_UNIT_FOREVER_REL, ds->progress_read, &read_progress_task,
      ds);

  return ds;
}

/**
 * Task that post-processes the share item tree.
 * This processing has to be done in the main thread, because
 * it requires access to libgcrypt's hashing functions, and
 * libgcrypt is not thread-safe without some special magic.
 *
 * @param cls top of the stack
 * @param tc task context
 */
static void
trim_share_tree_task (void *cls,
  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ProcessMetadataStackItem *stack = cls;
  struct ProcessMetadataStackItem *next = stack;
  /* FIXME: figure out what to do when tc says we're shutting down */

  /* item == NULL means that we've just finished going over the children of
   * current directory.
   */
  if (stack->item == NULL)
  {
    if (stack->parent->item != NULL)
    {
      /* end of a directory */
      struct GNUNET_FS_Uri *ksk;

      /* use keyword and metadata counters to create lists of keywords to move
       * and metadata to copy.
       */
      process_keywords_and_metadata (stack, &stack->parent->exclude_ksk, &stack->parent->item->meta);

      /* create keywords from metadata (copies all text-metadata as keywords,
       * AND parses the directory name we've just added, producing even more
       * keywords.
       * then merge these keywords with the ones moved from children.
       */
      ksk = GNUNET_FS_uri_ksk_create_from_meta_data (stack->parent->item->meta);
      stack->parent->item->ksk_uri = GNUNET_FS_uri_ksk_merge (ksk, stack->parent->exclude_ksk);
      GNUNET_FS_uri_destroy (ksk);

      /* remove moved keywords from children (complete the move) */
      remove_keywords (stack->parent, stack->parent->item);
      GNUNET_FS_uri_destroy (stack->parent->exclude_ksk);

      /* go up the stack */
      next = stack->parent;
      GNUNET_free (stack);
      next->end_directory = GNUNET_YES;
    }
    else
    {
      /* we've just finished processing the toplevel directory */
      struct GNUNET_FS_ProcessMetadataContext *ctx = stack->ctx;
      next = NULL;
      GNUNET_SCHEDULER_add_continuation (ctx->cb, ctx->cls,
          GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      GNUNET_free (stack->parent);
      GNUNET_free (stack);
      GNUNET_free (ctx);
    }
  }
  else if (stack->item->is_directory
      && !stack->end_directory
      && stack->item->children_head != NULL)
  {
    /* recurse into subdirectory */
    next = GNUNET_malloc (sizeof (struct ProcessMetadataStackItem));
    next->ctx = stack->ctx;
    next->item = stack->item->children_head;
    next->keywordcounter = GNUNET_CONTAINER_multihashmap_create (1024);
    next->metacounter = GNUNET_CONTAINER_multihashmap_create (1024);
    next->dir_entry_count = 0;
    next->parent = stack;
  }
  else
  {
    /* process a child entry (a file or a directory) and move to the next one*/
    if (stack->item->is_directory)
      stack->end_directory = GNUNET_NO;
    if (stack->ctx->toplevel->is_directory)
    {
      stack->dir_entry_count++;
      GNUNET_CONTAINER_meta_data_iterate (stack->item->meta, &add_to_meta_counter, stack->metacounter);

      if (stack->item->is_directory)
      {
        char *user = getenv ("USER");
        if ((user == NULL) || (0 != strncasecmp (user, stack->item->short_filename, strlen(user))))
        {
          /* only use filename if it doesn't match $USER */
          GNUNET_CONTAINER_meta_data_insert (stack->item->meta, "<libgnunetfs>",
					     EXTRACTOR_METATYPE_FILENAME,
					     EXTRACTOR_METAFORMAT_UTF8,
					     "text/plain", stack->item->short_filename,
					     strlen (stack->item->short_filename) + 1);
          GNUNET_CONTAINER_meta_data_insert (stack->item->meta, "<libgnunetfs>",
					     EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME,
					     EXTRACTOR_METAFORMAT_UTF8,
					     "text/plain", stack->item->short_filename,
					     strlen (stack->item->short_filename) + 1);
        }
      }
    }
    stack->item->ksk_uri = GNUNET_FS_uri_ksk_create_from_meta_data (stack->item->meta);
    if (stack->ctx->toplevel->is_directory)
    {
      GNUNET_FS_uri_ksk_get_keywords (stack->item->ksk_uri, &add_to_keyword_counter, stack->keywordcounter);
    }
    stack->item = stack->item->next;
  }
  /* Call this task again later, if there are more entries to process */
  if (next)
    GNUNET_SCHEDULER_add_continuation (&trim_share_tree_task, next,
        GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}

/**
 * Process a share item tree, moving frequent keywords up and
 * copying frequent metadata up.
 *
 * @param toplevel toplevel directory in the tree, returned by the scanner
 * @param cb called after processing is done
 * @param cls closure for 'cb'
 */
struct GNUNET_FS_ProcessMetadataContext *
GNUNET_FS_trim_share_tree (struct GNUNET_FS_ShareTreeItem *toplevel,
    GNUNET_SCHEDULER_Task cb, void *cls)
{
  struct GNUNET_FS_ProcessMetadataContext *ret;

  if (toplevel == NULL)
  {
    struct GNUNET_SCHEDULER_TaskContext tc;
    tc.reason = GNUNET_SCHEDULER_REASON_PREREQ_DONE;
    cb (cls, &tc);
    return NULL;
  }

  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_ProcessMetadataContext));
  ret->toplevel = toplevel;
  ret->stack = GNUNET_malloc (sizeof (struct ProcessMetadataStackItem));
  ret->stack->ctx = ret;
  ret->stack->item = toplevel;

  if (ret->stack->ctx->toplevel->is_directory)
  {
    ret->stack->keywordcounter = GNUNET_CONTAINER_multihashmap_create (1024);
    ret->stack->metacounter = GNUNET_CONTAINER_multihashmap_create (1024);
  }

  ret->stack->dir_entry_count = 0;
  ret->stack->end_directory = GNUNET_NO;

  /* dummy stack entry that tells us we're at the top of the stack */
  ret->stack->parent = GNUNET_malloc (sizeof (struct ProcessMetadataStackItem));
  ret->stack->parent->ctx = ret;

  ret->cb = cb;
  ret->cls = cls;

  GNUNET_SCHEDULER_add_continuation (&trim_share_tree_task, ret->stack,
    GNUNET_SCHEDULER_REASON_PREREQ_DONE);
  return ret;
}
