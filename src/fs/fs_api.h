/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_api.h
 * @brief shared definitions for the FS library
 * @author Igor Wronsky, Christian Grothoff
 */
#ifndef FS_API_H
#define FS_API_H

#include "gnunet_constants.h"
#include "gnunet_datastore_service.h"
#include "gnunet_dht_service.h"
#include "gnunet_fs_service.h"
#include "gnunet_block_lib.h"
#include "block_fs.h"
#include "fs.h"

/**
 * Size of the individual blocks used for file-sharing.
 */
#define DBLOCK_SIZE (32*1024)

/**
 * Pick a multiple of 2 here to achive 8-byte alignment!  We also
 * probably want DBlocks to have (roughly) the same size as IBlocks.
 * With SHA-512, the optimal value is 32768 byte / 128 byte = 256 (128
 * byte = 2 * 512 bits).  DO NOT CHANGE!
 */
#define CHK_PER_INODE 256

/**
 * Maximum size for a file to be considered for inlining in a
 * directory.
 */
#define MAX_INLINE_SIZE 65536

/**
 * Name of the directory with top-level searches.
 */
#define GNUNET_FS_SYNC_PATH_MASTER_SEARCH "search"

/**
 * Name of the directory with sub-searches (namespace-updates).
 */
#define GNUNET_FS_SYNC_PATH_CHILD_SEARCH "search-child"

/**
 * Name of the directory with master downloads (not associated
 * with search or part of another download).
 */
#define GNUNET_FS_SYNC_PATH_MASTER_DOWNLOAD "download"

/**
 * Name of the directory with downloads that are part of another
 * download or a search.
 */
#define GNUNET_FS_SYNC_PATH_CHILD_DOWNLOAD "download-child"

/**
 * Name of the directory with publishing operations.
 */
#define GNUNET_FS_SYNC_PATH_MASTER_PUBLISH "publish"

/**
 * Name of the directory with files that are being published
 */
#define GNUNET_FS_SYNC_PATH_FILE_INFO "publish-file"

/**
 * Name of the directory with unindex operations.
 */
#define GNUNET_FS_SYNC_PATH_MASTER_UNINDEX "unindex"


/**
 * @brief complete information needed
 * to download a file.
 */
struct FileIdentifier
{

  /**
   * Total size of the file in bytes. (network byte order (!))
   */
  uint64_t file_length;

  /**
   * Query and key of the top GNUNET_EC_IBlock.
   */
  struct ContentHashKey chk;

};


/**
 * Information about a file and its location
 * (peer claiming to share the file).
 */
struct Location
{
  /**
   * Information about the shared file.
   */
  struct FileIdentifier fi;

  /**
   * Identity of the peer sharing the file.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded peer;

  /**
   * Time when this location URI expires.
   */
  struct GNUNET_TIME_Absolute expirationTime;

  /**
   * RSA signature over the GNUNET_EC_FileIdentifier,
   * GNUNET_hash of the peer and expiration time.
   */
  struct GNUNET_CRYPTO_RsaSignature contentSignature;

};

/**
 * Types of URIs.
 */
enum uri_types
{
    /**
     * Content-hash-key (simple file).
     */
  chk,

    /**
     * Signed key space (file in namespace).
     */
  sks,

    /**
     * Keyword search key (query with keywords).
     */
  ksk,

    /**
     * Location (chk with identity of hosting peer).
     */
  loc
};

/**
 * A Universal Resource Identifier (URI), opaque.
 */
struct GNUNET_FS_Uri
{
  /**
   * Type of the URI.
   */
  enum uri_types type;

  union
  {
    struct
    {
      /**
       * Keywords start with a '+' if they are
       * mandatory (in which case the '+' is NOT
       * part of the keyword) and with a
       * simple space if they are optional
       * (in which case the space is ALSO not
       * part of the actual keyword).
       *
       * Double-quotes to protect spaces and
       * %-encoding are NOT used internally
       * (only in URI-strings).
       */
      char **keywords;

      /**
       * Size of the keywords array.
       */
      unsigned int keywordCount;
    } ksk;

    struct
    {
      /**
       * Hash of the public key for the namespace.
       */
      GNUNET_HashCode namespace;

      /**
       * Human-readable identifier chosen for this
       * entry in the namespace.
       */
      char *identifier;
    } sks;

    /**
     * Information needed to retrieve a file (content-hash-key
     * plus file size).
     */
    struct FileIdentifier chk;

    /**
     * Information needed to retrieve a file including signed
     * location (identity of a peer) of the content.
     */
    struct Location loc;
  } data;

};


/**
 * Information for a file or directory that is
 * about to be published.
 */
struct GNUNET_FS_FileInformation
{

  /**
   * Files in a directory are kept as a linked list.
   */
  struct GNUNET_FS_FileInformation *next;

  /**
   * If this is a file in a directory, "dir" refers to
   * the directory; otherwise NULL.
   */
  struct GNUNET_FS_FileInformation *dir;

  /**
   * Handle to the master context.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * Pointer kept for the client.
   */
  void *client_info;

  /**
   * Metadata to use for the file.
   */
  struct GNUNET_CONTAINER_MetaData *meta;

  /**
   * Keywords to use for KBlocks.
   */
  struct GNUNET_FS_Uri *keywords;

  /**
   * CHK for this file or directory. NULL if
   * we have not yet computed it.
   */
  struct GNUNET_FS_Uri *chk_uri;

  /**
   * Block options for the file.
   */
  struct GNUNET_FS_BlockOptions bo;

  /**
   * At what time did we start this upload?
   */
  struct GNUNET_TIME_Absolute start_time;

  /**
   * Under what filename is this struct serialized
   * (for operational persistence).  Should be determined
   * using 'mktemp'.
   */
  char *serialization;

  /**
   * Encoder being used to publish this file.
   */
  struct GNUNET_FS_TreeEncoder *te;

  /**
   * Error message (non-NULL if this operation failed).
   */
  char *emsg;

  /**
   * Name of the file or directory (must be an absolute path).
   */
  char *filename;

  /**
   * Data describing either the file or the directory.
   */
  union
  {

    /**
     * Data for a file.
     */
    struct
    {

      /**
       * Function that can be used to read the data for the file.
       */
      GNUNET_FS_DataReader reader;

      /**
       * Closure for reader.
       */
      void *reader_cls;

      /**
       * If this file is being indexed, this value is set to the hash
       * over the entire file (when the indexing process is started).
       * Otherwise this field is not used.
       */
      GNUNET_HashCode file_id;

      /**
       * Size of the file (in bytes).
       */
      uint64_t file_size;

      /**
       * Should the file be indexed or inserted?
       */
      int do_index;

      /**
       * Is "file_id" already valid?  Set to GNUNET_YES once the hash
       * has been calculated.
       */
      int have_hash;

      /**
       * Has the service confirmed our INDEX_START request?
       * GNUNET_YES if this step has been completed.
       */
      int index_start_confirmed;

    } file;

    /**
     * Data for a directory.
     */
    struct
    {

      /**
       * Linked list of entries in the directory.
       */
      struct GNUNET_FS_FileInformation *entries;

      /**
       * Size of the directory itself (in bytes); 0 if the
       * size has not yet been calculated.
       */
      size_t dir_size;

      /**
       * Pointer to the data for the directory (or NULL if not
       * available).
       */
      void *dir_data;

    } dir;

  } data;

  /**
   * Is this struct for a file or directory?
   */
  int is_directory;

  /**
   * Are we done publishing this file?
   */
  int is_published;

};


/**
 * The job is now ready to run and should use the given client
 * handle to communicate with the FS service.
 *
 * @param cls closure
 * @param client handle to use for FS communication
 */
typedef void (*GNUNET_FS_QueueStart) (void *cls,
                                      struct GNUNET_CLIENT_Connection * client);


/**
 * The job must now stop to run and should destry the client handle as
 * soon as possible (ideally prior to returning).
 */
typedef void (*GNUNET_FS_QueueStop) (void *cls);



/**
 * Priorities for the queue.
 */ 
enum GNUNET_FS_QueuePriority
  {
    /**
     * This is a probe (low priority).
     */
    GNUNET_FS_QUEUE_PRIORITY_PROBE,

    /**
     * Default priority.
     */
    GNUNET_FS_QUEUE_PRIORITY_NORMAL
  };


/**
 * Entry in the job queue.
 */
struct GNUNET_FS_QueueEntry
{
  /**
   * This is a linked list.
   */
  struct GNUNET_FS_QueueEntry *next;

  /**
   * This is a linked list.
   */
  struct GNUNET_FS_QueueEntry *prev;

  /**
   * Function to call when the job is started.
   */
  GNUNET_FS_QueueStart start;

  /**
   * Function to call when the job needs to stop (or is done / dequeued).
   */
  GNUNET_FS_QueueStop stop;

  /**
   * Closure for start and stop.
   */
  void *cls;

  /**
   * Handle to FS primary context.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * Client handle, or NULL if job is not running.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Time the job was originally queued.
   */
  struct GNUNET_TIME_Absolute queue_time;

  /**
   * Time the job was started last.
   */
  struct GNUNET_TIME_Absolute start_time;

  /**
   * Total amount of time the job has been running (except for the
   * current run).
   */
  struct GNUNET_TIME_Relative run_time;

  /**
   * How many blocks do the active downloads have?
   */
  unsigned int blocks;

  /**
   * How important is this download?
   */
  enum GNUNET_FS_QueuePriority priority;

  /**
   * How often have we (re)started this download?
   */
  unsigned int start_times;

};




/**
 * Information we store for each search result.
 */
struct GNUNET_FS_SearchResult
{

  /**
   * Search context this result belongs to.
   */
  struct GNUNET_FS_SearchContext *sc;

  /**
   * URI to which this search result refers to.
   */
  struct GNUNET_FS_Uri *uri;

  /**
   * Metadata for the search result.
   */
  struct GNUNET_CONTAINER_MetaData *meta;

  /**
   * Client info for this search result.
   */
  void *client_info;

  /**
   * ID of a job that is currently probing this results' availability
   * (NULL if we are not currently probing).
   */
  struct GNUNET_FS_DownloadContext *probe_ctx;

  /**
   * ID of an associated download based on this search result (or
   * NULL for none).
   */
  struct GNUNET_FS_DownloadContext *download;

  /**
   * If this search result triggered an update search, this field
   * links to the update search.
   */
  struct GNUNET_FS_SearchContext *update_search;

  /**
   * Name under which this search result is stored on disk.
   */
  char *serialization;

  /**
   * Bitmap that specifies precisely which keywords have been matched already.
   */
  uint8_t *keyword_bitmap;

  /**
   * Key for the search result
   */
  GNUNET_HashCode key;

  /**
   * ID of the task that will clean up the probe_ctx should it not
   * complete on time (and that will need to be cancelled if we clean
   * up the search result before then).
   */
  GNUNET_SCHEDULER_TaskIdentifier probe_cancel_task;

  /**
   * When did the current probe become active?
   */
  struct GNUNET_TIME_Absolute probe_active_time;

  /**
   * How much longer should we run the current probe before giving up?
   */
  struct GNUNET_TIME_Relative remaining_probe_time;

  /**
   * Number of mandatory keywords for which we have NOT yet found the
   * search result; when this value hits zero, the search result is
   * given to the callback.
   */
  uint32_t mandatory_missing;

  /**
   * Number of optional keywords under which this result was also
   * found.
   */
  uint32_t optional_support;

  /**
   * Number of availability tests that have succeeded for this result.
   */
  uint32_t availability_success;

  /**
   * Number of availability trials that we have performed for this
   * search result.
   */
  uint32_t availability_trials;

};


/**
 * Add a job to the queue.
 *
 * @param h handle to the overall FS state
 * @param start function to call to begin the job
 * @param stop function to call to pause the job, or on dequeue (if the job was running)
 * @param cls closure for start and stop
 * @param blocks number of blocks this download has
 * @param priority how important is this download
 * @return queue handle
 */
struct GNUNET_FS_QueueEntry *
GNUNET_FS_queue_ (struct GNUNET_FS_Handle *h, GNUNET_FS_QueueStart start,
                  GNUNET_FS_QueueStop stop, void *cls, unsigned int blocks,
		  enum GNUNET_FS_QueuePriority priority);


/**
 * Dequeue a job from the queue.
 * @param qh handle for the job
 */
void
GNUNET_FS_dequeue_ (struct GNUNET_FS_QueueEntry *qh);


/**
 * Function that provides data by reading from a file.
 *
 * @param cls closure (points to the file information)
 * @param offset offset to read from; it is possible
 *            that the caller might need to go backwards
 *            a bit at times
 * @param max maximum number of bytes that should be
 *            copied to buf; readers are not allowed
 *            to provide less data unless there is an error;
 *            a value of "0" will be used at the end to allow
 *            the reader to clean up its internal state
 * @param buf where the reader should write the data
 * @param emsg location for the reader to store an error message
 * @return number of bytes written, usually "max", 0 on error
 */
size_t
GNUNET_FS_data_reader_file_ (void *cls, uint64_t offset, size_t max, void *buf,
                             char **emsg);


/**
 * Create the closure for the 'GNUNET_FS_data_reader_file_' callback.
 *
 * @param filename file to read
 * @return closure to use
 */
void *
GNUNET_FS_make_file_reader_context_ (const char *filename);



/**
 * Function that provides data by copying from a buffer.
 *
 * @param cls closure (points to the buffer)
 * @param offset offset to read from; it is possible
 *            that the caller might need to go backwards
 *            a bit at times
 * @param max maximum number of bytes that should be
 *            copied to buf; readers are not allowed
 *            to provide less data unless there is an error;
 *            a value of "0" will be used at the end to allow
 *            the reader to clean up its internal state
 * @param buf where the reader should write the data
 * @param emsg location for the reader to store an error message
 * @return number of bytes written, usually "max", 0 on error
 */
size_t
GNUNET_FS_data_reader_copy_ (void *cls, uint64_t offset, size_t max, void *buf,
                             char **emsg);

/**
 * Notification of FS that a search probe has made progress.
 * This function is used INSTEAD of the client's event handler
 * for downloads where the GNUNET_FS_DOWNLOAD_IS_PROBE flag is set.
 *
 * @param cls closure, always NULL (!), actual closure
 *        is in the client-context of the info struct
 * @param info details about the event, specifying the event type
 *        and various bits about the event
 * @return client-context (for the next progress call
 *         for this operation; should be set to NULL for
 *         SUSPEND and STOPPED events).  The value returned
 *         will be passed to future callbacks in the respective
 *         field in the GNUNET_FS_ProgressInfo struct.
 */
void *
GNUNET_FS_search_probe_progress_ (void *cls,
                                  const struct GNUNET_FS_ProgressInfo *info);


/**
 * Main function that performs the upload.
 *
 * @param cls "struct GNUNET_FS_PublishContext" identifies the upload
 * @param tc task context
 */
void
GNUNET_FS_publish_main_ (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function called once the hash of the file
 * that is being unindexed has been computed.
 *
 * @param cls closure, unindex context
 * @param file_id computed hash, NULL on error
 */
void
GNUNET_FS_unindex_process_hash_ (void *cls, const GNUNET_HashCode * file_id);


/**
 * Extract the keywords for KBlock removal
 *
 * @param uc context for the unindex operation.
 */
void
GNUNET_FS_unindex_do_extract_keywords_ (struct GNUNET_FS_UnindexContext *uc);


/**
 * If necessary, connect to the datastore and remove the KBlocks.
 *
 * @param uc context for the unindex operation.
 */
void
GNUNET_FS_unindex_do_remove_kblocks_ (struct GNUNET_FS_UnindexContext *uc);


/**
 * Fill in all of the generic fields for a publish event and call the
 * callback.
 *
 * @param pi structure to fill in
 * @param pc overall publishing context
 * @param p file information for the file being published
 * @param offset where in the file are we so far
 * @return value returned from callback
 */
void *
GNUNET_FS_publish_make_status_ (struct GNUNET_FS_ProgressInfo *pi,
                                struct GNUNET_FS_PublishContext *pc,
                                const struct GNUNET_FS_FileInformation *p,
                                uint64_t offset);


/**
 * Fill in all of the generic fields for a download event and call the
 * callback.
 *
 * @param pi structure to fill in
 * @param dc overall download context
 */
void
GNUNET_FS_download_make_status_ (struct GNUNET_FS_ProgressInfo *pi,
                                 struct GNUNET_FS_DownloadContext *dc);


/**
 * Task that creates the initial (top-level) download
 * request for the file.
 *
 * @param cls the 'struct GNUNET_FS_DownloadContext'
 * @param tc scheduler context
 */
void
GNUNET_FS_download_start_task_ (void *cls,
                                const struct GNUNET_SCHEDULER_TaskContext *tc);



/**
 * Fill in all of the generic fields for
 * an unindex event and call the callback.
 *
 * @param pi structure to fill in
 * @param uc overall unindex context
 * @param offset where we are in the file (for progress)
 */
void
GNUNET_FS_unindex_make_status_ (struct GNUNET_FS_ProgressInfo *pi,
                                struct GNUNET_FS_UnindexContext *uc,
                                uint64_t offset);

/**
 * Fill in all of the generic fields for a search event and
 * call the callback.
 *
 * @param pi structure to fill in
 * @param sc overall search context
 * @return value returned by the callback
 */
void *
GNUNET_FS_search_make_status_ (struct GNUNET_FS_ProgressInfo *pi,
                               struct GNUNET_FS_SearchContext *sc);


/**
 * Connect to the datastore and remove the blocks.
 *
 * @param uc context for the unindex operation.
 */
void
GNUNET_FS_unindex_do_remove_ (struct GNUNET_FS_UnindexContext *uc);

/**
 * Build the request and actually initiate the search using the
 * GNUnet FS service.
 *
 * @param sc search context
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_FS_search_start_searching_ (struct GNUNET_FS_SearchContext *sc);

/**
 * Start the downloading process (by entering the queue).
 *
 * @param dc our download context
 */
void
GNUNET_FS_download_start_downloading_ (struct GNUNET_FS_DownloadContext *dc);


/**
 * Start download probes for the given search result.
 *
 * @param sr the search result
 */
void
GNUNET_FS_search_start_probe_ (struct GNUNET_FS_SearchResult *sr);

/**
 * Remove serialization/deserialization file from disk.
 *
 * @param h master context
 * @param ext component of the path
 * @param ent entity identifier
 */
void
GNUNET_FS_remove_sync_file_ (struct GNUNET_FS_Handle *h, const char *ext,
                             const char *ent);


/**
 * Remove serialization/deserialization directory from disk.
 *
 * @param h master context
 * @param ext component of the path
 * @param uni unique name of parent
 */
void
GNUNET_FS_remove_sync_dir_ (struct GNUNET_FS_Handle *h, const char *ext,
                            const char *uni);


/**
 * Synchronize this file-information struct with its mirror
 * on disk.  Note that all internal FS-operations that change
 * file information data should already call "sync" internally,
 * so this function is likely not useful for clients.
 *
 * @param fi the struct to sync
 */
void
GNUNET_FS_file_information_sync_ (struct GNUNET_FS_FileInformation *f);

/**
 * Synchronize this publishing struct with its mirror
 * on disk.  Note that all internal FS-operations that change
 * publishing structs should already call "sync" internally,
 * so this function is likely not useful for clients.
 *
 * @param pc the struct to sync
 */
void
GNUNET_FS_publish_sync_ (struct GNUNET_FS_PublishContext *pc);

/**
 * Synchronize this unindex struct with its mirror
 * on disk.  Note that all internal FS-operations that change
 * publishing structs should already call "sync" internally,
 * so this function is likely not useful for clients.
 *
 * @param uc the struct to sync
 */
void
GNUNET_FS_unindex_sync_ (struct GNUNET_FS_UnindexContext *uc);

/**
 * Synchronize this search struct with its mirror
 * on disk.  Note that all internal FS-operations that change
 * publishing structs should already call "sync" internally,
 * so this function is likely not useful for clients.
 *
 * @param sc the struct to sync
 */
void
GNUNET_FS_search_sync_ (struct GNUNET_FS_SearchContext *sc);

/**
 * Synchronize this search result with its mirror
 * on disk.  Note that all internal FS-operations that change
 * publishing structs should already call "sync" internally,
 * so this function is likely not useful for clients.
 *
 * @param sr the struct to sync
 */
void
GNUNET_FS_search_result_sync_ (struct GNUNET_FS_SearchResult *sr);

/**
 * Synchronize this download struct with its mirror
 * on disk.  Note that all internal FS-operations that change
 * publishing structs should already call "sync" internally,
 * so this function is likely not useful for clients.
 *
 * @param dc the struct to sync
 */
void
GNUNET_FS_download_sync_ (struct GNUNET_FS_DownloadContext *dc);

/**
 * Create SUSPEND event for the given publish operation
 * and then clean up our state (without stop signal).
 *
 * @param cls the 'struct GNUNET_FS_PublishContext' to signal for
 */
void
GNUNET_FS_publish_signal_suspend_ (void *cls);

/**
 * Create SUSPEND event for the given search operation
 * and then clean up our state (without stop signal).
 *
 * @param cls the 'struct GNUNET_FS_SearchContext' to signal for
 */
void
GNUNET_FS_search_signal_suspend_ (void *cls);

/**
 * Create SUSPEND event for the given download operation
 * and then clean up our state (without stop signal).
 *
 * @param cls the 'struct GNUNET_FS_DownloadContext' to signal for
 */
void
GNUNET_FS_download_signal_suspend_ (void *cls);

/**
 * Create SUSPEND event for the given unindex operation
 * and then clean up our state (without stop signal).
 *
 * @param cls the 'struct GNUNET_FS_UnindexContext' to signal for
 */
void
GNUNET_FS_unindex_signal_suspend_ (void *cls);

/**
 * Function signature of the functions that can be called
 * to trigger suspend signals and clean-up for top-level
 * activities.
 *
 * @param cls closure
 */
typedef void (*SuspendSignalFunction) (void *cls);

/**
 * We track all of the top-level activities of FS
 * so that we can signal 'suspend' on shutdown.
 */
struct TopLevelActivity
{
  /**
   * This is a doubly-linked list.
   */
  struct TopLevelActivity *next;

  /**
   * This is a doubly-linked list.
   */
  struct TopLevelActivity *prev;

  /**
   * Function to call for suspend-signalling and clean up.
   */
  SuspendSignalFunction ssf;

  /**
   * Closure for 'ssf' (some struct GNUNET_FS_XXXHandle*)
   */
  void *ssf_cls;
};


/**
 * Create a top-level activity entry.
 *
 * @param h global fs handle
 * @param ssf suspend signal function to use
 * @param ssf_cls closure for ssf
 * @return fresh top-level activity handle
 */
struct TopLevelActivity *
GNUNET_FS_make_top (struct GNUNET_FS_Handle *h, SuspendSignalFunction ssf,
                    void *ssf_cls);


/**
 * Destroy a top-level activity entry.
 *
 * @param h global fs handle
 * @param top top level activity entry
 */
void
GNUNET_FS_end_top (struct GNUNET_FS_Handle *h, struct TopLevelActivity *top);



/**
 * Master context for most FS operations.
 */
struct GNUNET_FS_Handle
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Name of our client.
   */
  char *client_name;

  /**
   * Function to call with updates on our progress.
   */
  GNUNET_FS_ProgressCallback upcb;

  /**
   * Closure for upcb.
   */
  void *upcb_cls;

  /**
   * Head of DLL of top-level activities.
   */
  struct TopLevelActivity *top_head;

  /**
   * Tail of DLL of top-level activities.
   */
  struct TopLevelActivity *top_tail;

  /**
   * Head of DLL of running jobs.
   */
  struct GNUNET_FS_QueueEntry *running_head;

  /**
   * Tail of DLL of running jobs.
   */
  struct GNUNET_FS_QueueEntry *running_tail;

  /**
   * Head of DLL of pending jobs.
   */
  struct GNUNET_FS_QueueEntry *pending_head;

  /**
   * Tail of DLL of pending jobs.
   */
  struct GNUNET_FS_QueueEntry *pending_tail;

  /**
   * Task that processes the jobs in the running and pending queues
   * (and moves jobs around as needed).
   */
  GNUNET_SCHEDULER_TaskIdentifier queue_job;

  /**
   * Average time we take for a single request to be satisfied.
   * FIXME: not yet calcualted properly...
   */
  struct GNUNET_TIME_Relative avg_block_latency;

  /**
   * How many actual downloads do we have running right now?
   */
  unsigned int active_downloads;

  /**
   * How many blocks do the active downloads have?
   */
  unsigned int active_blocks;

  /**
   * General flags.
   */
  enum GNUNET_FS_Flags flags;

  /**
   * Maximum number of parallel downloads.
   */
  unsigned int max_parallel_downloads;

  /**
   * Maximum number of parallel requests.
   */
  unsigned int max_parallel_requests;

};


/**
 * Handle for controlling a publication process.
 */
struct GNUNET_FS_PublishContext
{
  /**
   * Handle to the global fs context.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * Our top-level activity entry (if we are top-level, otherwise NULL).
   */
  struct TopLevelActivity *top;

  /**
   * File-structure that is being shared.
   */
  struct GNUNET_FS_FileInformation *fi;

  /**
   * Namespace that we are publishing in, NULL if we have no namespace.
   */
  struct GNUNET_FS_Namespace *namespace;

  /**
   * ID of the content in the namespace, NULL if we have no namespace.
   */
  char *nid;

  /**
   * ID for future updates, NULL if we have no namespace or no updates.
   */
  char *nuid;

  /**
   * Filename used for serializing information about this operation
   * (should be determined using 'mktemp').
   */
  char *serialization;

  /**
   * Our own client handle for the FS service; only briefly used when
   * we start to index a file, otherwise NULL.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Current position in the file-tree for the upload.
   */
  struct GNUNET_FS_FileInformation *fi_pos;

  /**
   * Non-null if we are currently hashing a file.
   */
  struct GNUNET_CRYPTO_FileHashContext *fhc;

  /**
   * Connection to the datastore service.
   */
  struct GNUNET_DATASTORE_Handle *dsh;

  /**
   * Queue entry for reservation/unreservation.
   */
  struct GNUNET_DATASTORE_QueueEntry *qre;

  /**
   * Context for SKS publishing operation that is part of this publishing operation
   * (NULL if not active).
   */
  struct GNUNET_FS_PublishSksContext *sks_pc;

  /**
   * Context for KSK publishing operation that is part of this publishing operation
   * (NULL if not active).
   */
  struct GNUNET_FS_PublishKskContext *ksk_pc;

  /**
   * ID of the task performing the upload. NO_TASK if the upload has
   * completed.
   */
  GNUNET_SCHEDULER_TaskIdentifier upload_task;

  /**
   * Storage space to reserve for the operation.
   */
  uint64_t reserve_space;

  /**
   * Overall number of entries to reserve for the
   * publish operation.
   */
  uint32_t reserve_entries;

  /**
   * Options for publishing.
   */
  enum GNUNET_FS_PublishOptions options;

  /**
   * Space reservation ID with datastore service
   * for this upload.
   */
  int rid;

  /**
   * Set to GNUNET_YES if all processing has completed.
   */
  int all_done;
  
  /**
   * Flag set to GNUNET_YES if the next callback from
   * GNUNET_FS_file_information_inspect should be skipped because it
   * is for the directory which was already processed with the parent.
   */
  int skip_next_fi_callback;
};


/**
 * Phases of unindex processing (state machine).
 */
enum UnindexState
{
  /**
   * We're currently hashing the file.
   */
  UNINDEX_STATE_HASHING = 0,

  /**
   * We're telling the datastore to delete
   * the respective DBlocks and IBlocks.
   */
  UNINDEX_STATE_DS_REMOVE = 1,
  
  /**
   * Find out which keywords apply.
   */
  UNINDEX_STATE_EXTRACT_KEYWORDS = 2,

  /**
   * We're telling the datastore to remove KBlocks.
   */
  UNINDEX_STATE_DS_REMOVE_KBLOCKS = 3,

  /**
   * We're notifying the FS service about
   * the unindexing.
   */
  UNINDEX_STATE_FS_NOTIFY = 4,
  
  /**
   * We're done.
   */
  UNINDEX_STATE_COMPLETE = 5,
  
  /**
   * We've encountered a fatal error.
   */
  UNINDEX_STATE_ERROR = 6
};


/**
 * Handle for controlling an unindexing operation.
 */
struct GNUNET_FS_UnindexContext
{

  /**
   * The content hash key of the last block we processed, will in the
   * end be set to the CHK from the URI.  Used to remove the KBlocks.
   */
  struct ContentHashKey chk; 

  /**
   * Global FS context.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * Our top-level activity entry.
   */
  struct TopLevelActivity *top;

  /**
   * Directory scanner to find keywords (KBlock removal).
   */
  struct GNUNET_FS_DirScanner *dscan;

  /**
   * Keywords found (telling us which KBlocks to remove).
   */
  struct GNUNET_FS_Uri *ksk_uri;

  /**
   * Current offset in KSK removal.
   */
  uint32_t ksk_offset;

  /**
   * Name of the file that we are unindexing.
   */
  char *filename;

  /**
   * Short name under which we are serializing the state of this operation.
   */
  char *serialization;

  /**
   * Connection to the FS service, only valid during the
   * UNINDEX_STATE_FS_NOTIFY phase.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Connection to the datastore service, only valid during the
   * UNINDEX_STATE_DS_NOTIFY phase.
   */
  struct GNUNET_DATASTORE_Handle *dsh;

  /**
   * Pointer kept for the client.
   */
  void *client_info;

  /**
   * Merkle-ish tree encoder context.
   */
  struct GNUNET_FS_TreeEncoder *tc;

  /**
   * Handle used to read the file.
   */
  struct GNUNET_DISK_FileHandle *fh;

  /**
   * Handle to datastore 'get_key' operation issued for
   * obtaining KBlocks.
   */
  struct GNUNET_DATASTORE_QueueEntry *dqe;

  /**
   * Current key for decrypting KBLocks from 'get_key' operation.
   */
  GNUNET_HashCode key;

  /**
   * Current query of 'get_key' operation.
   */
  GNUNET_HashCode query;

  /**
   * First content UID, 0 for none.
   */
  uint64_t first_uid;

  /**
   * Error message, NULL on success.
   */
  char *emsg;

  /**
   * Context for hashing of the file.
   */
  struct GNUNET_CRYPTO_FileHashContext *fhc;

  /**
   * Overall size of the file.
   */
  uint64_t file_size;

  /**
   * Random offset given to 'GNUNET_DATASTORE_get_key'.
   */
  uint64_t roff;

  /**
   * When did we start?
   */
  struct GNUNET_TIME_Absolute start_time;

  /**
   * Hash of the file's contents (once computed).
   */
  GNUNET_HashCode file_id;

  /**
   * Current operatinonal phase.
   */
  enum UnindexState state;

};


/**
 * Information we keep for each keyword in
 * a keyword search.
 */
struct SearchRequestEntry
{
  /**
   * Hash of the original keyword, also known as the
   * key (for decrypting the KBlock).
   */
  GNUNET_HashCode key;

  /**
   * Hash of the public key, also known as the query.
   */
  GNUNET_HashCode query;

  /**
   * Map that contains a "struct GNUNET_FS_SearchResult" for each result that
   * was found under this keyword.  Note that the entries will point
   * to the same locations as those in the master result map (in
   * "struct GNUNET_FS_SearchContext"), so they should not be freed.
   * The key for each entry is the XOR of the key and query in the CHK
   * URI (as a unique identifier for the search result).
   */
  struct GNUNET_CONTAINER_MultiHashMap *results;

  /**
   * Is this keyword a mandatory keyword
   * (started with '+')?
   */
  int mandatory;

};


/**
 * Handle for controlling a search.
 */
struct GNUNET_FS_SearchContext
{
  /**
   * Handle to the global FS context.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * Our top-level activity entry (if we are top-level, otherwise NULL).
   */
  struct TopLevelActivity *top;

  /**
   * List of keywords that we're looking for.
   */
  struct GNUNET_FS_Uri *uri;

  /**
   * For update-searches, link to the search result that triggered
   * the update search; otherwise NULL.
   */
  struct GNUNET_FS_SearchResult *psearch_result;

  /**
   * Connection to the FS service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Pointer we keep for the client.
   */
  void *client_info;

  /**
   * Name of the file on disk we use for persistence.
   */
  char *serialization;

  /**
   * Error message (non-NULL if this operation failed).
   */
  char *emsg;

  /**
   * Map that contains a "struct GNUNET_FS_SearchResult" for each result that
   * was found in the search.  The key for each entry is the XOR of
   * the key and query in the CHK URI (as a unique identifier for the
   * search result).
   */
  struct GNUNET_CONTAINER_MultiHashMap *master_result_map;

  /**
   * Per-keyword information for a keyword search.  This array will
   * have exactly as many entries as there were keywords.
   */
  struct SearchRequestEntry *requests;

  /**
   * When did we start?
   */
  struct GNUNET_TIME_Absolute start_time;

  /**
   * ID of a task that is using this struct and that must be cancelled
   * when the search is being stopped (if not
   * GNUNET_SCHEDULER_NO_TASK).  Used for the task that adds some
   * artificial delay when trying to reconnect to the FS service.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * How many of the entries in the search request
   * map have been passed to the service so far?
   */
  unsigned int search_request_map_offset;

  /**
   * How many of the keywords in the KSK
   * map have been passed to the service so far?
   */
  unsigned int keyword_offset;

  /**
   * Anonymity level for the search.
   */
  uint32_t anonymity;

  /**
   * Number of mandatory keywords in this query.
   */
  uint32_t mandatory_count;

  /**
   * Options for the search.
   */
  enum GNUNET_FS_SearchOptions options;
};


/**
 * FSM for possible states a block can go through.  The typical
 * order of progression is linear through the states, alternatives
 * are documented in the comments.
 */
enum BlockRequestState
{
    /**
     * Initial state, block has only been allocated (since it is
     * relevant to the overall download request).
     */
  BRS_INIT = 0,

    /**
     * We've checked the block on the path down the tree, and the
     * content on disk did match the desired CHK, but not all
     * the way down, so at the bottom some blocks will still
     * need to be reconstructed).
     */
  BRS_RECONSTRUCT_DOWN = 1,

    /**
     * We've calculated the CHK bottom-up based on the meta data.
     * This may work, but if it did we have to write the meta data to
     * disk at the end (and we still need to check against the
     * CHK set on top).
     */
  BRS_RECONSTRUCT_META_UP = 2,

    /**
     * We've calculated the CHK bottom-up based on what we have on
     * disk, which may not be what the desired CHK is.  If the
     * reconstructed CHKs match whatever comes from above, we're
     * done with the respective subtree.
     */
  BRS_RECONSTRUCT_UP = 3,

    /**
     * We've determined the real, desired CHK for this block
     * (full tree reconstruction failed), request is now pending.
     * If the CHK that bubbled up through reconstruction did match
     * the top-level request, the state machine for the subtree
     * would have moved to BRS_DOWNLOAD_UP.
     */
  BRS_CHK_SET = 4,

    /**
     * We've successfully downloaded this block, but the children
     * still need to be either downloaded or verified (download
     * request propagates down).  If the download fails, the
     * state machine for this block may move to
     * BRS_DOWNLOAD_ERROR instead.
     */
  BRS_DOWNLOAD_DOWN = 5,

    /**
     * This block and all of its children have been downloaded
     * successfully (full completion propagates up).
     */
  BRS_DOWNLOAD_UP = 6,

    /**
     * We got a block back that matched the query but did not hash to
     * the key (malicious publisher or hash collision); this block
     * can never be downloaded (error propagates up).
     */
  BRS_ERROR = 7
};


/**
 * Information about an active download request.
 */
struct DownloadRequest
{
  /**
   * While pending, we keep all download requests in a doubly-linked list.
   */
  struct DownloadRequest *next;

  /**
   * While pending, we keep all download requests in a doubly-linked list.
   */
  struct DownloadRequest *prev;

  /**
   * Parent in the CHK-tree.
   */
  struct DownloadRequest *parent;

  /**
   * Array (!) of child-requests, or NULL for the bottom of the tree.
   */
  struct DownloadRequest **children;

  /**
   * CHK for the request for this block (set during reconstruction
   * to what we have on disk, later to what we want to have).
   */
  struct ContentHashKey chk;

  /**
   * Offset of the corresponding block.  Specifically, first (!) byte of
   * the first DBLOCK in the subtree induced by block represented by
   * this request.
   */
  uint64_t offset;

  /**
   * Number of entries in 'children' array.
   */
  unsigned int num_children;

  /**
   * Depth of the corresponding block in the tree.  0==DBLOCKs.
   */
  unsigned int depth;

  /**
   * Offset of the CHK for this block in the parent block
   */
  unsigned int chk_idx;

  /**
   * State in the FSM.
   */
  enum BlockRequestState state;

  /**
   * GNUNET_YES if this entry is in the pending list.
   */
  int is_pending;

};


/**
 * (recursively) free download request structure
 *
 * @param dr request to free
 */
void
GNUNET_FS_free_download_request_ (struct DownloadRequest *dr);


/**
 * Context for controlling a download.
 */
struct GNUNET_FS_DownloadContext
{

  /**
   * Global FS context.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * Our top-level activity entry (if we are top-level, otherwise NULL).
   */
  struct TopLevelActivity *top;

  /**
   * Connection to the FS service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Parent download (used when downloading files
   * in directories).
   */
  struct GNUNET_FS_DownloadContext *parent;

  /**
   * Associated search (used when downloading files
   * based on search results), or NULL for none.
   */
  struct GNUNET_FS_SearchResult *search;

  /**
   * Head of list of child downloads.
   */
  struct GNUNET_FS_DownloadContext *child_head;

  /**
   * Tail of list of child downloads.
   */
  struct GNUNET_FS_DownloadContext *child_tail;

  /**
   * Previous download belonging to the same parent.
   */
  struct GNUNET_FS_DownloadContext *prev;

  /**
   * Next download belonging to the same parent.
   */
  struct GNUNET_FS_DownloadContext *next;

  /**
   * Context kept for the client.
   */
  void *client_info;

  /**
   * URI that identifies the file that we are downloading.
   */
  struct GNUNET_FS_Uri *uri;

  /**
   * Known meta-data for the file (can be NULL).
   */
  struct GNUNET_CONTAINER_MetaData *meta;

  /**
   * Error message, NULL if we're doing OK.
   */
  char *emsg;

  /**
   * Random portion of filename we use for syncing state of this
   * download.
   */
  char *serialization;

  /**
   * Where are we writing the data (name of the
   * file, can be NULL!).
   */
  char *filename;

  /**
   * Where are we writing the data temporarily (name of the
   * file, can be NULL!); used if we do not have a permanent
   * name and we are a directory and we do a recursive download.
   */
  char *temp_filename;

  /**
   * Our entry in the job queue.
   */
  struct GNUNET_FS_QueueEntry *job_queue;

  /**
   * Non-NULL if we are currently having a request for
   * transmission pending with the client handle.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Tree encoder used for the reconstruction.
   */
  struct GNUNET_FS_TreeEncoder *te;

  /**
   * File handle for reading data from an existing file
   * (to pass to tree encoder).
   */
  struct GNUNET_DISK_FileHandle *rfh;

  /**
   * Map of active requests (those waiting for a response).  The key
   * is the hash of the encryped block (aka query).
   */
  struct GNUNET_CONTAINER_MultiHashMap *active;

  /**
   * Head of linked list of pending requests.
   */
  struct DownloadRequest *pending_head;

  /**
   * Head of linked list of pending requests.
   */
  struct DownloadRequest *pending_tail;

  /**
   * Top-level download request.
   */
  struct DownloadRequest *top_request;

  /**
   * Identity of the peer having the content, or all-zeros
   * if we don't know of such a peer.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * ID of a task that is using this struct and that must be cancelled
   * when the download is being stopped (if not
   * GNUNET_SCHEDULER_NO_TASK).  Used for the task that adds some
   * artificial delay when trying to reconnect to the FS service or
   * the task processing incrementally the data on disk, or the
   * task requesting blocks, etc.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * What is the first offset that we're interested
   * in?
   */
  uint64_t offset;

  /**
   * How many bytes starting from offset are desired?
   * This is NOT the overall length of the file!
   */
  uint64_t length;

  /**
   * How many bytes have we already received within
   * the specified range (DBlocks only).
   */
  uint64_t completed;

  /**
   * What was the size of the file on disk that we're downloading
   * before we started?  Used to detect if there is a point in
   * checking an existing block on disk for matching the desired
   * content.  0 if the file did not exist already.
   */
  uint64_t old_file_size;

  /**
   * Time download was started.
   */
  struct GNUNET_TIME_Absolute start_time;

  /**
   * Desired level of anonymity.
   */
  uint32_t anonymity;

  /**
   * The depth of the file-tree.
   */
  unsigned int treedepth;

  /**
   * Options for the download.
   */
  enum GNUNET_FS_DownloadOptions options;

  /**
   * Flag set upon transitive completion (includes child downloads).
   * This flag is only set to GNUNET_YES for directories where all
   * child-downloads have also completed (and signalled completion).
   */
  int has_finished;

  /**
   * Have we started the receive continuation yet?
   */
  int in_receive;

  /**
   * Are we ready to issue requests (reconstructions are finished)?
   */
  int issue_requests;

};


/**
 * Information about an (updateable) node in the
 * namespace.
 */
struct NamespaceUpdateNode
{
  /**
   * Identifier for this node.
   */
  char *id;

  /**
   * Identifier of children of this node.
   */
  char *update;

  /**
   * Metadata for this entry.
   */
  struct GNUNET_CONTAINER_MetaData *md;

  /**
   * URI of this entry in the namespace.
   */
  struct GNUNET_FS_Uri *uri;

  /**
   * Namespace update generation ID.  Used to ensure
   * freshness of the tree_id.
   */
  unsigned int nug;

  /**
   * TREE this entry belongs to (if nug is current).
   */
  unsigned int tree_id;

};


struct GNUNET_FS_Namespace
{

  /**
   * Handle to the FS service context.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * Array with information about nodes in the namespace.
   */
  struct NamespaceUpdateNode **update_nodes;

  /**
   * Private key for the namespace.
   */
  struct GNUNET_CRYPTO_RsaPrivateKey *key;

  /**
   * Hash map mapping identifiers of update nodes
   * to the update nodes (initialized on-demand).
   */
  struct GNUNET_CONTAINER_MultiHashMap *update_map;

  /**
   * Name of the file with the private key.
   */
  char *filename;

  /**
   * Name of the namespace.
   */
  char *name;

  /**
   * Size of the update nodes array.
   */
  unsigned int update_node_count;

  /**
   * Reference counter.
   */
  unsigned int rc;

  /**
   * Generator for unique nug numbers.
   */
  unsigned int nug_gen;
};

#endif

/* end of fs_api.h */
