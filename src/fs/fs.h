/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs.h
 * @brief definitions for the entire fs module
 * @author Igor Wronsky, Christian Grothoff
 */
#ifndef FS_H
#define FS_H

#include "gnunet_constants.h"
#include "gnunet_datastore_service.h"
#include "gnunet_fs_service.h"
#include "gnunet_block_lib.h"

/**
 * Size of the individual blocks used for file-sharing.
 */
#define DBLOCK_SIZE (32*1024)

/**
 * Maximum legal size for a kblock.
 */
#define MAX_KBLOCK_SIZE (60 * 1024)

/**
 * Maximum legal size for an sblock.
 */
#define MAX_SBLOCK_SIZE (60 * 1024)

/**
 * Maximum legal size for an nblock.
 */
#define MAX_NBLOCK_SIZE (60 * 1024)

/**
 * Pick a multiple of 2 here to achive 8-byte alignment!
 * We also probably want DBlocks to have (roughly) the
 * same size as IBlocks.  With SHA-512, the optimal
 * value is 32768 byte / 128 byte = 256
 * (128 byte = 2 * 512 bits).  DO NOT CHANGE!
 */
#define CHK_PER_INODE 256


/**
 * Maximum size for a file to be considered for
 * inlining in a directory.
 */
#define MAX_INLINE_SIZE 65536


/**
 * Blocksize to use when hashing files
 * for indexing (blocksize for IO, not for
 * the DBlocks).  Larger blocksizes can
 * be more efficient but will be more disruptive
 * as far as the scheduler is concerned.
 */
#define HASHING_BLOCKSIZE (1024 * 1024)

/**
 * Number of bits we set per entry in the bloomfilter.
 * Do not change!
 */
#define BLOOMFILTER_K 16

/**
 * Number of availability trials we perform per search result.
 */
#define AVAILABILITY_TRIALS_MAX 8

/**
 * By how much (in ms) do we decrement the TTL
 * at each hop?
 */
#define TTL_DECREMENT 5000

/**
 * Length of the P2P success tracker.  Note that
 * having a very long list can also hurt performance.
 */
#define P2P_SUCCESS_LIST_SIZE 8


/**
 * Length of the CS-2-P success tracker.  Note that
 * having a very long list can also hurt performance.
 */
#define CS2P_SUCCESS_LIST_SIZE 8

/**
 * How long are we willing to wait for the datastore to be ready to
 * process a request for a query without priority?
 */
#define BASIC_DATASTORE_REQUEST_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)


/**
 * How long are we willing to wait for the core to be ready to
 * transmit a reply to the target peer (if we can not transmit
 * until then, we will discard the reply).
 */
#define ACCEPTABLE_REPLY_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)


/**
 * Bandwidth value of an (effectively) 0-priority query.
 */
#define QUERY_BANDWIDTH_VALUE 0.001

/**
 * Bandwidth value of a 0-priority content (must be
 * fairly high compared to query since content is
 * typically significantly larger -- and more valueable
 * since it can take many queries to get one piece of
 * content).
 */
#define CONTENT_BANDWIDTH_VALUE 0.8

/**
 * By which amount do we decrement the TTL for simple forwarding /
 * indirection of the query; in milli-seconds.  Set somewhat in
 * accordance to your network latency (above the time it'll take you
 * to send a packet and get a reply).
 */
#define TTL_DECREMENT 5000

/**
 * Until which load do we consider the peer idle and do not
 * charge at all? (should be larger than GNUNET_IDLE_LOAD_THRESHOLD used
 * by the rest of the code)!
 */
#define IDLE_LOAD_THRESHOLD ((100 + GNUNET_CONSTANTS_IDLE_LOAD_THRESHOLD) / 2)



/**
 * @brief content hash key
 */
struct ContentHashKey 
{
  /**
   * Hash of the original content, used for encryption.
   */
  GNUNET_HashCode key;

  /**
   * Hash of the encrypted content, used for querying.
   */
  GNUNET_HashCode query;
};


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
   * At what time should the content expire?
   */
  struct GNUNET_TIME_Absolute expirationTime;

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
    struct {

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
    struct {
      
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
   * Desired anonymity level.
   */
  uint32_t anonymity;

  /**
   * Desired priority (for keeping the content in the DB).
   */
  uint32_t priority;

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
typedef void (*GNUNET_FS_QueueStart)(void *cls,
				     struct GNUNET_CLIENT_Connection *client);


/**
 * The job must now stop to run and should destry the client handle as
 * soon as possible (ideally prior to returning).
 */
typedef void (*GNUNET_FS_QueueStop)(void *cls);


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
   *
   * FIXME: not yet serialized.
   */
  struct GNUNET_FS_DownloadContext *download;

  /**
   * Name under which this search result is stored on disk.
   */
  char *serialization;

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
 * @return queue handle
 */
struct GNUNET_FS_QueueEntry *
GNUNET_FS_queue_ (struct GNUNET_FS_Handle *h,
		  GNUNET_FS_QueueStart start,
		  GNUNET_FS_QueueStop stop,
		  void *cls,
		  unsigned int blocks);


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
GNUNET_FS_data_reader_file_(void *cls, 
			    uint64_t offset,
			    size_t max, 
			    void *buf,
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
GNUNET_FS_data_reader_copy_(void *cls, 
			    uint64_t offset,
			    size_t max, 
			    void *buf,
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
void*
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
GNUNET_FS_unindex_process_hash_ (void *cls,
				 const GNUNET_HashCode *file_id);


/**
 * Fill in all of the generic fields for a publish event and call the
 * callback.
 *
 * @param pi structure to fill in
 * @param sc overall publishing context
 * @param p file information for the file being published
 * @param offset where in the file are we so far
 * @return value returned from callback
 */
void *
GNUNET_FS_publish_make_status_ (struct GNUNET_FS_ProgressInfo *pi,
				struct GNUNET_FS_PublishContext *sc,
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
GNUNET_FS_remove_sync_file_ (struct GNUNET_FS_Handle *h,
			     const char *ext,
			     const char *ent);


/**
 * Remove serialization/deserialization directory from disk.
 *
 * @param h master context
 * @param ext component of the path 
 * @param uni unique name of parent 
 */
void
GNUNET_FS_remove_sync_dir_ (struct GNUNET_FS_Handle *h,
			    const char *ext,
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
 * Function signature of the functions that can be called
 * to trigger suspend signals and clean-up for top-level
 * activities.
 *
 * @param cls closure
 */
typedef void (*SuspendSignalFunction)(void *cls);				      

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
GNUNET_FS_make_top (struct GNUNET_FS_Handle *h,
		    SuspendSignalFunction ssf,
		    void *ssf_cls);


/**
 * Destroy a top-level activity entry.
 * 
 * @param h global fs handle
 * @param top top level activity entry
 */
void
GNUNET_FS_end_top (struct GNUNET_FS_Handle *h,
		   struct TopLevelActivity *top);


/**
 * Create SUSPEND event for the given download operation
 * and then clean up our state (without stop signal).
 *
 * @param cls the 'struct GNUNET_FS_DownloadContext' to signal for
 */
void
GNUNET_FS_download_signal_suspend_ (void *cls);


/**
 * Master context for most FS operations.
 */
struct GNUNET_FS_Handle
{
  /**
   * Scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

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
   * Connection to the FS service.
   */
  struct GNUNET_CLIENT_Connection *client;

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
   * Connection to the datastore service.
   */
  struct GNUNET_DATASTORE_Handle *dsh;

  /**
   * ID of the task performing the upload. NO_TASK if the upload has
   * completed.
   */
  GNUNET_SCHEDULER_TaskIdentifier upload_task;

  /**
   * Typically GNUNET_NO.  Set to GNUNET_YES if "upload_task" is
   * GNUNET_SCHEDULER_NO_TASK and we're waiting for a response from
   * the datastore service (in which case this struct must not be
   * freed until we have that response).  If someone tries to stop the
   * download for good during this period, "in_network_wait" is set to
   * GNUNET_SYSERR which will cause the struct to be destroyed right
   * after we have the reply (or timeout) from the datastore service.
   */
  int in_network_wait;

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
     * We're notifying the FS service about
     * the unindexing.
     */
    UNINDEX_STATE_FS_NOTIFY = 1,

    /**
     * We're telling the datastore to delete
     * the respective entries.
     */
    UNINDEX_STATE_DS_REMOVE = 2,

    /**
     * We're done.
     */
    UNINDEX_STATE_COMPLETE = 3,

    /**
     * We've encountered a fatal error.
     */
    UNINDEX_STATE_ERROR = 4,

    /**
     * We've been aborted.  The next callback should clean up the
     * struct.
     */
    UNINDEX_STATE_ABORTED = 5
  };


/**
 * Handle for controlling an unindexing operation.
 */
struct GNUNET_FS_UnindexContext
{
  
  /**
   * Global FS context.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * Our top-level activity entry.
   */
  struct TopLevelActivity *top;

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
   * Error message, NULL on success.
   */
  char *emsg;

  /**
   * Overall size of the file.
   */ 
  uint64_t file_size;

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
   * For update-searches, link to the base-SKS search that triggered
   * the update search; otherwise NULL.
   */
  struct GNUNET_FS_SearchContext *parent;

  /**
   * For update-searches, link to the first child search that
   * triggered the update search; otherwise NULL.
   */
  struct GNUNET_FS_SearchContext *child_head;

  /**
   * For update-searches, link to the last child search that triggered
   * the update search; otherwise NULL.
   */
  struct GNUNET_FS_SearchContext *child_tail;

  /**
   * For update-searches, link to the next child belonging to the same
   * parent.
   */
  struct GNUNET_FS_SearchContext *next;

  /**
   * For update-searches, link to the previous child belonging to the
   * same parent.
   */
  struct GNUNET_FS_SearchContext *prev;

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
 * Information about an active download request.
 */ 
struct DownloadRequest
{
  /**
   * While pending, we keep all download requests in a linked list.
   */
  struct DownloadRequest *next;

  /**
   * CHK for the request.
   */
  struct ContentHashKey chk;

  /**
   * Offset of the corresponding block.
   */
  uint64_t offset;

  /**
   * Depth of the corresponding block in the tree.
   */
  unsigned int depth;

  /**
   * Set if this request is currently in the linked list of pending
   * requests.  Needed in case we get a response for a request that we
   * have not yet send (i.e. due to two blocks with identical
   * content); in this case, we would need to remove the block from
   * the pending list (and need a fast way to check if the block is on
   * it).
   */
  int is_pending;

};


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
   *
   * FIXME: not yet serialized
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
   * URI that identifies the file that
   * we are downloading.
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
   * Map of active requests (those waiting
   * for a response).  The key is the hash
   * of the encryped block (aka query).
   */
  struct GNUNET_CONTAINER_MultiHashMap *active;

  /**
   * Linked list of pending requests.
   */
  struct DownloadRequest *pending;

  /**
   * Non-NULL if we are currently having a request for
   * transmission pending with the client handle.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Our entry in the job queue.
   */
  struct GNUNET_FS_QueueEntry *job_queue;

  /**
   * Identity of the peer having the content, or all-zeros
   * if we don't know of such a peer.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * ID of a task that is using this struct
   * and that must be cancelled when the download
   * is being stopped (if not GNUNET_SCHEDULER_NO_TASK).
   * Used for the task that adds some artificial
   * delay when trying to reconnect to the FS
   * service.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * What was the size of the file on disk that we're downloading
   * before we started?  Used to detect if there is a point in
   * checking an existing block on disk for matching the desired
   * content.  0 if the file did not exist already.
   */
  uint64_t old_file_size;

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

};

struct GNUNET_FS_Namespace
{

  /**
   * Private key for the namespace.
   */
  struct GNUNET_CRYPTO_RsaPrivateKey *key;

  /**
   * Name of the file with the private key.
   */
  char *filename;

  /**
   * Name of the namespace.
   */ 
  char *name;

  /**
   * Reference counter.
   */
  unsigned int rc;
};


/**
 * Message sent from a GNUnet (fs) publishing activity to the
 * gnunet-fs-service to initiate indexing of a file.  The service is
 * supposed to check if the specified file is available and has the
 * same cryptographic hash.  It should then respond with either a
 * confirmation or a denial.
 *
 * On OSes where this works, it is considered acceptable if the
 * service only checks that the path, device and inode match (it can
 * then be assumed that the hash will also match without actually
 * computing it; this is an optimization that should be safe given
 * that the client is not our adversary).
 */
struct IndexStartMessage
{

  /**
   * Message type will be GNUNET_MESSAGE_TYPE_FS_INDEX_START.
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of device containing the file, as seen by the client.  This
   * device ID is obtained using a call like "statvfs" (and converting
   * the "f_fsid" field to a 32-bit big-endian number).  Use 0 if the
   * OS does not support this, in which case the service must do a
   * full hash recomputation.
   */
  uint32_t device GNUNET_PACKED;
  
  /**
   * Inode of the file on the given device, as seen by the client
   * ("st_ino" field from "struct stat").  Use 0 if the OS does not
   * support this, in which case the service must do a full hash
   * recomputation.
   */
  uint64_t inode GNUNET_PACKED;

  /**
   * Hash of the file that we would like to index.
   */
  GNUNET_HashCode file_id;

  /* this is followed by a 0-terminated
     filename of a file with the hash
     "file_id" as seen by the client */

};


/**
 * Message send by FS service in response to a request
 * asking for a list of all indexed files.
 */
struct IndexInfoMessage
{
  /**
   * Message type will be 
   * GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_ENTRY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Hash of the indexed file.
   */
  GNUNET_HashCode file_id;

  /* this is followed by a 0-terminated
     filename of a file with the hash
     "file_id" as seen by the client */
  
};


/**
 * Message sent from a GNUnet (fs) unindexing activity to the
 * gnunet-service-fs to indicate that a file will be unindexed.  The
 * service is supposed to remove the file from the list of indexed
 * files and response with a confirmation message (even if the file
 * was already not on the list).
 */
struct UnindexMessage
{

  /**
   * Message type will be 
   * GNUNET_MESSAGE_TYPE_FS_UNINDEX.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Hash of the file that we will unindex.
   */
  GNUNET_HashCode file_id;

};


/**
 * Message sent from a GNUnet (fs) search activity to the
 * gnunet-service-fs to start a search.
 */
struct SearchMessage
{

  /**
   * Message type will be 
   * GNUNET_MESSAGE_TYPE_FS_START_SEARCH.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Bitmask with options.  Zero for no options, one for loopback-only.  
   * Other bits are currently not defined.
   */
  int32_t options GNUNET_PACKED;

  /**
   * Type of the content that we're looking for.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Desired anonymity level, big-endian.
   */
  uint32_t anonymity_level GNUNET_PACKED;

  /**
   * If the request is for a DBLOCK or IBLOCK, this is the identity of
   * the peer that is known to have a response.  Set to all-zeros if
   * such a target is not known (note that even if OUR anonymity
   * level is >0 we may happen to know the responder's identity;
   * nevertheless, we should probably not use it for a DHT-lookup
   * or similar blunt actions in order to avoid exposing ourselves).
   * <p>
   * If the request is for an SBLOCK, this is the identity of the
   * pseudonym to which the SBLOCK belongs. 
   * <p>
   * If the request is for a KBLOCK, "target" must be all zeros.
   */
  GNUNET_HashCode target;

  /**
   * Hash of the keyword (aka query) for KBLOCKs; Hash of
   * the CHK-encoded block for DBLOCKS and IBLOCKS (aka query)
   * and hash of the identifier XORed with the target for
   * SBLOCKS (aka query).
   */
  GNUNET_HashCode query;

  /* this is followed by the hash codes of already-known
     results (which should hence be excluded from what
     the service returns); naturally, this only applies
     to queries that can have multiple results, such as
     those for KBLOCKS (KSK) and SBLOCKS (SKS) */
};


/**
 * Only the (mandatory) query is included.
 */
#define GET_MESSAGE_BIT_QUERY_ONLY 0

/**
 * The peer identity of a peer waiting for the
 * reply is included (used if the response
 * should be transmitted to someone other than
 * the sender of the GET).
 */
#define GET_MESSAGE_BIT_RETURN_TO 1

/**
 * The hash of the public key of the target
 * namespace is included (for SKS queries).
 */
#define GET_MESSAGE_BIT_SKS_NAMESPACE 2

/**
 * The peer identity of a peer that had claimed to have the content
 * previously is included (can be used if responder-anonymity is not
 * desired; note that the precursor presumably lacked a direct
 * connection to the specified peer; still, the receiver is in no way
 * required to limit forwarding only to the specified peer, it should
 * only prefer it somewhat if possible).
 */
#define GET_MESSAGE_BIT_TRANSMIT_TO 4


/**
 * Message sent between peers asking for FS-content.
 */
struct GetMessage
{

  /**
   * Message type will be GNUNET_MESSAGE_TYPE_FS_GET.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Type of the query (block type).
   */
  uint32_t type GNUNET_PACKED;

  /**
   * How important is this request (network byte order)
   */
  uint32_t priority GNUNET_PACKED;

  /**
   * Relative time to live in MILLISECONDS (network byte order)
   */
  int32_t ttl GNUNET_PACKED;

  /**
   * The content hash should be mutated using this value
   * before checking against the bloomfilter (used to
   * get many different filters for the same hash codes).
   * The number should be in big-endian format when used
   * for mingling.
   */
  int32_t filter_mutator GNUNET_PACKED;

  /**
   * Which of the optional hash codes are present at the end of the
   * message?  See GET_MESSAGE_BIT_xx constants.  For each bit that is
   * set, an additional GNUNET_HashCode with the respective content
   * (in order of the bits) will be appended to the end of the GET
   * message.
   */
  uint32_t hash_bitmap GNUNET_PACKED;

  /**
   * Hashcodes of the file(s) we're looking for.
   * Details depend on the query type.
   */
  GNUNET_HashCode query GNUNET_PACKED;

  /* this is followed by hash codes
     as specified in the  "hash_bitmap";
     after that, an optional bloomfilter
     (with bits set for replies that should
     be suppressed) can be present */
};


/**
 * Response from FS service with a result for a previous FS search.
 * Note that queries for DBLOCKS and IBLOCKS that have received a
 * single response are considered done.  This message is transmitted
 * between peers as well as between the service and a client.
 */
struct PutMessage
{

  /**
   * Message type will be GNUNET_MESSAGE_TYPE_FS_PUT.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Type of the block (in big endian).  Should never be zero.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * When does this result expire? 
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /* this is followed by the actual encrypted content */

};


#endif

/* end of fs.h */
