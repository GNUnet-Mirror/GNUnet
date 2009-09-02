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

#include "gnunet_datastore_service.h"
#include "gnunet_fs_service.h"

/**
 * Size of the individual blocks used for file-sharing.
 */
#define DBLOCK_SIZE (32*1024)


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
 * @brief content hash key
 */
struct ContentHashKey 
{
  GNUNET_HashCode key;
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

enum uri_types
{ chk, sks, ksk, loc };

/**
 * A Universal Resource Identifier (URI), opaque.
 */
struct GNUNET_FS_Uri
{
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
   * (for operational persistence).
   */
  char *serialization;
  
  /**
   * Encoder being used to publish this file.
   */
  struct GNUNET_FS_TreeEncoder *te;

  /**
   * Error message (non-NULL if this operation
   * failed).
   */
  char *emsg;

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
       * Name of the file (must be an absolute path).
       * Only required for indexing.  FIXME: not yet
       * initialized!
       */
      char *filename;

      /**
       * If this file is being indexed, this value
       * is set to the hash over the entire file
       * (when the indexing process is started). 
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

    } file;

    /**
     * Data for a directory.
     */
    struct {
      
      /**
       * Name of the directory.
       */
      char *dirname;
      
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
   * Desired anonymity level.
   */
  unsigned int anonymity;

  /**
   * Desired priority (for keeping the content in the DB).
   */
  unsigned int priority;

};


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


};


/**
 * Handle for controlling an upload.
 */
struct GNUNET_FS_PublishContext
{
  /**
   * Handle to the global fs context.
   */ 
  struct GNUNET_FS_Handle *h;

  /**
   * Argument to pass to the client in callbacks.
   */
  void *client_ctx;
  
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
   * ID of the task performing the upload. NO_TASK
   * if the upload has completed.
   */
  GNUNET_SCHEDULER_TaskIdentifier upload_task;

  /**
   * Our own client handle for the FS service;
   * only briefly used when we start to index a
   * file, otherwise NULL.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Typically GNUNET_NO.  Set to GNUNET_YES if
   * "upload_task" is GNUNET_SCHEDULER_NO_TASK
   * and we're waiting for a response from the
   * datastore service (in which case this
   * struct must not be freed until we have that
   * response).  If someone tries to stop the
   * download for good during this period, 
   * "in_network_wait" is set to GNUNET_SYSERR
   * which will cause the struct to be destroyed
   * right after we have the reply (or timeout)
   * from the datastore service.
   */
  int in_network_wait;

  /**
   * Options for publishing.
   */
  enum GNUNET_FS_PublishOptions options;

  /**
   * Current position in the file-tree for the
   * upload.
   */
  struct GNUNET_FS_FileInformation *fi_pos;

  /**
   * Connection to the datastore service.
   */
  struct GNUNET_DATASTORE_Handle *dsh;

  /**
   * Space reservation ID with datastore service
   * for this upload.
   */
  int rid;
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
   * Name of the file that we are unindexing.
   */
  char *filename;

  /**
   * Connection to the FS service,
   * only valid during the UNINDEX_STATE_FS_NOTIFY
   * phase.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Connection to the datastore service,
   * only valid during the UNINDEX_STATE_DS_NOTIFY
   * phase.
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
   * Overall size of the file.
   */ 
  uint64_t file_size;

  /**
   * When did we start?
   */
  struct GNUNET_TIME_Absolute start_time;

  /**
   * Hash of the file's contents (once
   * computed).
   */
  GNUNET_HashCode file_id;
 
  /**
   * Current operatinonal phase.
   */
  enum UnindexState state; 

};


/**
 * Handle for controlling a search.
 */
struct GNUNET_FS_SearchContext
{
};


/**
 * Context for controlling a download.
 */
struct GNUNET_FS_DownloadContext
{
};

struct GNUNET_FS_Namespace
{

  /**
   * Private key for the namespace.
   */
  struct GNUNET_CRYPTO_RsaPrivateKey *key;

  /**
   * Reference counter.
   */
  unsigned int rc;
};


/**
 * @brief index block (indexing a DBlock that 
 *        can be obtained directly from reading
 *        the plaintext file)
 */
struct OnDemandBlock
{
  /**
   * Hash code of the entire content of the
   * file that was indexed (used to uniquely
   * identify the plaintext file).
   */
  GNUNET_HashCode file_id;

  /**
   * At which offset should we be able to find
   * this on-demand encoded block?
   */
  uint64_t offset;

};


/**
 * @brief keyword block (advertising data under a keyword)
 */
struct KBlock
{

  /**
   * GNUNET_RSA_Signature using RSA-key generated from search keyword.
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

  /**
   * What is being signed and why?
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * Key generated (!) from the H(keyword) as the seed!
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded keyspace;

  /* 0-terminated URI here */

  /* variable-size Meta-Data follows here */

};

/**
 * @brief namespace content block (advertising data under an identifier in a namespace)
 */
struct SBlock
{

  /**
   * GNUNET_RSA_Signature using RSA-key of the namespace
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

  /**
   * What is being signed and why?
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * Hash of the hash of the human-readable identifier used for
   * this entry (the hash of the human-readable identifier is
   * used as the key for decryption; the xor of this identifier
   * and the hash of the "keyspace" is the datastore-query hash).
   */
  GNUNET_HashCode identifier;

  /**
   * Public key of the namespace.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded subspace;

  /* 0-terminated update-identifier here */

  /* 0-terminated URI here */

  /* variable-size Meta-Data follows here */

};


/**
 * Message sent from a GNUnet (fs) publishing
 * activity to the gnunet-fs-service to 
 * initiate indexing of a file.  The service
 * is supposed to check if the specified file
 * is available and has the same cryptographic
 * hash.  It should then respond with either
 * a confirmation or a denial.
 *
 * On OSes where this works, it is considered
 * acceptable if the service only checks that
 * the path, device and inode match (it can
 * then be assumed that the hash will also match
 * without actually computing it; this is an
 * optimization that should be safe given that
 * the client is not our adversary).
 */
struct IndexStartMessage
{

  /**
   * Message type will be 
   * GNUNET_MESSAGE_TYPE_FS_INDEX_START.
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of device containing the file, as seen by the client.  This
   * device ID is obtained using a call like "statvfs" (and converting
   * the "f_fsid" field to a 32-bit big-endian number).  Use 0 if the
   * OS does not support this, in which case the service must do a
   * full hash recomputation.
   */
  uint32_t device;
  
  /**
   * Inode of the file on the given device, as seen by the client
   * ("st_ino" field from "struct stat").  Use 0 if the OS does not
   * support this, in which case the service must do a full hash
   * recomputation.
   */
  uint64_t inode;

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
   * Hash of the indexed file.
   */
  GNUNET_HashCode file_id;

  /* this is followed by a 0-terminated
     filename of a file with the hash
     "file_id" as seen by the client */
  
};


/**
 * Message sent from a GNUnet (fs) unindexing
 * activity to the gnunet-fs-service to 
 * indicate that a file will be unindexed.  The service
 * is supposed to remove the file from the
 * list of indexed files and response with
 * a confirmation message (even if the file
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
  uint32_t reserved;

  /**
   * Hash of the file that we will unindex.
   */
  GNUNET_HashCode file_id;

};



#endif

/* end of fs.h */
