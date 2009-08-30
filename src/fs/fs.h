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
#define GNUNET_FS_DBLOCK_SIZE (32*1024)


/**
 * Pick a multiple of 2 here to achive 8-byte alignment!
 * We also probably want DBlocks to have (roughly) the
 * same size as IBlocks.  With SHA-512, the optimal
 * value is 32768 byte / 128 byte = 256
 * (128 byte = 2 * 512 bits).  DO NOT CHANGE!
 */
#define GNUNET_FS_CHK_PER_INODE 256


/**
 * Maximum size for a file to be considered for
 * inlining in a directory.
 */
#define GNUNET_FS_MAX_INLINE_SIZE 65536



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
   * In-memory cache of the current CHK tree.
   * This struct will contain the CHK values
   * from the root to the currently processed
   * node in the tree as identified by 
   * "current_depth" and "publish_offset".
   * The "chktree" will be initially NULL,
   * then allocated to a sufficient number of
   * entries for the size of the file and
   * finally freed once the upload is complete.
   */
  struct ContentHashKey *chk_tree;

  /**
   * Error message (non-NULL if this operation
   * failed).
   */
  char *emsg;
  
  /**
   * Number of entries in "chk_tree".
   */
  unsigned int chk_tree_depth;

  /**
   * Depth in the CHK-tree at which we are
   * currently publishing.  0 is the root
   * of the tree.
   */
  unsigned int current_depth;

  /**
   * How many bytes of this file or directory have been
   * published so far?
   */
  uint64_t publish_offset;

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
 * Handle for controlling an unindexing operation.
 */
struct GNUNET_FS_UnindexContext
{
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
   * Reference counter.
   */
  unsigned int rc;
};


/**
 * @brief keyword block (advertising data under a keyword)
 */
struct GNUNET_FS_KBlock
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

#endif

/* end of fs.h */
