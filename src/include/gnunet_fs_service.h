/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
- review:
* directory creation/inspection API
* unindex start/stop API
* resume notifications 
* ProgressCallback: struct/union instead of tons of args?
* download options (no temporary files -- what about no files at all?)

/**
 * @file include/gnunet_fs_service.h
 * @brief support for file-sharing via GNUnet 
 * @author Christian Grothoff
 */

#ifndef GNUNET_FS_LIB_H
#define GNUNET_FS_LIB_H

#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Version number of the implementation.
 * History:
 *
 * 1.x.x: initial version with triple GNUNET_hash and merkle tree
 * 2.x.x: root node with mime-type, filename and version number
 * 2.1.x: combined GNUNET_EC_ContentHashKey/3HASH encoding with 25:1 super-nodes
 * 2.2.x: with directories
 * 3.0.x: with namespaces
 * 3.1.x: with namespace meta-data
 * 3.2.x: with collections
 * 4.0.x: with expiration, variable meta-data, kblocks
 * 4.1.x: with new error and configuration handling
 * 5.0.x: with location URIs
 * 6.0.0: with support for OR in KSKs
 * 6.1.x: with simplified namespace support
 * 9.0.0: CPS-style integrated API
 */
#define GNUNET_FS_VERSION 0x00090000

#define GNUNET_DIRECTORY_MIME  "application/gnunet-directory"
#define GNUNET_DIRECTORY_MAGIC "\211GND\r\n\032\n"
#define GNUNET_DIRECTORY_EXT   ".gnd"

/* URI API */ 

#define GNUNET_FS_URI_PREFIX      "gnunet://fs/"
#define GNUNET_FS_SEARCH_INFIX    "ksk/"
#define GNUNET_FS_SUBSPACE_INFIX  "sks/"
#define GNUNET_FS_FILE_INFIX      "chk/"
#define GNUNET_FS_LOCATION_INFIX  "loc/"

/**
 * Iterator over keywords
 *
 * @param cls closure
 * @param keyword the keyword
 * @param is_mandatory is the keyword mandatory (in a search)
 * @return GNUNET_OK to continue to iterate, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_FS_KeywordIterator) (void *cls,
					  const char *keyword,
					  int is_mandatory);


/**
 * Does the meta-data claim that this is a directory?
 * Checks if the mime-type is that of a GNUnet directory.
 *
 * @return GNUNET_YES if it is, GNUNET_NO if it is not, GNUNET_SYSERR if
 *  we have no mime-type information (treat as 'GNUNET_NO')
 */
int 
GNUNET_FS_meta_data_test_for_directory (const struct GNUNET_CONTAINER_MetaData *md);


/**
 * A URI (in internal representation).
 */
struct GNUNET_FS_Uri;


/**
 * Get a unique key from a URI.  This is for putting URIs
 * into HashMaps.  The key may change between FS implementations.
 *
 * @param uri uri to convert to a unique key
 * @param key wherer to store the unique key
 */
void 
GNUNET_FS_uri_to_key (const struct GNUNET_FS_Uri *uri,
		      GNUNET_HashCode * key);

/**
 * Convert a URI to a UTF-8 String.
 *
 * @param uri uri to convert to a string
 * @return the UTF-8 string
 */
char *
GNUNET_FS_uri_to_string (const struct GNUNET_FS_Uri *uri);

/**
 * Convert keyword URI to a human readable format
 * (i.e. the search query that was used in the first place)
 *
 * @param uri ksk uri to convert to a string 
 * @return string with the keywords
 */
char *
GNUNET_FS_ksk_uri_ksk_to_string_fancy (const struct GNUNET_FS_Uri *uri);

/**
 * Convert a UTF-8 String to a URI.
 *
 * @param uri string to parse
 * @param emsg where to store the parser error message (if any)
 * @return NULL on error
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_parse (const char *uri,
		     char **emsg);

/**
 * Free URI.
 *
 * @param uri uri to free
 */
void 
GNUNET_FS_uri_destroy (struct GNUNET_FS_Uri *uri);


/**
 * How many keywords are ANDed in this keyword URI?
 *
 * @param uri ksk uri to get the number of keywords from
 * @return 0 if this is not a keyword URI
 */
unsigned int 
GNUNET_FS_uri_ksk_get_keyword_count (const struct GNUNET_FS_Uri *uri);


/**
 * Iterate over all keywords in this keyword URI.
 *
 * @param uri ksk uri to get the keywords from
 * @param iterator function to call on each keyword
 * @param iterator_cls closure for iterator
 * @return -1 if this is not a keyword URI, otherwise number of
 *   keywords iterated over until iterator aborted
 */
int 
GNUNET_FS_uri_ksk_get_keywords (const struct GNUNET_FS_Uri *uri,
				GNUNET_FS_KeywordIterator iterator, 
				void *iterator_cls);


/**
 * Obtain the identity of the peer offering the data
 *
 * @param uri the location URI to inspect
 * @param peer where to store the identify of the peer (presumably) offering the content
 * @return GNUNET_SYSERR if this is not a location URI, otherwise GNUNET_OK
 */
int
GNUNET_FS_uri_loc_get_peer_identity (const struct GNUNET_FS_Uri *uri,
				     struct GNUNET_PeerIdentity * peer);


/**
 * Obtain the URI of the content itself.
 *
 * @param uri location URI to get the content URI from
 * @return NULL if argument is not a location URI
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_loc_get_uri (const struct GNUNET_FS_Uri *uri);


/**
 * Construct a location URI (this peer will be used for the location).
 *
 * @param baseURI content offered by the sender
 * @param cfg configuration information (used to find our hostkey)
 * @param expiration_time how long will the content be offered?
 * @return the location URI, NULL on error
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_loc_create (const struct GNUNET_FS_Uri *baseUri,
			  struct GNUNET_CONFIGURATION_Handle *cfg,
			  struct GNUNET_TIME_Absolute expiration_time);


/**
 * Duplicate URI.
 *
 * @param uri the URI to duplicate
 * @return copy of the URI
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_dup (const struct GNUNET_FS_Uri *uri);


/**
 * Create an FS URI from a single user-supplied string of keywords.
 * The string is broken up at spaces into individual keywords.
 * Keywords that start with "+" are mandatory.  Double-quotes can
 * be used to prevent breaking up strings at spaces (and also
 * to specify non-mandatory keywords starting with "+").
 *
 * Keywords must contain a balanced number of double quotes and
 * double quotes can not be used in the actual keywords (for
 * example, the string '""foo bar""' will be turned into two
 * "OR"ed keywords 'foo' and 'bar', not into '"foo bar"'.
 *
 * @param keywords the keyword string
 * @return an FS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_ksk_create (const char *keywords);


/**
 * Create an FS URI from a user-supplied command line of keywords.
 * Arguments should start with "+" to indicate mandatory
 * keywords.
 *
 * @param argc number of keywords
 * @param argv keywords (double quotes are not required for
 *             keywords containing spaces; however, double
 *             quotes are required for keywords starting with
 *             "+"); there is no mechanism for having double
 *             quotes in the actual keywords (if the user
 *             did specifically specify double quotes, the
 *             caller should convert each double quote
 *             into two single quotes).
 * @return an FS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_ksk_create_from_args (unsigned int argc,
				    const char **argv);


/**
 * Test if two URIs are equal.
 *
 * @param u1 one of the URIs
 * @param u2 the other URI
 * @return GNUNET_YES if the URIs are equal
 */
int 
GNUNET_FS_uri_test_equal (const struct GNUNET_FS_Uri *u1,
			  const struct GNUNET_FS_Uri *u2);


/**
 * Is this a namespace URI?
 *
 * @param uri the uri to check
 * @return GNUNET_YES if this is an SKS uri
 */
int
GNUNET_FS_uri_test_sks (const struct GNUNET_FS_Uri *uri);


/**
 * Get the ID of a namespace from the given
 * namespace URI.
 *
 * @param uri the uri to get the namespace ID from
 * @param nsid where to store the ID of the namespace
 * @return GNUNET_OK on success
 */
int 
GNUNET_FS_uri_sks_get_namespace (const struct GNUNET_FS_Uri *uri,
				 GNUNET_HashCode * nsid);


/**
 * Get the content identifier of an SKS URI.
 *
 * @param uri the sks uri
 * @return NULL on error (not a valid SKS URI)
 */
char *
GNUNET_FS_uri_sks_get_content_id (const struct GNUNET_FS_Uri *uri);


/**
 * Convert namespace URI to a human readable format
 * (using the namespace description, if available).
 *
 * @param cfg configuration to use
 * @param uri SKS uri to convert
 * @return NULL on error (not an SKS URI)
 */
char *
GNUNET_FS_uri_sks_to_string_fancy (struct GNUNET_CONFIGURATION_Handle *cfg,
				   const struct GNUNET_FS_Uri *uri);


/**
 * Is this a keyword URI?
 *
 * @param uri the uri
 * @return GNUNET_YES if this is a KSK uri
 */
int 
GNUNET_FS_uri_test_ksk (const struct GNUNET_FS_Uri *uri);


/**
 * Is this a file (or directory) URI?
 *
 * @param uri the uri to check
 * @return GNUNET_YES if this is a CHK uri
 */
int 
GNUNET_FS_uri_test_chk (const struct GNUNET_FS_Uri *uri);


/**
 * What is the size of the file that this URI
 * refers to?
 *
 * @param uri the CHK URI to inspect
 * @return size of the file as specified in the CHK URI
 */
uint64_t 
GNUNET_FS_uri_chk_get_file_size (const struct GNUNET_FS_Uri *uri);


/**
 * Is this a location URI?
 *
 * @param uri the uri to check
 * @return GNUNET_YES if this is a LOC uri
 */
int 
GNUNET_FS_uri_test_loc (const struct GNUNET_FS_Uri *uri);


/**
 * Construct a keyword-URI from meta-data (take all entries
 * in the meta-data and construct one large keyword URI
 * that lists all keywords that can be found in the meta-data).
 * @deprecated
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_ksk_create_from_meta_data (const struct GNUNET_MetaData *md);


/**
 * Command-line option parser function that allows the user
 * to specify one or more '-k' options with keywords.  Each
 * specified keyword will be added to the URI.  A pointer to
 * the URI must be passed as the "scls" argument.
 *
 * @param ctx command line processor context
 * @param scls must be of type "struct GNUNET_FS_Uri **"
 * @param option name of the option (typically 'k')
 * @param value command line argument given
 * @return GNUNET_OK on success
 */
int
GNUNET_FS_getopt_configure_set_keywords (GNUNET_GETOPT_CommandLineProcessorContext* ctx, 
					 void *scls,
					 const char *option,
					 const char *value);


/**
 * Command-line option parser function that allows the user to specify
 * one or more '-m' options with metadata.  Each specified entry of
 * the form "type=value" will be added to the metadata.  A pointer to
 * the metadata must be passed as the "scls" argument.
 *
 * @param ctx command line processor context
 * @param scls must be of type "struct GNUNET_MetaData **"
 * @param option name of the option (typically 'k')
 * @param value command line argument given
 * @return GNUNET_OK on success
 */
int
GNUNET_FS_getopt_configure_set_metadata (GNUNET_GETOPT_CommandLineProcessorContext* ctx, 
					 void *scls,
					 const char *option,
					 const char *value);



/* ************************* sharing API ***************** */


/**
 * Possible status codes used in the callback for the 
 * various file-sharing operations.  On each file (or search),
 * the callback is guaranteed to be called once with "START"
 * and once with STOPPED; calls with PROGRESS, ERROR or COMPLETED
 * are optional and depend on the circumstances; parent operations
 * will be STARTED before child-operations and STOPPED after
 * their respective child-operations.  START and STOP signals 
 * are typically generated either due to explicit client requests
 * or because of suspend/resume operations.
 */
enum GNUNET_FS_Status
{
  GNUNET_FS_STATUS_SHARE_START,
  GNUNET_FS_STATUS_SHARE_RESUME,
  GNUNET_FS_STATUS_SHARE_SUSPEND,
  GNUNET_FS_STATUS_SHARE_PROGRESS,
  GNUNET_FS_STATUS_SHARE_ERROR,
  GNUNET_FS_STATUS_SHARE_COMPLETED,
  GNUNET_FS_STATUS_SHARE_STOPPED,
  GNUNET_FS_STATUS_DOWNLOAD_START,
  GNUNET_FS_STATUS_DOWNLOAD_RESUME,
  GNUNET_FS_STATUS_DOWNLOAD_SUSPEND,
  GNUNET_FS_STATUS_DOWNLOAD_PROGRESS,
  GNUNET_FS_STATUS_DOWNLOAD_ERROR,
  GNUNET_FS_STATUS_DOWNLOAD_COMPLETED,
  GNUNET_FS_STATUS_DOWNLOAD_STOPPED,
  GNUNET_FS_STATUS_SEARCH_START,
  GNUNET_FS_STATUS_SEARCH_RESUME,
  GNUNET_FS_STATUS_SEARCH_RESUME_RESULT,
  GNUNET_FS_STATUS_SEARCH_SUSPEND,
  GNUNET_FS_STATUS_SEARCH_RESULT,
  GNUNET_FS_STATUS_SEARCH_UPDATE,
  GNUNET_FS_STATUS_SEARCH_ERROR,
  GNUNET_FS_STATUS_SEARCH_STOPPED,
  GNUNET_FS_STATUS_UNINDEX_START,
  GNUNET_FS_STATUS_UNINDEX_RESUME,
  GNUNET_FS_STATUS_UNINDEX_SUSPEND,
  GNUNET_FS_STATUS_UNINDEX_PROGRESS,
  GNUNET_FS_STATUS_UNINDEX_ERROR,
  GNUNET_FS_STATUS_UNINDEX_STOPPED,
  GNUNET_FS_STATUS_NAMESPACE_DISCOVERED
};


/**
 * Notification of FS to a client about the progress of an 
 * operation.  Callbacks of this type will be used for uploads,
 * downloads and searches.  Some of the arguments depend a bit 
 * in their meaning on the context in which the callback is used.
 *
 * @param cls closure
 * @param cctx client-context (for the next progress call
 *        for this operation; should be set to NULL for
 *        SUSPEND and STOPPED events)
 * @param ctx location where the callback can store a context pointer
 *        to keep track of things for this specific operation
 * @param pctx context pointer set by the callback for the parent operation
 *        (NULL if there is no parent operation); for a search result,
 *        the actual search is the parent and the individual search results
 *        are the children (multiple calls for the same search result can
 *        be used whenever availability/certainty or metadata values change)
 * @param filename name of the file that this update is about, NULL for 
 *        searches
 * @param availability value between 0 and 100 indicating how likely
 *        we think it is that this search result is actually available
 *        in the network (or, in the case of a download, that the download 
 *        will complete); always 100 for uploads; percentage of blocks
 *        that could be unindexed so far for unindexing operations
 *        (indicates how many blocks in the indexed file changed in 
 *        the meantime)
 * @param certainty how certain are we that the availability value is
 *        actually correct?  certainty is also between 0 and 100.
 * @param fsize number of bytes that will need to be processed (for this file)
 * @param completed number of bytes that have been processed (for this file)
 * @param offset offset of the data of buffer in the file
 * @param eta absolute estimated time for the completion of the operation
 * @param uri pointer to CHK URI for search results and downloads; pointer
 *        to KSK uri for uploads; client can modify KSK uri to change the
 *        set of keywords that will be used
 * @param meta metadata for search results and downloads (NULL for downloads
 *        if no metadata is available); can be modified for uploads to change
 *        metadata that will be used
 * @param bsize number of bytes in the buffer
 * @param buffer pointer to the last bytes processed; will be a plaintext
 *        buffer for files (with content downloaded or uploaded) and 
 *        NULL when searching; points to an error message of bsize bytes
 *        if this callback is used to signal an error
 * @return GNUNET_SYSERR to abort the overall operation; GNUNET_NO to
 *        stop this specific operation (do not share this file or skip
 *        this download; GNUNET_NO has no meaning for search results);
 *        GNUNET_YES to continue processing as usual
 * @deprecated (use 2-arg function getting union argument instead)
 */
typedef int (*GNUNET_FS_ProgressCallback)
  (void *cls,
   void **cctx,
   const struct GNUNET_FS_ProgressInfo *info);


   void **ctx,
   void *pctx,
   const char *filename,
   enum GNUNET_FS_Status status,
   float availability,
   float certainty,
   uint64_t fsize,
   uint64_t completed, 
   uint64_t offset, struct GNUNET_TIME_Absolute eta,
   struct GNUNET_FS_Uri **uri,
   struct GNUNET_CONTAINER_MetaData *meta,
   size_t bsize, const void *buffer);



/**
 * Handle to one of our namespaces.
 */
struct GNUNET_FS_Namespace;


/**
 * Handle for controlling an upload.
 */
struct GNUNET_FS_ShareContext;


/**
 * Handle for controlling an unindexing operation.
 */
struct GNUNET_FS_UnindexContext;


/**
 * Handle for controlling a search.
 */
struct GNUNET_FS_SearchContext;


/**
 * Context for controlling a download.
 */
struct GNUNET_FS_DownloadContext;


/**
 * Handle for detail information about a file that is being shared.
 * Specifies metadata, keywords, how to get the contents of the file
 * (i.e. data-buffer in memory, filename on disk) and other options.
 */
struct GNUNET_FS_FileInformation;


/**
 * Argument given to the progress callback with
 * information about what is going on.
 */
struct GNUNET_FS_ProgressInfo
{  

  /**
   * Values that depend on the event type.
   */
  union {
    
    /**
     * Values for all "GNUNET_FS_STATUS_SHARE_*" events.
     */
    struct {

      /**
       * Context for controlling the upload.
       */
      struct GNUNET_FS_ShareContext *sc;

      /**
       * Information about the file that is being shared.
       */
      struct GNUNET_FS_FileInformation *fi;

      /**
       * Client context pointer (set the last time
       * by the client for this operation; initially
       * NULL on START/RESUME events).
       */
      void *cctx;

      /**
       * Client context pointer for the parent operation
       * (if this is a file in a directory or a subdirectory).
       */
      void *pctx;
      
      /**
       * How large is the file overall?  For directories,
       * this is only the size of the directory itself,
       * not of the other files contained within the 
       * directory.
       */
      uint64_t size;

      /**
       * At what time do we expect to finish the upload?
       * (will be a value in the past for completed
       * uploads).
       */ 
      struct GNUNET_TIME_Absolute eta;

      /**
       * How many bytes have we completed?
       */
      uint64_t completed;

      /**
       * Additional values for specific events.
       */
      union {

	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_SHARE_PROGRESS events.
	 */
	struct {
	  
	  /**
	   * Data block we just published.
	   */
	  const void *data;
	  
	  /**
	   * At what offset in the file is "data"?
	   */
	  uint64_t offset;
	  
	  /**
	   * Length of the data block.
	   */
	  uint64_t data_len;

	} progress;

	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_SHARE_ERROR events.
	 */
	struct {
	  
	  /**
	   * Error message.
	   */
	  const char *message;

	} error;

      } specifics;

    } share;

    
    /**
     * Values for all "GNUNET_FS_STATUS_DOWNLOAD_*" events.
     */
    struct {

      /**
       * Context for controlling the download.
       */
      struct GNUNET_FS_DownloadContext *dc;

      /**
       * Client context pointer (set the last time
       * by the client for this operation; initially
       * NULL on START/RESUME events).
       */
      void *cctx;

      /**
       * Client context pointer for the parent operation
       * (if this is a file in a directory or a subdirectory).
       */
      void *pctx;
      
      /**
       * How large is the file overall?  For directories,
       * this is only the size of the directory itself,
       * not of the other files contained within the 
       * directory.
       */
      uint64_t size;

      /**
       * At what time do we expect to finish the upload?
       * (will be a value in the past for completed
       * uploads).
       */ 
      struct GNUNET_TIME_Absolute eta;

      /**
       * How many bytes have we completed?
       */
      uint64_t completed;

      /**
       * Additional values for specific events.
       */
      union {
	
	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_DOWNLOAD_PROGRESS events.
	 */
	struct {
  
	  /**
	   * Data block we just obtained.
	   */
	  const void *data;
	  
	  /**
	   * At what offset in the file is "data"?
	   */
	  uint64_t offset;
	  
	  /**
	   * Length of the data block.
	   */
	  uint64_t data_len;

	  /**
	   * Amount of trust we offered to get the block.
	   */
	  unsigned int trust_offered;	  

	} progress;

	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_DOWNLOAD_ERROR events.
	 */
	struct {

	  /**
	   * Error message.
	   */
	  const char *message;

	} error;

      } specifics;

    } download;

    /**
     * Values for all "GNUNET_FS_STATUS_SEARCH_*" events.
     */
    struct {

      /**
       * Context for controlling the search.
       */
      struct GNUNET_FS_SearchContext *sc;

      /**
       * Client context pointer (set the last time by the client for
       * this operation; initially NULL on START/RESUME events).  Note
       * that this value can only be set on START/RESUME; setting
       * "cctx" on RESULT/RESUME_RESULT will actually update the
       * private context for "UPDATE" events.
       */
      void *cctx;

      /**
       * Additional values for specific events.
       */
      union {
	
	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_SEARCH_RESULT events.
	 */
	struct {
	  
	  /**
	   * Metadata for the search result.
	   */
	  struct GNUNET_MetaData *meta;
	  // FIXME...

	} result;
	
	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_SEARCH_RESUME_RESULT events.
	 */
	struct {
	  
	  /**
	   * Metadata for the search result.
	   */
	  struct GNUNET_MetaData *meta;
	  // FIXME...
	  
	} resume_result;
	
	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_SEARCH_UPDATE events.
	 */
	struct {

	  /**
	   * Private context set for for this result
	   * during the "RESULT" event.
	   */
	  void *cctx;
	  // FIXME...

	} update;

	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_SEARCH_ERROR events.
	 */
	struct {

	  /**
	   * Error message.
	   */
	  const char *message;

	} error;

      } specifics;

    } search;

    /**
     * Values for all "GNUNET_FS_STATUS_UNINDEX_*" events.
     */
    struct {

      /**
       * Context for controlling the unindexing.
       */
      struct GNUNET_FS_UnindexContext *uc;

      /**
       * Client context pointer (set the last time
       * by the client for this operation; initially
       * NULL on START/RESUME events).
       */
      void *cctx;

      /**
       * How large is the file overall?
       */
      uint64_t size;

      /**
       * At what time do we expect to finish unindexing?
       * (will be a value in the past for completed
       * unindexing opeations).
       */ 
      struct GNUNET_TIME_Absolute eta;

      /**
       * How many bytes have we completed?
       */
      uint64_t completed;

      /**
       * Additional values for specific events.
       */
      union {

	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_UNINDEX_PROGRESS events.
	 */
	struct {
  
	  /**
	   * Data block we just unindexed.
	   */
	  const void *data;
	  
	  /**
	   * At what offset in the file is "data"?
	   */
	  uint64_t offset;
	  
	  /**
	   * Length of the data block.
	   */
	  uint64_t data_len;

	} progress;

	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_UNINDEX_ERROR events.
	 */
	struct {

	  /**
	   * Error message.
	   */
	  const char *message;

	} error;

      } specifics;

    } unindex;

    
    /**
     * Values for all "GNUNET_FS_STATUS_NAMESPACE_*" events.
     */
    struct {
      /**
       * Handle to the namespace (NULL if it is not a local
       * namespace).
       */
      struct GNUNET_FS_Namespace *ns;

      /**
       * Short, human-readable name of the namespace.
       */
      const char *name;

      /**
       * Root identifier for the namespace, can be NULL.
       */
      const char *root;

      /**
       * Metadata for the namespace.
       */
      struct GNUNET_CONTAINER_MetaData *meta;

      /**
       * Hash-identifier for the namespace.
       */
      struct GNUNET_HashCode id;      

    } namespace;

  } value;

  /**
   * Specific status code (determines the event type).
   */  
  enum GNUNET_FS_Status status;

};


/**
 * Handle to the file-sharing service.
 */
struct GNUNET_FS_Handle;


/**
 * Setup a connection to the file-sharing service.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param client_name unique identifier for this client 
 * @param upcb function to call to notify about FS actions
 * @param upcb_cls closure for upcb
 */
struct GNUNET_FS_Handle *
GNUNET_FS_start (struct GNUNET_SCHEDULER_Handle *sched,
		 struct GNUNET_CONFIGURATION_Handle *cfg,
		 const char *client_name,
		 GNUNET_FS_ProgressCallback upcb,
		 void *upcb_cls);


/**
 * Close our connection with the file-sharing service.
 * The callback given to GNUNET_FS_start will no longer be
 * called after this function returns.
 *
 * @param h handle that was returned from GNUNET_FS_start
 */                    
void 
GNUNET_FS_stop (struct GNUNET_FS_Handle *h); 


/**
 * Share a file or directory.
 *
 * @param h handle to the file sharing subsystem
 * @param ctx initial value to use for the '*ctx' in the callback
 * @param filename name of the file or directory to share
 * @param do_index GNUNET_YES for index, GNUNET_NO for insertion,
 *                GNUNET_SYSERR for simulation
 * @param anonymity what is the desired anonymity level for sharing?
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param expirationTime when should this content expire?
 * @param namespace namespace to share the file in, NULL for no namespace
 * @param nid identifier to use for the shared content in the namespace
 *        (can be NULL, must be NULL if namespace is NULL)
 * @param nuid update-identifier that will be used for future updates 
 *        (can be NULL, must be NULL if namespace or nid is NULL)
 * @deprecated API not powerful enough to share complex directory structures
 *         with metadata in general (need to pre-build tree)
 */
struct GNUNET_FS_ShareContext *
GNUNET_FS_share_start (struct GNUNET_FS_Handle *h,
		       void *ctx,
		       const char *filename,
		       int do_index,
		       unsigned int anonymity,
		       unsigned int priority,
		       struct GNUNET_TIME_Absolute expirationTime,
		       struct GNUNET_FS_Namespace *namespace
		       const char *nid,
		       const char *nuid);


/**
 * Stop an upload.  Will abort incomplete uploads (but 
 * not remove blocks that have already been shared) or
 * simply clean up the state for completed uploads.
 *
 * @param sc context for the upload to stop
 */
void 
GNUNET_FS_share_stop (struct GNUNET_FS_ShareContext *sc);


/**
 * Type of a function called by "GNUNET_FS_get_indexed_files".
 *
 * @param cls closure
 * @param filename the name of the file
 * @return GNUNET_OK to continue iteration, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_FS_FileProcessor) (void *cls,
					const char *filename);


/**
 * Iterate over all indexed files.
 *
 * @param h handle to the file sharing subsystem
 * @param iterator function to call on each indexed file
 * @param iterator_cls closure for iterator
 */
void 
GNUNET_FS_get_indexed_files (struct GNUNET_FS_Handle *h,
			     GNUNET_FS_FileProcessor iterator,
			     void *iterator_cls);





/**
 * Unindex a file.
 *
 * @param h handle to the file sharing subsystem
 * @param filename file to unindex
 * @return NULL on error, otherwise handle 
 */
struct GNUNET_FS_UnindexContext *
GNUNET_FS_unindex (struct GNUNET_FS_Handle *h,
		   const char *filename);


/**
 * Clean up after completion of an unindex operation.
 *
 * @param uc handle
 */
void
GNUNET_FS_unindex_stop (struct GNUNET_FS_UnindexContext *uc);



/**
 * Publish an advertismement for a namespace.  
 *
 * @param h handle to the file sharing subsystem
 * @param namespace handle for the namespace that should be advertised
 * @param meta meta-data for the namespace advertisement
 * @param anonymity for the namespace advertismement
 * @param priority for the namespace advertisement
 * @param expiration for the namespace advertisement
 * @param advertisementURI the keyword (!) URI to advertise the
 *        namespace under (we will create a GNUNET_EC_KNBlock)
 * @param rootEntry name of the root entry in the namespace (for
 *        the namespace advertisement)
 *
 * @return uri of the advertisement
 */
struct GNUNET_FS_Uri *
GNUNET_FS_namespace_advertise (struct GNUNET_FS_Handle *h,
			       struct GNUNET_FS_Namespace *namespace,
			       const struct GNUNET_MetaData *meta,
			       unsigned int anonymity,
			       unsigned int priority,
			       struct GNUNET_TIME_Absolute expiration,
			       const struct GNUNET_FS_Uri *advertisementURI,
			       const char *rootEntry);


/**
 * Create a namespace with the given name; if one already
 * exists, return a handle to the existing namespace.
 *
 * @param h handle to the file sharing subsystem
 * @param name name to use for the namespace
 * @return handle to the namespace, NULL on error
 */
struct GNUNET_FS_Namespace *
GNUNET_FS_namespace_create (struct GNUNET_FS_Handle *h,
			    const char *name);


/**
 * Delete a namespace handle.  Can be used for a clean shutdown (free
 * memory) or also to freeze the namespace to prevent further
 * insertions by anyone.
 *
 * @param namespace handle to the namespace that should be deleted / freed
 * @param freeze prevents future insertions; creating a namespace
 *        with the same name again will create a fresh namespace instead
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int 
GNUNET_FS_namespace_delete (struct GNUNET_FS_Namespace *namespace,
			    int freeze);


/**
 * Callback with information about local (!) namespaces.
 * Contains the names of the local namespace and the global
 * ID.
 *
 * @param cls closure
 * @param name human-readable identifier of the namespace
 * @param id hash identifier for the namespace
 */
typedef void (*GNUNET_FS_NamespaceInfoProcessor) (void *cls,
						  const char *name,
						  const GNUNET_HashCode *id);


/**
 * Build a list of all available local (!) namespaces The returned
 * names are only the nicknames since we only iterate over the local
 * namespaces.
 *
 * @param h handle to the file sharing subsystem
 * @param cb function to call on each known namespace
 * @param cb_cls closure for cb
 * @return GNUNET_SYSERR on error, otherwise the number of pseudonyms in list
 */
int 
GNUNET_FS_namespace_list (struct GNUNET_FS_Handle *h,
			  GNUNET_FS_NamespaceProcessor cb,
			  void *cb_cls);


/**
 * Function called on updateable identifiers.
 *
 * @param cls closure
 * @param last_id last identifier 
 * @param last_uri uri used for the content published under the last_id
 * @param last_meta metadata associated with last_uri
 * @param next_id identifier that should be used for updates
 */
typedef void 
(*GNUNET_FS_IdentifierProcessor)(void *cls,
				 const char *last_id, 
				 const struct GNUNET_FS_Uri *last_uri,
				 const struct GNUNET_CONTAINER_MetaData *last_meta,
				 const char *next_id);


/**
 * List all of the identifiers in the namespace for 
 * which we could produce an update.
 *
 * @param namespace namespace to inspect for updateable content
 * @param ip function to call on each updateable identifier
 * @param ip_cls closure for ip
 */
void
GNUNET_FS_namespace_list_updateable (struct GNUNET_FS_Namespace *namespace,
				     GNUNET_FS_IdentifierProcessor ip, 
				     void *ip_cls);


/**
 * Start search for content.
 *
 * @param h handle to the file sharing subsystem
 * @param uri specifies the search parameters; can be
 *        a KSK URI or an SKS URI.
 * @param anonymity desired level of anonymity
 * @return context that can be used to control the search
 */
struct GNUNET_FS_SearchContext *
GNUNET_FS_search_start (struct GNUNET_FS_Handle *h,
			const struct GNUNET_FS_Uri *uri,
			unsigned int anonymity);


/**
 * Pause search.  
 *
 * @param sc context for the search that should be paused
 */
void 
GNUNET_FS_search_pause (struct GNUNET_FS_SearchContext *sc);


/**
 * Resume paused search.
 *
 * @param sc context for the search that should be resumed
 */
void 
GNUNET_FS_search_resume (struct GNUNET_FS_SearchContext *sc);


/**
 * Stop search for content.
 *
 * @param sc context for the search that should be stopped
 */
void 
GNUNET_FS_search_stop (struct GNUNET_FS_SearchContext *sc);


/**
 * Download parts of a file.  Note that this will store
 * the blocks at the respective offset in the given file.  Also, the
 * download is still using the blocking of the underlying FS
 * encoding.  As a result, the download may *write* outside of the
 * given boundaries (if offset and length do not match the 32k FS
 * block boundaries). <p>
 *
 * This function should be used to focus a download towards a
 * particular portion of the file (optimization), not to strictly
 * limit the download to exactly those bytes.
 *
 * @param h handle to the file sharing subsystem
 * @param uri the URI of the file (determines what to download); CHK or LOC URI
 * @param filename where to store the file, maybe NULL (then no file is
 *        created on disk and data must be grabbed from the callbacks)
 * @param offset at what offset should we start the download (typically 0)
 * @param length how many bytes should be downloaded starting at offset
 * @param anonymity anonymity level to use for the download
 * @param no_temporaries set to GNUNET_YES to disallow generation of temporary files
 * @param recursive should this be a recursive download (useful for directories
 *        to automatically trigger download of files in the directories)
 * @param parent parent download to associate this download with (use NULL
 *        for top-level downloads; useful for manually-triggered recursive downloads)
 * @return context that can be used to control this download
 */
struct GNUNET_FS_DownloadContext *
GNUNET_FS_file_download_start (struct GNUNET_FS_Handle *h,
			       const struct GNUNET_FS_Uri *uri,
			       const char *filename,
			       unsigned long long offset,
			       unsigned long long length,
			       unsigned int anonymity,
			       int no_temporaries,	
			       int recursive,
			       struct GNUNET_FS_DownloadContext *parent);


/**
 * Stop a download (aborts if download is incomplete).
 *
 * @param rm handle for the download
 * @param do_delete delete files of incomplete downloads
 */
void
GNUNET_FS_file_download_stop (struct GNUNET_FS_DownloadContext *rm,
			      int do_delete);


/**
 * Iterate over all entries in a directory.  Note that directories
 * are structured such that it is possible to iterate over the
 * individual blocks as well as over the entire directory.  Thus
 * a client can call this function on the buffer in the
 * GNUNET_FS_ProgressCallback.
 *
 * @param size number of bytes in data
 * @param data pointer to the beginning of the directory
 * @param offset offset of data in the directory
 * @param spcb function to call on each entry
 * @param spcb_cls closure for spcb
 */
void 
GNUNET_FS_directory_list_contents (size_t size,
				   const void *data,
				   uint64_t offset,
				   GNUNET_FS_SearchResultProcessor spcb, 
				   void *spcb_cls);


/**
 * Create a directory.
 *
 * @param data pointer set to the beginning of the directory
 * @param len set to number of bytes in data
 * @param count number of entries in uris and metaDatas

 * @param uris URIs of the files in the directory
 * @param metaDatas meta-data for the files (must match
 *        respective values at same offset in in uris)
 * @param meta meta-data for the directory.  The meta entry
 *        is extended with the mime-type for a GNUnet directory.

 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 * @deprecated (not powerful enough?)
 */
int 
GNUNET_FS_directory_create (char **data,
			    uint64_t *len,
			    unsigned int count,
			    const GNUNET_FS_FileInfo * fis,
			    struct GNUNET_MetaData *meta);


/**
 * Initialize collection.
 *
 * @param h handle to the file sharing subsystem
 * @param namespace namespace to use for the collection
 * @return GNUNET_OK on success, GNUNET_SYSERR if another
 *         namespace is already set for our collection
 */
int 
GNUNET_FS_collection_start (struct GNUNET_FS_Handle *h,
			    struct GNUNET_FS_Namespace *namespace);


/**
 * Stop collection.
 *
 * @param h handle to the file sharing subsystem
 * @return GNUNET_OK on success, GNUNET_SYSERR if no collection is active
 */
int 
GNUNET_CO_collection_stop (struct GNUNET_FS_Handle *h);


/**
 * Are we using a collection?
 *
 * @param h handle to the file sharing subsystem
 * @return NULL if there is no collection,
 */
struct GNUNET_FS_Namespace *
GNUNET_FS_collection_get(struct GNUNET_FS_Handle *h);


/**
 * Publish an update of the current collection information to the
 * network now.  The function has no effect if the collection has not
 * changed since the last publication.  If we are currently not
 * collecting, this function does nothing.
 *
 * @param h handle to the file sharing subsystem
 */
void GNUNET_FS_collection_publish (struct GNUNET_FS_Handle *h);


/**
 * If we are currently building a collection, publish the given file
 * information in that collection.  If we are currently not
 * collecting, this function does nothing.
 *
 * @param h handle to the file sharing subsystem
 * @param uri uri to add to the collection
 * @param meta metadata for the uri
 */
void GNUNET_FS_collection_add (const struct GNUNET_FS_Handle *h,
			       const struct GNUNET_FS_Uri *uri,
			       const struct GNUNET_CONTAINER_MetaData *meta);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
