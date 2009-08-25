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
/**
 * @file include/gnunet_fs_service.h
 * @brief API for file-sharing via GNUnet 
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


/* ******************** URI API *********************** */

#define GNUNET_FS_URI_PREFIX "gnunet://fs/"
#define GNUNET_FS_URI_KSK_INFIX "ksk/"
#define GNUNET_FS_URI_SKS_INFIX "sks/"
#define GNUNET_FS_URI_CHK_INFIX "chk/"
#define GNUNET_FS_URI_LOC_INFIX "loc/"


/**
 * A Universal Resource Identifier (URI), opaque.
 */
struct GNUNET_FS_Uri;


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
GNUNET_FS_uri_ksk_to_string_fancy (const struct GNUNET_FS_Uri *uri);

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
 * Canonicalize keyword URI.  Performs operations such
 * as decapitalization and removal of certain characters.
 * (useful for search).
 *
 * @param uri the URI to canonicalize 
 * @return canonicalized version of the URI, NULL on error
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_ksk_canonicalize (const struct GNUNET_FS_Uri *uri);


/**
 * Merge the sets of keywords from two KSK URIs.
 * (useful for merging the canonicalized keywords with
 * the original keywords for sharing).
 *
 * @param u1 first uri
 * @param u2 second uri
 * @return merged URI, NULL on error
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_ksk_merge (const struct GNUNET_FS_Uri *u1,
			 const struct GNUNET_FS_Uri *u2);


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
 * @param emsg where to store an error message
 * @return an FS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_ksk_create (const char *keywords,
			  char **emsg);


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
GNUNET_FS_uri_ksk_create_from_meta_data (const struct GNUNET_CONTAINER_MetaData *md);


/* ******************** command-line option parsing API *********************** */

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
GNUNET_FS_getopt_configure_set_keywords (struct GNUNET_GETOPT_CommandLineProcessorContext* ctx, 
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
GNUNET_FS_getopt_configure_set_metadata (struct GNUNET_GETOPT_CommandLineProcessorContext* ctx, 
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
  /**
   * Notification that we have started to publish a file structure.
   */
  GNUNET_FS_STATUS_PUBLISH_START,

  /**
   * Notification that we have resumed sharing a file structure.
   */
  GNUNET_FS_STATUS_PUBLISH_RESUME,

  /**
   * Notification that we have suspended sharing a file structure.
   */
  GNUNET_FS_STATUS_PUBLISH_SUSPEND,

  /**
   * Notification that we are making progress sharing a file structure.
   */
  GNUNET_FS_STATUS_PUBLISH_PROGRESS,

  /**
   * Notification that an error was encountered  sharing a file structure.
   * The application will continue to receive resume/suspend events for
   * this structure until "GNUNET_FS_publish_stop" is called.
   */
  GNUNET_FS_STATUS_PUBLISH_ERROR,

  /**
   * Notification that we completed sharing a file structure.
   * The application will continue to receive resume/suspend events for
   * this structure until "GNUNET_FS_publish_stop" is called.
   */
  GNUNET_FS_STATUS_PUBLISH_COMPLETED,

  /**
   * Notification that we have stopped
   * the process of uploading a file structure; no
   * futher events will be generated for this action.
   */
  GNUNET_FS_STATUS_PUBLISH_STOPPED,

  /**
   * Notification that we have started this download.
   */
  GNUNET_FS_STATUS_DOWNLOAD_START,

  /**
   * Notification that this download is being resumed.
   */
  GNUNET_FS_STATUS_DOWNLOAD_RESUME,

  /**
   * Notification that this download was suspended.
   */
  GNUNET_FS_STATUS_DOWNLOAD_SUSPEND,

  /**
   * Notification about progress with this download.
   */
  GNUNET_FS_STATUS_DOWNLOAD_PROGRESS,

  /**
   * Notification that this download encountered an error.
   */
  GNUNET_FS_STATUS_DOWNLOAD_ERROR,

  /**
   * Notification that this download completed.  Note that for
   * directories, completion does not imply completion of all files in
   * the directory.
   */
  GNUNET_FS_STATUS_DOWNLOAD_COMPLETED,

  /**
   * Notification that this download was stopped
   * (final event with respect to this action).
   */
  GNUNET_FS_STATUS_DOWNLOAD_STOPPED,

  /**
   * First event generated when a client requests 
   * a search to begin or when a namespace result
   * automatically triggers the search for updates.
   */
  GNUNET_FS_STATUS_SEARCH_START,

  /**
   * Last event when a search is being resumed;
   * note that "GNUNET_FS_SEARCH_START" will not
   * be generated in this case.
   */
  GNUNET_FS_STATUS_SEARCH_RESUME,

  /**
   * Event generated for each search result
   * when the respective search is resumed.
   */
  GNUNET_FS_STATUS_SEARCH_RESUME_RESULT,

  /**
   * Last event when a search is being suspended;
   * note that "GNUNET_FS_SEARCH_STOPPED" will not
   * be generated in this case.
   */
  GNUNET_FS_STATUS_SEARCH_SUSPEND,
  
  /**
   * Event generated for each search result
   * when the respective search is suspended.
   */
  GNUNET_FS_STATUS_SEARCH_SUSPEND_RESULT,

  /**
   * This search has yielded a result.
   */
  GNUNET_FS_STATUS_SEARCH_RESULT,

  /**
   * We have discovered a new namespace.
   */
  GNUNET_FS_STATUS_SEARCH_RESULT_NAMESPACE,

  /**
   * We have additional data about the quality
   * or availability of a search result.
   */
  GNUNET_FS_STATUS_SEARCH_UPDATE,

  /**
   * Signals a problem with this search.
   */
  GNUNET_FS_STATUS_SEARCH_ERROR,

  /**
   * Signals that this search was paused.
   */
  GNUNET_FS_STATUS_SEARCH_PAUSED,

  /**
   * Signals that this search was continued (unpaused).
   */
  GNUNET_FS_STATUS_SEARCH_CONTINUED,

  /**
   * Event generated for each search result
   * when the respective search is stopped.
   */
  GNUNET_FS_STATUS_SEARCH_RESULT_STOPPED,

  /**
   * Last message from a search; this signals
   * that there will be no further events associated
   * with this search.
   */
  GNUNET_FS_STATUS_SEARCH_STOPPED,

  /**
   * Notification that we started to unindex a file.
   */ 
  GNUNET_FS_STATUS_UNINDEX_START,

  /**
   * Notification that we resumed unindexing of a file.
   */
  GNUNET_FS_STATUS_UNINDEX_RESUME,

  /**
   * Notification that we suspended unindexing a file.
   */
  GNUNET_FS_STATUS_UNINDEX_SUSPEND,

  /**
   * Notification that we made progress unindexing a file.
   */
  GNUNET_FS_STATUS_UNINDEX_PROGRESS,

  /**
   * Notification that we encountered an error unindexing
   * a file.
   */
  GNUNET_FS_STATUS_UNINDEX_ERROR,

  /**
   * Notification that the unindexing of this file
   * was stopped (final event for this action).
   */
  GNUNET_FS_STATUS_UNINDEX_STOPPED

};


/**
 * Handle to one of our namespaces.
 */
struct GNUNET_FS_Namespace;


/**
 * Handle for controlling an upload.
 */
struct GNUNET_FS_PublishContext;


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
 * Handle for detail information about a file that is being publishd.
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
     * Values for all "GNUNET_FS_STATUS_PUBLISH_*" events.
     */
    struct {

      /**
       * Context for controlling the upload.
       */
      struct GNUNET_FS_PublishContext *sc;

      /**
       * Information about the file that is being publishd.
       */
      const struct GNUNET_FS_FileInformation *fi;

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
       * How long has this upload been actively running
       * (excludes times where the upload was suspended).
       */
      struct GNUNET_TIME_Relative duration;

      /**
       * How many bytes have we completed?
       */
      uint64_t completed;

      /**
       * What anonymity level is used for this upload?
       */
      unsigned int anonymity;

      /**
       * Additional values for specific events.
       */
      union {

	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_PUBLISH_PROGRESS events.
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
	 * GNUNET_FS_STATUS_PUBLISH_RESUME events.
	 */
	struct {
	  
	  /**
	   * Error message, NULL if no error was encountered so far.
	   */
	  const char *message;

	} resume;

	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_PUBLISH_ERROR events.
	 */
	struct {
	  
	  /**
	   * Error message, never NULL.
	   */
	  const char *message;

	} error;

      } specifics;

    } publish;

    
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
       * URI used for this download.
       */
      const struct GNUNET_FS_Uri *uri;
      
      /**
       * How large is the file overall?  For directories,
       * this is only the size of the directory itself,
       * not of the other files contained within the 
       * directory.
       */
      uint64_t size;

      /**
       * At what time do we expect to finish the download?
       * (will be a value in the past for completed
       * uploads).
       */ 
      struct GNUNET_TIME_Absolute eta;

      /**
       * How long has this download been active?
       */ 
      struct GNUNET_TIME_Relative duration;

      /**
       * How many bytes have we completed?
       */
      uint64_t completed;

      /**
       * What anonymity level is used for this download?
       */
      unsigned int anonymity;

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
	 * GNUNET_FS_STATUS_DOWNLOAD_START events.
	 */
	struct {

	  /**
	   * Known metadata for the download.
	   */
	  const struct GNUNET_MetaData *meta;

	} start;

	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_DOWNLOAD_RESUME events.
	 */
	struct {

	  /**
	   * Known metadata for the download.
	   */
	  const struct GNUNET_MetaData *meta;

	  /**
	   * Error message, NULL if we have not encountered any error yet.
	   */
	  const char *message;

	} resume;

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
       * Context for controlling the search, NULL for
       * searches that were not explicitly triggered
       * by the client (i.e., searches for updates in
       * namespaces).
       */
      struct GNUNET_FS_SearchContext *sc;

      /**
       * Client context pointer (set the last time by the client for
       * this operation; initially NULL on START/RESUME events).  Note
       * that this value can only be set on START/RESUME; returning
       * non-NULL on RESULT/RESUME_RESULT will actually update the
       * private context for "UPDATE" events.
       */
      void *cctx;

      /**
       * Client parent-context pointer; NULL for top-level searches,
       * non-NULL for automatically triggered searches for updates in
       * namespaces.
       */
      void *pctx;

      /**
       * What query is used for this search
       * (list of keywords or SKS identifier).
       */
      const struct GNUNET_FS_Uri *query;

      /**
       * How long has this search been actively running
       * (excludes times where the search was paused or
       * suspended).
       */
      struct GNUNET_TIME_Relative duration;

      /**
       * What anonymity level is used for this search?
       */
      unsigned int anonymity;

      /**
       * How much trust have we been offering for this search
       * so far?
       */
      unsigned int trust_offered;

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
	  const struct GNUNET_MetaData *meta;

	  /**
	   * URI for the search result.
	   */
	  const struct GNUNET_FS_Uri *uri;

	} result;
	
	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_SEARCH_RESUME_RESULT events.
	 */
	struct {
	  
	  /**
	   * Metadata for the search result.
	   */
	  const struct GNUNET_MetaData *meta;

	  /**
	   * URI for the search result.
	   */
	  const struct GNUNET_FS_Uri *uri;

	  /**
	   * Current availability rank (negative:
	   * unavailable, positive: available)
	   */
	  int availability_rank;
 
	  /**
	   * On how many total queries is the given
	   * availability_rank based?
	   */
	  unsigned int availabiliy_certainty;

	  /**
	   * Updated applicability rank (the larger,
	   * the better the result fits the search
	   * criteria).
	   */
 	  unsigned int applicabiliy_rank;	  
	  
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
	  
	  /**
	   * Metadata for the search result.
	   */
	  const struct GNUNET_MetaData *meta;

	  /**
	   * URI for the search result.
	   */
	  const struct GNUNET_FS_Uri *uri;

	  /**
	   * Current availability rank (negative:
	   * unavailable, positive: available)
	   */
	  int availability_rank;
 
	  /**
	   * On how many total queries is the given
	   * availability_rank based?
	   */
	  unsigned int availabiliy_certainty;

	  /**
	   * Updated applicability rank (the larger,
	   * the better the result fits the search
	   * criteria).
	   */
 	  unsigned int applicabiliy_rank;

	} update;
	
	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_SEARCH_RESULT_SUSPEND events.
	 * These events are automatically triggered for
	 * each search result before the 
	 * GNUNET_FS_STATUS_SEARCH_SUSPEND event.  This
	 * happens primarily to give the client a chance
	 * to clean up the "cctx" (if needed).
	 */
	struct {

	  /**
	   * Private context set for for this result
	   * during the "RESULT" event.
	   */
	  void *cctx;
	  
	  /**
	   * Metadata for the search result.
	   */
	  const struct GNUNET_MetaData *meta;

	  /**
	   * URI for the search result.
	   */
	  const struct GNUNET_FS_Uri *uri;

	} result_suspend;
	
	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_SEARCH_RESULT_STOPPED events.
	 * These events are automatically triggered for
	 * each search result before the 
	 * GNUNET_FS_STATUS_SEARCH_STOPPED event.  This
	 * happens primarily to give the client a chance
	 * to clean up the "cctx" (if needed).
	 */
	struct {

	  /**
	   * Private context set for for this result
	   * during the "RESULT" event.
	   */
	  void *cctx;
	  
	  /**
	   * Metadata for the search result.
	   */
	  const struct GNUNET_MetaData *meta;

	  /**
	   * URI for the search result.
	   */
	  const struct GNUNET_FS_Uri *uri;

	} result_stopped;

	/**
	 * These values are only valid for
	 * GNUNET_FS_STATUS_SEARCH_RESUME events.
	 */
	struct {

	  /**
	   * Error message, NULL if we have not encountered any error yet.
	   */
	  const char *message;

	  /**
	   * Is this search currently paused?
	   */
	  int is_paused;

	} resume;

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
    
	/**
	 * Values for all "GNUNET_FS_STATUS_RESULT_NAMESPACE" events.
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
	  const struct GNUNET_CONTAINER_MetaData *meta;
	  
	  /**
	   * Hash-identifier for the namespace.
	   */
	  GNUNET_HashCode id;      
	  
	} namespace;

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
       * Name of the file that is being unindexed.
       */
      const char *filename;

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
       * How long has this upload been actively running
       * (excludes times where the upload was suspended).
       */
      struct GNUNET_TIME_Relative duration;

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
	 * GNUNET_FS_STATUS_UNINDEX_RESUME events.
	 */
	struct {

	  /**
	   * Error message, NULL if we have not encountered any error yet.
	   */
	  const char *message;

	} resume;

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

  } value;

  /**
   * Specific status code (determines the event type).
   */  
  enum GNUNET_FS_Status status;

};


/**
 * Notification of FS to a client about the progress of an 
 * operation.  Callbacks of this type will be used for uploads,
 * downloads and searches.  Some of the arguments depend a bit 
 * in their meaning on the context in which the callback is used.
 *
 * @param cls closure
 * @param info details about the event, specifying the event type
 *        and various bits about the event
 * @return client-context (for the next progress call
 *         for this operation; should be set to NULL for
 *         SUSPEND and STOPPED events).  The value returned
 *         will be passed to future callbacks in the respective
 *         field in the GNUNET_FS_ProgressInfo struct.
 */
typedef void* (*GNUNET_FS_ProgressCallback)
  (void *cls,
   const struct GNUNET_FS_ProgressInfo *info);


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
		 const struct GNUNET_CONFIGURATION_Handle *cfg,
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
 * Function called on entries in a GNUNET_FS_FileInformation publish-structure.
 *
 * @param cls closure
 * @param fi the entry in the publish-structure
 * @param length length of the file or directory
 * @param meta metadata for the file or directory (can be modified)
 * @param uri pointer to the keywords that will be used for this entry (can be modified)
 * @param anonymity pointer to selected anonymity level (can be modified)
 * @param priority pointer to selected priority (can be modified)
 * @param expirationTime pointer to selected expiration time (can be modified)
 * @param client_info pointer to client context set upon creation (can be modified)
 * @return GNUNET_OK to continue, GNUNET_NO to remove
 *         this entry from the directory, GNUNET_SYSERR
 *         to abort the iteration
 */
typedef int (*GNUNET_FS_FileInformationProcessor)(void *cls,
						  struct GNUNET_FS_FileInformation *fi,
						  uint64_t length,
						  struct GNUNET_CONTAINER_MetaData *meta,
						  struct GNUNET_FS_Uri **uri,
						  unsigned int *anonymity,
						  unsigned int *priority,
						  struct GNUNET_TIME_Absolute *expirationTime,
						  void **client_info);


/**
 * Recover file information structure from disk.
 *
 * @param name filename for the structure on disk
 * @return NULL on error 
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_recover (const char *name);


/**
 * Obtain the name under which this file information
 * structure is stored on disk.  Only works for top-level
 * file information structures.
 *
 * @param s structure to get the filename for
 * @return NULL on error, otherwise filename that
 *         can be passed to "GNUNET_FS_file_information_recover"
 *         to read this fi-struct from disk.
 */
const char *
GNUNET_FS_file_information_get_id (struct GNUNET_FS_FileInformation *s);


/**
 * Synchronize this file-information struct with its mirror
 * on disk.  Note that all internal FS-operations that change
 * file information data should already call "sync" internally,
 * so this function is likely not useful for clients.
 * 
 * @param s the struct to sync
 */
void
GNUNET_FS_file_information_sync (struct GNUNET_FS_FileInformation *s);


/**
 * Create an entry for a file in a publish-structure.
 *
 * @param filename name of the file or directory to publish
 * @param keywords under which keywords should this file be available
 *         directly; can be NULL
 * @param meta metadata for the file
 * @param do_index GNUNET_YES for index, GNUNET_NO for insertion,
 *                GNUNET_SYSERR for simulation
 * @param anonymity what is the desired anonymity level for sharing?
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param expirationTime when should this content expire?
 * @return publish structure entry for the file
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_file (void *client_info,
					     const char *filename,
					     const struct GNUNET_FS_Uri *keywords,
					     const struct GNUNET_CONTAINER_MetaData *meta,
					     int do_index,
					     unsigned int anonymity,
					     unsigned int priority,
					     struct GNUNET_TIME_Absolute expirationTime);


/**
 * Create an entry for a file in a publish-structure.
 *
 * @param length length of the file
 * @param data data for the file (should not be used afterwards by
 *        the caller; caller will "free")
 * @param keywords under which keywords should this file be available
 *         directly; can be NULL
 * @param meta metadata for the file
 * @param do_index GNUNET_YES for index, GNUNET_NO for insertion,
 *                GNUNET_SYSERR for simulation
 * @param anonymity what is the desired anonymity level for sharing?
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param expirationTime when should this content expire?
 * @return publish structure entry for the file
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_data (void *client_info,
					     uint64_t length,
					     void *data,
					     const struct GNUNET_FS_Uri *keywords,
					     const struct GNUNET_CONTAINER_MetaData *meta,
					     int do_index,
					     unsigned int anonymity,
					     unsigned int priority,
					     struct GNUNET_TIME_Absolute expirationTime);


/**
 * Function that provides data.
 *
 * @param cls closure
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
typedef size_t (*GNUNET_FS_DataReader)(void *cls, 
				       uint64_t offset,
				       size_t max, 
				       void *buf,
				       char **emsg);


/**
 * Create an entry for a file in a publish-structure.
 *
 * @param length length of the file
 * @param reader function that can be used to obtain the data for the file 
 * @param reader_cls closure for "reader"
 * @param keywords under which keywords should this file be available
 *         directly; can be NULL
 * @param meta metadata for the file
 * @param do_index GNUNET_YES for index, GNUNET_NO for insertion,
 *                GNUNET_SYSERR for simulation
 * @param anonymity what is the desired anonymity level for sharing?
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param expirationTime when should this content expire?
 * @return publish structure entry for the file
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_reader (void *client_info,
					       uint64_t length,
					       GNUNET_FS_DataReader reader,
					       void *reader_cls,
					       const struct GNUNET_FS_Uri *keywords,
					       const struct GNUNET_CONTAINER_MetaData *meta,
					       int do_index,
					       unsigned int anonymity,
					       unsigned int priority,
					       struct GNUNET_TIME_Absolute expirationTime);


/**
 * Function that a "GNUNET_FS_DirectoryScanner" should call
 * for each entry in the directory.
 *
 * @param cls closure
 * @param filename name of the file (including path); must end 
 *          in a "/" (even on W32) if this is a directory
 * @param fi information about the file (should not be
 *        used henceforth by the caller)
 */
typedef void (*GNUNET_FS_FileProcessor)(void *cls,
					const char *filename,
					struct GNUNET_FS_FileInformation *fi);


/**
 * Type of a function that will be used to scan a directory.
 * 
 * @param cls closure
 * @param dirname name of the directory to scan
 * @param do_index should files be indexed or inserted
 * @param anonymity desired anonymity level
 * @param priority priority for publishing
 * @param expirationTime expiration for publication
 * @param proc function to call on each entry
 * @param proc_cls closure for proc
 * @param emsg where to store an error message (on errors)
 * @return GNUNET_OK on success
 */
typedef int (*GNUNET_FS_DirectoryScanner)(void *cls,
					  const char *dirname,
					  int do_index,
					  unsigned int anonymity,
					  unsigned int priority,
					  struct GNUNET_TIME_Absolute expirationTime,
					  GNUNET_FS_FileProcessor proc,
					  void *proc_cls,
					  char **emsg);



/**
 * Simple, useful default implementation of a directory scanner
 * (GNUNET_FS_DirectoryScanner).  This implementation expects to get a
 * UNIX filename, will publish all files in the directory except hidden
 * files (those starting with a ".").  Metadata will be extracted
 * using GNU libextractor; the specific list of plugins should be
 * specified in "cls", passing NULL will disable (!)  metadata
 * extraction.  Keywords will be derived from the metadata and be
 * subject to default canonicalization.  This is strictly a
 * convenience function.
 *
 * @param cls must be of type "struct EXTRACTOR_Extractor*"
 * @param dirname name of the directory to scan
 * @param do_index should files be indexed or inserted
 * @param anonymity desired anonymity level
 * @param priority priority for publishing
 * @param expirationTime expiration for publication
 * @param proc function called on each entry
 * @param proc_cls closure for proc
 * @param emsg where to store an error message (on errors)
 * @return GNUNET_OK on success
 */
int
GNUNET_FS_directory_scanner_default (void *cls,
				     const char *dirname,
				     int do_index,
				     unsigned int anonymity,
				     unsigned int priority,
				     struct GNUNET_TIME_Absolute expirationTime,
				     GNUNET_FS_FileProcessor proc,
				     void *proc_cls,
				     char **emsg);


/**
 * Create a publish-structure from an existing file hierarchy, inferring
 * and organizing keywords and metadata as much as possible.  This
 * function primarily performs the recursive build and re-organizes
 * keywords and metadata; for automatically getting metadata
 * extraction, scanning of directories and creation of the respective
 * GNUNET_FS_FileInformation entries the default scanner should be
 * passed (GNUNET_FS_directory_scanner_default).  This is strictly a
 * convenience function.
 *
 * @param filename name of the top-level file or directory
 * @param scanner function used to get a list of files in a directory
 * @param scanner_cls closure for scanner
 * @param do_index should files in the hierarchy be indexed?
 * @param anonymity what is the desired anonymity level for sharing?
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param expirationTime when should this content expire?
 * @param emsg where to store an error message
 * @return publish structure entry for the directory, NULL on error
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_directory (void *client_info,
						  const char *filename,
						  GNUNET_FS_DirectoryScanner scanner,
						  void *scanner_cls,
						  int do_index,
						  unsigned int anonymity,
						  unsigned int priority,
						  struct GNUNET_TIME_Absolute expirationTime,
						  char **emsg);


/**
 * Create an entry for an empty directory in a publish-structure.
 * This function should be used by applications for which the
 * use of "GNUNET_FS_file_information_create_from_directory"
 * is not appropriate.
 *
 * @param meta metadata for the directory
 * @param keywords under which keywords should this directory be available
 *         directly; can be NULL
 * @param anonymity what is the desired anonymity level for sharing?
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param expirationTime when should this content expire?
 * @return publish structure entry for the directory , NULL on error
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_empty_directory (void *client_info,
						   const struct GNUNET_CONTAINER_MetaData *meta,
						   const struct GNUNET_FS_Uri *keywords,
						   unsigned int anonymity,
						   unsigned int priority,
						   struct GNUNET_TIME_Absolute expirationTime);


/**
 * Add an entry to a directory in a publish-structure.  Clients
 * should never modify publish structures that were passed to
 * "GNUNET_FS_publish_start" already.
 *
 * @param dir the directory
 * @param end the entry to add; the entry must not have been
 *            added to any other directory at this point and 
 *            must not include "dir" in its structure
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_FS_file_information_add (struct GNUNET_FS_FileInformation *dir,
				struct GNUNET_FS_FileInformation *end);


/**
 * Inspect a file or directory in a publish-structure.  Clients
 * should never modify publish structures that were passed to
 * "GNUNET_FS_publish_start" already.  When called on a directory,
 * this function will FIRST call "proc" with information about
 * the directory itself and then for each of the files in the
 * directory (but not for files in subdirectories).  When called
 * on a file, "proc" will be called exactly once (with information
 * about the specific file).
 *
 * @param dir the directory
 * @param proc function to call on each entry
 * @param proc_cls closure for proc
 */
void
GNUNET_FS_file_information_inspect (struct GNUNET_FS_FileInformation *dir,
				    GNUNET_FS_FileInformationProcessor proc,
				    void *proc_cls);


/**
 * Destroy publish-structure.  Clients should never destroy publish
 * structures that were passed to "GNUNET_FS_publish_start" already.
 *
 * @param fi structure to destroy
 * @param cleaner function to call on each entry in the structure
 *        (useful to clean up client_info); can be NULL; return
 *        values are ignored
 * @param cleaner_cls closure for cleaner
 */
void
GNUNET_FS_file_information_destroy (struct GNUNET_FS_FileInformation *fi,
				    GNUNET_FS_FileInformationProcessor cleaner,
				    void *cleaner_cls);


/**
 * Publish a file or directory.
 *
 * @param h handle to the file sharing subsystem
 * @param ctx initial value to use for the '*ctx'
 *        in the callback (for the GNUNET_FS_STATUS_PUBLISH_START event).
 * @param fi information about the file or directory structure to publish
 * @param namespace namespace to publish the file in, NULL for no namespace
 * @param nid identifier to use for the publishd content in the namespace
 *        (can be NULL, must be NULL if namespace is NULL)
 * @param nuid update-identifier that will be used for future updates 
 *        (can be NULL, must be NULL if namespace or nid is NULL)
 * @return context that can be used to control the publish operation
 */
struct GNUNET_FS_PublishContext *
GNUNET_FS_publish_start (struct GNUNET_FS_Handle *h,
		       void *ctx,
		       const struct GNUNET_FS_FileInformation *fi,
		       struct GNUNET_FS_Namespace *namespace,
		       const char *nid,
		       const char *nuid);


/**
 * Stop an upload.  Will abort incomplete uploads (but 
 * not remove blocks that have already been publishd) or
 * simply clean up the state for completed uploads.
 *
 * @param sc context for the upload to stop
 */
void 
GNUNET_FS_publish_stop (struct GNUNET_FS_PublishContext *sc);


/**
 * Type of a function called by "GNUNET_FS_get_indexed_files".
 *
 * @param cls closure
 * @param filename the name of the file
 * @return GNUNET_OK to continue iteration, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_FS_IndexedFileProcessor) (void *cls,
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
			     GNUNET_FS_IndexedFileProcessor iterator,
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
 */
void 
GNUNET_FS_namespace_list (struct GNUNET_FS_Handle *h,
			  GNUNET_FS_NamespaceInfoProcessor cb,
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
 * Continue paused search.
 *
 * @param sc context for the search that should be resumed
 */
void 
GNUNET_FS_search_continue (struct GNUNET_FS_SearchContext *sc);


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
GNUNET_FS_collection_stop (struct GNUNET_FS_Handle *h);


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





/* ******************** Directory API *********************** */


#define GNUNET_FS_DIRECTORY_MIME  "application/gnunet-directory"
#define GNUNET_FS_DIRECTORY_MAGIC "\211GND\r\n\032\n"
#define GNUNET_FS_DIRECTORY_EXT   ".gnd"

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
 * Set the MIMETYPE information for the given
 * metadata to "application/gnunet-directory".
 * 
 * @param md metadata to add mimetype to
 */
void
GNUNET_FS_meta_data_make_directory (struct GNUNET_CONTAINER_MetaData *md);


/**
 * Function used to process entries in a directory.
 *
 * @param cls closure
 * @param filename name of the file in the directory
 * @param uri URI of the file
 * @param metadata metadata for the file; metadata for
 *        the directory if everything else is NULL/zero
 * @param length length of the available data for the file
 *           (of type size_t since data must certainly fit
 *            into memory; if files are larger than size_t
 *            permits, then they will certainly not be
 *            embedded with the directory itself).
 * @param data data available for the file (length bytes)
 */
typedef void (*GNUNET_FS_DirectoryEntryProcessor)(void *cls,
						  const char *filename,
						  const struct GNUNET_FS_Uri *uri,
						  const struct GNUNET_CONTAINER_MetaData *meta,
						  size_t length,
						  const void *data);


/**
 * Iterate over all entries in a directory.  Note that directories
 * are structured such that it is possible to iterate over the
 * individual blocks as well as over the entire directory.  Thus
 * a client can call this function on the buffer in the
 * GNUNET_FS_ProgressCallback.  Also, directories can optionally
 * include the contents of (small) files embedded in the directory
 * itself; for those files, the processor may be given the
 * contents of the file directly by this function.
 *
 * @param size number of bytes in data
 * @param data pointer to the beginning of the directory
 * @param offset offset of data in the directory
 * @param dep function to call on each entry
 * @param dep_cls closure for dep
 */
void 
GNUNET_FS_directory_list_contents (size_t size,
				   const void *data,
				   uint64_t offset,
				   GNUNET_FS_DirectoryEntryProcessor dep, 
				   void *dep_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
