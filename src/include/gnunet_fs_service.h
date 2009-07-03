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
int GNUNET_FS_meta_data_test_for_directory (const struct GNUNET_CONTAINER_MetaData *md);


/**
 * A URI (in internal representation).
 */
struct GNUNET_FS_Uri;

/**
 * Get a unique key from a URI.  This is for putting URIs
 * into HashMaps.  The key may change between FS implementations.
 */
void GNUNET_FS_uri_to_key (const struct GNUNET_FS_Uri *uri,
                             GNUNET_HashCode * key);

/**
 * Convert a URI to a UTF-8 String.
 */
char *GNUNET_FS_uri_to_string (const struct GNUNET_FS_Uri *uri);

/**
 * Convert keyword URI to a human readable format
 * (i.e. the search query that was used in the first place)
 */
char *GNUNET_FS_ksk_uri_ksk_to_string_fancy (const struct
                                                    GNUNET_FS_Uri *uri);

/**
 * Convert a UTF-8 String to a URI.
*
* @param uri string to parse
* @param emsg where to store the parser error message (if any)
* @return NULL on error
 */
struct GNUNET_FS_Uri *GNUNET_FS_uri_parse (
                                               const char *uri, char **emsg);

/**
 * Free URI.
 */
void GNUNET_FS_uri_destroy (struct GNUNET_FS_Uri *uri);

/**
 * How many keywords are ANDed in this keyword URI?
 * @return 0 if this is not a keyword URI
 */
unsigned int GNUNET_FS_uri_ksk_get_keyword_count (const struct
                                                         GNUNET_FS_Uri
                                                         *uri);

/**
 * Iterate over all keywords in this keyword URI.
 *
 * @return -1 if this is not a keyword URI, otherwise number of
 *   keywords iterated over until iterator aborted
 */
int GNUNET_FS_uri_ksk_get_keywords (const struct GNUNET_FS_Uri *uri,
                                           GNUNET_FS_KeywordIterator
                                           iterator, void *iterator_cls);

/**
 * Obtain the identity of the peer offering the data
 * @return GNUNET_SYSERR if this is not a location URI, otherwise GNUNET_OK
 */
int GNUNET_FS_uri_loc_get_peer_identity (const struct GNUNET_FS_Uri
                                                *uri,
                                                struct GNUNET_PeerIdentity * peer);

/**
 * Obtain the URI of the content itself.
 *
 * @return NULL if argument is not a location URI
 */
struct GNUNET_FS_Uri *GNUNET_FS_uri_loc_get_uri (const struct
                                                                  GNUNET_FS_Uri
                                                                  *uri);

/**
 * Construct a location URI.
 *
 * @param baseURI content offered by the sender
 * @param expiration_time how long will the content be offered?
 * @return the location URI, NULL on error
 */
struct GNUNET_FS_Uri *GNUNET_FS_uri_loc_create (const struct
                                                     GNUNET_FS_Uri *baseUri,
	struct GNUNET_CONFIGURATION_Handle *cfg,
                                                 struct GNUNET_TIME_Absolute
                                                     expirationTime
                                                     );


/**
 * Duplicate URI.
 */
struct GNUNET_FS_Uri *GNUNET_FS_uri_dup (const struct
                                                   GNUNET_FS_Uri *uri);

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
 * @return an FS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct GNUNET_FS_Uri *GNUNET_FS_uri_ksk_create (
                                                           const char
                                                           *keywords);

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
struct GNUNET_FS_Uri *GNUNET_FS_uri_ksk_create_from_args (
                                                                 unsigned int
                                                                 argc,
                                                                 const char
                                                                 **argv);

/**
 * Test if two URIs are equal.
 */
int GNUNET_FS_uri_test_equal (const struct GNUNET_FS_Uri *u1,
                                const struct GNUNET_FS_Uri *u2);

/**
 * Is this a namespace URI?
 */
int GNUNET_FS_uri_test_sks (const struct GNUNET_FS_Uri *uri);

/**
 * Get the ID of a namespace from the given
 * namespace URI.
 */
int GNUNET_FS_uri_sks_get_namespace (const struct GNUNET_FS_Uri *uri,
                                            GNUNET_HashCode * nsid);

/**
 * Get the content identifier of an SKS URI.
 *
 * @return NULL on error
 */
char *GNUNET_FS_uri_sks_get_content_id (const struct GNUNET_FS_Uri
                                               *uri);


/**
 * Is this a keyword URI?
 */
int GNUNET_FS_uri_test_ksk (const struct GNUNET_FS_Uri *uri);

/**
 * Is this a file (or directory) URI?
 */
int GNUNET_FS_uri_test_chk (const struct GNUNET_FS_Uri *uri);

/**
 * What is the size of the file that this URI
 * refers to?
 */
uint64_t GNUNET_FS_uri_chk_get_file_size (const struct GNUNET_FS_Uri
                                                  *uri);

/**
 * Is this a location URI?
 */
int GNUNET_FS_uri_test_loc (const struct GNUNET_FS_Uri *uri);



/**
 * Construct a keyword-URI from meta-data (take all entries
 * in the meta-data and construct one large keyword URI
 * that lists all keywords that can be found in the meta-data).
 */
struct GNUNET_FS_Uri *GNUNET_FS_uri_ksk_create_from_meta_data (const struct
                                                 GNUNET_MetaData *md);

/**
 * @param scls must be of type "struct GNUNET_FS_Uri **"
 */
int
GNUNET_FS_getopt_configure_set_keywords (GNUNET_GETOPT_CommandLineProcessorContext
                                           * ctx, void *scls,
                                           const char *option,
                                           const char *value);

/**
 * @param scls must be of type "struct GNUNET_MetaData **"
 */
int
GNUNET_FS_getopt_configure_set_metadata (GNUNET_GETOPT_CommandLineProcessorContext
                                           * ctx, void *scls,
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
  GNUNET_FS_STATUS_UPLOAD_START,
  GNUNET_FS_STATUS_UPLOAD_PROGRESS,
  GNUENT_FS_STATUS_UPLOAD_ERROR,
  GNUNET_FS_STATUS_UPLOAD_COMPLETED,
  GNUNET_FS_STATUS_UPLOAD_STOPPED,
  GNUNET_FS_DOWNLOAD_START,
  GNUNET_FS_DOWNLOAD_PROGRESS,
  GNUNET_FS_DOWNLOAD_ERROR,
  GNUNET_FS_DOWNLOAD_COMPLETED,
  GNUNET_FS_DOWNLOAD_STOPPED,
  GNUNET_FS_SEARCH_START,
  GNUNET_FS_SEARCH_PROGRESS,
  GNUNET_FS_SEARCH_ERROR,
  GNUNET_FS_SEARCH_STOPPED
/* fixme: unindex status codes... */
};


/**
 * Notification of FS to a client about the progress of an 
 * operation.  Callbacks of this type will be used for uploads,
 * downloads and searches.  Some of the arguments depend a bit 
 * in their meaning on the context in which the callback is used.
 *
 * @param cls closure
 * @param ctx location where the callback can store a context pointer
 *        to keep track of things for this specific operation
 * @param pctx context pointer set by the callback for the parent operation
 *        (NULL if there is no parent operation); for a search result,
 *        the actual search is the parent and the individual search results
 *        are the children (multiple calls for the same search result can
 *        be used whenever availability/certainty or metadata values change)
 * @param filename name of the file that this update is about, NULL for 
 *        searches
 * @param status specific status code
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
 */
typedef int (*GNUNET_FS_ProgressCallback)
  (void *cls,
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
 * Handle to the file-sharing service.
 */
struct GNUNET_FS_Handle;


/**
* Setup a connection to the file-sharing service.
*
* @param client_name unique identifier for this client 
 */
struct GNUNET_FS_Handle *
GNUNET_FS_start (struct GNUNET_SCHEDULER_Handle *sched,
                     struct GNUNET_CONFIGURATION_Handle *cfg,
		 const char *client_name,
	 GNUNET_FS_ProgressCallback upcb,
                     void *upcb_closure);

/**
* Close our connection with the file-sharing service.
* The callback given to GNUNET_FS_start will no longer be
* called after this function returns.
*/                    
void GNUNET_FS_stop (struct GNUNET_FS_Handle *h); 


/**
* Handle to one of our namespaces.
*/
struct GNUNET_FS_Namespace;

struct GNUNET_FS_ShareContext;

/**
 * Share a file or directory.
 *
 * @param ctx initial value to use for the '*ctx' in the callback
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param do_index GNUNET_YES for index, GNUNET_NO for insertion,
 *                GNUNET_SYSERR for simulation
 * @param namespace namespace to share the file in, NULL for no namespace
 * @param nid identifier to use for the shared content in the namespace
 *        (can be NULL, must be NULL if namespace is NULL)
 * @param nuid update-identifier that will be used for future updates 
 *        (can be NULL, must be NULL if namespace or nid is NULL)
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
                     const char *nid, const char *nuid);

void GNUNET_FS_share_stop (struct GNUNET_FS_ShareContext *sc);

/**
 * @return GNUNET_OK to continue iteration, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_FS_FileProcessor) (void *cls, const char *filename);


/**
 * Iterate over all indexed files.
 */
void GNUNET_FS_get_indexed_files (struct GNUNET_FS_Handle *sched,
                                   GNUNET_FS_FileProcessor iterator,
                                   void *iterator_closure);

/**
 * Unindex a file.
 */
void GNUNET_FS_unindex (struct GNUNET_FS_Handle *h,
                              const char *filename,
                              );


/**
 * Create a new namespace (and publish an advertismement).
 * This publishes both an GNUNET_EC_NBlock in the namespace itself
 * as well as KNBlocks under all keywords specified in
 * the advertisementURI.
 *
 * @param anonymity for the namespace advertismement
 * @param priority for the namespace advertisement
 * @param expiration for the namespace advertisement
 * @param advertisementURI the keyword (!) URI to advertise the
 *        namespace under (GNUNET_EC_KNBlock)
 * @param meta meta-data for the namespace advertisement
 *        (will be used to derive a name)
 * @param rootEntry name of the root entry in the namespace (for
 *        the namespace advertisement)
 *
 * @return uri of the advertisement
 */
struct GNUNET_FS_Uri *
GNUNET_FS_namespace_advertise (struct GNUNET_FS_Namespace *namespace,
                                                      const struct
                                                      GNUNET_MetaData
                                                      *meta,
                                                      unsigned int
                                                      anonymity,
                                                      unsigned int priority,
                                                      struct GNUNET_TIME_Absolute
                                                      expiration,
                                                      const struct
                                                      GNUNET_FS_Uri
                                                      *advertisementURI,
                                                      const char *rootEntry);

/**
 * Create a namespace with the given name; if one already
 * exists, return a handle to the existing namespace.
 *
 * @return handle to the namespace, NULL on error
 */
struct GNUNET_FS_Namespace *
GNUNET_FS_namespace_create (struct GNUNET_FS_Handle *h,
			    const char *name,
	const char *root);

/**
 * Delete a namespace handle.
 *
 * @param freeze prevents future insertions; creating a namespace
 *        with the same name again will create a fresh namespace instead
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_FS_namespace_delete (struct GNUNET_FS_Namespace *namespace,
				int freeze);


/**
 * Callback with information about local (!) namespaces.
 * Contains the names of the local namespace and the global
 * ID.
 */
typedef void (*GNUNET_FS_NamespaceInfoProcessor) (void *cls,
                                                 const char *name,
const char *root,
		const GNUNET_HashCode *id);

/**
 * Build a list of all available local (!) namespaces
 * The returned names are only the nicknames since
 * we only iterate over the local namespaces.
 *
 * @param list where to store the names (is allocated, caller frees)
 * @return GNUNET_SYSERR on error, otherwise the number of pseudonyms in list
 */
int GNUNET_FS_namespace_list (struct GNUNET_FS_Handle *h,
                                GNUNET_FS_NamespaceProcessor cb,
                                void *cls);

typedef void (*GNUNET_FS_IdentifierProcessor)(void *cls,
	const char *last_id, const struct GNUNET_FS_Uri *last_uri,
        const struct GNUNET_CONTAINER_MetaData *last_meta,
const char *next_id);

/**
 * List all of the identifiers in the namespace for 
 * which we could produce an update.
 *
 */
void
GNUNET_FS_namespace_list_updateable (struct
                            GNUNET_FS_Namespace *namespace,
				GNUNET_FS_IdentifierProcessor ip, 
			    void *ip_cls);


struct GNUNET_FS_SearchContext;

/**
 * Start search for content.
 *
 * @param uri specifies the search parameters;
 *        this must be a simple URI (with a single
 *        keyword)
 */
struct GNUNET_FS_SearchContext *
GNUNET_FS_search_start (struct
                        GNUNET_FS_Handle *h,
                                                            const struct
                                                            GNUNET_FS_Uri
                                                            *uri,
                                                            unsigned int
                                                            anonymity
                                                            );


void GNUNET_FS_search_pause (struct GNUNET_FS_SearchContext *sc);

void GNUNET_FS_search_resume (struct GNUNET_FS_SearchContext *sc);

/**
 * Stop search for content.
 *
 * @param uri specifies the search parameters
 * @param uri set to the URI of the uploaded file
 */
void GNUNET_FS_search_stop (struct GNUNET_FS_SearchContext *sctx);


struct GNUNET_FS_DownloadContext;

/**
 * Download parts of a file.  Note that this will store
 * the blocks at the respective offset in the given file.  Also, the
 * download is still using the blocking of the underlying FS
 * encoding.  As a result, the download may *write* outside of the
 * given boundaries (if offset and length do not match the 32k FS
 * block boundaries).  <p>
 *
 * This function should be used to focus a download towards a
 * particular portion of the file (optimization), not to strictly
 * limit the download to exactly those bytes.
 *
 * @param uri the URI of the file (determines what to download)
 * @param filename where to store the file, maybe NULL (then no file is
 *        created on disk)
 * @param no_temporaries set to GNUNET_YES to disallow generation of temporary files
 * @param start starting offset
 * @param length length of the download (starting at offset)
 */
struct GNUNET_FS_DownloadContext
  *GNUNET_FS_file_download_start (struct GNUNET_FS_Handle *h,
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
 * @param do_delete delete files of incomplete downloads
 */
int
GNUNET_FS_file_download_stop (struct GNUNET_FS_DownloadContext
                                        *rm,
			      int do_delete);


/**
 * Iterate over all entries in a directory.  Note that directories
 * are structured such that it is possible to iterate over the
 * individual blocks as well as over the entire directory.  Thus
 * a client can call this function on the buffer in the
 * GNUNET_FS_ProgressCallback.
 *
 * @param data pointer to the beginning of the directory
 * @param size number of bytes in data
 * @param offset offset of data in the file
 */
void GNUNET_FS_directory_list_contents (size_t size,
                                       const void *data,
                                       uint64_t offset,
                                         GNUNET_FS_SearchResultProcessor
                                         spcb, void *spcbClosure);

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
 */
int GNUNET_FS_directory_create (
                                  char **data,
                                  unsigned long long *len,
                                  unsigned int count,
                                  const GNUNET_FS_FileInfo * fis,
                                  struct GNUNET_MetaData *meta);




/**
 * Initialize collection.
 */
void GNUNET_FS_collection_start (struct GNUNET_FS_Handle *h,
		     struct GNUNET_FS_Namespace *namespace);

/**
 * Stop collection.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR if no collection is active
 */
int GNUNET_CO_collection_stop (struct GNUNET_FS_Handle *h);


/**
 * Are we using a collection?
 *
 * @return NULL if there is no collection,
 */
struct GNUNET_FS_Namespace *GNUNET_FS_collection_get(struct GNUNET_FS_Handle *h);

/**
 * Publish an update of the current collection information to the
 * network now.  The function has no effect if the collection has not
 * changed since the last publication.  If we are currently not
 * collecting, this function does nothing.
 */
void GNUNET_FS_collection_publish (struct GNUNET_FS_Handle *h);

/**
 * If we are currently building a collection, publish the given file
 * information in that collection.  If we are currently not
 * collecting, this function does nothing.
 */
void GNUNET_FS_collection_add (const struct GNUNET_FS_Handle *h,
		const struct GNUNET_FS_Uri *uri,
	 const struct GNUNET_CONTAINER_MetaData *meta);



/**
 * Convert namespace URI to a human readable format
 * (using the namespace description, if available).
 */
char *GNUNET_FS_uri_sks_to_string_fancy (
                                                  struct
                                                  GNUNET_CONFIGURATION_Handle *cfg,
                                                  const struct GNUNET_FS_Uri
                                                  *uri);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
