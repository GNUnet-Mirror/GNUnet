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
 * @file fs/fs_uri.c
 * @brief Parses and produces uri strings.
 * @author Igor Wronsky, Christian Grothoff
 *
 * GNUnet URIs are of the general form "gnunet://MODULE/IDENTIFIER".
 * The specific structure of "IDENTIFIER" depends on the module and
 * maybe differenciated into additional subcategories if applicable.
 * This module only deals with ecrs identifiers (MODULE = "ecrs").
 * <p>
 *
 * This module only parses URIs for the AFS module.  The ECRS URIs fall
 * into four categories, "chk", "sks", "ksk" and "loc".  The first three
 * categories were named in analogy (!) to Freenet, but they do NOT
 * work in exactly the same way.  They are very similar from the user's
 * point of view (unique file identifier, subspace, keyword), but the
 * implementation is rather different in pretty much every detail.
 * The concrete URI formats are:
 *
 * <ul><li>
 *
 * First, there are URIs that identify a file.  They have the format
 * "gnunet://ecrs/chk/HEX1.HEX2.SIZE".  These URIs can be used to
 * download the file.  The description, filename, mime-type and other
 * meta-data is NOT part of the file-URI since a URI uniquely
 * identifies a resource (and the contents of the file would be the
 * same even if it had a different description).
 *
 * </li><li>
 *
 * The second category identifies entries in a namespace.  The format
 * is "gnunet://ecrs/sks/NAMESPACE/IDENTIFIER" where the namespace
 * should be given in HEX.  Applications may allow using a nickname
 * for the namespace if the nickname is not ambiguous.  The identifier
 * can be either an ASCII sequence or a HEX-encoding.  If the
 * identifier is in ASCII but the format is ambiguous and could denote
 * a HEX-string a "/" is appended to indicate ASCII encoding.
 *
 * </li> <li>
 *
 * The third category identifies ordinary searches.  The format is
 * "gnunet://ecrs/ksk/KEYWORD[+KEYWORD]*".  Using the "+" syntax
 * it is possible to encode searches with the boolean "AND" operator.
 * "+" is used since it indicates a commutative 'and' operation and
 * is unlikely to be used in a keyword by itself.
 *
 * </li><li>
 *
 * The last category identifies a datum on a specific machine.  The
 * format is "gnunet://ecrs/loc/HEX1.HEX2.SIZE.PEER.SIG.EXPTIME".  PEER is
 * the BinName of the public key of the peer storing the datum.  The
 * signature (SIG) certifies that this peer has this content.
 * HEX1, HEX2 and SIZE correspond to a 'chk' URI.
 *
 * </li></ul>
 *
 * The encoding for hexadecimal values is defined in the hashing.c
 * module in the gnunetutil library and discussed there.
 * <p>
 */
#include "platform.h"
#include "gnunet_fs_lib.h"
#include "fs.h"


/**
 * Get a unique key from a URI.  This is for putting URIs
 * into HashMaps.  The key may change between FS implementations.
 *
 * @param uri uri to convert to a unique key
 * @param key wherer to store the unique key
 */
void 
GNUNET_FS_uri_to_key (const struct GNUNET_FS_Uri *uri,
		      GNUNET_HashCode * key)
{
  switch (uri->type)
    {
    case chk:
      *key = uri->data.fi.chk.query;
      return;
    case sks:
      GNUNET_hash (uri->data.sks.identifier,
                   strlen (uri->data.sks.identifier), key);
      break;
    case ksk:
      if (uri->data.ksk.keywordCount > 0)
        GNUNET_hash (uri->data.ksk.keywords[0],
                     strlen (uri->data.ksk.keywords[0]), key);
      break;
    case loc:
      GNUNET_hash (&uri->data.loc.fi,
                   sizeof (GNUNET_EC_FileIdentifier) +
                   sizeof (GNUNET_RSA_PublicKey), key);
      break;
    default:
      memset (key, 0, sizeof (GNUNET_HashCode));
      break;
    }
}


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
GNUNET_FS_uri_destroy (struct GNUNET_FS_Uri *uri)
{
  unsigned int i;

  GNUNET_assert (uri != NULL);
  switch (uri->type)
    {
    case ksk:
      for (i = 0; i < uri->data.ksk.keywordCount; i++)
        GNUNET_free (uri->data.ksk.keywords[i]);
      GNUNET_array_grow (uri->data.ksk.keywords, uri->data.ksk.keywordCount,
                         0);
      break;
    case sks:
      GNUNET_free (uri->data.sks.identifier);
      break;
    case loc:
      break;
    default:
      /* do nothing */
      break;
    }
  GNUNET_free (uri);
}

/**
 * How many keywords are ANDed in this keyword URI?
 *
 * @param uri ksk uri to get the number of keywords from
 * @return 0 if this is not a keyword URI
 */
unsigned int 
GNUNET_FS_uri_ksk_get_keyword_count (const struct GNUNET_FS_Uri *uri)
{
  if (uri->type != ksk)
    return 0;
  return uri->data.ksk.keywordCount;
}


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
				void *iterator_cls)
{
  unsigned int i;
  char *keyword;

  if (uri->type != ksk)
    return -1;
  if (iterator == NULL)
    return uri->data.ksk.keywordCount;
  for (i = 0; i < uri->data.ksk.keywordCount; i++)
    {
      keyword = uri->data.ksk.keywords[i];
      /* first character of keyword indicates
         if it is mandatory or not */
      if (GNUNET_OK != iterator (&keyword[1], keyword[0] == '+', cls))
        return i;
    }
  return i;
}


/**
 * Obtain the identity of the peer offering the data
 *
 * @param uri the location URI to inspect
 * @param peer where to store the identify of the peer (presumably) offering the content
 * @return GNUNET_SYSERR if this is not a location URI, otherwise GNUNET_OK
 */
int
GNUNET_FS_uri_loc_get_peer_identity (const struct GNUNET_FS_Uri *uri,
				     struct GNUNET_PeerIdentity * peer)
{
  if (uri->type != loc)
    return GNUNET_SYSERR;
  GNUNET_hash (&uri->data.loc.peer, sizeof (GNUNET_RSA_PublicKey),
               &peer->hashPubKey);
  return GNUNET_OK;
}


/**
 * Obtain the URI of the content itself.
 *
 * @param uri location URI to get the content URI from
 * @return NULL if argument is not a location URI
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_loc_get_uri (const struct GNUNET_FS_Uri *uri)
{
  struct GNUNET_ECRS_Uri *ret;

  if (uri->type != loc)
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_ECRS_Uri));
  ret->type = chk;
  ret->data.chk = uri->data.loc.fi;
  return ret;
}


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
GNUNET_FS_uri_dup (const struct GNUNET_FS_Uri *uri)
{
  struct GNUNET_ECRS_URI *ret;
  unsigned int i;

  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_Uri));
  memcpy (ret, uri, sizeof (struct GNUNET_FS_Uri));
  switch (ret->type)
    {
    case ksk:
      if (ret->data.ksk.keywordCount > 0)
        {
          ret->data.ksk.keywords
            = GNUNET_malloc (ret->data.ksk.keywordCount * sizeof (char *));
          for (i = 0; i < ret->data.ksk.keywordCount; i++)
            ret->data.ksk.keywords[i] =
              GNUNET_strdup (uri->data.ksk.keywords[i]);
        }
      else
        ret->data.ksk.keywords = NULL;  /* just to be sure */
      break;
    case sks:
      ret->data.sks.identifier = GNUNET_strdup (uri->data.sks.identifier);
      break;
    case loc:
      break;
    default:
      break;
    }
  return ret;
}


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
			  const struct GNUNET_FS_Uri *u2)
{
  int ret;
  unsigned int i;
  unsigned int j;

  GNUNET_assert (uri1 != NULL);
  GNUNET_assert (uri2 != NULL);
  if (uri1->type != uri2->type)
    return GNUNET_NO;
  switch (uri1->type)
    {
    case chk:
      if (0 == memcmp (&uri1->data.chk,
                       &uri2->data.chk,
		       sizeof (struct FileIdentifier)))
        return GNUNET_YES;
      return GNUNET_NO;
    case sks:
      if ((0 == memcmp (&uri1->data.sks.namespace,
                        &uri2->data.sks.namespace,
                        sizeof (GNUNET_HashCode))) &&
          (0 == strcmp (uri1->data.sks.identifier,
                        uri2->data.sks.identifier)))

        return GNUNET_YES;
      return GNUNET_NO;
    case ksk:
      if (uri1->data.ksk.keywordCount != uri2->data.ksk.keywordCount)
        return GNUNET_NO;
      for (i = 0; i < uri1->data.ksk.keywordCount; i++)
        {
          ret = GNUNET_NO;
          for (j = 0; j < uri2->data.ksk.keywordCount; j++)
            {
              if (0 == strcmp (uri1->data.ksk.keywords[i],
                               uri2->data.ksk.keywords[j]))
                {
                  ret = GNUNET_YES;
                  break;
                }
            }
          if (ret == GNUNET_NO)
            return GNUNET_NO;
        }
      return GNUNET_YES;
    case loc:
      if (memcmp (&uri1->data.loc,
                  &uri2->data.loc,
                  sizeof (struct FileIdentifier) +
                  sizeof (GNUNET_RSA_PublicKey) +
                  sizeof (struct GNUNET_TIME_Absolute) +
                  sizeof (unsigned short) + sizeof (unsigned short)) != 0)
        return GNUNET_NO;
      return GNUNET_YES;
    default:
      return GNUNET_NO;
    }
}


/**
 * Is this a namespace URI?
 *
 * @param uri the uri to check
 * @return GNUNET_YES if this is an SKS uri
 */
int
GNUNET_FS_uri_test_sks (const struct GNUNET_FS_Uri *uri)
{
  return uri->type == sks;
}


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
				 GNUNET_HashCode * nsid)
{
  if (! GNUNET_FS_uri_test_sks (uri))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  *id = uri->data.sks.namespace;
  return GNUNET_OK;
}


/**
 * Get the content identifier of an SKS URI.
 *
 * @param uri the sks uri
 * @return NULL on error (not a valid SKS URI)
 */
char *
GNUNET_FS_uri_sks_get_content_id (const struct GNUNET_FS_Uri *uri)
{
  if (!GNUNET_FS_uri_test_sks (uri))
    {
      GNUNET_break (0);
      return NULL;
    }
  return GNUNET_strdup (uri->data.sks.identifier);
}


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
GNUNET_FS_uri_test_ksk (const struct GNUNET_FS_Uri *uri)
{
#if EXTRA_CHECKS
  unsigned int i;

  if (uri->type == ksk)
    {
      for (i = uri->data.ksk.keywordCount - 1; i >= 0; i--)
        GNUNET_assert (uri->data.ksk.keywords[i] != NULL);
    }
#endif
  return uri->type == ksk;
}


/**
 * Is this a file (or directory) URI?
 *
 * @param uri the uri to check
 * @return GNUNET_YES if this is a CHK uri
 */
int 
GNUNET_FS_uri_test_chk (const struct GNUNET_FS_Uri *uri)
{
  return uri->type == chk;
}


/**
 * What is the size of the file that this URI
 * refers to?
 *
 * @param uri the CHK URI to inspect
 * @return size of the file as specified in the CHK URI
 */
uint64_t 
GNUNET_FS_uri_chk_get_file_size (const struct GNUNET_FS_Uri *uri)
{
  switch (uri->type)
    {
    case chk:
      return GNUNET_ntohll (uri->data.chk.file_length);
    case loc:
      return GNUNET_ntohll (uri->data.loc.fi.file_length);
    default:
      GNUNET_assert (0);
    }
  return 0;                     /* unreachable */
}


/**
 * Is this a location URI?
 *
 * @param uri the uri to check
 * @return GNUNET_YES if this is a LOC uri
 */
int 
GNUNET_FS_uri_test_loc (const struct GNUNET_FS_Uri *uri)
{
  return uri->type == loc;
}


/**
 * Function called on each value in the meta data.
 * Adds it to the URI.
 *
 * @param cls URI to update
 * @param type type of the meta data
 * @param data value of the meta data
 * @return GNUNET_OK (always)
 */
static int
gather_uri_data (void *cls,
		 EXTRACTOR_KeywordType type, 
		 const char *data)
{
  struct GNUNET_FS_Uri *uri = cls;
  char *nkword;
  int j;
  
  for (j = uri->data.ksk.keywordCount - 1; j >= 0; j--)
    if (0 == strcmp (&uri->data.ksk.keywords[j][1], data))
      return GNUNET_OK;
  nkword = GNUNET_malloc (strlen (data) + 2);
  strcpy (nkword, " ");         /* not mandatory */
  strcat (nkword, data);
  uri->data.ksk.keywords[uri->data.ksk.keywordCount++] = nkword;
  return GNUNET_OK;
}


/**
 * Construct a keyword-URI from meta-data (take all entries
 * in the meta-data and construct one large keyword URI
 * that lists all keywords that can be found in the meta-data).
 * @deprecated
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_ksk_create_from_meta_data (const struct GNUNET_MetaData *md)
{
  struct GNUNET_FS_Uri *ret;

  if (md == NULL)
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_Uri));
  ret->type = ksk;
  ret->data.ksk.keywordCount = 0;
  ret->data.ksk.keywords = NULL;
  ret->data.ksk.keywords
    = GNUNET_malloc (sizeof (char *) *
                     GNUNET_meta_data_get_contents (md, NULL, NULL));
  GNUNET_meta_data_get_contents (md, &gather_uri_data, ret);
  return ret;

}

#if 0

// old code...



/**
 * In URI-encoding, does the given character
 * need to be encoded using %-encoding?
 */
static int
needs_percent (char c)
{
  return (!((isalnum (c)) ||
            (c == '-') || (c == '_') || (c == '.') || (c == '~')));
}

/**
 * Generate a keyword URI.
 * @return NULL on error (i.e. keywordCount == 0)
 */
static char *
createKeywordURI (char **keywords, unsigned int keywordCount)
{
  size_t n;
  char *ret;
  unsigned int i;
  unsigned int j;
  unsigned int wpos;
  size_t slen;
  const char *keyword;

  n =
    keywordCount + strlen (GNUNET_ECRS_URI_PREFIX) +
    strlen (GNUNET_ECRS_SEARCH_INFIX) + 1;
  for (i = 0; i < keywordCount; i++)
    {
      keyword = keywords[i];
      slen = strlen (keyword);
      n += slen;
      for (j = 0; j < slen; j++)
        {
          if ((j == 0) && (keyword[j] == ' '))
            {
              n--;
              continue;         /* skip leading space */
            }
          if (needs_percent (keyword[j]))
            n += 2;             /* will use %-encoding */
        }
    }
  ret = GNUNET_malloc (n);
  strcpy (ret, GNUNET_ECRS_URI_PREFIX);
  strcat (ret, GNUNET_ECRS_SEARCH_INFIX);
  wpos = strlen (ret);
  for (i = 0; i < keywordCount; i++)
    {
      keyword = keywords[i];
      slen = strlen (keyword);
      for (j = 0; j < slen; j++)
        {
          if ((j == 0) && (keyword[j] == ' '))
            continue;           /* skip leading space */
          if (needs_percent (keyword[j]))
            {
              sprintf (&ret[wpos], "%%%02X", keyword[j]);
              wpos += 3;
            }
          else
            {
              ret[wpos++] = keyword[j];
            }
        }
      if (i != keywordCount - 1)
        ret[wpos++] = '+';
    }
  return ret;
}

/**
 * Generate a subspace URI.
 */
static char *
createSubspaceURI (const GNUNET_HashCode * namespace, const char *identifier)
{
  size_t n;
  char *ret;
  GNUNET_EncName ns;

  n =
    sizeof (GNUNET_EncName) + strlen (GNUNET_ECRS_URI_PREFIX) +
    strlen (GNUNET_ECRS_SUBSPACE_INFIX) + 1 + strlen (identifier);
  ret = GNUNET_malloc (n);
  GNUNET_hash_to_enc (namespace, &ns);
  GNUNET_snprintf (ret, n,
                   "%s%s%s/%s",
                   GNUNET_ECRS_URI_PREFIX, GNUNET_ECRS_SUBSPACE_INFIX,
                   (const char *) &ns, identifier);
  return ret;
}

/**
 * Generate a file URI.
 */
static char *
createFileURI (const GNUNET_EC_FileIdentifier * fi)
{
  char *ret;
  GNUNET_EncName keyhash;
  GNUNET_EncName queryhash;
  size_t n;

  GNUNET_hash_to_enc (&fi->chk.key, &keyhash);
  GNUNET_hash_to_enc (&fi->chk.query, &queryhash);

  n =
    strlen (GNUNET_ECRS_URI_PREFIX) + 2 * sizeof (GNUNET_EncName) + 8 + 16 +
    32 + strlen (GNUNET_ECRS_FILE_INFIX);
  ret = GNUNET_malloc (n);
  GNUNET_snprintf (ret,
                   n,
                   "%s%s%s.%s.%llu",
                   GNUNET_ECRS_URI_PREFIX,
                   GNUNET_ECRS_FILE_INFIX,
                   (char *) &keyhash, (char *) &queryhash,
                   GNUNET_ntohll (fi->file_length));
  return ret;
}

#include "bincoder.c"

/**
 * Create a (string) location URI from a Location.
 */
static char *
createLocURI (const Location * loc)
{
  size_t n;
  char *ret;
  GNUNET_EncName keyhash;
  GNUNET_EncName queryhash;
  char *peerId;
  char *peerSig;

  GNUNET_hash_to_enc (&loc->fi.chk.key, &keyhash);
  GNUNET_hash_to_enc (&loc->fi.chk.query, &queryhash);
  n = 2148;
  peerId = bin2enc (&loc->peer, sizeof (GNUNET_RSA_PublicKey));
  peerSig = bin2enc (&loc->contentSignature, sizeof (GNUNET_RSA_Signature));
  ret = GNUNET_malloc (n);
  GNUNET_snprintf (ret,
                   n,
                   "%s%s%s.%s.%llu.%s.%s.%u",
                   GNUNET_ECRS_URI_PREFIX,
                   GNUNET_ECRS_LOCATION_INFIX,
                   (char *) &keyhash,
                   (char *) &queryhash,
                   GNUNET_ntohll (loc->fi.file_length),
                   peerId, peerSig, loc->expirationTime);
  GNUNET_free (peerSig);
  GNUNET_free (peerId);
  return ret;
}

/**
 * Convert a URI to a UTF-8 String.
 */
char *
GNUNET_ECRS_uri_to_string (const struct GNUNET_ECRS_URI *uri)
{
  if (uri == NULL)
    {
      GNUNET_GE_BREAK (NULL, 0);
      return NULL;
    }
  switch (uri->type)
    {
    case ksk:
      return createKeywordURI (uri->data.ksk.keywords,
                               uri->data.ksk.keywordCount);
    case sks:
      return createSubspaceURI (&uri->data.sks.namespace,
                                uri->data.sks.identifier);
    case chk:
      return createFileURI (&uri->data.fi);
    case loc:
      return createLocURI (&uri->data.loc);
    default:
      GNUNET_GE_BREAK (NULL, 0);
      return NULL;
    }
}

/**
 * Convert keyword URI to a human readable format
 * (i.e. the search query that was used in the first place)
 */
char *
GNUNET_ECRS_ksk_uri_to_human_readable_string (const struct GNUNET_ECRS_URI
                                              *uri)
{
  size_t n;
  char *ret;
  unsigned int i;
  const char *keyword;
  char **keywords;
  unsigned int keywordCount;

  if ((uri == NULL) || (uri->type != ksk))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return NULL;
    }
  keywords = uri->data.ksk.keywords;
  keywordCount = uri->data.ksk.keywordCount;
  n = keywordCount + 1;
  for (i = 0; i < keywordCount; i++)
    {
      keyword = keywords[i];
      n += strlen (keyword) - 1;
      if (NULL != strstr (&keyword[1], " "))
        n += 2;
      if (keyword[0] == '+')
        n++;
    }
  ret = GNUNET_malloc (n);
  strcpy (ret, "");
  for (i = 0; i < keywordCount; i++)
    {
      keyword = keywords[i];
      if (NULL != strstr (&keyword[1], " "))
        {
          strcat (ret, "\"");
          if (keyword[0] == '+')
            strcat (ret, keyword);
          else
            strcat (ret, &keyword[1]);
          strcat (ret, "\"");
        }
      else
        {
          if (keyword[0] == '+')
            strcat (ret, keyword);
          else
            strcat (ret, &keyword[1]);
        }
      strcat (ret, " ");
    }
  return ret;
}

/**
 * Given a keyword with %-encoding (and possibly quotes to protect
 * spaces), return a copy of the keyword without %-encoding and
 * without double-quotes (%22).  Also, add a space at the beginning
 * if there is not a '+'.
 */
static char *
percent_decode_keyword (const char *in)
{
  char *out;
  char *ret;
  unsigned int rpos;
  unsigned int wpos;
  unsigned int hx;

  out = GNUNET_strdup (in);
  rpos = 0;
  wpos = 0;
  while (out[rpos] != '\0')
    {
      if (out[rpos] == '%')
        {
          if (1 != sscanf (&out[rpos + 1], "%2X", &hx))
            {
              GNUNET_free (out);
              return NULL;
            }
          rpos += 3;
          if (hx == '"')
            continue;           /* skip double quote */
          out[wpos++] = (char) hx;
        }
      else
        {
          out[wpos++] = out[rpos++];
        }
    }
  out[wpos] = '\0';
  if (out[0] == '+')
    {
      ret = GNUNET_strdup (out);
    }
  else
    {
      /* need to prefix with space */
      ret = GNUNET_malloc (strlen (out) + 2);
      strcpy (ret, " ");
      strcat (ret, out);
    }
  GNUNET_free (out);
  return ret;
}

/**
 * Parses an ECRS search URI.
 *
 * @param uri an uri string
 * @param keyword will be set to an array with the keywords
 * @return GNUNET_SYSERR if this is not a search URI, otherwise
 *  the number of keywords placed in the array
 */
static int
parseKeywordURI (struct GNUNET_GE_Context *ectx, const char *uri,
                 char ***keywords)
{
  unsigned int pos;
  int ret;
  int iret;
  int i;
  size_t slen;
  char *dup;
  int saw_quote;

  GNUNET_GE_ASSERT (ectx, uri != NULL);

  slen = strlen (uri);
  pos = strlen (GNUNET_ECRS_URI_PREFIX);

  if (0 != strncmp (uri, GNUNET_ECRS_URI_PREFIX, pos))
    return GNUNET_SYSERR;
  if (0 !=
      strncmp (&uri[pos], GNUNET_ECRS_SEARCH_INFIX,
               strlen (GNUNET_ECRS_SEARCH_INFIX)))
    return GNUNET_SYSERR;
  pos += strlen (GNUNET_ECRS_SEARCH_INFIX);
  if (slen == pos)
    {
      /* no keywords */
      (*keywords) = NULL;
      return 0;
    }
  if ((uri[slen - 1] == '+') || (uri[pos] == '+'))
    return GNUNET_SYSERR;       /* no keywords / malformed */

  ret = 1;
  saw_quote = 0;
  for (i = pos; i < slen; i++)
    {
      if ((uri[i] == '%') && (&uri[i] == strstr (&uri[i], "%22")))
        {
          saw_quote = (saw_quote + 1) % 2;
          i += 3;
          continue;
        }
      if ((uri[i] == '+') && (saw_quote == 0))
        {
          ret++;
          if (uri[i - 1] == '+')
            return GNUNET_SYSERR;       /* "++" not allowed */
        }
    }
  if (saw_quote == 1)
    return GNUNET_SYSERR;       /* quotes not balanced */
  iret = ret;
  dup = GNUNET_strdup (uri);
  (*keywords) = GNUNET_malloc (ret * sizeof (char *));
  for (i = 0; i < ret; i++)
    (*keywords)[i] = NULL;
  for (i = slen - 1; i >= pos; i--)
    {
      if ((uri[i] == '%') && (&uri[i] == strstr (&uri[i], "%22")))
        {
          saw_quote = (saw_quote + 1) % 2;
          i += 3;
          continue;
        }
      if ((dup[i] == '+') && (saw_quote == 0))
        {
          (*keywords)[--ret] = percent_decode_keyword (&dup[i + 1]);
          if (NULL == (*keywords)[ret])
            goto CLEANUP;
          dup[i] = '\0';
        }
    }
  (*keywords)[--ret] = percent_decode_keyword (&dup[pos]);
  if (NULL == (*keywords)[ret])
    goto CLEANUP;
  GNUNET_GE_ASSERT (ectx, ret == 0);
  GNUNET_free (dup);
  return iret;
CLEANUP:
  for (i = 0; i < ret; i++)
    GNUNET_free_non_null ((*keywords)[i]);
  GNUNET_free (*keywords);
  *keywords = NULL;
  GNUNET_free (dup);
  return GNUNET_SYSERR;
}

/**
 * Parses an AFS namespace / subspace identifier URI.
 *
 * @param uri an uri string
 * @param namespace set to the namespace ID
 * @param identifier set to the ID in the namespace
 * @return GNUNET_OK on success, GNUNET_SYSERR if this is not a namespace URI
 */
static int
parseSubspaceURI (struct GNUNET_GE_Context *ectx,
                  const char *uri,
                  GNUNET_HashCode * namespace, char **identifier)
{
  unsigned int pos;
  size_t slen;
  char *up;

  GNUNET_GE_ASSERT (ectx, uri != NULL);

  slen = strlen (uri);
  pos = strlen (GNUNET_ECRS_URI_PREFIX);

  if (0 != strncmp (uri, GNUNET_ECRS_URI_PREFIX, pos))
    return GNUNET_SYSERR;
  if (0 != strncmp (&uri[pos],
                    GNUNET_ECRS_SUBSPACE_INFIX,
                    strlen (GNUNET_ECRS_SUBSPACE_INFIX)))
    return GNUNET_SYSERR;
  pos += strlen (GNUNET_ECRS_SUBSPACE_INFIX);
  if ((slen < pos + sizeof (GNUNET_EncName) + 1) ||
      (!((uri[pos + sizeof (GNUNET_EncName) - 1] == '/') ||
         (uri[pos + sizeof (GNUNET_EncName) - 1] == '\\'))))
    return GNUNET_SYSERR;

  up = GNUNET_strdup (uri);
  up[pos + sizeof (GNUNET_EncName) - 1] = '\0';
  if ((GNUNET_OK != GNUNET_enc_to_hash (&up[pos], namespace)))
    {
      GNUNET_free (up);
      return GNUNET_SYSERR;
    }
  *identifier = GNUNET_strdup (&up[pos + sizeof (GNUNET_EncName)]);
  GNUNET_free (up);
  return GNUNET_OK;
}

/**
 * Parses an URI that identifies a file
 *
 * @param uri an uri string
 * @param fi the file identifier
 * @return GNUNET_OK on success, GNUNET_SYSERR if this is not a file URI
 */
static int
parseFileURI (struct GNUNET_GE_Context *ectx, const char *uri,
              GNUNET_EC_FileIdentifier * fi)
{
  unsigned int pos;
  size_t slen;
  char *dup;

  GNUNET_GE_ASSERT (ectx, uri != NULL);

  slen = strlen (uri);
  pos = strlen (GNUNET_ECRS_URI_PREFIX);

  if (0 != strncmp (uri, GNUNET_ECRS_URI_PREFIX, pos))
    return GNUNET_SYSERR;
  if (0 !=
      strncmp (&uri[pos], GNUNET_ECRS_FILE_INFIX,
               strlen (GNUNET_ECRS_FILE_INFIX)))
    return GNUNET_SYSERR;
  pos += strlen (GNUNET_ECRS_FILE_INFIX);
  if ((slen < pos + 2 * sizeof (GNUNET_EncName) + 1) ||
      (uri[pos + sizeof (GNUNET_EncName) - 1] != '.') ||
      (uri[pos + sizeof (GNUNET_EncName) * 2 - 1] != '.'))
    return GNUNET_SYSERR;

  dup = GNUNET_strdup (uri);
  dup[pos + sizeof (GNUNET_EncName) - 1] = '\0';
  dup[pos + sizeof (GNUNET_EncName) * 2 - 1] = '\0';
  if ((GNUNET_OK != GNUNET_enc_to_hash (&dup[pos],
                                        &fi->chk.key)) ||
      (GNUNET_OK != GNUNET_enc_to_hash (&dup[pos + sizeof (GNUNET_EncName)],
                                        &fi->chk.query)) ||
      (1 != SSCANF (&dup[pos + sizeof (GNUNET_EncName) * 2],
                    "%llu", &fi->file_length)))
    {
      GNUNET_free (dup);
      return GNUNET_SYSERR;
    }
  GNUNET_free (dup);
  fi->file_length = GNUNET_htonll (fi->file_length);
  return GNUNET_OK;
}

/**
 * Parses an URI that identifies a location (and file).
 * Also verifies validity of the location URI.
 *
 * @param uri an uri string
 * @param loc where to store the location
 * @return GNUNET_OK on success, GNUNET_SYSERR if this is not a file URI
 */
static int
parseLocationURI (struct GNUNET_GE_Context *ectx, const char *uri,
                  Location * loc)
{
  unsigned int pos;
  unsigned int npos;
  int ret;
  size_t slen;
  char *dup;
  char *addr;


  GNUNET_GE_ASSERT (ectx, uri != NULL);
  addr = NULL;
  slen = strlen (uri);
  pos = strlen (GNUNET_ECRS_URI_PREFIX);

  if (0 != strncmp (uri, GNUNET_ECRS_URI_PREFIX, pos))
    return GNUNET_SYSERR;
  if (0 != strncmp (&uri[pos],
                    GNUNET_ECRS_LOCATION_INFIX,
                    strlen (GNUNET_ECRS_LOCATION_INFIX)))
    return GNUNET_SYSERR;
  pos += strlen (GNUNET_ECRS_LOCATION_INFIX);
  if ((slen < pos + 2 * sizeof (GNUNET_EncName) + 1) ||
      (uri[pos + sizeof (GNUNET_EncName) - 1] != '.') ||
      (uri[pos + sizeof (GNUNET_EncName) * 2 - 1] != '.'))
    return GNUNET_SYSERR;

  dup = GNUNET_strdup (uri);
  dup[pos + sizeof (GNUNET_EncName) - 1] = '\0';
  dup[pos + sizeof (GNUNET_EncName) * 2 - 1] = '\0';
  npos = pos + sizeof (GNUNET_EncName) * 2;
  while ((uri[npos] != '\0') && (uri[npos] != '.'))
    npos++;
  if (dup[npos] == '\0')
    goto ERR;
  dup[npos++] = '\0';
  if ((GNUNET_OK != GNUNET_enc_to_hash (&dup[pos],
                                        &loc->fi.chk.key)) ||
      (GNUNET_OK != GNUNET_enc_to_hash (&dup[pos + sizeof (GNUNET_EncName)],
                                        &loc->fi.chk.query)) ||
      (1 != SSCANF (&dup[pos + sizeof (GNUNET_EncName) * 2],
                    "%llu", &loc->fi.file_length)))
    goto ERR;
  loc->fi.file_length = GNUNET_htonll (loc->fi.file_length);
  ret = enc2bin (&dup[npos], &loc->peer, sizeof (GNUNET_RSA_PublicKey));
  if (ret == -1)
    goto ERR;
  npos += ret;
  if (dup[npos++] != '.')
    goto ERR;
  ret =
    enc2bin (&dup[npos], &loc->contentSignature,
             sizeof (GNUNET_RSA_Signature));
  if (ret == -1)
    goto ERR;
  npos += ret;
  if (dup[npos++] != '.')
    goto ERR;
  if (1 != SSCANF (&dup[npos], "%u", &loc->expirationTime))
    goto ERR;
  /* Finally: verify sigs! */
  if (GNUNET_OK != GNUNET_RSA_verify (&loc->fi,
                                      sizeof (GNUNET_EC_FileIdentifier) +
                                      sizeof (GNUNET_PeerIdentity) +
                                      sizeof (GNUNET_Int32Time),
                                      &loc->contentSignature, &loc->peer))
    goto ERR;
  GNUNET_free (dup);
  return GNUNET_OK;
ERR:
  GNUNET_free (dup);
  GNUNET_free_non_null (addr);
  return GNUNET_SYSERR;
}

/**
 * Convert a UTF-8 String to a URI.
 */
URI *
GNUNET_ECRS_string_to_uri (struct GNUNET_GE_Context * ectx, const char *uri)
{
  URI *ret;
  int len;

  ret = GNUNET_malloc (sizeof (URI));
  if (GNUNET_OK == parseFileURI (ectx, uri, &ret->data.fi))
    {
      ret->type = chk;
      return ret;
    }
  if (GNUNET_OK == parseSubspaceURI (ectx,
                                     uri,
                                     &ret->data.sks.namespace,
                                     &ret->data.sks.identifier))
    {
      ret->type = sks;
      return ret;
    }
  if (GNUNET_OK == parseLocationURI (ectx, uri, &ret->data.loc))
    {
      ret->type = loc;
      return ret;
    }
  len = parseKeywordURI (ectx, uri, &ret->data.ksk.keywords);
  if (len < 0)
    {
      GNUNET_free (ret);
      return NULL;
    }
  ret->type = ksk;
  ret->data.ksk.keywordCount = len;
  return ret;
}



/**
 * Construct a location URI.
 *
 * @param baseURI content offered by the sender
 * @param sender identity of the peer with the content
 * @param expiration_time how long will the content be offered?
 * @param proto transport protocol to reach the peer
 * @param sas sender address size (for HELLO)
 * @param address sas bytes of address information
 * @param signer function to call for obtaining
 *        RSA signatures for "sender".
 * @return the location URI
 */
struct GNUNET_ECRS_URI *
GNUNET_ECRS_location_to_uri (const struct GNUNET_ECRS_URI *baseUri,
                             const GNUNET_RSA_PublicKey * sender,
                             GNUNET_Int32Time expirationTime,
                             GNUNET_ECRS_SignFunction signer,
                             void *signer_cls)
{
  struct GNUNET_ECRS_URI *uri;

  if (baseUri->type != chk)
    return NULL;

  uri = GNUNET_malloc (sizeof (struct GNUNET_ECRS_URI));
  uri->type = loc;
  uri->data.loc.fi = baseUri->data.fi;
  uri->data.loc.peer = *sender;
  uri->data.loc.expirationTime = expirationTime;
  signer (signer_cls,
          sizeof (GNUNET_EC_FileIdentifier) +
          sizeof (GNUNET_PeerIdentity) +
          sizeof (GNUNET_Int32Time),
          &uri->data.loc.fi, &uri->data.loc.contentSignature);
  return uri;
}

#endif

/* end of uri.c */
