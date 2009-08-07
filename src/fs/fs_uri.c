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
#include "gnunet_fs_service.h"
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
      *key = uri->data.chk.chk.query;
      return;
    case sks:
      GNUNET_CRYPTO_hash (uri->data.sks.identifier,
			  strlen (uri->data.sks.identifier), key);
      break;
    case ksk:
      if (uri->data.ksk.keywordCount > 0)
        GNUNET_CRYPTO_hash (uri->data.ksk.keywords[0],
			    strlen (uri->data.ksk.keywords[0]), key);
      break;
    case loc:
      GNUNET_CRYPTO_hash (&uri->data.loc.fi,
			  sizeof (struct FileIdentifier) +
			  sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), key);
      break;
    default:
      memset (key, 0, sizeof (GNUNET_HashCode));
      break;
    }
}


/**
 * Convert keyword URI to a human readable format
 * (i.e. the search query that was used in the first place)
 *
 * @param uri ksk uri to convert to a string 
 * @return string with the keywords
 */
char *
GNUNET_FS_uri_ksk_to_string_fancy (const struct GNUNET_FS_Uri *uri)
{
  size_t n;
  char *ret;
  unsigned int i;
  const char *keyword;
  char **keywords;
  unsigned int keywordCount;

  if ((uri == NULL) || (uri->type != ksk))
    {
      GNUNET_break (0);
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
 * 
 * @param in string with %-encoding
 * @param emsg where to store the parser error message (if any)
 * @return decodded string with leading space (or preserved plus)
 */
static char *
percent_decode_keyword (const char *in, char **emsg)
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
 * Parse a KSK URI.
 *
 * @param s an uri string
 * @param emsg where to store the parser error message (if any)
 * @return NULL on error, otherwise the KSK URI
 */
static struct GNUNET_FS_Uri *
uri_ksk_parse (const char *s, char **emsg)
{
  struct GNUNET_FS_Uri *ret;
  char **keywords;
  unsigned int pos;
  int max;
  int iret;
  int i;
  size_t slen;
  char *dup;
  int saw_quote;

  GNUNET_assert (s != NULL);
  slen = strlen (s);
  pos = strlen (GNUNET_FS_URI_PREFIX GNUNET_FS_URI_KSK_INFIX);
  if ( (slen <= pos) ||
       (0 != strncmp (s, GNUNET_FS_URI_PREFIX GNUNET_FS_URI_KSK_INFIX, 
		      pos) ) ||
       (s[slen - 1] == '+') ||
       (s[pos] == '+') )
    return NULL;       /* no keywords / malformed */
  
  max = 1;
  saw_quote = 0;
  for (i = pos; i < slen; i++)
    {
      if ((s[i] == '%') && (&s[i] == strstr (&s[i], "%22")))
        {
          saw_quote = (saw_quote + 1) % 2;
          i += 3;
          continue;
        }
      if ((s[i] == '+') && (saw_quote == 0))
        {
          max++;
          if (s[i - 1] == '+')
            return NULL;       /* "++" not allowed */
        }
    }
  if (saw_quote == 1)
    return NULL;       /* quotes not balanced */
  iret = max;
  dup = GNUNET_strdup (s);
  keywords = GNUNET_malloc (max * sizeof (char *));
  for (i = slen - 1; i >= pos; i--)
    {
      if ((s[i] == '%') && (&s[i] == strstr (&s[i], "%22")))
        {
          saw_quote = (saw_quote + 1) % 2;
          i += 3;
          continue;
        }
      if ((dup[i] == '+') && (saw_quote == 0))
        {
          keywords[--max] = percent_decode_keyword (&dup[i + 1], emsg);
          if (NULL == keywords[max])
            goto CLEANUP;
          dup[i] = '\0';
        }
    }
  keywords[--max] = percent_decode_keyword (&dup[pos], emsg);
  if (NULL == keywords[max])
    goto CLEANUP;
  GNUNET_assert (max == 0);
  GNUNET_free (dup);
  ret = GNUNET_malloc (sizeof(struct GNUNET_FS_Uri));
  ret->type = ksk;
  ret->data.ksk.keywordCount = iret;
  ret->data.ksk.keywords = keywords;
  return ret;
CLEANUP:
  for (i = 0; i < max; i++)
    GNUNET_free_non_null (keywords[i]);
  GNUNET_free (keywords);
  GNUNET_free (dup);
  return NULL;
}


/**
 * Parse an SKS URI.
 *
 * @param s an uri string
 * @param emsg where to store the parser error message (if any)
 * @return NULL on error, SKS URI otherwise
 */
static struct GNUNET_FS_Uri *
uri_sks_parse (const char *s, char **emsg)
{
  struct GNUNET_FS_Uri *ret;
  GNUNET_HashCode namespace;
  char *identifier;
  unsigned int pos;
  size_t slen;
  char enc[sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded)];

  GNUNET_assert (s != NULL);
  slen = strlen (s);
  pos = strlen (GNUNET_FS_URI_PREFIX GNUNET_FS_URI_SKS_INFIX);
  if ( (slen <= pos) ||
       (0 != strncmp (s, GNUNET_FS_URI_PREFIX GNUNET_FS_URI_SKS_INFIX, 
		      pos) ) ||
       (slen < pos + sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) + 1) ||
       (s[pos + sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1] != '/') )
    return NULL;
  memcpy (enc, &s[pos], sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded));
  enc[sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded)-1] = '\0';
  if (GNUNET_OK != GNUNET_CRYPTO_hash_from_string (enc, &namespace))
    return NULL;
  identifier = GNUNET_strdup (&s[pos + sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded)]);
  ret = GNUNET_malloc (sizeof(struct GNUNET_FS_Uri));
  ret->type = sks;
  ret->data.sks.namespace = namespace;
  ret->data.sks.identifier = identifier;
  return ret;
}


/**
 * Parse a CHK URI.
 *
 * @param s an uri string
 * @param emsg where to store the parser error message (if any)
 * @return NULL on error, CHK URI otherwise
 */
static struct GNUNET_FS_Uri *
uri_chk_parse (const char *s, char **emsg)
{
  struct GNUNET_FS_Uri *ret;
  struct FileIdentifier fi;
  unsigned int pos;
  size_t slen;
  char h1[sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded)];
  char h2[sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded)];

  GNUNET_assert (s != NULL);

  slen = strlen (s);
  pos = strlen (GNUNET_FS_URI_PREFIX GNUNET_FS_URI_CHK_INFIX);
  if ( (slen < pos + 2 * sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) + 1) ||
       (0 != strncmp (s, GNUNET_FS_URI_PREFIX GNUNET_FS_URI_CHK_INFIX, 
		      pos) ) ||
       (s[pos + sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1] != '.') ||
       (s[pos + sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) * 2 - 1] != '.') )
    return NULL;

  memcpy (h1,
	  &s[pos], 
	  sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded));
  h1[sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded)-1] = '\0';
  memcpy (h2,
	  &s[pos + sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded)],
	  sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded));
  h2[sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded)-1] = '\0';
  
  if ((GNUNET_OK != GNUNET_CRYPTO_hash_from_string (h1,
					       &fi.chk.key)) ||
      (GNUNET_OK != GNUNET_CRYPTO_hash_from_string (h2,
					       &fi.chk.query)) ||
      (1 != SSCANF (&s[pos + sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) * 2],
                    "%llu", 
		    &fi.file_length)))
    return NULL;
  fi.file_length = GNUNET_htonll (fi.file_length);

  ret = GNUNET_malloc (sizeof(struct GNUNET_FS_Uri));
  ret->type = chk;
  ret->data.chk = fi;
  return ret;
}


/**
 * Parse a LOC URI.
 * Also verifies validity of the location URI.
 *
 * @param s an uri string
 * @param emsg where to store the parser error message (if any)
 * @return NULL on error, valid LOC URI otherwise
 */
static struct GNUNET_FS_Uri *
uri_loc_parse (const char *s, char **emsg)
{
  struct GNUNET_FS_Uri *ret;
  char h1[sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded)];
  char h2[sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded)];
  unsigned int pos;
  unsigned int npos;
  unsigned long long exptime;
  int ret;
  size_t slen;
  char *addr;

  GNUNET_assert (s != NULL);
  slen = strlen (s);
  pos = strlen (GNUNET_FS_URI_PREFIX GNUNET_FS_URI_LOC_INFIX);
  if ( (slen < pos + 2 * sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) + 1) ||
       (0 != strncmp (s, GNUNET_FS_URI_PREFIX GNUNET_FS_URI_LOC_INFIX, 
		      pos) ) ||
       (s[pos + sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1] != '.') ||
       (s[pos + sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) * 2 - 1] != '.') )
    return NULL;

  memcpy (h1,
	  &s[pos], 
	  sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded));
  h1[sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded)-1] = '\0';
  memcpy (h2,
	  &s[pos + sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded)],
	  sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded));
  h2[sizeof(struct GNUNET_CRYPTO_HashAsciiEncoded)-1] = '\0';
  
  if ((GNUNET_OK != GNUNET_CRYPTO_hash_from_string (h1,
						    &fi.chk.key)) ||
      (GNUNET_OK != GNUNET_CRYPTO_hash_from_string (h2,
						    &fi.chk.query)) 
      (1 != SSCANF (&s[pos + sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) * 2],
                    "%llu", 
		    &fi.file_length)) )
    return NULL;
  fi.file_length = GNUNET_htonll (fi.file_length);

  npos = pos + sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) * 2;
  while ((s[npos] != '\0') && (s[npos] != '.'))
    npos++;
  if (s[npos] == '\0')
    goto ERR;
  ret = enc2bin (&s[npos], 
		 &loc->peer,
		 sizeof (GNUNET_RSA_PublicKey));
  if (ret == -1)
    goto ERR;
  npos += ret;
  if (dup[npos++] != '.')
    goto ERR;
  ret = enc2bin (&s[npos],
		 &loc->contentSignature,
		 sizeof (struct GNUNET_CRYPTO_RsaSignature));
  if (ret == -1)
    goto ERR;
  npos += ret;
  if (dup[npos++] != '.')
    goto ERR;
  if (1 != SSCANF (&dup[npos], "%llu", &exptime))
    goto ERR;
  // FIXME: do something to exptime...
  /* Finally: verify sigs! */
  if (GNUNET_OK != GNUNET_RSA_verify (&loc->fi,
                                      sizeof (struct FileIdentifier) +
                                      sizeof (GNUNET_PeerIdentity) +
                                      sizeof (GNUNET_Int32Time),
                                      &loc->contentSignature, 
				      &loc->peer))
    goto ERR;

  ret = GNUNET_malloc (sizeof(struct GNUNET_FS_Uri));
  ret->type = loc;
  ret->data.loc.chk = fi;
  ret->data.loc.xx = yy;

  return ret;
ERR:
  GNUNET_free_non_null (addr);
  return NULL;
}


/**
 * Convert a UTF-8 String to a URI.
 *
 * @param uri string to parse
 * @param emsg where to store the parser error message (if any)
 * @return NULL on error
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_parse (const char *uri,
		     char **emsg)
{
  struct GNUNET_FS_Uri *ret;

  if ( (NULL != (ret = uri_chk_parse (uri, emsg))) ||
       (NULL != (ret = uri_ksk_parse (uri, emsg))) ||
       (NULL != (ret = uri_sks_parse (uri, emsg))) ||
       (NULL != (ret = uri_loc_parse (uri, emsg))) )
    return ret;
  return NULL;
}


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
      if (GNUNET_OK != iterator (iterator_cls,
				 &keyword[1],
				 keyword[0] == '+'))
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
  GNUNET_CRYPTO_hash (&uri->data.loc.peer,
		      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
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
  struct GNUNET_FS_Uri *ret;

  if (uri->type != loc)
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_Uri));
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
GNUNET_FS_uri_ksk_canonicalize (const struct GNUNET_FS_Uri *uri)
{
  /* FIXME: not implemented */
  return NULL;
}


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
			 const struct GNUNET_FS_Uri *u2)
{
  /* FIXME */
  return NULL;
}


/**
 * Duplicate URI.
 *
 * @param uri the URI to duplicate
 * @return copy of the URI
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_dup (const struct GNUNET_FS_Uri *uri)
{
  struct GNUNET_FS_Uri *ret;
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
GNUNET_FS_uri_ksk_create (const char *keywords)
{
  /* FIXME */
  return NULL;
}


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
				    const char **argv)
{
  /* FIXME */
  return NULL;
}


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

  GNUNET_assert (u1 != NULL);
  GNUNET_assert (u2 != NULL);
  if (u1->type != u2->type)
    return GNUNET_NO;
  switch (u1->type)
    {
    case chk:
      if (0 == memcmp (&u1->data.chk,
                       &u2->data.chk,
		       sizeof (struct FileIdentifier)))
        return GNUNET_YES;
      return GNUNET_NO;
    case sks:
      if ((0 == memcmp (&u1->data.sks.namespace,
                        &u2->data.sks.namespace,
                        sizeof (GNUNET_HashCode))) &&
          (0 == strcmp (u1->data.sks.identifier,
                        u2->data.sks.identifier)))

        return GNUNET_YES;
      return GNUNET_NO;
    case ksk:
      if (u1->data.ksk.keywordCount != u2->data.ksk.keywordCount)
        return GNUNET_NO;
      for (i = 0; i < u1->data.ksk.keywordCount; i++)
        {
          ret = GNUNET_NO;
          for (j = 0; j < u2->data.ksk.keywordCount; j++)
            {
              if (0 == strcmp (u1->data.ksk.keywords[i],
                               u2->data.ksk.keywords[j]))
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
      if (memcmp (&u1->data.loc,
                  &u2->data.loc,
                  sizeof (struct FileIdentifier) +
                  sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) +
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
  *nsid = uri->data.sks.namespace;
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
				   const struct GNUNET_FS_Uri *uri)
{
  /* FIXME */
  return NULL;
}


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
GNUNET_FS_uri_ksk_create_from_meta_data (const struct GNUNET_CONTAINER_MetaData *md)
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
                     GNUNET_CONTAINER_meta_data_get_contents (md, NULL, NULL));
  GNUNET_CONTAINER_meta_data_get_contents (md, &gather_uri_data, ret);
  return ret;

}


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
 * Convert a KSK URI to a string.
 *
 * @param uri the URI to convert
 * @return NULL on error (i.e. keywordCount == 0)
 */
static char *
uri_ksk_to_string (const struct GNUNET_FS_Uri *uri)
{
  char ** keywords; 
  unsigned int keywordCount;
  size_t n;
  char *ret;
  unsigned int i;
  unsigned int j;
  unsigned int wpos;
  size_t slen;
  const char *keyword;

  if (uri->type != ksk)
    return NULL;
  keywords = uri->data.ksk.keywords;
  keywordCount = uri->data.ksk.keywordCount;
  n =
    keywordCount + strlen (GNUNET_FS_URI_PREFIX) +
    strlen (GNUNET_FS_URI_KSK_INFIX) + 1;
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
  strcpy (ret, GNUNET_FS_URI_PREFIX);
  strcat (ret, GNUNET_FS_URI_KSK_INFIX);
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
 * Convert SKS URI to a string.
 *
 * @param uri sks uri to convert
 * @return NULL on error
 */
static char *
uri_sks_to_string (const struct GNUNET_FS_Uri *uri)
{
  const GNUNET_HashCode * namespace;
  const char *identifier;
  char *ret;
  struct GNUNET_CRYPTO_HashAsciiEncoded ns;
  
  if (uri->type != sks)
    return NULL;
  namespace = &uri->data.sks.namespace;
  identifier = uri->data.sks.identifier;
  GNUNET_CRYPTO_hash_to_enc (namespace, &ns);
  GNUNET_asprintf (&ret,
                   "%s%s%s/%s",
                   GNUNET_FS_URI_PREFIX, 
		   GNUNET_FS_URI_SKS_INFIX,
                   (const char *) &ns, identifier);
  return ret;
}


/**
 * Convert a CHK URI to a string.
 *
 * @param uri chk uri to convert
 * @return NULL on error
 */
static char *
uri_chk_to_string (const struct GNUNET_FS_Uri *uri)
{
  const struct FileIdentifier * fi;
  char *ret;
  struct GNUNET_CRYPTO_HashAsciiEncoded keyhash;
  struct GNUNET_CRYPTO_HashAsciiEncoded queryhash;

  if (uri->type != chk)
    return NULL;
  fi = &uri->data.chk;
  GNUNET_CRYPTO_hash_to_enc (&fi->chk.key, &keyhash);
  GNUNET_CRYPTO_hash_to_enc (&fi->chk.query, &queryhash);

  GNUNET_asprintf (&ret,
                   "%s%s%s.%s.%llu",
                   GNUNET_FS_URI_PREFIX,
                   GNUNET_FS_URI_CHK_INFIX,
                   (const char *) &keyhash, 
		   (const char *) &queryhash,
                   GNUNET_ntohll (fi->file_length));
  return ret;
}

/**
 * Convert binary data to a string.
 *
 * @return converted data
 */
static char *
bin2enc (const void *data, size_t size)
{
  /**
   * 64 characters for encoding, 6 bits per character
   */
  static char *tbl =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_=";
  
  size_t len;
  size_t pos;
  unsigned int bits;
  unsigned int hbits;
  char *ret;

  GNUNET_assert (strlen (tbl) == 64);
  len = size * 8 / 6;
  if (((size * 8) % 6) != 0)
    len++;
  ret = GNUNET_malloc (len + 1);
  ret[len] = '\0';
  len = 0;
  bits = 0;
  hbits = 0;
  for (pos = 0; pos < size; pos++)
    {
      bits |= ((((const unsigned char *) data)[pos]) << hbits);
      hbits += 8;
      while (hbits >= 6)
        {
          ret[len++] = tbl[bits & 63];
          bits >>= 6;
          hbits -= 6;
        }
    }
  if (hbits > 0)
    ret[len++] = tbl[bits & 63];
  return ret;
}


/**
 * Convert a character back to the binary value
 * that it represents (given base64-encoding).
 *
 * @param a character to convert
 * @return offset in the "tbl" array
 */
static unsigned int
c2v (unsigned char a)
{
  if ((a >= '0') && (a <= '9'))
    return a - '0';
  if ((a >= 'A') && (a <= 'Z'))
    return (a - 'A' + 10);
  if ((a >= 'a') && (a <= 'z'))
    return (a - 'a' + 36);
  if (a == '_')
    return 62;
  if (a == '=')
    return 63;
  return -1;
}


/**
 * Convert string back to binary data.
 *
 * @param input '\0'-terminated string
 * @param data where to write binary data
 * @param size how much data should be converted
 * @return number of characters processed from input,
 *        -1 on error
 */
static int
enc2bin (const char *input, void *data, size_t size)
{
  size_t len;
  size_t pos;
  unsigned int bits;
  unsigned int hbits;

  len = size * 8 / 6;
  if (((size * 8) % 6) != 0)
    len++;
  if (strlen (input) < len)
    return -1;                  /* error! */
  bits = 0;
  hbits = 0;
  len = 0;
  pos = 0;
  for (pos = 0; pos < size; pos++)
    {
      while (hbits < 8)
        {
          bits |= (c2v (input[len++]) << hbits);
          hbits += 6;
        }
      (((unsigned char *) data)[pos]) = (unsigned char) bits;
      bits >>= 8;
      hbits -= 8;
    }
  return len;
}


/**
 * Convert a LOC URI to a string.
 *
 * @param uri loc uri to convert
 * @return NULL on error
 */
static char *
uri_loc_to_string (const struct GNUNET_FS_Uri *uri)
{
  char *ret;
  struct GNUNET_CRYPTO_HashAsciiEncoded keyhash;
  struct GNUNET_CRYPTO_HashAsciiEncoded queryhash;
  char *peerId;
  char *peerSig;

  GNUNET_CRYPTO_hash_to_enc (&uri->data.loc.fi.chk.key, &keyhash);
  GNUNET_CRYPTO_hash_to_enc (&uri->data.loc.fi.chk.query, &queryhash);
  peerId = bin2enc (&uri->data.loc.peer,
		    sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  peerSig = bin2enc (&uri->data.loc.contentSignature, 
		     sizeof (struct GNUNET_CRYPTO_RsaSignature));
  GNUNET_asprintf (&ret,
                   "%s%s%s.%s.%llu.%s.%s.%u", // FIXME: expirationTime 64-bit???
                   GNUNET_FS_URI_PREFIX,
                   GNUNET_FS_URI_LOC_INFIX,
                   (const char *) &keyhash,
                   (const char *) &queryhash,
                   GNUNET_ntohll (uri->data.loc.fi.file_length),
                   peerId,
		   peerSig,
		   uri->data.loc.expirationTime);
  GNUNET_free (peerSig);
  GNUNET_free (peerId);
  return ret;
}


/**
 * Convert a URI to a UTF-8 String.
 *
 * @param uri uri to convert to a string
 * @return the UTF-8 string
 */
char *
GNUNET_FS_uri_to_string (const struct GNUNET_FS_Uri *uri)
{
  if (uri == NULL)
    {
      GNUNET_break (0);
      return NULL;
    }
  switch (uri->type)
    {
    case ksk:
      return uri_ksk_to_string (uri);
    case sks:
      return uri_sks_to_string (uri);
    case chk:
      return uri_chk_to_string (uri);
    case loc:
      return uri_loc_to_string (uri);
    default:
      GNUNET_break (0);
      return NULL;
    }
}


#if 0

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
