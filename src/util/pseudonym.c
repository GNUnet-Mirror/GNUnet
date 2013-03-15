/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006, 2007, 2008, 2013 Christian Grothoff (and other contributing authors)

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
 * @file util/pseudonym.c
 * @brief helper functions
 * @author Christian Grothoff
 *
 * TODO:
 * - all cryptographic operations are currently NOT implemented and
 *   provided by stubs that merely pretend to work!
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_container_lib.h"
#include "gnunet_disk_lib.h"
#include "gnunet_pseudonym_lib.h"
#include "gnunet_bio_lib.h"
#include <gcrypt.h>

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GCRY(level, cmd, rc) do { LOG(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, gcry_strerror(rc)); } while(0);

/**
 * Name of the directory which stores meta data for pseudonym
 */
#define PS_METADATA_DIR DIR_SEPARATOR_STR "data" DIR_SEPARATOR_STR "pseudonym" DIR_SEPARATOR_STR "metadata" DIR_SEPARATOR_STR

/**
 * Name of the directory which stores names for pseudonyms
 */
#define PS_NAMES_DIR    DIR_SEPARATOR_STR "data" DIR_SEPARATOR_STR "pseudonym" DIR_SEPARATOR_STR "names"    DIR_SEPARATOR_STR


/**
 * Configuration section we use.
 */
#define GNUNET_CLIENT_SERVICE_NAME "client"


/* ************************* Disk operations (pseudonym data mgmt) **************** */

/**
 * Registered callbacks for discovery of pseudonyms.
 */
struct GNUNET_PSEUDONYM_DiscoveryHandle
{
  /**
   * This is a doubly linked list.
   */
  struct GNUNET_PSEUDONYM_DiscoveryHandle *next;

  /**
   * This is a doubly linked list.
   */
  struct GNUNET_PSEUDONYM_DiscoveryHandle *prev;

  /**
   * Function to call each time a pseudonym is discovered.
   */
  GNUNET_PSEUDONYM_Iterator callback;

  /**
   * Closure for callback.
   */
  void *callback_cls;
};


/**
 * Head of the linked list of functions to call when
 * new pseudonyms are added.
 */
static struct GNUNET_PSEUDONYM_DiscoveryHandle *disco_head;

/**
 * Tail of the linked list of functions to call when
 * new pseudonyms are added.
 */
static struct GNUNET_PSEUDONYM_DiscoveryHandle *disco_tail;


/**
 * Internal notification about new tracked URI.
 *
 * @param pseudonym public key of the pseudonym
 * @param md meta data to be written
 * @param rating rating of pseudonym
 */
static void
internal_notify (const struct GNUNET_PseudonymIdentifier *pseudonym,
                 const struct GNUNET_CONTAINER_MetaData *md, int rating)
{
  struct GNUNET_PSEUDONYM_DiscoveryHandle *pos;

  for (pos = disco_head; NULL != pos; pos = pos->next)
    pos->callback (pos->callback_cls, pseudonym, NULL, NULL, md, rating);
}


/**
 * Register callback to be invoked whenever we discover
 * a new pseudonym.
 * Will immediately call provided iterator callback for all
 * already discovered pseudonyms.
 *
 * @param cfg configuration to use
 * @param iterator iterator over pseudonym
 * @param iterator_cls point to a closure
 * @return registration handle
 */
struct GNUNET_PSEUDONYM_DiscoveryHandle *
GNUNET_PSEUDONYM_discovery_callback_register (const struct
					      GNUNET_CONFIGURATION_Handle *cfg,
                                              GNUNET_PSEUDONYM_Iterator iterator, 
					      void *iterator_cls)
{
  struct GNUNET_PSEUDONYM_DiscoveryHandle *dh;

  dh = GNUNET_malloc (sizeof (struct GNUNET_PSEUDONYM_DiscoveryHandle));
  dh->callback = iterator;
  dh->callback_cls = iterator_cls;
  GNUNET_CONTAINER_DLL_insert (disco_head, disco_tail, dh);
  GNUNET_PSEUDONYM_list_all (cfg, iterator, iterator_cls);
  return dh;
}


/**
 * Unregister pseudonym discovery callback.
 *
 * @param dh registration to unregister
 */
void
GNUNET_PSEUDONYM_discovery_callback_unregister (struct GNUNET_PSEUDONYM_DiscoveryHandle *dh)
{
  GNUNET_CONTAINER_DLL_remove (disco_head, disco_tail, dh);
  GNUNET_free (dh);
}


/**
 * Get the filename (or directory name) for the given
 * pseudonym identifier and directory prefix.
 *
 * @param cfg configuration to use
 * @param prefix path components to append to the private directory name
 * @param pseudonym the pseudonym, can be NULL
 * @return filename of the pseudonym (if pseudonym != NULL) or directory with the data (if pseudonym == NULL)
 */
static char *
get_data_filename (const struct GNUNET_CONFIGURATION_Handle *cfg,
                   const char *prefix, 
		   const struct GNUNET_PseudonymIdentifier *pseudonym)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  struct GNUNET_HashCode psid;

  if (NULL != pseudonym)
  {
    GNUNET_CRYPTO_hash (pseudonym,
			sizeof (struct GNUNET_PseudonymIdentifier),
			&psid);
    GNUNET_CRYPTO_hash_to_enc (&psid, &enc);
  }
  return GNUNET_DISK_get_home_filename (cfg, 
					GNUNET_CLIENT_SERVICE_NAME, prefix,
                                        (NULL == pseudonym) 
					? NULL 
					: (const char *) &enc,
                                        NULL);
}


/**
 * Get the filename (or directory name) for the given
 * hash code and directory prefix.
 *
 * @param cfg configuration to use
 * @param prefix path components to append to the private directory name
 * @param hc some hash code
 * @return filename of the pseudonym (if hc != NULL) or directory with the data (if hc == NULL)
 */
static char *
get_data_filename_hash (const struct GNUNET_CONFIGURATION_Handle *cfg,
			const char *prefix, 
			const struct GNUNET_HashCode *hc)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;

  if (NULL != hc)
    GNUNET_CRYPTO_hash_to_enc (hc, &enc);
  return GNUNET_DISK_get_home_filename (cfg, 
					GNUNET_CLIENT_SERVICE_NAME, prefix,
                                        (NULL == hc) 
					? NULL 
					: (const char *) &enc,
                                        NULL);
}


/**
 * Set the pseudonym metadata, rank and name.
 * Writes the pseudonym infomation into a file
 *
 * @param cfg overall configuration
 * @param pseudonym id of the pseudonym
 * @param name name to set. Must be the non-unique version of it.
 *        May be NULL, in which case it erases pseudonym's name!
 * @param md metadata to set
 *        May be NULL, in which case it erases pseudonym's metadata!
 * @param rank rank to assign
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_PSEUDONYM_set_info (const struct GNUNET_CONFIGURATION_Handle *cfg,
			   const struct GNUNET_PseudonymIdentifier *pseudonym,
			   const char *name,
			   const struct GNUNET_CONTAINER_MetaData *md, 
			   int32_t rank)
{
  char *fn;
  struct GNUNET_BIO_WriteHandle *fileW;

  fn = get_data_filename (cfg, PS_METADATA_DIR, pseudonym);
  if (NULL == (fileW = GNUNET_BIO_write_open (fn)))
  {
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  if ((GNUNET_OK != GNUNET_BIO_write (fileW, pseudonym, 
				      sizeof (struct GNUNET_PseudonymIdentifier))) ||
      (GNUNET_OK != GNUNET_BIO_write_int32 (fileW, rank)) ||
      (GNUNET_OK != GNUNET_BIO_write_string (fileW, name)) ||
      (GNUNET_OK != GNUNET_BIO_write_meta_data (fileW, md)))
  {
    (void) GNUNET_BIO_write_close (fileW);
    GNUNET_break (GNUNET_OK == GNUNET_DISK_directory_remove (fn));
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != GNUNET_BIO_write_close (fileW))
  {
    GNUNET_break (GNUNET_OK == GNUNET_DISK_directory_remove (fn));
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  } 
  GNUNET_free (fn);
  /* create entry for pseudonym name in names */
  if (NULL != name)
    GNUNET_free_non_null (GNUNET_PSEUDONYM_name_uniquify (cfg, pseudonym, 
							  name, NULL));
  return GNUNET_OK;
}


/**
 * Read pseudonym infomation from a file
 *
 * @param cfg configuration to use
 * @param pseudonym hash code of a pseudonym
 * @param meta meta data to be read from a file
 * @param rank rank of a pseudonym
 * @param ns_name name of a pseudonym
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
read_info (const struct GNUNET_CONFIGURATION_Handle *cfg,
           const struct GNUNET_PseudonymIdentifier *pseudonym,
           struct GNUNET_CONTAINER_MetaData **meta,
	   int32_t *rank,
           char **ns_name)
{
  struct GNUNET_PseudonymIdentifier pd;
  char *fn;
  char *emsg;
  struct GNUNET_BIO_ReadHandle *fileR;

  fn = get_data_filename (cfg, PS_METADATA_DIR, pseudonym);
  if (GNUNET_YES !=
      GNUNET_DISK_file_test (fn))
  {
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  if (NULL == (fileR = GNUNET_BIO_read_open (fn)))
  {
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  emsg = NULL;
  *ns_name = NULL;
  if ( (GNUNET_OK != GNUNET_BIO_read (fileR, "pseudonym", &pd, sizeof (pd))) ||
       (0 != memcmp (&pd, pseudonym, sizeof (pd))) ||
       (GNUNET_OK != GNUNET_BIO_read_int32 (fileR, rank)) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_string (fileR, "Read string error!", ns_name, 200)) ||
       (GNUNET_OK !=
       GNUNET_BIO_read_meta_data (fileR, "Read meta data error!", meta)) )
  {
    (void) GNUNET_BIO_read_close (fileR, &emsg);
    GNUNET_free_non_null (emsg);
    GNUNET_free_non_null (*ns_name);
    *ns_name = NULL;
    GNUNET_break (GNUNET_OK == GNUNET_DISK_directory_remove (fn));
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != GNUNET_BIO_read_close (fileR, &emsg))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Failed to parse metadata about pseudonym from file `%s': %s\n"), fn,
         emsg);
    GNUNET_break (GNUNET_OK == GNUNET_DISK_directory_remove (fn));
    GNUNET_CONTAINER_meta_data_destroy (*meta);
    *meta = NULL;
    GNUNET_free_non_null (*ns_name);
    *ns_name = NULL;
    GNUNET_free_non_null (emsg);
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  GNUNET_free (fn);
  return GNUNET_OK;
}


/**
 * Return unique variant of the namespace name.  Use it after
 * GNUNET_PSEUDONYM_get_info() to make sure that name is unique.
 *
 * @param cfg configuration
 * @param pseudonym public key of the pseudonym
 * @param name name to uniquify
 * @param suffix if not NULL, filled with the suffix value
 * @return NULL on failure (should never happen), name on success.
 *         Free the name with GNUNET_free().
 */
char *
GNUNET_PSEUDONYM_name_uniquify (const struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_PseudonymIdentifier *pseudonym,
				const char *name,
				unsigned int *suffix)
{
  struct GNUNET_HashCode nh;
  struct GNUNET_PseudonymIdentifier pi;
  uint64_t len;
  char *fn;
  struct GNUNET_DISK_FileHandle *fh;
  unsigned int i;
  unsigned int idx;
  char *ret;
  struct stat sbuf;

  GNUNET_CRYPTO_hash (name, strlen (name), &nh);
  fn = get_data_filename_hash (cfg, PS_NAMES_DIR, &nh);
  len = 0;
  if (0 == STAT (fn, &sbuf))
    GNUNET_break (GNUNET_OK == GNUNET_DISK_file_size (fn, &len, GNUNET_YES, GNUNET_YES));
  fh = GNUNET_DISK_file_open (fn,
                              GNUNET_DISK_OPEN_CREATE |
                              GNUNET_DISK_OPEN_READWRITE,
                              GNUNET_DISK_PERM_USER_READ |
                              GNUNET_DISK_PERM_USER_WRITE);
  i = 0;
  idx = -1;
  while ((len >= sizeof (struct GNUNET_PseudonymIdentifier)) &&
         (sizeof (struct GNUNET_PseudonymIdentifier) ==
          GNUNET_DISK_file_read (fh, &pi, sizeof (struct GNUNET_PseudonymIdentifier))))
  {
    if (0 == memcmp (&pi, pseudonym, sizeof (struct GNUNET_PseudonymIdentifier)))
    {
      idx = i;
      break;
    }
    i++;
    len -= sizeof (struct GNUNET_HashCode);
  }
  if (-1 == idx)
  {
    idx = i;
    if (sizeof (struct GNUNET_PseudonymIdentifier) !=
        GNUNET_DISK_file_write (fh, pseudonym, sizeof (struct GNUNET_PseudonymIdentifier)))
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "write", fn);
  }
  GNUNET_DISK_file_close (fh);
  ret = GNUNET_malloc (strlen (name) + 32);
  GNUNET_snprintf (ret, strlen (name) + 32, "%s-%u", name, idx);
  if (suffix != NULL)
    *suffix = idx;
  GNUNET_free (fn);
  return ret;
}


/**
 * Get namespace name, metadata and rank
 * This is a wrapper around internal read_info() call, and ensures that
 * returned data is not invalid (not NULL).
 *
 * @param cfg configuration
 * @param pseudonym public key of the pseudonym
 * @param ret_meta a location to store metadata pointer. NULL, if metadata
 *        is not needed. Destroy with GNUNET_CONTAINER_meta_data_destroy().
 * @param ret_rank a location to store rank. NULL, if rank not needed.
 * @param ret_name a location to store human-readable name. Name is not unique.
 *        NULL, if name is not needed. Free with GNUNET_free().
 * @param name_is_a_dup is set to GNUNET_YES, if ret_name was filled with
 *        a duplicate of a "no-name" placeholder
 * @return GNUNET_OK on success. GNUENT_SYSERR if the data was
 *         unobtainable (in that case ret_* are filled with placeholders - 
 *         empty metadata container, rank -1 and a "no-name" name).
 */
int
GNUNET_PSEUDONYM_get_info (const struct GNUNET_CONFIGURATION_Handle *cfg,
			   const struct GNUNET_PseudonymIdentifier *pseudonym, 
			   struct GNUNET_CONTAINER_MetaData **ret_meta,
			   int32_t *ret_rank, 
			   char **ret_name, 
			   int *name_is_a_dup)
{
  struct GNUNET_CONTAINER_MetaData *meta;
  char *name;
  int32_t rank = -1;

  meta = NULL;
  name = NULL;
  if (GNUNET_OK == read_info (cfg, pseudonym, &meta, &rank, &name))
  {
    if ((meta != NULL) && (name == NULL))
      name =
          GNUNET_CONTAINER_meta_data_get_first_by_types (meta,
                                                         EXTRACTOR_METATYPE_TITLE,
                                                         EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME,
                                                         EXTRACTOR_METATYPE_FILENAME,
                                                         EXTRACTOR_METATYPE_DESCRIPTION,
                                                         EXTRACTOR_METATYPE_SUBJECT,
                                                         EXTRACTOR_METATYPE_PUBLISHER,
                                                         EXTRACTOR_METATYPE_AUTHOR_NAME,
                                                         EXTRACTOR_METATYPE_COMMENT,
                                                         EXTRACTOR_METATYPE_SUMMARY,
                                                         -1);
    if (ret_name != NULL)
    {
      if (name == NULL)
      {
        name = GNUNET_strdup (_("no-name"));
        if (name_is_a_dup != NULL)
          *name_is_a_dup = GNUNET_YES;
      }
      else if (name_is_a_dup != NULL)
        *name_is_a_dup = GNUNET_NO;
      *ret_name = name;
    }
    else if (name != NULL)
      GNUNET_free (name);

    if (ret_meta != NULL)
    {
      if (meta == NULL)
        meta = GNUNET_CONTAINER_meta_data_create ();
      *ret_meta = meta;
    }
    else if (meta != NULL)
      GNUNET_CONTAINER_meta_data_destroy (meta);

    if (ret_rank != NULL)
      *ret_rank = rank;

    return GNUNET_OK;
  }
  if (ret_name != NULL)
    *ret_name = GNUNET_strdup (_("no-name"));
  if (ret_meta != NULL)
    *ret_meta = GNUNET_CONTAINER_meta_data_create ();
  if (ret_rank != NULL)
    *ret_rank = -1;
  if (name_is_a_dup != NULL)
    *name_is_a_dup = GNUNET_YES;
  return GNUNET_SYSERR;
}


/**
 * Get the namespace ID belonging to the given namespace name.
 *
 * @param cfg configuration to use
 * @param ns_uname unique (!) human-readable name for the namespace
 * @param pseudonym set to public key of pseudonym based on 'ns_uname'
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_PSEUDONYM_name_to_id (const struct GNUNET_CONFIGURATION_Handle *cfg,
			     const char *ns_uname, 
			     struct GNUNET_PseudonymIdentifier *pseudonym)
{
  size_t slen;
  uint64_t len;
  unsigned int idx;
  char *name;
  struct GNUNET_HashCode nh;
  char *fn;
  struct GNUNET_DISK_FileHandle *fh;

  idx = -1;
  slen = strlen (ns_uname);
  while ((slen > 0) && (1 != SSCANF (&ns_uname[slen - 1], "-%u", &idx)))
    slen--;
  if (0 == slen)
    return GNUNET_SYSERR;
  name = GNUNET_strdup (ns_uname);
  name[slen - 1] = '\0';

  GNUNET_CRYPTO_hash (name, strlen (name), &nh);
  GNUNET_free (name);
  fn = get_data_filename_hash (cfg, PS_NAMES_DIR, &nh);

  if ((GNUNET_OK != GNUNET_DISK_file_test (fn) ||
       (GNUNET_OK != GNUNET_DISK_file_size (fn, &len, GNUNET_YES, GNUNET_YES))) ||
      ((idx + 1) * sizeof (struct GNUNET_PseudonymIdentifier) > len))
  {
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  fh = GNUNET_DISK_file_open (fn,
                              GNUNET_DISK_OPEN_CREATE |
                              GNUNET_DISK_OPEN_READWRITE,
                              GNUNET_DISK_PERM_USER_READ |
                              GNUNET_DISK_PERM_USER_WRITE);
  GNUNET_free (fn);
  if (GNUNET_SYSERR ==
      GNUNET_DISK_file_seek (fh, idx * sizeof (struct GNUNET_PseudonymIdentifier),
			     GNUNET_DISK_SEEK_SET))
  {
    GNUNET_DISK_file_close (fh);
    return GNUNET_SYSERR;
  }
  if (sizeof (struct GNUNET_PseudonymIdentifier) !=
      GNUNET_DISK_file_read (fh, pseudonym, sizeof (struct GNUNET_PseudonymIdentifier)))
  {
    GNUNET_DISK_file_close (fh);
    return GNUNET_SYSERR;
  }
  GNUNET_DISK_file_close (fh);
  return GNUNET_OK;
}



/**
 * struct used to list the pseudonym
 */
struct ListPseudonymClosure
{

  /**
   * iterator over pseudonym
   */
  GNUNET_PSEUDONYM_Iterator iterator;

  /**
   * Closure for iterator.
   */
  void *iterator_cls;

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};



/**
 * Helper function to list all available pseudonyms
 *
 * @param cls point to a struct ListPseudonymClosure
 * @param fullname name of pseudonym
 */
static int
list_pseudonym_helper (void *cls, const char *fullname)
{
  struct ListPseudonymClosure *lpc = cls;
  struct GNUNET_PseudonymIdentifier pd;
  char *emsg;
  struct GNUNET_BIO_ReadHandle *fileR;
  int32_t rank;
  char *ns_name;
  struct GNUNET_CONTAINER_MetaData *meta;
  int ret; 
  char *name_unique;

  if (NULL == (fileR = GNUNET_BIO_read_open (fullname)))
    return GNUNET_SYSERR;
  emsg = NULL;
  ns_name = NULL;
  if ( (GNUNET_OK != GNUNET_BIO_read (fileR, "pseudonym", &pd, sizeof (pd))) ||
       (GNUNET_OK != GNUNET_BIO_read_int32 (fileR, &rank)) ||
       (GNUNET_OK !=
	GNUNET_BIO_read_string (fileR, "Read string error!", &ns_name, 200)) ||
       (GNUNET_OK !=
       GNUNET_BIO_read_meta_data (fileR, "Read meta data error!", &meta)) )
  {
    (void) GNUNET_BIO_read_close (fileR, &emsg);
    GNUNET_free_non_null (emsg);
    GNUNET_free_non_null (ns_name);
    GNUNET_break (GNUNET_OK == GNUNET_DISK_directory_remove (fullname));
    return GNUNET_SYSERR;
  }
  if (NULL == ns_name)
    ns_name = GNUNET_strdup (_("no-name"));
  if (GNUNET_OK != GNUNET_BIO_read_close (fileR, &emsg))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Failed to parse metadata about pseudonym from file `%s': %s\n"), fullname,
         emsg);
    GNUNET_break (GNUNET_OK == GNUNET_DISK_directory_remove (fullname));
    GNUNET_CONTAINER_meta_data_destroy (meta);
    GNUNET_free (ns_name);
    GNUNET_free_non_null (emsg);
    return GNUNET_SYSERR;
  }
  ret = GNUNET_OK;
  name_unique = GNUNET_PSEUDONYM_name_uniquify (lpc->cfg, &pd, ns_name, NULL);
  if (NULL != lpc->iterator)
    ret = lpc->iterator (lpc->iterator_cls, &pd, ns_name, name_unique, meta, rank);
  GNUNET_free (ns_name);
  GNUNET_free_non_null (name_unique);
  GNUNET_CONTAINER_meta_data_destroy (meta);
  return ret;
}


/**
 * List all available pseudonyms.
 *
 * @param cfg overall configuration
 * @param iterator function to call for each pseudonym
 * @param iterator_cls closure for iterator
 * @return number of pseudonyms found
 */
int
GNUNET_PSEUDONYM_list_all (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           GNUNET_PSEUDONYM_Iterator iterator, 
			   void *iterator_cls)
{
  struct ListPseudonymClosure cls;
  char *fn;
  int ret;

  cls.iterator = iterator;
  cls.iterator_cls = iterator_cls;
  cls.cfg = cfg;
  fn = get_data_filename (cfg, PS_METADATA_DIR, NULL);
  GNUNET_assert (fn != NULL);
  GNUNET_DISK_directory_create (fn);
  ret = GNUNET_DISK_directory_scan (fn, &list_pseudonym_helper, &cls);
  GNUNET_free (fn);
  return ret;
}


/**
 * Change the rank of a pseudonym.
 *
 * @param cfg overall configuration
 * @param pseudonym the pseudonym
 * @param delta by how much should the rating be changed?
 * @return new rating of the pseudonym
 */
int
GNUNET_PSEUDONYM_rank (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       const struct GNUNET_PseudonymIdentifier *pseudonym, 
		       int32_t delta)
{
  struct GNUNET_CONTAINER_MetaData *meta;
  int ret;
  int32_t rank;
  char *name;

  name = NULL;
  ret = read_info (cfg, pseudonym, &meta, &rank, &name);
  if (ret == GNUNET_SYSERR)
  {
    rank = 0;
    meta = GNUNET_CONTAINER_meta_data_create ();
  }
  rank += delta;
  GNUNET_PSEUDONYM_set_info (cfg, pseudonym, name, meta, rank);
  GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_free_non_null (name);
  return rank;
}


/**
 * Add a pseudonym to the set of known pseudonyms.
 * For all pseudonym advertisements that we discover
 * FS should automatically call this function.
 *
 * @param cfg overall configuration
 * @param pseudonym the pseudonym to add
 * @param meta metadata for the pseudonym
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_PSEUDONYM_add (const struct GNUNET_CONFIGURATION_Handle *cfg,
                      const struct GNUNET_PseudonymIdentifier *pseudonym,
                      const struct GNUNET_CONTAINER_MetaData *meta)
{
  char *name;
  int32_t rank;
  struct GNUNET_CONTAINER_MetaData *old;
  char *fn;
  struct stat sbuf;
  int ret;

  rank = 0;
  fn = get_data_filename (cfg, PS_METADATA_DIR, pseudonym);
  GNUNET_assert (fn != NULL);

  if ((0 == STAT (fn, &sbuf)) &&
      (GNUNET_OK == read_info (cfg, pseudonym, &old, &rank, &name)))
  {
    GNUNET_CONTAINER_meta_data_merge (old, meta);
    ret = GNUNET_PSEUDONYM_set_info (cfg, pseudonym, name, old, rank);
    GNUNET_CONTAINER_meta_data_destroy (old);
    GNUNET_free_non_null (name);
  }
  else
  {
    ret = GNUNET_PSEUDONYM_set_info (cfg, pseudonym, NULL, meta, rank);
  }
  GNUNET_free (fn);
  internal_notify (pseudonym, meta, rank);
  return ret;
}


/* ***************************** cryptographic operations ************************* */

/**
 * Handle for a pseudonym (private key).
 */
struct GNUNET_PseudonymHandle
{
  /**
   * 256-bit 'd' secret value (mod 'n', where n is 256-bit for NIST P-256).
   */
  unsigned char d[256 / 8];

  /**
   * Public key corresponding to the private key.
   */
  struct GNUNET_PseudonymIdentifier public_key;
};


/**
 * If target != size, move target bytes to the end of the size-sized
 * buffer and zero out the first target-size bytes.
 *
 * @param buf original buffer
 * @param size number of bytes in the buffer
 * @param target target size of the buffer
 */
static void
adjust (unsigned char *buf, size_t size, size_t target)
{
  if (size < target)
  {
    memmove (&buf[target - size], buf, size);
    memset (buf, 0, target - size);
  }
}


/**
 * Extract values from an S-expression.
 *
 * @param array where to store the result(s)
 * @param sexp S-expression to parse
 * @param topname top-level name in the S-expression that is of interest
 * @param elems names of the elements to extract
 * @return 0 on success
 */
static int
key_from_sexp (gcry_mpi_t * array, gcry_sexp_t sexp, const char *topname,
               const char *elems)
{
  gcry_sexp_t list;
  gcry_sexp_t l2;
  const char *s;
  unsigned int i;
  unsigned int idx;

  if (! (list = gcry_sexp_find_token (sexp, topname, 0)))
    return 1;  
  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  if (! list)  
    return 2;
  idx = 0;
  for (s = elems; *s; s++, idx++)
  {
    if (! (l2 = gcry_sexp_find_token (list, s, 1)))
    {
      for (i = 0; i < idx; i++)
      {
        gcry_free (array[i]);
        array[i] = NULL;
      }
      gcry_sexp_release (list);
      return 3;                 /* required parameter not found */
    }
    array[idx] = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release (l2);
    if (! array[idx])
    {
      for (i = 0; i < idx; i++)
      {
        gcry_free (array[i]);
        array[i] = NULL;
      }
      gcry_sexp_release (list);
      return 4;                 /* required parameter is invalid */
    }
  }
  gcry_sexp_release (list);
  return 0;
}


/**
 * Create a pseudonym.
 *
 * @param filename name of the file to use for storage, NULL for in-memory only
 * @return handle to the private key of the pseudonym
 */
struct GNUNET_PseudonymHandle *
GNUNET_PSEUDONYM_create (const char *filename)
{
  struct GNUNET_PseudonymHandle *ph;
  ssize_t ret;
  gcry_sexp_t r_key;
  gcry_sexp_t params;
  gcry_error_t rc;
  gcry_mpi_t skey[2];
  size_t size;

  ph = GNUNET_malloc (sizeof (struct GNUNET_PseudonymHandle));
  if ( (NULL != filename) &&
       (GNUNET_YES == GNUNET_DISK_file_test (filename)) )
  {
    ret = GNUNET_DISK_fn_read (filename, ph, 
			       sizeof (struct GNUNET_PseudonymHandle));
    /* Note: we don't do any validation here, maybe we should? */
    if (sizeof (struct GNUNET_PseudonymHandle) == ret)
      return ph;
  }  
  if (0 != (rc = gcry_sexp_build (&params, NULL,
                                  "(genkey(ecdsa(curve \"NIST P-256\")))")))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return NULL;
  }
  if (0 != (rc = gcry_pk_genkey (&r_key, params)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return NULL;
  }
  /* NOTE: treating a point as a normal MPI value; hopefully that works... */
  rc = key_from_sexp (skey, r_key, "private-key", "dq");
  if (0 != rc)
    rc = key_from_sexp (skey, r_key, "private-key", "dq");
  if (0 != rc)
    rc = key_from_sexp (skey, r_key, "ecc", "dq");
  gcry_sexp_release (r_key);
  size = sizeof (ph->d);
  GNUNET_assert (0 ==
                 gcry_mpi_print (GCRYMPI_FMT_USG, ph->d, size, &size,
                                 skey[0]));
  adjust (ph->d, size, sizeof (ph->d));
  size = sizeof (ph->public_key.q);  
  GNUNET_assert (0 ==
                 gcry_mpi_print (GCRYMPI_FMT_USG, ph->public_key.q, size, &size,
                                 skey[1]));
  adjust (ph->public_key.q, size, sizeof (ph->public_key.q));
  gcry_mpi_release (skey[0]);
  gcry_mpi_release (skey[1]);
  if (NULL != filename)
  {
    ret = GNUNET_DISK_fn_write (filename, ph, sizeof (struct GNUNET_PseudonymHandle),
				GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
    if (sizeof (struct GNUNET_PseudonymHandle) != ret)
    {
      GNUNET_free (ph);
      return NULL;
    }
  }
  return ph;
}


/**
 * Create a pseudonym, from a file that must already exist.
 *
 * @param filename name of the file to use for storage, NULL for in-memory only
 * @return handle to the private key of the pseudonym
 */
struct GNUNET_PseudonymHandle *
GNUNET_PSEUDONYM_create_from_existing_file (const char *filename)
{
  struct GNUNET_PseudonymHandle *ph;
  ssize_t ret;

  ph = GNUNET_malloc (sizeof (struct GNUNET_PseudonymHandle));
  ret = GNUNET_DISK_fn_read (filename, ph, 
			     sizeof (struct GNUNET_PseudonymHandle));
  if (sizeof (struct GNUNET_PseudonymHandle) != ret)
  {
    GNUNET_free (ph);
    return NULL;
  }
  /* Note: we don't do any validation here; maybe we should? */
  return ph;
}


/**
 * Get the handle for the 'anonymous' pseudonym shared by all users.
 * That pseudonym uses a fixed 'secret' for the private key; this
 * construction is useful to make anonymous and pseudonymous APIs
 * (and packets) indistinguishable on the network.  See #2564.
 *
 * @return handle to the (non-secret) private key of the 'anonymous' pseudonym
 */
struct GNUNET_PseudonymHandle *
GNUNET_PSEUDONYM_get_anonymous_pseudonym_handle ()
{
  struct GNUNET_PseudonymHandle *ph;

  ph = GNUNET_malloc (sizeof (struct GNUNET_PseudonymHandle));
  /* FIXME: if we use 'd=0' for the anonymous handle (as per#2564),
     then I believe the public key should be also zero, as Q=0P=0.
     However, libgcrypt's point representation is completely internal,
     and treats a z-coordinate of zero as infinity, so we likely need
     to set it to (0,0,1) internally --- or actually calculate Q=qP
     explicitly.  Either way, we don't have an API to do so yet :-(.
  */
  GNUNET_break (0);
  return ph;
}


/**
 * Destroy a pseudonym handle.  Does NOT remove the private key from
 * the disk.
 *
 * @param ph pseudonym handle to destroy
 */
void
GNUNET_PSEUDONYM_destroy (struct GNUNET_PseudonymHandle *ph)
{
  GNUNET_free (ph);
}


/**
 * Convert the data specified in the given purpose argument to an
 * S-expression suitable for signature operations.
 *
 * @param purpose data to convert
 * @return converted s-expression
 */
static gcry_sexp_t
data_to_pkcs1 (const struct GNUNET_PseudonymSignaturePurpose *purpose)
{
  struct GNUNET_CRYPTO_ShortHashCode hc;
  size_t bufSize;
  gcry_sexp_t data;

  GNUNET_CRYPTO_short_hash (purpose, ntohl (purpose->size), &hc);
#define FORMATSTRING "(4:data(5:flags3:raw)(5:value32:01234567890123456789012345678901))"
  bufSize = strlen (FORMATSTRING) + 1;
  {
    char buff[bufSize];

    memcpy (buff, FORMATSTRING, bufSize);
    memcpy (&buff
	    [bufSize -
	     strlen
	     ("01234567890123456789012345678901))")
	     - 1], &hc, sizeof (struct GNUNET_CRYPTO_ShortHashCode));
    GNUNET_assert (0 == gcry_sexp_new (&data, buff, bufSize, 0));
  }
#undef FORMATSTRING
  return data;
}


/**
 * Cryptographically sign some data with the pseudonym.
 *
 * @param ph private key used for signing (corresponds to 'x' in #2564)
 * @param purpose data to sign
 * @param seed hash of the plaintext of the data that we are signing, 
 *             used for deterministic PRNG for anonymous signing;
 *             corresponds to 'k' in section 2.7 of #2564
 * @param signing_key modifier to apply to the private key for signing;
 *                    corresponds to 'h' in section 2.3 of #2564.
 * @param signature where to store the signature
 * @return GNUNET_SYSERR on failure
 */
int 
GNUNET_PSEUDONYM_sign (struct GNUNET_PseudonymHandle *ph,
		       const struct GNUNET_PseudonymSignaturePurpose *purpose,
		       const struct GNUNET_HashCode *seed,
		       const struct GNUNET_HashCode *signing_key,
		       struct GNUNET_PseudonymSignature *signature)
{
  size_t size;
  size_t erroff;
  gcry_mpi_t x;
  gcry_mpi_t k;
  gcry_mpi_t h;
  gcry_mpi_t d;
  gcry_mpi_t n; /* n from P-256 */
  gcry_sexp_t spriv;
  gcry_sexp_t data;
  gcry_sexp_t result;
  gcry_mpi_t rs[2];
  int rc;

  /* get private key 'x' from pseudonym */
  size = sizeof (ph->d);
  if (0 != (rc = gcry_mpi_scan (&x, GCRYMPI_FMT_USG,
				&ph->d,
				size, &size)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    return GNUNET_SYSERR;
  }
  /* get 'h' value from signing key */
  size = sizeof (struct GNUNET_HashCode);
  if (0 != (rc = gcry_mpi_scan (&h, GCRYMPI_FMT_USG,
				signing_key,
				size, &size)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    gcry_mpi_release (x);
    return GNUNET_SYSERR;
  } 
  
  /* initialize 'n' from P-256; hex copied from libgcrypt code */
  if (0 != (rc = gcry_mpi_scan (&n, GCRYMPI_FMT_HEX, 
				"0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 0, NULL)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    gcry_mpi_release (x);
    gcry_mpi_release (h);
    return GNUNET_SYSERR;
  }

  /* calculate d = x + h mod n */
  d = gcry_mpi_new (256);
  gcry_mpi_addm (d, x, h, n);
  gcry_mpi_release (x);
  gcry_mpi_release (h);
  gcry_mpi_release (n);
  
  /* now build sexpression with the signing key;
     NOTE: libgcrypt docs say that we should specify 'Q', but
     with the current API we cannot calculate Q=dP, so hopefully
     libgcrypt will derive it from 'd' for us... */
  if (0 != (rc = gcry_sexp_build (&spriv, &erroff,
				  "(private-key(ecc(curve \"NIST P-256\")(d %m)))",
				  d)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    gcry_mpi_release (d);
    return GNUNET_SYSERR;
  }
  gcry_mpi_release (d);
  /* prepare data for signing */
  data = data_to_pkcs1 (purpose);
  
  /* get 'k' value from seed, if available */
  if (NULL != seed)
  {
    size = sizeof (struct GNUNET_HashCode);
    if (0 != (rc = gcry_mpi_scan (&k, GCRYMPI_FMT_USG,
				  seed,
				  size, &size)))
    {
      LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
      gcry_mpi_release (x);
      return GNUNET_SYSERR;
    }
  }

  /* actually create signature */
  /* FIXME: need API to pass 'k' if 'seed' was non-NULL! */
  if (0 != (rc = gcry_pk_sign (&result, data, spriv)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("ECC signing failed at %s:%d: %s\n"), __FILE__,
         __LINE__, gcry_strerror (rc));
    gcry_sexp_release (data);
    gcry_sexp_release (spriv);
    if (NULL != seed)
      gcry_mpi_release (k);
    memset (signature, 0, sizeof (struct GNUNET_PseudonymSignature));
    return GNUNET_SYSERR;
  }
  if (NULL != seed)
    gcry_mpi_release (k);
  gcry_sexp_release (data);
  gcry_sexp_release (spriv);

  /* extract 'r' and 's' values from sexpression 'result' and store in 'signature';
     FIXME: libgcrypt does not document format of s-expression returned for ECC
     signatures; so "ecc" here is just a guess. */
  if (0 != (rc = key_from_sexp (rs, result, "ecc", "rs")))
  {
    GNUNET_break (0);
    gcry_sexp_release (result);
    return GNUNET_SYSERR;
  }
  gcry_sexp_release (result);
  size = sizeof (signature->sig_r);
  if (0 != (rc = gcry_mpi_print (GCRYMPI_FMT_USG, (unsigned char *) signature->sig_r, size,
                                 &size, rs[0])))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_print", rc);
    gcry_mpi_release (rs[0]);
    gcry_mpi_release (rs[1]);
    return GNUNET_SYSERR;
  }
  gcry_mpi_release (rs[0]);
  size = sizeof (signature->sig_s);
  if (0 != (rc = gcry_mpi_print (GCRYMPI_FMT_USG, (unsigned char *) signature->sig_s, size,
                                 &size, rs[1])))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_print", rc);
    gcry_mpi_release (rs[1]);
    return GNUNET_SYSERR;
  }
  gcry_mpi_release (rs[1]);
  return GNUNET_OK;
}


/**
 * Given a pseudonym and a signing key, derive the corresponding public
 * key that would be used to verify the resulting signature.
 *
 * @param pseudonym the public key (g^x in DSA, dQ in ECDSA)
 * @param signing_key input to derive 'h' (see section 2.4 of #2564)
 * @param verification_key resulting public key to verify the signature
 *        created from the 'ph' of 'pseudonym' and the 'signing_key';
 *        the value stored here can then be given to GNUNET_PSEUDONYM_verify.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_PSEUDONYM_derive_verification_key (struct GNUNET_PseudonymIdentifier *pseudonym,
					  const struct GNUNET_HashCode *signing_key,
					  struct GNUNET_PseudonymIdentifier *verification_key)
{
  struct GNUNET_HashCode hc;
  struct GNUNET_HashCode x;
  gcry_mpi_t h;  
  size_t size;
  int rc;

  /* get 'h' value from signing key */
  size = sizeof (struct GNUNET_HashCode);
  if (0 != (rc = gcry_mpi_scan (&h, GCRYMPI_FMT_USG,
				signing_key,
				size, &size)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    return GNUNET_SYSERR;
  }
  /* FIXME: calculate hQ --- need point multiplication API! */
  gcry_mpi_release (h);
  /* FIXME: calculate V = dQ + hQ --- need point addition API! */
  
  GNUNET_break (0);
  GNUNET_CRYPTO_hash (pseudonym, sizeof (*pseudonym), &hc);
  GNUNET_CRYPTO_hash_xor (&hc, signing_key, &x);  
  memset (verification_key, 0, sizeof (struct GNUNET_PseudonymIdentifier));
  memcpy (verification_key, &x, GNUNET_MIN (sizeof (x), sizeof (*verification_key)));
  return GNUNET_OK;
}


/**
 * Verify a signature made with a pseudonym.
 *
 * @param purpose data that was signed
 * @param signature signature to verify
 * @param verification_key public key to use for checking the signature;
 *                    corresponds to 'g^(x+h)' in section 2.4 of #2564.
 * @return GNUNET_OK on success (signature valid, 'pseudonym' set),
 *         GNUNET_SYSERR if the signature is invalid
 */
int
GNUNET_PSEUDONYM_verify (const struct GNUNET_PseudonymSignaturePurpose *purpose,
			 const struct GNUNET_PseudonymSignature *signature,
			 const struct GNUNET_PseudonymIdentifier *verification_key)
{
#if FUTURE
  gcry_sexp_t data;
  gcry_sexp_t sig_sexpr;
  gcry_sexp_t pk_sexpr;
  size_t size;
  gcry_mpi_t r;
  gcry_mpi_t s;
  gcry_mpi_t q;
  size_t erroff;
  int rc;

  /* build s-expression for signature */
  size = sizeof (signature->sig_r);
  if (0 != (rc = gcry_mpi_scan (&r, GCRYMPI_FMT_USG,
                                signature->sig_r, size, &size)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    return GNUNET_SYSERR;
  }
  size = sizeof (signature->sig_s);
  if (0 != (rc = gcry_mpi_scan (&s, GCRYMPI_FMT_USG,
                                signature->sig_s, size, &size)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    gcry_mpi_release (r);
    return GNUNET_SYSERR;
  }
  if (0 != (rc = gcry_sexp_build (&sig_sexpr, &erroff, "(sig-val(ecc(r %m)(s %m)))",
                                  r, s)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    gcry_mpi_release (r);
    gcry_mpi_release (s);
    return GNUNET_SYSERR;
  }
  gcry_mpi_release (r);
  gcry_mpi_release (s);

  /* build s-expression for data that was signed */
  data = data_to_pkcs1 (purpose);

  /* build s-expression for public key */
  /* NOTE: treating a point as a normal MPI value; hopefully that works... */
  size = sizeof (verification_key->q);
  if (0 != (rc = gcry_mpi_scan (&q, GCRYMPI_FMT_USG,
                                verification_key->q, size, &size)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    gcry_sexp_release (data);
    gcry_sexp_release (sig_sexpr);
    return GNUNET_SYSERR;
  }
  if (0 != (rc = gcry_sexp_build (&sig_sexpr, &erroff, "(public-key(ecc(curve \"NIST P-256\")(q %m)))",
                                  q)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    gcry_mpi_release (q);
    gcry_sexp_release (data);
    gcry_sexp_release (sig_sexpr);
    return GNUNET_SYSERR;
  }
  gcry_mpi_release (q);

  /* finally, verify the signature */
  rc = gcry_pk_verify (sig_sexpr, data, pk_sexpr);
  gcry_sexp_release (sig_sexpr);
  gcry_sexp_release (data);
  gcry_sexp_release (pk_sexpr);
  if (rc)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("RSA signature verification failed at %s:%d: %s\n"), __FILE__,
         __LINE__, gcry_strerror (rc));
    return GNUNET_SYSERR;
  }
#else
  GNUNET_break (0);
#endif
  return GNUNET_OK;
}


/**
 * Get the identifier (public key) of a pseudonym.
 *
 * @param ph pseudonym handle with the private key
 * @param pseudonym pseudonym identifier (set based on 'ph')
 */
void
GNUNET_PSEUDONYM_get_identifier (struct GNUNET_PseudonymHandle *ph,
				 struct GNUNET_PseudonymIdentifier *pseudonym)
{
  memcpy (pseudonym, &ph->public_key,
	  sizeof (struct GNUNET_PseudonymIdentifier));
}


/**
 * Remove pseudonym from the set of known pseudonyms.
 *
 * @param cfg overall configuration
 * @param id the pseudonym identifier
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_PSEUDONYM_remove (const struct GNUNET_CONFIGURATION_Handle *cfg,
			 const struct GNUNET_PseudonymIdentifier *id)
{
  char *fn;
  int result;

  fn = get_data_filename (cfg, PS_METADATA_DIR, id);
  if (NULL == fn)
    return GNUNET_SYSERR;
  result = UNLINK (fn);
  GNUNET_free (fn);  
  return (0 == result) ? GNUNET_OK : GNUNET_SYSERR;
}

/* end of pseudonym.c */
