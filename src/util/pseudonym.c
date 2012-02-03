/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_container_lib.h"
#include "gnunet_disk_lib.h"
#include "gnunet_pseudonym_lib.h"
#include "gnunet_bio_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

/**
 * Name of the directory which stores meta data for pseudonym
 */
#define PS_METADATA_DIR DIR_SEPARATOR_STR "data" DIR_SEPARATOR_STR "pseudonyms" DIR_SEPARATOR_STR "metadata" DIR_SEPARATOR_STR

/**
 * Name of the directory which stores names for pseudonyms
 */
#define PS_NAMES_DIR    DIR_SEPARATOR_STR "data" DIR_SEPARATOR_STR "pseudonyms" DIR_SEPARATOR_STR "names"    DIR_SEPARATOR_STR


/**
 * Configuration section we use.
 */
#define GNUNET_CLIENT_SERVICE_NAME "client"



/**
 * Registered callbacks for discovery of pseudonyms.
 */
struct DiscoveryCallback
{
  /**
   * This is a linked list.
   */
  struct DiscoveryCallback *next;

  /**
   * Function to call each time a pseudonym is discovered.
   */
  GNUNET_PSEUDONYM_Iterator callback;

  /**
   * Closure for callback.
   */
  void *closure;
};


/**
 * Head of the linked list of functions to call when
 * new pseudonyms are added.
 */
static struct DiscoveryCallback *head;

/**
 * Internal notification about new tracked URI.
 * @param id a point to the hash code of pseudonym
 * @param md meta data to be written
 * @param rating rating of pseudonym
 */
static void
internal_notify (const GNUNET_HashCode * id,
                 const struct GNUNET_CONTAINER_MetaData *md, int rating)
{
  struct DiscoveryCallback *pos;

  pos = head;
  while (pos != NULL)
  {
    pos->callback (pos->closure, id, md, rating);
    pos = pos->next;
  }
}

/**
 * Register callback to be invoked whenever we discover
 * a new pseudonym.
 * @param cfg configuration to use
 * @param iterator iterator over pseudonym
 * @param closure point to a closure
 */
int
GNUNET_PSEUDONYM_discovery_callback_register (const struct
                                              GNUNET_CONFIGURATION_Handle *cfg,
                                              GNUNET_PSEUDONYM_Iterator
                                              iterator, void *closure)
{
  struct DiscoveryCallback *list;

  list = GNUNET_malloc (sizeof (struct DiscoveryCallback));
  list->callback = iterator;
  list->closure = closure;
  list->next = head;
  head = list;
  GNUNET_PSEUDONYM_list_all (cfg, iterator, closure);
  return GNUNET_OK;
}

/**
 * Unregister pseudonym discovery callback.
 * @param iterator iterator over pseudonym
 * @param closure point to a closure
 */
int
GNUNET_PSEUDONYM_discovery_callback_unregister (GNUNET_PSEUDONYM_Iterator
                                                iterator, void *closure)
{
  struct DiscoveryCallback *prev;
  struct DiscoveryCallback *pos;

  prev = NULL;
  pos = head;
  while ((pos != NULL) &&
         ((pos->callback != iterator) || (pos->closure != closure)))
  {
    prev = pos;
    pos = pos->next;
  }
  if (pos == NULL)
    return GNUNET_SYSERR;
  if (prev == NULL)
    head = pos->next;
  else
    prev->next = pos->next;
  GNUNET_free (pos);
  return GNUNET_OK;
}


/**
 * Get the filename (or directory name) for the given
 * pseudonym identifier and directory prefix.
 * @param cfg configuration to use
 * @param prefix path components to append to the private directory name
 * @param psid hash code of pseudonym, can be NULL
 * @return filename of the pseudonym (if psid != NULL) or directory with the data (if psid == NULL)
 */
static char *
get_data_filename (const struct GNUNET_CONFIGURATION_Handle *cfg,
                   const char *prefix, const GNUNET_HashCode * psid)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;

  if (psid != NULL)
    GNUNET_CRYPTO_hash_to_enc (psid, &enc);
  return GNUNET_DISK_get_home_filename (cfg, GNUNET_CLIENT_SERVICE_NAME, prefix,
                                        (psid ==
                                         NULL) ? NULL : (const char *) &enc,
                                        NULL);
}


/**
 * Write the pseudonym infomation into a file
 * @param cfg configuration to use
 * @param nsid hash code of a pseudonym
 * @param meta meta data to be written into a file
 * @param ranking ranking of a pseudonym
 * @param ns_name name of a pseudonym
 */
static void
write_pseudonym_info (const struct GNUNET_CONFIGURATION_Handle *cfg,
                      const GNUNET_HashCode * nsid,
                      const struct GNUNET_CONTAINER_MetaData *meta,
                      int32_t ranking, const char *ns_name)
{
  char *fn;
  struct GNUNET_BIO_WriteHandle *fileW;

  fn = get_data_filename (cfg, PS_METADATA_DIR, nsid);
  GNUNET_assert (fn != NULL);
  fileW = GNUNET_BIO_write_open (fn);
  if (NULL != fileW)
  {
    if ((GNUNET_OK != GNUNET_BIO_write_int32 (fileW, ranking)) ||
        (GNUNET_OK != GNUNET_BIO_write_string (fileW, ns_name)) ||
        (GNUNET_OK != GNUNET_BIO_write_meta_data (fileW, meta)))
    {
      (void) GNUNET_BIO_write_close (fileW);
      GNUNET_break (GNUNET_OK == GNUNET_DISK_directory_remove (fn));
      GNUNET_free (fn);
      return;
    }
    if (GNUNET_OK != GNUNET_BIO_write_close (fileW))
    {
      GNUNET_break (GNUNET_OK == GNUNET_DISK_directory_remove (fn));
      GNUNET_free (fn);
      return;
    }
  }
  GNUNET_free (fn);
  /* create entry for pseudonym name in names */
  /* FIXME: 90% of what this call does is not needed
   * here => refactor code to only create the entry! */
  GNUNET_free_non_null (GNUNET_PSEUDONYM_id_to_name (cfg, nsid));
}


/**
 * read the pseudonym infomation from a file
 * @param cfg configuration to use
 * @param nsid hash code of a pseudonym
 * @param meta meta data to be read from a file
 * @param ranking ranking of a pseudonym
 * @param ns_name name of a pseudonym
 */
static int
read_info (const struct GNUNET_CONFIGURATION_Handle *cfg,
           const GNUNET_HashCode * nsid,
           struct GNUNET_CONTAINER_MetaData **meta, int32_t * ranking,
           char **ns_name)
{
  char *fn;
  char *emsg;
  struct GNUNET_BIO_ReadHandle *fileR;

  fn = get_data_filename (cfg, PS_METADATA_DIR, nsid);
  GNUNET_assert (fn != NULL);
  fileR = GNUNET_BIO_read_open (fn);
  if (fileR == NULL)
  {
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  emsg = NULL;
  *ns_name = NULL;
  if ((GNUNET_OK != GNUNET_BIO_read_int32 (fileR, ranking)) ||
      (GNUNET_OK !=
       GNUNET_BIO_read_string (fileR, "Read string error!", ns_name, 200)) ||
      (GNUNET_OK !=
       GNUNET_BIO_read_meta_data (fileR, "Read meta data error!", meta)))
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
 * Return the unique, human readable name for the given namespace.
 *
 * @param cfg configuration
 * @param nsid cryptographic ID of the namespace
 * @return NULL on failure (should never happen)
 */
char *
GNUNET_PSEUDONYM_id_to_name (const struct GNUNET_CONFIGURATION_Handle *cfg,
                             const GNUNET_HashCode * nsid)
{
  struct GNUNET_CONTAINER_MetaData *meta;
  char *name;
  GNUNET_HashCode nh;
  char *fn;
  uint64_t len;
  struct GNUNET_DISK_FileHandle *fh;
  unsigned int i;
  unsigned int idx;
  char *ret;
  struct stat sbuf;
  int32_t temp = 0;
  int32_t *rank = &temp;

  meta = NULL;
  name = NULL;
  if (GNUNET_OK == read_info (cfg, nsid, &meta, rank, &name))
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
    if (meta != NULL)
    {
      GNUNET_CONTAINER_meta_data_destroy (meta);
      meta = NULL;
    }
  }
  if (name == NULL)
    name = GNUNET_strdup (_("no-name"));
  GNUNET_CRYPTO_hash (name, strlen (name), &nh);
  fn = get_data_filename (cfg, PS_NAMES_DIR, &nh);
  GNUNET_assert (fn != NULL);

  len = 0;
  if (0 == STAT (fn, &sbuf))
    GNUNET_DISK_file_size (fn, &len, GNUNET_YES);
  fh = GNUNET_DISK_file_open (fn,
                              GNUNET_DISK_OPEN_CREATE |
                              GNUNET_DISK_OPEN_READWRITE,
                              GNUNET_DISK_PERM_USER_READ |
                              GNUNET_DISK_PERM_USER_WRITE);
  i = 0;
  idx = -1;
  while ((len >= sizeof (GNUNET_HashCode)) &&
         (sizeof (GNUNET_HashCode) ==
          GNUNET_DISK_file_read (fh, &nh, sizeof (GNUNET_HashCode))))
  {
    if (0 == memcmp (&nh, nsid, sizeof (GNUNET_HashCode)))
    {
      idx = i;
      break;
    }
    i++;
    len -= sizeof (GNUNET_HashCode);
  }
  if (idx == -1)
  {
    idx = i;
    if (sizeof (GNUNET_HashCode) !=
        GNUNET_DISK_file_write (fh, nsid, sizeof (GNUNET_HashCode)))
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "write", fn);
  }
  GNUNET_DISK_file_close (fh);
  ret = GNUNET_malloc (strlen (name) + 32);
  GNUNET_snprintf (ret, strlen (name) + 32, "%s-%u", name, idx);
  GNUNET_free (name);
  GNUNET_free (fn);
  return ret;
}

/**
 * Get the namespace ID belonging to the given namespace name.
 *
 * @param cfg configuration to use
 * @param ns_uname human-readable name for the namespace
 * @param nsid set to namespace ID based on 'ns_uname'
 * @return GNUNET_OK on success
 */
int
GNUNET_PSEUDONYM_name_to_id (const struct GNUNET_CONFIGURATION_Handle *cfg,
                             const char *ns_uname, GNUNET_HashCode * nsid)
{
  size_t slen;
  uint64_t len;
  unsigned int idx;
  char *name;
  GNUNET_HashCode nh;
  char *fn;
  struct GNUNET_DISK_FileHandle *fh;

  idx = -1;
  slen = strlen (ns_uname);
  while ((slen > 0) && (1 != sscanf (&ns_uname[slen - 1], "-%u", &idx)))
    slen--;
  if (slen == 0)
    return GNUNET_SYSERR;
  name = GNUNET_strdup (ns_uname);
  name[slen - 1] = '\0';
  GNUNET_CRYPTO_hash (name, strlen (name), &nh);
  GNUNET_free (name);
  fn = get_data_filename (cfg, PS_NAMES_DIR, &nh);
  GNUNET_assert (fn != NULL);

  if ((GNUNET_OK != GNUNET_DISK_file_test (fn) ||
       (GNUNET_OK != GNUNET_DISK_file_size (fn, &len, GNUNET_YES))) ||
      ((idx + 1) * sizeof (GNUNET_HashCode) > len))
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
  GNUNET_DISK_file_seek (fh, idx * sizeof (GNUNET_HashCode),
                         GNUNET_DISK_SEEK_SET);
  if (sizeof (GNUNET_HashCode) !=
      GNUNET_DISK_file_read (fh, nsid, sizeof (GNUNET_HashCode)))
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
  void *closure;

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};



/**
 * the help function to list all available pseudonyms
 * @param cls point to a struct ListPseudonymClosure
 * @param fullname name of pseudonym
 */
static int
list_pseudonym_helper (void *cls, const char *fullname)
{
  struct ListPseudonymClosure *c = cls;
  int ret;
  GNUNET_HashCode id;
  int rating;
  struct GNUNET_CONTAINER_MetaData *meta;
  const char *fn;
  char *str;

  if (strlen (fullname) < sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded))
    return GNUNET_OK;
  fn = &fullname[strlen (fullname) + 1 -
                 sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded)];
  if (fn[-1] != DIR_SEPARATOR)
    return GNUNET_OK;
  ret = GNUNET_OK;
  if (GNUNET_OK != GNUNET_CRYPTO_hash_from_string (fn, &id))
    return GNUNET_OK;           /* invalid name */
  str = NULL;
  if (GNUNET_OK != read_info (c->cfg, &id, &meta, &rating, &str))
    return GNUNET_OK;           /* ignore entry */
  GNUNET_free_non_null (str);
  if (c->iterator != NULL)
    ret = c->iterator (c->closure, &id, meta, rating);
  GNUNET_CONTAINER_meta_data_destroy (meta);
  return ret;
}


/**
 * List all available pseudonyms.
 *
 * @param cfg overall configuration
 * @param iterator function to call for each pseudonym
 * @param closure closure for iterator
 * @return number of pseudonyms found
 */
int
GNUNET_PSEUDONYM_list_all (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           GNUNET_PSEUDONYM_Iterator iterator, void *closure)
{
  struct ListPseudonymClosure cls;
  char *fn;
  int ret;

  cls.iterator = iterator;
  cls.closure = closure;
  cls.cfg = cfg;
  fn = get_data_filename (cfg, PS_METADATA_DIR, NULL);
  GNUNET_assert (fn != NULL);
  GNUNET_DISK_directory_create (fn);
  ret = GNUNET_DISK_directory_scan (fn, &list_pseudonym_helper, &cls);
  GNUNET_free (fn);
  return ret;
}


/**
 * Change the ranking of a pseudonym.
 *
 * @param cfg overall configuration
 * @param nsid id of the pseudonym
 * @param delta by how much should the rating be
 *  changed?
 * @return new rating of the pseudonym
 */
int
GNUNET_PSEUDONYM_rank (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       const GNUNET_HashCode * nsid, int delta)
{
  struct GNUNET_CONTAINER_MetaData *meta;
  int ret;
  int32_t ranking;
  char *name;

  name = NULL;
  ret = read_info (cfg, nsid, &meta, &ranking, &name);
  if (ret == GNUNET_SYSERR)
  {
    ranking = 0;
    meta = GNUNET_CONTAINER_meta_data_create ();
  }
  ranking += delta;
  write_pseudonym_info (cfg, nsid, meta, ranking, name);
  GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_free_non_null (name);
  return ranking;
}


/**
 * Add a pseudonym to the set of known pseudonyms.
 * For all pseudonym advertisements that we discover
 * FS should automatically call this function.
 *
 * @param cfg overall configuration
 * @param id the pseudonym identifier
 * @param meta metadata for the pseudonym
 */
void
GNUNET_PSEUDONYM_add (const struct GNUNET_CONFIGURATION_Handle *cfg,
                      const GNUNET_HashCode * id,
                      const struct GNUNET_CONTAINER_MetaData *meta)
{
  char *name;
  int32_t ranking;
  struct GNUNET_CONTAINER_MetaData *old;
  char *fn;
  struct stat sbuf;

  ranking = 0;
  fn = get_data_filename (cfg, PS_METADATA_DIR, id);
  GNUNET_assert (fn != NULL);

  if ((0 == STAT (fn, &sbuf)) &&
      (GNUNET_OK == read_info (cfg, id, &old, &ranking, &name)))
  {
    GNUNET_CONTAINER_meta_data_merge (old, meta);
    write_pseudonym_info (cfg, id, old, ranking, name);
    GNUNET_CONTAINER_meta_data_destroy (old);
    GNUNET_free_non_null (name);
  }
  else
  {
    write_pseudonym_info (cfg, id, meta, ranking, NULL);
  }
  GNUNET_free (fn);
  internal_notify (id, meta, ranking);
}


/* end of pseudonym.c */
