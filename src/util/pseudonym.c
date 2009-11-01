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

/** 
 * FIXME
 */
#define PS_METADATA_DIR DIR_SEPARATOR_STR "data" DIR_SEPARATOR_STR "pseudonyms/metadata" DIR_SEPARATOR_STR

/** 
 * FIXME
 */
#define PS_NAMES_DIR    DIR_SEPARATOR_STR "data" DIR_SEPARATOR_STR "pseudonyms/names"    DIR_SEPARATOR_STR


/** 
 * FIXME
 */
struct DiscoveryCallback
{

  /** 
   * FIXME
   */
  struct DiscoveryCallback *next;

  /** 
   * FIXME
   */
  GNUNET_PSEUDONYM_Iterator callback;

  /** 
   * FIXME
   */
  void *closure;
};


/** 
 * FIXME
 */
static struct DiscoveryCallback *head;

/**
 * Internal notification about new tracked URI.
 * 
 * FIXME
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
 * 
 * FIXME
 */
int
GNUNET_PSEUDONYM_discovery_callback_register (const struct
                                              GNUNET_CONFIGURATION_Handle
                                              *cfg,
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
 * 
 * FIXME
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
 * 
 * FIXME
 */
static char *
get_data_filename (const struct GNUNET_CONFIGURATION_Handle
                   *cfg, const char *prefix, const GNUNET_HashCode * psid)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;

  if (psid != NULL)
    GNUNET_CRYPTO_hash_to_enc (psid, &enc);
  return GNUNET_DISK_get_home_filename (cfg,
                                        GNUNET_CLIENT_SERVICE_NAME,
                                        prefix,
                                        (psid ==
                                         NULL) ? NULL : (const char *) &enc,
                                        NULL);
}


/**
 * FIXME
 */
static void
write_pseudonym_info (const struct GNUNET_CONFIGURATION_Handle *cfg,
                      const GNUNET_HashCode * nsid,
                      const struct GNUNET_CONTAINER_MetaData *meta,
                      int32_t ranking, const char *ns_name)
{
  size_t size;
  size_t tag;
  size_t off;
  char *buf;
  char *fn;

  fn = get_data_filename (cfg, PS_METADATA_DIR, nsid);
  GNUNET_assert (fn != NULL);
  size = GNUNET_CONTAINER_meta_data_get_serialized_size (meta,
                                                         GNUNET_CONTAINER_META_DATA_SERIALIZE_FULL);
  tag = size + sizeof (int32_t) + 1;
  off = 0;
  if (ns_name != NULL)
    {
      off = strlen (ns_name);
      tag += off;
    }
  buf = GNUNET_malloc (tag);
  ((int32_t *) buf)[0] = htonl (ranking);       /* ranking */
  if (ns_name != NULL)
    {
      memcpy (&buf[sizeof (int32_t)], ns_name, off + 1);
    }
  else
    {
      buf[sizeof (int)] = '\0';
    }
  GNUNET_assert
    (size == GNUNET_CONTAINER_meta_data_serialize (meta,
                                                   &buf[sizeof
                                                        (int32_t) +
                                                        off + 1],
                                                   size,
                                                   GNUNET_CONTAINER_META_DATA_SERIALIZE_FULL));
  GNUNET_break
    (tag == GNUNET_DISK_fn_write (fn, buf, tag, GNUNET_DISK_PERM_USER_READ
                                  | GNUNET_DISK_PERM_USER_WRITE |
                                  GNUNET_DISK_PERM_GROUP_READ));
  GNUNET_free (fn);
  GNUNET_free (buf);
  /* create entry for pseudonym name in names */
  GNUNET_free_non_null (GNUNET_PSEUDONYM_id_to_name (cfg, nsid));
}


/**
 * FIXME
 */
static int
read_info (const struct GNUNET_CONFIGURATION_Handle *cfg,
           const GNUNET_HashCode * nsid,
           struct GNUNET_CONTAINER_MetaData **meta,
           int32_t * ranking, char **ns_name)
{
  uint64_t len;
  size_t size;
  size_t zend;
  struct stat sbuf;
  char *buf;
  char *fn;

  if (meta != NULL)
    *meta = NULL;
  if (ns_name != NULL)
    *ns_name = NULL;
  fn = get_data_filename (cfg, PS_METADATA_DIR, nsid);
  GNUNET_assert (fn != NULL);

  if ((0 != STAT (fn, &sbuf))
      || (GNUNET_OK != GNUNET_DISK_file_size (fn, &len, GNUNET_YES)))
    {
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  if (len <= sizeof (int32_t) + 1)
    {
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  if (len > 16 * 1024 * 1024)
    {
      /* too big, must be invalid! remove! */
      GNUNET_break (0);
      if (0 != UNLINK (fn))
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  buf = GNUNET_malloc (len);
  if (len != GNUNET_DISK_fn_read (fn, buf, len))
    {
      GNUNET_free (buf);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  if (ranking != NULL)
    *ranking = ntohl (((int32_t *) buf)[0]);
  zend = sizeof (int32_t);
  while ((zend < len) && (buf[zend] != '\0'))
    zend++;
  if (zend == len)
    {
      GNUNET_free (buf);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  if (ns_name != NULL)
    {
      if (zend != sizeof (int32_t))
        *ns_name = GNUNET_strdup (&buf[sizeof (int32_t)]);
      else
        *ns_name = NULL;
    }
  zend++;
  size = len - zend;
  if (meta != NULL)
    {
      *meta = GNUNET_CONTAINER_meta_data_deserialize (&buf[zend], size);
      if ((*meta) == NULL)
        {
          /* invalid data! remove! */
          GNUNET_break (0);
          if (0 != UNLINK (fn))
            GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                      "unlink", fn);
          GNUNET_free (buf);
          GNUNET_free (fn);
          return GNUNET_SYSERR;
        }
    }
  GNUNET_free (fn);
  GNUNET_free (buf);
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

  meta = NULL;
  name = NULL;
  if (GNUNET_OK == read_info (cfg, nsid, &meta, NULL, &name))
    {
      if ((meta != NULL) && (name == NULL))
        name = GNUNET_CONTAINER_meta_data_get_first_by_types (meta,
                                                              EXTRACTOR_TITLE,
                                                              EXTRACTOR_FILENAME,
                                                              EXTRACTOR_DESCRIPTION,
                                                              EXTRACTOR_SUBJECT,
                                                              EXTRACTOR_PUBLISHER,
                                                              EXTRACTOR_AUTHOR,
                                                              EXTRACTOR_COMMENT,
                                                              EXTRACTOR_SUMMARY,
                                                              EXTRACTOR_OWNER,
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
  fh = GNUNET_DISK_file_open (fn, GNUNET_DISK_OPEN_CREATE
                              | GNUNET_DISK_OPEN_READWRITE,
                              GNUNET_DISK_PERM_USER_READ |
                              GNUNET_DISK_PERM_USER_WRITE);
  i = 0;
  idx = -1;
  while ((len >= sizeof (GNUNET_HashCode)) &&
         (sizeof (GNUNET_HashCode)
          == GNUNET_DISK_file_read (fh, &nh, sizeof (GNUNET_HashCode))))
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
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "write", fn);
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
  fh = GNUNET_DISK_file_open (fn, GNUNET_DISK_OPEN_CREATE
                              | GNUNET_DISK_OPEN_READWRITE,
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
 * FIXME
 */
struct ListPseudonymClosure
{

  /**
   * FIXME
   */
  GNUNET_PSEUDONYM_Iterator iterator;

  /**
   * FIXME
   */
  void *closure;

  /**
   * FIXME
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};



/**
 * FIXME
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

  if (strlen (fullname) < sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded))
    return GNUNET_OK;
  fn =
    &fullname[strlen (fullname) + 1 -
              sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded)];
  if (fn[-1] != DIR_SEPARATOR)
    return GNUNET_OK;
  ret = GNUNET_OK;
  if (GNUNET_OK != GNUNET_CRYPTO_hash_from_string (fn, &id))
    return GNUNET_OK;           /* invalid name */
  if (GNUNET_OK != read_info (c->cfg, &id, &meta, &rating, NULL))
    return GNUNET_OK;           /* ignore entry */
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
 * Insert metadata into existing MD record (passed as cls).
 *
 * @param cls metadata to add to
 * @param type type of entry to insert
 * @param data value of entry to insert
 */
static int
merge_meta_helper (void *cls, EXTRACTOR_KeywordType type, const char *data)
{
  struct GNUNET_CONTAINER_MetaData *meta = cls;
  GNUNET_CONTAINER_meta_data_insert (meta, type, data);
  return GNUNET_OK;
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
      GNUNET_CONTAINER_meta_data_get_contents (meta, &merge_meta_helper, old);
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
