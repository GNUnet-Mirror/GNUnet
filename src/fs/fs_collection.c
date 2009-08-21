/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_collection.c
 * @brief Helper functions for building a collection
 * @author Christian Grothoff
 *
 * A collection is a special kind of namespace.  A collection is the
 * set of files provided by the same user, but unlike namespaces it is
 * automatically managed by the GNUnet UI.  A collection is a single
 * directory in a namespace that is automatically updated each time
 * the user updates or deletes a file.  That is, once the user starts
 * a collection the gnunet-tools will always keep the corresponding
 * directory and namespace entries up-to-date.
 *
 * A good way of thinking about a collection is a lazy user's
 * namespace.
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_fs_service.h"


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
			    struct GNUNET_FS_Namespace *namespace)
{
  return GNUNET_SYSERR;
}


/**
 * Stop collection.
 *
 * @param h handle to the file sharing subsystem
 * @return GNUNET_OK on success, GNUNET_SYSERR if no collection is active
 */
int 
GNUNET_FS_collection_stop (struct GNUNET_FS_Handle *h)
{
  return GNUNET_SYSERR;
}


/**
 * Are we using a collection?
 *
 * @param h handle to the file sharing subsystem
 * @return NULL if there is no collection,
 */
struct GNUNET_FS_Namespace *
GNUNET_FS_collection_get(struct GNUNET_FS_Handle *h)
{
  return NULL;
}


/**
 * Publish an update of the current collection information to the
 * network now.  The function has no effect if the collection has not
 * changed since the last publication.  If we are currently not
 * collecting, this function does nothing.
 *
 * @param h handle to the file sharing subsystem
 */
void GNUNET_FS_collection_publish (struct GNUNET_FS_Handle *h)
{
}


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
			       const struct GNUNET_CONTAINER_MetaData *meta)
{
}


#if 0

/**
 * Filename used to store collection information
 */
#define COLLECTION "collection"

#define COLLECTION_ROOT "root"

/**
 * How long does a collection advertisement live?
 */
#define COLLECTION_ADV_LIFETIME (12 * GNUNET_CRON_MONTHS)

/**
 * @brief information about a collection
 */
typedef struct CollectionData
{

  /**
   * What is the pseudonym ID for the publication?
   */
  GNUNET_HashCode pid;

  /**
   * Anonymity level for the collection. (NBO)
   */
  unsigned int anonymityLevel;

  /**
   * Priority of the collection (NBO).
   */
  unsigned int priority;

  /**
   * Has this collection changed since the last publication?
   */
  int changed;

  /**
   * Revision counter
   */
  unsigned int revision;

} CollectionData;


typedef struct
{

  CollectionData data;

  /**
   * Metadata describing the collection
   */
  struct GNUNET_MetaData *meta;

  /**
   * Files in the collection.
   */
  GNUNET_ECRS_FileInfo *files;

  /**
   * How many files are in files?
   */
  unsigned int file_count;


} CollectionInfo;

static CollectionInfo *collectionData;

static struct GNUNET_Mutex *lock;

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

static char *
getCollectionFileName ()
{
  return GNUNET_get_home_filename (ectx, cfg, GNUNET_NO, COLLECTION, NULL);
}

/**
 * Initialize collection module.
 */
void
GNUNET_CO_init (struct GNUNET_GE_Context *e,
                struct GNUNET_GC_Configuration *c)
{
  char *fn;
  int len;
  unsigned int mlen;
  unsigned long long size;
  char *buf;
  int fd;
  const char *pos;
  size_t rsize;
  unsigned int i;
  char *tmp;

  cfg = c;
  ectx = e;
  lock = GNUNET_mutex_create (GNUNET_YES);
  fn = getCollectionFileName ();
  if (!GNUNET_disk_file_test (ectx, fn))
    {
      GNUNET_free (fn);
      return;
    }
  /* read collection data */
  if (GNUNET_OK != GNUNET_disk_file_size (ectx, fn, &size, GNUNET_YES))
    {
      GNUNET_free (fn);
      return;
    }
  if ((size > 0x7FFFFFFF) ||
      (size < sizeof (CollectionData) + 2 * sizeof (int)))
    {
      GNUNET_GE_BREAK (ectx, 0);
      UNLINK (fn);
      GNUNET_free (fn);
      return;
    }
  fd = OPEN (fn, O_RDONLY | O_LARGEFILE);
  if (fd == -1)
    {
      GNUNET_GE_BREAK (ectx, 0);
      UNLINK (fn);
      GNUNET_free (fn);
      return;
    }
  rsize = (size_t) size;
  buf = MMAP (NULL, rsize, PROT_READ, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED)
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                   GNUNET_GE_USER | GNUNET_GE_BULK, "mmap",
                                   fn);
      CLOSE (fd);
      GNUNET_free (fn);
      return;
    }
  collectionData = GNUNET_malloc (sizeof (CollectionInfo));
  memset (collectionData, 0, sizeof (CollectionInfo));
  memcpy (&collectionData->data, buf, sizeof (CollectionData));
  pos = &buf[sizeof (CollectionData)];
  rsize -= sizeof (CollectionData);
  len = ntohl (*(int *) pos);
  if (len > 1024 * 1024 * 4)
    goto ERR;
  pos += sizeof (int);
  mlen = ntohl (*(unsigned int *) pos);
  pos += sizeof (unsigned int);
  rsize -= 2 * sizeof (int);
  if (mlen > rsize)
    goto ERR;
  GNUNET_array_grow (collectionData->files, collectionData->file_count, len);
  collectionData->meta = GNUNET_meta_data_deserialize (ectx, pos, mlen);
  rsize -= mlen;
  pos += mlen;
  GNUNET_GE_BREAK (ectx, collectionData->meta != NULL);
  for (i = 0; i < collectionData->file_count; i++)
    {
      if (rsize < 2 * sizeof (int))
        {
          GNUNET_GE_BREAK (ectx, 0);
          break;
        }
      len = ntohl (*(int *) pos);
      pos += sizeof (int);
      mlen = ntohl (*(int *) pos);
      pos += sizeof (int);
      rsize -= 2 * sizeof (int);
      if (rsize < mlen + len)
        {
          GNUNET_GE_BREAK (ectx, 0);
          break;
        }
      if (len > 1024 * 16)
        {
          GNUNET_GE_BREAK (ectx, 0);
          len = 1024 * 16;
        }
      tmp = GNUNET_malloc (len + 1);
      tmp[len] = '\0';
      memcpy (tmp, pos, len);
      pos += len;
      rsize -= len;
      collectionData->files[i].uri = GNUNET_ECRS_string_to_uri (ectx, tmp);
      GNUNET_GE_ASSERT (ectx, collectionData->files[i].uri != NULL);
      GNUNET_free (tmp);
      collectionData->files[i].meta
        = GNUNET_meta_data_deserialize (ectx, pos, mlen);
      GNUNET_GE_ASSERT (ectx, collectionData->files[i].meta != NULL);
      pos += mlen;
      rsize -= mlen;
    }
  GNUNET_GE_ASSERT (ectx, rsize == 0);
  MUNMAP (buf, (size_t) size);
  CLOSE (fd);
  GNUNET_free (fn);
  /* kill invalid entries (meta or uri == NULL) */
  for (i = 0; i < collectionData->file_count; i++)
    {
      if ((collectionData->files[i].uri != NULL) &&
          (collectionData->files[i].meta != NULL))
        continue;
      if (collectionData->files[i].uri != NULL)
        GNUNET_ECRS_uri_destroy (collectionData->files[i].uri);
      if (collectionData->files[i].meta != NULL)
        GNUNET_meta_data_destroy (collectionData->files[i].meta);
      collectionData->files[i]
        = collectionData->files[collectionData->file_count - 1];
      GNUNET_array_grow (collectionData->files,
                         collectionData->file_count,
                         collectionData->file_count - 1);
    }
  return;
ERR:
  MUNMAP (buf, (size_t) size);
  CLOSE (fd);
  GNUNET_free (fn);
  GNUNET_free (collectionData);
  collectionData = NULL;
}

static void
WRITEINT (int fd, int val)
{
  int bval;

  bval = htonl (val);
  WRITE (fd, &bval, sizeof (int));
}

static void
writeCO ()
{
  char *fn;
  unsigned int mlen;
  char *buf;
  int fd;
  unsigned int i;
  char *tmp;

  if (collectionData == NULL)
    return;

  /* write collection data */
  mlen =
    GNUNET_meta_data_get_serialized_size (collectionData->meta, GNUNET_NO);
  buf = GNUNET_malloc (mlen);
  if (mlen != GNUNET_meta_data_serialize (ectx,
                                          collectionData->meta, buf,
                                          mlen, GNUNET_NO))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_free (buf);
      return;
    }

  fn = getCollectionFileName ();
  fd = OPEN (fn,
             O_CREAT | O_LARGEFILE | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
  if (fd == -1)
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_USER | GNUNET_GE_ADMIN |
                                   GNUNET_GE_ERROR | GNUNET_GE_BULK, "open",
                                   fn);
      GNUNET_free (fn);
      GNUNET_free (buf);
      return;
    }
  GNUNET_GE_BREAK (ectx, collectionData->file_count <= 1024 * 1024 * 4);
  WRITE (fd, collectionData, sizeof (CollectionData));
  WRITEINT (fd, collectionData->file_count);
  WRITEINT (fd, mlen);
  WRITE (fd, buf, mlen);
  GNUNET_free (buf);
  for (i = 0; i < collectionData->file_count; i++)
    {
      mlen =
        GNUNET_meta_data_get_serialized_size (collectionData->files[i].meta,
                                              GNUNET_NO);
      buf = GNUNET_malloc (mlen);
      if (mlen != GNUNET_meta_data_serialize (ectx,
                                              collectionData->files[i].meta,
                                              buf, mlen, GNUNET_NO))
        {
          GNUNET_GE_BREAK (ectx, 0);
          GNUNET_free (buf);
          break;
        }
      tmp = GNUNET_ECRS_uri_to_string (collectionData->files[i].uri);
      WRITEINT (fd, strlen (tmp));
      WRITEINT (fd, mlen);
      GNUNET_GE_BREAK (ectx, strlen (tmp) < 16 * 1024);
      WRITE (fd, tmp, strlen (tmp));
      GNUNET_free (tmp);
      WRITE (fd, buf, mlen);
      GNUNET_free (buf);
    }
  CLOSE (fd);
  GNUNET_free (fn);
}

static void
free_collection_data ()
{
  unsigned int i;

  if (collectionData == NULL)
    return;
  GNUNET_meta_data_destroy (collectionData->meta);
  for (i = 0; i < collectionData->file_count; i++)
    {
      GNUNET_meta_data_destroy (collectionData->files[i].meta);
      GNUNET_ECRS_uri_destroy (collectionData->files[i].uri);
    }
  GNUNET_array_grow (collectionData->files, collectionData->file_count, 0);
  GNUNET_free (collectionData);
  collectionData = NULL;
}

/**
 * Shutdown collection module.
 */
void
GNUNET_CO_done ()
{
  writeCO ();
  free_collection_data ();
  GNUNET_mutex_destroy (lock);
  lock = NULL;
  ectx = NULL;
  cfg = NULL;
}


/**
 * Start collection.
 *
 * @param updateInterval of GNUNET_ECRS_SBLOCK_UPDATE_NONE
 *        means to update _immediately_ on any change,
 *        wherease GNUNET_ECRS_SBLOCK_UPDATE_SPORADIC means
 *        to publish updates when the CO_Context
 *        is destroyed (i.e. on exit from the UI).
 */
int
GNUNET_CO_collection_start (unsigned int anonymityLevel,
                            unsigned int prio,
                            const struct GNUNET_MetaData *meta)
{
  struct GNUNET_ECRS_URI *advertisement;
  struct GNUNET_ECRS_URI *rootURI;
  const char *root = COLLECTION_ROOT;

  GNUNET_mutex_lock (lock);
  GNUNET_CO_collection_stop (); /* cancel old collection */
  advertisement = GNUNET_ECRS_keyword_string_to_uri (ectx, COLLECTION);
  GNUNET_GE_ASSERT (ectx, advertisement != NULL);
  rootURI = GNUNET_ECRS_namespace_create (ectx,
                                          cfg,
                                          meta,
                                          anonymityLevel,
                                          prio,
                                          GNUNET_get_time () +
                                          COLLECTION_ADV_LIFETIME,
                                          advertisement, root);
  GNUNET_ECRS_uri_destroy (advertisement);
  if (rootURI == NULL)
    {
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  collectionData = GNUNET_malloc (sizeof (CollectionInfo));
  memset (collectionData, 0, sizeof (CollectionInfo));
  GNUNET_ECRS_uri_get_namespace_from_sks (rootURI, &collectionData->data.pid);
  GNUNET_ECRS_uri_destroy (rootURI);
  collectionData->data.priority = htonl (prio);
  collectionData->data.anonymityLevel = htonl (anonymityLevel);
  collectionData->meta = GNUNET_meta_data_duplicate (meta);
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * Stop collection.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR if no collection is active
 */
int
GNUNET_CO_collection_stop ()
{
  GNUNET_mutex_lock (lock);
  if (collectionData == NULL)
    {
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  GNUNET_ECRS_namespace_delete (ectx, cfg, &collectionData->data.pid);
  free_collection_data ();
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * Are we using a collection?
 *
 * @return NULL if there is no collection, otherwise its metadata
 */
struct GNUNET_MetaData *
GNUNET_CO_collection_get_name ()
{
  struct GNUNET_MetaData *meta;

  GNUNET_mutex_lock (lock);
  if (collectionData == NULL)
    {
      GNUNET_mutex_unlock (lock);
      return NULL;
    }
  meta = GNUNET_meta_data_duplicate (collectionData->meta);
  GNUNET_mutex_unlock (lock);
  return meta;
}

/**
 * Publish an update of the current collection information to the
 * network now.  The function has no effect if the collection has not
 * changed since the last publication.  If we are currently not
 * collecting, this function does nothing.
 */
void
GNUNET_CO_collection_publish_now ()
{
  struct GNUNET_ECRS_URI *uri;
  struct GNUNET_ECRS_URI *directoryURI;
  unsigned long long dirLen;
  char *tmpName;
  int fd;
  char *dirData;
  char this_revision_string[128];
  char next_revision_string[128];
  const char *tmpdir;

  GNUNET_mutex_lock (lock);
  if ((collectionData == NULL) ||
      (ntohl (collectionData->data.changed) == GNUNET_NO))
    {
      GNUNET_mutex_unlock (lock);
      return;
    }

  tmpdir = getenv ("TMPDIR");
  tmpdir = tmpdir ? tmpdir : "/tmp";

#define TEMPLATE "/gnunet-collectionXXXXXX"
  tmpName = GNUNET_malloc (strlen (tmpdir) + sizeof (TEMPLATE) + 1);
  strcpy (tmpName, tmpdir);
  strcat (tmpName, TEMPLATE);
#undef TEMPLATE
  fd = mkstemp (tmpName);
  if (fd == -1)
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_BULK, "mkstemp");
      GNUNET_free (tmpName);
      GNUNET_mutex_unlock (lock);
      return;
    }
  dirData = NULL;
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_OK == GNUNET_ECRS_directory_create (ectx,
                                                               &dirData,
                                                               &dirLen,
                                                               collectionData->file_count,
                                                               collectionData->files,
                                                               collectionData->meta));
  if (-1 == WRITE (fd, dirData, dirLen))
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_BULK, "write");
      GNUNET_free (tmpName);
      GNUNET_free (dirData);
      GNUNET_mutex_unlock (lock);
      return;
    }
  GNUNET_free (dirData);
  CLOSE (fd);
  if (GNUNET_OK != GNUNET_ECRS_file_upload (ectx, cfg, tmpName, GNUNET_NO,      /* indexing */
                                            ntohl (collectionData->
                                                   data.anonymityLevel),
                                            ntohl (collectionData->
                                                   data.priority),
                                            GNUNET_get_time () +
                                            COLLECTION_ADV_LIFETIME, NULL,
                                            NULL, NULL, NULL, &directoryURI))
    {
      UNLINK (tmpName);
      GNUNET_free (tmpName);
      GNUNET_mutex_unlock (lock);
      return;
    }
  UNLINK (tmpName);
  GNUNET_free (tmpName);
  if (ntohl (collectionData->data.revision) == 0)
    strcpy (this_revision_string, COLLECTION_ROOT);
  else
    GNUNET_snprintf (this_revision_string,
                     sizeof (this_revision_string),
                     _("Revision %u"), ntohl (collectionData->data.revision));
  GNUNET_snprintf (next_revision_string,
                   sizeof (next_revision_string),
                   _("Revision %u"),
                   ntohl (collectionData->data.revision) + 1);
  uri = GNUNET_ECRS_namespace_add_content (ectx,
                                           cfg,
                                           &collectionData->data.pid,
                                           ntohl (collectionData->
                                                  data.anonymityLevel),
                                           ntohl (collectionData->
                                                  data.priority),
                                           GNUNET_get_time () +
                                           COLLECTION_ADV_LIFETIME,
                                           this_revision_string,
                                           next_revision_string, directoryURI,
                                           collectionData->meta);
  if (uri != NULL)
    {
      collectionData->data.revision =
        htonl (ntohl (collectionData->data.revision) + 1);
      collectionData->data.changed = htonl (GNUNET_NO);
      GNUNET_ECRS_uri_destroy (uri);
    }
  GNUNET_mutex_unlock (lock);
}

/**
 * If we are currently building a collection, publish
 * the given file information in that collection.
 * If we are currently not collecting, this function
 * does nothing.
 */
void
GNUNET_CO_collection_add_item (const GNUNET_ECRS_FileInfo * fi)
{
  unsigned int i;
  GNUNET_ECRS_FileInfo fc;

  if ((GNUNET_ECRS_uri_test_ksk (fi->uri)))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return;
    }
  if (lock == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return;
    }
  GNUNET_mutex_lock (lock);
  if (collectionData == NULL)
    {
      GNUNET_mutex_unlock (lock);
      return;
    }
  for (i = 0; i < collectionData->file_count; i++)
    {
      if (GNUNET_ECRS_uri_test_equal (fi->uri, collectionData->files[i].uri))
        {
          GNUNET_mutex_unlock (lock);
          return;
        }
    }
  fc.uri = GNUNET_ECRS_uri_duplicate (fi->uri);
  fc.meta = GNUNET_meta_data_duplicate (fi->meta);
  GNUNET_array_append (collectionData->files, collectionData->file_count, fc);
  collectionData->data.changed = htonl (GNUNET_YES);
  GNUNET_mutex_unlock (lock);
}

#endif

/* end of fs_collection.c */
