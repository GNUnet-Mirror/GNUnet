/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file fs/gnunet-service-fs_indexing.c
 * @brief program that provides indexing functions of the file-sharing service
 * @author Christian Grothoff
 */
#include "platform.h"
#include <float.h>
#include "gnunet_core_service.h"
#include "gnunet_datastore_service.h"
#include "gnunet_peer_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-fs.h"
#include "gnunet-service-fs_indexing.h"
#include "fs.h"

/**
 * In-memory information about indexed files (also available
 * on-disk).
 */
struct IndexInfo
{
  /**
   * This is a doubly linked list.
   */
  struct IndexInfo *next;

  /**
   * This is a doubly linked list.
   */
  struct IndexInfo *prev;

  /**
   * Name of the indexed file.  Memory allocated
   * at the end of this struct (do not free).
   */
  const char *filename;

  /**
   * Context for transmitting confirmation to client,
   * NULL if we've done this already.
   */
  struct GNUNET_SERVER_TransmitContext *tc;

  /**
   * Context for hashing of the file.
   */
  struct GNUNET_CRYPTO_FileHashContext *fhc;

  /**
   * Hash of the contents of the file.
   */
  struct GNUNET_HashCode file_id;
};


/**
 * Head of linked list of indexed files.
 * FIXME: we don't need both a DLL and a hashmap here!
 */
static struct IndexInfo *indexed_files_head;

/**
 * Tail of linked list of indexed files.
 */
static struct IndexInfo *indexed_files_tail;

/**
 * Maps hash over content of indexed files to the respective 'struct IndexInfo'.
 * The filenames are pointers into the indexed_files linked list and
 * do not need to be freed.
 */
static struct GNUNET_CONTAINER_MultiHashMap *ifm;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Datastore handle.  Created and destroyed by code in
 * gnunet-service-fs (this is an alias).
 */
static struct GNUNET_DATASTORE_Handle *dsh;


/**
 * Write the current index information list to disk.
 */
static void
write_index_list ()
{
  struct GNUNET_BIO_WriteHandle *wh;
  char *fn;
  struct IndexInfo *pos;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "FS", "INDEXDB", &fn))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                               "fs",
                               "INDEXDB");
    return;
  }
  wh = GNUNET_BIO_write_open_file (fn);
  if (NULL == wh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                _ ("Could not open `%s'.\n"),
                fn);
    GNUNET_free (fn);
    return;
  }
  for (pos = indexed_files_head; NULL != pos; pos = pos->next)
    if ((GNUNET_OK != GNUNET_BIO_write (wh,
                                        "fs-indexing-file-id",
                                        &pos->file_id,
                                        sizeof(struct GNUNET_HashCode))) ||
        (GNUNET_OK != GNUNET_BIO_write_string (wh,
                                               "fs-indexing-filename",
                                               pos->filename)))
      break;
  if (GNUNET_OK != GNUNET_BIO_write_close (wh, NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                _ ("Error writing `%s'.\n"),
                fn);
    GNUNET_free (fn);
    return;
  }
  GNUNET_free (fn);
}


/**
 * Read index information from disk.
 */
static void
read_index_list ()
{
  struct GNUNET_BIO_ReadHandle *rh;
  char *fn;
  struct IndexInfo *pos;
  char *fname;
  struct GNUNET_HashCode hc;
  size_t slen;
  char *emsg;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "FS", "INDEXDB", &fn))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                               "fs",
                               "INDEXDB");
    return;
  }
  if (GNUNET_NO == GNUNET_DISK_file_test (fn))
  {
    /* no index info yet */
    GNUNET_free (fn);
    return;
  }
  rh = GNUNET_BIO_read_open_file (fn);
  if (NULL == rh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                _ ("Could not open `%s'.\n"),
                fn);
    GNUNET_free (fn);
    return;
  }
  while (
    (GNUNET_OK == GNUNET_BIO_read (rh,
                                   "Hash of indexed file",
                                   &hc,
                                   sizeof(struct GNUNET_HashCode))) &&
    (GNUNET_OK ==
     GNUNET_BIO_read_string (rh, "Name of indexed file", &fname, 1024 * 16)) &&
    (fname != NULL))
  {
    slen = strlen (fname) + 1;
    pos = GNUNET_malloc (sizeof(struct IndexInfo) + slen);
    pos->file_id = hc;
    pos->filename = (const char *) &pos[1];
    GNUNET_memcpy (&pos[1], fname, slen);
    if (GNUNET_SYSERR == GNUNET_CONTAINER_multihashmap_put (
          ifm,
          &pos->file_id,
          pos,
          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      GNUNET_free (pos);
    }
    else
    {
      GNUNET_CONTAINER_DLL_insert (indexed_files_head, indexed_files_tail, pos);
    }
    GNUNET_free (fname);
  }
  if (GNUNET_OK != GNUNET_BIO_read_close (rh, &emsg))
    GNUNET_free (emsg);
  GNUNET_free (fn);
}


/**
 * Continuation called from datastore's remove
 * function.
 *
 * @param cls unused
 * @param success did the deletion work?
 * @param min_expiration minimum expiration time required for content to be stored
 * @param msg error message
 */
static void
remove_cont (void *cls,
             int success,
             struct GNUNET_TIME_Absolute min_expiration,
             const char *msg)
{
  if (GNUNET_OK != success)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Failed to delete bogus block: %s\n"),
                msg);
}


/**
 * We've received an on-demand encoded block from the datastore.
 * Attempt to do on-demand encoding and (if successful), call the
 * continuation with the resulting block.  On error, clean up and ask
 * the datastore for more results.
 *
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 * @param cont function to call with the actual block (at most once, on success)
 * @param cont_cls closure for cont
 * @return GNUNET_OK on success
 */
int
GNUNET_FS_handle_on_demand_block (const struct GNUNET_HashCode *key,
                                  uint32_t size,
                                  const void *data,
                                  enum GNUNET_BLOCK_Type type,
                                  uint32_t priority,
                                  uint32_t anonymity,
                                  uint32_t replication,
                                  struct GNUNET_TIME_Absolute expiration,
                                  uint64_t uid,
                                  GNUNET_DATASTORE_DatumProcessor cont,
                                  void *cont_cls)
{
  const struct OnDemandBlock *odb;
  struct GNUNET_HashCode nkey;
  struct GNUNET_CRYPTO_SymmetricSessionKey skey;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct GNUNET_HashCode query;
  ssize_t nsize;
  char ndata[DBLOCK_SIZE];
  char edata[DBLOCK_SIZE];
  const char *fn;
  struct GNUNET_DISK_FileHandle *fh;
  uint64_t off;
  struct IndexInfo *ii;

  if (size != sizeof(struct OnDemandBlock))
  {
    GNUNET_break (0);
    GNUNET_DATASTORE_remove (dsh, key, size, data, -1, -1, &remove_cont, NULL);
    return GNUNET_SYSERR;
  }
  odb = (const struct OnDemandBlock *) data;
  off = GNUNET_ntohll (odb->offset);
  ii = GNUNET_CONTAINER_multihashmap_get (ifm, &odb->file_id);
  if (NULL == ii)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to find index %s\n",
                GNUNET_h2s (&odb->file_id));
    return GNUNET_SYSERR;
  }
  fn = ii->filename;
  if ((NULL == fn) || (0 != access (fn, R_OK)))
  {
    GNUNET_STATISTICS_update (
      GSF_stats,
      gettext_noop ("# index blocks removed: original file inaccessible"),
      1,
      GNUNET_YES);
    GNUNET_DATASTORE_remove (dsh, key, size, data, -1, -1, &remove_cont, NULL);
    return GNUNET_SYSERR;
  }
  if ((NULL == (fh = GNUNET_DISK_file_open (fn,
                                            GNUNET_DISK_OPEN_READ,
                                            GNUNET_DISK_PERM_NONE))) ||
      (off != GNUNET_DISK_file_seek (fh, off, GNUNET_DISK_SEEK_SET)) ||
      (-1 == (nsize = GNUNET_DISK_file_read (fh, ndata, sizeof(ndata)))))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ (
                  "Could not access indexed file `%s' (%s) at offset %llu: %s\n"),
                GNUNET_h2s (&odb->file_id),
                fn,
                (unsigned long long) off,
                (fn == NULL) ? _ ("not indexed") : strerror (errno));
    if (fh != NULL)
      GNUNET_DISK_file_close (fh);
    GNUNET_DATASTORE_remove (dsh, key, size, data, -1, -1, &remove_cont, NULL);
    return GNUNET_SYSERR;
  }
  GNUNET_DISK_file_close (fh);
  GNUNET_CRYPTO_hash (ndata, nsize, &nkey);
  GNUNET_CRYPTO_hash_to_aes_key (&nkey, &skey, &iv);
  GNUNET_CRYPTO_symmetric_encrypt (ndata, nsize, &skey, &iv, edata);
  GNUNET_CRYPTO_hash (edata, nsize, &query);
  if (0 != memcmp (&query, key, sizeof(struct GNUNET_HashCode)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Indexed file `%s' changed at offset %llu\n"),
                fn,
                (unsigned long long) off);
    GNUNET_DATASTORE_remove (dsh, key, size, data, -1, -1, &remove_cont, NULL);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "On-demand encoded block for query `%s'\n",
              GNUNET_h2s (key));
  cont (cont_cls,
        key,
        nsize,
        edata,
        GNUNET_BLOCK_TYPE_FS_DBLOCK,
        priority,
        anonymity,
        replication,
        expiration,
        uid);
  return GNUNET_OK;
}


/**
 * Transmit information about indexed files to @a mq.
 *
 * @param mq message queue to send information to
 */
void
GNUNET_FS_indexing_send_list (struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_MQ_Envelope *env;
  struct IndexInfoMessage *iim;
  struct GNUNET_MessageHeader *iem;
  size_t slen;
  const char *fn;
  struct IndexInfo *pos;

  for (pos = indexed_files_head; NULL != pos; pos = pos->next)
  {
    fn = pos->filename;
    slen = strlen (fn) + 1;
    if (slen + sizeof(struct IndexInfoMessage) >= GNUNET_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      break;
    }
    env =
      GNUNET_MQ_msg_extra (iim, slen, GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_ENTRY);
    iim->reserved = 0;
    iim->file_id = pos->file_id;
    GNUNET_memcpy (&iim[1], fn, slen);
    GNUNET_MQ_send (mq, env);
  }
  env = GNUNET_MQ_msg (iem, GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_END);
  GNUNET_MQ_send (mq, env);
}


/**
 * Remove a file from the index.
 *
 * @param fid identifier of the file to remove
 * @return #GNUNET_YES if the @a fid was found
 */
int
GNUNET_FS_indexing_do_unindex (const struct GNUNET_HashCode *fid)
{
  struct IndexInfo *pos;

  for (pos = indexed_files_head; NULL != pos; pos = pos->next)
  {
    if (0 == memcmp (&pos->file_id, fid, sizeof(struct GNUNET_HashCode)))
    {
      GNUNET_CONTAINER_DLL_remove (indexed_files_head, indexed_files_tail, pos);
      GNUNET_break (
        GNUNET_OK ==
        GNUNET_CONTAINER_multihashmap_remove (ifm, &pos->file_id, pos));
      GNUNET_free (pos);
      write_index_list ();
      return GNUNET_YES;
    }
  }
  return GNUNET_NO;
}


/**
 * Add the given file to the list of indexed files.
 *
 * @param filename name of the file
 * @param file_id hash identifier for @a filename
 */
void
GNUNET_FS_add_to_index (const char *filename,
                        const struct GNUNET_HashCode *file_id)
{
  struct IndexInfo *ii;
  size_t slen;

  ii = GNUNET_CONTAINER_multihashmap_get (ifm, file_id);
  if (NULL != ii)
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_INFO,
      _ (
        "Index request received for file `%s' is already indexed as `%s'.  Permitting anyway.\n"),
      filename,
      ii->filename);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding file %s to index as %s\n",
              filename,
              GNUNET_h2s (file_id));
  slen = strlen (filename) + 1;
  ii = GNUNET_malloc (sizeof(struct IndexInfo) + slen);
  ii->file_id = *file_id;
  ii->filename = (const char *) &ii[1];
  GNUNET_memcpy (&ii[1], filename, slen);
  GNUNET_CONTAINER_DLL_insert (indexed_files_head, indexed_files_tail, ii);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (
                   ifm,
                   &ii->file_id,
                   ii,
                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  write_index_list ();
}


/**
 * Shutdown the module.
 */
void
GNUNET_FS_indexing_done ()
{
  struct IndexInfo *pos;

  while (NULL != (pos = indexed_files_head))
  {
    GNUNET_CONTAINER_DLL_remove (indexed_files_head, indexed_files_tail, pos);
    if (pos->fhc != NULL)
      GNUNET_CRYPTO_hash_file_cancel (pos->fhc);
    GNUNET_break (
      GNUNET_OK ==
      GNUNET_CONTAINER_multihashmap_remove (ifm, &pos->file_id, pos));
    GNUNET_free (pos);
  }
  GNUNET_CONTAINER_multihashmap_destroy (ifm);
  ifm = NULL;
  cfg = NULL;
}


/**
 * Initialize the indexing submodule.
 *
 * @param c configuration to use
 * @param d datastore to use
 */
int
GNUNET_FS_indexing_init (const struct GNUNET_CONFIGURATION_Handle *c,
                         struct GNUNET_DATASTORE_Handle *d)
{
  cfg = c;
  dsh = d;
  ifm = GNUNET_CONTAINER_multihashmap_create (128, GNUNET_YES);
  read_index_list ();
  return GNUNET_OK;
}


/* end of gnunet-service-fs_indexing.c */
