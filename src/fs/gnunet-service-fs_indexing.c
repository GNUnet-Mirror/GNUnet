/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
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
			       "fs", "INDEXDB");
    return;
  }
  wh = GNUNET_BIO_write_open (fn);
  if (NULL == wh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                _("Could not open `%s'.\n"), fn);
    GNUNET_free (fn);
    return;
  }
  for (pos = indexed_files_head; NULL != pos; pos = pos->next)
    if ((GNUNET_OK !=
         GNUNET_BIO_write (wh, &pos->file_id, sizeof (struct GNUNET_HashCode))) ||
        (GNUNET_OK != GNUNET_BIO_write_string (wh, pos->filename)))
      break;
  if (GNUNET_OK != GNUNET_BIO_write_close (wh))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                _("Error writing `%s'.\n"), fn);
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
			       "fs", "INDEXDB");
    return;
  }
  if (GNUNET_NO == GNUNET_DISK_file_test (fn))
  {
    /* no index info yet */
    GNUNET_free (fn);
    return;
  }
  rh = GNUNET_BIO_read_open (fn);
  if (NULL == rh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                _("Could not open `%s'.\n"), fn);
    GNUNET_free (fn);
    return;
  }
  while ((GNUNET_OK ==
          GNUNET_BIO_read (rh, "Hash of indexed file", &hc,
                           sizeof (struct GNUNET_HashCode))) &&
         (GNUNET_OK ==
          GNUNET_BIO_read_string (rh, "Name of indexed file", &fname,
                                  1024 * 16)) && (fname != NULL))
  {
    slen = strlen (fname) + 1;
    pos = GNUNET_malloc (sizeof (struct IndexInfo) + slen);
    pos->file_id = hc;
    pos->filename = (const char *) &pos[1];
    memcpy (&pos[1], fname, slen);
    if (GNUNET_SYSERR ==
        GNUNET_CONTAINER_multihashmap_put (ifm, &pos->file_id, pos,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      GNUNET_free (pos);
    }
    else
    {
      GNUNET_CONTAINER_DLL_insert (indexed_files_head,
				   indexed_files_tail,
				   pos);
    }
    GNUNET_free (fname);
  }
  if (GNUNET_OK != GNUNET_BIO_read_close (rh, &emsg))
    GNUNET_free (emsg);
  GNUNET_free (fn);
}


/**
 * We've validated the hash of the file we're about to index.  Signal
 * success to the client and update our internal data structures.
 *
 * @param ii the index info entry for the request
 */
static void
signal_index_ok (struct IndexInfo *ii)
{
  struct IndexInfo *ir;
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_put (ifm, &ii->file_id,
                                         ii,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    ir = GNUNET_CONTAINER_multihashmap_get (ifm,
					    &ii->file_id);
    GNUNET_assert (NULL != ir);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _
                ("Index request received for file `%s' is already indexed as `%s'.  Permitting anyway.\n"),
                ii->filename,
		ir->filename);
    GNUNET_SERVER_transmit_context_append_data (ii->tc, NULL, 0,
                                                GNUNET_MESSAGE_TYPE_FS_INDEX_START_OK);
    GNUNET_SERVER_transmit_context_run (ii->tc, GNUNET_TIME_UNIT_MINUTES);
    GNUNET_free (ii);
    return;
  }
  GNUNET_CONTAINER_DLL_insert (indexed_files_head,
			       indexed_files_tail,
			       ii);
  write_index_list ();
  GNUNET_SERVER_transmit_context_append_data (ii->tc, NULL, 0,
                                              GNUNET_MESSAGE_TYPE_FS_INDEX_START_OK);
  GNUNET_SERVER_transmit_context_run (ii->tc, GNUNET_TIME_UNIT_MINUTES);
  ii->tc = NULL;
}


/**
 * Function called once the hash computation over an
 * indexed file has completed.
 *
 * @param cls closure, our publishing context
 * @param res resulting hash, NULL on error
 */
static void
hash_for_index_val (void *cls, const struct GNUNET_HashCode * res)
{
  struct IndexInfo *ii = cls;

  ii->fhc = NULL;
  if ((res == NULL) ||
      (0 != memcmp (res, &ii->file_id, sizeof (struct GNUNET_HashCode))))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Hash mismatch trying to index file `%s' which has hash `%s'\n"),
                ii->filename, GNUNET_h2s (res));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Wanted `%s'\n",
                GNUNET_h2s (&ii->file_id));
    GNUNET_SERVER_transmit_context_append_data (ii->tc, NULL, 0,
                                                GNUNET_MESSAGE_TYPE_FS_INDEX_START_FAILED);
    GNUNET_SERVER_transmit_context_run (ii->tc, GNUNET_TIME_UNIT_MINUTES);
    GNUNET_free (ii);
    return;
  }
  signal_index_ok (ii);
}


/**
 * Handle INDEX_START-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
void
GNUNET_FS_handle_index_start (void *cls, struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *message)
{
  const struct IndexStartMessage *ism;
  char *fn;
  uint16_t msize;
  struct IndexInfo *ii;
  size_t slen;
  uint64_t dev;
  uint64_t ino;
  uint64_t mydev;
  uint64_t myino;

  msize = ntohs (message->size);
  if ((msize <= sizeof (struct IndexStartMessage)) ||
      (((const char *) message)[msize - 1] != '\0'))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  ism = (const struct IndexStartMessage *) message;
  if (0 != ism->reserved)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  fn = GNUNET_STRINGS_filename_expand ((const char *) &ism[1]);
  if (fn == NULL)
  {
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  dev = GNUNET_ntohll (ism->device);
  ino = GNUNET_ntohll (ism->inode);
  ism = (const struct IndexStartMessage *) message;
  slen = strlen (fn) + 1;
  ii = GNUNET_malloc (sizeof (struct IndexInfo) + slen);
  ii->filename = (const char *) &ii[1];
  memcpy (&ii[1], fn, slen);
  ii->file_id = ism->file_id;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message for file `%s'\n",
              "START_INDEX", ii->filename);
  ii->tc = GNUNET_SERVER_transmit_context_create (client);
  mydev = 0;
  myino = 0;
  if (((dev != 0) || (ino != 0)) &&
      (GNUNET_OK == GNUNET_DISK_file_get_identifiers (fn, &mydev, &myino)) &&
      ((dev == mydev) && (ino == myino)))
  {
    /* fast validation OK! */
    signal_index_ok (ii);
    GNUNET_free (fn);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Mismatch in file identifiers (%llu != %llu or %u != %u), need to hash.\n",
              (unsigned long long) ino, (unsigned long long) myino,
              (unsigned int) dev, (unsigned int) mydev);
  /* slow validation, need to hash full file (again) */
  ii->fhc =
      GNUNET_CRYPTO_hash_file (GNUNET_SCHEDULER_PRIORITY_IDLE, fn,
                               HASHING_BLOCKSIZE, &hash_for_index_val, ii);
  if (ii->fhc == NULL)
    hash_for_index_val (ii, NULL);
  GNUNET_free (fn);
}


/**
 * Handle INDEX_LIST_GET-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
void
GNUNET_FS_handle_index_list_get (void *cls, struct GNUNET_SERVER_Client *client,
                                 const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVER_TransmitContext *tc;
  struct IndexInfoMessage *iim;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1] GNUNET_ALIGN;
  size_t slen;
  const char *fn;
  struct IndexInfo *pos;

  tc = GNUNET_SERVER_transmit_context_create (client);
  iim = (struct IndexInfoMessage *) buf;
  for (pos = indexed_files_head; NULL != pos; pos = pos->next)
  {
    fn = pos->filename;
    slen = strlen (fn) + 1;
    if (slen + sizeof (struct IndexInfoMessage) >=
        GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      break;
    }
    iim->header.type = htons (GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_ENTRY);
    iim->header.size = htons (slen + sizeof (struct IndexInfoMessage));
    iim->reserved = 0;
    iim->file_id = pos->file_id;
    memcpy (&iim[1], fn, slen);
    GNUNET_SERVER_transmit_context_append_message (tc, &iim->header);
  }
  GNUNET_SERVER_transmit_context_append_data (tc, NULL, 0,
                                              GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_END);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_MINUTES);
}


/**
 * Handle UNINDEX-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
void
GNUNET_FS_handle_unindex (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
  const struct UnindexMessage *um;
  struct IndexInfo *pos;
  struct GNUNET_SERVER_TransmitContext *tc;
  int found;

  um = (const struct UnindexMessage *) message;
  if (0 != um->reserved)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  found = GNUNET_NO;
  for (pos = indexed_files_head; NULL != pos; pos = pos->next)
  {
    if (0 == memcmp (&pos->file_id, &um->file_id, sizeof (struct GNUNET_HashCode)))
    {
      GNUNET_CONTAINER_DLL_remove (indexed_files_head,
				   indexed_files_tail,
				   pos);
      GNUNET_break (GNUNET_OK ==
                    GNUNET_CONTAINER_multihashmap_remove (ifm, &pos->file_id,
							  pos));
      GNUNET_free (pos);
      found = GNUNET_YES;
      break;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client requested unindexing of file `%s': %s\n",
              GNUNET_h2s (&um->file_id), found ? "found" : "not found");
  if (GNUNET_YES == found)
    write_index_list ();
  tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_SERVER_transmit_context_append_data (tc, NULL, 0,
                                              GNUNET_MESSAGE_TYPE_FS_UNINDEX_OK);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_MINUTES);
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
remove_cont (void *cls, int success,
	     struct GNUNET_TIME_Absolute min_expiration,
	     const char *msg)
{
  if (GNUNET_OK != success)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to delete bogus block: %s\n"), msg);
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
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 * @param cont function to call with the actual block (at most once, on success)
 * @param cont_cls closure for cont
 * @return GNUNET_OK on success
 */
int
GNUNET_FS_handle_on_demand_block (const struct GNUNET_HashCode * key, uint32_t size,
                                  const void *data, enum GNUNET_BLOCK_Type type,
                                  uint32_t priority, uint32_t anonymity,
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

  if (size != sizeof (struct OnDemandBlock))
  {
    GNUNET_break (0);
    GNUNET_DATASTORE_remove (dsh, key, size, data, -1, -1,
                             GNUNET_TIME_UNIT_FOREVER_REL, &remove_cont, NULL);
    return GNUNET_SYSERR;
  }
  odb = (const struct OnDemandBlock *) data;
  off = GNUNET_ntohll (odb->offset);
  ii = GNUNET_CONTAINER_multihashmap_get (ifm, &odb->file_id);
  if (NULL == ii)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  fn = ii->filename;
  if ((NULL == fn) || (0 != ACCESS (fn, R_OK)))
  {
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# index blocks removed: original file inaccessible"),
                              1, GNUNET_YES);
    GNUNET_DATASTORE_remove (dsh, key, size, data, -1, -1,
                             GNUNET_TIME_UNIT_FOREVER_REL, &remove_cont, NULL);
    return GNUNET_SYSERR;
  }
  if ((NULL ==
       (fh =
        GNUNET_DISK_file_open (fn, GNUNET_DISK_OPEN_READ,
                               GNUNET_DISK_PERM_NONE))) ||
      (off != GNUNET_DISK_file_seek (fh, off, GNUNET_DISK_SEEK_SET)) ||
      (-1 == (nsize = GNUNET_DISK_file_read (fh, ndata, sizeof (ndata)))))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Could not access indexed file `%s' (%s) at offset %llu: %s\n"),
                GNUNET_h2s (&odb->file_id), fn, (unsigned long long) off,
                (fn == NULL) ? _("not indexed") : STRERROR (errno));
    if (fh != NULL)
      GNUNET_DISK_file_close (fh);
    GNUNET_DATASTORE_remove (dsh, key, size, data, -1, -1,
                             GNUNET_TIME_UNIT_FOREVER_REL, &remove_cont, NULL);
    return GNUNET_SYSERR;
  }
  GNUNET_DISK_file_close (fh);
  GNUNET_CRYPTO_hash (ndata, nsize, &nkey);
  GNUNET_CRYPTO_hash_to_aes_key (&nkey, &skey, &iv);
  GNUNET_CRYPTO_symmetric_encrypt (ndata, nsize, &skey, &iv, edata);
  GNUNET_CRYPTO_hash (edata, nsize, &query);
  if (0 != memcmp (&query, key, sizeof (struct GNUNET_HashCode)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Indexed file `%s' changed at offset %llu\n"), fn,
                (unsigned long long) off);
    GNUNET_DATASTORE_remove (dsh, key, size, data, -1, -1,
                             GNUNET_TIME_UNIT_FOREVER_REL, &remove_cont, NULL);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "On-demand encoded block for query `%s'\n", GNUNET_h2s (key));
  cont (cont_cls, key, nsize, edata, GNUNET_BLOCK_TYPE_FS_DBLOCK, priority,
        anonymity, expiration, uid);
  return GNUNET_OK;
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
    GNUNET_CONTAINER_DLL_remove (indexed_files_head,
				 indexed_files_tail,
				 pos);
    if (pos->fhc != NULL)
      GNUNET_CRYPTO_hash_file_cancel (pos->fhc);
    GNUNET_break (GNUNET_OK ==
		  GNUNET_CONTAINER_multihashmap_remove (ifm,
							&pos->file_id, pos));
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
