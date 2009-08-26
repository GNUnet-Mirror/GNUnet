/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_publish.c
 * @brief publish a file or directory in GNUnet
 * @see http://gnunet.org/encoding.php3
 * @author Krista Bennett
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "fs.h"

#define DEBUG_PUBLISH GNUNET_YES


/**
 * Main function that performs the upload.
 * @param cls "struct GNUNET_FS_PublishContext" identifies the upload
 * @param tc task context
 */
static void
do_upload (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_PublishContext *sc = cls;

  sc->upload_task = GNUNET_SCHEDULER_NO_TASK;  

  // FIXME: find next block, process, schedule
  // transmission to FS service
}


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
			 struct GNUNET_FS_FileInformation *fi,
			 struct GNUNET_FS_Namespace *namespace,
			 const char *nid,
			 const char *nuid)
{
  struct GNUNET_FS_PublishContext *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_PublishContext));
  ret->h = h;
  ret->client_ctx = ctx;
  ret->fi = fi;
  ret->namespace = namespace;
  if (namespace != NULL)
    {
      namespace->rc++;
      GNUNET_assert (NULL != nid);
      ret->nid = GNUNET_strdup (nid);
      if (NULL != nuid)
	ret->nuid = GNUNET_strdup (nuid);
    }
  // FIXME: make upload persistent!
  ret->upload_task 
    = GNUNET_SCHEDULER_add_delayed (h->sched,
				    GNUNET_NO,
				    GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
				    GNUNET_SCHEDULER_NO_TASK,
				    GNUNET_TIME_UNIT_ZERO,
				    &do_upload,
				    ret);
  return ret;
}


/**
 * Stop an upload.  Will abort incomplete uploads (but 
 * not remove blocks that have already been publishd) or
 * simply clean up the state for completed uploads.
 *
 * @param sc context for the upload to stop
 */
void 
GNUNET_FS_publish_stop (struct GNUNET_FS_PublishContext *sc)
{
  if (GNUNET_SCHEDULER_NO_TASK != sc->upload_task)
    GNUNET_SCHEDULER_cancel (sc->h->sched, sc->upload_task);
  // FIXME: remove from persistence DB (?) --- think more about
  //        shutdown / persistent-resume APIs!!!
  GNUNET_FS_file_information_destroy (sc->fi, NULL, NULL);
  GNUNET_FS_namespace_delete (sc->namespace, GNUNET_NO);
  GNUNET_free_non_null (sc->nid);  
  GNUNET_free_non_null (sc->nuid);
  GNUNET_free (sc);
}


#if 0

/**
 * Append the given key and query to the iblock[level].  If
 * iblock[level] is already full, compute its chk and push it to
 * level+1 and clear the level.  iblocks is guaranteed to be big
 * enough.
 */
static int
pushBlock (struct GNUNET_ClientServerConnection *sock,
           const GNUNET_EC_ContentHashKey * chk,
           unsigned int level,
           GNUNET_DatastoreValue ** iblocks,
           unsigned int prio, GNUNET_CronTime expirationTime)
{
  unsigned int size;
  unsigned int present;
  GNUNET_DatastoreValue *value;
  GNUNET_EC_DBlock *db;
  GNUNET_EC_ContentHashKey ichk;

  size = ntohl (iblocks[level]->size);
  GNUNET_GE_ASSERT (NULL, size > sizeof (GNUNET_DatastoreValue));
  size -= sizeof (GNUNET_DatastoreValue);
  GNUNET_GE_ASSERT (NULL,
                    size - sizeof (GNUNET_EC_DBlock) <=
                    GNUNET_ECRS_IBLOCK_SIZE);
  present =
    (size - sizeof (GNUNET_EC_DBlock)) / sizeof (GNUNET_EC_ContentHashKey);
  db = (GNUNET_EC_DBlock *) & iblocks[level][1];
  if (present == GNUNET_ECRS_CHK_PER_INODE)
    {
      GNUNET_EC_file_block_get_key (db, size, &ichk.key);
      GNUNET_EC_file_block_get_query (db, size, &ichk.query);
      if (GNUNET_OK != pushBlock (sock,
                                  &ichk, level + 1, iblocks, prio,
                                  expirationTime))
        return GNUNET_SYSERR;
      GNUNET_EC_file_block_encode (db, size, &ichk.query, &value);
      if (value == NULL)
        {
          GNUNET_GE_BREAK (NULL, 0);
          return GNUNET_SYSERR;
        }
      value->priority = htonl (prio);
      value->expiration_time = GNUNET_htonll (expirationTime);
      if (GNUNET_OK != GNUNET_FS_insert (sock, value))
        {
          GNUNET_free (value);
          return GNUNET_SYSERR;
        }
      GNUNET_free (value);
      size = sizeof (GNUNET_EC_DBlock); /* type */
    }
  /* append GNUNET_EC_ContentHashKey */
  memcpy (&((char *) db)[size], chk, sizeof (GNUNET_EC_ContentHashKey));
  size += sizeof (GNUNET_EC_ContentHashKey) + sizeof (GNUNET_DatastoreValue);
  GNUNET_GE_ASSERT (NULL, size < GNUNET_MAX_BUFFER_SIZE);
  iblocks[level]->size = htonl (size);

  return GNUNET_OK;
}

/**
 * Index or insert a file.
 *
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param doIndex GNUNET_YES for index, GNUNET_NO for insertion,
 *         GNUNET_SYSERR for simulation
 * @param uri set to the URI of the uploaded file
 * @return GNUNET_SYSERR if the upload failed (i.e. not enough space
 *  or gnunetd not running)
 */
int
GNUNET_ECRS_file_upload (struct GNUNET_GE_Context *ectx,
                         struct GNUNET_GC_Configuration *cfg,
                         const char *filename,
                         int doIndex,
                         unsigned int anonymityLevel,
                         unsigned int priority,
                         GNUNET_CronTime expirationTime,
                         GNUNET_ECRS_UploadProgressCallback upcb,
                         void *upcbClosure,
                         GNUNET_ECRS_TestTerminate tt,
                         void *ttClosure, struct GNUNET_ECRS_URI **uri)
{
  unsigned long long filesize;
  unsigned long long pos;
  unsigned int treedepth;
  int fd;
  int i;
  int ret;
  unsigned int size;
  GNUNET_DatastoreValue **iblocks;
  GNUNET_DatastoreValue *dblock;
  GNUNET_EC_DBlock *db;
  GNUNET_DatastoreValue *value;
  struct GNUNET_ClientServerConnection *sock;
  GNUNET_HashCode fileId;
  GNUNET_EC_ContentHashKey mchk;
  GNUNET_CronTime eta;
  GNUNET_CronTime start;
  GNUNET_CronTime now;
  GNUNET_EC_FileIdentifier fid;
#if DEBUG_UPLOAD
  GNUNET_EncName enc;
#endif

  GNUNET_GE_ASSERT (ectx, cfg != NULL);
  start = GNUNET_get_time ();
  memset (&mchk, 0, sizeof (GNUNET_EC_ContentHashKey));
  if (GNUNET_YES != GNUNET_disk_file_test (ectx, filename))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' is not a file.\n"), filename);
      return GNUNET_SYSERR;
    }
  if (GNUNET_OK !=
      GNUNET_disk_file_size (ectx, filename, &filesize, GNUNET_YES))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Cannot get size of file `%s'"), filename);

      return GNUNET_SYSERR;
    }
  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Failed to connect to gnunetd."));
      return GNUNET_SYSERR;
    }
  eta = 0;
  if (upcb != NULL)
    upcb (filesize, 0, eta, upcbClosure);
  if (doIndex == GNUNET_YES)
    {
      if (GNUNET_SYSERR == GNUNET_hash_file (ectx, filename, &fileId))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("Cannot hash `%s'.\n"), filename);

          GNUNET_client_connection_destroy (sock);
          return GNUNET_SYSERR;
        }
      if (GNUNET_YES == GNUNET_FS_test_indexed (sock, &fileId))
        {
          /* file already indexed; simulate only to get the URI! */
          doIndex = GNUNET_SYSERR;
        }
    }
  if (doIndex == GNUNET_YES)
    {
      now = GNUNET_get_time ();
      eta = now + 2 * (now - start);
      /* very rough estimate: GNUNET_hash reads once through the file,
         we'll do that once more and write it.  But of course
         the second read may be cached, and we have the encryption,
         so a factor of two is really, really just a rough estimate */
      start = now;
      /* reset the counter since the formula later does not
         take the time for GNUNET_hash_file into account */

      switch (GNUNET_FS_prepare_to_index (sock, &fileId, filename))
        {
        case GNUNET_SYSERR:
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("Initialization for indexing file `%s' failed.\n"),
                         filename);
          GNUNET_client_connection_destroy (sock);
          return GNUNET_SYSERR;
        case GNUNET_NO:
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _
                         ("Indexing file `%s' failed. Suggestion: try to insert the file.\n"),
                         filename);
          GNUNET_client_connection_destroy (sock);
          return GNUNET_SYSERR;
        default:
          break;
        }
    }
  treedepth = GNUNET_ECRS_compute_depth (filesize);
  fd = GNUNET_disk_file_open (ectx, filename, O_RDONLY | O_LARGEFILE);
  if (fd == -1)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Cannot open file `%s': `%s'"), filename,
                     STRERROR (errno));

      GNUNET_client_connection_destroy (sock);
      return GNUNET_SYSERR;
    }

  dblock =
    GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + GNUNET_ECRS_DBLOCK_SIZE +
                   sizeof (GNUNET_EC_DBlock));
  dblock->size =
    htonl (sizeof (GNUNET_DatastoreValue) + GNUNET_ECRS_DBLOCK_SIZE +
           sizeof (GNUNET_EC_DBlock));
  dblock->anonymity_level = htonl (anonymityLevel);
  dblock->priority = htonl (priority);
  dblock->type = htonl (GNUNET_ECRS_BLOCKTYPE_DATA);
  dblock->expiration_time = GNUNET_htonll (expirationTime);
  db = (GNUNET_EC_DBlock *) & dblock[1];
  db->type = htonl (GNUNET_ECRS_BLOCKTYPE_DATA);
  iblocks =
    GNUNET_malloc (sizeof (GNUNET_DatastoreValue *) * (treedepth + 1));
  for (i = 0; i <= treedepth; i++)
    {
      iblocks[i] =
        GNUNET_malloc (sizeof (GNUNET_DatastoreValue) +
                       GNUNET_ECRS_IBLOCK_SIZE + sizeof (GNUNET_EC_DBlock));
      iblocks[i]->size =
        htonl (sizeof (GNUNET_DatastoreValue) + sizeof (GNUNET_EC_DBlock));
      iblocks[i]->anonymity_level = htonl (anonymityLevel);
      iblocks[i]->priority = htonl (priority);
      iblocks[i]->type = htonl (GNUNET_ECRS_BLOCKTYPE_DATA);
      iblocks[i]->expiration_time = GNUNET_htonll (expirationTime);
      ((GNUNET_EC_DBlock *) & iblocks[i][1])->type =
        htonl (GNUNET_ECRS_BLOCKTYPE_DATA);
    }

  pos = 0;
  while (pos < filesize)
    {
      if (upcb != NULL)
        upcb (filesize, pos, eta, upcbClosure);
      if (tt != NULL)
        if (GNUNET_OK != tt (ttClosure))
          goto FAILURE;
      size = GNUNET_ECRS_DBLOCK_SIZE;
      if (size > filesize - pos)
        {
          size = filesize - pos;
          memset (&db[1], 0, GNUNET_ECRS_DBLOCK_SIZE);
        }
      GNUNET_GE_ASSERT (ectx,
                        sizeof (GNUNET_DatastoreValue) + size +
                        sizeof (GNUNET_EC_DBlock) < GNUNET_MAX_BUFFER_SIZE);
      dblock->size =
        htonl (sizeof (GNUNET_DatastoreValue) + size +
               sizeof (GNUNET_EC_DBlock));
      if (size != READ (fd, &db[1], size))
        {
          GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                       GNUNET_GE_ERROR | GNUNET_GE_BULK |
                                       GNUNET_GE_ADMIN | GNUNET_GE_USER,
                                       "READ", filename);
          goto FAILURE;
        }
      if (tt != NULL)
        if (GNUNET_OK != tt (ttClosure))
          goto FAILURE;
      GNUNET_EC_file_block_get_key (db, size + sizeof (GNUNET_EC_DBlock),
                                    &mchk.key);
      GNUNET_EC_file_block_get_query (db, size + sizeof (GNUNET_EC_DBlock),
                                      &mchk.query);
#if DEBUG_UPLOAD
      GNUNET_hash_to_enc (&mchk.query, &enc);
      fprintf (stderr,
               "Query for current block of size %u is `%s'\n", size,
               (const char *) &enc);
#endif
      if (doIndex == GNUNET_YES)
        {
          if (GNUNET_SYSERR == GNUNET_FS_index (sock, &fileId, dblock, pos))
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_ERROR | GNUNET_GE_BULK |
                             GNUNET_GE_USER,
                             _
                             ("Indexing data of file `%s' failed at position %llu.\n"),
                             filename, pos);
              goto FAILURE;
            }
        }
      else
        {
          value = NULL;
          if (GNUNET_OK !=
              GNUNET_EC_file_block_encode (db,
                                           size + sizeof (GNUNET_EC_DBlock),
                                           &mchk.query, &value))
            {
              GNUNET_GE_BREAK (ectx, 0);
              goto FAILURE;
            }
          GNUNET_GE_ASSERT (ectx, value != NULL);
          *value = *dblock;     /* copy options! */
          if ((doIndex == GNUNET_NO) &&
              (GNUNET_OK != (ret = GNUNET_FS_insert (sock, value))))
            {
              GNUNET_GE_BREAK (ectx, ret == GNUNET_NO);
              GNUNET_free (value);
              goto FAILURE;
            }
          GNUNET_free (value);
        }
      pos += size;
      now = GNUNET_get_time ();
      if (pos > 0)
        {
          eta = (GNUNET_CronTime) (start +
                                   (((double) (now - start) / (double) pos))
                                   * (double) filesize);
        }
      if (GNUNET_OK != pushBlock (sock, &mchk, 0,       /* dblocks are on level 0 */
                                  iblocks, priority, expirationTime))
        goto FAILURE;
    }
  if (tt != NULL)
    if (GNUNET_OK != tt (ttClosure))
      goto FAILURE;
#if DEBUG_UPLOAD
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Tree depth is %u, walking up tree.\n", treedepth);
#endif
  for (i = 0; i < treedepth; i++)
    {
      size = ntohl (iblocks[i]->size) - sizeof (GNUNET_DatastoreValue);
      GNUNET_GE_ASSERT (ectx, size < GNUNET_MAX_BUFFER_SIZE);
      if (size == sizeof (GNUNET_EC_DBlock))
        {
#if DEBUG_UPLOAD
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "Level %u is empty\n", i);
#endif
          continue;
        }
      db = (GNUNET_EC_DBlock *) & iblocks[i][1];
      GNUNET_EC_file_block_get_key (db, size, &mchk.key);
#if DEBUG_UPLOAD
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Computing query for %u bytes content.\n", size);
#endif
      GNUNET_EC_file_block_get_query (db, size, &mchk.query);
#if DEBUG_UPLOAD
      IF_GELOG (ectx,
                GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                GNUNET_hash_to_enc (&mchk.query, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Query for current block at level %u is `%s'.\n", i,
                     &enc);
#endif
      if (GNUNET_OK != pushBlock (sock,
                                  &mchk, i + 1, iblocks, priority,
                                  expirationTime))
        {
          GNUNET_GE_BREAK (ectx, 0);
          goto FAILURE;
        }
      GNUNET_EC_file_block_encode (db, size, &mchk.query, &value);
      if (value == NULL)
        {
          GNUNET_GE_BREAK (ectx, 0);
          goto FAILURE;
        }
      value->expiration_time = GNUNET_htonll (expirationTime);
      value->priority = htonl (priority);
      if ((doIndex != GNUNET_SYSERR) &&
          (GNUNET_SYSERR == GNUNET_FS_insert (sock, value)))
        {
          GNUNET_GE_BREAK (ectx, 0);
          GNUNET_free (value);
          goto FAILURE;
        }
      GNUNET_free (value);
      GNUNET_free (iblocks[i]);
      iblocks[i] = NULL;
    }
#if DEBUG_UPLOAD
  IF_GELOG (ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&mchk.query, &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Query for top block is %s\n", &enc);
#endif
  /* build URI */
  fid.file_length = GNUNET_htonll (filesize);
  db = (GNUNET_EC_DBlock *) & iblocks[treedepth][1];

  fid.chk = *(GNUNET_EC_ContentHashKey *) & (db[1]);
  *uri = GNUNET_malloc (sizeof (URI));
  (*uri)->type = chk;
  (*uri)->data.fi = fid;

  /* free resources */
  GNUNET_free_non_null (iblocks[treedepth]);
  GNUNET_free (iblocks);
  GNUNET_free (dblock);
  if (upcb != NULL)
    upcb (filesize, filesize, eta, upcbClosure);
  CLOSE (fd);
  GNUNET_client_connection_destroy (sock);
  return GNUNET_OK;
FAILURE:
  for (i = 0; i <= treedepth; i++)
    GNUNET_free_non_null (iblocks[i]);
  GNUNET_free (iblocks);
  GNUNET_free (dblock);
  CLOSE (fd);
  GNUNET_client_connection_destroy (sock);
  return GNUNET_SYSERR;
}

#endif 

/* end of fs_publish.c */
