/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_unindex.c
 * @author Krista Bennett
 * @author Christian Grothoff
 * @brief Unindex file.
 *
 * TODO:
 * - code cleanup (share more with upload.c)
 */

#include "platform.h"
#include "gnunet_fs_service.h"
#include "fs.h"

/**
 * Iterate over all indexed files.
 *
 * @param h handle to the file sharing subsystem
 * @param iterator function to call on each indexed file
 * @param iterator_cls closure for iterator
 */
void 
GNUNET_FS_get_indexed_files (struct GNUNET_FS_Handle *h,
			     GNUNET_FS_IndexedFileProcessor iterator,
			     void *iterator_cls)
{
}


/**
 * Unindex a file.
 *
 * @param h handle to the file sharing subsystem
 * @param filename file to unindex
 * @return NULL on error, otherwise handle 
 */
struct GNUNET_FS_UnindexContext *
GNUNET_FS_unindex (struct GNUNET_FS_Handle *h,
		   const char *filename)
{
  return NULL;
}


/**
 * Clean up after completion of an unindex operation.
 *
 * @param uc handle
 */
void
GNUNET_FS_unindex_stop (struct GNUNET_FS_UnindexContext *uc)
{
}



#if 0

#define STRICT_CHECKS GNUNET_NO

/**
 * Append the given key and query to the iblock[level].
 * If iblock[level] is already full, compute its chk
 * and push it to level+1.  iblocks is guaranteed to
 * be big enough.
 *
 * This function matches exactly upload.c::pushBlock,
 * except in the call to 'GNUNET_FS_delete'.  TODO: refactor
 * to avoid code duplication (move to block.c, pass
 * GNUNET_FS_delete as argument!).
 */
static int
pushBlock (struct GNUNET_ClientServerConnection *sock,
           const GNUNET_EC_ContentHashKey * chk, unsigned int level,
           GNUNET_DatastoreValue ** iblocks)
{
  unsigned int size;
  unsigned int present;
  GNUNET_DatastoreValue *value;
  GNUNET_EC_DBlock *db;
  GNUNET_EC_ContentHashKey ichk;

  size = ntohl (iblocks[level]->size) - sizeof (GNUNET_DatastoreValue);
  present =
    (size - sizeof (GNUNET_EC_DBlock)) / sizeof (GNUNET_EC_ContentHashKey);
  db = (GNUNET_EC_DBlock *) & iblocks[level][1];
  if (present == GNUNET_ECRS_CHK_PER_INODE)
    {
      GNUNET_EC_file_block_get_key (db, size, &ichk.key);
      GNUNET_EC_file_block_get_query (db, size, &ichk.query);
      if (GNUNET_OK != pushBlock (sock, &ichk, level + 1, iblocks))
        {
          GNUNET_GE_BREAK (NULL, 0);
          return GNUNET_SYSERR;
        }
      GNUNET_EC_file_block_encode (db, size, &ichk.query, &value);
#if STRICT_CHECKS
      if (GNUNET_SYSERR == GNUNET_FS_delete (sock, value))
        {
          GNUNET_free (value);
          GNUNET_GE_BREAK (NULL, 0);
          return GNUNET_SYSERR;
        }
#else
      GNUNET_FS_delete (sock, value);
#endif
      GNUNET_free (value);
      size = sizeof (GNUNET_EC_DBlock);
    }
  /* append GNUNET_EC_ContentHashKey */
  memcpy (&((char *) db)[size], chk, sizeof (GNUNET_EC_ContentHashKey));
  iblocks[level]->size = htonl (size +
                                sizeof (GNUNET_EC_ContentHashKey) +
                                sizeof (GNUNET_DatastoreValue));
  return GNUNET_OK;
}



/**
 * Undo sym-linking operation:
 * a) check if we have a symlink
 * b) delete symbolic link
 */
static int
undoSymlinking (struct GNUNET_GE_Context *ectx,
                const char *fn,
                const GNUNET_HashCode * fileId,
                struct GNUNET_ClientServerConnection *sock)
{
  GNUNET_EncName enc;
  char *serverDir;
  char *serverFN;
  struct stat buf;

#ifndef S_ISLNK
  if (1)
    return GNUNET_OK;           /* symlinks do not exist? */
#endif
  if (0 != LSTAT (fn, &buf))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_BULK |
                                   GNUNET_GE_USER | GNUNET_GE_ADMIN, "stat",
                                   fn);
      return GNUNET_SYSERR;
    }
#ifdef S_ISLNK
  if (!S_ISLNK (buf.st_mode))
    return GNUNET_OK;
#endif
  serverDir =
    GNUNET_get_daemon_configuration_value (sock, "FS", "INDEX-DIRECTORY");
  if (serverDir == NULL)
    return GNUNET_OK;
  serverFN = GNUNET_malloc (strlen (serverDir) + 2 + sizeof (GNUNET_EncName));
  strcpy (serverFN, serverDir);
  GNUNET_free (serverDir);
  if (serverFN[strlen (serverFN) - 1] != DIR_SEPARATOR)
    strcat (serverFN, DIR_SEPARATOR_STR);
  GNUNET_hash_to_enc (fileId, &enc);
  strcat (serverFN, (char *) &enc);

  if (0 != UNLINK (serverFN))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_BULK |
                                   GNUNET_GE_USER | GNUNET_GE_ADMIN, "unlink",
                                   serverFN);
      GNUNET_free (serverFN);
      return GNUNET_SYSERR;
    }
  GNUNET_free (serverFN);
  return GNUNET_OK;
}



/**
 * Unindex a file.
 *
 * @return GNUNET_SYSERR if the unindexing failed (i.e. not indexed)
 */
int
GNUNET_ECRS_file_unindex (struct GNUNET_GE_Context *ectx,
                          struct GNUNET_GC_Configuration *cfg,
                          const char *filename,
                          GNUNET_ECRS_UploadProgressCallback upcb,
                          void *upcbClosure, GNUNET_ECRS_TestTerminate tt,
                          void *ttClosure)
{
  unsigned long long filesize;
  unsigned long long pos;
  unsigned int treedepth;
  int fd;
  int i;
  unsigned int size;
  GNUNET_DatastoreValue **iblocks;
  GNUNET_DatastoreValue *dblock;
  GNUNET_EC_DBlock *db;
  GNUNET_DatastoreValue *value;
  struct GNUNET_ClientServerConnection *sock;
  GNUNET_HashCode fileId;
  GNUNET_EC_ContentHashKey chk;
  GNUNET_CronTime eta;
  GNUNET_CronTime start;
  GNUNET_CronTime now;
  int wasIndexed;

  start = GNUNET_get_time ();
  if (GNUNET_YES != GNUNET_disk_file_test (ectx, filename))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  if (GNUNET_OK !=
      GNUNET_disk_file_size (ectx, filename, &filesize, GNUNET_YES))
    return GNUNET_SYSERR;
  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    return GNUNET_SYSERR;
  eta = 0;
  if (upcb != NULL)
    upcb (filesize, 0, eta, upcbClosure);
  if (GNUNET_SYSERR == GNUNET_hash_file (ectx, filename, &fileId))
    {
      GNUNET_client_connection_destroy (sock);
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  now = GNUNET_get_time ();
  eta = now + 2 * (now - start);
  /* very rough estimate: GNUNET_hash reads once through the file,
     we'll do that once more and write it.  But of course
     the second read may be cached, and we have the encryption,
     so a factor of two is really, really just a rough estimate */
  start = now;
  /* reset the counter since the formula later does not
     take the time for GNUNET_hash_file into account */
  treedepth = GNUNET_ECRS_compute_depth (filesize);

  /* Test if file is indexed! */
  wasIndexed = GNUNET_FS_test_indexed (sock, &fileId);

  fd = GNUNET_disk_file_open (ectx, filename, O_RDONLY | O_LARGEFILE);
  if (fd == -1)
    {
      GNUNET_client_connection_destroy (sock);
      return GNUNET_SYSERR;
    }
  dblock =
    GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + GNUNET_ECRS_DBLOCK_SIZE +
                   sizeof (GNUNET_EC_DBlock));
  dblock->size =
    htonl (sizeof (GNUNET_DatastoreValue) + GNUNET_ECRS_DBLOCK_SIZE +
           sizeof (GNUNET_EC_DBlock));
  dblock->anonymity_level = htonl (0);
  dblock->priority = htonl (0);
  dblock->type = htonl (GNUNET_ECRS_BLOCKTYPE_DATA);
  dblock->expiration_time = GNUNET_htonll (0);
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
      iblocks[i]->anonymity_level = htonl (0);
      iblocks[i]->priority = htonl (0);
      iblocks[i]->type = htonl (GNUNET_ECRS_BLOCKTYPE_DATA);
      iblocks[i]->expiration_time = GNUNET_htonll (0);
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
      dblock->size =
        htonl (sizeof (GNUNET_DatastoreValue) + size +
               sizeof (GNUNET_EC_DBlock));
      if (size != READ (fd, &db[1], size))
        {
          GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                       GNUNET_GE_ERROR | GNUNET_GE_USER |
                                       GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                                       "READ", filename);
          goto FAILURE;
        }
      if (tt != NULL)
        if (GNUNET_OK != tt (ttClosure))
          goto FAILURE;
      GNUNET_EC_file_block_get_key (db, size + sizeof (GNUNET_EC_DBlock),
                                    &chk.key);
      GNUNET_EC_file_block_get_query (db, size + sizeof (GNUNET_EC_DBlock),
                                      &chk.query);
      if (GNUNET_OK != pushBlock (sock, &chk, 0,        /* dblocks are on level 0 */
                                  iblocks))
        {
          GNUNET_GE_BREAK (ectx, 0);
          goto FAILURE;
        }
      if (!wasIndexed)
        {
          if (GNUNET_OK ==
              GNUNET_EC_file_block_encode (db, size, &chk.query, &value))
            {
              *value = *dblock; /* copy options! */
#if STRICT_CHECKS
              if (GNUNET_OK != GNUNET_FS_delete (sock, value))
                {
                  GNUNET_free (value);
                  GNUNET_GE_BREAK (ectx, 0);
                  goto FAILURE;
                }
#else
              GNUNET_FS_delete (sock, value);
#endif
              GNUNET_free (value);
            }
          else
            {
              goto FAILURE;
            }
        }
      pos += size;
      now = GNUNET_get_time ();
      eta = (GNUNET_CronTime) (start +
                               (((double) (now - start) / (double) pos))
                               * (double) filesize);
    }
  if (tt != NULL)
    if (GNUNET_OK != tt (ttClosure))
      goto FAILURE;
  for (i = 0; i < treedepth; i++)
    {
      size = ntohl (iblocks[i]->size) - sizeof (GNUNET_DatastoreValue);
      db = (GNUNET_EC_DBlock *) & iblocks[i][1];
      GNUNET_EC_file_block_get_key (db, size, &chk.key);
      GNUNET_EC_file_block_get_query (db, size, &chk.query);
      if (GNUNET_OK != pushBlock (sock, &chk, i + 1, iblocks))
        {
          GNUNET_GE_BREAK (ectx, 0);
          goto FAILURE;
        }
      GNUNET_EC_file_block_encode (db, size, &chk.query, &value);
#if STRICT_CHECKS
      if (GNUNET_OK != GNUNET_FS_delete (sock, value))
        {
          GNUNET_free (value);
          GNUNET_GE_BREAK (ectx, 0);
          goto FAILURE;
        }
#else
      GNUNET_FS_delete (sock, value);
#endif
      GNUNET_free (value);
      GNUNET_free (iblocks[i]);
      iblocks[i] = NULL;
    }

  if (wasIndexed)
    {
      if (GNUNET_OK == undoSymlinking (ectx, filename, &fileId, sock))
        {
          if (GNUNET_OK !=
              GNUNET_FS_unindex (sock, GNUNET_ECRS_DBLOCK_SIZE, &fileId))
            {
              GNUNET_GE_BREAK (ectx, 0);
              goto FAILURE;
            }
        }
      else
        {
          GNUNET_GE_BREAK (ectx, 0);
          goto FAILURE;
        }
    }
  GNUNET_free (iblocks[treedepth]);
  /* free resources */
  GNUNET_free (iblocks);
  GNUNET_free (dblock);
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

/* end of fs_unindex.c */
