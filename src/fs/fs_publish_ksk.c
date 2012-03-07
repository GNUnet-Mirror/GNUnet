/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2012 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file fs/fs_publish_ksk.c
 * @brief publish a URI under a keyword in GNUnet
 * @see https://gnunet.org/encoding
 * @author Krista Bennett
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "fs_api.h"
#include "fs_tree.h"


/**
 * Maximum legal size for a kblock.
 */
#define MAX_KBLOCK_SIZE (60 * 1024)


/**
 * Context for the KSK publication.
 */
struct GNUNET_FS_PublishKskContext
{

  /**
   * Keywords to use.
   */
  struct GNUNET_FS_Uri *ksk_uri;

  /**
   * Global FS context.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * The master block that we are sending
   * (in plaintext), has "mdsize+slen" more
   * bytes than the struct would suggest.
   */
  struct KBlock *kb;

  /**
   * Buffer of the same size as "kb" for
   * the encrypted version.
   */
  struct KBlock *cpy;

  /**
   * Handle to the datastore, NULL if we are just
   * simulating.
   */
  struct GNUNET_DATASTORE_Handle *dsh;

  /**
   * Handle to datastore PUT request.
   */
  struct GNUNET_DATASTORE_QueueEntry *qre;

  /**
   * Current task.
   */
  GNUNET_SCHEDULER_TaskIdentifier ksk_task;

  /**
   * Function to call once we're done.
   */
  GNUNET_FS_PublishContinuation cont;

  /**
   * Closure for cont.
   */
  void *cont_cls;

  /**
   * When should the KBlocks expire?
   */
  struct GNUNET_FS_BlockOptions bo;

  /**
   * Size of the serialized metadata.
   */
  ssize_t mdsize;

  /**
   * Size of the (CHK) URI as a string.
   */
  size_t slen;

  /**
   * Keyword that we are currently processing.
   */
  unsigned int i;

};


/**
 * Continuation of "GNUNET_FS_publish_ksk" that performs
 * the actual publishing operation (iterating over all
 * of the keywords).
 *
 * @param cls closure of type "struct PublishKskContext*"
 * @param tc unused
 */
static void
publish_ksk_cont (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function called by the datastore API with
 * the result from the PUT request.
 *
 * @param cls closure of type "struct GNUNET_FS_PublishKskContext*"
 * @param success GNUNET_OK on success
 * @param min_expiration minimum expiration time required for content to be stored
 * @param msg error message (or NULL)
 */
static void
kb_put_cont (void *cls, int success, 
	     struct GNUNET_TIME_Absolute min_expiration,
	     const char *msg)
{
  struct GNUNET_FS_PublishKskContext *pkc = cls;

  pkc->qre = NULL;
  if (GNUNET_OK != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"KBlock PUT operation failed: %s\n", msg);
    pkc->cont (pkc->cont_cls, NULL, msg);
    GNUNET_FS_publish_ksk_cancel (pkc);
    return;
  }
  pkc->ksk_task = GNUNET_SCHEDULER_add_now (&publish_ksk_cont, pkc);
}


/**
 * Continuation of "GNUNET_FS_publish_ksk" that performs the actual
 * publishing operation (iterating over all of the keywords).
 *
 * @param cls closure of type "struct GNUNET_FS_PublishKskContext*"
 * @param tc unused
 */
static void
publish_ksk_cont (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_PublishKskContext *pkc = cls;
  const char *keyword;
  GNUNET_HashCode key;
  GNUNET_HashCode query;
  struct GNUNET_CRYPTO_AesSessionKey skey;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  struct GNUNET_CRYPTO_RsaPrivateKey *pk;

  pkc->ksk_task = GNUNET_SCHEDULER_NO_TASK;
  if ((pkc->i == pkc->ksk_uri->data.ksk.keywordCount) || (NULL == pkc->dsh))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "KSK PUT operation complete\n");
    pkc->cont (pkc->cont_cls, pkc->ksk_uri, NULL);
    GNUNET_FS_publish_ksk_cancel (pkc);
    return;
  }
  keyword = pkc->ksk_uri->data.ksk.keywords[pkc->i++];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Publishing under keyword `%s'\n",
              &keyword[1]);
  /* first character of keyword indicates if it is
   * mandatory or not -- ignore for hashing */
  GNUNET_CRYPTO_hash (&keyword[1], strlen (&keyword[1]), &key);
  GNUNET_CRYPTO_hash_to_aes_key (&key, &skey, &iv);
  GNUNET_CRYPTO_aes_encrypt (&pkc->kb[1], pkc->slen + pkc->mdsize, &skey, &iv,
                             &pkc->cpy[1]);
  pk = GNUNET_CRYPTO_rsa_key_create_from_hash (&key);
  GNUNET_assert (NULL != pk);
  GNUNET_CRYPTO_rsa_key_get_public (pk, &pkc->cpy->keyspace);
  GNUNET_CRYPTO_hash (&pkc->cpy->keyspace,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &query);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_sign (pk, &pkc->cpy->purpose,
                                         &pkc->cpy->signature));
  GNUNET_CRYPTO_rsa_key_free (pk);
  pkc->qre =
      GNUNET_DATASTORE_put (pkc->dsh, 0, &query,
                            pkc->mdsize + sizeof (struct KBlock) + pkc->slen,
                            pkc->cpy, GNUNET_BLOCK_TYPE_FS_KBLOCK,
                            pkc->bo.content_priority, pkc->bo.anonymity_level,
                            pkc->bo.replication_level, pkc->bo.expiration_time,
                            -2, 1, GNUNET_CONSTANTS_SERVICE_TIMEOUT,
                            &kb_put_cont, pkc);
}


/**
 * Publish a CHK under various keywords on GNUnet.
 *
 * @param h handle to the file sharing subsystem
 * @param ksk_uri keywords to use
 * @param meta metadata to use
 * @param uri URI to refer to in the KBlock
 * @param bo per-block options
 * @param options publication options
 * @param cont continuation
 * @param cont_cls closure for cont
 * @return NULL on error ('cont' will still be called)
 */
struct GNUNET_FS_PublishKskContext *
GNUNET_FS_publish_ksk (struct GNUNET_FS_Handle *h,
                       const struct GNUNET_FS_Uri *ksk_uri,
                       const struct GNUNET_CONTAINER_MetaData *meta,
                       const struct GNUNET_FS_Uri *uri,
                       const struct GNUNET_FS_BlockOptions *bo,
                       enum GNUNET_FS_PublishOptions options,
                       GNUNET_FS_PublishContinuation cont, void *cont_cls)
{
  struct GNUNET_FS_PublishKskContext *pkc;
  char *uris;
  size_t size;
  char *kbe;
  char *sptr;

  GNUNET_assert (NULL != uri);
  pkc = GNUNET_malloc (sizeof (struct GNUNET_FS_PublishKskContext));
  pkc->h = h;
  pkc->bo = *bo;
  pkc->cont = cont;
  pkc->cont_cls = cont_cls;
  if (0 == (options & GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY))
  {
    pkc->dsh = GNUNET_DATASTORE_connect (h->cfg);
    if (NULL == pkc->dsh)
    {
      cont (cont_cls, NULL, _("Could not connect to datastore."));
      GNUNET_free (pkc);
      return NULL;
    }
  }
  if (meta == NULL)
    pkc->mdsize = 0;
  else
    pkc->mdsize = GNUNET_CONTAINER_meta_data_get_serialized_size (meta);
  GNUNET_assert (pkc->mdsize >= 0);
  uris = GNUNET_FS_uri_to_string (uri);
  pkc->slen = strlen (uris) + 1;
  size = pkc->mdsize + sizeof (struct KBlock) + pkc->slen;
  if (size > MAX_KBLOCK_SIZE)
  {
    size = MAX_KBLOCK_SIZE;
    pkc->mdsize = size - sizeof (struct KBlock) - pkc->slen;
  }
  pkc->kb = GNUNET_malloc (size);
  kbe = (char *) &pkc->kb[1];
  memcpy (kbe, uris, pkc->slen);
  GNUNET_free (uris);
  sptr = &kbe[pkc->slen];
  if (meta != NULL)
    pkc->mdsize =
        GNUNET_CONTAINER_meta_data_serialize (meta, &sptr, pkc->mdsize,
                                              GNUNET_CONTAINER_META_DATA_SERIALIZE_PART);
  if (-1 == pkc->mdsize)
  {
    GNUNET_break (0);
    GNUNET_free (pkc->kb);
    if (pkc->dsh != NULL)
    {
      GNUNET_DATASTORE_disconnect (pkc->dsh, GNUNET_NO);
      pkc->dsh = NULL;
    }
    GNUNET_free (pkc);
    cont (cont_cls, NULL, _("Internal error."));
    return NULL;
  }
  size = sizeof (struct KBlock) + pkc->slen + pkc->mdsize;

  pkc->cpy = GNUNET_malloc (size);
  pkc->cpy->purpose.size =
      htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
             sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) +
             pkc->mdsize + pkc->slen);
  pkc->cpy->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_FS_KBLOCK);
  pkc->ksk_uri = GNUNET_FS_uri_dup (ksk_uri);
  pkc->ksk_task = GNUNET_SCHEDULER_add_now (&publish_ksk_cont, pkc);
  return pkc;
}


/**
 * Abort the KSK publishing operation.
 *
 * @param pkc context of the operation to abort.
 */
void
GNUNET_FS_publish_ksk_cancel (struct GNUNET_FS_PublishKskContext *pkc)
{
  if (GNUNET_SCHEDULER_NO_TASK != pkc->ksk_task)
  {
    GNUNET_SCHEDULER_cancel (pkc->ksk_task);
    pkc->ksk_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != pkc->qre)
  {
    GNUNET_DATASTORE_cancel (pkc->qre);
    pkc->qre = NULL;
  }
  if (NULL != pkc->dsh)
  {
    GNUNET_DATASTORE_disconnect (pkc->dsh, GNUNET_NO);
    pkc->dsh = NULL;
  }
  GNUNET_free (pkc->cpy);
  GNUNET_free (pkc->kb);
  GNUNET_FS_uri_destroy (pkc->ksk_uri);
  GNUNET_free (pkc);
}


/* end of fs_publish_ksk.c */
