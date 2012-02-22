/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2012 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_namespace_advertise.c
 * @brief advertise namespaces (creating NBlocks)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "fs_api.h"


/**
 * Maximum legal size for an nblock.
 */
#define MAX_NBLOCK_SIZE (60 * 1024)


/**
 * Context for advertising a namespace.
 */
struct GNUNET_FS_AdvertisementContext
{
  /**
   * Function to call with the result.
   */
  GNUNET_FS_PublishContinuation cont;

  /**
   * Closure for cont.
   */
  void *cont_cls;

  /**
   * Datastore handle.
   */
  struct GNUNET_DATASTORE_Handle *dsh;

  /**
   * Our KSK URI.
   */
  struct GNUNET_FS_Uri *ksk_uri;

  /**
   * Plaintext.
   */
  char *pt;

  /**
   * NBlock to sign and store.
   */
  struct NBlock *nb;

  /**
   * The namespace.
   */
  struct GNUNET_FS_Namespace *ns;

  /**
   * Current datastore queue entry for advertising.
   */
  struct GNUNET_DATASTORE_QueueEntry *dqe;

  /**
   * Block options.
   */
  struct GNUNET_FS_BlockOptions bo;

  /**
   * Number of bytes of plaintext.
   */
  size_t pt_size;

  /**
   * Current keyword offset.
   */
  unsigned int pos;
};


// FIXME: I see no good reason why this should need to be done
// in a new task (anymore).  Integrate with 'cancel' function below?
/**
 * Disconnect from the datastore.
 *
 * @param cls datastore handle
 * @param tc scheduler context
 */
static void
do_disconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DATASTORE_Handle *dsh = cls;

  GNUNET_DATASTORE_disconnect (dsh, GNUNET_NO);
}


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure (our struct GNUNET_FS_AdvertismentContext)
 * @param success GNUNET_SYSERR on failure
 * @param min_expiration minimum expiration time required for content to be stored
 * @param msg NULL on success, otherwise an error message
 */
static void
advertisement_cont (void *cls, int success, 
		    struct GNUNET_TIME_Absolute min_expiration,
		    const char *msg)
{
  struct GNUNET_FS_AdvertisementContext *ac = cls;
  const char *keyword;
  GNUNET_HashCode key;
  GNUNET_HashCode query;
  struct GNUNET_CRYPTO_AesSessionKey skey;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  struct GNUNET_CRYPTO_RsaPrivateKey *pk;

  ac->dqe = NULL;
  if (GNUNET_SYSERR == success)
  {
    /* error! */
    (void) GNUNET_SCHEDULER_add_now (&do_disconnect, ac->dsh);
    ac->dsh = NULL;
    if (msg == NULL)
    {
      GNUNET_break (0);
      msg = _("Unknown error");
    }
    if (ac->cont != NULL)
    {
      ac->cont (ac->cont_cls, NULL, msg);
      ac->cont = NULL;
    }
    GNUNET_FS_namespace_advertise_cancel (ac);
    return;
  }
  if (ac->pos == ac->ksk_uri->data.ksk.keywordCount)
  {
    /* done! */
    (void) GNUNET_SCHEDULER_add_now (&do_disconnect, ac->dsh);
    ac->dsh = NULL;
    if (ac->cont != NULL)
    {
      ac->cont (ac->cont_cls, ac->ksk_uri, NULL);
      ac->cont = NULL;
    }
    GNUNET_FS_namespace_advertise_cancel (ac);
    return;
  }
  keyword = ac->ksk_uri->data.ksk.keywords[ac->pos++];
  /* first character of keyword indicates if it is
   * mandatory or not -- ignore for hashing */
  GNUNET_CRYPTO_hash (&keyword[1], strlen (&keyword[1]), &key);
  GNUNET_CRYPTO_hash_to_aes_key (&key, &skey, &iv);
  GNUNET_CRYPTO_aes_encrypt (ac->pt, ac->pt_size, &skey, &iv, &ac->nb[1]);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CRYPTO_rsa_sign (ac->ns->key, &ac->nb->ns_purpose,
                                        &ac->nb->ns_signature));
  pk = GNUNET_CRYPTO_rsa_key_create_from_hash (&key);
  GNUNET_assert (pk != NULL);
  GNUNET_CRYPTO_rsa_key_get_public (pk, &ac->nb->keyspace);
  GNUNET_CRYPTO_hash (&ac->nb->keyspace,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &query);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CRYPTO_rsa_sign (pk, &ac->nb->ksk_purpose,
                                        &ac->nb->ksk_signature));
  GNUNET_CRYPTO_rsa_key_free (pk);
  ac->dqe = GNUNET_DATASTORE_put (ac->dsh, 0 /* no reservation */ ,
				  &query, ac->pt_size + sizeof (struct NBlock), ac->nb,
				  GNUNET_BLOCK_TYPE_FS_NBLOCK, ac->bo.content_priority,
				  ac->bo.anonymity_level, ac->bo.replication_level,
				  ac->bo.expiration_time, -2, 1,
				  GNUNET_CONSTANTS_SERVICE_TIMEOUT, &advertisement_cont,
				  ac);
}


/**
 * Publish an advertismement for a namespace.
 *
 * @param h handle to the file sharing subsystem
 * @param ksk_uri keywords to use for advertisment
 * @param namespace handle for the namespace that should be advertised
 * @param meta meta-data for the namespace advertisement
 * @param bo block options
 * @param rootEntry name of the root of the namespace
 * @param cont continuation
 * @param cont_cls closure for cont
 * @return NULL on error ('cont' is still called)
 */
struct GNUNET_FS_AdvertisementContext *
GNUNET_FS_namespace_advertise (struct GNUNET_FS_Handle *h,
                               struct GNUNET_FS_Uri *ksk_uri,
                               struct GNUNET_FS_Namespace *namespace,
                               const struct GNUNET_CONTAINER_MetaData *meta,
                               const struct GNUNET_FS_BlockOptions *bo,
                               const char *rootEntry,
                               GNUNET_FS_PublishContinuation cont,
                               void *cont_cls)
{
  size_t reslen;
  size_t size;
  ssize_t mdsize;
  struct NBlock *nb;
  char *mdst;
  struct GNUNET_DATASTORE_Handle *dsh;
  struct GNUNET_FS_AdvertisementContext *ctx;
  char *pt;

  /* create advertisements */
  mdsize = GNUNET_CONTAINER_meta_data_get_serialized_size (meta);
  if (-1 == mdsize)
  {
    cont (cont_cls, NULL, _("Failed to serialize meta data"));
    return NULL;
  }
  reslen = strlen (rootEntry) + 1;
  size = mdsize + sizeof (struct NBlock) + reslen;
  if (size > MAX_NBLOCK_SIZE)
  {
    size = MAX_NBLOCK_SIZE;
    mdsize = size - sizeof (struct NBlock) - reslen;
  }

  pt = GNUNET_malloc (mdsize + reslen);
  memcpy (pt, rootEntry, reslen);
  mdst = &pt[reslen];
  mdsize =
      GNUNET_CONTAINER_meta_data_serialize (meta, &mdst, mdsize,
                                            GNUNET_CONTAINER_META_DATA_SERIALIZE_PART);
  if (-1 == mdsize)
  {
    GNUNET_break (0);
    GNUNET_free (pt);
    cont (cont_cls, NULL, _("Failed to serialize meta data"));
    return NULL;
  }
  size = mdsize + sizeof (struct NBlock) + reslen;
  nb = GNUNET_malloc (size);
  GNUNET_CRYPTO_rsa_key_get_public (namespace->key, &nb->subspace);
  nb->ns_purpose.size =
      htonl (mdsize + reslen +
             sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
             sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  nb->ns_purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_FS_NBLOCK);
  nb->ksk_purpose.size =
      htonl (size - sizeof (struct GNUNET_CRYPTO_RsaSignature));
  nb->ksk_purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_FS_NBLOCK_KSIG);
  dsh = GNUNET_DATASTORE_connect (h->cfg);
  if (NULL == dsh)
  {
    GNUNET_free (nb);
    GNUNET_free (pt);
    cont (cont_cls, NULL, _("Failed to connect to datastore service"));
    return NULL;
  }
  ctx = GNUNET_malloc (sizeof (struct GNUNET_FS_AdvertisementContext));
  ctx->cont = cont;
  ctx->cont_cls = cont_cls;
  ctx->dsh = dsh;
  ctx->ksk_uri = GNUNET_FS_uri_dup (ksk_uri);
  ctx->nb = nb;
  ctx->pt = pt;
  ctx->pt_size = mdsize + reslen;
  ctx->ns = namespace;
  ctx->ns->rc++;
  ctx->bo = *bo;
  advertisement_cont (ctx, GNUNET_OK, GNUNET_TIME_UNIT_ZERO_ABS, NULL);
  return ctx;
}


/**
 * Abort the namespace advertisement operation.
 *
 * @param ac context of the operation to abort.
 */
void
GNUNET_FS_namespace_advertise_cancel (struct GNUNET_FS_AdvertisementContext *ac)
{
  if (NULL != ac->dqe)
  {
    GNUNET_DATASTORE_cancel (ac->dqe);
    ac->dqe = NULL;
  }
  if (NULL != ac->dsh)
  {
    GNUNET_DATASTORE_disconnect (ac->dsh, GNUNET_NO);
    ac->dsh = NULL;
  }
  GNUNET_FS_uri_destroy (ac->ksk_uri);
  GNUNET_free (ac->pt);
  GNUNET_free (ac->nb);
  GNUNET_FS_namespace_delete (ac->ns, GNUNET_NO);
  GNUNET_free (ac);
}


/* end of fs_namespace_advertise.c */
