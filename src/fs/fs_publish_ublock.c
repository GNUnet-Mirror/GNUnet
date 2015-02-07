/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_publish_ublock.c
 * @brief publish a UBLOCK in GNUnet
 * @see https://gnunet.org/encoding and #2564
 * @author Krista Bennett
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "fs_publish_ublock.h"
#include "fs_api.h"
#include "fs_tree.h"


/**
 * Derive the key for symmetric encryption/decryption from
 * the public key and the label.
 *
 * @param skey where to store symmetric key
 * @param iv where to store the IV
 * @param label label to use for key derivation
 * @param pub public key to use for key derivation
 */
static void
derive_ublock_encryption_key (struct GNUNET_CRYPTO_SymmetricSessionKey *skey,
			      struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
			      const char *label,
			      const struct GNUNET_CRYPTO_EcdsaPublicKey *pub)
{
  struct GNUNET_HashCode key;

  /* derive key from 'label' and public key of the namespace */
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CRYPTO_kdf (&key, sizeof (key),
				    "UBLOCK-ENC", strlen ("UBLOCK-ENC"),
				    label, strlen (label),
				    pub, sizeof (*pub),
				    NULL, 0));
  GNUNET_CRYPTO_hash_to_aes_key (&key, skey, iv);
}


/**
 * Decrypt the given UBlock, storing the result in output.
 *
 * @param input input data
 * @param input_len number of bytes in @a input
 * @param ns public key under which the UBlock was stored
 * @param label label under which the UBlock was stored
 * @param output where to write the result, has input_len bytes
 */
void
GNUNET_FS_ublock_decrypt_ (const void *input,
			   size_t input_len,
			   const struct GNUNET_CRYPTO_EcdsaPublicKey *ns,
			   const char *label,
			   void *output)
{
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct GNUNET_CRYPTO_SymmetricSessionKey skey;

  derive_ublock_encryption_key (&skey, &iv,
				label, ns);
  GNUNET_CRYPTO_symmetric_decrypt (input, input_len,
			     &skey, &iv,
                             output);
}


/**
 * Context for 'ublock_put_cont'.
 */
struct GNUNET_FS_PublishUblockContext
{

  /**
   * Function to call when done.
   */
  GNUNET_FS_UBlockContinuation cont;

  /**
   * Closure of 'cont'.
   */
  void *cont_cls;

  /**
   * Handle for active datastore operation.
   */
  struct GNUNET_DATASTORE_QueueEntry *qre;

  /**
   * Task to run continuation asynchronously.
   */
  struct GNUNET_SCHEDULER_Task * task;

};


/**
 * Continuation of #GNUNET_FS_publish_ublock_().
 *
 * @param cls closure of type "struct GNUNET_FS_PublishUblockContext*"
 * @param success GNUNET_SYSERR on failure (including timeout/queue drop)
 *                GNUNET_NO if content was already there
 *                GNUNET_YES (or other positive value) on success
 * @param min_expiration minimum expiration time required for 0-priority content to be stored
 *                by the datacache at this time, zero for unknown, forever if we have no
 *                space for 0-priority content
 * @param msg NULL on success, otherwise an error message
 */
static void
ublock_put_cont (void *cls,
		 int32_t success,
		 struct GNUNET_TIME_Absolute min_expiration,
		 const char *msg)
{
  struct GNUNET_FS_PublishUblockContext *uc = cls;

  uc->qre = NULL;
  uc->cont (uc->cont_cls, msg);
  GNUNET_free (uc);
}


/**
 * Run the continuation.
 *
 * @param cls the `struct GNUNET_FS_PublishUblockContext *`
 * @param tc scheduler context
 */
static void
run_cont (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_PublishUblockContext *uc = cls;

  uc->task = NULL;
  uc->cont (uc->cont_cls, NULL);
  GNUNET_free (uc);
}


/**
 * Publish a UBlock.
 *
 * @param h handle to the file sharing subsystem
 * @param dsh datastore handle to use for storage operation
 * @param label identifier to use
 * @param ulabel update label to use, may be an empty string for none
 * @param ns namespace to publish in
 * @param meta metadata to use
 * @param uri URI to refer to in the UBlock
 * @param bo per-block options
 * @param options publication options
 * @param cont continuation
 * @param cont_cls closure for @a cont
 * @return NULL on error (@a cont will still be called)
 */
struct GNUNET_FS_PublishUblockContext *
GNUNET_FS_publish_ublock_ (struct GNUNET_FS_Handle *h,
			   struct GNUNET_DATASTORE_Handle *dsh,
			   const char *label,
			   const char *ulabel,
			   const struct GNUNET_CRYPTO_EcdsaPrivateKey *ns,
			   const struct GNUNET_CONTAINER_MetaData *meta,
			   const struct GNUNET_FS_Uri *uri,
			   const struct GNUNET_FS_BlockOptions *bo,
			   enum GNUNET_FS_PublishOptions options,
			   GNUNET_FS_UBlockContinuation cont, void *cont_cls)
{
  struct GNUNET_FS_PublishUblockContext *uc;
  struct GNUNET_HashCode query;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct GNUNET_CRYPTO_SymmetricSessionKey skey;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *nsd;
  struct GNUNET_CRYPTO_EcdsaPublicKey pub;
  char *uris;
  size_t size;
  char *kbe;
  char *sptr;
  ssize_t mdsize;
  size_t slen;
  size_t ulen;
  struct UBlock *ub_plain;
  struct UBlock *ub_enc;

  /* compute ublock to publish */
  if (NULL == meta)
    mdsize = 0;
  else
    mdsize = GNUNET_CONTAINER_meta_data_get_serialized_size (meta);
  GNUNET_assert (mdsize >= 0);
  uris = GNUNET_FS_uri_to_string (uri);
  slen = strlen (uris) + 1;
  if (NULL == ulabel)
    ulen = 1;
  else
    ulen = strlen (ulabel) + 1;
  size = mdsize + sizeof (struct UBlock) + slen + ulen;
  if (size > MAX_UBLOCK_SIZE)
  {
    size = MAX_UBLOCK_SIZE;
    mdsize = size - sizeof (struct UBlock) - (slen + ulen);
  }
  ub_plain = GNUNET_malloc (size);
  kbe = (char *) &ub_plain[1];
  if (NULL != ulabel)
    memcpy (kbe, ulabel, ulen);
  kbe += ulen;
  memcpy (kbe, uris, slen);
  kbe += slen;
  GNUNET_free (uris);
  sptr = kbe;
  if (NULL != meta)
    mdsize =
      GNUNET_CONTAINER_meta_data_serialize (meta, &sptr, mdsize,
					    GNUNET_CONTAINER_META_DATA_SERIALIZE_PART);
  if (-1 == mdsize)
  {
    GNUNET_break (0);
    GNUNET_free (ub_plain);
    cont (cont_cls, _("Internal error."));
    return NULL;
  }
  size = sizeof (struct UBlock) + slen + mdsize + ulen;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Publishing under identifier `%s'\n",
              label);
  /* get public key of the namespace */
  GNUNET_CRYPTO_ecdsa_key_get_public (ns,
				    &pub);
  derive_ublock_encryption_key (&skey, &iv,
				label, &pub);

  /* encrypt ublock */
  ub_enc = GNUNET_malloc (size);
  GNUNET_CRYPTO_symmetric_encrypt (&ub_plain[1],
			     ulen + slen + mdsize,
			     &skey, &iv,
                             &ub_enc[1]);
  GNUNET_free (ub_plain);
  ub_enc->purpose.size = htonl (ulen + slen + mdsize +
				sizeof (struct UBlock)
				- sizeof (struct GNUNET_CRYPTO_EcdsaSignature));
  ub_enc->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_FS_UBLOCK);

  /* derive signing-key from 'label' and public key of the namespace */
  nsd = GNUNET_CRYPTO_ecdsa_private_key_derive (ns, label, "fs-ublock");
  GNUNET_CRYPTO_ecdsa_key_get_public (nsd,
				    &ub_enc->verification_key);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CRYPTO_ecdsa_sign (nsd,
					 &ub_enc->purpose,
					 &ub_enc->signature));
  GNUNET_CRYPTO_hash (&ub_enc->verification_key,
		      sizeof (ub_enc->verification_key),
		      &query);
  GNUNET_free (nsd);

  uc = GNUNET_new (struct GNUNET_FS_PublishUblockContext);
  uc->cont = cont;
  uc->cont_cls = cont_cls;
  if (NULL != dsh)
  {
    uc->qre =
      GNUNET_DATASTORE_put (dsh, 0, &query,
                            ulen + slen + mdsize + sizeof (struct UBlock),
                            ub_enc,
                            GNUNET_BLOCK_TYPE_FS_UBLOCK,
                            bo->content_priority,
                            bo->anonymity_level,
                            bo->replication_level,
                            bo->expiration_time,
                            -2, 1,
                            GNUNET_CONSTANTS_SERVICE_TIMEOUT,
                            &ublock_put_cont, uc);
  }
  else
  {
    uc->task = GNUNET_SCHEDULER_add_now (&run_cont,
                                         uc);
  }
  return uc;
}


/**
 * Abort UBlock publishing operation.
 *
 * @param uc operation to abort.
 */
void
GNUNET_FS_publish_ublock_cancel_ (struct GNUNET_FS_PublishUblockContext *uc)
{
  if (NULL != uc->qre)
    GNUNET_DATASTORE_cancel (uc->qre);
  if (NULL != uc->task)
    GNUNET_SCHEDULER_cancel (uc->task);
  GNUNET_free (uc);
}

/* end of fs_publish_ublock.c */
