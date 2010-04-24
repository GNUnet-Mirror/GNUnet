/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_namespace.c
 * @brief create and destroy namespaces
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "fs.h"

/**
 * Return the name of the directory in which we store
 * our local namespaces (or rather, their public keys).
 *
 * @param h global fs handle 
 * @return NULL on error, otherwise the name of the directory
 */
static char *
get_namespace_directory (struct GNUNET_FS_Handle *h)
{
  char *dn;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (h->cfg,
					       "FS",
					       "IDENTITY_DIR",
					       &dn))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Configuration fails to specify `%s' in section `%s'\n"),
		  "IDENTITY_DIR",
		  "fs");
      return NULL;
    }
  return dn;
}


/**
 * Context for advertising a namespace.
 */
struct AdvertisementContext
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
   * Expiration time.
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * Number of bytes of plaintext.
   */ 
  size_t pt_size;

  /**
   * Anonymity level.
   */
  uint32_t anonymity;

  /**
   * Content priority.
   */
  uint32_t priority;

  /**
   * Current keyword offset.
   */
  unsigned int pos;
};


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure (our struct AdvertismentContext)
 * @param success GNUNET_SYSERR on failure
 * @param msg NULL on success, otherwise an error message
 */
static void
advertisement_cont (void *cls,
		    int success,
		    const char *msg)
{
  struct AdvertisementContext *ac = cls;
  const char *keyword;
  GNUNET_HashCode key;
  GNUNET_HashCode query;
  struct GNUNET_CRYPTO_AesSessionKey skey;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  struct GNUNET_CRYPTO_RsaPrivateKey *pk;
  
  if (GNUNET_OK != success)
    {
      /* error! */
      GNUNET_DATASTORE_disconnect (ac->dsh, GNUNET_NO);
      ac->cont (ac->cont_cls, NULL, msg);
      GNUNET_FS_uri_destroy (ac->ksk_uri);
      GNUNET_free (ac->pt);
      GNUNET_free (ac->nb);
      GNUNET_FS_namespace_delete (ac->ns, GNUNET_NO);
      GNUNET_free (ac);
      return;
    }
  if (ac->pos == ac->ksk_uri->data.ksk.keywordCount)
    {
      /* done! */
      GNUNET_DATASTORE_disconnect (ac->dsh, GNUNET_NO);
      ac->cont (ac->cont_cls, ac->ksk_uri, NULL);
      GNUNET_FS_uri_destroy (ac->ksk_uri);
      GNUNET_free (ac->pt);
      GNUNET_free (ac->nb);
      GNUNET_FS_namespace_delete (ac->ns, GNUNET_NO);
      GNUNET_free (ac);
      return;
    }
  keyword = ac->ksk_uri->data.ksk.keywords[ac->pos++];
  /* first character of keyword indicates if it is
     mandatory or not -- ignore for hashing */
  GNUNET_CRYPTO_hash (&keyword[1], strlen (&keyword[1]), &key);
  GNUNET_CRYPTO_hash_to_aes_key (&key, &skey, &iv);
  GNUNET_CRYPTO_aes_encrypt (ac->pt,
			     ac->pt_size,
			     &skey,
			     &iv,
			     &ac->nb[1]);
  GNUNET_break (GNUNET_OK == 
		GNUNET_CRYPTO_rsa_sign (ac->ns->key,
					&ac->nb->ns_purpose,
					&ac->nb->ns_signature));
  pk = GNUNET_CRYPTO_rsa_key_create_from_hash (&key);
  GNUNET_CRYPTO_rsa_key_get_public (pk, &ac->nb->keyspace);
  GNUNET_CRYPTO_hash (&ac->nb->keyspace,
		      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
		      &query);
  GNUNET_break (GNUNET_OK == 
		GNUNET_CRYPTO_rsa_sign (pk,
					&ac->nb->ksk_purpose,
					&ac->nb->ksk_signature));
  GNUNET_CRYPTO_rsa_key_free (pk);
  GNUNET_DATASTORE_put (ac->dsh,
			0 /* no reservation */, 
			&query,
			ac->pt_size + sizeof (struct NBlock),
			ac->nb,
			GNUNET_BLOCK_TYPE_NBLOCK,
			ac->priority,
			ac->anonymity,
			ac->expiration,
			GNUNET_CONSTANTS_SERVICE_TIMEOUT, 
			&advertisement_cont,
			ac);
}


/**
 * Publish an advertismement for a namespace.  
 *
 * @param h handle to the file sharing subsystem
 * @param ksk_uri keywords to use for advertisment
 * @param namespace handle for the namespace that should be advertised
 * @param meta meta-data for the namespace advertisement
 * @param anonymity for the namespace advertismement
 * @param priority for the namespace advertisement
 * @param expiration for the namespace advertisement
 * @param rootEntry name of the root of the namespace
 * @param cont continuation
 * @param cont_cls closure for cont
 */
void
GNUNET_FS_namespace_advertise (struct GNUNET_FS_Handle *h,
			       struct GNUNET_FS_Uri *ksk_uri,
			       struct GNUNET_FS_Namespace *namespace,
			       const struct GNUNET_CONTAINER_MetaData *meta,
			       uint32_t anonymity,
			       uint32_t priority,
			       struct GNUNET_TIME_Absolute expiration,
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
  struct AdvertisementContext *ctx;
  char *pt;

  /* create advertisements */
  mdsize = GNUNET_CONTAINER_meta_data_get_serialized_size (meta);
  if (-1 == mdsize)
    {
      cont (cont_cls, NULL, _("Failed to serialize meta data"));
      return;
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
  mdsize = GNUNET_CONTAINER_meta_data_serialize (meta,
						 &mdst,
						 mdsize,
						 GNUNET_CONTAINER_META_DATA_SERIALIZE_PART);
  if (mdsize == -1)
    {
      GNUNET_break (0);
      GNUNET_free (pt);
      cont (cont_cls, NULL, _("Failed to serialize meta data"));
      return;
    }
  size = mdsize + sizeof (struct NBlock) + reslen;  
  nb = GNUNET_malloc (size);
  GNUNET_CRYPTO_rsa_key_get_public (namespace->key, 
				    &nb->subspace);
  nb->ns_purpose.size = htonl (mdsize + reslen + 
			    sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
			    sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  nb->ns_purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_FS_NBLOCK);
  nb->ksk_purpose.size = htonl (size - sizeof (struct GNUNET_CRYPTO_RsaSignature));
  nb->ksk_purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_FS_NBLOCK_KSIG);
  dsh = GNUNET_DATASTORE_connect (h->cfg, h->sched);
  if (NULL == dsh)
    {
      GNUNET_free (nb);
      GNUNET_free (pt);
      cont (cont_cls, NULL, _("Failed to connect to datastore service"));
      return;
    }  
  ctx = GNUNET_malloc (sizeof (struct AdvertisementContext));
  ctx->cont = cont;
  ctx->cont_cls = cont_cls;
  ctx->dsh = dsh;
  ctx->ksk_uri = GNUNET_FS_uri_dup (ksk_uri);
  ctx->nb = nb;
  ctx->pt = pt;
  ctx->pt_size = mdsize + reslen;
  ctx->ns = namespace;
  ctx->ns->rc++;
  ctx->anonymity = anonymity;
  ctx->priority = priority;
  ctx->expiration = expiration;
  advertisement_cont (ctx, GNUNET_OK, NULL);
}


/**
 * Create a namespace with the given name; if one already
 * exists, return a handle to the existing namespace.
 *
 * @param h handle to the file sharing subsystem
 * @param name name to use for the namespace
 * @return handle to the namespace, NULL on error
 */
struct GNUNET_FS_Namespace *
GNUNET_FS_namespace_create (struct GNUNET_FS_Handle *h,
			    const char *name)
{
  char *dn;
  char *fn;
  struct GNUNET_FS_Namespace *ret;

  dn = get_namespace_directory (h);
  GNUNET_asprintf (&fn,
		   "%s%s%s",
		   dn,
		   DIR_SEPARATOR_STR,
		   name);
  GNUNET_free (dn);
  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_Namespace));
  ret->rc = 1;
  ret->key = GNUNET_CRYPTO_rsa_key_create_from_file (fn);
  if (ret->key == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to create or read private key for namespace `%s'\n"),
		  name);
      GNUNET_free (ret);
      GNUNET_free (fn);
      return NULL;
    }
  ret->filename = fn;
  return ret;
}


/**
 * Delete a namespace handle.  Can be used for a clean shutdown (free
 * memory) or also to freeze the namespace to prevent further
 * insertions by anyone.
 *
 * @param namespace handle to the namespace that should be deleted / freed
 * @param freeze prevents future insertions; creating a namespace
 *        with the same name again will create a fresh namespace instead
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int 
GNUNET_FS_namespace_delete (struct GNUNET_FS_Namespace *namespace,
			    int freeze)
{
  namespace->rc--;
  if (freeze)
    {
      if (0 != UNLINK (namespace->filename))
	GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
				  "unlink",
				  namespace->filename);      
    }
  if (0 == namespace->rc)
    {
      GNUNET_CRYPTO_rsa_key_free (namespace->key);
      GNUNET_free (namespace->filename);
      GNUNET_free (namespace);
    }
  return GNUNET_OK;
}


/**
 * Context for the 'process_namespace' callback.
 * Specifies a function to call on each namespace.
 */
struct ProcessNamespaceContext
{
  /**
   * Function to call.
   */
  GNUNET_FS_NamespaceInfoProcessor cb;

  /**
   * Closure for 'cb'.
   */
  void *cb_cls;
};


/**
 * Function called with a filename of a namespace. Reads the key and
 * calls the callback.
 *
 * @param cls closure (struct ProcessNamespaceContext)
 * @param filename complete filename (absolute path)
 * @return GNUNET_OK to continue to iterate,
 *  GNUNET_SYSERR to abort iteration with error!
 */
static int
process_namespace (void *cls, 
		   const char *filename)
{
  struct ProcessNamespaceContext *pnc = cls;
  struct GNUNET_CRYPTO_RsaPrivateKey *key;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pk;
  GNUNET_HashCode id;
  const char *name;
  const char *t;

  key = GNUNET_CRYPTO_rsa_key_create_from_file (filename);
  if (key == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to read namespace private key file `%s', deleting it!\n"),
		  filename);
      if (0 != UNLINK (filename))
	GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
				  "unlink",
				  filename);
      return GNUNET_OK;
    }
  GNUNET_CRYPTO_rsa_key_get_public (key, &pk);
  GNUNET_CRYPTO_rsa_key_free (key);
  GNUNET_CRYPTO_hash (&pk, sizeof(pk), &id); 
  name = filename;
  while (NULL != (t = strstr (name, DIR_SEPARATOR_STR)))
    name = t + 1;
  pnc->cb (pnc->cb_cls,
	   name,
	   &id);
  return GNUNET_OK;
}


/**
 * Build a list of all available local (!) namespaces The returned
 * names are only the nicknames since we only iterate over the local
 * namespaces.
 *
 * @param h handle to the file sharing subsystem
 * @param cb function to call on each known namespace
 * @param cb_cls closure for cb
 */
void 
GNUNET_FS_namespace_list (struct GNUNET_FS_Handle *h,
			  GNUNET_FS_NamespaceInfoProcessor cb,
			  void *cb_cls)
{
  char *dn;
  struct ProcessNamespaceContext ctx;
  
  dn = get_namespace_directory (h);
  if (dn == NULL)
    return;
  ctx.cb = cb;
  ctx.cb_cls = cb_cls;
  GNUNET_DISK_directory_scan (dn,
			      &process_namespace,
			      &ctx);
  GNUNET_free (dn);
}

/* end of fs_namespace.c */

