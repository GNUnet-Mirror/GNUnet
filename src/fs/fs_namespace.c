/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_namespace.c
 * @brief create and destroy namespaces
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "fs_api.h"


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
      GNUNET_CONFIGURATION_get_value_filename (h->cfg, "FS", "IDENTITY_DIR",
                                               &dn))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       "fs", "IDENTITY_DIR");
    return NULL;
  }
  return dn;
}


/**
 * Return the name of the directory in which we store
 * the update information graph for the given local namespace.
 *
 * @param ns namespace handle
 * @return NULL on error, otherwise the name of the directory
 */
static char *
get_update_information_directory (struct GNUNET_FS_Namespace *ns)
{
  char *dn;
  char *ret;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (ns->h->cfg, "FS", "UPDATE_DIR",
                                               &dn))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       "fs", "UPDATE_DIR");
    return NULL;
  }
  GNUNET_asprintf (&ret, "%s%s%s", dn, DIR_SEPARATOR_STR, ns->name);
  GNUNET_free (dn);
  return ret;
}


/**
 * Write the namespace update node graph to a file.
 *
 * @param ns namespace to dump
 */
static void
write_update_information_graph (struct GNUNET_FS_Namespace *ns)
{
  char *fn;
  struct GNUNET_BIO_WriteHandle *wh;
  unsigned int i;
  struct NamespaceUpdateNode *n;
  char *uris;

  fn = get_update_information_directory (ns);
  wh = GNUNET_BIO_write_open (fn);
  if (NULL == wh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to open `%s' for writing: %s\n"), STRERROR (errno));
    GNUNET_free (fn);
    return;
  }
  if (GNUNET_OK != GNUNET_BIO_write_int32 (wh, ns->update_node_count))
    goto END;
  for (i = 0; i < ns->update_node_count; i++)
  {
    n = ns->update_nodes[i];
    uris = GNUNET_FS_uri_to_string (n->uri);
    if ((GNUNET_OK != GNUNET_BIO_write_string (wh, n->id)) ||
        (GNUNET_OK != GNUNET_BIO_write_meta_data (wh, n->md)) ||
        (GNUNET_OK != GNUNET_BIO_write_string (wh, n->update)) ||
        (GNUNET_OK != GNUNET_BIO_write_string (wh, uris)))
    {
      GNUNET_free (uris);
      break;
    }
    GNUNET_free (uris);
  }
END:
  if (GNUNET_OK != GNUNET_BIO_write_close (wh))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Failed to write `%s': %s\n"),
                STRERROR (errno));
  GNUNET_free (fn);
}


/**
 * Read the namespace update node graph from a file.
 *
 * @param ns namespace to read
 */
static void
read_update_information_graph (struct GNUNET_FS_Namespace *ns)
{
  char *fn;
  struct GNUNET_BIO_ReadHandle *rh;
  unsigned int i;
  struct NamespaceUpdateNode *n;
  char *uris;
  uint32_t count;
  char *emsg;

  fn = get_update_information_directory (ns);
  if (GNUNET_YES != GNUNET_DISK_file_test (fn))
  {
    GNUNET_free (fn);
    return;
  }
  rh = GNUNET_BIO_read_open (fn);
  if (NULL == rh)
  {
    GNUNET_free (fn);
    return;
  }
  if (GNUNET_OK != GNUNET_BIO_read_int32 (rh, &count))
  {
    GNUNET_break (0);
    goto END;
  }
  if (count > 1024 * 1024)
  {
    GNUNET_break (0);
    goto END;
  }
  if (0 == count)
  {
    GNUNET_break (GNUNET_OK == GNUNET_BIO_read_close (rh, NULL));
    GNUNET_free (fn);
    return;
  }
  ns->update_nodes =
      GNUNET_malloc (count * sizeof (struct NamespaceUpdateNode *));

  for (i = 0; i < count; i++)
  {
    n = GNUNET_malloc (sizeof (struct NamespaceUpdateNode));
    if ((GNUNET_OK != GNUNET_BIO_read_string (rh, "identifier", &n->id, 1024))
        || (GNUNET_OK != GNUNET_BIO_read_meta_data (rh, "meta", &n->md)) ||
        (GNUNET_OK !=
         GNUNET_BIO_read_string (rh, "update-id", &n->update, 1024)) ||
        (GNUNET_OK != GNUNET_BIO_read_string (rh, "uri", &uris, 1024 * 2)))
    {
      GNUNET_break (0);
      GNUNET_free_non_null (n->id);
      GNUNET_free_non_null (n->update);
      if (n->md != NULL)
        GNUNET_CONTAINER_meta_data_destroy (n->md);
      GNUNET_free (n);
      break;
    }
    n->uri = GNUNET_FS_uri_parse (uris, &emsg);
    GNUNET_free (uris);
    if (n->uri == NULL)
    {
      GNUNET_break (0);
      GNUNET_free (emsg);
      GNUNET_free (n->id);
      GNUNET_free_non_null (n->update);
      GNUNET_CONTAINER_meta_data_destroy (n->md);
      GNUNET_free (n);
      break;
    }
    ns->update_nodes[i] = n;
  }
  ns->update_node_count = i;
END:
  if (GNUNET_OK != GNUNET_BIO_read_close (rh, &emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Failed to write `%s': %s\n"), emsg);
    GNUNET_free (emsg);
  }
  GNUNET_free (fn);
}


/**
 * Create a namespace with the given name; if one already
 * exists, return a handle to the existing namespace.
 *
 * @param h handle to the file sharing subsystem
 * @param name name to use for the namespace
 * @return handle to the namespace, NULL on error (i.e. invalid filename)
 */
struct GNUNET_FS_Namespace *
GNUNET_FS_namespace_create (struct GNUNET_FS_Handle *h, const char *name)
{
  char *dn;
  char *fn;
  struct GNUNET_FS_Namespace *ret;

  dn = get_namespace_directory (h);
  if (NULL == dn)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Can't determine where namespace directory is\n"));
    return NULL;
  }
  GNUNET_asprintf (&fn, "%s%s%s", dn, DIR_SEPARATOR_STR, name);
  GNUNET_free (dn);
  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_Namespace));
  ret->h = h;
  ret->rc = 1;
  ret->key = GNUNET_FS_pseudonym_create (fn);
  if (NULL == ret->key)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to create or read private key for namespace `%s'\n"),
                name);
    GNUNET_free (ret);
    GNUNET_free (fn);
    return NULL;
  }
  ret->name = GNUNET_strdup (name);
  ret->filename = fn;
  return ret;
}


/**
 * Open the namespace with the given name; if it does not exist,
 * or the key file is corrupted, the function fails.
 *
 * @param h handle to the file sharing subsystem
 * @param name name of the namespace
 * @return handle to the namespace,
 *         NULL on error (i.e. invalid filename, non-existent filename)
 */
struct GNUNET_FS_Namespace *
GNUNET_FS_namespace_open_existing (struct GNUNET_FS_Handle *h, const char *name)
{
  char *dn;
  char *fn;
  struct GNUNET_FS_Namespace *ret;

  dn = get_namespace_directory (h);
  if (NULL == dn)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Can't determine where namespace directory is\n"));
    return NULL;
  }
  GNUNET_asprintf (&fn, "%s%s%s", dn, DIR_SEPARATOR_STR, name);
  GNUNET_free (dn);
  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_Namespace));
  ret->h = h;
  ret->rc = 1;
  ret->key = GNUNET_FS_pseudonym_create_from_existing_file (fn);
  if (NULL == ret->key)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to read private key for namespace `%s'\n"), name);
    GNUNET_free (ret);
    GNUNET_free (fn);
    return NULL;
  }
  ret->name = GNUNET_strdup (name);
  ret->filename = fn;
  return ret;
}


/**
 * Rename a local namespace.
 *
 * @param h handle to the file sharing subsystem
 * @param old_name old name of the namespace
 * @param new_name new name of the namespace
 * @return GNUNET_OK on success, GNUNET_SYSERR on error (see errno for details)
 */
int
GNUNET_FS_namespace_rename (struct GNUNET_FS_Handle *h, 
			    const char *old_name, 
			    const char *new_name)
{
  char *dn;
  char *fn_old;
  char *fn_new;
  int result;
  int save_errno;

  dn = get_namespace_directory (h);
  if (NULL == dn)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Can't determine where namespace directory is\n"));
    return GNUNET_SYSERR;
  }
  GNUNET_asprintf (&fn_old, "%s%s%s", dn, DIR_SEPARATOR_STR, old_name);
  GNUNET_asprintf (&fn_new, "%s%s%s", dn, DIR_SEPARATOR_STR, new_name);
  GNUNET_free (dn);
  result = RENAME (fn_old, fn_new);
  save_errno = errno;
  GNUNET_free (fn_old);
  GNUNET_free (fn_new);
  errno = save_errno;
  if (result == 0)
    return GNUNET_OK;
  return GNUNET_SYSERR;
}


/**
 * Duplicate a namespace handle.
 *
 * @param ns namespace handle
 * @return duplicated handle to the namespace
 */
struct GNUNET_FS_Namespace *
GNUNET_FS_namespace_dup (struct GNUNET_FS_Namespace *ns)
{
  ns->rc++;
  return ns;
}


/**
 * Delete a namespace handle.  Can be used for a clean shutdown (free
 * memory) or also to freeze the namespace to prevent further
 * insertions by anyone.
 *
 * @param ns handle to the namespace that should be deleted / freed
 * @param freeze prevents future insertions; creating a namespace
 *        with the same name again will create a fresh namespace instead
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_FS_namespace_delete (struct GNUNET_FS_Namespace *ns, int freeze)
{
  unsigned int i;
  struct NamespaceUpdateNode *nsn;

  ns->rc--;
  if (freeze)
  {
    if (0 != UNLINK (ns->filename))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "unlink",
                                ns->filename);
  }
  if (0 != ns->rc)
    return GNUNET_OK;
  GNUNET_FS_pseudonym_destroy (ns->key);
  GNUNET_free (ns->filename);
  GNUNET_free (ns->name);
  for (i = 0; i < ns->update_node_count; i++)
  {
    nsn = ns->update_nodes[i];
    GNUNET_CONTAINER_meta_data_destroy (nsn->md);
    GNUNET_FS_uri_destroy (nsn->uri);
    GNUNET_free (nsn->id);
    GNUNET_free (nsn->update);
    GNUNET_free (nsn);
  }
  GNUNET_array_grow (ns->update_nodes, ns->update_node_count,
		     0);
  if (ns->update_map != NULL)
    GNUNET_CONTAINER_multihashmap_destroy (ns->update_map);
  GNUNET_free (ns);
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
 * Get hash of the public key of a namespace.
 *
 * @param ns namespace
 * @param id buffer to store the key in
 * @return GNUNET_OK on success
 *         GNUNET_SYSERR on failure (contents of id remain intact)
 */
int
GNUNET_FS_namespace_get_public_identifier (struct GNUNET_FS_Namespace *ns,
					   struct GNUNET_FS_PseudonymIdentifier *id)
{
  if ((NULL == ns) || (NULL == id))
    return GNUNET_SYSERR;
  GNUNET_FS_pseudonym_get_identifier (ns->key, id);
  return GNUNET_OK;
}


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
process_namespace (void *cls, const char *filename)
{
  struct ProcessNamespaceContext *pnc = cls;
  struct GNUNET_FS_PseudonymHandle *ph;
  struct GNUNET_FS_PseudonymIdentifier id;
  const char *name;
  const char *t;

  if (NULL == (ph = GNUNET_FS_pseudonym_create (filename)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Failed to read namespace private key file `%s', deleting it!\n"),
                filename);
    if (0 != UNLINK (filename))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", filename);
    return GNUNET_OK;
  }
  GNUNET_FS_pseudonym_get_identifier (ph, &id);
  GNUNET_FS_pseudonym_destroy (ph);
  name = filename;
  while (NULL != (t = strstr (name, DIR_SEPARATOR_STR)))
    name = t + 1;
  pnc->cb (pnc->cb_cls, name, &id);
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
                          GNUNET_FS_NamespaceInfoProcessor cb, void *cb_cls)
{
  char *dn;
  struct ProcessNamespaceContext ctx;

  dn = get_namespace_directory (h);
  if (NULL == dn)
    return;
  ctx.cb = cb;
  ctx.cb_cls = cb_cls;
  GNUNET_DISK_directory_scan (dn, &process_namespace, &ctx);
  GNUNET_free (dn);
}


/**
 * Context for the SKS publication.
 */
struct GNUNET_FS_PublishSksContext
{

  /**
   * URI of the new entry in the namespace.
   */
  struct GNUNET_FS_Uri *uri;

  /**
   * Namespace update node to add to namespace on success (or to be
   * deleted if publishing failed).
   */
  struct NamespaceUpdateNode *nsn;

  /**
   * Namespace we're publishing to.
   */
  struct GNUNET_FS_Namespace *ns;

  /**
   * Handle to the datastore.
   */
  struct GNUNET_DATASTORE_Handle *dsh;

  /**
   * Function to call once we're done.
   */
  GNUNET_FS_PublishContinuation cont;

  /**
   * Closure for cont.
   */
  void *cont_cls;

  /**
   * Handle for our datastore request.
   */
  struct GNUNET_DATASTORE_QueueEntry *dqe;
};


/**
 * Function called by the datastore API with
 * the result from the PUT (UBlock) request.
 *
 * @param cls closure of type "struct GNUNET_FS_PublishSksContext*"
 * @param success GNUNET_OK on success
 * @param min_expiration minimum expiration time required for content to be stored
 * @param msg error message (or NULL)
 */
static void
sb_put_cont (void *cls, int success, 
	     struct GNUNET_TIME_Absolute min_expiration,
	     const char *msg)
{
  struct GNUNET_FS_PublishSksContext *psc = cls;
  struct GNUNET_HashCode hc;

  psc->dqe = NULL;
  if (GNUNET_OK != success)
  {
    if (NULL != psc->cont)
      psc->cont (psc->cont_cls, NULL, msg);
    GNUNET_FS_publish_sks_cancel (psc);
    return;
  }
  if (NULL != psc->nsn)
  {
    /* FIXME: this can be done much more
     * efficiently by simply appending to the
     * file and overwriting the 4-byte header */
    if (psc->ns->update_nodes == NULL)
      read_update_information_graph (psc->ns);
    GNUNET_array_append (psc->ns->update_nodes,
			 psc->ns->update_node_count, psc->nsn);
    if (NULL != psc->ns->update_map)
    {
      GNUNET_CRYPTO_hash (psc->nsn->id, strlen (psc->nsn->id), &hc);
      GNUNET_CONTAINER_multihashmap_put (psc->ns->update_map, &hc,
					 psc->nsn,
					 GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    }
    psc->nsn = NULL;
    write_update_information_graph (psc->ns);
  }
  if (NULL != psc->cont)
    psc->cont (psc->cont_cls, psc->uri, NULL);
  GNUNET_FS_publish_sks_cancel (psc);
}


/**
 * Publish an SBlock on GNUnet.
 *
 * @param h handle to the file sharing subsystem
 * @param ns namespace to publish in
 * @param identifier identifier to use
 * @param update update identifier to use
 * @param meta metadata to use
 * @param uri URI to refer to in the SBlock
 * @param bo block options
 * @param options publication options
 * @param cont continuation
 * @param cont_cls closure for cont
 * @return NULL on error ('cont' will still be called)
 */
struct GNUNET_FS_PublishSksContext *
GNUNET_FS_publish_sks (struct GNUNET_FS_Handle *h,
                       struct GNUNET_FS_Namespace *ns,
                       const char *identifier, const char *update,
                       const struct GNUNET_CONTAINER_MetaData *meta,
                       const struct GNUNET_FS_Uri *uri,
                       const struct GNUNET_FS_BlockOptions *bo,
                       enum GNUNET_FS_PublishOptions options,
                       GNUNET_FS_PublishContinuation cont, void *cont_cls)
{
  struct GNUNET_FS_PublishSksContext *psc;
  struct GNUNET_CRYPTO_AesSessionKey sk;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  struct GNUNET_FS_Uri *sks_uri;
  char *uris;
  size_t size;
  size_t slen;
  size_t nidlen;
  size_t idlen;
  ssize_t mdsize;
  struct UBlock *ub;
  struct UBlock *ub_enc;
  char *dest;
  struct GNUNET_CONTAINER_MetaData *mmeta;
  struct GNUNET_HashCode id_hash;          /* hash of thisId */
  struct GNUNET_HashCode ns_hash;          /* hash of namespace public key */
  struct GNUNET_HashCode key;              /* id_hash ^ ns_hash, for AES key */
  struct GNUNET_HashCode signing_key;      /* H(key) = input for public key */
  struct GNUNET_HashCode query;            /* H(verification_key) = query */

  idlen = strlen (identifier);
  if (NULL != update)
    nidlen = strlen (update) + 1;
  else
    nidlen = 1;
  uris = GNUNET_FS_uri_to_string (uri);
  slen = strlen (uris) + 1;
  if ( (slen >= MAX_UBLOCK_SIZE - sizeof (struct UBlock)) ||
       (nidlen >= MAX_UBLOCK_SIZE - sizeof (struct UBlock) - slen) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Identifiers or URI too long to create UBlock"));
    GNUNET_free (uris);
    return NULL;
  }
  if (NULL == meta)
    mmeta = GNUNET_CONTAINER_meta_data_create ();
  else
    mmeta = GNUNET_CONTAINER_meta_data_duplicate (meta);
  mdsize = GNUNET_CONTAINER_meta_data_get_serialized_size (mmeta);
  size = sizeof (struct UBlock) + slen + nidlen + mdsize;
  if ( (size > MAX_UBLOCK_SIZE) ||
       (size < sizeof (struct UBlock) + slen + nidlen) )
  {
    size = MAX_UBLOCK_SIZE;
    mdsize = MAX_UBLOCK_SIZE - (sizeof (struct UBlock) + slen + nidlen);
  }
  ub = GNUNET_malloc (sizeof (struct UBlock) + size);
  dest = (char *) &ub[1];
  if (NULL != update)
    memcpy (dest, update, nidlen);
  else
    memset (dest, 0, 1);
  dest += nidlen;
  memcpy (dest, uris, slen);
  GNUNET_free (uris);
  dest += slen;
  mdsize =
      GNUNET_CONTAINER_meta_data_serialize (mmeta, &dest, mdsize,
                                            GNUNET_CONTAINER_META_DATA_SERIALIZE_PART);
  GNUNET_CONTAINER_meta_data_destroy (mmeta);
  if (-1 == mdsize)
  {
    GNUNET_break (0);
    GNUNET_free (ub);
    if (NULL != cont)
      cont (cont_cls, NULL, _("Internal error."));
    return NULL;
  }
  sks_uri = GNUNET_malloc (sizeof (struct GNUNET_FS_Uri));
  sks_uri->type = GNUNET_FS_URI_SKS;
  sks_uri->data.sks.identifier = GNUNET_strdup (identifier);
  GNUNET_FS_namespace_get_public_identifier (ns,
					     &sks_uri->data.sks.ns);

  size = sizeof (struct UBlock) + mdsize + slen + nidlen;
  ub_enc = GNUNET_malloc (size);
  GNUNET_CRYPTO_hash (identifier, idlen, &id_hash);
  GNUNET_CRYPTO_hash (&sks_uri->data.sks.ns, 
		      sizeof (sks_uri->data.sks.ns), &ns_hash);
  GNUNET_CRYPTO_hash_xor (&id_hash, &ns_hash, &key);
  GNUNET_CRYPTO_hash_to_aes_key (&key, &sk, &iv);
  GNUNET_CRYPTO_hash (&key, sizeof (struct GNUNET_HashCode), &signing_key);

  GNUNET_CRYPTO_aes_encrypt (&ub[1], 
			     size - sizeof (struct UBlock),
			     &sk, &iv,
                             &ub_enc[1]);
  ub_enc->purpose.size = htonl (nidlen + slen + mdsize + sizeof (struct UBlock)
				- sizeof (struct GNUNET_FS_PseudonymSignature));
  ub_enc->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_FS_UBLOCK);
  GNUNET_FS_pseudonym_derive_verification_key (&sks_uri->data.sks.ns, 
					       &signing_key,
					       &ub_enc->verification_key);
  GNUNET_CRYPTO_hash (&ub_enc->verification_key,
		      sizeof (ub_enc->verification_key),
		      &query);
  GNUNET_FS_pseudonym_sign (ns->key,
			    &ub_enc->purpose,
			    NULL,
			    &signing_key,
			    &ub_enc->signature);
  psc = GNUNET_malloc (sizeof (struct GNUNET_FS_PublishSksContext));
  psc->uri = sks_uri;
  psc->cont = cont;
  psc->ns = GNUNET_FS_namespace_dup (ns);
  psc->cont_cls = cont_cls;
  if (0 != (options & GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY))
  {
    GNUNET_free (ub_enc);
    GNUNET_free (ub);
    sb_put_cont (psc, GNUNET_OK, GNUNET_TIME_UNIT_ZERO_ABS, NULL);
    return NULL;
  }
  psc->dsh = GNUNET_DATASTORE_connect (h->cfg);
  if (NULL == psc->dsh)
  {
    GNUNET_free (ub_enc);
    GNUNET_free (ub);
    sb_put_cont (psc, GNUNET_NO, GNUNET_TIME_UNIT_ZERO_ABS, _("Failed to connect to datastore."));
    return NULL;
  }

  if (NULL != update)
  {
    psc->nsn = GNUNET_malloc (sizeof (struct NamespaceUpdateNode));
    psc->nsn->id = GNUNET_strdup (identifier);
    psc->nsn->update = GNUNET_strdup (update);
    psc->nsn->md = GNUNET_CONTAINER_meta_data_duplicate (meta);
    psc->nsn->uri = GNUNET_FS_uri_dup (uri);
  }
  
  psc->dqe = GNUNET_DATASTORE_put (psc->dsh, 0, &query, size, ub_enc,
				   GNUNET_BLOCK_TYPE_FS_UBLOCK, bo->content_priority,
				   bo->anonymity_level, bo->replication_level,
				   bo->expiration_time, -2, 1,
				   GNUNET_CONSTANTS_SERVICE_TIMEOUT, &sb_put_cont, psc);
  GNUNET_free (ub);
  GNUNET_free (ub_enc);
  return psc;
}


/**
 * Abort the SKS publishing operation.
 *
 * @param psc context of the operation to abort.
 */
void
GNUNET_FS_publish_sks_cancel (struct GNUNET_FS_PublishSksContext *psc)
{
  if (NULL != psc->dqe)
  {
    GNUNET_DATASTORE_cancel (psc->dqe);
    psc->dqe = NULL;
  }
  if (NULL != psc->dsh)
  {
    GNUNET_DATASTORE_disconnect (psc->dsh, GNUNET_NO);
    psc->dsh = NULL;
  }
  GNUNET_FS_namespace_delete (psc->ns, GNUNET_NO);
  GNUNET_FS_uri_destroy (psc->uri);
  if (NULL != psc->nsn)
  {
    GNUNET_CONTAINER_meta_data_destroy (psc->nsn->md);
    GNUNET_FS_uri_destroy (psc->nsn->uri);
    GNUNET_free (psc->nsn->id);
    GNUNET_free (psc->nsn->update);
    GNUNET_free (psc->nsn);
  }
  GNUNET_free (psc);
}


/**
 * Closure for 'process_update_node'.
 */
struct ProcessUpdateClosure
{
  /**
   * Function to call for each node.
   */
  GNUNET_FS_IdentifierProcessor ip;

  /**
   * Closure for 'ip'.
   */
  void *ip_cls;
};


/**
 * Call the iterator in the closure for each node.
 *
 * @param cls closure (of type 'struct ProcessUpdateClosure *')
 * @param key current key code
 * @param value value in the hash map (of type 'struct NamespaceUpdateNode *')
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
process_update_node (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct ProcessUpdateClosure *pc = cls;
  struct NamespaceUpdateNode *nsn = value;

  pc->ip (pc->ip_cls, nsn->id, nsn->uri, nsn->md, nsn->update);
  return GNUNET_YES;
}


/**
 * Closure for 'find_trees'.
 */
struct FindTreeClosure
{
  /**
   * Namespace we are operating on.
   */
  struct GNUNET_FS_Namespace *ns;

  /**
   * Array with 'head's of TREEs.
   */
  struct NamespaceUpdateNode **tree_array;

  /**
   * Size of 'tree_array'
   */
  unsigned int tree_array_size;

  /**
   * Current generational ID used.
   */
  unsigned int nug;

  /**
   * Identifier for the current TREE, or UINT_MAX for none yet.
   */
  unsigned int id;
};


/**
 * Find all nodes reachable from the current node (including the
 * current node itself).  If they are in no tree, add them to the
 * current one.   If they are the head of another tree, merge the
 * trees.  If they are in the middle of another tree, let them be.
 * We can tell that a node is already in an tree by checking if
 * its 'nug' field is set to the current 'nug' value.  It is the
 * head of an tree if it is in the 'tree_array' under its respective
 * 'tree_id'.
 *
 * In short, we're trying to find the smallest number of tree to
 * cover a directed graph.
 *
 * @param cls closure (of type 'struct FindTreeClosure')
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
find_trees (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct FindTreeClosure *fc = cls;
  struct NamespaceUpdateNode *nsn = value;
  struct GNUNET_HashCode hc;

  if (nsn->nug == fc->nug)
  {
    if (UINT_MAX == nsn->tree_id)
      return GNUNET_YES;        /* circular */
    GNUNET_assert (nsn->tree_id < fc->tree_array_size);
    if (fc->tree_array[nsn->tree_id] != nsn)
      return GNUNET_YES;        /* part of "another" (directed) TREE,
                                 * and not root of it, end trace */
    if (nsn->tree_id == fc->id)
      return GNUNET_YES;        /* that's our own root (can this be?) */
    /* merge existing TREE, we have a root for both */
    fc->tree_array[nsn->tree_id] = NULL;
    if (UINT_MAX == fc->id)
      fc->id = nsn->tree_id;    /* take over ID */
  }
  else
  {
    nsn->nug = fc->nug;
    nsn->tree_id = UINT_MAX;    /* mark as undef */
    /* trace */
    GNUNET_CRYPTO_hash (nsn->update, strlen (nsn->update), &hc);
    GNUNET_CONTAINER_multihashmap_get_multiple (fc->ns->update_map, &hc,
                                                &find_trees, fc);
  }
  return GNUNET_YES;
}


/**
 * List all of the identifiers in the namespace for which we could
 * produce an update.  Namespace updates form a graph where each node
 * has a name.  Each node can have any number of URI/meta-data entries
 * which can each be linked to other nodes.  Cycles are possible.
 *
 * Calling this function with "next_id" NULL will cause the library to
 * call "ip" with a root for each strongly connected component of the
 * graph (a root being a node from which all other nodes in the Tree
 * are reachable).
 *
 * Calling this function with "next_id" being the name of a node will
 * cause the library to call "ip" with all children of the node.  Note
 * that cycles within the final tree are possible (including self-loops).
 * I know, odd definition of a tree, but the GUI will display an actual
 * tree (GtkTreeView), so that's what counts for the term here.
 *
 * @param ns namespace to inspect for updateable content
 * @param next_id ID to look for; use NULL to look for tree roots
 * @param ip function to call on each updateable identifier
 * @param ip_cls closure for ip
 */
void
GNUNET_FS_namespace_list_updateable (struct GNUNET_FS_Namespace *ns,
                                     const char *next_id,
                                     GNUNET_FS_IdentifierProcessor ip,
                                     void *ip_cls)
{
  unsigned int i;
  unsigned int nug;
  struct GNUNET_HashCode hc;
  struct NamespaceUpdateNode *nsn;
  struct ProcessUpdateClosure pc;
  struct FindTreeClosure fc;

  if (NULL == ns->update_nodes)
    read_update_information_graph (ns);
  if (NULL == ns->update_nodes)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No updateable nodes found for ID `%s'\n", next_id);
    return;                     /* no nodes */
  }
  if (NULL == ns->update_map)
  {
    /* need to construct */
    ns->update_map =
        GNUNET_CONTAINER_multihashmap_create (2 +
                                              3 * ns->update_node_count /
                                              4,
					      GNUNET_NO);
    for (i = 0; i < ns->update_node_count; i++)
    {
      nsn = ns->update_nodes[i];
      GNUNET_CRYPTO_hash (nsn->id, strlen (nsn->id), &hc);
      GNUNET_CONTAINER_multihashmap_put (ns->update_map, &hc, nsn,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    }
  }
  if (NULL != next_id)
  {
    GNUNET_CRYPTO_hash (next_id, strlen (next_id), &hc);
    pc.ip = ip;
    pc.ip_cls = ip_cls;
    GNUNET_CONTAINER_multihashmap_get_multiple (ns->update_map, &hc,
                                                &process_update_node, &pc);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Calculating TREEs to find roots of update trees\n");
  /* Find heads of TREEs in update graph */
  nug = ++ns->nug_gen;
  fc.tree_array = NULL;
  fc.tree_array_size = 0;

  for (i = 0; i < ns->update_node_count; i++)
  {
    nsn = ns->update_nodes[i];
    if (nsn->nug == nug)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "TREE of node `%s' is %u\n", nsn->id,
                  nsn->nug);
      continue;                 /* already placed in TREE */
    }
    GNUNET_CRYPTO_hash (nsn->update, strlen (nsn->update), &hc);
    nsn->nug = nug;
    nsn->tree_id = UINT_MAX;
    fc.id = UINT_MAX;
    fc.nug = nug;
    fc.ns = ns;
    GNUNET_CONTAINER_multihashmap_get_multiple (ns->update_map, &hc,
                                                &find_trees, &fc);
    if (UINT_MAX == fc.id)
    {
      /* start new TREE */
      for (fc.id = 0; fc.id < fc.tree_array_size; fc.id++)
      {
        if (fc.tree_array[fc.id] == NULL)
        {
          fc.tree_array[fc.id] = nsn;
          nsn->tree_id = fc.id;
          break;
        }
      }
      if (fc.id == fc.tree_array_size)
      {
        GNUNET_array_append (fc.tree_array, fc.tree_array_size, nsn);
        nsn->tree_id = fc.id;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Starting new TREE %u with node `%s'\n", nsn->tree_id,
                  nsn->id);
      /* put all nodes with same identifier into this TREE */
      GNUNET_CRYPTO_hash (nsn->id, strlen (nsn->id), &hc);
      fc.id = nsn->tree_id;
      fc.nug = nug;
      fc.ns = ns;
      GNUNET_CONTAINER_multihashmap_get_multiple (ns->update_map, &hc,
                                                  &find_trees, &fc);
    }
    else
    {
      /* make head of TREE "id" */
      fc.tree_array[fc.id] = nsn;
      nsn->tree_id = fc.id;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "TREE of node `%s' is %u\n", nsn->id,
                fc.id);
  }
  for (i = 0; i < fc.tree_array_size; i++)
  {
    nsn = fc.tree_array[i];
    if (NULL != nsn)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Root of TREE %u is node `%s'\n", i,
                  nsn->id);
      ip (ip_cls, nsn->id, nsn->uri, nsn->md, nsn->update);
    }
  }
  GNUNET_array_grow (fc.tree_array, fc.tree_array_size, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Done processing TREEs\n");
}


/* end of fs_namespace.c */
