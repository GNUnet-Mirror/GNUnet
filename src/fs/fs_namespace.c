/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
#include "gnunet_fs_service.h"


/**
 * Publish an advertismement for a namespace.  
 *
 * @param h handle to the file sharing subsystem
 * @param namespace handle for the namespace that should be advertised
 * @param meta meta-data for the namespace advertisement
 * @param anonymity for the namespace advertismement
 * @param priority for the namespace advertisement
 * @param expiration for the namespace advertisement
 * @param advertisementURI the keyword (!) URI to advertise the
 *        namespace under (we will create a GNUNET_EC_KNBlock)
 * @param rootEntry name of the root entry in the namespace (for
 *        the namespace advertisement)
 *
 * @return uri of the advertisement
 */
struct GNUNET_FS_Uri *
GNUNET_FS_namespace_advertise (struct GNUNET_FS_Handle *h,
			       struct GNUNET_FS_Namespace *namespace,
			       const struct GNUNET_CONTAINER_MetaData *meta,
			       uint32_t anonymity,
			       uint32_t priority,
			       struct GNUNET_TIME_Absolute expiration,
			       const struct GNUNET_FS_Uri *advertisementURI,
			       const char *rootEntry)
{
  return NULL;
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
  return NULL;
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
  return GNUNET_SYSERR;
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
}

/* end of fs_namespace.c */

#if 0
/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/namespace.c
 * @brief creation, deletion and advertising of namespaces
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fs_lib.h"
#include "ecrs_core.h"
#include "ecrs.h"

#define PSEUDODIR "data/namespace/keys/"
#define INITVALUE "GNUnet!!"
#define MAX_SBLOCK_SIZE 32000

static char *
getPseudonymFileName (struct GNUNET_GE_Context *ectx,
                      struct GNUNET_GC_Configuration *cfg,
                      const GNUNET_HashCode * pid)
{
  char *gnHome;
  char *fileName;
  GNUNET_EncName enc;

  GNUNET_GC_get_configuration_value_filename (cfg,
                                              "GNUNET",
                                              "GNUNET_HOME",
                                              GNUNET_DEFAULT_HOME_DIRECTORY,
                                              &fileName);
  gnHome = GNUNET_expand_file_name (ectx, fileName);
  GNUNET_free (fileName);
  fileName =
    GNUNET_malloc (strlen (gnHome) + strlen (PSEUDODIR) +
                   sizeof (GNUNET_EncName) + 2);
  strcpy (fileName, gnHome);
  GNUNET_free (gnHome);
  strcat (fileName, DIR_SEPARATOR_STR);
  strcat (fileName, PSEUDODIR);
  GNUNET_disk_directory_create (ectx, fileName);
  if (pid != NULL)
    {
      GNUNET_hash_to_enc (pid, &enc);
      strcat (fileName, (char *) &enc);
    }
  return fileName;
}


/**
 * Check if the given namespace exists (locally).
 *
 * @return GNUNET_OK if the namespace exists, GNUNET_SYSERR if not
 */
int
GNUNET_ECRS_namespace_test_exists (struct GNUNET_GE_Context *ectx,
                                   struct GNUNET_GC_Configuration *cfg,
                                   const GNUNET_HashCode * pid)
{
  char *fileName;
  int ret;

  fileName = getPseudonymFileName (ectx, cfg, pid);
  ret = GNUNET_disk_file_test (ectx, fileName);
  GNUNET_free (fileName);
  return ret;
}

/**
 * Delete a local namespace.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_ECRS_namespace_delete (struct GNUNET_GE_Context *ectx,
                              struct GNUNET_GC_Configuration *cfg,
                              const GNUNET_HashCode * pid)
{
  char *fileName;

  fileName = getPseudonymFileName (ectx, cfg, pid);
  if (GNUNET_YES != GNUNET_disk_file_test (ectx, fileName))
    {
      GNUNET_free (fileName);
      return GNUNET_SYSERR;     /* no such namespace */
    }
  if (0 != UNLINK (fileName))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_BULK, "unlink", fileName);
      GNUNET_free (fileName);
      return GNUNET_SYSERR;
    }
  GNUNET_free (fileName);
  return GNUNET_OK;
}

/**
 * Write the private key of the namespace to a file.
 */
static int
write_namespace_key (struct GNUNET_GC_Configuration *cfg,
                     const struct GNUNET_RSA_PrivateKey *key)
{
  GNUNET_RSA_PrivateKeyEncoded *namespace_priv_key_encoded;
  char *fileName;
  GNUNET_RSA_PublicKey pubk;
  GNUNET_HashCode pid;

  GNUNET_RSA_get_public_key (key, &pubk);
  GNUNET_hash (&pubk, sizeof (GNUNET_RSA_PublicKey), &pid);
  fileName = getPseudonymFileName (NULL, cfg, &pid);
  if (GNUNET_YES == GNUNET_disk_file_test (NULL, fileName))
    {
      GNUNET_GE_BREAK (NULL, 0);        /* hash collision!? */
      GNUNET_free (fileName);
      return GNUNET_SYSERR;
    }
  namespace_priv_key_encoded = GNUNET_RSA_encode_key (key);
  GNUNET_disk_file_write (NULL, fileName,
                          (const char *) namespace_priv_key_encoded,
                          ntohs (namespace_priv_key_encoded->len), "600");
  GNUNET_free (fileName);
  GNUNET_free (namespace_priv_key_encoded);
  return GNUNET_OK;
}

/**
 * Create a new namespace (and publish an advertismement).
 * This publishes both an GNUNET_EC_NBlock in the namespace itself
 * as well as KNBlocks under all keywords specified in
 * the advertisementURI.
 *
 * @param anonymity_level for the namespace advertismement
 * @param priority for the namespace advertisement
 * @param expiration for the namespace advertisement
 * @param advertisementURI the keyword (!) URI to advertise the
 *        namespace under (GNUNET_EC_KNBlock)
 * @param meta meta-data for the namespace advertisement
 *        (will be used to derive a name)
 * @param rootEntry name of the root entry in the namespace (for
 *        the namespace advertisement)
 * @param rootURI set to the URI of the namespace, NULL if
 *        no advertisement was created
 *
 * @return URI on success, NULL on error
 */
struct GNUNET_ECRS_URI *
GNUNET_ECRS_namespace_create (struct GNUNET_GE_Context *ectx,
                              struct GNUNET_GC_Configuration *cfg,
                              const struct GNUNET_CONTAINER_MetaData *meta,
                              uint32_t anonymityLevel,
                              uint32_t priority,
                              GNUNET_CronTime expiration,
                              const struct GNUNET_ECRS_URI *advertisementURI,
                              const char *rootEntry)
{
  struct GNUNET_ECRS_URI *rootURI;
  struct GNUNET_RSA_PrivateKey *namespace_priv_key;
  GNUNET_HashCode hc;
  struct GNUNET_ClientServerConnection *sock;
  GNUNET_DatastoreValue *value;
  GNUNET_DatastoreValue *knvalue;
  unsigned int size;
  unsigned int mdsize;
  struct GNUNET_RSA_PrivateKey *pk;
  GNUNET_EC_SBlock *sb;
  GNUNET_EC_KSBlock *ksb;
  char **keywords;
  const char *keyword;
  unsigned int keywordCount;
  int i;
  char *cpy;
  char *rtgt;

  if ((advertisementURI != NULL)
      && (!GNUNET_ECRS_uri_test_ksk (advertisementURI)))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  namespace_priv_key = GNUNET_RSA_create_key ();
  if (GNUNET_OK != write_namespace_key (cfg, namespace_priv_key))
    {
      GNUNET_RSA_free_key (namespace_priv_key);
      return NULL;
    }

  /* create advertisements */
  mdsize = GNUNET_meta_data_get_serialized_size (meta, GNUNET_SERIALIZE_PART);
  size = mdsize + sizeof (GNUNET_EC_SBlock) + strlen (rootEntry) + 2;
  if (size > MAX_SBLOCK_SIZE)
    {
      size = MAX_SBLOCK_SIZE;
      mdsize = size - sizeof (GNUNET_EC_SBlock) - strlen (rootEntry) - 2;
    }
  value = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + size);
  memset (value, 0, sizeof (GNUNET_DatastoreValue) + size);
  sb = (GNUNET_EC_SBlock *) & value[1];
  sb->type = htonl (GNUNET_ECRS_BLOCKTYPE_SIGNED);
  GNUNET_RSA_get_public_key (namespace_priv_key, &sb->subspace);
  rtgt = (char *) &sb[1];
  memcpy (rtgt, rootEntry, strlen (rootEntry) + 1);
  mdsize = GNUNET_meta_data_serialize (ectx,
                                       meta,
                                       &rtgt[strlen (rootEntry) + 2],
                                       mdsize, GNUNET_SERIALIZE_PART);
  if (mdsize == -1)
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_RSA_free_key (namespace_priv_key);
      GNUNET_free (value);
      return NULL;
    }
  size = mdsize + sizeof (GNUNET_EC_SBlock) + strlen (rootEntry) + 2;
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_OK == GNUNET_RSA_sign (namespace_priv_key,
                                                  size
                                                  -
                                                  sizeof
                                                  (GNUNET_RSA_Signature) -
                                                  sizeof
                                                  (GNUNET_RSA_PublicKey) -
                                                  sizeof (unsigned int),
                                                  &sb->identifier,
                                                  &sb->signature));
  value->size = htonl (sizeof (GNUNET_DatastoreValue) + size);
  value->type = htonl (GNUNET_ECRS_BLOCKTYPE_SIGNED);
  value->priority = htonl (priority);
  value->anonymity_level = htonl (anonymityLevel);
  value->expiration_time = GNUNET_htonll (expiration);
  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    {
      GNUNET_free (value);
      GNUNET_RSA_free_key (namespace_priv_key);
      return NULL;
    }
  if (GNUNET_OK != GNUNET_FS_insert (sock, value))
    {
      GNUNET_free (value);
      GNUNET_client_connection_destroy (sock);
      GNUNET_RSA_free_key (namespace_priv_key);
      return NULL;
    }


  /* publish KNBlocks */
  size += sizeof (GNUNET_EC_KSBlock) - sizeof (GNUNET_EC_SBlock);
  knvalue = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + size);
  *knvalue = *value;
  knvalue->type = htonl (GNUNET_ECRS_BLOCKTYPE_KEYWORD_SIGNED);
  knvalue->size = htonl (sizeof (GNUNET_DatastoreValue) + size);
  ksb = (GNUNET_EC_KSBlock *) & knvalue[1];
  ksb->type = htonl (GNUNET_ECRS_BLOCKTYPE_KEYWORD_SIGNED);
  memcpy (&ksb->sblock,
          sb, sizeof (GNUNET_EC_SBlock) + mdsize + strlen (rootEntry) + 2);

  if (advertisementURI != NULL)
    {
      keywords = advertisementURI->data.ksk.keywords;
      keywordCount = advertisementURI->data.ksk.keywordCount;
      cpy =
        GNUNET_malloc (size - sizeof (GNUNET_EC_KBlock) -
                       sizeof (unsigned int));
      memcpy (cpy,
              &ksb->sblock,
              size - sizeof (GNUNET_EC_KBlock) - sizeof (unsigned int));
      for (i = 0; i < keywordCount; i++)
        {
          keyword = keywords[i];
          /* first character of keyword indicates
             mandatory or not -- ignore for hashing! */
          GNUNET_hash (&keyword[1], strlen (&keyword[1]), &hc);
          pk = GNUNET_RSA_create_key_from_hash (&hc);
          GNUNET_RSA_get_public_key (pk, &ksb->kblock.keyspace);
          GNUNET_GE_ASSERT (ectx,
                            size - sizeof (GNUNET_EC_KBlock) -
                            sizeof (unsigned int) ==
                            sizeof (GNUNET_EC_SBlock) + mdsize +
                            strlen (rootEntry) + 2);
          GNUNET_ECRS_encryptInPlace (&hc, &ksb->sblock,
                                      size - sizeof (GNUNET_EC_KBlock) -
                                      sizeof (unsigned int));

          GNUNET_GE_ASSERT (ectx,
                            GNUNET_OK == GNUNET_RSA_sign (pk,
                                                          size -
                                                          sizeof
                                                          (GNUNET_EC_KBlock) -
                                                          sizeof (unsigned
                                                                  int),
                                                          &ksb->sblock,
                                                          &ksb->
                                                          kblock.signature));
          /* extra check: verify sig */
          GNUNET_RSA_free_key (pk);
          if (GNUNET_OK != GNUNET_FS_insert (sock, knvalue))
            {
              GNUNET_GE_BREAK (ectx, 0);
              GNUNET_free (cpy);
              GNUNET_free (knvalue);
              GNUNET_free (value);
              GNUNET_client_connection_destroy (sock);
              GNUNET_RSA_free_key (namespace_priv_key);
              return NULL;
            }
          /* restore nblock to avoid re-encryption! */
          memcpy (&ksb->sblock,
                  cpy,
                  size - sizeof (GNUNET_EC_KBlock) - sizeof (unsigned int));
        }
      GNUNET_free (cpy);
    }
  rootURI = GNUNET_malloc (sizeof (URI));
  rootURI->type = sks;
  GNUNET_hash (&sb->subspace,
               sizeof (GNUNET_RSA_PublicKey), &rootURI->data.sks.namespace);
  rootURI->data.sks.identifier = GNUNET_strdup (rootEntry);
  GNUNET_free (knvalue);
  GNUNET_free (value);
  GNUNET_client_connection_destroy (sock);
  GNUNET_RSA_free_key (namespace_priv_key);

  return rootURI;
}

static struct GNUNET_RSA_PrivateKey *
read_namespace_key (struct GNUNET_GC_Configuration *cfg,
                    const GNUNET_HashCode * pid)
{
  char *fileName;
  GNUNET_RSA_PrivateKeyEncoded *hke;
  struct GNUNET_RSA_PrivateKey *hk;
  char *dst;
  unsigned long long len;

  fileName = getPseudonymFileName (NULL, cfg, pid);
  if (GNUNET_OK != GNUNET_disk_file_size (NULL, fileName, &len, GNUNET_YES))
    {
      GNUNET_free (fileName);
      return NULL;
    }
  if (len < 2)
    {
      GNUNET_GE_LOG (NULL, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("File `%s' does not contain a pseudonym.\n"),
                     fileName);
      GNUNET_free (fileName);
      return NULL;
    }
  dst = GNUNET_malloc (len);
  len = GNUNET_disk_file_read (NULL, fileName, len, dst);
  hke = (GNUNET_RSA_PrivateKeyEncoded *) dst;
  if (ntohs (hke->len) != len)
    {
      GNUNET_GE_LOG (NULL, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Format of pseudonym `%s' is invalid.\n"), fileName);
      GNUNET_free (fileName);
      GNUNET_free (hke);
      return NULL;
    }
  GNUNET_free (fileName);
  hk = GNUNET_RSA_decode_key (hke);
  GNUNET_free (hke);
  return hk;
}


/**
 * Add an entry into a namespace.
 *
 * @param dstU to which URI should the namespace entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 * @param thisId name of this entry in the namespace (keyword/identifier)
 * @param nextId name of the update for this entry (to be published in
 *               the future; maybe NULL)
 * @param pid unique identifier of the namespace/pseudonym
 * @return URI on success, NULL on error
 */
struct GNUNET_ECRS_URI *
GNUNET_ECRS_namespace_add_content (struct GNUNET_GE_Context *ectx,
                                   struct GNUNET_GC_Configuration *cfg,
                                   const GNUNET_HashCode * pid,
                                   uint32_t anonymityLevel,
                                   uint32_t priority,
                                   GNUNET_CronTime expiration,
                                   const char *thisId,
                                   const char *nextId,
                                   const struct GNUNET_ECRS_URI *dstU,
                                   const struct GNUNET_MetaData *md)
{
  struct GNUNET_ECRS_URI *uri;
  struct GNUNET_ClientServerConnection *sock;
  GNUNET_DatastoreValue *value;
  unsigned int size;
  unsigned int mdsize;
  struct GNUNET_RSA_PrivateKey *hk;
  GNUNET_EC_SBlock *sb;
  char *dstURI;
  char *destPos;
  GNUNET_HashCode hc;           /* hash of thisId = key */
  GNUNET_HashCode hc2;          /* hash of hc = identifier */
  int ret;
  unsigned int nidlen;

  hk = read_namespace_key (cfg, pid);
  if (hk == NULL)
    return NULL;

  /* THEN: construct GNUNET_EC_SBlock */
  dstURI = GNUNET_ECRS_uri_to_string (dstU);
  mdsize = GNUNET_meta_data_get_serialized_size (md, GNUNET_SERIALIZE_PART);
  if (nextId == NULL)
    nextId = "";
  nidlen = strlen (nextId) + 1;
  size = mdsize + sizeof (GNUNET_EC_SBlock) + strlen (dstURI) + 1 + nidlen;
  if (size > MAX_SBLOCK_SIZE)
    {
      size = MAX_SBLOCK_SIZE;
      mdsize =
        size - (sizeof (GNUNET_EC_SBlock) + strlen (dstURI) + 1 + nidlen);
    }
  value = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + size);
  sb = (GNUNET_EC_SBlock *) & value[1];
  sb->type = htonl (GNUNET_ECRS_BLOCKTYPE_SIGNED);
  destPos = (char *) &sb[1];
  memcpy (destPos, nextId, nidlen);
  destPos += nidlen;
  memcpy (destPos, dstURI, strlen (dstURI) + 1);
  destPos += strlen (dstURI) + 1;
  mdsize = GNUNET_meta_data_serialize (ectx,
                                       md,
                                       destPos,
                                       mdsize, GNUNET_SERIALIZE_PART);
  if (mdsize == -1)
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_free (dstURI);
      GNUNET_RSA_free_key (hk);
      GNUNET_free (value);
      return NULL;
    }
  size = sizeof (GNUNET_EC_SBlock) + mdsize + strlen (dstURI) + 1 + nidlen;
  value->size = htonl (sizeof (GNUNET_DatastoreValue) + size);
  value->type = htonl (GNUNET_ECRS_BLOCKTYPE_SIGNED);
  value->priority = htonl (priority);
  value->anonymity_level = htonl (anonymityLevel);
  value->expiration_time = GNUNET_htonll (expiration);
  GNUNET_hash (thisId, strlen (thisId), &hc);
  GNUNET_hash (&hc, sizeof (GNUNET_HashCode), &hc2);
  uri = GNUNET_malloc (sizeof (URI));
  uri->type = sks;
  GNUNET_RSA_get_public_key (hk, &sb->subspace);
  GNUNET_hash (&sb->subspace,
               sizeof (GNUNET_RSA_PublicKey), &uri->data.sks.namespace);
  GNUNET_GE_BREAK (ectx, 0 == memcmp (&uri->data.sks.namespace,
                                      pid, sizeof (GNUNET_HashCode)));
  uri->data.sks.identifier = GNUNET_strdup (thisId);
  GNUNET_hash_xor (&hc2, &uri->data.sks.namespace, &sb->identifier);
  GNUNET_ECRS_encryptInPlace (&hc, &sb[1], size - sizeof (GNUNET_EC_SBlock));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_OK == GNUNET_RSA_sign (hk,
                                                  size
                                                  -
                                                  sizeof
                                                  (GNUNET_RSA_Signature) -
                                                  sizeof
                                                  (GNUNET_RSA_PublicKey) -
                                                  sizeof (unsigned int),
                                                  &sb->identifier,
                                                  &sb->signature));
  GNUNET_RSA_free_key (hk);
  sock = GNUNET_client_connection_create (ectx, cfg);
  ret = GNUNET_FS_insert (sock, value);
  if (ret != GNUNET_OK)
    {
      GNUNET_free (uri);
      uri = NULL;
    }
  GNUNET_client_connection_destroy (sock);
  GNUNET_free (value);
  GNUNET_free (dstURI);

  return uri;
}

struct lNCLS
{
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
  GNUNET_ECRS_NamespaceInfoProcessor cb;
  void *cls;
  int cnt;
};

static int
processFile_ (void *cls, const char *fileName)
{
  struct lNCLS *c = cls;
  struct GNUNET_RSA_PrivateKey *hk;
  GNUNET_RSA_PrivateKeyEncoded *hke;
  char *dst;
  unsigned long long len;
  GNUNET_HashCode namespace;
  GNUNET_RSA_PublicKey pk;
  const char *name;

  if (GNUNET_OK !=
      GNUNET_disk_file_size (c->ectx, fileName, &len, GNUNET_YES))
    return GNUNET_OK;
  if (len < 2)
    {
      GNUNET_GE_LOG (c->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Format of file `%s' is invalid, trying to remove.\n"),
                     fileName);
      UNLINK (fileName);
      return GNUNET_OK;
    }
  dst = GNUNET_malloc (len);
  len = GNUNET_disk_file_read (c->ectx, fileName, len, dst);
  hke = (GNUNET_RSA_PrivateKeyEncoded *) dst;
  if (ntohs (hke->len) != len)
    {
      GNUNET_GE_LOG (c->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Format of file `%s' is invalid, trying to remove.\n"),
                     fileName);
      UNLINK (fileName);
      GNUNET_free (hke);
      return GNUNET_OK;
    }
  hk = GNUNET_RSA_decode_key (hke);
  GNUNET_free (hke);
  if (hk == NULL)
    {
      GNUNET_GE_LOG (c->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Format of file `%s' is invalid, trying to remove.\n"),
                     fileName);
      UNLINK (fileName);
      GNUNET_GE_BREAK (c->ectx, 0);
      return GNUNET_SYSERR;
    }
  GNUNET_RSA_get_public_key (hk, &pk);
  GNUNET_RSA_free_key (hk);
  GNUNET_hash (&pk, sizeof (GNUNET_RSA_PublicKey), &namespace);
  if (NULL != c->cb)
    {
      name = fileName;
      while (NULL != strstr (name, DIR_SEPARATOR_STR))
        name = 1 + strstr (name, DIR_SEPARATOR_STR);
      if (GNUNET_OK == c->cb (&namespace, name, c->cls))
        c->cnt++;
      else
        c->cnt = GNUNET_SYSERR;
    }
  else
    c->cnt++;
  return GNUNET_OK;
}

/**
 * Build a list of all available namespaces
 *
 * @param list where to store the names (is allocated, caller frees)
 * @return GNUNET_SYSERR on error, otherwise the number of pseudonyms in list
 */
int
GNUNET_ECRS_get_namespaces (struct GNUNET_GE_Context *ectx,
                            struct GNUNET_GC_Configuration *cfg,
                            GNUNET_ECRS_NamespaceInfoProcessor cb, void *cls)
{
  char *dirName;
  struct lNCLS myCLS;

  myCLS.cls = cls;
  myCLS.cb = cb;
  myCLS.cnt = 0;
  myCLS.ectx = ectx;
  myCLS.cfg = cfg;
  dirName = getPseudonymFileName (ectx, cfg, NULL);
  GNUNET_disk_directory_scan (ectx, dirName, &processFile_, &myCLS);
  GNUNET_free (dirName);
  return myCLS.cnt;
}



/* end of namespace.c */
#endif
