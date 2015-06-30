/*
     This file is part of GNUnet
     Copyright (C) 2003-2013 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_namespace.c
 * @brief publishing to namespaces, and tracking updateable entries
 *        for our namespaces
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "fs_api.h"
#include "fs_publish_ublock.h"


/**
 * Information about an (updateable) node in the
 * namespace.
 */
struct NamespaceUpdateNode
{
  /**
   * Identifier for this node.
   */
  char *id;

  /**
   * Identifier of children of this node.
   */
  char *update;

  /**
   * Metadata for this entry.
   */
  struct GNUNET_CONTAINER_MetaData *md;

  /**
   * URI of this entry in the namespace.
   */
  struct GNUNET_FS_Uri *uri;

  /**
   * Namespace update generation ID.  Used to ensure
   * freshness of the tree_id.
   */
  unsigned int nug;

  /**
   * TREE this entry belongs to (if nug is current).
   */
  unsigned int tree_id;

};


/**
 * Handle to update information for a namespace.
 */
struct GNUNET_FS_UpdateInformationGraph
{

  /**
   * Handle to the FS service context.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * Array with information about nodes in the namespace.
   */
  struct NamespaceUpdateNode **update_nodes;

  /**
   * Private key for the namespace.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey ns;

  /**
   * Hash map mapping identifiers of update nodes
   * to the update nodes (initialized on-demand).
   */
  struct GNUNET_CONTAINER_MultiHashMap *update_map;

  /**
   * Size of the update nodes array.
   */
  unsigned int update_node_count;

  /**
   * Reference counter.
   */
  unsigned int rc;

  /**
   * Generator for unique nug numbers.
   */
  unsigned int nug_gen;
};


/**
 * Return the name of the directory in which we store
 * the update information graph for the given local namespace.
 *
 * @param h file-sharing handle
 * @param ns namespace handle
 * @return NULL on error, otherwise the name of the directory
 */
static char *
get_update_information_directory (struct GNUNET_FS_Handle *h,
				  const struct GNUNET_CRYPTO_EcdsaPrivateKey *ns)
{
  char *dn;
  char *ret;
  struct GNUNET_CRYPTO_EcdsaPublicKey pub;
  struct GNUNET_HashCode hc;
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (h->cfg, "FS", "UPDATE_DIR",
                                               &dn))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       "fs", "UPDATE_DIR");
    return NULL;
  }
  GNUNET_CRYPTO_ecdsa_key_get_public (ns, &pub);
  GNUNET_CRYPTO_hash (&pub, sizeof (pub), &hc);
  GNUNET_CRYPTO_hash_to_enc (&hc,
			     &enc);
  GNUNET_asprintf (&ret, "%s%s%s",
		   dn,
		   DIR_SEPARATOR_STR,
		   (const char *) enc.encoding);
  GNUNET_free (dn);
  return ret;
}


/**
 * Release memory occupied by UIG datastructure.
 *
 * @param uig data structure to free
 */
static void
free_update_information_graph (struct GNUNET_FS_UpdateInformationGraph *uig)
{
  unsigned int i;
  struct NamespaceUpdateNode *nsn;

  for (i = 0; i < uig->update_node_count; i++)
  {
    nsn = uig->update_nodes[i];
    GNUNET_CONTAINER_meta_data_destroy (nsn->md);
    GNUNET_FS_uri_destroy (nsn->uri);
    GNUNET_free (nsn->id);
    GNUNET_free (nsn->update);
    GNUNET_free (nsn);
  }
  GNUNET_array_grow (uig->update_nodes, uig->update_node_count,
		     0);
  if (NULL != uig->update_map)
    GNUNET_CONTAINER_multihashmap_destroy (uig->update_map);
  GNUNET_free (uig);
}


/**
 * Write a namespace's update node graph to a file.
 *
 * @param uig update information graph to dump
 */
static void
write_update_information_graph (struct GNUNET_FS_UpdateInformationGraph *uig)
{
  char *fn;
  struct GNUNET_BIO_WriteHandle *wh;
  unsigned int i;
  struct NamespaceUpdateNode *n;
  char *uris;

  fn = get_update_information_directory (uig->h,
					 &uig->ns);
  wh = GNUNET_BIO_write_open (fn);
  if (NULL == wh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to open `%s' for writing: %s\n"), STRERROR (errno));
    GNUNET_free (fn);
    return;
  }
  if (GNUNET_OK != GNUNET_BIO_write_int32 (wh, uig->update_node_count))
    goto END;
  for (i = 0; i < uig->update_node_count; i++)
  {
    n = uig->update_nodes[i];
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
 * @param h FS handle to use
 * @param ns namespace to read
 * @return update graph, never NULL
 */
static struct GNUNET_FS_UpdateInformationGraph *
read_update_information_graph (struct GNUNET_FS_Handle *h,
			       const struct GNUNET_CRYPTO_EcdsaPrivateKey *ns)
{
  struct GNUNET_FS_UpdateInformationGraph *uig;
  char *fn;
  struct GNUNET_BIO_ReadHandle *rh;
  unsigned int i;
  struct NamespaceUpdateNode *n;
  char *uris;
  uint32_t count;
  char *emsg;

  uig = GNUNET_new (struct GNUNET_FS_UpdateInformationGraph);
  uig->h = h;
  uig->ns = *ns;
  fn = get_update_information_directory (h, ns);
  if (GNUNET_YES != GNUNET_DISK_file_test (fn))
  {
    GNUNET_free (fn);
    return uig;
  }
  rh = GNUNET_BIO_read_open (fn);
  if (NULL == rh)
  {
    GNUNET_free (fn);
    return uig;
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
    goto END;
  uig->update_nodes =
    GNUNET_malloc (count * sizeof (struct NamespaceUpdateNode *));

  for (i = 0; i < count; i++)
  {
    n = GNUNET_new (struct NamespaceUpdateNode);
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
    uig->update_nodes[i] = n;
  }
  uig->update_node_count = i;
 END:
  if (GNUNET_OK != GNUNET_BIO_read_close (rh, &emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Failed to read `%s': %s\n"),
		fn, emsg);
    GNUNET_free (emsg);
  }
  GNUNET_free (fn);
  return uig;
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
  struct GNUNET_CRYPTO_EcdsaPrivateKey ns;

  /**
   * Handle to the datastore.
   */
  struct GNUNET_DATASTORE_Handle *dsh;

  /**
   * Handle to FS.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * Function to call once we're done.
   */
  GNUNET_FS_PublishContinuation cont;

  /**
   * Closure for cont.
   */
  void *cont_cls;

  /**
   * Handle for our UBlock operation request.
   */
  struct GNUNET_FS_PublishUblockContext *uc;
};


/**
 * Function called by the UBlock construction with
 * the result from the PUT (UBlock) request.
 *
 * @param cls closure of type "struct GNUNET_FS_PublishSksContext*"
 * @param msg error message (or NULL)
 */
static void
sks_publish_cont (void *cls,
		  const char *msg)
{
  struct GNUNET_FS_PublishSksContext *psc = cls;
  struct GNUNET_FS_UpdateInformationGraph *uig;

  psc->uc = NULL;
  if (NULL != msg)
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
    uig = read_update_information_graph (psc->h,
					 &psc->ns);
    GNUNET_array_append (uig->update_nodes,
			 uig->update_node_count,
			 psc->nsn);
    psc->nsn = NULL;
    write_update_information_graph (uig);
    free_update_information_graph (uig);
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
                       const struct GNUNET_CRYPTO_EcdsaPrivateKey *ns,
                       const char *identifier, const char *update,
                       const struct GNUNET_CONTAINER_MetaData *meta,
                       const struct GNUNET_FS_Uri *uri,
                       const struct GNUNET_FS_BlockOptions *bo,
                       enum GNUNET_FS_PublishOptions options,
                       GNUNET_FS_PublishContinuation cont, void *cont_cls)
{
  struct GNUNET_FS_PublishSksContext *psc;
  struct GNUNET_FS_Uri *sks_uri;

  sks_uri = GNUNET_new (struct GNUNET_FS_Uri);
  sks_uri->type = GNUNET_FS_URI_SKS;
  sks_uri->data.sks.identifier = GNUNET_strdup (identifier);
  GNUNET_CRYPTO_ecdsa_key_get_public (ns,
				    &sks_uri->data.sks.ns);

  psc = GNUNET_new (struct GNUNET_FS_PublishSksContext);
  psc->h = h;
  psc->uri = sks_uri;
  psc->cont = cont;
  psc->cont_cls = cont_cls;
  psc->ns = *ns;
  if (0 == (options & GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY))
  {
    psc->dsh = GNUNET_DATASTORE_connect (h->cfg);
    if (NULL == psc->dsh)
    {
      sks_publish_cont (psc,
			_("Failed to connect to datastore."));
      return NULL;
    }
  }
  if (NULL != update)
  {
    psc->nsn = GNUNET_new (struct NamespaceUpdateNode);
    psc->nsn->id = GNUNET_strdup (identifier);
    psc->nsn->update = GNUNET_strdup (update);
    psc->nsn->md = GNUNET_CONTAINER_meta_data_duplicate (meta);
    psc->nsn->uri = GNUNET_FS_uri_dup (uri);
  }
  psc->uc = GNUNET_FS_publish_ublock_ (h,
				       psc->dsh,
				       identifier,
				       update,
				       ns,
				       meta,
				       uri,
				       bo,
				       options,
				       &sks_publish_cont,
				       psc);
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
  if (NULL != psc->uc)
  {
    GNUNET_FS_publish_ublock_cancel_ (psc->uc);
    psc->uc = NULL;
  }
  if (NULL != psc->dsh)
  {
    GNUNET_DATASTORE_disconnect (psc->dsh, GNUNET_NO);
    psc->dsh = NULL;
  }
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
process_update_node (void *cls,
		     const struct GNUNET_HashCode *key,
		     void *value)
{
  struct ProcessUpdateClosure *pc = cls;
  struct NamespaceUpdateNode *nsn = value;

  pc->ip (pc->ip_cls,
	  nsn->id,
	  nsn->uri,
	  nsn->md,
	  nsn->update);
  return GNUNET_YES;
}


/**
 * Closure for 'find_trees'.
 */
struct FindTreeClosure
{
  /**
   * UIG we are operating on.
   */
  struct GNUNET_FS_UpdateInformationGraph *uig;

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
find_trees (void *cls,
	    const struct GNUNET_HashCode *key,
	    void *value)
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
    GNUNET_CONTAINER_multihashmap_get_multiple (fc->uig->update_map, &hc,
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
 * @param h fs handle to use
 * @param ns namespace to inspect for updateable content
 * @param next_id ID to look for; use NULL to look for tree roots
 * @param ip function to call on each updateable identifier
 * @param ip_cls closure for ip
 */
void
GNUNET_FS_namespace_list_updateable (struct GNUNET_FS_Handle *h,
				     const struct GNUNET_CRYPTO_EcdsaPrivateKey *ns,
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
  struct GNUNET_FS_UpdateInformationGraph *uig;

  uig = read_update_information_graph (h, ns);
  if (NULL == uig->update_nodes)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No updateable nodes found for ID `%s'\n", next_id);
    free_update_information_graph (uig);
    return;                     /* no nodes */
  }
  uig->update_map =
    GNUNET_CONTAINER_multihashmap_create (2 +
					  3 * uig->update_node_count /
					  4,
					  GNUNET_NO);
  for (i = 0; i < uig->update_node_count; i++)
  {
    nsn = uig->update_nodes[i];
    GNUNET_CRYPTO_hash (nsn->id, strlen (nsn->id), &hc);
    GNUNET_CONTAINER_multihashmap_put (uig->update_map, &hc, nsn,
				       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  }
  if (NULL != next_id)
  {
    GNUNET_CRYPTO_hash (next_id, strlen (next_id), &hc);
    pc.ip = ip;
    pc.ip_cls = ip_cls;
    GNUNET_CONTAINER_multihashmap_get_multiple (uig->update_map, &hc,
                                                &process_update_node, &pc);
    free_update_information_graph (uig);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Calculating TREEs to find roots of update trees\n");
  /* Find heads of TREEs in update graph */
  nug = ++uig->nug_gen;
  fc.tree_array = NULL;
  fc.tree_array_size = 0;

  for (i = 0; i < uig->update_node_count; i++)
  {
    nsn = uig->update_nodes[i];
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
    fc.uig = uig;
    GNUNET_CONTAINER_multihashmap_get_multiple (uig->update_map, &hc,
                                                &find_trees, &fc);
    if (UINT_MAX == fc.id)
    {
      /* start new TREE */
      for (fc.id = 0; fc.id < fc.tree_array_size; fc.id++)
      {
        if (NULL == fc.tree_array[fc.id])
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
      fc.uig = uig;
      GNUNET_CONTAINER_multihashmap_get_multiple (uig->update_map, &hc,
                                                  &find_trees, &fc);
    }
    else
    {
      /* make head of TREE "id" */
      fc.tree_array[fc.id] = nsn;
      nsn->tree_id = fc.id;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"TREE of node `%s' is %u\n", nsn->id,
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
  free_update_information_graph (uig);
}


/* end of fs_namespace.c */
