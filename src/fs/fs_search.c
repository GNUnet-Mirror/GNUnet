/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_search.c
 * @brief Helper functions for searching.
 * @author Christian Grothoff
 *
 * TODO:
 * - handle namespace advertisements (NBlocks, see FIXME;
 *   note that we currently use KBLOCK instead of ANY when
 *   searching => NBLOCKS would not fit! FIX this as well!)
 * - add support for pushing "already seen" information
 *   to FS service for bloomfilter (can wait)
 * - handle availability probes (can wait)
 * - make operations persistent (can wait)
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_fs_service.h"
#include "gnunet_protocols.h"
#include "fs.h"

#define DEBUG_SEARCH GNUNET_NO



/**
 * Fill in all of the generic fields for 
 * a search event.
 *
 * @param pi structure to fill in
 * @param sc overall search context
 */
static void
make_search_status (struct GNUNET_FS_ProgressInfo *pi,
		    struct GNUNET_FS_SearchContext *sc)
{
  pi->value.search.sc = sc;
  pi->value.search.cctx
    = sc->client_info;
  pi->value.search.pctx
    = (sc->parent == NULL) ? NULL : sc->parent->client_info;
  pi->value.search.query 
    = sc->uri;
  pi->value.search.duration = GNUNET_TIME_absolute_get_duration (sc->start_time);
  pi->value.search.anonymity = sc->anonymity;
}


/**
 * Check if the given result is identical
 * to the given URI.
 * 
 * @param cls points to the URI we check against
 * @param key not used
 * @param value a "struct SearchResult" who's URI we
 *        should compare with
 * @return GNUNET_SYSERR if the result is present,
 *         GNUNET_OK otherwise
 */
static int
test_result_present (void *cls,
		     const GNUNET_HashCode * key,
		     void *value)
{
  const struct GNUNET_FS_Uri *uri = cls;
  struct SearchResult *sr = value;

  if (GNUNET_FS_uri_test_equal (uri,
				sr->uri))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * We've found a new CHK result.  Let the client
 * know about it.
 * 
 * @param sc the search context
 * @param sr the specific result
 */
static void
notify_client_chk_result (struct GNUNET_FS_SearchContext *sc, 
			  struct SearchResult *sr)
{			  
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_SEARCH_RESULT;
  make_search_status (&pi, sc);
  pi.value.search.specifics.result.meta = sr->meta;
  pi.value.search.specifics.result.uri = sr->uri;
  sr->client_info = sc->h->upcb (sc->h->upcb_cls,
				 &pi);
}


/**
 * We've found new information about an existing CHK result.  Let the
 * client know about it.
 * 
 * @param sc the search context
 * @param sr the specific result
 */
static void
notify_client_chk_update (struct GNUNET_FS_SearchContext *sc, 
			  struct SearchResult *sr)
{			  
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_SEARCH_UPDATE;
  make_search_status (&pi, sc);
  pi.value.search.specifics.update.cctx = sr->client_info;
  pi.value.search.specifics.update.meta = sr->meta;
  pi.value.search.specifics.update.uri = sr->uri;
  pi.value.search.specifics.update.availability_rank
    = 2*sr->availability_success - sr->availability_trials;
  pi.value.search.specifics.update.availability_certainty 
    = sr->availability_trials;
  pi.value.search.specifics.update.applicability_rank 
    = sr->optional_support;
  sr->client_info = sc->h->upcb (sc->h->upcb_cls,
				 &pi);
}


/**
 * Context for "get_result_present".
 */
struct GetResultContext 
{
  /**
   * The URI we're looking for.
   */
  const struct GNUNET_FS_Uri *uri;

  /**
   * Where to store a pointer to the search
   * result struct if we found a match.
   */
  struct SearchResult *sr;
};


/**
 * Check if the given result is identical to the given URI and if so
 * return it.
 * 
 * @param cls a "struct GetResultContext"
 * @param key not used
 * @param value a "struct SearchResult" who's URI we
 *        should compare with
 * @return GNUNET_OK
 */
static int
get_result_present (void *cls,
		     const GNUNET_HashCode * key,
		     void *value)
{
  struct GetResultContext *grc = cls;
  struct SearchResult *sr = value;

  if (GNUNET_FS_uri_test_equal (grc->uri,
				sr->uri))
    grc->sr = sr;
  return GNUNET_OK;
}


/**
 * We have received a KSK result.  Check how it fits in with the
 * overall query and notify the client accordingly.
 *
 * @param sc context for the overall query
 * @param ent entry for the specific keyword
 * @param uri the URI that was found
 * @param meta metadata associated with the URI
 *        under the "ent" keyword
 */
static void
process_ksk_result (struct GNUNET_FS_SearchContext *sc, 
		    struct SearchRequestEntry *ent,
		    const struct GNUNET_FS_Uri *uri,
		    const struct GNUNET_CONTAINER_MetaData *meta)
{
  GNUNET_HashCode key;
  struct SearchResult *sr;
  struct GetResultContext grc;
  int is_new;

  /* check if new */
  GNUNET_FS_uri_to_key (uri, &key);
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_get_multiple (ent->results,
						  &key,
						  &test_result_present,
						  (void*) uri))
    return; /* duplicate result */
  /* try to find search result in master map */
  grc.sr = NULL;
  grc.uri = uri;
  GNUNET_CONTAINER_multihashmap_get_multiple (sc->master_result_map,
					      &key,
					      &get_result_present,
					      &grc);
  sr = grc.sr;
  is_new = (NULL == sr) || (sr->mandatory_missing > 0);
  if (NULL == sr)
    {
      sr = GNUNET_malloc (sizeof (struct SearchResult));
      sr->uri = GNUNET_FS_uri_dup (uri);
      sr->meta = GNUNET_CONTAINER_meta_data_duplicate (meta);
      sr->mandatory_missing = sc->mandatory_count;
      GNUNET_CONTAINER_multihashmap_put (sc->master_result_map,
					 &key,
					 sr,
					 GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    }
  else
    {
      /* FIXME: consider combining the meta data */
    }
  /* check if mandatory satisfied */
  if (ent->mandatory)
    sr->mandatory_missing--;
  else
    sr->optional_support++;
  if (0 != sr->mandatory_missing)
    return;
  if (is_new)
    notify_client_chk_result (sc, sr);
  else
    notify_client_chk_update (sc, sr);
  /* FIXME: consider starting probes for "sr" */
}


/**
 * Start search for content, internal API.
 *
 * @param h handle to the file sharing subsystem
 * @param uri specifies the search parameters; can be
 *        a KSK URI or an SKS URI.
 * @param anonymity desired level of anonymity
 * @param cctx client context
 * @param parent parent search (for namespace update searches)
 * @return context that can be used to control the search
 */
static struct GNUNET_FS_SearchContext *
search_start (struct GNUNET_FS_Handle *h,
	      const struct GNUNET_FS_Uri *uri,
	      uint32_t anonymity,
	      void *cctx,
	      struct GNUNET_FS_SearchContext *parent);


/**
 * We have received an SKS result.  Start searching for updates and
 * notify the client if it is a new result.
 *
 * @param sc context for the overall query
 * @param id_update identifier for updates, NULL for none
 * @param uri the URI that was found
 * @param meta metadata associated with the URI
  */
static void
process_sks_result (struct GNUNET_FS_SearchContext *sc, 
		    const char *id_update,
		    const struct GNUNET_FS_Uri *uri,
		    const struct GNUNET_CONTAINER_MetaData *meta)
{
  struct GNUNET_FS_Uri uu;
  GNUNET_HashCode key;
  struct SearchResult *sr;

  /* check if new */
  GNUNET_FS_uri_to_key (uri, &key);
  GNUNET_CRYPTO_hash_xor (&uri->data.chk.chk.key,
			  &uri->data.chk.chk.query,
			  &key);
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_get_multiple (sc->master_result_map,
						  &key,
						  &test_result_present,
						  (void*) uri))
    return; /* duplicate result */
  sr = GNUNET_malloc (sizeof (struct SearchResult));
  sr->uri = GNUNET_FS_uri_dup (uri);
  sr->meta = GNUNET_CONTAINER_meta_data_duplicate (meta);
  GNUNET_CONTAINER_multihashmap_put (sc->master_result_map,
				     &key,
				     sr,
				     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  /* FIXME: consider starting probes for "sr" */

  /* notify client */
  notify_client_chk_result (sc, sr);
  /* search for updates */
  if (strlen (id_update) == 0)
    return; /* no updates */
  uu.type = sks;
  uu.data.sks.namespace = sc->uri->data.sks.namespace;
  uu.data.sks.identifier = GNUNET_strdup (id_update);
  /* FIXME: should attach update search
     to the individual result, not
     the entire SKS search! */
  search_start (sc->h,
		&uu,
		sc->anonymity,
		NULL,
		sc);
}


/**
 * Process a keyword-search result.
 *
 * @param sc our search context
 * @param kb the kblock
 * @param size size of kb
 */
static void
process_kblock (struct GNUNET_FS_SearchContext *sc,
		const struct KBlock *kb,
		size_t size)
{
  unsigned int i;
  size_t j;
  GNUNET_HashCode q;
  char pt[size - sizeof (struct KBlock)];
  struct GNUNET_CRYPTO_AesSessionKey skey;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  const char *eos;
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_FS_Uri *uri;
  char *emsg;
  
  GNUNET_CRYPTO_hash (&kb->keyspace,
		      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
		      &q);
  /* find key */
  for (i=0;i<sc->uri->data.ksk.keywordCount;i++)
    if (0 == memcmp (&q,
		     &sc->requests[i].query,
		     sizeof (GNUNET_HashCode)))
      break;
  if (i == sc->uri->data.ksk.keywordCount)
    {
      /* oops, does not match any of our keywords!? */
      GNUNET_break (0);
      return;
    }
  /* decrypt */
  GNUNET_CRYPTO_hash_to_aes_key (&sc->requests[i].key, &skey, &iv);
  GNUNET_CRYPTO_aes_decrypt (&kb[1],
			     size - sizeof (struct KBlock),
			     &skey,
			     &iv,
			     pt);
  /* parse */
  eos = memchr (pt, 0, sizeof (pt));
  if (NULL == eos)
    {
      GNUNET_break_op (0);
      return;
    }
  j = eos - pt + 1;
  if (sizeof (pt) == j)
    meta = GNUNET_CONTAINER_meta_data_create ();
  else
    meta = GNUNET_CONTAINER_meta_data_deserialize (&pt[j],
						   sizeof (pt) - j);
  if (meta == NULL)
    {
      GNUNET_break_op (0);       /* kblock malformed */
      return;
    }
  uri = GNUNET_FS_uri_parse (pt, &emsg);
  if (uri == NULL)
    {
      GNUNET_break_op (0);       /* kblock malformed */
      GNUNET_free_non_null (emsg);
      GNUNET_CONTAINER_meta_data_destroy (meta);
      return;
    }
  /* process */
  process_ksk_result (sc, &sc->requests[i], uri, meta);

  /* clean up */
  GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_FS_uri_destroy (uri);
}


/**
 * Process a namespace-search result.
 *
 * @param sc our search context
 * @param sb the sblock
 * @param size size of sb
 */
static void
process_sblock (struct GNUNET_FS_SearchContext *sc,
		const struct SBlock *sb,
		size_t size)
{
  size_t len = size - sizeof (struct SBlock);
  char pt[len];
  struct GNUNET_CRYPTO_AesSessionKey skey;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  struct GNUNET_FS_Uri *uri;
  struct GNUNET_CONTAINER_MetaData *meta;
  const char *id;
  const char *uris;
  size_t off;
  char *emsg;
  GNUNET_HashCode key;
  char *identifier;

  /* decrypt */
  identifier = sc->uri->data.sks.identifier;
  GNUNET_CRYPTO_hash (identifier, 
		      strlen (identifier), 
		      &key);
  GNUNET_CRYPTO_hash_to_aes_key (&key, &skey, &iv);
  GNUNET_CRYPTO_aes_decrypt (&sb[1],
			     len,
			     &skey,
			     &iv,
			     pt);
  /* parse */
  off = GNUNET_STRINGS_buffer_tokenize (pt,
					len, 
					2, 
					&id, 
					&uris);
  if (off == 0)
    {
      GNUNET_break_op (0);     /* sblock malformed */
      return;
    }
  meta = GNUNET_CONTAINER_meta_data_deserialize (&pt[off], 
						 len - off);
  if (meta == NULL)
    {
      GNUNET_break_op (0);     /* sblock malformed */
      return;
    }
  uri = GNUNET_FS_uri_parse (uris, &emsg);
  if (uri == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Failed to parse URI `%s': %s\n",
		  uris, emsg);
      GNUNET_break_op (0);     /* sblock malformed */
      GNUNET_free_non_null (emsg);
      GNUNET_CONTAINER_meta_data_destroy (meta);
      return;
    }
  /* process */
  process_sks_result (sc, id, uri, meta);
  /* clean up */
  GNUNET_FS_uri_destroy (uri);
  GNUNET_CONTAINER_meta_data_destroy (meta);
}


/**
 * Process a search result.
 *
 * @param sc our search context
 * @param type type of the result
 * @param expiration when it will expire
 * @param data the (encrypted) response
 * @param size size of data
 */
static void
process_result (struct GNUNET_FS_SearchContext *sc,
		uint32_t type,
		struct GNUNET_TIME_Absolute expiration,
		const void *data,
		size_t size)
{
  if (GNUNET_TIME_absolute_get_duration (expiration).value > 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Result received has already expired.\n");
      return; /* result expired */
    }
  switch (type)
    {
    case GNUNET_DATASTORE_BLOCKTYPE_KBLOCK:
      if (! GNUNET_FS_uri_test_ksk (sc->uri))
	{
	  GNUNET_break (0);
	  return;
	}
      if (sizeof (struct KBlock) > size)
	{
	  GNUNET_break_op (0);
	  return;
	}
      process_kblock (sc, data, size);
      break;
    case GNUNET_DATASTORE_BLOCKTYPE_SBLOCK:
      if (! GNUNET_FS_uri_test_sks (sc->uri))
	{
	  GNUNET_break (0);
	  return;
	}
      if (sizeof (struct SBlock) > size)
	{
	  GNUNET_break_op (0);
	  return;
	}
      process_sblock (sc, data, size);
      break;
    case GNUNET_DATASTORE_BLOCKTYPE_NBLOCK:
      GNUNET_break (0); // FIXME: not implemented!
      break;
    case GNUNET_DATASTORE_BLOCKTYPE_ANY:
    case GNUNET_DATASTORE_BLOCKTYPE_DBLOCK:
    case GNUNET_DATASTORE_BLOCKTYPE_ONDEMAND:
    case GNUNET_DATASTORE_BLOCKTYPE_IBLOCK:
      GNUNET_break (0);
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Got result with unknown block type `%d', ignoring"),
		  type);
      break;
    }
}


/**
 * Shutdown any existing connection to the FS
 * service and try to establish a fresh one
 * (and then re-transmit our search request).
 *
 * @param sc the search to reconnec
 */
static void 
try_reconnect (struct GNUNET_FS_SearchContext *sc);


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void 
receive_results (void *cls,
		 const struct GNUNET_MessageHeader * msg)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  const struct PutMessage *cm;
  uint16_t msize;

  if ( (NULL == msg) ||
       (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_FS_PUT) ||
       (ntohs (msg->size) <= sizeof (struct PutMessage)) )
    {
      try_reconnect (sc);
      return;
    }
  msize = ntohs (msg->size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Receiving %u bytes of result from fs service\n",
	      msize);
  cm = (const struct PutMessage*) msg;
  process_result (sc, 
		  ntohl (cm->type),
		  GNUNET_TIME_absolute_ntoh (cm->expiration),
		  &cm[1],
		  msize - sizeof (struct PutMessage));
  /* continue receiving */
  GNUNET_CLIENT_receive (sc->client,
			 &receive_results,
			 sc,
			 GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * We're ready to transmit the search request to the
 * file-sharing service.  Do it.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_search_request (void *cls,
			 size_t size, 
			 void *buf)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  size_t msize;
  struct SearchMessage *sm;
  unsigned int i;
  const char *identifier;
  GNUNET_HashCode key;
  GNUNET_HashCode idh;

  if (NULL == buf)
    {
      try_reconnect (sc);
      return 0;
    }
  if (GNUNET_FS_uri_test_ksk (sc->uri))
    {
      msize = sizeof (struct SearchMessage) * sc->uri->data.ksk.keywordCount;
      GNUNET_assert (size >= msize);
      sm = buf;
      memset (sm, 0, msize);
      for (i=0;i<sc->uri->data.ksk.keywordCount;i++)
	{
	  sm[i].header.size = htons (sizeof (struct SearchMessage));
	  sm[i].header.type = htons (GNUNET_MESSAGE_TYPE_FS_START_SEARCH);
	  sm[i].type = htonl (GNUNET_DATASTORE_BLOCKTYPE_KBLOCK);
	  sm[i].anonymity_level = htonl (sc->anonymity);
	  sm[i].query = sc->requests[i].query;
	}
    }
  else
    {
      GNUNET_assert (GNUNET_FS_uri_test_sks (sc->uri));
      msize = sizeof (struct SearchMessage);
      GNUNET_assert (size >= msize);
      sm = buf;
      memset (sm, 0, msize);
      sm->header.size = htons (sizeof (struct SearchMessage));
      sm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_START_SEARCH);
      sm->type = htonl (GNUNET_DATASTORE_BLOCKTYPE_SBLOCK);
      sm->anonymity_level = htonl (sc->anonymity);
      sm->target = sc->uri->data.sks.namespace;
      identifier = sc->uri->data.sks.identifier;
      GNUNET_CRYPTO_hash (identifier,
			  strlen (identifier),
			  &key);
      GNUNET_CRYPTO_hash (&key,
			  sizeof (GNUNET_HashCode),
			  &idh);
      GNUNET_CRYPTO_hash_xor (&idh,
			      &sm->target,
			      &sm->query);
   }
  GNUNET_CLIENT_receive (sc->client,
			 &receive_results,
			 sc,
			 GNUNET_TIME_UNIT_FOREVER_REL);
  return msize;
}


/**
 * Reconnect to the FS service and transmit
 * our queries NOW.
 *
 * @param cls our search context
 * @param tc unused
 */
static void
do_reconnect (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  struct GNUNET_CLIENT_Connection *client;
  size_t size;
  
  sc->task = GNUNET_SCHEDULER_NO_TASK;
  client = GNUNET_CLIENT_connect (sc->h->sched,
				  "fs",
				  sc->h->cfg);
  if (NULL == client)
    {
      try_reconnect (sc);
      return;
    }
  sc->client = client;
  if (GNUNET_FS_uri_test_ksk (sc->uri))
    size = sizeof (struct SearchMessage) * sc->uri->data.ksk.keywordCount;
  else
    size = sizeof (struct SearchMessage);
  GNUNET_CLIENT_notify_transmit_ready (client,
				       size,
                                       GNUNET_CONSTANTS_SERVICE_TIMEOUT,
				       GNUNET_NO,
				       &transmit_search_request,
				       sc);  
}


/**
 * Shutdown any existing connection to the FS
 * service and try to establish a fresh one
 * (and then re-transmit our search request).
 *
 * @param sc the search to reconnec
 */
static void 
try_reconnect (struct GNUNET_FS_SearchContext *sc)
{
  if (NULL != sc->client)
    {
      GNUNET_CLIENT_disconnect (sc->client, GNUNET_NO);
      sc->client = NULL;
    }
  sc->task
    = GNUNET_SCHEDULER_add_delayed (sc->h->sched,
				    GNUNET_TIME_UNIT_SECONDS,
				    &do_reconnect,
				    sc);
}


/**
 * Start search for content, internal API.
 *
 * @param h handle to the file sharing subsystem
 * @param uri specifies the search parameters; can be
 *        a KSK URI or an SKS URI.
 * @param anonymity desired level of anonymity
 * @param cctx initial value for the client context
 * @param parent parent search (for namespace update searches)
 * @return context that can be used to control the search
 */
static struct GNUNET_FS_SearchContext *
search_start (struct GNUNET_FS_Handle *h,
	      const struct GNUNET_FS_Uri *uri,
	      uint32_t anonymity,
	      void *cctx,
	      struct GNUNET_FS_SearchContext *parent)
{
  struct GNUNET_FS_SearchContext *sc;
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_FS_ProgressInfo pi;
  size_t size;
  unsigned int i;
  const char *keyword;
  GNUNET_HashCode hc;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;  
  struct GNUNET_CRYPTO_RsaPrivateKey *pk;

  if (GNUNET_FS_uri_test_ksk (uri))
    {
      size = sizeof (struct SearchMessage) * uri->data.ksk.keywordCount;
    }
  else
    {
      GNUNET_assert (GNUNET_FS_uri_test_sks (uri));
      size = sizeof (struct SearchMessage);
    }
  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Too many keywords specified for a single search."));
      return NULL;
    }
  client = GNUNET_CLIENT_connect (h->sched,
				  "fs",
				  h->cfg);
  if (NULL == client)
    return NULL;
  sc = GNUNET_malloc (sizeof(struct GNUNET_FS_SearchContext));
  sc->h = h;
  sc->uri = GNUNET_FS_uri_dup (uri);
  sc->anonymity = anonymity;
  sc->start_time = GNUNET_TIME_absolute_get ();
  sc->client = client;  
  sc->parent = parent;
  sc->master_result_map = GNUNET_CONTAINER_multihashmap_create (16);
  sc->client_info = cctx;
  if (GNUNET_FS_uri_test_ksk (uri))
    {
      GNUNET_assert (0 != sc->uri->data.ksk.keywordCount);
      sc->requests = GNUNET_malloc (sizeof (struct SearchRequestEntry) *
				    sc->uri->data.ksk.keywordCount);
      for (i=0;i<sc->uri->data.ksk.keywordCount;i++)
	{
	  keyword = &sc->uri->data.ksk.keywords[i][1];
	  GNUNET_CRYPTO_hash (keyword, strlen (keyword), &hc);
	  pk = GNUNET_CRYPTO_rsa_key_create_from_hash (&hc);
	  GNUNET_CRYPTO_rsa_key_get_public (pk, &pub);
	  GNUNET_CRYPTO_rsa_key_free (pk);
	  GNUNET_CRYPTO_hash (&pub,
			      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), 
			      &sc->requests[i].query);
	  sc->requests[i].mandatory = (sc->uri->data.ksk.keywords[i][0] == '+');
	  if (sc->requests[i].mandatory)
	    sc->mandatory_count++;
	  sc->requests[i].results = GNUNET_CONTAINER_multihashmap_create (4);
	  GNUNET_CRYPTO_hash (keyword,
			      strlen (keyword),
			      &sc->requests[i].key);
	}
    }
  if (NULL != parent)
    GNUNET_CONTAINER_DLL_insert (parent->child_head,
				 parent->child_tail,
				 sc);
  pi.status = GNUNET_FS_STATUS_SEARCH_START;
  make_search_status (&pi, sc);
  sc->client_info = h->upcb (h->upcb_cls,
			     &pi);
  GNUNET_CLIENT_notify_transmit_ready (client,
				       size,
                                       GNUNET_CONSTANTS_SERVICE_TIMEOUT,
				       GNUNET_NO,
				       &transmit_search_request,
				       sc);  
  return sc;
}


/**
 * Start search for content.
 *
 * @param h handle to the file sharing subsystem
 * @param uri specifies the search parameters; can be
 *        a KSK URI or an SKS URI.
 * @param anonymity desired level of anonymity
 * @param cctx initial value for the client context
 * @return context that can be used to control the search
 */
struct GNUNET_FS_SearchContext *
GNUNET_FS_search_start (struct GNUNET_FS_Handle *h,
			const struct GNUNET_FS_Uri *uri,
			uint32_t anonymity,
			void *cctx)
{
  return search_start (h, uri, anonymity, cctx, NULL);
}


/**
 * Pause search.  
 *
 * @param sc context for the search that should be paused
 */
void 
GNUNET_FS_search_pause (struct GNUNET_FS_SearchContext *sc)
{
  struct GNUNET_FS_ProgressInfo pi;

  if (sc->task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (sc->h->sched,
			     sc->task);
  sc->task = GNUNET_SCHEDULER_NO_TASK;
  if (NULL != sc->client)
    GNUNET_CLIENT_disconnect (sc->client, GNUNET_NO);
  sc->client = NULL;
  // FIXME: make persistent!
  // FIXME: should this freeze all active probes?
  pi.status = GNUNET_FS_STATUS_SEARCH_PAUSED;
  make_search_status (&pi, sc);
  sc->client_info = sc->h->upcb (sc->h->upcb_cls,
				 &pi);
}


/**
 * Continue paused search.
 *
 * @param sc context for the search that should be resumed
 */
void 
GNUNET_FS_search_continue (struct GNUNET_FS_SearchContext *sc)
{
  struct GNUNET_FS_ProgressInfo pi;

  GNUNET_assert (sc->client == NULL);
  GNUNET_assert (sc->task == GNUNET_SCHEDULER_NO_TASK);
  do_reconnect (sc, NULL);
  // FIXME: make persistent!
  pi.status = GNUNET_FS_STATUS_SEARCH_CONTINUED;
  make_search_status (&pi, sc);
  sc->client_info = sc->h->upcb (sc->h->upcb_cls,
				 &pi);
}


/**
 * Free the given search result.
 *
 * @param cls the global FS handle
 * @param key the key for the search result (unused)
 * @param value the search result to free
 * @return GNUNET_OK
 */
static int
search_result_free (void *cls,
		    const GNUNET_HashCode * key,
		    void *value)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  struct GNUNET_FS_Handle *h = sc->h;
  struct SearchResult *sr = value;
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_SEARCH_RESULT_STOPPED;
  make_search_status (&pi, sc);
  pi.value.search.specifics.result_stopped.cctx = sr->client_info;
  pi.value.search.specifics.result_stopped.meta = sr->meta;
  pi.value.search.specifics.result_stopped.uri = sr->uri;
  sr->client_info = h->upcb (h->upcb_cls,
			     &pi);
  GNUNET_break (NULL == sr->client_info);
  
  GNUNET_FS_uri_destroy (sr->uri);
  GNUNET_CONTAINER_meta_data_destroy (sr->meta);
  if (sr->probe_ctx != NULL)
    {
      GNUNET_FS_download_stop (sr->probe_ctx, GNUNET_YES);
      h->active_probes--;
      /* FIXME: trigger starting of new
	 probes here!? Maybe not -- could
	 cause new probes to be immediately
	 stopped again... */
    }
  if (sr->probe_cancel_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (h->sched,
			       sr->probe_cancel_task);
    }
  GNUNET_free (sr);
  return GNUNET_OK;
}


/**
 * Stop search for content.
 *
 * @param sc context for the search that should be stopped
 */
void 
GNUNET_FS_search_stop (struct GNUNET_FS_SearchContext *sc)
{
  struct GNUNET_FS_ProgressInfo pi;
  unsigned int i;
  struct GNUNET_FS_SearchContext *parent;

  // FIXME: make un-persistent!
  if (NULL != (parent = sc->parent))
    {
      GNUNET_CONTAINER_DLL_remove (parent->child_head,
				   parent->child_tail,
				   sc);
      sc->parent = NULL;
    }
  while (NULL != sc->child_head)
    GNUNET_FS_search_stop (sc->child_head);
  GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
					 &search_result_free,
					 sc);
  pi.status = GNUNET_FS_STATUS_SEARCH_STOPPED;
  make_search_status (&pi, sc);
  sc->client_info = sc->h->upcb (sc->h->upcb_cls,
				 &pi);
  GNUNET_break (NULL == sc->client_info);
  if (sc->task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (sc->h->sched,
			     sc->task);
  if (NULL != sc->client)
    GNUNET_CLIENT_disconnect (sc->client, GNUNET_NO);
  GNUNET_CONTAINER_multihashmap_destroy (sc->master_result_map);
  if (sc->requests != NULL)
    {
      GNUNET_assert (GNUNET_FS_uri_test_ksk (sc->uri));
      for (i=0;i<sc->uri->data.ksk.keywordCount;i++)
	GNUNET_CONTAINER_multihashmap_destroy (sc->requests[i].results);
    }
  GNUNET_free_non_null (sc->requests);
  GNUNET_FS_uri_destroy (sc->uri);
  GNUNET_free (sc);
}

/* end of fs_search.c */
