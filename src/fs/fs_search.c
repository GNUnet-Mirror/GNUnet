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
 * - aggregate and process results (FSUI-style)
 * - call progress callbacks
 * - make operations persistent (can wait)
 * - add support for pushing "already seen" information
 *   to FS service for bloomfilter (can wait)
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_fs_service.h"
#include "gnunet_protocols.h"
#include "fs.h"

#define DEBUG_SEARCH GNUNET_YES


/**
 * We have received a KSK result.  Check
 * how it fits in with the overall query
 * and notify the client accordingly.
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
  // FIXME: check if new
  // FIXME: check if mandatory satisfied
  // FIXME: notify client!
}


/**
 * We have received an SKS result.  Start
 * searching for updates and notify the
 * client if it is a new result.
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
  // FIXME: check if new
  // FIXME: notify client

  if (strlen (id_update) > 0)
    {
      // FIXME: search for updates!
#if 0
      updateURI.type = sks;
      GNUNET_hash (&sb->subspace,
                   sizeof (GNUNET_RSA_PublicKey),
                   &updateURI.data.sks.namespace);
      updateURI.data.sks.identifier = GNUNET_strdup (id);
      add_search_for_uri (&updateURI, sqc);
#endif
    }
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
  GNUNET_CRYPTO_aes_encrypt (&kb[1],
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
  GNUNET_CRYPTO_aes_encrypt (&sb[1],
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
    return; /* result expired */
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
      if (! GNUNET_FS_uri_test_ksk (sc->uri))
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
  const struct ContentMessage *cm;
  uint16_t msize;

  if ( (NULL == msg) ||
       (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_FS_CONTENT) ||
       (ntohs (msg->size) <= sizeof (struct ContentMessage)) )
    {
      try_reconnect (sc);
      return;
    }
  msize = ntohs (msg->size);
  cm = (const struct ContentMessage*) msg;
  process_result (sc, 
		  ntohl (cm->type),
		  GNUNET_TIME_absolute_ntoh (cm->expiration),
		  &cm[1],
		  msize - sizeof (struct ContentMessage));
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
  const char *keyword;
  const char *identifier;
  GNUNET_HashCode idh;
  GNUNET_HashCode hc;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;  
  struct GNUNET_CRYPTO_RsaPrivateKey *pk;

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
      sc->requests = GNUNET_malloc (sizeof (struct SearchRequestEntry) *
				    sc->uri->data.ksk.keywordCount);
      for (i=0;i<sc->uri->data.ksk.keywordCount;i++)
	{
	  sm[i].header.size = htons (sizeof (struct SearchMessage));
	  sm[i].header.type = htons (GNUNET_MESSAGE_TYPE_FS_START_SEARCH);
	  sm[i].anonymity_level = htonl (sc->anonymity);
	  keyword = &sc->uri->data.ksk.keywords[i][1];

	  GNUNET_CRYPTO_hash (keyword, strlen (keyword), &hc);
	  pk = GNUNET_CRYPTO_rsa_key_create_from_hash (&hc);
	  GNUNET_CRYPTO_rsa_key_get_public (pk, &pub);
	  GNUNET_CRYPTO_rsa_key_free (pk);
	  GNUNET_CRYPTO_hash (&pub,
			      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), 
			      &sm[i].query);
	  sc->requests[i].query = sm[i].query;
	  GNUNET_CRYPTO_hash (keyword,
			      strlen (keyword),
			      &sc->requests[i].key);
	}
    }
  else
    {
      msize = sizeof (struct SearchMessage);
      GNUNET_assert (size >= msize);
      sm = buf;
      memset (sm, 0, msize);
      sm->header.size = htons (sizeof (struct SearchMessage));
      sm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_START_SEARCH);
      sm->anonymity_level = htonl (sc->anonymity);
      sm->target = sc->uri->data.sks.namespace;
      identifier = sc->uri->data.sks.identifier;
      GNUNET_CRYPTO_hash (identifier,
			  strlen (identifier),
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
      GNUNET_CLIENT_disconnect (sc->client);
      sc->client = NULL;
    }
  sc->task
    = GNUNET_SCHEDULER_add_delayed (sc->h->sched,
				    GNUNET_NO,
				    GNUNET_SCHEDULER_PRIORITY_IDLE,
				    GNUNET_SCHEDULER_NO_TASK,
				    GNUNET_TIME_UNIT_SECONDS,
				    &do_reconnect,
				    sc);
}


/**
 * Start search for content.
 *
 * @param h handle to the file sharing subsystem
 * @param uri specifies the search parameters; can be
 *        a KSK URI or an SKS URI.
 * @param anonymity desired level of anonymity
 * @return context that can be used to control the search
 */
struct GNUNET_FS_SearchContext *
GNUNET_FS_search_start (struct GNUNET_FS_Handle *h,
			const struct GNUNET_FS_Uri *uri,
			unsigned int anonymity)
{
  struct GNUNET_FS_SearchContext *sc;
  struct GNUNET_CLIENT_Connection *client;
  size_t size;

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
  client = GNUNET_CLIENT_connect (sc->h->sched,
				  "fs",
				  sc->h->cfg);
  if (NULL == client)
    return NULL;
  sc = GNUNET_malloc (sizeof(struct GNUNET_FS_SearchContext));
  sc->h = h;
  sc->uri = GNUNET_FS_uri_dup (uri);
  sc->anonymity = anonymity;
  sc->start_time = GNUNET_TIME_absolute_get ();
  sc->client = client;  
  // FIXME: call callback!
  GNUNET_CLIENT_notify_transmit_ready (client,
				       size,
                                       GNUNET_CONSTANTS_SERVICE_TIMEOUT,
				       &transmit_search_request,
				       sc);  
  return sc;
}


/**
 * Pause search.  
 *
 * @param sc context for the search that should be paused
 */
void 
GNUNET_FS_search_pause (struct GNUNET_FS_SearchContext *sc)
{
  if (sc->task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (sc->h->sched,
			     sc->task);
  sc->task = GNUNET_SCHEDULER_NO_TASK;
  if (NULL != sc->client)
    GNUNET_CLIENT_disconnect (sc->client);
  sc->client = NULL;
  // FIXME: make persistent!
  // FIXME: call callback!
}


/**
 * Continue paused search.
 *
 * @param sc context for the search that should be resumed
 */
void 
GNUNET_FS_search_continue (struct GNUNET_FS_SearchContext *sc)
{
  GNUNET_assert (sc->client == NULL);
  GNUNET_assert (sc->task == GNUNET_SCHEDULER_NO_TASK);
  do_reconnect (sc, NULL);
  // FIXME: make persistent!
  // FIXME: call callback!
}


/**
 * Stop search for content.
 *
 * @param sc context for the search that should be stopped
 */
void 
GNUNET_FS_search_stop (struct GNUNET_FS_SearchContext *sc)
{
  // FIXME: make un-persistent!
  // FIXME: call callback!
  if (sc->task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (sc->h->sched,
			     sc->task);
  if (NULL != sc->client)
    GNUNET_CLIENT_disconnect (sc->client);
  GNUNET_free_non_null (sc->requests);
  GNUNET_FS_uri_destroy (sc->uri);
  GNUNET_free (sc);
}

/* end of fs_search.c */
