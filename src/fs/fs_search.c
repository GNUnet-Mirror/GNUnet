/*
     This file is part of GNUnet.
     (C) 2001-2006, 2008-2012 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 59 Tem ple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/
/**
 * @file fs/fs_search.c
 * @brief Helper functions for searching.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_fs_service.h"
#include "gnunet_protocols.h"
#include "fs_api.h"


/**
 * Number of availability trials we perform per search result.
 */
#define AVAILABILITY_TRIALS_MAX 8

/**
 * Fill in all of the generic fields for a search event and
 * call the callback.
 *
 * @param pi structure to fill in
 * @param sc overall search context
 * @return value returned by the callback
 */
void *
GNUNET_FS_search_make_status_ (struct GNUNET_FS_ProgressInfo *pi,
                               struct GNUNET_FS_SearchContext *sc)
{
  void *ret;

  pi->value.search.sc = sc;
  pi->value.search.cctx = sc->client_info;
  pi->value.search.pctx =
      (NULL == sc->psearch_result) ? NULL : sc->psearch_result->client_info;
  pi->value.search.query = sc->uri;
  pi->value.search.duration =
      GNUNET_TIME_absolute_get_duration (sc->start_time);
  pi->value.search.anonymity = sc->anonymity;
  ret = sc->h->upcb (sc->h->upcb_cls, pi);
  return ret;
}


/**
 * Check if the given result is identical
 * to the given URI.
 *
 * @param cls points to the URI we check against
 * @param key not used
 * @param value a "struct GNUNET_FS_SearchResult" who's URI we
 *        should compare with
 * @return GNUNET_SYSERR if the result is present,
 *         GNUNET_OK otherwise
 */
static int
test_result_present (void *cls, const GNUNET_HashCode * key, void *value)
{
  const struct GNUNET_FS_Uri *uri = cls;
  struct GNUNET_FS_SearchResult *sr = value;

  if (GNUNET_FS_uri_test_equal (uri, sr->uri))
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
                          struct GNUNET_FS_SearchResult *sr)
{
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_SEARCH_RESULT;
  pi.value.search.specifics.result.meta = sr->meta;
  pi.value.search.specifics.result.uri = sr->uri;
  pi.value.search.specifics.result.result = sr;
  pi.value.search.specifics.result.applicability_rank = sr->optional_support;
  sr->client_info = GNUNET_FS_search_make_status_ (&pi, sc);
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
                          struct GNUNET_FS_SearchResult *sr)
{
  struct GNUNET_FS_ProgressInfo pi;
 
  pi.status = GNUNET_FS_STATUS_SEARCH_UPDATE;
  pi.value.search.specifics.update.cctx = sr->client_info;
  pi.value.search.specifics.update.meta = sr->meta;
  pi.value.search.specifics.update.uri = sr->uri;
  pi.value.search.specifics.update.availability_rank =
      2 * sr->availability_success - sr->availability_trials;
  pi.value.search.specifics.update.availability_certainty =
      sr->availability_trials;
  pi.value.search.specifics.update.applicability_rank = sr->optional_support;
  sr->client_info = GNUNET_FS_search_make_status_ (&pi, sc);
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
  struct GNUNET_FS_SearchResult *sr;
};


/**
 * Check if the given result is identical to the given URI and if so
 * return it.
 *
 * @param cls a "struct GetResultContext"
 * @param key not used
 * @param value a "struct GNUNET_FS_SearchResult" who's URI we
 *        should compare with
 * @return GNUNET_OK
 */
static int
get_result_present (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GetResultContext *grc = cls;
  struct GNUNET_FS_SearchResult *sr = value;

  if (GNUNET_FS_uri_test_equal (grc->uri, sr->uri))
    grc->sr = sr;
  return GNUNET_OK;
}


/**
 * Signal result of last probe to client and then schedule next
 * probe.
 */
static void
signal_probe_result (struct GNUNET_FS_SearchResult *sr)
{
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_SEARCH_UPDATE;
  pi.value.search.specifics.update.cctx = sr->client_info;
  pi.value.search.specifics.update.meta = sr->meta;
  pi.value.search.specifics.update.uri = sr->uri;
  pi.value.search.specifics.update.availability_rank = sr->availability_success;
  pi.value.search.specifics.update.availability_certainty =
      sr->availability_trials;
  pi.value.search.specifics.update.applicability_rank = sr->optional_support;
  sr->client_info = GNUNET_FS_search_make_status_ (&pi, sr->sc);
  GNUNET_FS_search_start_probe_ (sr);
}


/**
 * Handle the case where we have failed to receive a response for our probe.
 *
 * @param cls our 'struct GNUNET_FS_SearchResult*'
 * @param tc scheduler context
 */
static void
probe_failure_handler (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_SearchResult *sr = cls;

  sr->probe_cancel_task = GNUNET_SCHEDULER_NO_TASK;
  sr->availability_trials++;
  GNUNET_FS_download_stop (sr->probe_ctx, GNUNET_YES);
  sr->probe_ctx = NULL;
  GNUNET_FS_search_result_sync_ (sr);
  signal_probe_result (sr);
}


/**
 * Handle the case where we have gotten a response for our probe.
 *
 * @param cls our 'struct GNUNET_FS_SearchResult*'
 * @param tc scheduler context
 */
static void
probe_success_handler (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_SearchResult *sr = cls;

  sr->probe_cancel_task = GNUNET_SCHEDULER_NO_TASK;
  sr->availability_trials++;
  sr->availability_success++;
  GNUNET_FS_download_stop (sr->probe_ctx, GNUNET_YES);
  sr->probe_ctx = NULL;
  GNUNET_FS_search_result_sync_ (sr);
  signal_probe_result (sr);
}


/**
 * Notification of FS that a search probe has made progress.
 * This function is used INSTEAD of the client's event handler
 * for downloads where the GNUNET_FS_DOWNLOAD_IS_PROBE flag is set.
 *
 * @param cls closure, always NULL (!), actual closure
 *        is in the client-context of the info struct
 * @param info details about the event, specifying the event type
 *        and various bits about the event
 * @return client-context (for the next progress call
 *         for this operation; should be set to NULL for
 *         SUSPEND and STOPPED events).  The value returned
 *         will be passed to future callbacks in the respective
 *         field in the GNUNET_FS_ProgressInfo struct.
 */
void *
GNUNET_FS_search_probe_progress_ (void *cls,
                                  const struct GNUNET_FS_ProgressInfo *info)
{
  struct GNUNET_FS_SearchResult *sr = info->value.download.cctx;
  struct GNUNET_TIME_Relative dur;

  switch (info->status)
  {
  case GNUNET_FS_STATUS_DOWNLOAD_START:
    /* ignore */
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_RESUME:
    /* probes should never be resumed */
    GNUNET_assert (0);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_SUSPEND:
    /* probes should never be suspended */
    GNUNET_break (0);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_PROGRESS:
    /* ignore */
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_ERROR:
    if (GNUNET_SCHEDULER_NO_TASK != sr->probe_cancel_task)
    {
      GNUNET_SCHEDULER_cancel (sr->probe_cancel_task);
      sr->probe_cancel_task = GNUNET_SCHEDULER_NO_TASK;
    }
    sr->probe_cancel_task =
        GNUNET_SCHEDULER_add_delayed (sr->remaining_probe_time,
                                      &probe_failure_handler, sr);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_COMPLETED:
    if (GNUNET_SCHEDULER_NO_TASK != sr->probe_cancel_task)
    {
      GNUNET_SCHEDULER_cancel (sr->probe_cancel_task);
      sr->probe_cancel_task = GNUNET_SCHEDULER_NO_TASK;
    }
    sr->probe_cancel_task =
        GNUNET_SCHEDULER_add_now (&probe_success_handler, sr);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_STOPPED:
    if (GNUNET_SCHEDULER_NO_TASK != sr->probe_cancel_task)
    {
      GNUNET_SCHEDULER_cancel (sr->probe_cancel_task);
      sr->probe_cancel_task = GNUNET_SCHEDULER_NO_TASK;
    }
    sr = NULL;
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_ACTIVE:
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == sr->probe_cancel_task);
    sr->probe_active_time = GNUNET_TIME_absolute_get ();
    sr->probe_cancel_task =
        GNUNET_SCHEDULER_add_delayed (sr->remaining_probe_time,
                                      &probe_failure_handler, sr);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_INACTIVE:
    if (GNUNET_SCHEDULER_NO_TASK != sr->probe_cancel_task)
    {
      GNUNET_SCHEDULER_cancel (sr->probe_cancel_task);
      sr->probe_cancel_task = GNUNET_SCHEDULER_NO_TASK;
    }
    dur = GNUNET_TIME_absolute_get_duration (sr->probe_active_time);
    sr->remaining_probe_time =
        GNUNET_TIME_relative_subtract (sr->remaining_probe_time, dur);
    GNUNET_FS_search_result_sync_ (sr);
    break;
  default:
    GNUNET_break (0);
    return NULL;
  }
  return sr;
}


/**
 * Start download probes for the given search result.
 *
 * @param sr the search result
 */
void
GNUNET_FS_search_start_probe_ (struct GNUNET_FS_SearchResult *sr)
{
  uint64_t off;
  uint64_t len;

  if (NULL != sr->probe_ctx)
    return;
  if (NULL != sr->download)
    return;
  if (0 == (sr->sc->h->flags & GNUNET_FS_FLAGS_DO_PROBES))
    return;
  if (sr->availability_trials > AVAILABILITY_TRIALS_MAX)
    return;
  if ( (chk != sr->uri->type) && (loc != sr->uri->type))
    return;
  len = GNUNET_FS_uri_chk_get_file_size (sr->uri);
  if (0 == len)
    return;
  if ((len <= DBLOCK_SIZE) && (sr->availability_success > 0))
    return;
  off = len / DBLOCK_SIZE;
  if (off > 0)
    off = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, off);
  off *= DBLOCK_SIZE;
  if (len - off < DBLOCK_SIZE)
    len = len - off;
  else
    len = DBLOCK_SIZE;
  sr->remaining_probe_time =
      GNUNET_TIME_relative_multiply (sr->sc->h->avg_block_latency,
                                     2 * (1 + sr->availability_trials));
  sr->probe_ctx =
      GNUNET_FS_download_start (sr->sc->h, sr->uri, sr->meta, NULL, NULL, off,
                                len, sr->sc->anonymity,
                                GNUNET_FS_DOWNLOAD_NO_TEMPORARIES |
                                GNUNET_FS_DOWNLOAD_IS_PROBE, sr, NULL);
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
  struct GNUNET_FS_SearchResult *sr;
  struct GetResultContext grc;
  int is_new;
  unsigned int koff;

  /* check if new */
  GNUNET_assert (NULL != sc);
  GNUNET_FS_uri_to_key (uri, &key);
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_get_multiple (ent->results, &key,
                                                  &test_result_present,
                                                  (void *) uri))
    return;                     /* duplicate result */
  /* try to find search result in master map */
  grc.sr = NULL;
  grc.uri = uri;
  GNUNET_CONTAINER_multihashmap_get_multiple (sc->master_result_map, &key,
                                              &get_result_present, &grc);
  sr = grc.sr;
  is_new = (NULL == sr) || (sr->mandatory_missing > 0);
  if (NULL == sr)
  {
    sr = GNUNET_malloc (sizeof (struct GNUNET_FS_SearchResult));
    sr->sc = sc;
    sr->uri = GNUNET_FS_uri_dup (uri);
    sr->meta = GNUNET_CONTAINER_meta_data_duplicate (meta);
    sr->mandatory_missing = sc->mandatory_count;
    sr->key = key;
    sr->keyword_bitmap = GNUNET_malloc ((sc->uri->data.ksk.keywordCount + 7) / 8); /* round up, count bits */
    GNUNET_CONTAINER_multihashmap_put (sc->master_result_map, &key, sr,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  }
  else
  {
    GNUNET_CONTAINER_meta_data_merge (sr->meta, meta);
  }
  koff = ent - sc->requests;
  GNUNET_assert ( (ent >= sc->requests) && (koff < sc->uri->data.ksk.keywordCount));
  sr->keyword_bitmap[koff / 8] |= (1 << (koff % 8));
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
  GNUNET_FS_search_result_sync_ (sr);
  GNUNET_FS_search_start_probe_ (sr);
}


/**
 * Start search for content, internal API.
 *
 * @param h handle to the file sharing subsystem
 * @param uri specifies the search parameters; can be
 *        a KSK URI or an SKS URI.
 * @param anonymity desired level of anonymity
 * @param options options for the search
 * @param cctx client context
 * @param psearch parent search result (for namespace update searches)
 * @return context that can be used to control the search
 */
static struct GNUNET_FS_SearchContext *
search_start (struct GNUNET_FS_Handle *h, const struct GNUNET_FS_Uri *uri,
              uint32_t anonymity, enum GNUNET_FS_SearchOptions options,
              void *cctx, struct GNUNET_FS_SearchResult *psearch);


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
process_sks_result (struct GNUNET_FS_SearchContext *sc, const char *id_update,
                    const struct GNUNET_FS_Uri *uri,
                    const struct GNUNET_CONTAINER_MetaData *meta)
{
  struct GNUNET_FS_Uri uu;
  GNUNET_HashCode key;
  struct GNUNET_FS_SearchResult *sr;

  /* check if new */
  GNUNET_assert (NULL != sc);
  GNUNET_FS_uri_to_key (uri, &key);
  GNUNET_CRYPTO_hash_xor (&uri->data.chk.chk.key, &uri->data.chk.chk.query,
                          &key);
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_get_multiple (sc->master_result_map, &key,
                                                  &test_result_present,
                                                  (void *) uri))
    return;                     /* duplicate result */
  sr = GNUNET_malloc (sizeof (struct GNUNET_FS_SearchResult));
  sr->sc = sc;
  sr->uri = GNUNET_FS_uri_dup (uri);
  sr->meta = GNUNET_CONTAINER_meta_data_duplicate (meta);
  sr->key = key;
  GNUNET_CONTAINER_multihashmap_put (sc->master_result_map, &key, sr,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_FS_search_result_sync_ (sr);
  GNUNET_FS_search_start_probe_ (sr);
  /* notify client */
  notify_client_chk_result (sc, sr);
  /* search for updates */
  if (0 == strlen (id_update))
    return;                     /* no updates */
  uu.type = sks;
  uu.data.sks.namespace = sc->uri->data.sks.namespace;
  uu.data.sks.identifier = GNUNET_strdup (id_update);
  (void) search_start (sc->h, &uu, sc->anonymity, sc->options, NULL, sr);
  GNUNET_free (uu.data.sks.identifier);
}


/**
 * Decrypt a block using a 'keyword' as the passphrase.  Given the
 * KSK public key derived from the keyword, this function looks up
 * the original keyword in the search context and decrypts the
 * given ciphertext block.
 *
 * @param sc search context with the keywords
 * @param public_key public key to use to lookup the keyword
 * @param edata encrypted data
 * @param edata_size number of bytes in 'edata' (and 'data')
 * @param data where to store the plaintext
 * @return keyword index on success, GNUNET_SYSERR on error (no such 
 *        keyword, internal error)
 */
static int
decrypt_block_with_keyword (const struct GNUNET_FS_SearchContext *sc,
			    const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key,
			    const void *edata,
			    size_t edata_size,
			    char *data)
{ 
  GNUNET_HashCode q;
  struct GNUNET_CRYPTO_AesSessionKey skey;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  int i;

  GNUNET_CRYPTO_hash (public_key,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &q);
  /* find key */
  for (i = 0; i < sc->uri->data.ksk.keywordCount; i++)
    if (0 == memcmp (&q, &sc->requests[i].query, sizeof (GNUNET_HashCode)))
      break;
  if (i == sc->uri->data.ksk.keywordCount)
  {
    /* oops, does not match any of our keywords!? */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  /* decrypt */
  GNUNET_CRYPTO_hash_to_aes_key (&sc->requests[i].key, &skey, &iv);
  if (-1 ==
      GNUNET_CRYPTO_aes_decrypt (edata, edata_size, &skey,
                                 &iv, data))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return i;
}


/**
 * Process a keyword-search result.
 *
 * @param sc our search context
 * @param kb the kblock
 * @param size size of kb
 */
static void
process_kblock (struct GNUNET_FS_SearchContext *sc, const struct KBlock *kb,
                size_t size)
{
  size_t j;
  char pt[size - sizeof (struct KBlock)];
  const char *eos;
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_FS_Uri *uri;
  char *emsg;
  int i;

  if (-1 == (i = decrypt_block_with_keyword (sc,
					     &kb->keyspace,
					     &kb[1],
					     size - sizeof (struct KBlock),
					     pt)))
    return;
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
    meta = GNUNET_CONTAINER_meta_data_deserialize (&pt[j], sizeof (pt) - j);
  if (NULL == meta)
  {
    GNUNET_break_op (0);        /* kblock malformed */
    return;
  }
  uri = GNUNET_FS_uri_parse (pt, &emsg);
  if (NULL == uri)
  {
    GNUNET_break_op (0);        /* kblock malformed */
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
 * Process a keyword-search result with a namespace advertisment.
 *
 * @param sc our search context
 * @param nb the nblock
 * @param size size of nb
 */
static void
process_nblock (struct GNUNET_FS_SearchContext *sc, const struct NBlock *nb,
                size_t size)
{
  size_t j;
  char pt[size - sizeof (struct NBlock)];
  const char *eos;
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_FS_Uri *uri;
  char *uris;
  int i;

  if (-1 == (i = decrypt_block_with_keyword (sc,
					     &nb->keyspace,
					     &nb[1],
					     size - sizeof (struct NBlock),
					     pt)))
    return;
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
    meta = GNUNET_CONTAINER_meta_data_deserialize (&pt[j], sizeof (pt) - j);
  if (NULL == meta)
  {
    GNUNET_break_op (0);        /* nblock malformed */
    return;
  }

  uri = GNUNET_malloc (sizeof (struct GNUNET_FS_Uri));
  uri->type = sks;
  uri->data.sks.identifier = GNUNET_strdup (pt);
  GNUNET_CRYPTO_hash (&nb->subspace,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &uri->data.sks.namespace);
  uris = GNUNET_FS_uri_to_string (uri);
  GNUNET_CONTAINER_meta_data_insert (meta, "<gnunet>", EXTRACTOR_METATYPE_URI,
                                     EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                     uris, strlen (uris) + 1);
  GNUNET_free (uris);
  GNUNET_PSEUDONYM_add (sc->h->cfg, &uri->data.sks.namespace, meta);
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
process_sblock (struct GNUNET_FS_SearchContext *sc, const struct SBlock *sb,
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
  GNUNET_CRYPTO_hash (identifier, strlen (identifier), &key);
  GNUNET_CRYPTO_hash_to_aes_key (&key, &skey, &iv);
  if (-1 == GNUNET_CRYPTO_aes_decrypt (&sb[1], len, &skey, &iv, pt))
  {
    GNUNET_break (0);
    return;
  }
  /* parse */
  off = GNUNET_STRINGS_buffer_tokenize (pt, len, 2, &id, &uris);
  if (0 == off)
  {
    GNUNET_break_op (0);        /* sblock malformed */
    return;
  }
  meta = GNUNET_CONTAINER_meta_data_deserialize (&pt[off], len - off);
  if (meta == NULL)
  {
    GNUNET_break_op (0);        /* sblock malformed */
    return;
  }
  uri = GNUNET_FS_uri_parse (uris, &emsg);
  if (NULL == uri)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to parse URI `%s': %s\n", uris,
                emsg);
    GNUNET_break_op (0);        /* sblock malformed */
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
process_result (struct GNUNET_FS_SearchContext *sc, enum GNUNET_BLOCK_Type type,
                struct GNUNET_TIME_Absolute expiration, const void *data,
                size_t size)
{
  if (GNUNET_TIME_absolute_get_duration (expiration).rel_value > 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Result received has already expired.\n");
    return;                     /* result expired */
  }
  switch (type)
  {
  case GNUNET_BLOCK_TYPE_FS_KBLOCK:
    if (!GNUNET_FS_uri_test_ksk (sc->uri))
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
  case GNUNET_BLOCK_TYPE_FS_SBLOCK:
    if (!GNUNET_FS_uri_test_sks (sc->uri))
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
  case GNUNET_BLOCK_TYPE_FS_NBLOCK:
    if (!GNUNET_FS_uri_test_ksk (sc->uri))
    {
      GNUNET_break (0);
      return;
    }
    if (sizeof (struct NBlock) > size)
    {
      GNUNET_break_op (0);
      return;
    }
    process_nblock (sc, data, size);
    break;
  case GNUNET_BLOCK_TYPE_ANY:
    GNUNET_break (0);
    break;
  case GNUNET_BLOCK_TYPE_FS_DBLOCK:
    GNUNET_break (0);
    break;
  case GNUNET_BLOCK_TYPE_FS_ONDEMAND:
    GNUNET_break (0);
    break;
  case GNUNET_BLOCK_TYPE_FS_IBLOCK:
    GNUNET_break (0);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Got result with unknown block type `%d', ignoring"), type);
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
receive_results (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  const struct ClientPutMessage *cm;
  uint16_t msize;

  if ((NULL == msg) || (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_FS_PUT) ||
      (ntohs (msg->size) <= sizeof (struct ClientPutMessage)))
  {
    try_reconnect (sc);
    return;
  }
  msize = ntohs (msg->size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Receiving %u bytes of result from fs service\n", msize);
  cm = (const struct ClientPutMessage *) msg;
  process_result (sc, ntohl (cm->type),
                  GNUNET_TIME_absolute_ntoh (cm->expiration), &cm[1],
                  msize - sizeof (struct ClientPutMessage));
  /* continue receiving */
  GNUNET_CLIENT_receive (sc->client, &receive_results, sc,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Schedule the transmission of the (next) search request
 * to the service.
 *
 * @param sc context for the search
 */
static void
schedule_transmit_search_request (struct GNUNET_FS_SearchContext *sc);


/**
 * Closure for 'build_result_set'.
 */
struct MessageBuilderContext
{
  /**
   * How many entries can we store to xoff.
   */
  unsigned int put_cnt;

  /**
   * How many entries should we skip.
   */
  unsigned int skip_cnt;

  /**
   * Where to store the keys.
   */
  GNUNET_HashCode *xoff;

  /**
   * Search context we are iterating for.
   */
  struct GNUNET_FS_SearchContext *sc;

  /**
   * Keyword offset the search result must match (0 for SKS)
   */
  unsigned int keyword_offset;
};


/**
 * Iterating over the known results, pick those matching the given
 * result range and store their keys at 'xoff'.
 *
 * @param cls the 'struct MessageBuilderContext'
 * @param key key for a result
 * @param value the search result
 * @return GNUNET_OK to continue iterating
 */
static int
build_result_set (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct MessageBuilderContext *mbc = cls;
  struct GNUNET_FS_SearchResult *sr = value;

  if ( (NULL != sr->keyword_bitmap) &&
       (0 == (sr->keyword_bitmap[mbc->keyword_offset / 8] & (1 << (mbc->keyword_offset % 8)))) )
    return GNUNET_OK; /* have no match for this keyword yet */
  if (mbc->skip_cnt > 0)
  {
    mbc->skip_cnt--;
    return GNUNET_OK;
  }
  if (0 == mbc->put_cnt)
    return GNUNET_SYSERR;
  mbc->sc->search_request_map_offset++;
  mbc->xoff[--mbc->put_cnt] = *key;
  return GNUNET_OK;
}


/**
 * Iterating over the known results, count those
 * matching the given result range and increment
 * put count for each.
 *
 * @param cls the 'struct MessageBuilderContext'
 * @param key key for a result
 * @param value the search result
 * @return GNUNET_OK to continue iterating
 */
static int
find_result_set (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct MessageBuilderContext *mbc = cls;
  struct GNUNET_FS_SearchResult *sr = value;

  if ( (NULL != sr->keyword_bitmap) &&
       (0 == (sr->keyword_bitmap[mbc->keyword_offset / 8] & (1 << (mbc->keyword_offset % 8)))) )
    return GNUNET_OK; /* have no match for this keyword yet */
  mbc->put_cnt++;
  return GNUNET_OK;
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
transmit_search_request (void *cls, size_t size, void *buf)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  struct MessageBuilderContext mbc;
  size_t msize;
  struct SearchMessage *sm;
  const char *identifier;
  GNUNET_HashCode key;
  GNUNET_HashCode idh;
  unsigned int sqms;
  uint32_t options;

  if (NULL == buf)
  {
    try_reconnect (sc);
    return 0;
  }
  mbc.sc = sc;
  mbc.skip_cnt = sc->search_request_map_offset;
  sm = buf;
  sm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_START_SEARCH);
  mbc.xoff = (GNUNET_HashCode *) & sm[1];
  options = SEARCH_MESSAGE_OPTION_NONE;
  if (0 != (sc->options & GNUNET_FS_SEARCH_OPTION_LOOPBACK_ONLY))
    options |= SEARCH_MESSAGE_OPTION_LOOPBACK_ONLY;
  if (GNUNET_FS_uri_test_ksk (sc->uri))
  {
    msize = sizeof (struct SearchMessage);
    GNUNET_assert (size >= msize);
    mbc.keyword_offset = sc->keyword_offset;
    mbc.put_cnt = 0;
    GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
                                           &find_result_set, &mbc);
    sqms = mbc.put_cnt;
    mbc.put_cnt = (size - msize) / sizeof (GNUNET_HashCode);
    mbc.put_cnt = GNUNET_MIN (mbc.put_cnt, sqms - mbc.skip_cnt);
    if (sc->search_request_map_offset < sqms)
      GNUNET_assert (mbc.put_cnt > 0);

    sm->header.size = htons (msize);
    sm->type = htonl (GNUNET_BLOCK_TYPE_ANY);
    sm->anonymity_level = htonl (sc->anonymity);
    memset (&sm->target, 0, sizeof (GNUNET_HashCode));
    sm->query = sc->requests[sc->keyword_offset].query;
    msize += sizeof (GNUNET_HashCode) * mbc.put_cnt;
    GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
                                           &build_result_set, &mbc);
    sm->header.size = htons (msize);
    GNUNET_assert (sqms >= sc->search_request_map_offset);
    if (sqms != sc->search_request_map_offset)
    {
      /* more requesting to be done... */
      sm->options = htonl (options | SEARCH_MESSAGE_OPTION_CONTINUED);
      schedule_transmit_search_request (sc);
      return msize;
    }
    sm->options = htonl (options);
    sc->keyword_offset++;
    if (sc->uri->data.ksk.keywordCount != sc->keyword_offset)
    {
      /* more requesting to be done... */
      schedule_transmit_search_request (sc);
      return msize;
    }
  }
  else
  {
    GNUNET_assert (GNUNET_FS_uri_test_sks (sc->uri));
    msize = sizeof (struct SearchMessage);
    GNUNET_assert (size >= msize);
    sm->type = htonl (GNUNET_BLOCK_TYPE_FS_SBLOCK);
    sm->anonymity_level = htonl (sc->anonymity);
    sm->target = sc->uri->data.sks.namespace;
    identifier = sc->uri->data.sks.identifier;
    GNUNET_CRYPTO_hash (identifier, strlen (identifier), &key);
    GNUNET_CRYPTO_hash (&key, sizeof (GNUNET_HashCode), &idh);
    GNUNET_CRYPTO_hash_xor (&idh, &sm->target, &sm->query);
    mbc.put_cnt = (size - msize) / sizeof (GNUNET_HashCode);
    sqms = GNUNET_CONTAINER_multihashmap_size (sc->master_result_map);
    mbc.put_cnt = GNUNET_MIN (mbc.put_cnt, sqms - mbc.skip_cnt);
    mbc.keyword_offset = 0;
    if (sc->search_request_map_offset < sqms)
      GNUNET_assert (mbc.put_cnt > 0);
    msize += sizeof (GNUNET_HashCode) * mbc.put_cnt;
    GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
                                           &build_result_set, &mbc);
    sm->header.size = htons (msize);
    GNUNET_assert (sqms >= sc->search_request_map_offset);
    if (sqms != sc->search_request_map_offset)
    {
      /* more requesting to be done... */
      sm->options = htonl (options | SEARCH_MESSAGE_OPTION_CONTINUED);
      schedule_transmit_search_request (sc);
      return msize;
    }
    sm->options = htonl (options);
  }
  GNUNET_CLIENT_receive (sc->client, &receive_results, sc,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  return msize;
}


/**
 * Schedule the transmission of the (next) search request
 * to the service.
 *
 * @param sc context for the search
 */
static void
schedule_transmit_search_request (struct GNUNET_FS_SearchContext *sc)
{
  size_t size;
  unsigned int sqms;
  unsigned int fit;

  size = sizeof (struct SearchMessage);
  sqms =
      GNUNET_CONTAINER_multihashmap_size (sc->master_result_map) -
      sc->search_request_map_offset;
  fit = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - size) / sizeof (GNUNET_HashCode);
  fit = GNUNET_MIN (fit, sqms);
  size += sizeof (GNUNET_HashCode) * fit;
  GNUNET_CLIENT_notify_transmit_ready (sc->client, size,
                                       GNUNET_CONSTANTS_SERVICE_TIMEOUT,
                                       GNUNET_NO, &transmit_search_request, sc);

}


/**
 * Reconnect to the FS service and transmit
 * our queries NOW.
 *
 * @param cls our search context
 * @param tc unused
 */
static void
do_reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  struct GNUNET_CLIENT_Connection *client;

  sc->task = GNUNET_SCHEDULER_NO_TASK;
  client = GNUNET_CLIENT_connect ("fs", sc->h->cfg);
  if (NULL == client)
  {
    try_reconnect (sc);
    return;
  }
  sc->client = client;
  sc->search_request_map_offset = 0;
  sc->keyword_offset = 0;
  schedule_transmit_search_request (sc);
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
  sc->task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &do_reconnect,
                                    sc);
}


/**
 * Start search for content, internal API.
 *
 * @param h handle to the file sharing subsystem
 * @param uri specifies the search parameters; can be
 *        a KSK URI or an SKS URI.
 * @param anonymity desired level of anonymity
 * @param options options for the search
 * @param cctx initial value for the client context
 * @param psearch parent search result (for namespace update searches)
 * @return context that can be used to control the search
 */
static struct GNUNET_FS_SearchContext *
search_start (struct GNUNET_FS_Handle *h, const struct GNUNET_FS_Uri *uri,
              uint32_t anonymity, enum GNUNET_FS_SearchOptions options,
              void *cctx, struct GNUNET_FS_SearchResult *psearch)
{
  struct GNUNET_FS_SearchContext *sc;
  struct GNUNET_FS_ProgressInfo pi;

  sc = GNUNET_malloc (sizeof (struct GNUNET_FS_SearchContext));
  sc->h = h;
  sc->options = options;
  sc->uri = GNUNET_FS_uri_dup (uri);
  sc->anonymity = anonymity;
  sc->start_time = GNUNET_TIME_absolute_get ();
  if (NULL != psearch)
  {
    sc->psearch_result = psearch;
    psearch->update_search = sc;
  }
  sc->master_result_map = GNUNET_CONTAINER_multihashmap_create (16);
  sc->client_info = cctx;
  if (GNUNET_OK != GNUNET_FS_search_start_searching_ (sc))
  {
    GNUNET_FS_uri_destroy (sc->uri);
    GNUNET_CONTAINER_multihashmap_destroy (sc->master_result_map);
    GNUNET_free (sc);
    return NULL;
  }
  GNUNET_FS_search_sync_ (sc);
  pi.status = GNUNET_FS_STATUS_SEARCH_START;
  sc->client_info = GNUNET_FS_search_make_status_ (&pi, sc);
  return sc;
}


/**
 * Build the request and actually initiate the search using the
 * GNUnet FS service.
 *
 * @param sc search context
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_FS_search_start_searching_ (struct GNUNET_FS_SearchContext *sc)
{
  unsigned int i;
  const char *keyword;
  GNUNET_HashCode hc;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;
  struct GNUNET_CRYPTO_RsaPrivateKey *pk;

  GNUNET_assert (NULL == sc->client);
  if (GNUNET_FS_uri_test_ksk (sc->uri))
  {
    GNUNET_assert (0 != sc->uri->data.ksk.keywordCount);
    sc->requests =
        GNUNET_malloc (sizeof (struct SearchRequestEntry) *
                       sc->uri->data.ksk.keywordCount);
    for (i = 0; i < sc->uri->data.ksk.keywordCount; i++)
    {
      keyword = &sc->uri->data.ksk.keywords[i][1];
      GNUNET_CRYPTO_hash (keyword, strlen (keyword), &hc);
      pk = GNUNET_CRYPTO_rsa_key_create_from_hash (&hc);
      GNUNET_assert (NULL != pk);
      GNUNET_CRYPTO_rsa_key_get_public (pk, &pub);
      GNUNET_CRYPTO_rsa_key_free (pk);
      GNUNET_CRYPTO_hash (&pub,
                          sizeof (struct
                                  GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                          &sc->requests[i].query);
      sc->requests[i].mandatory = (sc->uri->data.ksk.keywords[i][0] == '+');
      if (sc->requests[i].mandatory)
        sc->mandatory_count++;
      sc->requests[i].results = GNUNET_CONTAINER_multihashmap_create (4);
      GNUNET_CRYPTO_hash (keyword, strlen (keyword), &sc->requests[i].key);
    }
  }
  sc->client = GNUNET_CLIENT_connect ("fs", sc->h->cfg);
  if (NULL == sc->client)
    return GNUNET_SYSERR;
  schedule_transmit_search_request (sc);
  return GNUNET_OK;
}


/**
 * Freeze probes for the given search result.
 *
 * @param cls the global FS handle
 * @param key the key for the search result (unused)
 * @param value the search result to free
 * @return GNUNET_OK
 */
static int
search_result_freeze_probes (void *cls, const GNUNET_HashCode * key,
                             void *value)
{
  struct GNUNET_FS_SearchResult *sr = value;

  if (NULL != sr->probe_ctx)
  {
    GNUNET_FS_download_stop (sr->probe_ctx, GNUNET_YES);
    sr->probe_ctx = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != sr->probe_cancel_task)
  {
    GNUNET_SCHEDULER_cancel (sr->probe_cancel_task);
    sr->probe_cancel_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != sr->update_search)
    GNUNET_FS_search_pause (sr->update_search);
  return GNUNET_OK;
}


/**
 * Resume probes for the given search result.
 *
 * @param cls the global FS handle
 * @param key the key for the search result (unused)
 * @param value the search result to free
 * @return GNUNET_OK
 */
static int
search_result_resume_probes (void *cls, const GNUNET_HashCode * key,
                             void *value)
{
  struct GNUNET_FS_SearchResult *sr = value;

  GNUNET_FS_search_start_probe_ (sr);
  if (NULL != sr->update_search)
    GNUNET_FS_search_continue (sr->update_search);
  return GNUNET_OK;
}


/**
 * Signal suspend and free the given search result.
 *
 * @param cls the global FS handle
 * @param key the key for the search result (unused)
 * @param value the search result to free
 * @return GNUNET_OK
 */
static int
search_result_suspend (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  struct GNUNET_FS_SearchResult *sr = value;
  struct GNUNET_FS_ProgressInfo pi;

  if (NULL != sr->download)
  {
    GNUNET_FS_download_signal_suspend_ (sr->download);
    sr->download = NULL;
  }
  if (NULL != sr->probe_ctx)
  {
    GNUNET_FS_download_stop (sr->probe_ctx, GNUNET_YES);
    sr->probe_ctx = NULL;
  }
  if (NULL != sr->update_search)
  {
    GNUNET_FS_search_signal_suspend_ (sr->update_search);
    sr->update_search = NULL;
  }
  pi.status = GNUNET_FS_STATUS_SEARCH_RESULT_SUSPEND;
  pi.value.search.specifics.result_suspend.cctx = sr->client_info;
  pi.value.search.specifics.result_suspend.meta = sr->meta;
  pi.value.search.specifics.result_suspend.uri = sr->uri;
  sr->client_info = GNUNET_FS_search_make_status_ (&pi, sc);
  GNUNET_break (NULL == sr->client_info);
  GNUNET_free_non_null (sr->serialization);
  GNUNET_FS_uri_destroy (sr->uri);
  GNUNET_CONTAINER_meta_data_destroy (sr->meta);
  if (GNUNET_SCHEDULER_NO_TASK != sr->probe_cancel_task)
  {
    GNUNET_SCHEDULER_cancel (sr->probe_cancel_task);
    sr->probe_cancel_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free_non_null (sr->keyword_bitmap);
  GNUNET_free (sr);
  return GNUNET_OK;
}


/**
 * Create SUSPEND event for the given search operation
 * and then clean up our state (without stop signal).
 *
 * @param cls the 'struct GNUNET_FS_SearchContext' to signal for
 */
void
GNUNET_FS_search_signal_suspend_ (void *cls)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  struct GNUNET_FS_ProgressInfo pi;
  unsigned int i;

  GNUNET_FS_end_top (sc->h, sc->top);
  GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
                                         &search_result_suspend, sc);
  pi.status = GNUNET_FS_STATUS_SEARCH_SUSPEND;
  sc->client_info = GNUNET_FS_search_make_status_ (&pi, sc);
  GNUNET_break (NULL == sc->client_info);
  if (sc->task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (sc->task);
  if (NULL != sc->client)
    GNUNET_CLIENT_disconnect (sc->client);
  GNUNET_CONTAINER_multihashmap_destroy (sc->master_result_map);
  if (NULL != sc->requests)
  {
    GNUNET_assert (GNUNET_FS_uri_test_ksk (sc->uri));
    for (i = 0; i < sc->uri->data.ksk.keywordCount; i++)
      GNUNET_CONTAINER_multihashmap_destroy (sc->requests[i].results);
  }
  GNUNET_free_non_null (sc->requests);
  GNUNET_free_non_null (sc->emsg);
  GNUNET_FS_uri_destroy (sc->uri);
  GNUNET_free_non_null (sc->serialization);
  GNUNET_free (sc);
}


/**
 * Start search for content.
 *
 * @param h handle to the file sharing subsystem
 * @param uri specifies the search parameters; can be
 *        a KSK URI or an SKS URI.
 * @param anonymity desired level of anonymity
 * @param options options for the search
 * @param cctx initial value for the client context
 * @return context that can be used to control the search
 */
struct GNUNET_FS_SearchContext *
GNUNET_FS_search_start (struct GNUNET_FS_Handle *h,
                        const struct GNUNET_FS_Uri *uri, uint32_t anonymity,
                        enum GNUNET_FS_SearchOptions options, void *cctx)
{
  struct GNUNET_FS_SearchContext *ret;

  ret = search_start (h, uri, anonymity, options, cctx, NULL);
  if (NULL == ret)
    return NULL;
  ret->top = GNUNET_FS_make_top (h, &GNUNET_FS_search_signal_suspend_, ret);
  return ret;
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

  if (GNUNET_SCHEDULER_NO_TASK != sc->task)
    GNUNET_SCHEDULER_cancel (sc->task);
  sc->task = GNUNET_SCHEDULER_NO_TASK;
  if (NULL != sc->client)
    GNUNET_CLIENT_disconnect (sc->client);
  sc->client = NULL;
  GNUNET_FS_search_sync_ (sc);
  GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
                                         &search_result_freeze_probes, sc);
  pi.status = GNUNET_FS_STATUS_SEARCH_PAUSED;
  sc->client_info = GNUNET_FS_search_make_status_ (&pi, sc);
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

  GNUNET_assert (NULL == sc->client);
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == sc->task);
  do_reconnect (sc, NULL);
  GNUNET_FS_search_sync_ (sc);
  pi.status = GNUNET_FS_STATUS_SEARCH_CONTINUED;
  sc->client_info = GNUNET_FS_search_make_status_ (&pi, sc);
  GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
                                         &search_result_resume_probes, sc);
}


/**
 * Signal stop for the given search result.
 *
 * @param cls the global FS handle
 * @param key the key for the search result (unused)
 * @param value the search result to free
 * @return GNUNET_OK
 */
static int
search_result_stop (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  struct GNUNET_FS_SearchResult *sr = value;
  struct GNUNET_FS_ProgressInfo pi;

  if (NULL != sr->download)
  {
    sr->download->search = NULL;
    sr->download->top =
        GNUNET_FS_make_top (sr->download->h,
                            &GNUNET_FS_download_signal_suspend_, sr->download);
    if (NULL != sr->download->serialization)
    {
      GNUNET_FS_remove_sync_file_ (sc->h, GNUNET_FS_SYNC_PATH_CHILD_DOWNLOAD,
                                   sr->download->serialization);
      GNUNET_free (sr->download->serialization);
      sr->download->serialization = NULL;
    }
    pi.status = GNUNET_FS_STATUS_DOWNLOAD_LOST_PARENT;
    GNUNET_FS_download_make_status_ (&pi, sr->download);
    GNUNET_FS_download_sync_ (sr->download);
    sr->download = NULL;
  }
  pi.status = GNUNET_FS_STATUS_SEARCH_RESULT_STOPPED;
  pi.value.search.specifics.result_stopped.cctx = sr->client_info;
  pi.value.search.specifics.result_stopped.meta = sr->meta;
  pi.value.search.specifics.result_stopped.uri = sr->uri;
  sr->client_info = GNUNET_FS_search_make_status_ (&pi, sc);
  return GNUNET_OK;
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
search_result_free (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_FS_SearchResult *sr = value;

  if (NULL != sr->update_search)
  {
    GNUNET_FS_search_stop (sr->update_search);
    GNUNET_assert (NULL == sr->update_search);
  }
  GNUNET_break (NULL == sr->client_info);
  GNUNET_free_non_null (sr->serialization);
  GNUNET_FS_uri_destroy (sr->uri);
  GNUNET_CONTAINER_meta_data_destroy (sr->meta);
  if (NULL != sr->probe_ctx)
    GNUNET_FS_download_stop (sr->probe_ctx, GNUNET_YES);
  if (GNUNET_SCHEDULER_NO_TASK != sr->probe_cancel_task)
    GNUNET_SCHEDULER_cancel (sr->probe_cancel_task);
  GNUNET_free_non_null (sr->keyword_bitmap);
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

  if (NULL != sc->top)
    GNUNET_FS_end_top (sc->h, sc->top);
  GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
                                         &search_result_stop, sc);
  if (NULL != sc->psearch_result)
    sc->psearch_result->update_search = NULL;
  if (NULL != sc->serialization)
  {
    GNUNET_FS_remove_sync_file_ (sc->h,
                                 (sc->psearch_result !=
                                  NULL) ? GNUNET_FS_SYNC_PATH_CHILD_SEARCH :
                                 GNUNET_FS_SYNC_PATH_MASTER_SEARCH,
                                 sc->serialization);
    GNUNET_FS_remove_sync_dir_ (sc->h,
                                (sc->psearch_result !=
                                 NULL) ? GNUNET_FS_SYNC_PATH_CHILD_SEARCH :
                                GNUNET_FS_SYNC_PATH_MASTER_SEARCH,
                                sc->serialization);
    GNUNET_free (sc->serialization);
  }
  pi.status = GNUNET_FS_STATUS_SEARCH_STOPPED;
  sc->client_info = GNUNET_FS_search_make_status_ (&pi, sc);
  GNUNET_break (NULL == sc->client_info);
  if (GNUNET_SCHEDULER_NO_TASK != sc->task)
    GNUNET_SCHEDULER_cancel (sc->task);
  if (NULL != sc->client)
    GNUNET_CLIENT_disconnect (sc->client);
  GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
                                         &search_result_free, sc);
  GNUNET_CONTAINER_multihashmap_destroy (sc->master_result_map);
  if (NULL != sc->requests)
  {
    GNUNET_assert (GNUNET_FS_uri_test_ksk (sc->uri));
    for (i = 0; i < sc->uri->data.ksk.keywordCount; i++)
      GNUNET_CONTAINER_multihashmap_destroy (sc->requests[i].results);
  }
  GNUNET_free_non_null (sc->requests);
  GNUNET_free_non_null (sc->emsg);
  GNUNET_FS_uri_destroy (sc->uri);
  GNUNET_free (sc);
}

/* end of fs_search.c */
