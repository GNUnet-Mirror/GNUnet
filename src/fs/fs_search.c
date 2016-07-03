/*
     This file is part of GNUnet.
     Copyright (C) 2001-2014 GNUnet e.V.

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
     Boston, MA 02110-1301, USA.
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
#include "fs_publish_ublock.h"


/**
 * Number of availability trials we perform per search result.
 */
#define AVAILABILITY_TRIALS_MAX 8

/**
 * Fill in all of the generic fields for a search event and
 * call the callback.
 *
 * @param pi structure to fill in
 * @param h file-sharing handle
 * @param sc overall search context
 * @return value returned by the callback
 */
void *
GNUNET_FS_search_make_status_ (struct GNUNET_FS_ProgressInfo *pi,
			       struct GNUNET_FS_Handle *h,
                               struct GNUNET_FS_SearchContext *sc)
{
  void *ret;

  pi->value.search.sc = sc;
  pi->value.search.cctx = (NULL != sc) ? sc->client_info : NULL;
  pi->value.search.pctx =
    ((NULL == sc) || (NULL == sc->psearch_result))
    ? NULL
    : sc->psearch_result->client_info;
  pi->value.search.query = (NULL != sc) ? sc->uri : NULL;
  pi->value.search.duration = (NULL != sc)
    ? GNUNET_TIME_absolute_get_duration (sc->start_time)
    : GNUNET_TIME_UNIT_ZERO;
  pi->value.search.anonymity = (NULL != sc) ? sc->anonymity : 0;
  pi->fsh = h;
  ret = h->upcb (h->upcb_cls, pi);
  return ret;
}


/**
 * Check if the given result is identical to the given URI.
 *
 * @param cls points to the URI we check against
 * @param key not used
 * @param value a `struct GNUNET_FS_SearchResult` who's URI we
 *        should compare with
 * @return #GNUNET_SYSERR if the result is present,
 *         #GNUNET_OK otherwise
 */
static int
test_result_present (void *cls,
                     const struct GNUNET_HashCode * key,
                     void *value)
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
  sr->client_info = GNUNET_FS_search_make_status_ (&pi, sc->h, sc);
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
  pi.value.search.specifics.update.current_probe_time
    = GNUNET_TIME_absolute_get_duration (sr->probe_active_time);
  sr->client_info = GNUNET_FS_search_make_status_ (&pi, sc->h, sc);
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
 * @param cls a `struct GetResultContext`
 * @param key not used
 * @param value a `struct GNUNET_FS_SearchResult` who's URI we
 *        should compare with
 * @return #GNUNET_OK
 */
static int
get_result_present (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
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
 *
 * @param sr search result to signal for
 */
static void
signal_probe_result (struct GNUNET_FS_SearchResult *sr)
{
  struct GNUNET_FS_ProgressInfo pi;

  pi.status = GNUNET_FS_STATUS_SEARCH_UPDATE;
  pi.value.search.specifics.update.cctx = sr->client_info;
  pi.value.search.specifics.update.meta = sr->meta;
  pi.value.search.specifics.update.uri = sr->uri;
  pi.value.search.specifics.update.availability_rank
    = 2 * sr->availability_success - sr->availability_trials;
  pi.value.search.specifics.update.availability_certainty
    = sr->availability_trials;
  pi.value.search.specifics.update.applicability_rank = sr->optional_support;
  pi.value.search.specifics.update.current_probe_time
    = GNUNET_TIME_absolute_get_duration (sr->probe_active_time);
  sr->client_info = GNUNET_FS_search_make_status_ (&pi, sr->h, sr->sc);
  GNUNET_FS_search_start_probe_ (sr);
}


/**
 * Handle the case where we have failed to receive a response for our probe.
 *
 * @param cls our `struct GNUNET_FS_SearchResult *`
 */
static void
probe_failure_handler (void *cls)
{
  struct GNUNET_FS_SearchResult *sr = cls;

  sr->probe_cancel_task = NULL;
  sr->availability_trials++;
  GNUNET_FS_download_stop (sr->probe_ctx, GNUNET_YES);
  sr->probe_ctx = NULL;
  GNUNET_FS_stop_probe_ping_task_ (sr);
  GNUNET_FS_search_result_sync_ (sr);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Probe #%u for search result %p failed\n",
	      sr->availability_trials,
	      sr);
  signal_probe_result (sr);
}


/**
 * Handle the case where we have gotten a response for our probe.
 *
 * @param cls our `struct GNUNET_FS_SearchResult *`
 */
static void
probe_success_handler (void *cls)
{
  struct GNUNET_FS_SearchResult *sr = cls;

  sr->probe_cancel_task = NULL;
  sr->availability_trials++;
  sr->availability_success++;
  GNUNET_FS_download_stop (sr->probe_ctx, GNUNET_YES);
  sr->probe_ctx = NULL;
  GNUNET_FS_stop_probe_ping_task_ (sr);
  GNUNET_FS_search_result_sync_ (sr);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Probe #%u for search result %p succeeded\n",
	      sr->availability_trials,
	      sr);
  signal_probe_result (sr);
}


/**
 * Notification of FS that a search probe has made progress.
 * This function is used INSTEAD of the client's event handler
 * for downloads where the #GNUNET_FS_DOWNLOAD_IS_PROBE flag is set.
 *
 * @param cls closure, always NULL (!), actual closure
 *        is in the client-context of the info struct
 * @param info details about the event, specifying the event type
 *        and various bits about the event
 * @return client-context (for the next progress call
 *         for this operation; should be set to NULL for
 *         SUSPEND and STOPPED events).  The value returned
 *         will be passed to future callbacks in the respective
 *         field in the `struct GNUNET_FS_ProgressInfo`.
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
    if (NULL != sr->probe_cancel_task)
    {
      GNUNET_SCHEDULER_cancel (sr->probe_cancel_task);
      sr->probe_cancel_task = NULL;
    }
    sr->probe_cancel_task =
        GNUNET_SCHEDULER_add_delayed (sr->remaining_probe_time,
                                      &probe_failure_handler, sr);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_COMPLETED:
    if (NULL != sr->probe_cancel_task)
    {
      GNUNET_SCHEDULER_cancel (sr->probe_cancel_task);
      sr->probe_cancel_task = NULL;
    }
    sr->probe_cancel_task =
        GNUNET_SCHEDULER_add_now (&probe_success_handler, sr);
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_STOPPED:
    if (NULL != sr->probe_cancel_task)
    {
      GNUNET_SCHEDULER_cancel (sr->probe_cancel_task);
      sr->probe_cancel_task = NULL;
    }
    sr = NULL;
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_ACTIVE:
    if (NULL == sr->probe_cancel_task)
    {
      sr->probe_active_time = GNUNET_TIME_absolute_get ();
      sr->probe_cancel_task =
        GNUNET_SCHEDULER_add_delayed (sr->remaining_probe_time,
                                      &probe_failure_handler, sr);
    }
    break;
  case GNUNET_FS_STATUS_DOWNLOAD_INACTIVE:
    if (NULL != sr->probe_cancel_task)
    {
      GNUNET_SCHEDULER_cancel (sr->probe_cancel_task);
      sr->probe_cancel_task = NULL;
    }
    dur = GNUNET_TIME_absolute_get_duration (sr->probe_active_time);
    sr->remaining_probe_time =
        GNUNET_TIME_relative_subtract (sr->remaining_probe_time, dur);
    if (0 == sr->remaining_probe_time.rel_value_us)
      sr->probe_cancel_task =
        GNUNET_SCHEDULER_add_now (&probe_failure_handler, sr);
    GNUNET_FS_search_result_sync_ (sr);
    break;
  default:
    GNUNET_break (0);
    return NULL;
  }
  return sr;
}


/**
 * Task run periodically to remind clients that a probe is active.
 *
 * @param cls the `struct GNUNET_FS_SearchResult` that we are probing for
 */
static void
probe_ping_task_cb (void *cls)
{
  struct GNUNET_FS_Handle *h = cls;
  struct GNUNET_FS_SearchResult *sr;

  for (sr = h->probes_head; NULL != sr; sr = sr->next)
    if (NULL != sr->probe_ctx->mq)
      signal_probe_result (sr);
  h->probe_ping_task
    = GNUNET_SCHEDULER_add_delayed (GNUNET_FS_PROBE_UPDATE_FREQUENCY,
				    &probe_ping_task_cb,
				    h);
}


/**
 * Start the ping task for this search result.
 *
 * @param sr result to start pinging for.
 */
static void
start_probe_ping_task (struct GNUNET_FS_SearchResult *sr)
{
  struct GNUNET_FS_Handle *h = sr->h;

  GNUNET_CONTAINER_DLL_insert (h->probes_head,
                               h->probes_tail,
                               sr);
  if (NULL == h->probe_ping_task)
    h->probe_ping_task
      = GNUNET_SCHEDULER_add_now (&probe_ping_task_cb,
                                  h);
}


/**
 * Stop the ping task for this search result.
 *
 * @param sr result to start pinging for.
 */
void
GNUNET_FS_stop_probe_ping_task_ (struct GNUNET_FS_SearchResult *sr)
{
  struct GNUNET_FS_Handle *h = sr->h;

  GNUNET_CONTAINER_DLL_remove (h->probes_head,
                               h->probes_tail,
                               sr);
  if (NULL == h->probes_head)
  {
    GNUNET_SCHEDULER_cancel (h->probe_ping_task);
    h->probe_ping_task = NULL;
  }
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
  if (0 == (sr->h->flags & GNUNET_FS_FLAGS_DO_PROBES))
    return;
  if (sr->availability_trials > AVAILABILITY_TRIALS_MAX)
    return;
  if ( (GNUNET_FS_URI_CHK != sr->uri->type) && (GNUNET_FS_URI_LOC != sr->uri->type))
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting probe #%u (at offset %llu) for search result %p\n",
	      sr->availability_trials + 1,
	      (unsigned long long) off,
	      sr);
  sr->remaining_probe_time =
      GNUNET_TIME_relative_multiply (sr->h->avg_block_latency,
                                     2 * (1 + sr->availability_trials));
  sr->probe_ctx =
      GNUNET_FS_download_start (sr->h, sr->uri, sr->meta, NULL, NULL, off,
                                len, sr->anonymity,
                                GNUNET_FS_DOWNLOAD_NO_TEMPORARIES |
                                GNUNET_FS_DOWNLOAD_IS_PROBE, sr, NULL);
  start_probe_ping_task (sr);
}


/**
 * Start download probes for the given search result.
 *
 * @param h file-sharing handle to use for the operation
 * @param uri URI to probe
 * @param meta meta data associated with the URI
 * @param client_info client info pointer to use for associated events
 * @param anonymity anonymity level to use for the probes
 * @return the search result handle to access the probe activity
 */
struct GNUNET_FS_SearchResult *
GNUNET_FS_probe (struct GNUNET_FS_Handle *h,
		 const struct GNUNET_FS_Uri *uri,
		 const struct GNUNET_CONTAINER_MetaData *meta,
		 void *client_info,
		 uint32_t anonymity)
{
  struct GNUNET_FS_SearchResult *sr;

  GNUNET_assert (NULL != h);
  sr = GNUNET_new (struct GNUNET_FS_SearchResult);
  sr->h = h;
  sr->uri = GNUNET_FS_uri_dup (uri);
  sr->meta = GNUNET_CONTAINER_meta_data_duplicate (meta);
  sr->client_info = client_info;
  sr->anonymity = anonymity;
  GNUNET_FS_search_start_probe_ (sr);
  return sr;
}


/**
 * Stop probing activity associated with a search result.
 *
 * @param sr search result
 */
static void
GNUNET_FS_search_stop_probe_ (struct GNUNET_FS_SearchResult *sr)
{
  if (NULL != sr->probe_ctx)
  {
    GNUNET_FS_download_stop (sr->probe_ctx, GNUNET_YES);
    sr->probe_ctx = NULL;
    GNUNET_FS_stop_probe_ping_task_ (sr);
  }
  if (NULL != sr->probe_cancel_task)
  {
    GNUNET_SCHEDULER_cancel (sr->probe_cancel_task);
    sr->probe_cancel_task = NULL;
  }
}


/**
 * Stop probe activity.  Must ONLY be used on values
 * returned from #GNUNET_FS_probe.
 *
 * @param sr search result to stop probing for (freed)
 * @return the value of the 'client_info' pointer
 */
void *
GNUNET_FS_probe_stop (struct GNUNET_FS_SearchResult *sr)
{
  void *client_info;

  GNUNET_assert (NULL == sr->sc);
  GNUNET_FS_search_stop_probe_ (sr);
  GNUNET_FS_uri_destroy (sr->uri);
  GNUNET_CONTAINER_meta_data_destroy (sr->meta);
  client_info = sr->client_info;
  GNUNET_free (sr);
  return client_info;
}


/**
 * We have received a KSK result.  Check how it fits in with the
 * overall query and notify the client accordingly.
 *
 * @param sc context for the overall query
 * @param ent entry for the specific keyword
 * @param uri the URI that was found
 * @param meta metadata associated with the URI
 *        under the @a ent keyword
 */
static void
process_ksk_result (struct GNUNET_FS_SearchContext *sc,
                    struct SearchRequestEntry *ent,
                    const struct GNUNET_FS_Uri *uri,
                    const struct GNUNET_CONTAINER_MetaData *meta)
{
  struct GNUNET_HashCode key;
  struct GNUNET_FS_SearchResult *sr;
  struct GetResultContext grc;
  int is_new;
  unsigned int koff;

  /* check if new */
  GNUNET_assert (NULL != sc);
  GNUNET_FS_uri_to_key (uri, &key);
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_get_multiple (ent->results,
                                                  &key,
                                                  &test_result_present,
                                                  (void *) uri))
    return;                     /* duplicate result */
  /* try to find search result in master map */
  grc.sr = NULL;
  grc.uri = uri;
  GNUNET_CONTAINER_multihashmap_get_multiple (sc->master_result_map,
                                              &key,
                                              &get_result_present, &grc);
  sr = grc.sr;
  is_new = (NULL == sr) || (sr->mandatory_missing > 0);
  if (NULL == sr)
  {
    sr = GNUNET_new (struct GNUNET_FS_SearchResult);
    sr->h = sc->h;
    sr->sc = sc;
    sr->anonymity = sc->anonymity;
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
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multihashmap_put (ent->results,
                                                   &sr->key,
                                                   sr,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  koff = ent - sc->requests;
  GNUNET_assert ( (ent >= sc->requests) &&
                  (koff < sc->uri->data.ksk.keywordCount));
  sr->keyword_bitmap[koff / 8] |= (1 << (koff % 8));
  /* check if mandatory satisfied */
  if (1 <= GNUNET_CONTAINER_multihashmap_size (ent->results))
  {
    if (ent->mandatory)
    {
      GNUNET_break (sr->mandatory_missing > 0);
      sr->mandatory_missing--;
    }
    else
    {
      sr->optional_support++;
    }
  }
  if (0 != sr->mandatory_missing)
  {
    GNUNET_break (NULL == sr->client_info);
    return;
  }
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
search_start (struct GNUNET_FS_Handle *h,
              const struct GNUNET_FS_Uri *uri,
              uint32_t anonymity,
              enum GNUNET_FS_SearchOptions options,
              void *cctx,
              struct GNUNET_FS_SearchResult *psearch);


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
  struct GNUNET_HashCode key;
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
  sr = GNUNET_new (struct GNUNET_FS_SearchResult);
  sr->h = sc->h;
  sr->sc = sc;
  sr->anonymity = sc->anonymity;
  sr->uri = GNUNET_FS_uri_dup (uri);
  sr->meta = GNUNET_CONTAINER_meta_data_duplicate (meta);
  sr->key = key;
  GNUNET_CONTAINER_multihashmap_put (sc->master_result_map, &key, sr,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_FS_search_result_sync_ (sr);
  GNUNET_FS_search_start_probe_ (sr);
  /* notify client */
  if (0 == sr->mandatory_missing)
    notify_client_chk_result (sc, sr);
  else
    GNUNET_break (NULL == sr->client_info);
  /* search for updates */
  if (0 == strlen (id_update))
    return;                     /* no updates */
  uu.type = GNUNET_FS_URI_SKS;
  uu.data.sks.ns = sc->uri->data.sks.ns;
  uu.data.sks.identifier = GNUNET_strdup (id_update);
  (void) search_start (sc->h, &uu, sc->anonymity, sc->options, NULL, sr);
  GNUNET_free (uu.data.sks.identifier);
}


/**
 * Decrypt a ublock using a 'keyword' as the passphrase.  Given the
 * KSK public key derived from the keyword, this function looks up
 * the original keyword in the search context and decrypts the
 * given ciphertext block.
 *
 * @param sc search context with the keywords
 * @param dpub derived public key used for the search
 * @param edata encrypted data
 * @param edata_size number of bytes in @a edata (and @a data)
 * @param data where to store the plaintext
 * @return keyword index on success, #GNUNET_SYSERR on error (no such
 *         keyword, internal error)
 */
static int
decrypt_block_with_keyword (const struct GNUNET_FS_SearchContext *sc,
			    const struct GNUNET_CRYPTO_EcdsaPublicKey *dpub,
			    const void *edata,
			    size_t edata_size,
			    char *data)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *anon;
  struct GNUNET_CRYPTO_EcdsaPublicKey anon_pub;
  unsigned int i;

  /* find key */
  for (i = 0; i < sc->uri->data.ksk.keywordCount; i++)
    if (0 == memcmp (dpub,
		     &sc->requests[i].dpub,
		     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
      break;
  if (i == sc->uri->data.ksk.keywordCount)
  {
    /* oops, does not match any of our keywords!? */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  /* decrypt */
  anon = GNUNET_CRYPTO_ecdsa_key_get_anonymous ();
  GNUNET_CRYPTO_ecdsa_key_get_public (anon, &anon_pub);
  GNUNET_FS_ublock_decrypt_ (edata, edata_size,
			     &anon_pub,
			     sc->requests[i].keyword,
			     data);
  return i;
}


/**
 * Process a keyword search result.  The actual type of block is
 * a UBlock; we know it is a keyword search result because that's
 * what we were searching for.
 *
 * @param sc our search context
 * @param ub the ublock with the keyword search result
 * @param size size of @a ub
 */
static void
process_kblock (struct GNUNET_FS_SearchContext *sc,
		const struct UBlock *ub,
                size_t size)
{
  size_t j;
  char pt[size - sizeof (struct UBlock)];
  const char *eos;
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_FS_Uri *uri;
  char *emsg;
  int i;

  if (-1 == (i = decrypt_block_with_keyword (sc,
					     &ub->verification_key,
					     &ub[1],
					     size - sizeof (struct UBlock),
					     pt)))
    return;
  /* parse; pt[0] is just '\0', so we skip over that */
  eos = memchr (&pt[1], '\0', sizeof (pt) - 1);
  if (NULL == eos)
  {
    GNUNET_break_op (0);
    return;
  }
  if (NULL == (uri = GNUNET_FS_uri_parse (&pt[1], &emsg)))
  {
    if (GNUNET_FS_VERSION > 0x00090400)
    {
      /* we broke this in 0x00090300, so don't bitch
         too loudly just one version up... */
      GNUNET_break_op (0);        /* ublock malformed */
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to parse URI `%s': %s\n"),
                  &pt[1],
                  emsg);
    }
    GNUNET_free_non_null (emsg);
    return;
  }
  j = eos - pt + 1;
  if (sizeof (pt) == j)
    meta = GNUNET_CONTAINER_meta_data_create ();
  else
    meta = GNUNET_CONTAINER_meta_data_deserialize (&pt[j], sizeof (pt) - j);
  if (NULL == meta)
  {
    GNUNET_break_op (0);        /* ublock malformed */
    GNUNET_FS_uri_destroy (uri);
    return;
  }
  process_ksk_result (sc,
                      &sc->requests[i],
                      uri,
                      meta);

  /* clean up */
  GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_FS_uri_destroy (uri);
}


/**
 * Process a namespace-search result.  The actual type of block is
 * a UBlock; we know it is a namespace search result because that's
 * what we were searching for.
 *
 * @param sc our search context
 * @param ub the ublock with a namespace result
 * @param size size of @a ub
 */
static void
process_sblock (struct GNUNET_FS_SearchContext *sc,
		const struct UBlock *ub,
                size_t size)
{
  size_t len = size - sizeof (struct UBlock);
  char pt[len];
  struct GNUNET_FS_Uri *uri;
  struct GNUNET_CONTAINER_MetaData *meta;
  const char *id;
  const char *uris;
  size_t off;
  char *emsg;

  GNUNET_FS_ublock_decrypt_ (&ub[1], len,
			     &sc->uri->data.sks.ns,
			     sc->uri->data.sks.identifier,
			     pt);
  /* parse */
  if (0 == (off = GNUNET_STRINGS_buffer_tokenize (pt, len, 2, &id, &uris)))
  {
    GNUNET_break_op (0);        /* ublock malformed */
    return;
  }
  if (NULL == (meta = GNUNET_CONTAINER_meta_data_deserialize (&pt[off], len - off)))
  {
    GNUNET_break_op (0);        /* ublock malformed */
    return;
  }
  if (NULL == (uri = GNUNET_FS_uri_parse (uris, &emsg)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to parse URI `%s': %s\n"),
		uris, emsg);
    GNUNET_break_op (0);        /* ublock malformed */
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
 * Shutdown any existing connection to the FS
 * service and try to establish a fresh one
 * (and then re-transmit our search request).
 *
 * @param sc the search to reconnec
 */
static void
try_reconnect (struct GNUNET_FS_SearchContext *sc);


/**
 * We check a result message from the service.
 *
 * @param cls closure
 * @param msg result message received
 */
static int
check_result (void *cls,
              const struct ClientPutMessage *cm)
{
  /* payload of any variable size is OK */
  return GNUNET_OK;
}


/**
 * We process a search result from the service.
 *
 * @param cls closure
 * @param msg result message received
 */
static void
handle_result (void *cls,
               const struct ClientPutMessage *cm)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  uint16_t msize = ntohs (cm->header.size) - sizeof (*cm);
  enum GNUNET_BLOCK_Type type = ntohl (cm->type);

  if (GNUNET_TIME_absolute_get_duration (GNUNET_TIME_absolute_ntoh (cm->expiration)).rel_value_us > 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Result received has already expired.\n");
    return;                     /* result expired */
  }
  switch (type)
  {
  case GNUNET_BLOCK_TYPE_FS_UBLOCK:
    if (GNUNET_FS_URI_SKS == sc->uri->type)
      process_sblock (sc,
                      (const struct UBlock *) &cm[1],
                      msize);
    else
      process_kblock (sc,
                      (const struct UBlock *) &cm[1],
                      msize);
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
                _("Got result with unknown block type `%d', ignoring"),
                type);
    break;
  }
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
 * Closure for #build_result_set().
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
  struct GNUNET_HashCode *xoff;

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
 * @param cls the `struct MessageBuilderContext`
 * @param key key for a result
 * @param value the search result
 * @return #GNUNET_OK to continue iterating
 */
static int
build_result_set (void *cls,
                  const struct GNUNET_HashCode *key,
                  void *value)
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
  mbc->xoff[--mbc->put_cnt] = *key;

  return GNUNET_OK;
}


/**
 * Iterating over the known results, count those matching the given
 * result range and increment put count for each.
 *
 * @param cls the `struct MessageBuilderContext`
 * @param key key for a result
 * @param value the search result
 * @return #GNUNET_OK to continue iterating
 */
static int
find_result_set (void *cls,
                 const struct GNUNET_HashCode *key,
                 void *value)
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
 * Schedule the transmission of the (next) search request
 * to the service.
 *
 * @param sc context for the search
 */
static void
schedule_transmit_search_request (struct GNUNET_FS_SearchContext *sc)
{
  struct MessageBuilderContext mbc;
  struct GNUNET_MQ_Envelope *env;
  struct SearchMessage *sm;
  struct GNUNET_CRYPTO_EcdsaPublicKey dpub;
  unsigned int total_seen_results; /* total number of result hashes to send */
  uint32_t options;
  unsigned int left;
  unsigned int todo;
  unsigned int fit;
  int first_call;
  unsigned int search_request_map_offset;
  unsigned int keyword_offset;

  memset (&mbc, 0, sizeof (mbc));
  mbc.sc = sc;
  if (GNUNET_FS_uri_test_ksk (sc->uri))
  {
    mbc.put_cnt = 0;
    GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
                                           &find_result_set,
                                           &mbc);
    total_seen_results = mbc.put_cnt;
  }
  else
  {
    total_seen_results
      = GNUNET_CONTAINER_multihashmap_size (sc->master_result_map);
  }
  search_request_map_offset = 0;
  keyword_offset = 0;

  first_call = GNUNET_YES;
  while ( (0 != (left =
                 (total_seen_results - search_request_map_offset))) ||
          (GNUNET_YES == first_call) )
  {
    first_call = GNUNET_NO;
    options = SEARCH_MESSAGE_OPTION_NONE;
    if (0 != (sc->options & GNUNET_FS_SEARCH_OPTION_LOOPBACK_ONLY))
      options |= SEARCH_MESSAGE_OPTION_LOOPBACK_ONLY;

    fit = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (*sm)) / sizeof (struct GNUNET_HashCode);
    todo = GNUNET_MIN (fit,
                       left);
    env = GNUNET_MQ_msg_extra (sm,
                               sizeof (struct GNUNET_HashCode) * todo,
                               GNUNET_MESSAGE_TYPE_FS_START_SEARCH);
    mbc.skip_cnt = search_request_map_offset;
    mbc.xoff = (struct GNUNET_HashCode *) &sm[1];

    if (GNUNET_FS_uri_test_ksk (sc->uri))
    {
      mbc.keyword_offset = keyword_offset;
      /* calculate how many results we can send in this message */
      mbc.put_cnt = todo;
      /* now build message */
      sm->type = htonl (GNUNET_BLOCK_TYPE_FS_UBLOCK);
      sm->anonymity_level = htonl (sc->anonymity);
      memset (&sm->target,
              0,
              sizeof (struct GNUNET_PeerIdentity));
      sm->query = sc->requests[keyword_offset].uquery;
      GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
                                             &build_result_set,
                                             &mbc);
      search_request_map_offset += todo;
      GNUNET_assert (0 == mbc.put_cnt);
      GNUNET_assert (total_seen_results >= search_request_map_offset);
      if (total_seen_results != search_request_map_offset)
      {
        /* more requesting to be done... */
        sm->options = htonl (options | SEARCH_MESSAGE_OPTION_CONTINUED);
      }
      else
      {
        sm->options = htonl (options);
        keyword_offset++;
        search_request_map_offset = 0;
        if (sc->uri->data.ksk.keywordCount != keyword_offset)
        {
          /* more keywords => more requesting to be done... */
          first_call = GNUNET_YES;
        }
      }
    }
    else
    {
      GNUNET_assert (GNUNET_FS_uri_test_sks (sc->uri));

      sm->type = htonl (GNUNET_BLOCK_TYPE_FS_UBLOCK);
      sm->anonymity_level = htonl (sc->anonymity);
      memset (&sm->target,
              0,
              sizeof (struct GNUNET_PeerIdentity));
      GNUNET_CRYPTO_ecdsa_public_key_derive (&sc->uri->data.sks.ns,
                                             sc->uri->data.sks.identifier,
                                             "fs-ublock",
                                             &dpub);
      GNUNET_CRYPTO_hash (&dpub,
                          sizeof (dpub),
                          &sm->query);
      mbc.put_cnt = todo;
      mbc.keyword_offset = 0;
      GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
                                             &build_result_set,
                                             &mbc);
      GNUNET_assert (total_seen_results >= search_request_map_offset);
      if (total_seen_results != search_request_map_offset)
      {
        /* more requesting to be done... */
        sm->options = htonl (options | SEARCH_MESSAGE_OPTION_CONTINUED);
      }
      else
      {
        sm->options = htonl (options);
      }
    }
    GNUNET_MQ_send (sc->mq,
                    env);
  }
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_FS_SearchContext *`
 * @param error error code
 */
static void
search_mq_error_handler (void *cls,
                         enum GNUNET_MQ_Error error)
{
  struct GNUNET_FS_SearchContext *sc = cls;

  if (NULL != sc->mq)
  {
    GNUNET_MQ_destroy (sc->mq);
    sc->mq = NULL;
  }
  try_reconnect (sc);
}


/**
 * Reconnect to the FS service and transmit
 * our queries NOW.
 *
 * @param cls our search context
 */
static void
do_reconnect (void *cls)
{
  GNUNET_MQ_hd_var_size (result,
                         GNUNET_MESSAGE_TYPE_FS_PUT,
                         struct ClientPutMessage);
  struct GNUNET_FS_SearchContext *sc = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    make_result_handler (sc),
    GNUNET_MQ_handler_end ()
  };

  sc->task = NULL;
  sc->mq = GNUNET_CLIENT_connecT (sc->h->cfg,
                                  "fs",
                                  handlers,
                                  &search_mq_error_handler,
                                  sc);
  if (NULL == sc->mq)
  {
    try_reconnect (sc);
    return;
  }
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
  if (NULL != sc->mq)
  {
    GNUNET_MQ_destroy (sc->mq);
    sc->mq = NULL;
  }
  sc->reconnect_backoff = GNUNET_TIME_STD_BACKOFF (sc->reconnect_backoff);
  sc->task =
      GNUNET_SCHEDULER_add_delayed (sc->reconnect_backoff,
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
 * @param options options for the search
 * @param cctx initial value for the client context
 * @param psearch parent search result (for namespace update searches)
 * @return context that can be used to control the search
 */
static struct GNUNET_FS_SearchContext *
search_start (struct GNUNET_FS_Handle *h,
              const struct GNUNET_FS_Uri *uri,
              uint32_t anonymity,
              enum GNUNET_FS_SearchOptions options,
              void *cctx,
              struct GNUNET_FS_SearchResult *psearch)
{
  struct GNUNET_FS_SearchContext *sc;
  struct GNUNET_FS_ProgressInfo pi;

  sc = GNUNET_new (struct GNUNET_FS_SearchContext);
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
  sc->master_result_map = GNUNET_CONTAINER_multihashmap_create (16, GNUNET_NO);
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
  sc->client_info = GNUNET_FS_search_make_status_ (&pi, sc->h, sc);
  return sc;
}


/**
 * Update the 'results' map for the individual keywords with the
 * results from the 'global' result set.
 *
 * @param cls closure, the `struct GNUNET_FS_SearchContext *`
 * @param key current key code
 * @param value value in the hash map, the `struct GNUNET_FS_SearchResult *`
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
update_sre_result_maps (void *cls,
                        const struct GNUNET_HashCode *key,
                        void *value)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  struct GNUNET_FS_SearchResult *sr = value;
  unsigned int i;

  for (i = 0; i < sc->uri->data.ksk.keywordCount; i++)
    if (0 != (sr->keyword_bitmap[i / 8] & (1 << (i % 8))))
      GNUNET_break (GNUNET_OK ==
                    GNUNET_CONTAINER_multihashmap_put (sc->requests[i].results,
                                                       &sr->key,
                                                       sr,
                                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  return GNUNET_YES;
}


/**
 * Build the request and actually initiate the search using the
 * GNUnet FS service.
 *
 * @param sc search context
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_FS_search_start_searching_ (struct GNUNET_FS_SearchContext *sc)
{
  unsigned int i;
  const char *keyword;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *anon;
  struct GNUNET_CRYPTO_EcdsaPublicKey anon_pub;
  struct SearchRequestEntry *sre;

  GNUNET_assert (NULL == sc->mq);
  if (GNUNET_FS_uri_test_ksk (sc->uri))
  {
    GNUNET_assert (0 != sc->uri->data.ksk.keywordCount);
    anon = GNUNET_CRYPTO_ecdsa_key_get_anonymous ();
    GNUNET_CRYPTO_ecdsa_key_get_public (anon, &anon_pub);
    sc->requests =
        GNUNET_malloc (sizeof (struct SearchRequestEntry) *
                       sc->uri->data.ksk.keywordCount);
    for (i = 0; i < sc->uri->data.ksk.keywordCount; i++)
    {
      keyword = &sc->uri->data.ksk.keywords[i][1];
      sre = &sc->requests[i];
      sre->keyword = GNUNET_strdup (keyword);
      GNUNET_CRYPTO_ecdsa_public_key_derive (&anon_pub,
                                             keyword,
                                             "fs-ublock",
                                             &sre->dpub);
      GNUNET_CRYPTO_hash (&sre->dpub,
			  sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey),
			  &sre->uquery);
      sre->mandatory = (sc->uri->data.ksk.keywords[i][0] == '+');
      if (sre->mandatory)
        sc->mandatory_count++;
      sre->results = GNUNET_CONTAINER_multihashmap_create (4, GNUNET_NO);
    }
    GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
                                           &update_sre_result_maps,
                                           sc);
  }
  GNUNET_assert (NULL == sc->task);
  do_reconnect (sc);
  if (NULL == sc->mq)
  {
    GNUNET_SCHEDULER_cancel (sc->task);
    sc->task = NULL;
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Freeze probes for the given search result.
 *
 * @param cls the global FS handle
 * @param key the key for the search result (unused)
 * @param value the search result to free
 * @return #GNUNET_OK
 */
static int
search_result_freeze_probes (void *cls,
                             const struct GNUNET_HashCode *key,
                             void *value)
{
  struct GNUNET_FS_SearchResult *sr = value;

  if (NULL != sr->probe_ctx)
  {
    GNUNET_FS_download_stop (sr->probe_ctx, GNUNET_YES);
    sr->probe_ctx = NULL;
    GNUNET_FS_stop_probe_ping_task_ (sr);
  }
  if (NULL != sr->probe_cancel_task)
  {
    GNUNET_SCHEDULER_cancel (sr->probe_cancel_task);
    sr->probe_cancel_task = NULL;
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
 * @return #GNUNET_OK
 */
static int
search_result_resume_probes (void *cls,
                             const struct GNUNET_HashCode * key,
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
 * @return #GNUNET_OK
 */
static int
search_result_suspend (void *cls,
                       const struct GNUNET_HashCode *key,
                       void *value)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  struct GNUNET_FS_SearchResult *sr = value;
  struct GNUNET_FS_ProgressInfo pi;

  if (NULL != sr->download)
  {
    GNUNET_FS_download_signal_suspend_ (sr->download);
    sr->download = NULL;
  }
  if (NULL != sr->update_search)
  {
    GNUNET_FS_search_signal_suspend_ (sr->update_search);
    sr->update_search = NULL;
  }
  GNUNET_FS_search_stop_probe_ (sr);
  if (0 == sr->mandatory_missing)
  {
    /* client is aware of search result, notify about suspension event */
    pi.status = GNUNET_FS_STATUS_SEARCH_RESULT_SUSPEND;
    pi.value.search.specifics.result_suspend.cctx = sr->client_info;
    pi.value.search.specifics.result_suspend.meta = sr->meta;
    pi.value.search.specifics.result_suspend.uri = sr->uri;
    sr->client_info = GNUNET_FS_search_make_status_ (&pi, sc->h, sc);
  }
  GNUNET_break (NULL == sr->client_info);
  GNUNET_free_non_null (sr->serialization);
  GNUNET_FS_uri_destroy (sr->uri);
  GNUNET_CONTAINER_meta_data_destroy (sr->meta);
  GNUNET_free_non_null (sr->keyword_bitmap);
  GNUNET_free (sr);
  return GNUNET_OK;
}


/**
 * Create SUSPEND event for the given search operation
 * and then clean up our state (without stop signal).
 *
 * @param cls the `struct GNUNET_FS_SearchContext` to signal for
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
  sc->client_info = GNUNET_FS_search_make_status_ (&pi, sc->h, sc);
  GNUNET_break (NULL == sc->client_info);
  if (sc->task != NULL)
  {
    GNUNET_SCHEDULER_cancel (sc->task);
    sc->task = NULL;
  }
  if (NULL != sc->mq)
  {
    GNUNET_MQ_destroy (sc->mq);
    sc->mq = NULL;
  }
  GNUNET_CONTAINER_multihashmap_destroy (sc->master_result_map);
  if (NULL != sc->requests)
  {
    GNUNET_assert (GNUNET_FS_uri_test_ksk (sc->uri));
    for (i = 0; i < sc->uri->data.ksk.keywordCount; i++)
    {
      GNUNET_CONTAINER_multihashmap_destroy (sc->requests[i].results);
      GNUNET_free (sc->requests[i].keyword);
    }
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

  if (NULL != sc->task)
  {
    GNUNET_SCHEDULER_cancel (sc->task);
    sc->task = NULL;
  }
  if (NULL != sc->mq)
  {
    GNUNET_MQ_destroy (sc->mq);
    sc->mq = NULL;
  }
  GNUNET_FS_search_sync_ (sc);
  GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
                                         &search_result_freeze_probes,
                                         sc);
  pi.status = GNUNET_FS_STATUS_SEARCH_PAUSED;
  sc->client_info = GNUNET_FS_search_make_status_ (&pi,
                                                   sc->h,
                                                   sc);
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

  GNUNET_assert (NULL == sc->mq);
  GNUNET_assert (NULL == sc->task);
  do_reconnect (sc);
  GNUNET_FS_search_sync_ (sc);
  pi.status = GNUNET_FS_STATUS_SEARCH_CONTINUED;
  sc->client_info = GNUNET_FS_search_make_status_ (&pi, sc->h, sc);
  GNUNET_CONTAINER_multihashmap_iterate (sc->master_result_map,
                                         &search_result_resume_probes, sc);
}


/**
 * Signal stop for the given search result.
 *
 * @param cls the global FS handle
 * @param key the key for the search result (unused)
 * @param value the search result to free
 * @return #GNUNET_OK
 */
static int
search_result_stop (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct GNUNET_FS_SearchContext *sc = cls;
  struct GNUNET_FS_SearchResult *sr = value;
  struct GNUNET_FS_ProgressInfo pi;

  GNUNET_FS_search_stop_probe_ (sr);
  if (NULL != sr->download)
  {
    sr->download->search = NULL;
    sr->download->top =
        GNUNET_FS_make_top (sr->download->h,
                            &GNUNET_FS_download_signal_suspend_,
                            sr->download);
    if (NULL != sr->download->serialization)
    {
      GNUNET_FS_remove_sync_file_ (sc->h,
                                   GNUNET_FS_SYNC_PATH_CHILD_DOWNLOAD,
                                   sr->download->serialization);
      GNUNET_free (sr->download->serialization);
      sr->download->serialization = NULL;
    }
    pi.status = GNUNET_FS_STATUS_DOWNLOAD_LOST_PARENT;
    GNUNET_FS_download_make_status_ (&pi, sr->download);
    GNUNET_FS_download_sync_ (sr->download);
    sr->download = NULL;
  }
  if (0 != sr->mandatory_missing)
  {
    /* client is unaware of search result as
       it does not match required keywords */
    GNUNET_break (NULL == sr->client_info);
    return GNUNET_OK;
  }
  pi.status = GNUNET_FS_STATUS_SEARCH_RESULT_STOPPED;
  pi.value.search.specifics.result_stopped.cctx = sr->client_info;
  pi.value.search.specifics.result_stopped.meta = sr->meta;
  pi.value.search.specifics.result_stopped.uri = sr->uri;
  sr->client_info = GNUNET_FS_search_make_status_ (&pi, sr->h, sc);
  return GNUNET_OK;
}


/**
 * Free the given search result.
 *
 * @param cls the global FS handle
 * @param key the key for the search result (unused)
 * @param value the search result to free
 * @return #GNUNET_OK
 */
static int
search_result_free (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct GNUNET_FS_SearchResult *sr = value;

  if (NULL != sr->update_search)
  {
    GNUNET_FS_search_stop (sr->update_search);
    GNUNET_assert (NULL == sr->update_search);
  }
  GNUNET_break (NULL == sr->probe_ctx);
  GNUNET_break (NULL == sr->probe_cancel_task);
  GNUNET_break (NULL == sr->client_info);
  GNUNET_free_non_null (sr->serialization);
  GNUNET_FS_uri_destroy (sr->uri);
  GNUNET_CONTAINER_meta_data_destroy (sr->meta);
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
  sc->client_info = GNUNET_FS_search_make_status_ (&pi, sc->h, sc);
  GNUNET_break (NULL == sc->client_info);
  if (NULL != sc->task)
  {
    GNUNET_SCHEDULER_cancel (sc->task);
    sc->task = NULL;
  }
  if (NULL != sc->mq)
  {
    GNUNET_MQ_destroy (sc->mq);
    sc->mq = NULL;
  }
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
