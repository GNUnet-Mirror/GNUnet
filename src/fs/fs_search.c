/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 */

#include "platform.h"
#include "gnunet_fs_service.h"
#include "fs.h"

#define DEBUG_SEARCH GNUNET_YES


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
  return NULL;
}


/**
 * Pause search.  
 *
 * @param sc context for the search that should be paused
 */
void 
GNUNET_FS_search_pause (struct GNUNET_FS_SearchContext *sc)
{
}

/**
 * Continue paused search.
 *
 * @param sc context for the search that should be resumed
 */
void 
GNUNET_FS_search_continue (struct GNUNET_FS_SearchContext *sc)
{
}


/**
 * Stop search for content.
 *
 * @param sc context for the search that should be stopped
 */
void 
GNUNET_FS_search_stop (struct GNUNET_FS_SearchContext *sc)
{
}




#if 0

/**
 * Context for an individual search.  Followed
 *  by keyCount keys of type GNUNET_HashCode.
 */
struct PendingSearch
{
  struct PendingSearch *next;

  struct GNUNET_ECRS_SearchContext *context;

  /**
   * The key (for decryption)
   */
  GNUNET_HashCode decryptKey;

  unsigned int keyCount;

  /**
   * What type of query is it?
   */
  unsigned int type;

};

/**
 * Context for search operation.
 */
struct GNUNET_ECRS_SearchContext
{
  /**
   * Time when the cron-job was first started.
   */
  GNUNET_CronTime start;

  /**
   * What is the global timeout?
   */
  GNUNET_CronTime timeout;

  /**
   * Search context
   */
  struct GNUNET_FS_SearchContext *sctx;

  /**
   * Active searches.
   */
  struct PendingSearch *queries;

  GNUNET_ECRS_SearchResultProcessor spcb;

  void *spcbClosure;

  struct GNUNET_GE_Context *ectx;

  struct GNUNET_GC_Configuration *cfg;

  int aborted;

  int my_sctx;

  unsigned int anonymityLevel;

};

static int
receive_response_callback (const GNUNET_HashCode * key,
                           const GNUNET_DatastoreValue * value,
                           void *cls, unsigned long long uid);

/**
 * Add a query to the SQC.
 */
static void
add_search (unsigned int type,
            unsigned int keyCount,
            const GNUNET_HashCode * keys,
            const GNUNET_HashCode * dkey,
            struct GNUNET_ECRS_SearchContext *sqc)
{
  struct PendingSearch *ps;

  ps =
    GNUNET_malloc (sizeof (struct PendingSearch) +
                   sizeof (GNUNET_HashCode) * keyCount);
  ps->type = type;
  ps->keyCount = keyCount;
  memcpy (&ps[1], keys, sizeof (GNUNET_HashCode) * keyCount);
  ps->decryptKey = *dkey;
  ps->context = sqc;
  ps->next = sqc->queries;
  sqc->queries = ps;
  GNUNET_FS_start_search (sqc->sctx,
                          NULL,
                          type,
                          keyCount,
                          keys,
                          sqc->anonymityLevel,
                          &receive_response_callback, ps);
}

/**
 * Add the query that corresponds to the given URI
 * to the SQC.
 */
static void
add_search_for_uri (const struct GNUNET_ECRS_URI *uri,
                    struct GNUNET_ECRS_SearchContext *sqc)
{
  struct GNUNET_GE_Context *ectx = sqc->ectx;

  switch (uri->type)
    {
    case chk:
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("CHK URI not allowed for search.\n"));
      break;
    case sks:
      {
        GNUNET_HashCode keys[2];
        GNUNET_HashCode hk;     /* hk = GNUNET_hash(identifier) */
        GNUNET_HashCode hk2;    /* hk2 = GNUNET_hash(hk) */

        GNUNET_hash (uri->data.sks.identifier,
                     strlen (uri->data.sks.identifier), &hk);
        GNUNET_hash (&hk, sizeof (GNUNET_HashCode), &hk2);
        /* compute routing key keys[0] = H(key) ^ namespace */
        GNUNET_hash_xor (&hk2, &uri->data.sks.namespace, &keys[0]);
        keys[1] = uri->data.sks.namespace;
        add_search (GNUNET_ECRS_BLOCKTYPE_SIGNED, 2, &keys[0], &hk, sqc);
        break;
      }
    case ksk:
      {
        GNUNET_HashCode hc;
        GNUNET_HashCode query;
        struct GNUNET_RSA_PrivateKey *pk;
        GNUNET_RSA_PublicKey pub;
        int i;
        const char *keyword;

#if DEBUG_SEARCH
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                       "Computing queries (this may take a while).\n");
#endif
        for (i = 0; i < uri->data.ksk.keywordCount; i++)
          {
            keyword = uri->data.ksk.keywords[i];
            /* first character of the keyword is
               "+" or " " to indicate mandatory or
               not -- ignore for hashing! */
            GNUNET_hash (&keyword[1], strlen (&keyword[1]), &hc);
            pk = GNUNET_RSA_create_key_from_hash (&hc);
            GNUNET_RSA_get_public_key (pk, &pub);
            GNUNET_hash (&pub, sizeof (GNUNET_RSA_PublicKey), &query);
            add_search (GNUNET_ECRS_BLOCKTYPE_ANY,      /* GNUNET_ECRS_BLOCKTYPE_KEYWORD, GNUNET_ECRS_BLOCKTYPE_NAMESPACE or GNUNET_ECRS_BLOCKTYPE_KEYWORD_FOR_NAMESPACE ok */
                        1, &query, &hc, sqc);
            GNUNET_RSA_free_key (pk);
          }
#if DEBUG_SEARCH
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                       "Queries ready.\n");
#endif
        break;
      }
    case loc:
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("LOC URI not allowed for search.\n"));
      break;
    default:
      GNUNET_GE_BREAK (ectx, 0);
      /* unknown URI type */
      break;
    }
}

/**
 * We found an GNUNET_EC_SBlock.  Decode the meta-data and call
 * the callback of the SQC with the root-URI for the namespace,
 * together with the namespace advertisement.  Also, if this is
 * a result with updates, automatically start the search for
 * updates.
 */
static int
process_sblock_result (const GNUNET_EC_SBlock * sb,
                       const GNUNET_HashCode * key,
                       unsigned int size,
                       struct GNUNET_ECRS_SearchContext *sqc)
{
  static GNUNET_HashCode allZeros;
  struct GNUNET_GE_Context *ectx = sqc->ectx;
  GNUNET_ECRS_FileInfo fi;
  URI updateURI;
  int ret;
  const char *id;
  const char *uris;
  unsigned int len;
  unsigned int off;
  int isRoot;

  len = size - sizeof (GNUNET_EC_SBlock);
  off = GNUNET_string_buffer_tokenize ((const char *) &sb[1],
                                       len, 2, &id, &uris);
  if (off == 0)
    {
      GNUNET_GE_BREAK_OP (ectx, 0);     /* sblock malformed */
      return GNUNET_SYSERR;
    }
  fi.meta = GNUNET_meta_data_deserialize (ectx, &id[off], len - off);
  if (fi.meta == NULL)
    {
      GNUNET_GE_BREAK_OP (ectx, 0);     /* sblock malformed */
      return GNUNET_SYSERR;
    }
  isRoot = 0 == memcmp (&sb->identifier, &allZeros, sizeof (GNUNET_HashCode));
  fi.uri = GNUNET_ECRS_string_to_uri (ectx, uris);
  if ((isRoot) && (fi.uri == NULL))
    {
      fi.uri = GNUNET_malloc (sizeof (URI));
      fi.uri->type = sks;
      GNUNET_hash (&sb->subspace,
                   sizeof (GNUNET_RSA_PublicKey),
                   &fi.uri->data.sks.namespace);
      fi.uri->data.sks.identifier = GNUNET_strdup (id);
    }
  if (fi.uri == NULL)
    {
      GNUNET_GE_BREAK_OP (ectx, 0);     /* sblock malformed */
      GNUNET_meta_data_destroy (fi.meta);
      return GNUNET_SYSERR;
    }
  if (sqc->spcb != NULL)
    {
      ret = sqc->spcb (&fi, key, isRoot, sqc->spcbClosure);
      if (ret == GNUNET_SYSERR)
        sqc->aborted = GNUNET_YES;
    }
  else
    ret = GNUNET_OK;
  if ((strlen (id) > 0) && (strlen (uris) > 0))
    {
      updateURI.type = sks;
      GNUNET_hash (&sb->subspace,
                   sizeof (GNUNET_RSA_PublicKey),
                   &updateURI.data.sks.namespace);
      updateURI.data.sks.identifier = GNUNET_strdup (id);
      add_search_for_uri (&updateURI, sqc);
      GNUNET_free (updateURI.data.sks.identifier);
    }
  GNUNET_meta_data_destroy (fi.meta);
  GNUNET_ECRS_uri_destroy (fi.uri);
  return ret;
}

/**
 * Process replies received in response to our
 * queries.  Verifies, decrypts and passes valid
 * replies to the callback.
 *
 * @return GNUNET_SYSERR if the entry is malformed
 */
static int
receive_response_callback (const GNUNET_HashCode * key,
                           const GNUNET_DatastoreValue * value,
                           void *cls, unsigned long long uid)
{
  struct PendingSearch *ps = cls;
  struct GNUNET_ECRS_SearchContext *sqc = ps->context;
  struct GNUNET_GE_Context *ectx = sqc->ectx;
  unsigned int type;
  GNUNET_ECRS_FileInfo fi;
  unsigned int size;
  int ret;
  GNUNET_HashCode query;
  GNUNET_CronTime expiration;

  expiration = GNUNET_ntohll (value->expiration_time);
  if (expiration < GNUNET_get_time ())
    return GNUNET_OK;           /* expired, ignore! */
  type = ntohl (value->type);
  size = ntohl (value->size) - sizeof (GNUNET_DatastoreValue);
#if DEBUG_SEARCH
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Search received reply of type %u and size %u.\n", type,
                 size);
#endif
  if (GNUNET_OK !=
      GNUNET_EC_file_block_check_and_get_query (size,
                                                (const GNUNET_EC_DBlock *)
                                                &value[1], GNUNET_YES,
                                                &query))
    {
      GNUNET_GE_BREAK_OP (NULL, 0);
      return GNUNET_SYSERR;
    }
  if (!((0 == memcmp (&query,
                      (GNUNET_HashCode *) & ps[1], sizeof (GNUNET_HashCode)))
        && ((ps->type == type) || (ps->type == GNUNET_ECRS_BLOCKTYPE_ANY))
        && (GNUNET_YES ==
            GNUNET_EC_is_block_applicable_for_query (type, size,
                                                     (const GNUNET_EC_DBlock
                                                      *) &value[1], &query,
                                                     ps->keyCount,
                                                     (GNUNET_HashCode *) &
                                                     ps[1]))))
    {
      return GNUNET_OK;         /* not a match */
    }

  switch (type)
    {
    case GNUNET_ECRS_BLOCKTYPE_KEYWORD:
      {
        GNUNET_EC_KBlock *kb;
        const char *dstURI;
#if DEBUG_SEARCH
        GNUNET_EncName enc;
#endif
        int j;

        if (size < sizeof (GNUNET_EC_KBlock))
          {
            GNUNET_GE_BREAK_OP (NULL, 0);
            return GNUNET_SYSERR;
          }
        kb = GNUNET_malloc (size);
        memcpy (kb, &value[1], size);
#if DEBUG_SEARCH
        IF_GELOG (ectx,
                  GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                  GNUNET_GE_USER, GNUNET_hash_to_enc (&ps->decryptKey, &enc));
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                       GNUNET_GE_USER,
                       "Decrypting KBlock with key %s.\n", &enc);
#endif
        GNUNET_ECRS_decryptInPlace (&ps->decryptKey,
                                    &kb[1], size - sizeof (GNUNET_EC_KBlock));
        j = sizeof (GNUNET_EC_KBlock);
        while ((j < size) && (((const char *) kb)[j] != '\0'))
          j++;
        if (j == size)
          {
            GNUNET_GE_BREAK_OP (ectx, 0);       /* kblock malformed */
            GNUNET_free (kb);
            return GNUNET_SYSERR;
          }
        dstURI = (const char *) &kb[1];
        j++;
        fi.meta = GNUNET_meta_data_deserialize (ectx,
                                                &((const char *)
                                                  kb)[j], size - j);
        if (fi.meta == NULL)
          {
            GNUNET_GE_BREAK_OP (ectx, 0);       /* kblock malformed */
            GNUNET_free (kb);
            return GNUNET_SYSERR;
          }
        fi.uri = GNUNET_ECRS_string_to_uri (ectx, dstURI);
        if (fi.uri == NULL)
          {
            GNUNET_GE_BREAK_OP (ectx, 0);       /* kblock malformed */
            GNUNET_meta_data_destroy (fi.meta);
            GNUNET_free (kb);
            return GNUNET_SYSERR;
          }
        if (sqc->spcb != NULL)
          {
            ret = sqc->spcb (&fi,
                             &ps->decryptKey, GNUNET_NO, sqc->spcbClosure);
            if (ret == GNUNET_SYSERR)
              sqc->aborted = GNUNET_YES;
          }
        else
          ret = GNUNET_OK;
        GNUNET_ECRS_uri_destroy (fi.uri);
        GNUNET_meta_data_destroy (fi.meta);
        GNUNET_free (kb);
        return ret;
      }
    case GNUNET_ECRS_BLOCKTYPE_SIGNED:
      {
        GNUNET_EC_SBlock *sb;
        int ret;

        if (size < sizeof (GNUNET_EC_SBlock))
          {
            GNUNET_GE_BREAK_OP (ectx, 0);       /* sblock malformed */
            return GNUNET_SYSERR;
          }
        sb = GNUNET_malloc (size);
        memcpy (sb, &value[1], size);
        GNUNET_ECRS_decryptInPlace (&ps->decryptKey,
                                    &sb[1], size - sizeof (GNUNET_EC_SBlock));
        ret = process_sblock_result (sb, &ps->decryptKey, size, sqc);
        GNUNET_free (sb);
        return ret;
      }
    case GNUNET_ECRS_BLOCKTYPE_KEYWORD_SIGNED:
      {
        GNUNET_EC_KSBlock *kb;
        int ret;

        if (size < sizeof (GNUNET_EC_KSBlock))
          {
            GNUNET_GE_BREAK_OP (ectx, 0);       /* ksblock malformed */
            return GNUNET_SYSERR;
          }
        kb = GNUNET_malloc (size);
        memcpy (kb, &value[1], size);
        GNUNET_ECRS_decryptInPlace (&ps->decryptKey,
                                    &kb->sblock,
                                    size - sizeof (GNUNET_EC_KBlock) -
                                    sizeof (unsigned int));
        ret =
          process_sblock_result (&kb->sblock, &ps->decryptKey,
                                 size - sizeof (GNUNET_EC_KSBlock) +
                                 sizeof (GNUNET_EC_SBlock), sqc);
        GNUNET_free (kb);
        return ret;
      }
    default:
      GNUNET_GE_BREAK_OP (ectx, 0);
      break;
    }                           /* end switch */
  return GNUNET_OK;
}

/**
 * Start search for content.
 *
 * @param uri specifies the search parameters
 * @param uri set to the URI of the uploaded file
 */
struct GNUNET_ECRS_SearchContext *
GNUNET_ECRS_search_start (struct GNUNET_GE_Context *ectx,
                          struct GNUNET_GC_Configuration *cfg,
                          struct GNUNET_FS_SearchContext *sc,
                          const struct GNUNET_ECRS_URI *uri,
                          unsigned int anonymityLevel,
                          GNUNET_ECRS_SearchResultProcessor spcb,
                          void *spcbClosure)
{
  struct GNUNET_ECRS_SearchContext *ctx;

  if (GNUNET_YES == GNUNET_ECRS_uri_test_ksk (uri))
    {
      if (1 != GNUNET_ECRS_uri_get_keyword_count_from_ksk (uri))
        return NULL;
    }
  else
    {
      if (GNUNET_YES != GNUNET_ECRS_uri_test_sks (uri))
        return NULL;
    }
  ctx = GNUNET_malloc (sizeof (struct GNUNET_ECRS_SearchContext));
  ctx->start = GNUNET_get_time ();
  ctx->anonymityLevel = anonymityLevel;
  ctx->ectx = ectx;
  ctx->cfg = cfg;
  ctx->queries = NULL;
  ctx->spcb = spcb;
  ctx->spcbClosure = spcbClosure;
  ctx->aborted = GNUNET_NO;
  ctx->sctx = sc == NULL ? GNUNET_FS_create_search_context (ectx, cfg) : sc;
  if (ctx->sctx == NULL)
    {
      GNUNET_free (ctx);
      return NULL;
    }
  ctx->my_sctx = (sc == NULL);
  add_search_for_uri (uri, ctx);
  return ctx;
}

/**
 * Stop search for content.
 *
 * @param uri specifies the search parameters
 * @param uri set to the URI of the uploaded file
 */
void
GNUNET_ECRS_search_stop (struct GNUNET_ECRS_SearchContext *ctx)
{
  struct PendingSearch *pos;

  while (ctx->queries != NULL)
    {
      pos = ctx->queries;
      ctx->queries = pos->next;
      if (!ctx->my_sctx)
        GNUNET_FS_stop_search (ctx->sctx, &receive_response_callback, pos);
      GNUNET_free (pos);
    }
  if (ctx->my_sctx)
    GNUNET_FS_destroy_search_context (ctx->sctx);
  GNUNET_free (ctx);
}

/**
 * Search for content.
 *
 * @param timeout how long to wait (relative)
 * @param uri specifies the search parameters
 * @param uri set to the URI of the uploaded file
 */
int
GNUNET_ECRS_search (struct GNUNET_GE_Context *ectx,
                    struct GNUNET_GC_Configuration *cfg,
                    const struct GNUNET_ECRS_URI *uri,
                    unsigned int anonymityLevel,
                    GNUNET_ECRS_SearchResultProcessor spcb,
                    void *spcbClosure, GNUNET_ECRS_TestTerminate tt,
                    void *ttClosure)
{
  struct GNUNET_ECRS_SearchContext *ctx;

  ctx =
    GNUNET_ECRS_search_start (ectx, cfg, NULL,
                              uri, anonymityLevel, spcb, spcbClosure);
  if (ctx == NULL)
    return GNUNET_SYSERR;
  while (((NULL == tt) || (GNUNET_OK == tt (ttClosure)))
         && (GNUNET_NO == GNUNET_shutdown_test ())
         && (ctx->aborted == GNUNET_NO))
    GNUNET_thread_sleep (100 * GNUNET_CRON_MILLISECONDS);
  GNUNET_ECRS_search_stop (ctx);
  return GNUNET_OK;
}

#endif

/* end of fs_search.c */
