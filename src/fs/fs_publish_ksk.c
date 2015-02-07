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
 * @file fs/fs_publish_ksk.c
 * @brief publish a URI under a keyword in GNUnet
 * @see https://gnunet.org/encoding and #2564
 * @author Krista Bennett
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "fs_api.h"
#include "fs_tree.h"
#include "fs_publish_ublock.h"

/**
 * Context for the KSK publication.
 */
struct GNUNET_FS_PublishKskContext
{

  /**
   * Keywords to use.
   */
  struct GNUNET_FS_Uri *ksk_uri;

  /**
   * URI to publish.
   */
  struct GNUNET_FS_Uri *uri;

  /**
   * Metadata to use.
   */
  struct GNUNET_CONTAINER_MetaData *meta;

  /**
   * Global FS context.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * UBlock publishing operation that is active.
   */
  struct GNUNET_FS_PublishUblockContext *uc;

  /**
   * Handle to the datastore, NULL if we are just simulating.
   */
  struct GNUNET_DATASTORE_Handle *dsh;

  /**
   * Current task.
   */
  struct GNUNET_SCHEDULER_Task * ksk_task;

  /**
   * Function to call once we're done.
   */
  GNUNET_FS_PublishContinuation cont;

  /**
   * Closure for cont.
   */
  void *cont_cls;

  /**
   * When should the KBlocks expire?
   */
  struct GNUNET_FS_BlockOptions bo;

  /**
   * Options to use.
   */
  enum GNUNET_FS_PublishOptions options;

  /**
   * Keyword that we are currently processing.
   */
  unsigned int i;

};


/**
 * Continuation of "GNUNET_FS_publish_ksk" that performs
 * the actual publishing operation (iterating over all
 * of the keywords).
 *
 * @param cls closure of type "struct PublishKskContext*"
 * @param tc unused
 */
static void
publish_ksk_cont (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function called by the datastore API with
 * the result from the PUT request.
 *
 * @param cls closure of type "struct GNUNET_FS_PublishKskContext*"
 * @param msg error message (or NULL)
 */
static void
kb_put_cont (void *cls,
	     const char *msg)
{
  struct GNUNET_FS_PublishKskContext *pkc = cls;

  pkc->uc = NULL;
  if (NULL != msg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"KBlock PUT operation failed: %s\n", msg);
    pkc->cont (pkc->cont_cls, NULL, msg);
    GNUNET_FS_publish_ksk_cancel (pkc);
    return;
  }
  pkc->ksk_task = GNUNET_SCHEDULER_add_now (&publish_ksk_cont, pkc);
}


/**
 * Continuation of "GNUNET_FS_publish_ksk" that performs the actual
 * publishing operation (iterating over all of the keywords).
 *
 * @param cls closure of type "struct GNUNET_FS_PublishKskContext*"
 * @param tc unused
 */
static void
publish_ksk_cont (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_PublishKskContext *pkc = cls;
  const char *keyword;

  pkc->ksk_task = NULL;
  if ( (pkc->i == pkc->ksk_uri->data.ksk.keywordCount) ||
       (NULL == pkc->dsh) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "KSK PUT operation complete\n");
    pkc->cont (pkc->cont_cls, pkc->ksk_uri, NULL);
    GNUNET_FS_publish_ksk_cancel (pkc);
    return;
  }
  keyword = pkc->ksk_uri->data.ksk.keywords[pkc->i++];
  pkc->uc = GNUNET_FS_publish_ublock_ (pkc->h,
				       pkc->dsh,
				       keyword + 1 /* skip '+' */,
				       NULL,
				       GNUNET_CRYPTO_ecdsa_key_get_anonymous (),
				       pkc->meta,
				       pkc->uri,
				       &pkc->bo,
				       pkc->options,
				       &kb_put_cont, pkc);
}


/**
 * Publish a CHK under various keywords on GNUnet.
 *
 * @param h handle to the file sharing subsystem
 * @param ksk_uri keywords to use
 * @param meta metadata to use
 * @param uri URI to refer to in the KBlock
 * @param bo per-block options
 * @param options publication options
 * @param cont continuation
 * @param cont_cls closure for cont
 * @return NULL on error ('cont' will still be called)
 */
struct GNUNET_FS_PublishKskContext *
GNUNET_FS_publish_ksk (struct GNUNET_FS_Handle *h,
                       const struct GNUNET_FS_Uri *ksk_uri,
                       const struct GNUNET_CONTAINER_MetaData *meta,
                       const struct GNUNET_FS_Uri *uri,
                       const struct GNUNET_FS_BlockOptions *bo,
                       enum GNUNET_FS_PublishOptions options,
                       GNUNET_FS_PublishContinuation cont, void *cont_cls)
{
  struct GNUNET_FS_PublishKskContext *pkc;

  GNUNET_assert (NULL != uri);
  pkc = GNUNET_new (struct GNUNET_FS_PublishKskContext);
  pkc->h = h;
  pkc->bo = *bo;
  pkc->options = options;
  pkc->cont = cont;
  pkc->cont_cls = cont_cls;
  pkc->meta = GNUNET_CONTAINER_meta_data_duplicate (meta);
  if (0 == (options & GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY))
  {
    pkc->dsh = GNUNET_DATASTORE_connect (h->cfg);
    if (NULL == pkc->dsh)
    {
      cont (cont_cls, NULL, _("Could not connect to datastore."));
      GNUNET_free (pkc);
      return NULL;
    }
  }
  pkc->uri = GNUNET_FS_uri_dup (uri);
  pkc->ksk_uri = GNUNET_FS_uri_dup (ksk_uri);
  pkc->ksk_task = GNUNET_SCHEDULER_add_now (&publish_ksk_cont, pkc);
  return pkc;
}


/**
 * Abort the KSK publishing operation.
 *
 * @param pkc context of the operation to abort.
 */
void
GNUNET_FS_publish_ksk_cancel (struct GNUNET_FS_PublishKskContext *pkc)
{
  if (NULL != pkc->ksk_task)
  {
    GNUNET_SCHEDULER_cancel (pkc->ksk_task);
    pkc->ksk_task = NULL;
  }
  if (NULL != pkc->uc)
  {
    GNUNET_FS_publish_ublock_cancel_ (pkc->uc);
    pkc->uc = NULL;
  }
  if (NULL != pkc->dsh)
  {
    GNUNET_DATASTORE_disconnect (pkc->dsh, GNUNET_NO);
    pkc->dsh = NULL;
  }
  GNUNET_CONTAINER_meta_data_destroy (pkc->meta);
  GNUNET_FS_uri_destroy (pkc->ksk_uri);
  GNUNET_FS_uri_destroy (pkc->uri);
  GNUNET_free (pkc);
}


/* end of fs_publish_ksk.c */
