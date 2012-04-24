/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-service-fs_lc.c
 * @brief API to handle 'local clients'
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet-service-fs.h"
#include "gnunet-service-fs_lc.h"
#include "gnunet-service-fs_cp.h"
#include "gnunet-service-fs_pr.h"


/**
 * Doubly-linked list of requests we are performing
 * on behalf of the same client.
 */
struct ClientRequest
{

  /**
   * This is a doubly-linked list.
   */
  struct ClientRequest *next;

  /**
   * This is a doubly-linked list.
   */
  struct ClientRequest *prev;

  /**
   * Request this entry represents.
   */
  struct GSF_PendingRequest *pr;

  /**
   * Client list this request belongs to.
   */
  struct GSF_LocalClient *lc;

  /**
   * Task scheduled to destroy the request.
   */
  GNUNET_SCHEDULER_TaskIdentifier kill_task;

};


/**
 * Replies to be transmitted to the client.  The actual
 * response message is allocated after this struct.
 */
struct ClientResponse
{
  /**
   * This is a doubly-linked list.
   */
  struct ClientResponse *next;

  /**
   * This is a doubly-linked list.
   */
  struct ClientResponse *prev;

  /**
   * Client list entry this response belongs to.
   */
  struct GSF_LocalClient *lc;

  /**
   * Number of bytes in the response.
   */
  size_t msize;
};


/**
 * A local client.
 */
struct GSF_LocalClient
{

  /**
   * We keep clients in a DLL.
   */
  struct GSF_LocalClient *next;

  /**
   * We keep clients in a DLL.
   */
  struct GSF_LocalClient *prev;

  /**
   * ID of the client.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Head of list of requests performed on behalf
   * of this client right now.
   */
  struct ClientRequest *cr_head;

  /**
   * Tail of list of requests performed on behalf
   * of this client right now.
   */
  struct ClientRequest *cr_tail;

  /**
   * Head of linked list of responses.
   */
  struct ClientResponse *res_head;

  /**
   * Tail of linked list of responses.
   */
  struct ClientResponse *res_tail;

  /**
   * Context for sending replies.
   */
  struct GNUNET_SERVER_TransmitHandle *th;

};


/**
 * Head of linked list of our local clients.
 */
static struct GSF_LocalClient *client_head;


/**
 * Head of linked list of our local clients.
 */
static struct GSF_LocalClient *client_tail;


/**
 * Look up a local client record or create one if it
 * doesn't exist yet.
 *
 * @param client handle of the client
 * @return handle to local client entry
 */
struct GSF_LocalClient *
GSF_local_client_lookup_ (struct GNUNET_SERVER_Client *client)
{
  struct GSF_LocalClient *pos;

  pos = client_head;
  while ((pos != NULL) && (pos->client != client))
    pos = pos->next;
  if (pos != NULL)
    return pos;
  pos = GNUNET_malloc (sizeof (struct GSF_LocalClient));
  pos->client = client;
  GNUNET_CONTAINER_DLL_insert (client_head, client_tail, pos);
  return pos;
}


/**
 * Free the given client request.
 *
 * @param cls the client request to free
 * @param tc task context
 */
static void
client_request_destroy (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ClientRequest *cr = cls;
  struct GSF_LocalClient *lc;

  cr->kill_task = GNUNET_SCHEDULER_NO_TASK;
  lc = cr->lc;
  GNUNET_CONTAINER_DLL_remove (lc->cr_head, lc->cr_tail, cr);
  GSF_pending_request_cancel_ (cr->pr, GNUNET_NO);
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop ("# client searches active"), -1,
                            GNUNET_NO);
  GNUNET_free (cr);
}


/**
 * Handle a reply to a pending request.  Also called if a request
 * expires (then with data == NULL).  The handler may be called
 * many times (depending on the request type), but will not be
 * called during or after a call to GSF_pending_request_cancel
 * and will also not be called anymore after a call signalling
 * expiration.
 *
 * @param cls user-specified closure
 * @param eval evaluation of the result
 * @param pr handle to the original pending request
 * @param reply_anonymity_level anonymity level for the reply, UINT32_MAX for "unknown"
 * @param expiration when does 'data' expire?
 * @param last_transmission when was the last time we've tried to download this block? (FOREVER if unknown)
 * @param type type of the block
 * @param data response data, NULL on request expiration
 * @param data_len number of bytes in data
 */
static void
client_response_handler (void *cls, enum GNUNET_BLOCK_EvaluationResult eval,
                         struct GSF_PendingRequest *pr,
                         uint32_t reply_anonymity_level,
                         struct GNUNET_TIME_Absolute expiration,
                         struct GNUNET_TIME_Absolute last_transmission,
                         enum GNUNET_BLOCK_Type type, const void *data,
                         size_t data_len)
{
  struct ClientRequest *cr = cls;
  struct GSF_LocalClient *lc;
  struct ClientPutMessage *pm;
  const struct GSF_PendingRequestData *prd;
  size_t msize;

  if (NULL == data)
  {
    /* ugh, request 'timed out' -- how can this be? */
    GNUNET_break (0);
    return;
  }
  prd = GSF_pending_request_get_data_ (pr);
  GNUNET_break (type != GNUNET_BLOCK_TYPE_ANY);
  if ((prd->type != type) && (prd->type != GNUNET_BLOCK_TYPE_ANY))
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop
                            ("# replies received for local clients"), 1,
                            GNUNET_NO);
  GNUNET_assert (pr == cr->pr);
  lc = cr->lc;
  msize = sizeof (struct ClientPutMessage) + data_len;
  {
    char buf[msize] GNUNET_ALIGN;

    pm = (struct ClientPutMessage *) buf;
    pm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_PUT);
    pm->header.size = htons (msize);
    pm->type = htonl (type);
    pm->expiration = GNUNET_TIME_absolute_hton (expiration);
    pm->last_transmission = GNUNET_TIME_absolute_hton (last_transmission);
    memcpy (&pm[1], data, data_len);
    GSF_local_client_transmit_ (lc, &pm->header);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Queued reply to query `%s' for local client\n",
              GNUNET_h2s (&prd->query), (unsigned int) prd->type);
  if (eval != GNUNET_BLOCK_EVALUATION_OK_LAST)
    return;
  if (GNUNET_SCHEDULER_NO_TASK != cr->kill_task)
    cr->kill_task = GNUNET_SCHEDULER_add_now (&client_request_destroy, cr);
}


/**
 * Handle START_SEARCH-message (search request from local client).
 * Only responsible for creating the request entry itself and setting
 * up reply callback and cancellation on client disconnect.  Does NOT
 * execute the actual request strategy (planning).
 *
 * @param client identification of the client
 * @param message the actual message
 * @param prptr where to store the pending request handle for the request
 * @return GNUNET_YES to start local processing,
 *         GNUNET_NO to not (yet) start local processing,
 *         GNUNET_SYSERR on error
 */
int
GSF_local_client_start_search_handler_ (struct GNUNET_SERVER_Client *client,
                                        const struct GNUNET_MessageHeader
                                        *message,
                                        struct GSF_PendingRequest **prptr)
{
  static GNUNET_HashCode all_zeros;
  const struct SearchMessage *sm;
  struct GSF_LocalClient *lc;
  struct ClientRequest *cr;
  struct GSF_PendingRequestData *prd;
  uint16_t msize;
  unsigned int sc;
  enum GNUNET_BLOCK_Type type;
  enum GSF_PendingRequestOptions options;

  msize = ntohs (message->size);
  if ((msize < sizeof (struct SearchMessage)) ||
      (0 != (msize - sizeof (struct SearchMessage)) % sizeof (GNUNET_HashCode)))
  {
    GNUNET_break (0);
    *prptr = NULL;
    return GNUNET_SYSERR;
  }
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop ("# client searches received"), 1,
                            GNUNET_NO);
  sc = (msize - sizeof (struct SearchMessage)) / sizeof (GNUNET_HashCode);
  sm = (const struct SearchMessage *) message;
  type = ntohl (sm->type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received request for `%s' of type %u from local client\n",
              GNUNET_h2s (&sm->query), (unsigned int) type);
  lc = GSF_local_client_lookup_ (client);
  cr = NULL;
  /* detect duplicate KBLOCK requests */
  if ((type == GNUNET_BLOCK_TYPE_FS_KBLOCK) ||
      (type == GNUNET_BLOCK_TYPE_FS_NBLOCK) || (type == GNUNET_BLOCK_TYPE_ANY))
  {
    cr = lc->cr_head;
    while (cr != NULL)
    {
      prd = GSF_pending_request_get_data_ (cr->pr);
      /* only unify with queries that hae not yet started local processing
	 (SEARCH_MESSAGE_OPTION_CONTINUED was always set) and that have a
	 matching query and type */
      if ((GNUNET_YES != prd->has_started) &&
	  (0 != memcmp (&prd->query, &sm->query, sizeof (GNUNET_HashCode))) &&
          (prd->type == type))
        break;
      cr = cr->next;
    }
  }
  if (cr != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Have existing request, merging content-seen lists.\n");
    GSF_pending_request_update_ (cr->pr, (const GNUNET_HashCode *) &sm[1], sc);
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# client searches updated (merged content seen list)"),
                              1, GNUNET_NO);
  }
  else
  {
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop ("# client searches active"), 1,
                              GNUNET_NO);
    cr = GNUNET_malloc (sizeof (struct ClientRequest));
    cr->lc = lc;
    GNUNET_CONTAINER_DLL_insert (lc->cr_head, lc->cr_tail, cr);
    options = GSF_PRO_LOCAL_REQUEST;
    if (0 != (SEARCH_MESSAGE_OPTION_LOOPBACK_ONLY & ntohl (sm->options)))
      options |= GSF_PRO_LOCAL_ONLY;
    cr->pr = GSF_pending_request_create_ (options, type, &sm->query, (type == GNUNET_BLOCK_TYPE_FS_SBLOCK) ? &sm->target        /* namespace */
                                          : NULL,
                                          (0 !=
                                           memcmp (&sm->target, &all_zeros,
                                                   sizeof (GNUNET_HashCode)))
                                          ? (const struct GNUNET_PeerIdentity *)
                                          &sm->target : NULL, NULL, 0,
                                          0 /* bf */ ,
                                          ntohl (sm->anonymity_level),
                                          0 /* priority */ ,
                                          0 /* ttl */ ,
                                          0 /* sender PID */ ,
                                          0 /* origin PID */ ,
                                          (const GNUNET_HashCode *) &sm[1], sc,
                                          &client_response_handler, cr);
  }
  *prptr = cr->pr;
  return (0 !=
          (SEARCH_MESSAGE_OPTION_CONTINUED & ntohl (sm->options))) ? GNUNET_NO :
      GNUNET_YES;
}


/**
 * Transmit the given message by copying it to the target buffer
 * "buf".  "buf" will be NULL and "size" zero if the socket was closed
 * for writing in the meantime.  In that case, do nothing
 * (the disconnect or shutdown handler will take care of the rest).
 * If we were able to transmit messages and there are still more
 * pending, ask core again for further calls to this function.
 *
 * @param cls closure, pointer to the 'struct GSF_LocalClient'
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_to_client (void *cls, size_t size, void *buf)
{
  struct GSF_LocalClient *lc = cls;
  char *cbuf = buf;
  struct ClientResponse *res;
  size_t msize;

  lc->th = NULL;
  if (NULL == buf)
    return 0;
  msize = 0;
  while ((NULL != (res = lc->res_head)) && (res->msize <= size))
  {
    memcpy (&cbuf[msize], &res[1], res->msize);
    msize += res->msize;
    size -= res->msize;
    GNUNET_CONTAINER_DLL_remove (lc->res_head, lc->res_tail, res);
    GNUNET_free (res);
  }
  if (NULL != res)
    lc->th =
        GNUNET_SERVER_notify_transmit_ready (lc->client, res->msize,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             &transmit_to_client, lc);
  return msize;
}


/**
 * Transmit a message to the given local client as soon as possible.
 * If the client disconnects before transmission, the message is
 * simply discarded.
 *
 * @param lc recipient
 * @param msg message to transmit to client
 */
void
GSF_local_client_transmit_ (struct GSF_LocalClient *lc,
                            const struct GNUNET_MessageHeader *msg)
{
  struct ClientResponse *res;
  size_t msize;

  msize = ntohs (msg->size);
  res = GNUNET_malloc (sizeof (struct ClientResponse) + msize);
  res->lc = lc;
  res->msize = msize;
  memcpy (&res[1], msg, msize);
  GNUNET_CONTAINER_DLL_insert_tail (lc->res_head, lc->res_tail, res);
  if (NULL == lc->th)
    lc->th =
        GNUNET_SERVER_notify_transmit_ready (lc->client, msize,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             &transmit_to_client, lc);
}


/**
 * A client disconnected from us.  Tear down the local client
 * record.
 *
 * @param cls unused
 * @param client handle of the client
 */
void
GSF_client_disconnect_handler_ (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct GSF_LocalClient *pos;
  struct ClientRequest *cr;
  struct ClientResponse *res;

  pos = client_head;
  while ((pos != NULL) && (pos->client != client))
    pos = pos->next;
  if (pos == NULL)
    return;
  while (NULL != (cr = pos->cr_head))
  {
    GNUNET_CONTAINER_DLL_remove (pos->cr_head, pos->cr_tail, cr);
    GSF_pending_request_cancel_ (cr->pr, GNUNET_NO);
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop ("# client searches active"), -1,
                              GNUNET_NO);
    if (GNUNET_SCHEDULER_NO_TASK != cr->kill_task)
      GNUNET_SCHEDULER_cancel (cr->kill_task);
    GNUNET_free (cr);
  }
  while (NULL != (res = pos->res_head))
  {
    GNUNET_CONTAINER_DLL_remove (pos->res_head, pos->res_tail, res);
    GNUNET_free (res);
  }
  if (pos->th != NULL)
  {
    GNUNET_SERVER_notify_transmit_ready_cancel (pos->th);
    pos->th = NULL;
  }
  GSF_handle_local_client_disconnect_ (pos);
  GNUNET_CONTAINER_DLL_remove (client_head, client_tail, pos);
  GNUNET_free (pos);
}


/* end of gnunet-service-fs_lc.c */
