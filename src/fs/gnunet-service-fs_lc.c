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
 * @brief API to handle 'connected peers'
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet-service-fs_lc.h"


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
  struct GNUNET_CONNECTION_TransmitHandle *th;

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
  while ( (pos != NULL) &&
	  (pos->client != client) )
    pos = pos->next;
  if (pos != NULL)
    return pos;
  pos = GNUNET_malloc (sizeof (struct GSF_LocalClient));
  pos->client = client;
  GNUNET_CONTAINER_DLL_insert (client_head,
			       client_tail,
			       pos);
  return pos;
}


/**
 * Handle START_SEARCH-message (search request from local client).
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
void
GSF_local_client_start_search_handler_ (void *cls,
					struct GNUNET_SERVER_Client *client,
					const struct GNUNET_MessageHeader *message)
{
  static GNUNET_HashCode all_zeros;
  const struct SearchMessage *sm;
  struct GSF_LocalClient *lc;
  struct ClientRequest *cr;
  struct GSF_PendingRequest *pr;
  uint16_t msize;
  unsigned int sc;
  enum GNUNET_BLOCK_Type type;
  enum GSF_PendingRequestOptions options;

  msize = ntohs (message->size);
  if ( (msize < sizeof (struct SearchMessage)) ||
       (0 != (msize - sizeof (struct SearchMessage)) % sizeof (GNUNET_HashCode)) )
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client,
				  GNUNET_SYSERR);
      return;
    }
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# client searches received"),
			    1,
			    GNUNET_NO);
  sc = (msize - sizeof (struct SearchMessage)) / sizeof (GNUNET_HashCode);
  sm = (const struct SearchMessage*) message;
  type = ntohl (sm->type);
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received request for `%s' of type %u from local client\n",
	      GNUNET_h2s (&sm->query),
	      (unsigned int) type);
#endif
  lc = GSF_local_client_lookup_ (client);


  /* detect duplicate KBLOCK requests */
  if ( (type == GNUNET_BLOCK_TYPE_FS_KBLOCK) ||
       (type == GNUNET_BLOCK_TYPE_FS_NBLOCK) ||
       (type == GNUNET_BLOCK_TYPE_ANY) )
    {
      cr = lc->cr_head;
      while ( (cl != NULL) &&
	      ( (0 != memcmp (GSF_pending_request_get_query_ (cr->pr),
			      &sm->query,
			      sizeof (GNUNET_HashCode))) ||
		(GSF_pending_request_get_type_ (cr->pr) != type) ) )
	cr = cr->next;
      if (crl != NULL) 	
	{ 
#if DEBUG_FS
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Have existing request, merging content-seen lists.\n");
#endif
	  GSF_pending_request_update_ (cr->pr,
				       &sm[1],
				       sc);
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# client searches updated (merged content seen list)"),
				    1,
				    GNUNET_NO);
	  GNUNET_SERVER_receive_done (client,
				      GNUNET_OK);
	  return;
	}
    }

  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# client searches active"),
			    1,
			    GNUNET_NO);
  cr = GNUNET_malloc (sizeof (struct ClientRequest));
  cr->lc = lc;
  GNUNET_CONTAINER_DLL_insert (lc->cr_head,
			       lc->cr_tail,
			       cr);
  options = GSF_PRO_LOCAL_REQUEST;  
  if (0 != (1 & ntohl (sm->options)))
    options |= GSF_PRO_LOCAL_ONLY;
  cr->pr = GSF_pending_request_create (options,
				       
				       type,
				       &sm->query,
				       (type == GNUNET_BLOCK_TYPE_SBLOCK)
				       ? &sm->target /* namespace */
				       : NULL,
				       (0 != memcmp (&sm->target,
						     &all_zeros,
						     sizeof (GNUNET_HashCode)))
				       ? &sm->target,
				       : NULL,
				       NULL /* bf */, 0 /* mingle */,
				       ntohl (sm->anonymity_level),
				       0 /* priority */,
				       &sm[1], sc,
				       &client_response_handler,
				       cr);
  // FIXME: start local processing and/or P2P processing?
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
transmit_to_client (void *cls,
		    size_t size,
		    void *buf)
{
  struct GSF_LocalClient *lc = cls;
  char *cbuf = buf;
  struct ClientResponse *res;
  size_t msize;
  
  cl->th = NULL;
  if (NULL == buf)
    return 0;
  msize = 0;
  while ( (NULL != (res = lc->res_head) ) &&
	  (res->msize <= size) )
    {
      memcpy (&cbuf[msize], &res[1], res->msize);
      msize += res->msize;
      size -= res->msize;
      GNUNET_CONTAINER_DLL_remove (cl->res_head,
				   cl->res_tail,
				   res);
      GNUNET_free (res);
    }
  if (NULL != res)
    lc->th = GNUNET_SERVER_notify_transmit_ready (lc->client,
						  res->msize,
						  GNUNET_TIME_UNIT_FOREVER_REL,
						  &transmit_to_client,
						  lc);
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
  GNUNET_CONTAINER_DLL_insert_tail (lc->res_head,
				    lc->res_tail,
				    res);
  if (NULL == lc->tc)
    lc->tc = GNUNET_CLIENT_notify_transmit_ready (lc->client,
						  msize,
						  GNUNET_TIME_UNIT_FOREVER_REL,
						  GNUNET_NO,
						  &transmit_to_client,
						  lc);
}


/**
 * A client disconnected from us.  Tear down the local client
 * record.
 *
 * @param cls unused
 * @param client handle of the client
 */
void
GSF_client_disconnect_handler_ (void *cls,
				const struct GNUNET_SERVER_Client *client)
{
  struct GSF_LocalClient *pos;
  struct DisconnectCallback *dc;
  struct ClientRequest *cr;
  struct ClientResponse *res;

  pos = client_head;
  while ( (pos != NULL) &&
	  (pos->client != client) )
    pos = pos->next;
  if (pos == NULL)
    return pos;
  while (NULL != (cr = pos->cr_head))
    {      
      GNUNET_CONTAINER_DLL_remove (pos->cr_head,
				   pos->cr_tail,
				   cr);
      GSF_pending_request_cancel_ (cr->pr);
      GNUNET_free (cr);
    }
  while (NULL != (res = pos->res_head))
    {
      GNUNET_CONTAINER_DLL_remove (pos->res_head,
				   pos->res_tail,
				   res);
      GNUNET_free (res);
    }
  if (pos->th != NULL)
    {
      GNUNET_CONNECTION_notify_transmit_ready_cancel (pos->th);
      pos->th = NULL;
    }
  GSF_handle_local_client_disconnect_ (pos);
  GNUNET_free (pos);
}


/* end of gnunet-service-fs_lc.c */
