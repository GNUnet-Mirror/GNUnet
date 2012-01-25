/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file dns/dns_api.c
 * @brief API to access the DNS service. 
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_dns_service.h"
#include "dns.h"


/**
 * Reply to send to service.
 */
struct ReplyQueueEntry
{
  /**
   * Kept in DLL.
   */
  struct ReplyQueueEntry *next;

  /**
   * Kept in DLL.
   */
  struct ReplyQueueEntry *prev;

  /**
   * Message to transmit, allocated at the end of this struct.
   */
  const struct GNUNET_MessageHeader *msg;

};


/**
 * Handle to identify an individual DNS request.
 */
struct GNUNET_DNS_RequestHandle
{

  /**
   * Handle to DNS API.
   */
  struct GNUNET_DNS_Handle *dh;

  /**
   * Stored in network byte order (as for us, it is just a random number).
   */
  uint64_t request_id;

  /**
   * Re-connect counter, to make sure we did not reconnect in the meantime.
   */
  uint32_t generation;

};


/**
 * DNS handle
 */
struct GNUNET_DNS_Handle
{

  /**
   * Connection to DNS service, or NULL.
   */
  struct GNUNET_CLIENT_Connection *dns_connection;

  /**
   * Handle to active transmission request, or NULL.
   */
  struct GNUNET_CLIENT_TransmitHandle *dns_transmit_handle;

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Function to call to get replies.
   */
  GNUNET_DNS_RequestHandler rh;
  
  /**
   * Closure for 'rh'.
   */
  void *rh_cls;

  /**
   * Head of replies to transmit.
   */
  struct ReplyQueueEntry *rq_head;

  /**
   * Tail of replies to transmit.
   */
  struct ReplyQueueEntry *rq_tail;

  /**
   * Task to reconnect to the service.
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

  /**
   * Re-connect counter, to make sure we did not reconnect in the meantime.
   */
  uint32_t generation;
  
  /**
   * Flags for events we care about.
   */
  enum GNUNET_DNS_Flags flags;

  /**
   * Did we start the receive loop yet?
   */
  int in_receive;

  /**
   * Number of GNUNET_DNS_RequestHandles we have outstanding. Must be 0 before
   * we can be disconnected.
   */
  unsigned int pending_requests;
};


/**
 * Add the given reply to our transmission queue and trigger sending if needed.
 *
 * @param dh handle with the connection
 * @param qe reply to queue
 */
static void
queue_reply (struct GNUNET_DNS_Handle *dh,
	     struct ReplyQueueEntry *qe);


/**
 * Reconnect to the DNS service.
 *
 * @param cls handle with the connection to connect
 * @param tc scheduler context (unused)
 */
static void
reconnect (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DNS_Handle *dh = cls;
  struct ReplyQueueEntry *qe;
  struct GNUNET_DNS_Register *msg;

  dh->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  dh->dns_connection = GNUNET_CLIENT_connect ("dns", dh->cfg);
  if (NULL == dh->dns_connection)
    return;
  dh->generation++;
  qe = GNUNET_malloc (sizeof (struct ReplyQueueEntry) +
		      sizeof (struct GNUNET_DNS_Register));
  msg = (struct GNUNET_DNS_Register*) &qe[1];
  qe->msg = &msg->header;
  msg->header.size = htons (sizeof (struct GNUNET_DNS_Register));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_DNS_CLIENT_INIT);
  msg->flags = htonl (dh->flags);
  queue_reply (dh, qe);
}


/**
 * Disconnect from the DNS service.
 *
 * @param dh handle with the connection to disconnect
 */
static void
disconnect (struct GNUNET_DNS_Handle *dh)
{
  struct ReplyQueueEntry *qe;

  if (NULL != dh->dns_transmit_handle)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (dh->dns_transmit_handle);
    dh->dns_transmit_handle = NULL;
  }
  if (NULL != dh->dns_connection)
  {
    GNUNET_CLIENT_disconnect (dh->dns_connection, GNUNET_NO);
    dh->dns_connection = NULL;
  }
  while (NULL != (qe = dh->rq_head))
  {
    GNUNET_CONTAINER_DLL_remove (dh->rq_head,
				 dh->rq_tail,
				 qe);
    GNUNET_free (qe);
  }
  dh->in_receive = GNUNET_NO;
}


/**
 * This receives packets from the DNS service and calls the application to
 * handle it.
 *
 * @param cls the struct GNUNET_DNS_Handle
 * @param msg message from the service (request)
 */
static void
request_handler (void *cls,
		 const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_DNS_Handle *dh = cls;
  const struct GNUNET_DNS_Request *req;
  struct GNUNET_DNS_RequestHandle *rh;
  size_t payload_length;

  /* the service disconnected, reconnect after short wait */
  if (msg == NULL)
  {
    disconnect (dh);
    dh->reconnect_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                      &reconnect, dh);
    return;
  }
  if ( (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_DNS_CLIENT_REQUEST) ||
       (ntohs (msg->size) < sizeof (struct GNUNET_DNS_Request)) )
  {
    /* the service did something strange, reconnect immediately */
    GNUNET_break (0);
    disconnect (dh);
    dh->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect, dh);
    return;
  }
  req = (const struct GNUNET_DNS_Request *) msg;
  GNUNET_break (ntohl (req->reserved) == 0);
  payload_length = ntohs (req->header.size) - sizeof (struct GNUNET_DNS_Request);
  GNUNET_CLIENT_receive (dh->dns_connection, 
			 &request_handler, dh,
                         GNUNET_TIME_UNIT_FOREVER_REL);

  /* finally, pass request to callback for answers */
  rh = GNUNET_malloc (sizeof (struct GNUNET_DNS_RequestHandle));
  rh->dh =dh;
  rh->request_id = req->request_id;
  rh->generation = dh->generation;  
  dh->pending_requests++;
  dh->rh (dh->rh_cls,
	  rh,
	  payload_length,
	  (const char*) &req[1]);
}


/**
 * Callback called by notify_transmit_ready; sends DNS replies
 * to the DNS service.
 *
 * @param cls the struct GNUNET_DNS_Handle
 * @param size number of bytes available in buf
 * @param buf where to copy the message for transmission
 * @return number of bytes copied to buf
 */
static size_t
send_response (void *cls, size_t size, void *buf)
{
  struct GNUNET_DNS_Handle *dh = cls;
  struct ReplyQueueEntry *qe;
  size_t len;
 
  dh->dns_transmit_handle = NULL;
  if (NULL == buf)
  {
    disconnect (dh);
    dh->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				    &reconnect, dh);
    return 0;
  }
  qe = dh->rq_head;
  if (NULL == qe)
    return 0;
  len = ntohs (qe->msg->size);
  if (len > size)
  {   
    dh->dns_transmit_handle =
      GNUNET_CLIENT_notify_transmit_ready (dh->dns_connection,
					   len,
					   GNUNET_TIME_UNIT_FOREVER_REL,
					   GNUNET_NO, 
					   &send_response, dh);
    return 0;
  }
  memcpy (buf, qe->msg, len);
  GNUNET_CONTAINER_DLL_remove (dh->rq_head,
			       dh->rq_tail,
			       qe);
  GNUNET_free (qe);
  if (GNUNET_NO == dh->in_receive)
  {
    dh->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (dh->dns_connection, 
			   &request_handler, dh,
			   GNUNET_TIME_UNIT_FOREVER_REL);
  }
  if (NULL != (qe = dh->rq_head))
  {
    dh->dns_transmit_handle =
      GNUNET_CLIENT_notify_transmit_ready (dh->dns_connection,
					   ntohs (qe->msg->size),
					   GNUNET_TIME_UNIT_FOREVER_REL,
					   GNUNET_NO, 
					   &send_response, dh);
  }
  return len;
} 


/**
 * Add the given reply to our transmission queue and trigger sending if needed.
 *
 * @param dh handle with the connection
 * @param qe reply to queue
 */
static void
queue_reply (struct GNUNET_DNS_Handle *dh,
	     struct ReplyQueueEntry *qe)
{
  if (NULL == dh->dns_connection)        
  {
    GNUNET_free (qe);
    return;
  }
  GNUNET_CONTAINER_DLL_insert_tail (dh->rq_head,
				    dh->rq_tail,
				    qe);
  if (NULL != dh->dns_transmit_handle)
    return;
  /* trigger sending */ 
  dh->dns_transmit_handle =
    GNUNET_CLIENT_notify_transmit_ready (dh->dns_connection,
					 ntohs (dh->rq_head->msg->size),
					 GNUNET_TIME_UNIT_FOREVER_REL,
					 GNUNET_NO, 
					 &send_response, dh);
}


/**
 * If a GNUNET_DNS_RequestHandler calls this function, the request is
 * given to other clients or the global DNS for resolution.  Once a
 * global response has been obtained, the request handler is AGAIN
 * called to give it a chance to observe and modify the response after
 * the "normal" resolution.  It is not legal for the request handler
 * to call this function if a response is already present.
 *
 * @param rh request that should now be forwarded
 */
void
GNUNET_DNS_request_forward (struct GNUNET_DNS_RequestHandle *rh)
{
  struct ReplyQueueEntry *qe;
  struct GNUNET_DNS_Response *resp;

  GNUNET_assert (0 < rh->dh->pending_requests--);
  if (rh->generation != rh->dh->generation)
  {
    GNUNET_free (rh);
    return;
  }
  qe = GNUNET_malloc (sizeof (struct ReplyQueueEntry) +
		      sizeof (struct GNUNET_DNS_Response));
  resp = (struct GNUNET_DNS_Response*) &qe[1];
  qe->msg = &resp->header;
  resp->header.size = htons (sizeof (struct GNUNET_DNS_Response));
  resp->header.type = htons (GNUNET_MESSAGE_TYPE_DNS_CLIENT_RESPONSE);
  resp->drop_flag = htonl (1);
  resp->request_id = rh->request_id;
  queue_reply (rh->dh, qe);
  GNUNET_free (rh);
}


/**
 * If a GNUNET_DNS_RequestHandler calls this function, the request is
 * to be dropped and no response should be generated.
 *
 * @param rh request that should now be dropped
 */
void
GNUNET_DNS_request_drop (struct GNUNET_DNS_RequestHandle *rh)
{
  struct ReplyQueueEntry *qe;
  struct GNUNET_DNS_Response *resp;

  GNUNET_assert (0 < rh->dh->pending_requests--);
  if (rh->generation != rh->dh->generation)
  {
      GNUNET_free (rh);
      return;
  }
  qe = GNUNET_malloc (sizeof (struct ReplyQueueEntry) +
		      sizeof (struct GNUNET_DNS_Response));
  resp = (struct GNUNET_DNS_Response*) &qe[1];
  qe->msg = &resp->header;
  resp->header.size = htons (sizeof (struct GNUNET_DNS_Response));
  resp->header.type = htons (GNUNET_MESSAGE_TYPE_DNS_CLIENT_RESPONSE);
  resp->request_id = rh->request_id;
  resp->drop_flag = htonl (0);
  queue_reply (rh->dh, qe);
  GNUNET_free (rh);
}


/**
 * If a GNUNET_DNS_RequestHandler calls this function, the request is
 * supposed to be answered with the data provided to this call (with
 * the modifications the function might have made).
 *
 * @param rh request that should now be answered
 * @param reply_length size of reply (uint16_t to force sane size)
 * @param reply reply data
 */
void
GNUNET_DNS_request_answer (struct GNUNET_DNS_RequestHandle *rh,	 
			   uint16_t reply_length,
			   const char *reply)
{
  struct ReplyQueueEntry *qe;
  struct GNUNET_DNS_Response *resp;

  GNUNET_assert (0 < rh->dh->pending_requests--);
  if (rh->generation != rh->dh->generation)
  {
      GNUNET_free (rh);
      return;
  }
  if (reply_length + sizeof (struct GNUNET_DNS_Response) >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    GNUNET_free (rh);
    return;
  }
  qe = GNUNET_malloc (sizeof (struct ReplyQueueEntry) +
		      sizeof (struct GNUNET_DNS_Response) + reply_length);
  resp = (struct GNUNET_DNS_Response*) &qe[1];
  qe->msg = &resp->header;
  resp->header.size = htons (sizeof (struct GNUNET_DNS_Response) + reply_length);
  resp->header.type = htons (GNUNET_MESSAGE_TYPE_DNS_CLIENT_RESPONSE);
  resp->drop_flag = htonl (2);
  resp->request_id = rh->request_id;
  memcpy (&resp[1], reply, reply_length);
  queue_reply (rh->dh, qe);
  GNUNET_free (rh);
}


/**
 * Connect to the service-dns
 *
 * @param cfg configuration to use
 * @param flags when to call rh
 * @param rh function to call with DNS requests
 * @param rh_cls closure to pass to rh
 * @return DNS handle 
 */
struct GNUNET_DNS_Handle *
GNUNET_DNS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
		    enum GNUNET_DNS_Flags flags,
		    GNUNET_DNS_RequestHandler rh,
		    void *rh_cls)
{
  struct GNUNET_DNS_Handle *dh;
  
  dh = GNUNET_malloc (sizeof (struct GNUNET_DNS_Handle));
  dh->cfg = cfg;
  dh->flags = flags;
  dh->rh = rh;
  dh->rh_cls = rh_cls;
  dh->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect, dh);
  return dh;
}


/**
 * Disconnect from the DNS service.
 *
 * @param dh DNS handle
 */
void
GNUNET_DNS_disconnect (struct GNUNET_DNS_Handle *dh)
{
  if (GNUNET_SCHEDULER_NO_TASK != dh->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (dh->reconnect_task);
    dh->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }
  disconnect (dh);
  /* make sure client has no pending requests left over! */
  GNUNET_assert (0 == dh->pending_requests);
  GNUNET_free (dh);
}

/* end of dns_api_new.c */
