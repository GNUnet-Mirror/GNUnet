/*
      This file is part of GNUnet
      Copyright (C) 2012, 2016 GNUnet e.V.

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
 * @file dns/dns_api.c
 * @brief API to access the DNS service.
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_dns_service.h"
#include "dns.h"


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
  struct GNUNET_MQ_Handle *mq;

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Function to call to get replies.
   */
  GNUNET_DNS_RequestHandler rh;

  /**
   * Closure for @e rh.
   */
  void *rh_cls;

  /**
   * Task to reconnect to the service.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Re-connect counter, to make sure we did not reconnect in the meantime.
   */
  uint32_t generation;

  /**
   * Flags for events we care about.
   */
  enum GNUNET_DNS_Flags flags;

  /**
   * Number of GNUNET_DNS_RequestHandles we have outstanding. Must be 0 before
   * we can be disconnected.
   */
  unsigned int pending_requests;
};


/**
 * Reconnect to the DNS service.
 *
 * @param cls handle with the connection to connect
 * @param tc scheduler context (unused)
 */
static void
reconnect (void *cls);


/**
 * Drop the existing connection and reconnect to the DNS service.
 *
 * @param dh handle with the connection
 */
static void
force_reconnect (struct GNUNET_DNS_Handle *dh)
{
  if (NULL != dh->mq)
  {
    GNUNET_MQ_destroy (dh->mq);
    dh->mq = NULL;
  }
  dh->reconnect_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                  &reconnect,
                                  dh);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_DNS_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_DNS_Handle *dh = cls;

  force_reconnect (dh);
}



/**
 * This receives packets from the DNS service and calls the application to
 * check that the request is well-formed
 *
 * @param cls the struct GNUNET_DNS_Handle
 * @param req message from the service (request)
 */
static int
check_request (void *cls,
               const struct GNUNET_DNS_Request *req)
{
  if (0 != ntohl (req->reserved))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * This receives packets from the DNS service and calls the application to
 * handle it.
 *
 * @param cls the `struct GNUNET_DNS_Handle *`
 * @param msg message from the service (request)
 */
static void
handle_request (void *cls,
                const struct GNUNET_DNS_Request *req)
{
  struct GNUNET_DNS_Handle *dh = cls;
  size_t payload_length = ntohs (req->header.size) - sizeof (*req);
  struct GNUNET_DNS_RequestHandle *rh;

  rh = GNUNET_new (struct GNUNET_DNS_RequestHandle);
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
 * Reconnect to the DNS service.
 *
 * @param cls handle with the connection to connect
 */
static void
reconnect (void *cls)
{
  GNUNET_MQ_hd_var_size (request,
                         GNUNET_MESSAGE_TYPE_DNS_CLIENT_REQUEST,
                         struct GNUNET_DNS_Request);
  struct GNUNET_DNS_Handle *dh = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    make_request_handler (dh),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DNS_Register *msg;

  dh->reconnect_task = NULL;
  dh->mq = GNUNET_CLIENT_connecT (dh->cfg,
                                  "dns",
                                  handlers,
                                  &mq_error_handler,
                                  dh);
  if (NULL == dh->mq)
    return;
  dh->generation++;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_DNS_CLIENT_INIT);
  msg->flags = htonl (dh->flags);
  GNUNET_MQ_send (dh->mq,
                  env);
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
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DNS_Response *resp;

  GNUNET_assert (0 < rh->dh->pending_requests--);
  if (rh->generation != rh->dh->generation)
  {
    GNUNET_free (rh);
    return;
  }
  env = GNUNET_MQ_msg (resp,
                       GNUNET_MESSAGE_TYPE_DNS_CLIENT_RESPONSE);
  resp->drop_flag = htonl (1);
  resp->request_id = rh->request_id;
  GNUNET_MQ_send (rh->dh->mq,
                  env);
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
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DNS_Response *resp;

  GNUNET_assert (0 < rh->dh->pending_requests--);
  if (rh->generation != rh->dh->generation)
  {
      GNUNET_free (rh);
      return;
  }
  env = GNUNET_MQ_msg (resp,
                       GNUNET_MESSAGE_TYPE_DNS_CLIENT_RESPONSE);
  resp->request_id = rh->request_id;
  resp->drop_flag = htonl (0);
  GNUNET_MQ_send (rh->dh->mq,
                  env);
  GNUNET_free (rh);
}


/**
 * If a GNUNET_DNS_RequestHandler calls this function, the request is
 * supposed to be answered with the data provided to this call (with
 * the modifications the function might have made).
 *
 * @param rh request that should now be answered
 * @param reply_length size of @a reply (uint16_t to force sane size)
 * @param reply reply data
 */
void
GNUNET_DNS_request_answer (struct GNUNET_DNS_RequestHandle *rh,
			   uint16_t reply_length,
			   const char *reply)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DNS_Response *resp;

  GNUNET_assert (0 < rh->dh->pending_requests--);
  if (rh->generation != rh->dh->generation)
  {
      GNUNET_free (rh);
      return;
  }
  if (reply_length + sizeof (struct GNUNET_DNS_Response)
      >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    GNUNET_free (rh);
    return;
  }
  env = GNUNET_MQ_msg_extra (resp,
                             reply_length,
                             GNUNET_MESSAGE_TYPE_DNS_CLIENT_RESPONSE);
  resp->drop_flag = htonl (2);
  resp->request_id = rh->request_id;
  GNUNET_memcpy (&resp[1],
          reply,
          reply_length);
  GNUNET_MQ_send (rh->dh->mq,
                  env);
  GNUNET_free (rh);
}


/**
 * Connect to the service-dns
 *
 * @param cfg configuration to use
 * @param flags when to call @a rh
 * @param rh function to call with DNS requests
 * @param rh_cls closure to pass to @a rh
 * @return DNS handle
 */
struct GNUNET_DNS_Handle *
GNUNET_DNS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
		    enum GNUNET_DNS_Flags flags,
		    GNUNET_DNS_RequestHandler rh,
		    void *rh_cls)
{
  struct GNUNET_DNS_Handle *dh;

  dh = GNUNET_new (struct GNUNET_DNS_Handle);
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
  if (NULL != dh->mq)
  {
    GNUNET_MQ_destroy (dh->mq);
    dh->mq = NULL;
  }
  if (NULL != dh->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (dh->reconnect_task);
    dh->reconnect_task = NULL;
  }
  /* make sure client has no pending requests left over! */
  GNUNET_break (0 == dh->pending_requests);
  GNUNET_free (dh);
}

/* end of dns_api.c */
