/*
     This file is part of GNUnet.
     (C) 

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
 * @file rps/rps_api.c
 * @brief API for rps
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "rps.h"
#include "gnunet_rps_service.h"

/**
 * Handler to handle requests from a client.
 */
struct GNUNET_RPS_Handle
{
  /**
   * The handle to the client configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The connection to the client.
   */
  struct GNUNET_CLIENT_Connection *conn;

  /**
   * The message queue to the client.
   */
  struct GNUNET_MQ_Handle *mq;
};

/**
 * Handler to single requests from the client.
 */
struct GNUNET_RPS_Request_Handle
{
  /**
   * The client issuing the request.
   */
  struct GNUNET_RPS_Handle *h;

  /**
   * The nuber of the request.
   */
  uint64_t n;

  /**
   * The callback to be called when we receive an answer.
   */
  GNUNET_RPS_NotifyReadyCB ready_cb;

  /**
   * The closure for the callback.
   */
  void *ready_cb_cls;
};

/**
 * Array of Request_Handles.
 */
struct GNUNET_RPS_Request_Handle *req_handlers = NULL;

/**
 * Current length of req_handlers.
 */
unsigned int req_handlers_size = 0;

/**
 * Struct used to pack the callback, its closure (provided by the caller)
 * and the connection handler to the service to pass it to a callback function.
 */
struct cb_cls_pack
{
  /**
   * Callback provided by the client
   */
  GNUNET_RPS_NotifyReadyCB cb;

  /**
   * Closure provided by the client
   */
  void *cls;

  /**
   * Handle to the service connection
   */
 struct GNUNET_CLIENT_Connection *service_conn;
};




/**
 * This function is called, when the service replies to our request.
 * It calls the callback the caller gave us with the provided closure
 * and disconnects afterwards.
 *
 * @param cls the closure
 * @param message the message
 */
  static void
handle_reply (void *cls,
              const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_RPS_CS_ReplyMessage *msg;
  //struct cb_cls_pack *pack;
  //struct GNUNET_RPS_Handle *h;
  struct GNUNET_PeerIdentity *peers;
  struct GNUNET_RPS_Request_Handle *rh;

  /* Give the peers back */
  msg = (struct GNUNET_RPS_CS_ReplyMessage *) message;
  //pack = (struct cb_cls_pack *) cls;
  //h = (struct GNUNET_RPS_Handle *) cls;
  peers = (struct GNUNET_PeerIdentity *) &msg[1];
  rh = &req_handlers[msg->n];
  rh->ready_cb((rh)->ready_cb_cls, msg->num_peers, peers);

  /* Disconnect */
  //GNUNET_CLIENT_disconnect(pack->service_conn);
}

/**
 */
  static void
mq_error_handler(void *cls, enum GNUNET_MQ_Error error)
{
  //TODO LOG
}

/**
 * Request n random peers.
 *
 * @param cfg the configuration to use.
 * @param n number of peers requesting.
 * @param cb a callback function called when the peers are ready
 * @param cls a closure given to the callback function
 */
  struct GNUNET_RPS_Request_Handle *
GNUNET_RPS_request_peers_single_call (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          uint64_t n,
                          GNUNET_RPS_NotifyReadyCB ready_cb,
                          void *cls)
{
  //struct GNUNET_CLIENT_Connection *service_conn;
  //static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
  //  {&handle_reply, GNUNET_MESSAGE_TYPE_RPS_CS_REPLY, 0},
  //  GNUNET_MQ_HANDLERS_END
  //};
  //struct cb_cls_pack *pack;
  //struct GNUNET_MQ_Handle *mq;
  //struct GNUNET_MQ_Envelope *ev;
  //struct GNUNET_RPS_CS_RequestMessage *msg;
  struct GNUNET_RPS_Handle *h;
  struct GNUNET_RPS_Request_Handle *rh;

  /* Connect to the service */
  h = GNUNET_RPS_connect(cfg);
  //h = GNUNET_new(struct GNUNET_RPS_Handle);
  //h->conn = GNUNET_CLIENT_connect("rps", cfg);
  //rh = GNUNET_new(struct GNUNET_RPS_Request_Handle);
  ////pack = GNUNET_malloc(sizeof(struct cb_cls_pack));
  ////pack->cb = ready_cb;
  ////pack->cls = cls;
  ////pack->service_conn = service_conn;
  //mq = GNUNET_MQ_queue_for_connection_client(service_conn,
  //                                           mq_handlers,
  //                                           mq_error_handler, // TODO implement
  //                                           h);

  /* Send the request to the service */
  rh = GNUNET_RPS_request_peers(h, n, ready_cb, cls);
  //ev = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_RPS_CS_REQUEST);
  //msg->num_peers = GNUNET_htonll(n);
  //GNUNET_MQ_send(mq, ev);
  //GNUNET_CLIENT_disconnect(service_conn);
  //rh = GNUNET_new(struct GNUNET_RPS_Request_Handle);
  GNUNET_RPS_disconnect(h);
  return rh;
}

/**
 * Connect to the rps service
 */
  struct GNUNET_RPS_Handle *
GNUNET_RPS_connect( const struct GNUNET_CONFIGURATION_Handle *cfg )
{
  struct GNUNET_RPS_Handle *h;
  //struct GNUNET_RPS_Request_Handle *rh;
  static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    {&handle_reply, GNUNET_MESSAGE_TYPE_RPS_CS_REPLY, 0},
    GNUNET_MQ_HANDLERS_END
  };

  h = GNUNET_new(struct GNUNET_RPS_Handle);
  //h->cfg = GNUNET_new(struct GNUNET_CONFIGURATION_Handle);
  //*h->cfg = *cfg;
  h->cfg = cfg; // FIXME |^
  h->conn = GNUNET_CLIENT_connect("rps", cfg);
  h->mq = GNUNET_MQ_queue_for_connection_client(h->conn,
                                                mq_handlers,
                                                mq_error_handler, // TODO implement
                                                h);


  return h;
}

/**
 * Request n random peers.
 */
  struct GNUNET_RPS_Request_Handle *
GNUNET_RPS_request_peers (struct GNUNET_RPS_Handle *h, uint64_t n,
                          GNUNET_RPS_NotifyReadyCB ready_cb,
                          void *cls)
{
  struct GNUNET_RPS_Request_Handle *rh;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_RequestMessage *msg;

  // assert func != NULL
  rh = GNUNET_new(struct GNUNET_RPS_Request_Handle);
  rh->h = h;
  rh->n = req_handlers_size; // TODO ntoh
  rh->ready_cb = ready_cb;
  rh->ready_cb_cls = cls;

  GNUNET_array_append(req_handlers, req_handlers_size, *rh);
  //memcpy(&req_handlers[req_handlers_size-1], rh, sizeof(struct GNUNET_RPS_Request_Handle));

  ev = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_RPS_CS_REQUEST);
  msg->num_peers = GNUNET_htonll(n);
  msg->n = rh->n;
  GNUNET_MQ_send(h->mq, ev);
  return rh;
}

/**
 * Cancle an issued request.
 */
  void
GNUNET_RPS_request_cancel ( struct GNUNET_RPS_Request_Handle *rh )
{
  // TODO
}

/**
 * Disconnect to the rps service
 */
  void
GNUNET_RPS_disconnect ( struct GNUNET_RPS_Handle *h )
{
  if ( NULL != h->conn ) {
    GNUNET_CLIENT_disconnect(h->conn);
  }
}


/* end of rps_api.c */
