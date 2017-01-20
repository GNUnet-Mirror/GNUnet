/*
     This file is part of GNUnet.
     Copyright (C) 2010-2014, 2016 GNUnet e.V.

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
 * @file transport/transport_api_blacklist.c
 * @brief library to access the blacklisting functions of the transport service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"
#include "transport.h"

/**
 * Handle for blacklisting requests.
 */
struct GNUNET_TRANSPORT_Blacklist
{

  /**
   * Connection to transport service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Function to call for determining if a peer is allowed
   * to communicate with us.
   */
  GNUNET_TRANSPORT_BlacklistCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

};


/**
 * Establish blacklist connection to transport service.
 *
 * @param br overall handle
 */
static void
reconnect (struct GNUNET_TRANSPORT_Blacklist *br);


/**
 * Handle blacklist queries.
 *
 * @param cls our overall handle
 * @param bm query
 */
static void
handle_query (void *cls,
              const struct BlacklistMessage *bm)
{
  struct GNUNET_TRANSPORT_Blacklist *br = cls;
  struct GNUNET_MQ_Envelope *env;
  struct BlacklistMessage *res;

  GNUNET_break (0 == ntohl (bm->is_allowed));
  env = GNUNET_MQ_msg (res,
                       GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_REPLY);
  res->is_allowed = htonl (br->cb (br->cb_cls,
                                   &bm->peer));
  res->peer = bm->peer;
  GNUNET_MQ_send (br->mq,
                  env);
}

/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_TRANSPORT_Blacklist *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_TRANSPORT_Blacklist *br = cls;

  reconnect (br);
}


/**
 * Establish blacklist connection to transport service.
 *
 * @param br overall handle
 */
static void
reconnect (struct GNUNET_TRANSPORT_Blacklist *br)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (query,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_QUERY,
                             struct BlacklistMessage,
                             br),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *req;

  if (NULL != br->mq)
    GNUNET_MQ_destroy (br->mq);
  br->mq = GNUNET_CLIENT_connect (br->cfg,
                                  "transport",
                                  handlers,
                                  &mq_error_handler,
                                  br);
  if (NULL == br->mq)
    return;
  env = GNUNET_MQ_msg (req,
                       GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_INIT);
  GNUNET_MQ_send (br->mq,
                  env);
}


/**
 * Install a blacklist callback.  The service will be queried for all
 * existing connections as well as any fresh connections to check if
 * they are permitted.  If the blacklisting callback is unregistered,
 * all hosts that were denied in the past will automatically be
 * whitelisted again.  Cancelling the blacklist handle is also the
 * only way to re-enable connections from peers that were previously
 * blacklisted.
 *
 * @param cfg configuration to use
 * @param cb callback to invoke to check if connections are allowed
 * @param cb_cls closure for @a cb
 * @return NULL on error, otherwise handle for cancellation
 */
struct GNUNET_TRANSPORT_Blacklist *
GNUNET_TRANSPORT_blacklist (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            GNUNET_TRANSPORT_BlacklistCallback cb,
                            void *cb_cls)
{
  struct GNUNET_TRANSPORT_Blacklist *br;

  br = GNUNET_new (struct GNUNET_TRANSPORT_Blacklist);
  br->cfg = cfg;
  br->cb = cb;
  br->cb_cls = cb_cls;
  reconnect (br);
  if (NULL == br->mq)
  {
    GNUNET_free (br);
    return NULL;
  }
  return br;
}


/**
 * Abort the blacklist.  Note that this function is the only way for
 * removing a peer from the blacklist.
 *
 * @param br handle of the request that is to be cancelled
 */
void
GNUNET_TRANSPORT_blacklist_cancel (struct GNUNET_TRANSPORT_Blacklist *br)
{
  GNUNET_MQ_destroy (br->mq);
  GNUNET_free (br);
}


/* end of transport_api_blacklist.c */
