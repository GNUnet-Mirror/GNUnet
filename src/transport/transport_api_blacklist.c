/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file transport/transport_api_blacklist.c
 * @brief library to access the blacklisting functions of the transport service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"
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
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Pending handle for the current request.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Function to call for determining if a peer is allowed
   * to communicate with us.
   */
  GNUNET_TRANSPORT_BlacklistCallback cb;

  /**
   * Closure for 'cb'.
   */
  void *cb_cls;

  /**
   * Peer currently under consideration.
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Establish blacklist connection to transport service.
 *
 * @param br overall handle
 */
static void
reconnect (struct GNUNET_TRANSPORT_Blacklist *br);


/**
 * Send our reply to a blacklisting request.
 *
 * @param br our overall context
 */
static void
reply (struct GNUNET_TRANSPORT_Blacklist *br);


/**
 * Handle blacklist queries.
 *
 * @param cls our overall handle
 * @param msg query
 */
static void
query_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_TRANSPORT_Blacklist *br = cls;
  const struct BlacklistMessage *bm;

  GNUNET_assert (br != NULL);
  if ((NULL == msg) ||
      (ntohs (msg->size) != sizeof (struct BlacklistMessage)) ||
      (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_QUERY))
  {
    reconnect (br);
    return;
  }
  bm = (const struct BlacklistMessage *) msg;
  GNUNET_break (0 == ntohl (bm->is_allowed));
  br->peer = bm->peer;
  reply (br);
}


/**
 * Receive blacklist queries from transport service.
 *
 * @param br overall handle
 */
static void
receive (struct GNUNET_TRANSPORT_Blacklist *br)
{
  GNUNET_CLIENT_receive (br->client, &query_handler, br,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Transmit the blacklist initialization request to the service.
 *
 * @param cls closure (struct GNUNET_TRANSPORT_Blacklist*)
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_blacklist_init (void *cls, size_t size, void *buf)
{
  struct GNUNET_TRANSPORT_Blacklist *br = cls;
  struct GNUNET_MessageHeader req;

  br->th = NULL;
  if (buf == NULL)
  {
    reconnect (br);
    return 0;
  }
  req.size = htons (sizeof (struct GNUNET_MessageHeader));
  req.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_INIT);
  memcpy (buf, &req, sizeof (req));
  receive (br);
  return sizeof (req);
}


/**
 * Establish blacklist connection to transport service.
 *
 * @param br overall handle
 */
static void
reconnect (struct GNUNET_TRANSPORT_Blacklist *br)
{
  if (br->client != NULL)
    GNUNET_CLIENT_disconnect (br->client, GNUNET_NO);
  br->client = GNUNET_CLIENT_connect ("transport", br->cfg);
  GNUNET_assert (br->client != NULL);
  br->th =
      GNUNET_CLIENT_notify_transmit_ready (br->client,
                                           sizeof (struct GNUNET_MessageHeader),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_YES, &transmit_blacklist_init,
                                           br);
}


/**
 * Transmit the blacklist response to the service.
 *
 * @param cls closure (struct GNUNET_TRANSPORT_Blacklist*)
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_blacklist_reply (void *cls, size_t size, void *buf)
{
  struct GNUNET_TRANSPORT_Blacklist *br = cls;
  struct BlacklistMessage req;

  br->th = NULL;
  if (buf == NULL)
  {
    reconnect (br);
    return 0;
  }
  req.header.size = htons (sizeof (req));
  req.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_REPLY);
  req.is_allowed = htonl (br->cb (br->cb_cls, &br->peer));
  req.peer = br->peer;
  memcpy (buf, &req, sizeof (req));
  br->th = NULL;
  receive (br);
  return sizeof (req);
}


/**
 * Send our reply to a blacklisting request.
 *
 * @param br our overall context
 */
static void
reply (struct GNUNET_TRANSPORT_Blacklist *br)
{
  GNUNET_assert (br->th == NULL);
  br->th =
      GNUNET_CLIENT_notify_transmit_ready (br->client,
                                           sizeof (struct BlacklistMessage),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_NO, &transmit_blacklist_reply,
                                           br);
  if (br->th == NULL)
  {
    reconnect (br);
    return;
  }
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
 * @param cb_cls closure for cb
 * @return NULL on error, otherwise handle for cancellation
 */
struct GNUNET_TRANSPORT_Blacklist *
GNUNET_TRANSPORT_blacklist (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            GNUNET_TRANSPORT_BlacklistCallback cb, void *cb_cls)
{
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_TRANSPORT_Blacklist *ret;

  client = GNUNET_CLIENT_connect ("transport", cfg);
  if (NULL == client)
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_Blacklist));
  ret->client = client;
  ret->cfg = cfg;
  ret->cb = cb;
  ret->cb_cls = cb_cls;
  GNUNET_assert (ret->th == NULL);
  ret->th =
      GNUNET_CLIENT_notify_transmit_ready (client,
                                           sizeof (struct GNUNET_MessageHeader),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_YES, &transmit_blacklist_init,
                                           ret);
  return ret;
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
  if (br->th != NULL)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (br->th);
    br->th = NULL;
  }
  GNUNET_CLIENT_disconnect (br->client, GNUNET_NO);
  GNUNET_free (br);
}


/* end of transport_api_blacklist.c */
