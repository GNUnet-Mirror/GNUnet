/*
     This file is part of GNUnet.
     Copyright (C) 2009-2014 Christian Grothoff (and other contributing authors)

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
 * @file core/core_api_monitor_peers.c
 * @brief implementation of the peer_iterate function
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_core_service.h"
#include "core.h"


/**
 * Handle to a CORE monitoring operation.
 */
struct GNUNET_CORE_MonitorHandle
{

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Our connection to the service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Handle for transmitting a request.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Function called with the peer.
   */
  GNUNET_CORE_MonitorCallback peer_cb;

  /**
   * Closure for @e peer_cb.
   */
  void *peer_cb_cls;

};


/**
 * Transmits the monitor request to the CORE service.
 *
 * Function is called to notify a client about the socket begin ready
 * to queue more data.  @a buf will be NULL and @a size zero if the
 * socket was closed for writing in the meantime.
 *
 * @param cls closure, our `struct GNUNET_CORE_MonitorHandle *`
 * @param size number of bytes available in @a buf
 * @param buf where the callee should write the message
 * @return number of bytes written to @a buf
 */
static size_t
transmit_monitor_request (void *cls,
                          size_t size,
                          void *buf);


/**
 * Protocol error, reconnect to CORE service and notify
 * client.
 *
 * @param mh monitoring session to reconnect to CORE
 */
static void
reconnect (struct GNUNET_CORE_MonitorHandle *mh)
{
  GNUNET_CLIENT_disconnect (mh->client);
  /* FIXME: use backoff? */
  mh->client = GNUNET_CLIENT_connect ("core", mh->cfg);
  GNUNET_assert (NULL != mh->client);
  mh->th =
    GNUNET_CLIENT_notify_transmit_ready (mh->client,
                                         sizeof (struct GNUNET_MessageHeader),
                                         GNUNET_TIME_UNIT_FOREVER_REL,
                                         GNUNET_YES,
                                         &transmit_monitor_request, mh);
  /* notify callback about reconnect */
  mh->peer_cb (mh->peer_cb_cls,
               NULL,
               GNUNET_CORE_KX_CORE_DISCONNECT,
               GNUNET_TIME_UNIT_FOREVER_ABS);
}


/**
 * Receive reply from CORE service with information about a peer.
 *
 * @param cls our `struct  GNUNET_CORE_MonitorHandle *`
 * @param msg NULL on error or last entry
 */
static void
receive_info (void *cls,
              const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CORE_MonitorHandle *mh = cls;
  const struct MonitorNotifyMessage *mon_message;
  uint16_t msize;

  if (NULL == msg)
  {
    reconnect (mh);
    return;
  }
  msize = ntohs (msg->size);
  /* Handle incorrect message type or size, disconnect and clean up */
  if ((ntohs (msg->type) != GNUNET_MESSAGE_TYPE_CORE_MONITOR_NOTIFY) ||
      (sizeof (struct MonitorNotifyMessage) != msize))
  {
    GNUNET_break (0);
    reconnect (mh);
    return;
  }
  mon_message = (const struct MonitorNotifyMessage *) msg;
  GNUNET_CLIENT_receive (mh->client,
                         &receive_info, mh,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  mh->peer_cb (mh->peer_cb_cls,
               &mon_message->peer,
               (enum GNUNET_CORE_KxState) ntohl (mon_message->state),
               GNUNET_TIME_absolute_ntoh (mon_message->timeout));
}


/**
 * Transmits the monitor request to the CORE service.
 *
 * Function is called to notify a client about the socket begin ready
 * to queue more data.  @a buf will be NULL and @a size zero if the
 * socket was closed for writing in the meantime.
 *
 * @param cls closure, our `struct GNUNET_CORE_MonitorHandle *`
 * @param size number of bytes available in @a buf
 * @param buf where the callee should write the message
 * @return number of bytes written to @a buf
 */
static size_t
transmit_monitor_request (void *cls,
                          size_t size,
                          void *buf)
{
  struct GNUNET_CORE_MonitorHandle *mh = cls;
  struct GNUNET_MessageHeader *msg;
  int msize;

  mh->th = NULL;
  msize = sizeof (struct GNUNET_MessageHeader);
  if ((size < msize) || (NULL == buf))
  {
    reconnect (mh);
    return 0;
  }
  msg = (struct GNUNET_MessageHeader *) buf;
  msg->size = htons (msize);
  msg->type = htons (GNUNET_MESSAGE_TYPE_CORE_MONITOR_PEERS);
  GNUNET_CLIENT_receive (mh->client,
                         &receive_info, mh,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  return msize;
}


/**
 * Monitor connectivity and KX status of all peers known to CORE.
 * Calls @a peer_cb with the current status for each connected peer,
 * and then once with NULL to indicate that all peers that are
 * currently active have been handled.  After that, the iteration
 * continues until it is cancelled.  Normal users of the CORE API are
 * not expected to use this function.  It is different in that it
 * truly lists all connections (including those where the KX is in
 * progress), not just those relevant to the application.  This
 * function is used by special applications for diagnostics.
 *
 * @param cfg configuration handle
 * @param peer_cb function to call with the peer information
 * @param peer_cb_cls closure for @a peer_cb
 * @return NULL on error
 */
struct GNUNET_CORE_MonitorHandle *
GNUNET_CORE_monitor_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           GNUNET_CORE_MonitorCallback peer_cb,
                           void *peer_cb_cls)
{
  struct GNUNET_CORE_MonitorHandle *mh;
  struct GNUNET_CLIENT_Connection *client;

  GNUNET_assert (NULL != peer_cb);
  client = GNUNET_CLIENT_connect ("core", cfg);
  if (NULL == client)
    return NULL;
  mh = GNUNET_new (struct GNUNET_CORE_MonitorHandle);
  mh->cfg = cfg;
  mh->client = client;
  mh->peer_cb = peer_cb;
  mh->peer_cb_cls = peer_cb_cls;
  mh->th =
    GNUNET_CLIENT_notify_transmit_ready (client,
                                         sizeof (struct GNUNET_MessageHeader),
                                         GNUNET_TIME_UNIT_FOREVER_REL,
                                         GNUNET_YES,
                                         &transmit_monitor_request, mh);
  return mh;
}


/**
 * Stop monitoring CORE activity.
 *
 * @param mh monitor to stop
 */
void
GNUNET_CORE_monitor_stop (struct GNUNET_CORE_MonitorHandle *mh)
{
  if (NULL != mh->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (mh->th);
    mh->th = NULL;
  }
  if (NULL != mh->client)
  {
    GNUNET_CLIENT_disconnect (mh->client);
    mh->client = NULL;
  }
  GNUNET_free (mh);
}


/* end of core_api_monitor_peers.c */
