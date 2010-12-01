/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file core/core_api_iterate_peers.c
 * @brief implementation of the peer_iterate function
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_core_service.h"
#include "core.h"


struct GNUNET_CORE_RequestContext
{
  
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
  GNUNET_CORE_ConnectEventHandler peer_cb;

  /**
   * Closure for peer_cb.
   */
  void *cb_cls;

};


/**
 * Receive reply from core service with information about a peer.
 *
 * @param cls our 'struct  GNUNET_CORE_RequestContext *'
 * @param msg NULL on error or last entry
 */
static void
receive_info (void *cls,
	      const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CORE_RequestContext *request_context = cls;
  const struct ConnectNotifyMessage *connect_message;
  uint32_t ats_count;
  uint16_t msize;

  /* Handle last message or error case, disconnect and clean up */
  msize = ntohs (msg->size);
  if ( (msg == NULL) ||
      ((ntohs (msg->type) == GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS_END) &&
      (msize == sizeof (struct GNUNET_MessageHeader))) )
    {
      if (request_context->peer_cb != NULL)
	request_context->peer_cb (request_context->cb_cls,
                                  NULL, NULL);
      GNUNET_CLIENT_disconnect (request_context->client, GNUNET_NO);
      GNUNET_free (request_context);
      return;
    }

  /* Handle incorrect message type or size, disconnect and clean up */
  if ( (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT) ||
       (msize < sizeof (struct ConnectNotifyMessage)) )
    {
      GNUNET_break (0);
      if (request_context->peer_cb != NULL)
        request_context->peer_cb (request_context->cb_cls,
                                  NULL, NULL);
      GNUNET_CLIENT_disconnect (request_context->client, GNUNET_NO);
      GNUNET_free (request_context);
      return;
    }
  connect_message = (const struct ConnectNotifyMessage *) msg;
  ats_count = ntohl (connect_message->ats_count);
  if ( (msize != sizeof (struct ConnectNotifyMessage) + ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information)) ||
       (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR != ntohl ((&connect_message->ats)[ats_count].type)) )
    {
      GNUNET_break (0);
      if (request_context->peer_cb != NULL)
        request_context->peer_cb (request_context->cb_cls,
                                  NULL, NULL);
      GNUNET_CLIENT_disconnect (request_context->client, GNUNET_NO);
      GNUNET_free (request_context);
      return;
    }
  /* Normal case */
  if (request_context->peer_cb != NULL)
    request_context->peer_cb (request_context->cb_cls,
                              &connect_message->peer,
                              &connect_message->ats);
  GNUNET_CLIENT_receive(request_context->client, 
			&receive_info, 
			request_context,
			GNUNET_TIME_UNIT_FOREVER_REL);
}

/**
 * Function called to notify a client about the socket
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_request(void *cls,
                 size_t size, void *buf)
{
  struct GNUNET_MessageHeader *msg;
  if ((size < sizeof(struct GNUNET_MessageHeader)) || (buf == NULL))
    return 0;

  msg = (struct GNUNET_MessageHeader *)buf;
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  msg->type = htons (GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS);
  return sizeof(struct GNUNET_MessageHeader);
}

/**
 * Obtain statistics and/or change preferences for the given peer.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param peer_cb function to call with the peer information
 * @param cb_cls closure for peer_cb
 * @return GNUNET_OK if iterating, GNUNET_SYSERR on error
 */
int
GNUNET_CORE_iterate_peers (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           GNUNET_CORE_ConnectEventHandler peer_cb,
                           void *cb_cls)
{
  struct GNUNET_CORE_RequestContext *request_context;
  struct GNUNET_CLIENT_Connection *client;

  client = GNUNET_CLIENT_connect ("core", cfg);
  if (client == NULL)
    return GNUNET_SYSERR;
  request_context = GNUNET_malloc (sizeof (struct GNUNET_CORE_RequestContext));
  request_context->client = client;
  request_context->peer_cb = peer_cb;
  request_context->cb_cls = cb_cls;

  request_context->th = GNUNET_CLIENT_notify_transmit_ready(client,
                                                            sizeof(struct GNUNET_MessageHeader),
                                                            GNUNET_TIME_relative_get_forever(),
                                                            GNUNET_YES,
                                                            &transmit_request,
                                                            NULL);

  GNUNET_CLIENT_receive(client, &receive_info, request_context, GNUNET_TIME_relative_get_forever());
  return GNUNET_OK;
}

/* end of core_api_iterate_peers.c */
