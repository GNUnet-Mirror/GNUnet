/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
struct GNUNET_TRANSPORT_BlacklistRequest
{

  /**
   * Connection to transport service.
   */
  struct GNUNET_CLIENT_Connection * client;

  /**
   * Function to call when done.
   */
  GNUNET_SCHEDULER_Task cont;

  /**
   * Clsoure for 'cont'.
   */
  void *cont_cls;

  /**
   * Scheduler to use.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Pending handle for the blacklisting request.
   */ 
  struct GNUNET_CLIENT_TransmitHandle *th;
  
  /**
   * How long should 'peer' be blacklisted?
   */
  struct GNUNET_TIME_Absolute duration;
  
  /**
   * Which peer is being blacklisted?
   */
  struct GNUNET_PeerIdentity peer;
  
};


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
transmit_blacklist_request (void *cls,
			    size_t size, void *buf)
{
  struct GNUNET_TRANSPORT_BlacklistRequest *br = cls;
  struct BlacklistMessage req;

  if (buf == NULL)
    {
      GNUNET_SCHEDULER_add_continuation (br->sched,
					 br->cont,
					 br->cont_cls,
					 GNUNET_SCHEDULER_REASON_TIMEOUT);
      GNUNET_free (br);
      return 0;
    }
  req.header.size = htons (sizeof (req));
  req.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST);
  req.reserved = htonl (0);
  req.peer = br->peer;
  req.until = GNUNET_TIME_absolute_hton (br->duration);
  memcpy (buf, &req, sizeof (req));
  GNUNET_SCHEDULER_add_continuation (br->sched,
				     br->cont,
				     br->cont_cls,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
  GNUNET_free (br);
  return sizeof (req);
}


/**
 * Blacklist a peer for a given period of time.  All connections
 * (inbound and outbound) to a peer that is blacklisted will be
 * dropped (as soon as we learn who the connection is for).  A second
 * call to this function for the same peer overrides previous
 * blacklisting requests.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param peer identity of peer to blacklist
 * @param duration how long to blacklist, use GNUNET_TIME_UNIT_ZERO to
 *        re-enable connections
 * @param timeout when should this operation (trying to establish the
 *        blacklisting time out)
 * @param cont continuation to call once the request has been processed
 * @param cont_cls closure for cont
 * @return NULL on error, otherwise handle for cancellation
 */
struct GNUNET_TRANSPORT_BlacklistRequest *
GNUNET_TRANSPORT_blacklist (struct GNUNET_SCHEDULER_Handle *sched,
			    const struct GNUNET_CONFIGURATION_Handle *cfg,
			    const struct GNUNET_PeerIdentity *peer,
			    struct GNUNET_TIME_Relative duration,
			    struct GNUNET_TIME_Relative timeout,
			    GNUNET_SCHEDULER_Task cont,
			    void *cont_cls)
{
  struct GNUNET_CLIENT_Connection * client;
  struct GNUNET_TRANSPORT_BlacklistRequest *ret;

  client = GNUNET_CLIENT_connect (sched, "transport", cfg);
  if (NULL == client)
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_BlacklistRequest));
  ret->client = client;
  ret->peer = *peer;
  ret->duration = GNUNET_TIME_relative_to_absolute (duration);
  ret->sched = sched;
  ret->cont = cont;
  ret->cont_cls = cont_cls;
  ret->th = GNUNET_CLIENT_notify_transmit_ready (client,
						 sizeof (struct BlacklistMessage),
						 timeout,
						 GNUNET_YES,
						 &transmit_blacklist_request,
						 ret);
  GNUNET_assert (NULL != ret->th);
  return ret;
}


/**
 * Abort transmitting the blacklist request.  Note that this function
 * is NOT for removing a peer from the blacklist (for that, call 
 * GNUNET_TRANSPORT_blacklist with a duration of zero).  This function
 * is only for aborting the transmission of a blacklist request
 * (i.e. because of shutdown).
 *
 * @param br handle of the request that is to be cancelled
 */
void
GNUNET_TRANSPORT_blacklist_cancel (struct GNUNET_TRANSPORT_BlacklistRequest * br)
{
  GNUNET_CLIENT_notify_transmit_ready_cancel (br->th);
  GNUNET_free (br);
}


/**
 * Handle for blacklist notifications.
 */
struct GNUNET_TRANSPORT_BlacklistNotification
{

  /**
   * Function to call whenever there is a change.
   */
  GNUNET_TRANSPORT_BlacklistCallback notify;

  /**
   * Closure for notify.
   */
  void *notify_cls;

  /**
   * Scheduler to use.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  
  /**
   * Connection to transport service.
   */
  struct GNUNET_CLIENT_Connection * client;

  /**
   * Pending handle for the notification request.
   */ 
  struct GNUNET_CLIENT_TransmitHandle *th;
};


/**
 * Send a request to receive blacklisting notifications
 *
 * @param bn context to initialize
 */
static void
request_notifications (struct GNUNET_TRANSPORT_BlacklistNotification *bn);


/**
 * Destroy the existing connection to the transport service and
 * setup a new one (the existing one had serious problems).
 * 
 * @param bn context to re-initialize
 */
static void
retry_get_notifications (struct GNUNET_TRANSPORT_BlacklistNotification *bn)
{
  GNUNET_CLIENT_disconnect (bn->client);
  bn->client = GNUNET_CLIENT_connect (bn->sched, "transport", bn->cfg);
  request_notifications (bn);
}


/**
 * Function called whenever we get a blacklisting notification.
 * Pass it on to the callback and wait for more.
 *
 * @param cls our 'struct GNUNET_TRANSPORT_BlacklistNotification *'
 * @param msg the blacklisting notification, NULL on error
 */
static void
recv_blacklist_info (void *cls,
		     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_TRANSPORT_BlacklistNotification *bn = cls;
  const struct BlacklistMessage *req;

  if ( (msg == NULL) ||
       (sizeof(struct BlacklistMessage) != ntohs(msg->size)) ||
       (GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST != ntohs(msg->type)) )
    {
      retry_get_notifications (bn);
      return;
    }
  req = (const struct BlacklistMessage*) msg;
  bn->notify (bn->notify_cls,
	      &req->peer,
	      GNUNET_TIME_absolute_ntoh (req->until));
  GNUNET_CLIENT_receive (bn->client,
			 &recv_blacklist_info,
			 bn,
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
transmit_notify_request (void *cls,
			 size_t size, void *buf)
{
  struct GNUNET_TRANSPORT_BlacklistNotification *bn = cls;
  struct GNUNET_MessageHeader hdr;

  bn->th = NULL;
  if (buf == NULL)
    {
      retry_get_notifications (bn);
      return 0;
    }
  GNUNET_assert (size >= sizeof(hdr));
  hdr.size = htons (sizeof (hdr));
  hdr.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_NOTIFY);
  memcpy (buf, &hdr, sizeof(hdr));
  return sizeof(hdr);  
}


/**
 * Send a request to receive blacklisting notifications
 *
 * @param bn context to initialize
 */
static void
request_notifications (struct GNUNET_TRANSPORT_BlacklistNotification *bn)
{
  GNUNET_assert (bn->client != NULL);
  bn->th = GNUNET_CLIENT_notify_transmit_ready (bn->client,
						sizeof (struct GNUNET_MessageHeader),
						GNUNET_TIME_UNIT_FOREVER_REL,
						GNUNET_YES,
						&transmit_notify_request,
						bn);
  GNUNET_assert (bn->th != NULL);
  GNUNET_CLIENT_receive (bn->client,
			 &recv_blacklist_info,
			 bn,
			 GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Call a function whenever a peer's blacklisting status changes.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param bc function to call on status changes
 * @param bc_cls closure for bc
 * @return NULL on error, otherwise handle for cancellation
 */
struct GNUNET_TRANSPORT_BlacklistNotification *
GNUNET_TRANSPORT_blacklist_notify (struct GNUNET_SCHEDULER_Handle *sched,
				   const struct GNUNET_CONFIGURATION_Handle *cfg,
				   GNUNET_TRANSPORT_BlacklistCallback bc,
				   void *bc_cls)
{
  struct GNUNET_TRANSPORT_BlacklistNotification *ret;
  struct GNUNET_CLIENT_Connection * client;

  client = GNUNET_CLIENT_connect (sched, "transport", cfg);
  if (NULL == client)
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_BlacklistNotification));
  ret->client = client;
  ret->sched = sched;
  ret->cfg = cfg;
  ret->notify = bc;
  ret->notify_cls = bc_cls;
  request_notifications (ret);
  return ret;
}


/**
 * Stop calling the notification callback associated with
 * the given blacklist notification.
 *
 * @param bn handle of the request that is to be cancelled
 */
void
GNUNET_TRANSPORT_blacklist_notify_cancel (struct GNUNET_TRANSPORT_BlacklistNotification * bn)
{
  if (bn->th != NULL)
    GNUNET_CLIENT_notify_transmit_ready_cancel (bn->th);
  GNUNET_CLIENT_disconnect (bn->client);
  GNUNET_free (bn);
}

/* end of transport_api_blacklist.c */
