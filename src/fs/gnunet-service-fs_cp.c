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
 * @file fs/gnunet-service-fs_cp.c
 * @brief API to handle 'connected peers'
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-fs.h"
#include "gnunet-service-fs_cp.h"


struct GSF_PeerTransmitHandle
{

  /**
   * Time when this transmission request was issued.
   */
  struct GNUNET_TIME_Absolute transmission_request_start_time;


};


/**
 * A connected peer.
 */
struct GSF_ConnectedPeer 
{

  /**
   * Performance data for this peer.
   */
  struct GSF_PeerPerformanceData ppd;

  /**
   * Time until when we blocked this peer from migrating
   * data to us.
   */
  struct GNUNET_TIME_Absolute last_migration_block;

  /**
   * Handle for an active request for transmission to this
   * peer, or NULL.
   */
  struct GNUNET_CORE_TransmitHandle *cth;

  /**
   * Messages (replies, queries, content migration) we would like to
   * send to this peer in the near future.  Sorted by priority, head.
   */
  struct GSF_PeerTransmitHandle *pth_head;

  /**
   * Messages (replies, queries, content migration) we would like to
   * send to this peer in the near future.  Sorted by priority, tail.
   */
  struct GSF_PeerTransmitHandle *pth_tail;

  /**
   * Context of our GNUNET_CORE_peer_change_preference call (or NULL).
   */
  struct GNUNET_CORE_InformationRequestContext *irc;

  /**
   * ID of delay task for scheduling transmission.
   */
  GNUNET_SCHEDULER_TaskIdentifier delayed_transmission_request_task;

  /**
   * Increase in traffic preference still to be submitted
   * to the core service for this peer.
   */
  uint64_t inc_preference;

  /**
   * Trust rating for this peer
   */
  uint32_t trust;

  /**
   * Trust rating for this peer on disk.
   */
  uint32_t disk_trust;

  /**
   * The peer's identity.
   */
  GNUNET_PEER_Id pid;

  /**
   * Which offset in "last_p2p_replies" will be updated next?
   * (we go round-robin).
   */
  unsigned int last_p2p_replies_woff;

  /**
   * Which offset in "last_client_replies" will be updated next?
   * (we go round-robin).
   */
  unsigned int last_client_replies_woff;

  /**
   * Current offset into 'last_request_times' ring buffer.
   */
  unsigned int last_request_times_off;

};


/**
 * A peer connected to us.  Setup the connected peer
 * records.
 *
 * @param peer identity of peer that connected
 * @param atsi performance data for the connection
 * @return handle to connected peer entry
 */
struct GSF_ConnectedPeer *
GSF_peer_connect_handler_ (const struct GNUNET_PeerIdentity *peer,
			   const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  // FIXME
  return NULL;
}


/**
 * Transmit a message to the given peer as soon as possible.
 * If the peer disconnects before the transmission can happen,
 * the callback is invoked with a 'NULL' buffer.
 *
 * @param peer target peer
 * @param is_query is this a query (GNUNET_YES) or content (GNUNET_NO)
 * @param priority how important is this request?
 * @param timeout when does this request timeout (call gmc with error)
 * @param size number of bytes we would like to send to the peer
 * @param gmc function to call to get the message
 * @param gmc_cls closure for gmc
 * @return handle to cancel request
 */
struct GSF_PeerTransmitHandle *
GSF_peer_transmit_ (struct GSF_ConnectedPeer *peer,
		    int is_query,
		    uint32_t priority,
		    struct GNUNET_TIME_Relative timeout,
		    size_t size,
		    GSF_GetMessageCallback gmc,
		    void *gmc_cls)
{
  // FIXME
  return NULL;
}


/**
 * Cancel an earlier request for transmission.
 */
void
GSF_peer_transmit_cancel_ (struct GSF_PeerTransmitHandle *pth)
{
}


/**
 * Report on receiving a reply; update the performance record of the given peer.
 *
 * @param peer responding peer (will be updated)
 * @param request_time time at which the original query was transmitted
 * @param request_priority priority of the original request
 * @param initiator_client local client on responsible for query (or NULL)
 * @param initiator_peer other peer responsible for query (or NULL)
 */
void
GSF_peer_update_performance_ (struct GSF_ConnectedPeer *peer,
			      GNUNET_TIME_Absolute request_time,
			      uint32_t request_priority,
			      const struct GSF_LocalClient *initiator_client,
			      const struct GSF_ConnectedPeer *initiator_peer)
{
}


/**
 * Method called whenever a given peer has a status change.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param bandwidth_in available amount of inbound bandwidth
 * @param bandwidth_out available amount of outbound bandwidth
 * @param timeout absolute time when this peer will time out
 *        unless we see some further activity from it
 * @param atsi status information
 */
void
GSF_peer_status_handler_ (void *cls,
			  const struct GNUNET_PeerIdentity *peer,
			  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
			  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
			  struct GNUNET_TIME_Absolute timeout,
			  const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
}


/**
 * A peer disconnected from us.  Tear down the connected peer
 * record.
 *
 * @param cls unused
 * @param peer identity of peer that connected
 */
void
GSF_peer_disconnect_handler_ (void *cls,
			      const struct GNUNET_PeerIdentity *peer)
{
}


/**
 * Iterate over all connected peers.
 *
 * @param it function to call for each peer
 * @param it_cls closure for it
 */
void
GSF_iterate_connected_peers_ (GSF_ConnectedPeerIterator it,
			      void *it_cls)
{
}


/**
 * Try to reserve bandwidth (to receive data FROM the given peer).
 * This function must only be called ONCE per connected peer at a
 * time; it can be called again after the 'rc' callback was invoked.
 * If the peer disconnects, the request is (silently!) ignored (and
 * the requester is responsible to register for notification about the
 * peer disconnect if any special action needs to be taken in this
 * case).
 *
 * @param cp peer to reserve bandwidth from
 * @param size number of bytes to reserve
 * @param rc function to call upon reservation success or failure
 * @param rc_cls closure for rc
 */
void
GSF_connected_peer_reserve_ (struct GSF_ConnectedPeer *cp,
			     size_t size,
			     GSF_PeerReserveCallback rc,
			     void *rc_cls)
{
  // FIXME: should we allow queueing multiple reservation requests?
  // FIXME: what about cancellation?
  // FIXME: change docu on peer disconnect handling?
  if (NULL != cp->irc)
    {
      rc (rc_cls, cp, GNUNET_NO);
      return;
    }
  // FIXME...
}


#endif
/* end of gnunet-service-fs_cp.h */
