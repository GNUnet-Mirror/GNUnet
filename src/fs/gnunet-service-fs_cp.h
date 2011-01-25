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
 * @file fs/gnunet-service-fs_cp.h
 * @brief API to handle 'connected peers'
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_FS_CP_H
#define GNUNET_SERVICE_FS_CP_H

#include "gnunet-service-fs.h"


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
			   const struct GNUNET_TRANSPORT_ATS_Information *atsi);


/**
 * Function called to get a message for transmission.
 *
 * @param cls closure
 * @param buf_size number of bytes available in buf
 * @param buf where to copy the message, NULL on error (peer disconnect)
 * @return number of bytes copied to 'buf', can be 0 (without indicating an error)
 */
typedef size_t (*GSF_GetMessageCallback)(void *cls,
					 size_t buf_size,
					 void *buf);


/**
 * Transmit a message to the given peer as soon as possible.
 * If the peer disconnects before the transmission can happen,
 * the callback is invoked with a 'NULL' buffer.
 *
 * @param peer target peer
 * @param size number of bytes we would like to send to the peer
 * @param gmc function to call to get the message
 * @param gmc_cls closure for gmc
 */
void
GSF_peer_transmit_ (struct GSF_ConnectedPeer *peer,
		    size_t size,
		    GSF_GetMessageCallback gmc,
		    void *gmc_cls);


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
			  const struct GNUNET_TRANSPORT_ATS_Information *atsi);


/**
 * A peer disconnected from us.  Tear down the connected peer
 * record.
 *
 * @param cls unused
 * @param peer identity of peer that connected
 */
void
GSF_peer_disconnect_handler_ (void *cls,
			      const struct GNUNET_PeerIdentity *peer);


/**
 * Signature of function called on a connected peer.
 *
 * @param cls closure
 * @param peer identity of the peer
 * @param cp handle to the connected peer record
 */
typedef void (*GSF_ConnectedPeerIterator)(void *cls,
					  const struct GNUNET_PeerIdentity *peer,
					  struct GSF_ConnectedPeer *cp);


/**
 * Iterate over all connected peers.
 *
 * @param it function to call for each peer
 * @param it_cls closure for it
 */
void
GSF_iterate_connected_peers_ (GSF_ConnectedPeerIterator it,
			      void *it_cls);


/**
 * Register callback to invoke on peer disconnect.
 *
 * @param cp peer to monitor
 * @param it function to call on disconnect
 * @param it_cls closure for it
 */
void
GSF_connected_peer_register_disconnect_callback_ (struct GSF_ConnectedPeer *cp,
						  GSF_ConnectedPeerIterator it,
						  void *it_cls);


/**
 * Unregister callback to invoke on peer disconnect.
 *
 * @param cp peer to stop monitoring
 * @param it function to no longer call on disconnect
 * @param it_cls closure for it
 */
void
GSF_connected_peer_unregister_disconnect_callback_ (struct GSF_ConnectedPeer *cp,
						    GSF_ConnectedPeerIterator it,
						    void *it_cls);


/**
 * Signature of function called on a reservation success.
 *
 * @param cls closure
 * @param cp handle to the connected peer record
 */
typedef void (*GSF_PeerReserveCallback)(void *cls,
					struct GSF_ConnectedPeer *cp);


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
 * @param rc function to call upon reservation success
 * @param rc_cls closure for rc
 */
void
GSF_connected_peer_reserve_ (struct GSF_ConnectedPeer *cp,
			     size_t size,
			     GSF_PeerReserveCallback rc,
			     void *rc_cls);


#endif
/* end of gnunet-service-fs_cp.h */
