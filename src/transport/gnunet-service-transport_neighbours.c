/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport_neighbours.c
 * @brief neighbour management
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-transport_neighbours.h"
#include "gnunet-service-transport.h"

// TODO:
// - have a way to access the currently 'connected' session
//   (for sending and to notice disconnect of it!)
// - have a way to access/update bandwidth/quota information per peer
//   (for CostReport/TrafficReport callbacks)



/**
 * Initialize the neighbours subsystem.
 *
 * @param cls closure for callbacks
 * @param connect_cb function to call if we connect to a peer
 * @param disconnect_cb function to call if we disconnect from a peer
 */
void 
GST_neighbours_start (void *cls,
		      GNUNET_TRANSPORT_NotifyConnect connect_cb,
		      GNUNET_TRANSPORT_NotifyDisconnect disconnect_cb)
{
}


/**
 * Cleanup the neighbours subsystem.
 */
void
GST_neighbours_stop ()
{
}


/**
 * Try to create a connection to the given target (eventually).
 *
 * @param target peer to try to connect to
 */
void
GST_neighbours_try_connect (const struct GNUNET_PeerIdentity *target)
{
}


/**
 * Test if we're connected to the given peer.
 * 
 * @param target peer to test
 * @return GNUNET_YES if we are connected, GNUNET_NO if not
 */
int
GST_neighbours_test_connected (const struct GNUNET_PeerIdentity *target)
{
  return GNUNET_NO;
}


/**
 * Transmit a message to the given target using the active connection.
 *
 * @param target destination
 * @param msg message to send
 * @param cont function to call when done
 * @param cont_cls closure for 'cont'
 */
void
GST_neighbours_send (const struct GNUNET_PeerIdentity *target,
		     const struct GNUNET_MessageHeader *msg,
		     GST_NeighbourSendContinuation cont,
		     void *cont_cls)
{
}


/**
 * Change the incoming quota for the given peer.
 *
 * @param neighbour identity of peer to change qutoa for
 * @param quota new quota 
 */
void
GST_neighbours_set_incoming_quota (const struct GNUNET_PeerIdentity *neighbour,
				   struct GNUNET_BANDWIDTH_Value32NBO quota)
{
#if 0

  n = find_neighbour (neighbour);
  if (n == NULL)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# SET QUOTA messages ignored (no such peer)"),
				1,
				GNUNET_NO);
      return;
    }
  GNUNET_BANDWIDTH_tracker_update_quota (&n->in_tracker,
					 quota);
  if (0 != ntohl (qsm->quota.value__))
    return;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Disconnecting peer `%4s' due to `%s'\n",
	      GNUNET_i2s(&n->id),
	      "SET_QUOTA");
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# disconnects due to quota of 0"),
			    1,
			    GNUNET_NO);
  GST_neighbours_force_disconnect (neighbour);

#endif
}


/**
 * If we have an active connection to the given target, it must be shutdown.
 *
 * @param target peer to disconnect from
 */
void
GST_neighbours_force_disconnect (const struct GNUNET_PeerIdentity *target)
{
}


/**
 * Iterate over all connected neighbours.
 *
 * @param cb function to call 
 * @param cb_cls closure for cb
 */
void
GST_neighbours_iterate (GST_NeighbourIterator cb,
			void *cb_cls)
{
}


/**
 * We have received a PONG.  Update lifeness of the neighbour.
 *
 * @param sender peer sending the PONG
 * @param hdr the PONG message (presumably)
 * @param plugin_name name of transport that delivered the PONG
 * @param sender_address address of the other peer, NULL if other peer
 *                       connected to us
 * @param sender_address_len number of bytes in sender_address
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 * @return GNUNET_OK if the message was well-formed, GNUNET_SYSERR if not
 */
int
GST_neighbours_handle_pong (const struct GNUNET_PeerIdentity *sender,
			    const struct GNUNET_MessageHeader *hdr,
			    const char *plugin_name,
			    const void *sender_address,
			    size_t sender_address_len,
			    const struct GNUNET_TRANSPORT_ATS_Information *ats,
			    uint32_t ats_count)
{
  return GNUNET_SYSERR;
}


/**
 * We have received a CONNECT.  Set the peer to connected.
 *
 * @param sender peer sending the PONG
 * @param hdr the PONG message (presumably)
 * @param plugin_name name of transport that delivered the PONG
 * @param sender_address address of the other peer, NULL if other peer
 *                       connected to us
 * @param sender_address_len number of bytes in sender_address
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 * @return GNUNET_OK if the message was well-formed, GNUNET_SYSERR if not
 */
int
GST_neighbours_handle_connect (const struct GNUNET_PeerIdentity *sender,
			       const struct GNUNET_MessageHeader *hdr,
			       const char *plugin_name,
			       const void *sender_address,
			       size_t sender_address_len,
			       const struct GNUNET_TRANSPORT_ATS_Information *ats,
			       uint32_t ats_count)
{
  return GNUNET_SYSERR;
}


/**
 * We have received a DISCONNECT.  Set the peer to disconnected.
 *
 * @param sender peer sending the PONG
 * @param hdr the PONG message (presumably)
 * @param plugin_name name of transport that delivered the PONG
 * @param sender_address address of the other peer, NULL if other peer
 *                       connected to us
 * @param sender_address_len number of bytes in sender_address
 * @return GNUNET_OK if the message was well-formed, GNUNET_SYSERR if not
 */
int
GST_neighbours_handle_disconnect (const struct GNUNET_PeerIdentity *sender,
				  const struct GNUNET_MessageHeader *hdr,
				  const char *plugin_name,
				  const void *sender_address,
				  size_t sender_address_len)
{
  return GNUNET_SYSERR;
}


/* end of file gnunet-service-transport_neighbours.c */
