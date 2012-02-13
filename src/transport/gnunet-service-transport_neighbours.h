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
 * @file transport/gnunet-service-transport_neighbours.h
 * @brief neighbour management API
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_NEIGHBOURS_H
#define GNUNET_SERVICE_TRANSPORT_NEIGHBOURS_H

#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "gnunet_util_lib.h"

// TODO:
// - ATS and similar info is a bit lacking in the API right now...



/**
 * Initialize the neighbours subsystem.
 *
 * @param cls closure for callbacks
 * @param connect_cb function to call if we connect to a peer
 * @param disconnect_cb function to call if we disconnect from a peer
 * @param peer_address_cb function to call if a neighbour's active address changes
 */
void
GST_neighbours_start (void *cls,
                      GNUNET_TRANSPORT_NotifyConnect connect_cb,
                      GNUNET_TRANSPORT_NotifyDisconnect disconnect_cb,
                      GNUNET_TRANSPORT_PeerIterateCallback peer_address_cb);


/**
 * Cleanup the neighbours subsystem.
 */
void
GST_neighbours_stop (void);


/**
 * Try to create a connection to the given target (eventually).
 *
 * @param target peer to try to connect to
 */
void
GST_neighbours_try_connect (const struct GNUNET_PeerIdentity *target);


/**
 * Test if we're connected to the given peer.
 *
 * @param target peer to test
 * @return GNUNET_YES if we are connected, GNUNET_NO if not
 */
int
GST_neighbours_test_connected (const struct GNUNET_PeerIdentity *target);


/**
 * Function called after the transmission is done.
 *
 * @param cls closure
 * @param success GNUNET_OK on success, GNUNET_NO on failure, GNUNET_SYSERR if we're not connected
 */
typedef void (*GST_NeighbourSendContinuation) (void *cls, int success);


/**
 * Transmit a message to the given target using the active connection.
 *
 * @param target destination
 * @param msg message to send
 * @param msg_size number of bytes in msg
 * @param timeout when to fail with timeout
 * @param cont function to call when done
 * @param cont_cls closure for 'cont'
 */
void
GST_neighbours_send (const struct GNUNET_PeerIdentity *target, const void *msg,
                     size_t msg_size, struct GNUNET_TIME_Relative timeout,
                     GST_NeighbourSendContinuation cont, void *cont_cls);


/**
 * We have received a message from the given sender.
 * How long should we delay before receiving more?
 * (Also used to keep the peer marked as live).
 *
 * @param sender sender of the message
 * @param size size of the message
 * @param do_forward set to GNUNET_YES if the message should be forwarded to clients
 *                   GNUNET_NO if the neighbour is not connected or violates the quota
 * @return how long to wait before reading more from this sender
 */
struct GNUNET_TIME_Relative
GST_neighbours_calculate_receive_delay (const struct GNUNET_PeerIdentity
                                        *sender, ssize_t size, int *do_forward);


/**
 * Keep the connection to the given neighbour alive longer,
 * we received a KEEPALIVE (or equivalent).
 *
 * @param neighbour neighbour to keep alive
 */
void
GST_neighbours_keepalive (const struct GNUNET_PeerIdentity *neighbour);

/**
 * We received a KEEP_ALIVE_RESPONSE message and use this to calculate latency
 * to this peer
 *
 * @param neighbour neighbour to keep alive
 * @param ats performance data
 * @param ats_count number of entries in ats
 */
void
GST_neighbours_keepalive_response (const struct GNUNET_PeerIdentity *neighbour,
                                   const struct GNUNET_ATS_Information *ats,
                                   uint32_t ats_count);


/**
 * Change the incoming quota for the given peer.
 *
 * @param neighbour identity of peer to change qutoa for
 * @param quota new quota
 */
void
GST_neighbours_set_incoming_quota (const struct GNUNET_PeerIdentity *neighbour,
                                   struct GNUNET_BANDWIDTH_Value32NBO quota);


/**
 * If we have an active connection to the given target, it must be shutdown.
 *
 * @param target peer to disconnect from
 */
void
GST_neighbours_force_disconnect (const struct GNUNET_PeerIdentity *target);


/**
 * Function called for each connected neighbour.
 *
 * @param cls closure
 * @param neighbour identity of the neighbour
 * @param ats performance data
 * @param ats_count number of entries in ats (including 0-termination)
 * @param address the address (or NULL)
 */
typedef void (*GST_NeighbourIterator) (void *cls,
                                       const struct GNUNET_PeerIdentity *
                                       neighbour,
                                       const struct GNUNET_ATS_Information *
                                       ats, uint32_t ats_count,
                                       const struct GNUNET_HELLO_Address *
                                       address);


/**
 * Iterate over all connected neighbours.
 *
 * @param cb function to call
 * @param cb_cls closure for cb
 */
void
GST_neighbours_iterate (GST_NeighbourIterator cb, void *cb_cls);


/**
 * A session was terminated. Take note.
 *
 * @param peer identity of the peer where the session died
 * @param session session that is gone
 */
void
GST_neighbours_session_terminated (const struct GNUNET_PeerIdentity *peer,
                                   struct Session *session);


/**
 * For an existing neighbour record, set the active connection to
 * use the given address.
 *
 * @param peer identity of the peer to switch the address for
 * @param address address of the other peer, NULL if other peer
 *                       connected to us
 * @param session session to use (or NULL)
 * @param ats performance data
 * @param ats_count number of entries in ats
 * @param bandwidth_in inbound quota to be used when connection is up
 * @param bandwidth_out outbound quota to be used when connection is up
 * @return GNUNET_YES if we are currently connected, GNUNET_NO if the
 *         connection is not up (yet)
 */
int
GST_neighbours_switch_to_address (const struct GNUNET_PeerIdentity *peer,
                                       const struct GNUNET_HELLO_Address
                                       *address, struct Session *session,
                                       const struct GNUNET_ATS_Information *ats,
                                       uint32_t ats_count,
                                       struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                                       struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out);


/**
 * We received a 'SESSION_CONNECT' message from the other peer.
 * Consider switching to it.
 *
 * @param message possibly a 'struct SessionConnectMessage' (check format)
 * @param peer identity of the peer to switch the address for
 * @param address address of the other peer, NULL if other peer
 *                       connected to us
 * @param session session to use (or NULL)
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
  */
void
GST_neighbours_handle_connect (const struct GNUNET_MessageHeader *message,
                               const struct GNUNET_PeerIdentity *peer,
                               const struct GNUNET_HELLO_Address *address,
                               struct Session *session,
                               const struct GNUNET_ATS_Information *ats,
                               uint32_t ats_count);


/**
 * We received a 'SESSION_CONNECT_ACK' message from the other peer.
 * Consider switching to it.
 *
 * @param message possibly a 'struct SessionConnectMessage' (check format)
 * @param peer identity of the peer to switch the address for
 * @param address address of the other peer, NULL if other peer
 *                       connected to us
 * @param session session to use (or NULL)
 * @param ats performance data
 * @param ats_count number of entries in ats
 */
void
GST_neighbours_handle_connect_ack (const struct GNUNET_MessageHeader *message,
                                   const struct GNUNET_PeerIdentity *peer,
                                   const struct GNUNET_HELLO_Address *address,
                                   struct Session *session,
                                   const struct GNUNET_ATS_Information *ats,
                                   uint32_t ats_count);

void
GST_neighbours_handle_ack (const struct GNUNET_MessageHeader *message,
                           const struct GNUNET_PeerIdentity *peer,
                           const struct GNUNET_HELLO_Address *address,
                           struct Session *session,
                           const struct GNUNET_ATS_Information *ats,
                           uint32_t ats_count);


/**
 * Obtain current latency information for the given neighbour.
 *
 * @param peer
 * @return observed latency of the address, FOREVER if the address was
 *         never successfully validated
 */
struct GNUNET_TIME_Relative
GST_neighbour_get_latency (const struct GNUNET_PeerIdentity *peer);


/**
 * Obtain current address information for the given neighbour.
 *
 * @param peer
 * @return address currently used
 */
struct GNUNET_HELLO_Address *
GST_neighbour_get_current_address (const struct GNUNET_PeerIdentity *peer);


/**
 * We received a disconnect message from the given peer,
 * validate and process.
 *
 * @param peer sender of the message
 * @param msg the disconnect message
 */
void
GST_neighbours_handle_disconnect_message (const struct GNUNET_PeerIdentity
                                          *peer,
                                          const struct GNUNET_MessageHeader
                                          *msg);


#endif
/* end of file gnunet-service-transport_neighbours.h */
