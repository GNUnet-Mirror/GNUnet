/*
     This file is part of GNUnet.
     Copyright (C) 2010-2015 Christian Grothoff (and other contributing authors)

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
#include "gnunet-service-transport.h"
#include "transport.h"
#include "gnunet_util_lib.h"


/**
 * Initialize the neighbours subsystem.
 *
 * @param max_fds maximum number of fds to use
 */
void
GST_neighbours_start (unsigned int max_fds);


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
 * @return #GNUNET_YES if we are connected, #GNUNET_NO if not
 */
int
GST_neighbours_test_connected (const struct GNUNET_PeerIdentity *target);


/**
 * Function called after the transmission is done.
 *
 * @param cls closure
 * @param success #GNUNET_OK on success, #GNUNET_NO on failure, #GNUNET_SYSERR if we're not connected
 * @param bytes_payload how much payload was transmitted
 * @param bytes_on_wire how many bytes were used on the wire
 */
typedef void
(*GST_NeighbourSendContinuation) (void *cls,
                                  int success,
                                  size_t bytes_payload,
                                  size_t bytes_on_wire);


/**
 * Transmit a message to the given target using the active connection.
 *
 * @param target destination
 * @param msg message to send
 * @param msg_size number of bytes in @a msg
 * @param timeout when to fail with timeout
 * @param cont function to call when done
 * @param cont_cls closure for @a cont
 */
void
GST_neighbours_send (const struct GNUNET_PeerIdentity *target,
                     const void *msg,
                     size_t msg_size,
                     struct GNUNET_TIME_Relative timeout,
                     GST_NeighbourSendContinuation cont, void *cont_cls);


/**
 * We have received a message from the given sender.
 * How long should we delay before receiving more?
 * (Also used to keep the peer marked as live).
 *
 * @param sender sender of the message
 * @param size size of the message
 * @param do_forward set to #GNUNET_YES if the message should be forwarded to clients
 *                   #GNUNET_NO if the neighbour is not connected or violates the quota
 * @return how long to wait before reading more from this sender
 */
struct GNUNET_TIME_Relative
GST_neighbours_calculate_receive_delay (const struct GNUNET_PeerIdentity *sender,
                                        ssize_t size,
                                        int *do_forward);


/**
 * Keep the connection to the given neighbour alive longer,
 * we received a KEEPALIVE (or equivalent); send a response.
 *
 * @param neighbour neighbour to keep alive (by sending keep alive response)
 * @param m the keep alive message containing the nonce to respond to
 */
void
GST_neighbours_keepalive (const struct GNUNET_PeerIdentity *neighbour,
                          const struct GNUNET_MessageHeader *m);


/**
 * We received a KEEP_ALIVE_RESPONSE message and use this to calculate
 * latency to this peer.  Pass the updated information (existing ats
 * plus calculated latency) to ATS.
 *
 * @param neighbour neighbour to keep alive
 * @param m the message containing the keep alive response
 */
void
GST_neighbours_keepalive_response (const struct GNUNET_PeerIdentity *neighbour,
                                   const struct GNUNET_MessageHeader *m);


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
 * Function called for each neighbour.
 *
 * @param cls closure
 * @param peer identity of the neighbour
 * @param address the address of the neighbour
 * @param state current state the peer is in
 * @param state_timeout timeout for this state
 * @param bandwidth_in inbound quota in NBO
 * @param bandwidth_out outbound quota in NBO
 */
typedef void
(*GST_NeighbourIterator) (void *cls,
                          const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_HELLO_Address *address,
                          enum GNUNET_TRANSPORT_PeerState state,
                          struct GNUNET_TIME_Absolute state_timeout,
                          struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                          struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out);


/**
 * Iterate over all connected neighbours.
 *
 * @param cb function to call
 * @param cb_cls closure for @a cb
 */
void
GST_neighbours_iterate (GST_NeighbourIterator cb, void *cb_cls);


/**
 * A session was terminated. Take note.
 *
 * @param peer identity of the peer where the session died
 * @param session session that is gone
 * @return #GNUNET_YES if this was a session used, #GNUNET_NO if
 *        this session was not in use
 */
int
GST_neighbours_session_terminated (const struct GNUNET_PeerIdentity *peer,
                                   struct Session *session);


/**
 * Track information about data we received from the
 * given address (used to notify ATS about our utilization
 * of allocated resources).
 *
 * @param address the address we got data from
 * @param message the message we received (really only the size is used)
 */
void
GST_neighbours_notify_data_recv (const struct GNUNET_HELLO_Address *address,
                                 const struct GNUNET_MessageHeader *message);


/**
 * Track information about payload (useful data) we received from the
 * given address (used to notify ATS about our utilization of
 * allocated resources).
 *
 * @param address the address we got data from
 * @param message the message we received (really only the size is used)
 */
void
GST_neighbours_notify_payload_recv (const struct GNUNET_HELLO_Address *address,
                                    const struct GNUNET_MessageHeader *message);


/**
 * Track information about data we transmitted using the given @a
 * address and @a session (used to notify ATS about our utilization of
 * allocated resources).
 *
 * @param address the address we transmitted data to
 * @param session session we used to transmit data
 * @param message the message we sent (really only the size is used)
 */
void
GST_neighbours_notify_data_sent (const struct GNUNET_HELLO_Address *address,
                                 struct Session *session,
                                 size_t size);


/**
 * Track information about payload (useful data) we transmitted using the
 * given address (used to notify ATS about our utilization of
 * allocated resources).
 *
 * @param address the address we transmitted data to
 * @param message the message we sent (really only the size is used)
 */
void
GST_neighbours_notify_payload_sent (const struct GNUNET_PeerIdentity *peer,
                                    size_t size);



/**
 * For an existing neighbour record, set the active connection to
 * use the given address.
 *
 * @param address address of the other peer to start using
 * @param session session to use (or NULL)
 * @param bandwidth_in inbound quota to be used when connection is up
 * @param bandwidth_out outbound quota to be used when connection is up
 */
void
GST_neighbours_switch_to_address (const struct GNUNET_HELLO_Address *address,
                                  struct Session *session,
                                  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                                  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out);


/**
 * We received a 'SESSION_CONNECT' message from the other peer.
 * Consider switching to it.
 *
 * @param message possibly a 'struct SessionConnectMessage' (check format)
 * @param peer identity of the peer to switch the address for
 * @return #GNUNET_OK if the message was fine, #GNUNET_SYSERR on serious error
 */
int
GST_neighbours_handle_session_syn (const struct GNUNET_MessageHeader *message,
                                   const struct GNUNET_PeerIdentity *peer);


/**
 * We received a 'SESSION_CONNECT_ACK' message from the other peer.
 * Consider switching to it.
 *
 * @param message possibly a `struct SessionConnectMessage` (check format)
 * @param address address of the other peer
 * @param session session to use (or NULL)
 * @return #GNUNET_OK if the message was fine, #GNUNET_SYSERR on serious error
 */
int
GST_neighbours_handle_session_syn_ack (const struct GNUNET_MessageHeader *message,
                                       const struct GNUNET_HELLO_Address *address,
                                       struct Session *session);


/**
 * We received a 'SESSION_ACK' message from the other peer.
 * If we sent a 'CONNECT_ACK' last, this means we are now
 * connected.  Otherwise, do nothing.
 *
 * @param message possibly a 'struct SessionConnectMessage' (check format)
 * @param address address of the other peer
 * @param session session to use (or NULL)
 * @return #GNUNET_OK if the message was fine, #GNUNET_SYSERR on serious error
 */
int
GST_neighbours_handle_session_ack (const struct GNUNET_MessageHeader *message,
				   const struct GNUNET_HELLO_Address *address,
				   struct Session *session);


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
GST_neighbours_handle_disconnect_message (const struct GNUNET_PeerIdentity *peer,
                                          const struct GNUNET_MessageHeader *msg);


#endif
/* end of file gnunet-service-transport_neighbours.h */
