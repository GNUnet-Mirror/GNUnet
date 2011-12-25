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

#include "fs.h"
#include "gnunet-service-fs.h"


/**
 * Maximum number of outgoing messages we queue per peer.
 *
 * Performance measurements for 2 peer setup for 50 MB file
 * (with MAX_DATASTORE_QUEUE = 1 and RETRY_PROBABILITY_INV = 1):
 *
 *   2: 1700 kb/s, 1372 kb/s
 *   8: 2117 kb/s, 1284 kb/s, 1112 kb/s
 *  16: 3500 kb/s, 3200 kb/s, 3388 kb/s
 *  32: 3441 kb/s, 3163 kb/s, 3277 kb/s
 * 128: 1700 kb/s; 2010 kb/s, 3383 kb/s, 1156 kb/s
 *
 * Conclusion: 16 seems to be a pretty good value (stable
 * and high performance, no excessive memory use).
 */
#define MAX_QUEUE_PER_PEER 16

/**
 * Length of the P2P success tracker.  Note that having a very long
 * list can also hurt performance.
 */
#define P2P_SUCCESS_LIST_SIZE 8

/**
 * Length of the CS-2-P success tracker.  Note that
 * having a very long list can also hurt performance.
 */
#define CS2P_SUCCESS_LIST_SIZE 8


/**
 * Performance data kept for a peer.
 */
struct GSF_PeerPerformanceData
{

  /**
   * Transport performance data.
   */
  struct GNUNET_ATS_Information *atsi;

  /**
   * List of the last clients for which this peer successfully
   * answered a query.
   */
  struct GSF_LocalClient *last_client_replies[CS2P_SUCCESS_LIST_SIZE];

  /**
   * List of the last PIDs for which
   * this peer successfully answered a query;
   * We use 0 to indicate no successful reply.
   */
  GNUNET_PEER_Id last_p2p_replies[P2P_SUCCESS_LIST_SIZE];

  /**
   * Average delay between sending the peer a request and
   * getting a reply (only calculated over the requests for
   * which we actually got a reply).   Calculated
   * as a moving average: new_delay = ((n-1)*last_delay+curr_delay) / n
   */
  struct GNUNET_TIME_Relative avg_reply_delay;

  /**
   * If we get content we already have from this peer, for how
   * long do we block him?  Adjusted based on the fraction of
   * redundant data we receive, between 1s and 1h.
   */
  struct GNUNET_TIME_Relative migration_delay;

  /**
   * Point in time until which this peer does not want us to migrate content
   * to it.
   */
  struct GNUNET_TIME_Absolute migration_blocked_until;

  /**
   * Transmission times for the last MAX_QUEUE_PER_PEER
   * requests for this peer.  Used as a ring buffer, current
   * offset is stored in 'last_request_times_off'.  If the
   * oldest entry is more recent than the 'avg_delay', we should
   * not send any more requests right now.
   */
  struct GNUNET_TIME_Absolute last_request_times[MAX_QUEUE_PER_PEER];

  /**
   * How long does it typically take for us to transmit a message
   * to this peer?  (delay between the request being issued and
   * the callback being invoked).
   */
  struct GNUNET_LOAD_Value *transmission_delay;

  /**
   * Average priority of successful replies.  Calculated
   * as a moving average: new_avg = ((n-1)*last_avg+curr_prio) / n
   */
  double avg_priority;

  /**
   * The peer's identity.
   */
  GNUNET_PEER_Id pid;

  /**
   * Trust rating for this peer
   */
  uint32_t trust;

  /**
   * Number of pending queries (replies are not counted)
   */
  unsigned int pending_queries;

  /**
   * Number of pending replies (queries are not counted)
   */
  unsigned int pending_replies;

};


/**
 * Signature of function called on a connected peer.
 *
 * @param cls closure
 * @param peer identity of the peer
 * @param cp handle to the connected peer record
 * @param perf peer performance data
 */
typedef void (*GSF_ConnectedPeerIterator) (void *cls,
                                           const struct GNUNET_PeerIdentity *
                                           peer, struct GSF_ConnectedPeer * cp,
                                           const struct GSF_PeerPerformanceData
                                           * ppd);


/**
 * Function called to get a message for transmission.
 *
 * @param cls closure
 * @param buf_size number of bytes available in buf
 * @param buf where to copy the message, NULL on error (peer disconnect)
 * @return number of bytes copied to 'buf', can be 0 (without indicating an error)
 */
typedef size_t (*GSF_GetMessageCallback) (void *cls, size_t buf_size,
                                          void *buf);


/**
 * Signature of function called on a reservation success or failure.
 *
 * @param cls closure
 * @param cp handle to the connected peer record
 * @param success GNUNET_YES on success, GNUNET_NO on failure
 */
typedef void (*GSF_PeerReserveCallback) (void *cls,
                                         struct GSF_ConnectedPeer * cp,
                                         int success);


/**
 * Handle to cancel a transmission request.
 */
struct GSF_PeerTransmitHandle;


/**
 * A peer connected to us.  Setup the connected peer
 * records.
 *
 * @param peer identity of peer that connected
 * @param atsi performance data for the connection
 * @param atsi_count number of records in 'atsi'
 * @return handle to connected peer entry
 */
struct GSF_ConnectedPeer *
GSF_peer_connect_handler_ (const struct GNUNET_PeerIdentity *peer,
                           const struct GNUNET_ATS_Information *atsi,
                           unsigned int atsi_count);


/**
 * Get a handle for a connected peer.
 *
 * @param peer peer's identity
 * @return NULL if this peer is not currently connected
 */
struct GSF_ConnectedPeer *
GSF_peer_get_ (const struct GNUNET_PeerIdentity *peer);


/**
 * Transmit a message to the given peer as soon as possible.
 * If the peer disconnects before the transmission can happen,
 * the callback is invoked with a 'NULL' buffer.
 *
 * @param cp target peer
 * @param is_query is this a query (GNUNET_YES) or content (GNUNET_NO)
 * @param priority how important is this request?
 * @param timeout when does this request timeout (call gmc with error)
 * @param size number of bytes we would like to send to the peer
 * @param gmc function to call to get the message
 * @param gmc_cls closure for gmc
 * @return handle to cancel request
 */
struct GSF_PeerTransmitHandle *
GSF_peer_transmit_ (struct GSF_ConnectedPeer *cp, int is_query,
                    uint32_t priority, struct GNUNET_TIME_Relative timeout,
                    size_t size, GSF_GetMessageCallback gmc, void *gmc_cls);


/**
 * Cancel an earlier request for transmission.
 *
 * @param pth request to cancel
 */
void
GSF_peer_transmit_cancel_ (struct GSF_PeerTransmitHandle *pth);


/**
 * Report on receiving a reply; update the performance record of the given peer.
 *
 * @param cp responding peer (will be updated)
 * @param request_time time at which the original query was transmitted
 * @param request_priority priority of the original request
 */
void
GSF_peer_update_performance_ (struct GSF_ConnectedPeer *cp,
                              struct GNUNET_TIME_Absolute request_time,
                              uint32_t request_priority);


/**
 * Report on receiving a reply in response to an initiating client.
 * Remember that this peer is good for this client.
 *
 * @param cp responding peer (will be updated)
 * @param initiator_client local client on responsible for query
 */
void
GSF_peer_update_responder_client_ (struct GSF_ConnectedPeer *cp,
                                   struct GSF_LocalClient *initiator_client);


/**
 * Report on receiving a reply in response to an initiating peer.
 * Remember that this peer is good for this initiating peer.
 *
 * @param cp responding peer (will be updated)
 * @param initiator_peer other peer responsible for query
 */
void
GSF_peer_update_responder_peer_ (struct GSF_ConnectedPeer *cp,
                                 const struct GSF_ConnectedPeer
                                 *initiator_peer);


/**
 * Handle P2P "MIGRATION_STOP" message.
 *
 * @param cls closure, always NULL
 * @param other the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @param atsi performance information
 * @param atsi_count number of records in 'atsi'
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GSF_handle_p2p_migration_stop_ (void *cls,
                                const struct GNUNET_PeerIdentity *other,
                                const struct GNUNET_MessageHeader *message,
                                const struct GNUNET_ATS_Information *atsi,
                                unsigned int atsi_count);


/**
 * Handle P2P "QUERY" message.  Only responsible for creating the
 * request entry itself and setting up reply callback and cancellation
 * on peer disconnect.  Does NOT execute the actual request strategy
 * (planning) or local database operations.
 *
 * @param other the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @return pending request handle, NULL on error
 */
struct GSF_PendingRequest *
GSF_handle_p2p_query_ (const struct GNUNET_PeerIdentity *other,
                       const struct GNUNET_MessageHeader *message);


/**
 * Return the performance data record for the given peer
 *
 * @param cp peer to query
 * @return performance data record for the peer
 */
struct GSF_PeerPerformanceData *
GSF_get_peer_performance_data_ (struct GSF_ConnectedPeer *cp);


/**
 * Ask a peer to stop migrating data to us until the given point
 * in time.
 *
 * @param cp peer to ask
 * @param block_time until when to block
 */
void
GSF_block_peer_migration_ (struct GSF_ConnectedPeer *cp,
                           struct GNUNET_TIME_Absolute block_time);


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
 * Notification that a local client disconnected.  Clean up all of our
 * references to the given handle.
 *
 * @param lc handle to the local client (henceforth invalid)
 */
void
GSF_handle_local_client_disconnect_ (const struct GSF_LocalClient *lc);


/**
 * Notify core about a preference we have for the given peer
 * (to allocate more resources towards it).  The change will
 * be communicated the next time we reserve bandwidth with
 * core (not instantly).
 *
 * @param cp peer to reserve bandwidth from
 * @param pref preference change
 */
void
GSF_connected_peer_change_preference_ (struct GSF_ConnectedPeer *cp,
                                       uint64_t pref);


/**
 * Obtain the identity of a connected peer.
 *
 * @param cp peer to reserve bandwidth from
 * @param id identity to set (written to)
 */
void
GSF_connected_peer_get_identity_ (const struct GSF_ConnectedPeer *cp,
                                  struct GNUNET_PeerIdentity *id);


/**
 * Iterate over all connected peers.
 *
 * @param it function to call for each peer
 * @param it_cls closure for it
 */
void
GSF_iterate_connected_peers_ (GSF_ConnectedPeerIterator it, void *it_cls);


/**
 * Initialize peer management subsystem.
 */
void
GSF_connected_peer_init_ (void);


/**
 * Shutdown peer management subsystem.
 */
void
GSF_connected_peer_done_ (void);


#endif
/* end of gnunet-service-fs_cp.h */
