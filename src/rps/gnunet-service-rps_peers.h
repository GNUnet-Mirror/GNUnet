/*
     This file is part of GNUnet.
     Copyright (C)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file rps/gnunet-service-rps_peers.h
 * @brief utilities for managing (information about) peers
 * @author Julius Bünger
 */
#include "gnunet_util_lib.h"
#include <inttypes.h>
#include "gnunet_cadet_service.h"


/**
 * Different flags indicating the status of another peer.
 */
enum Peers_PeerFlags
{
  /**
   * If we are waiting for a reply from that peer (sent a pull request).
   */
  Peers_PULL_REPLY_PENDING   = 0x01,

  /* IN_OTHER_GOSSIP_LIST = 0x02, unneeded? */
  /* IN_OWN_SAMPLER_LIST  = 0x04, unneeded? */
  /* IN_OWN_GOSSIP_LIST   = 0x08, unneeded? */

  /**
   * We set this bit when we can be sure the other peer is/was live.
   */
  Peers_VALID                = 0x10,

  /**
   * We set this bit when we know the peer is online.
   */
  Peers_ONLINE               = 0x20,

  /**
   * We set this bit when we are going to destroy the channel to this peer.
   * When cleanup_channel is called, we know that we wanted to destroy it.
   * Otherwise the channel to the other peer was destroyed.
   */
  Peers_TO_DESTROY           = 0x40,
};

/**
 * Keep track of the status of a channel.
 *
 * This is needed in order to know what to do with a channel when it's
 * destroyed.
 */
enum Peers_ChannelFlags
{
  /**
   * We destroyed the channel because the other peer established a second one.
   */
  Peers_CHANNEL_ESTABLISHED_TWICE = 0x1,

  /**
   * The channel was removed because it was not needed any more. This should be
   * the sending channel.
   */
  Peers_CHANNEL_CLEAN = 0x2,
};

/**
 * @brief The role of a channel. Sending or receiving.
 */
enum Peers_ChannelRole
{
  /**
   * Channel is used for sending
   */
  Peers_CHANNEL_ROLE_SENDING   = 0x01,

  /**
   * Channel is used for receiving
   */
  Peers_CHANNEL_ROLE_RECEIVING = 0x02,
};

/**
 * @brief Functions of this type can be used to be stored at a peer for later execution.
 *
 * @param cls closure
 * @param peer peer to execute function on
 */
typedef void (* PeerOp) (void *cls, const struct GNUNET_PeerIdentity *peer);

/**
 * @brief Initialise storage of peers
 *
 * @param cadet_h cadet handle
 * @param own_id own peer identity
 */
void
Peers_initialise (struct GNUNET_CADET_Handle *cadet_h,
                  const struct GNUNET_PeerIdentity *own_id);

/**
 * @brief Delete storage of peers that was created with #Peers_initialise ()
 */
void
Peers_terminate ();

/**
 * @brief Add peer to known peers.
 *
 * This function is called on new peer_ids from 'external' sources
 * (client seed, cadet get_peers(), ...)
 *
 * @param peer the new peer
 *
 * @return #GNUNET_YES if peer was inserted
 *         #GNUNET_NO  if peer was already known
 */
int
Peers_insert_peer (const struct GNUNET_PeerIdentity *peer);

/**
 * @brief Remove unecessary data
 * 
 * If the other peer is not intending to send messages, we have messages pending
 * to be sent to this peer and we are not waiting for a reply, remove the
 * information about it (its #PeerContext).
 *
 * @param peer the peer to clean
 * @return #GNUNET_YES if peer was removed
 *         #GNUNET_NO  otherwise
 */
int
Peers_clean_peer (const struct GNUNET_PeerIdentity *peer);

/**
 * @brief Remove peer
 * 
 * @param peer the peer to clean
 * @return #GNUNET_YES if peer was removed
 *         #GNUNET_NO  otherwise
 */
int
Peers_remove_peer (const struct GNUNET_PeerIdentity *peer);

/**
 * @brief set flags on a given peer.
 *
 * @param peer the peer to set flags on
 * @param flags the flags
 */
void
Peers_set_peer_flag (const struct GNUNET_PeerIdentity *peer, enum Peers_PeerFlags flags);

/**
 * @brief unset flags on a given peer.
 *
 * @param peer the peer to unset flags on
 * @param flags the flags
 */
void
Peers_unset_peer_flag (const struct GNUNET_PeerIdentity *peer, enum Peers_PeerFlags flags);

/**
 * @brief Check whether flags on a peer are set.
 *
 * @param peer the peer to check the flag of
 * @param flags the flags to check
 *
 * @return #GNUNET_YES if all given flags are set
 *         ##GNUNET_NO  otherwise
 */
int
Peers_check_peer_flag (const struct GNUNET_PeerIdentity *peer, enum Peers_PeerFlags flags);


/**
 * @brief set flags on a given channel.
 *
 * @param channel the channel to set flags on
 * @param flags the flags
 */
void
Peers_set_channel_flag (uint32_t *channel_flags, enum Peers_ChannelFlags flags);

/**
 * @brief unset flags on a given channel.
 *
 * @param channel the channel to unset flags on
 * @param flags the flags
 */
void
Peers_unset_channel_flag (uint32_t *channel_flags, enum Peers_ChannelFlags flags);

/**
 * @brief Check whether flags on a channel are set.
 *
 * @param channel the channel to check the flag of
 * @param flags the flags to check
 *
 * @return #GNUNET_YES if all given flags are set
 *         #GNUNET_NO  otherwise
 */
int
Peers_check_channel_flag (uint32_t *channel_flags, enum Peers_ChannelFlags flags);

/**
 * @brief Check whether we have information about the given peer.
 *
 * @param peer peer in question
 *
 * @return #GNUNET_YES if peer is known
 *         #GNUNET_NO  if peer is not knwon
 */
int
Peers_check_peer_known (const struct GNUNET_PeerIdentity *peer);

/**
 * @brief Indicate that we want to send to the other peer
 *
 * This establishes a sending channel
 *
 * @param peer the peer to establish channel to
 */
void
Peers_indicate_sending_intention (const struct GNUNET_PeerIdentity *peer);

/**
 * @brief Check whether other peer has the intention to send/opened channel
 *        towars us
 *
 * @param peer the peer in question
 *
 * @return #GNUNET_YES if peer has the intention to send
 *         #GNUNET_NO  otherwise
 */
int
Peers_check_peer_send_intention (const struct GNUNET_PeerIdentity *peer);

/**
 * Handle the channel a peer opens to us.
 *
 * @param cls The closure
 * @param channel The channel the peer wants to establish
 * @param initiator The peer's peer ID
 * @param port The port the channel is being established over
 * @param options Further options
 *
 * @return initial channel context for the channel
 *         (can be NULL -- that's not an error)
 */
void *
Peers_handle_inbound_channel (void *cls,
                              struct GNUNET_CADET_Channel *channel,
                              const struct GNUNET_PeerIdentity *initiator,
                              uint32_t port,
                              enum GNUNET_CADET_ChannelOption options);

/**
 * @brief Check whether a sending channel towards the given peer exists
 *
 * @param peer the peer to check for
 *
 * @return #GNUNET_YES if a sending channel towards that peer exists
 *         #GNUNET_NO  otherwise
 */
int
Peers_check_sending_channel_exists (const struct GNUNET_PeerIdentity *peer);

/**
 * @brief check whether the given channel is the sending channel of the given
 *        peer
 *
 * @param peer the peer in question
 * @param channel the channel to check for
 * @param role either #Peers_CHANNEL_ROLE_SENDING, or
 *                    #Peers_CHANNEL_ROLE_RECEIVING
 *
 * @return #GNUNET_YES if the given chennel is the sending channel of the peer
 *         #GNUNET_NO  otherwise
 */
int
Peers_check_channel_role (const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_CADET_Channel *channel,
                          enum Peers_ChannelRole role);

/**
 * @brief Destroy the send channel of a peer e.g. stop indicating a sending
 *        intention to another peer
 *
 * If there is also no channel to receive messages from that peer, remove it
 * from the peermap.
 *
 * @peer the peer identity of the peer whose sending channel to destroy
 * @return #GNUNET_YES if channel was destroyed
 *         #GNUNET_NO  otherwise
 */
int
Peers_destroy_sending_channel (const struct GNUNET_PeerIdentity *peer);

/**
 * This is called when a channel is destroyed.
 *
 * Removes peer completely from our knowledge if the send_channel was destroyed
 * Otherwise simply delete the recv_channel
 *
 * @param cls The closure
 * @param channel The channel being closed
 * @param channel_ctx The context associated with this channel
 */
void
Peers_cleanup_destroyed_channel (void *cls,
                                 const struct GNUNET_CADET_Channel *channel,
                                 void *channel_ctx);

/**
 * @brief Issue a check whether peer is live
 *
 * This tries to establish a channel to the given peer. Once the channel is
 * established successfully, we know the peer is live.
 *
 * @param peer the peer to check liveliness
 */
void
Peers_issue_peer_liveliness_check (const struct GNUNET_PeerIdentity *peer);

/**
 * @brief Send a message to another peer.
 *
 * Keeps track about pending messages so they can be properly removed when the
 * peer is destroyed.
 *
 * @param peer receeiver of the message
 * @param ev envelope of the message
 * @param type type of the message
 */
void
Peers_send_message (const struct GNUNET_PeerIdentity *peer,
                    struct GNUNET_MQ_Envelope *ev,
                    const char *type);

/**
 * @brief Schedule a operation on given peer
 *
 * Avoids scheduling an operation twice.
 *
 * @param peer the peer we want to schedule the operation for once it gets live
 *
 * @return #GNUNET_YES if the operation was scheduled
 *         #GNUNET_NO  otherwise
 */
int
Peers_schedule_operation (const struct GNUNET_PeerIdentity *peer,
                          const PeerOp peer_op);

/* end of gnunet-service-rps_peers.h */
