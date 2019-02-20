/*
      This file is part of GNUnet
      Copyright (C) 2012-2013 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU Affero General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.
     
      You should have received a copy of the GNU Affero General Public License
      along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file rps/rps.h
 * @brief example IPC messages between RPS API and GNS service
 * @author Julius Bünger
 */

#include "gnunet_rps_service.h"

/**
 * Mesh port used by RPS.
 */
#define GNUNET_RPS_CADET_PORT 31337


GNUNET_NETWORK_STRUCT_BEGIN

/***********************************************************************
 * P2P Messages
***********************************************************************/

/**
 * P2P Message to send PeerIDs to other peer.
 */
struct GNUNET_RPS_P2P_PullReplyMessage
{
  /**
   * Header including size and type in NBO
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of PeerIDs sent
   */
  uint32_t num_peers GNUNET_PACKED;

  /* Followed by num_peers * GNUNET_PeerIdentity */
};



/***********************************************************************
 * Client-Service Messages
***********************************************************************/

/**
 * Message from client to service with seed of peers.
 */
struct GNUNET_RPS_CS_SeedMessage
{
  /**
   * Header including size and type in NBO
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of peers
   */
  uint32_t num_peers GNUNET_PACKED;

  /* Followed by num_peers * GNUNET_PeerIdentity */
};

#if ENABLE_MALICIOUS
/**
 * Message from client to service to turn service malicious.
 */
struct GNUNET_RPS_CS_ActMaliciousMessage
{
  /**
   * Header including size and type in NBO
   */
  struct GNUNET_MessageHeader header;

  /**
   * If the type is 2 this is the attacked peer,
   * empty otherwise.
   */
  struct GNUNET_PeerIdentity attacked_peer;

  /**
   * Type of malicious behaviour.
   *
   * 0 No malicious bahaviour at all
   * 1 Try to maximise representation
   * 2 Try to partition the network
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Number of peers
   */
  uint32_t num_peers GNUNET_PACKED;

  /* Followed by num_peers * GNUNET_PeerIdentity when the type of malicious
     behaviour is 1 */
};
#endif /* ENABLE_MALICIOUS */


/**
 * Message from client to service telling it to start a new sub
 */
struct GNUNET_RPS_CS_SubStartMessage
{
  /**
   * Header including size and type in NBO
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Mean interval between two rounds
   */
  struct GNUNET_TIME_RelativeNBO round_interval;

  /**
   * Length of the shared value represented as string.
   */
  struct GNUNET_HashCode hash GNUNET_PACKED;
};


/**
 * Message from client to service telling it to stop a new sub
 */
struct GNUNET_RPS_CS_SubStopMessage
{
  /**
   * Header including size and type in NBO
   */
  struct GNUNET_MessageHeader header;

  /**
   * Length of the shared value represented as string.
   */
  struct GNUNET_HashCode hash GNUNET_PACKED;
};


/* Debug messages */

/**
 * Message from client to service indicating that
 * clients wants to get updates of the view
 */
struct GNUNET_RPS_CS_DEBUG_ViewRequest
{
  /**
   * Header including size and type in NBO
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of updates
   * 0 for sending updates until cancellation
   */
  uint32_t num_updates GNUNET_PACKED;
};

/**
 * Message from service to client containing current update of view
 */
struct GNUNET_RPS_CS_DEBUG_ViewReply
{
  /**
   * Header including size and type in NBO
   */
  struct GNUNET_MessageHeader header;

  /**
   * Identifyer of the message.
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Number of peers in the view
   */
  uint64_t num_peers GNUNET_PACKED;
};
  /* Followed by num_peers * GNUNET_PeerIdentity */

/**
 * Message from client to service indicating that
 * clients wants to get stream of biased peers
 */
struct GNUNET_RPS_CS_DEBUG_StreamRequest
{
  /**
   * Header including size and type in NBO
   */
  struct GNUNET_MessageHeader header;
};

/**
 * Message from service to client containing peer from biased stream
 */
struct GNUNET_RPS_CS_DEBUG_StreamReply
{
  /**
   * Header including size and type in NBO
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of peers
   */
  uint64_t num_peers GNUNET_PACKED;

  // TODO maybe source of peer (pull/push list, peerinfo, ...)

  /* Followed by num_peers * GNUNET_PeerIdentity */
};

GNUNET_NETWORK_STRUCT_END

/***********************************************************************
 * Defines from old gnunet-service-rps_peers.h
***********************************************************************/

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

  /**
   * We destroyed the channel because the other peer established a second one.
   */
  Peers_CHANNEL_DESTROING = 0x4,
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
 * @brief Iterator over valid peers.
 *
 * @param cls closure
 * @param peer current public peer id
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
typedef int
(*PeersIterator) (void *cls,
                  const struct GNUNET_PeerIdentity *peer);


/**
 * Handle to the statistics service.
 */
extern struct GNUNET_STATISTICS_Handle *stats;

