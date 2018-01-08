/*
      This file is part of GNUnet
      Copyright (C) 2012-2013 GNUnet e.V.

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
 * Message from client to RPS service to request random peer(s).
 */
struct GNUNET_RPS_CS_RequestMessage
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
   * Number of random peer requested
   */
  uint32_t num_peers GNUNET_PACKED;
};

/**
 * Message from RPS service to client to reply with random peer(s).
 */
struct GNUNET_RPS_CS_ReplyMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_RPS_CS_REPLY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Identifyer of the message.
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Number of random peer replied
   */
  uint32_t num_peers GNUNET_PACKED;

  /* Followed by num_peers * GNUNET_PeerIdentity */
};

/**
 * Message from client to RPS service to cancel request.
 */
struct GNUNET_RPS_CS_RequestCancelMessage
{
  /**
   * Header including size and type in NBO
   */
  struct GNUNET_MessageHeader header;

  /**
   * Identifyer of the message.
   */
  uint32_t id GNUNET_PACKED;
};

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

#ifdef ENABLE_MALICIOUS
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


GNUNET_NETWORK_STRUCT_END
