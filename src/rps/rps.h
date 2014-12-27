/*
      This file is part of GNUnet
      (C) 2012-2013 Christian Grothoff (and other contributing authors)

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
 * P2P Message to push own ID to other peer.
 */
struct GNUNET_RPS_P2P_PushMessage
{
  /**
   * Header including size and type in NBO
   */
  struct GNUNET_MessageHeader header;

  /** 
   * TODO Proof of work
   */
  uint64_t placeholder;
};

/**
 * P2P Message to request PeerIDs from other peer.
 */
struct GNUNET_RPS_P2P_PullRequestMessage
{
  /**
   * Header including size and type in NBO
   */
  struct GNUNET_MessageHeader header;

  /* This probably stays empty as we just
   * infrom the peer of our existence */
  uint64_t placeholder;
};

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
  uint64_t num_peers GNUNET_PACKED;

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
  uint64_t n;

  /**
   * Number of random peer requested
   */
  uint64_t num_peers GNUNET_PACKED;
};

/**
 * Message from RPS service to client to reply with random peer(s).
 */
struct GNUNET_RPS_CS_ReplyMessage
{
  /**
   * Header including size and type in NBO
   */
  struct GNUNET_MessageHeader header;

  /**
   * Identifyer of the message.
   */
  uint64_t n;

  /**
   * Number of random peer replied
   */
  uint64_t num_peers GNUNET_PACKED;

  /* Followed by num_peers * GNUNET_PeerIdentity */
};

/**
 * Message from client to service with seed of peers
 */
struct GNUNET_RPS_CS_SeedMessage
{
  /**
   * Number of peers
   */
  uint64_t n;

  /**
   * Peers
   */
  struct *GNUNET_PeerIdentity;
};

GNUNET_NETWORK_STRUCT_END
