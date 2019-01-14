/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010 GNUnet e.V.

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
 * @file peerinfo/peerinfo.h
 * @brief common internal definitions for peerinfo service
 * @author Christian Grothoff
 */

#ifndef PEERINFO_H
#define PEERINFO_H

#include "gnunet_crypto_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_peerinfo_service.h"



GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message requesting a listing of peers,
 * restricted to the specified peer identity.
 */
struct ListPeerMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_PEERINFO_GET
   */
  struct GNUNET_MessageHeader header;

  /**
   * Include friend only HELLOs and peers in callbacks
   */
  uint32_t include_friend_only GNUNET_PACKED;

  /**
   * Restrict to peers with this identity (optional
   * field, check header.size!).
   */
  struct GNUNET_PeerIdentity peer;

};

/**
 * Message requesting a listing of all peers,
 * restricted to the specified peer identity.
 */
struct ListAllPeersMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_PEERINFO_GET_ALL
   */
  struct GNUNET_MessageHeader header;

  /**
   * Include friend only HELLOs and peers in callbacks
   */
  uint32_t include_friend_only GNUNET_PACKED;

};


/**
 * Header for all communications.
 */
struct NotifyMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_PEERINFO_NOTIFY
   */
  struct GNUNET_MessageHeader header;

  /**
   * Include friend only HELLOs and peers in callbacks
   */
  uint32_t include_friend_only GNUNET_PACKED;

};


/**
 * Message used to inform the client about
 * a particular peer; this message is optionally followed
 * by a HELLO message for the respective peer (if available).
 * Check the header.size field to see if a HELLO is
 * present.
 */
struct InfoMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_PEERINFO_INFO
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * About which peer are we talking here?
   */
  struct GNUNET_PeerIdentity peer;

};
GNUNET_NETWORK_STRUCT_END

/*#ifndef PEERINFO_H*/
#endif
/* end of peerinfo.h */
