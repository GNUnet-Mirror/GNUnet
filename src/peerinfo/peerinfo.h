/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file peerinfo/peerinfo.h
 * @brief common internal definitions for peerinfo service
 * @author Christian Grothoff
 */
#include "gnunet_crypto_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_peerinfo_service.h"

#define DEBUG_PEERINFO GNUNET_EXTRA_LOGGING

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message requesting a listing of all known peers,
 * possibly restricted to the specified peer identity.
 */
struct ListPeerMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_PEERINFO_GET
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Restrict to peers with this identity (optional
   * field, check header.size!).
   */
  struct GNUNET_PeerIdentity peer;

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

/* end of peerinfo.h */
