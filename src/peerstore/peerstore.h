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
 * @file peerstore/peerstore.h
 * @brief IPC messages
 * @author Omar Tarabai
 */

#include "gnunet_peerstore_service.h"


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message carrying a PEERSTORE store request
 */
struct StoreRequestMessage
{

  /**
   * GNUnet message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * Peer Identity
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Size of the sub_system string
   * Allocated at position 0 after this struct
   */
  size_t sub_system_size;

  /**
   * Size of value blob
   * Allocated at position 1 after this struct
   */
  size_t value_size;

  /**
   * Lifetime of entry
   */
  struct GNUNET_TIME_Relative lifetime;

};

/**
 * Message carrying a PEERSTORE store response
 */
struct StoreResponseMessage
{
  /**
   * GNUnet message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * Was the store operation successful (#GNUNET_YES / #GNUNET_NO)
   */
  uint16_t success GNUNET_PACKED;

  /**
   * Size of the error message (0 if no error)
   */
  size_t emsg_size GNUNET_PACKED;
};

GNUNET_NETWORK_STRUCT_END
