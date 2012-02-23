/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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
 * @file gns/gns.h
 * @brief IPC messages between GNS API and GNS service
 * @author Martin Schanzenbach
 */
#ifndef GNS_H
#define GNS_H

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message from client to GNS service to lookup records.
 */
struct GNUNET_GNS_ClientLookupMessage
{
  /**
    * Header of type GNUNET_MESSAGE_TYPE_GNS_CLIENT_LOOKUP
   */
  struct GNUNET_MessageHeader header;

  /**
   * A key. TODO some uid
   */
  GNUNET_HashCode key;

  /**
   * Unique identifier for this request (for key collisions).
   */
  // FIXME: unaligned
  uint64_t unique_id;

  /**
   * the type of record to look up
   */
  // FIXME: bad type - should be of GNUNET_GNS_RecordType
  int type;

  /* Followed by the name to look up */
};


/**
 * Message from GNS service to client: new results.
 */
struct GNUNET_GNS_ClientResultMessage
{
  /**
    * Header of type GNUNET_MESSAGE_TYPE_GNS_CLIENT_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  // FIXME: unaligned
  uint64_t unique_id;

  /**
   * A key. TODO some uid
   * // FIXME: why hash?
   */
  GNUNET_HashCode key;

  /**
   * The number of records contained in response
   */  
  uint32_t num_records;

  // FIXME: what format has a GNS_Record?
  /* followed by num_records GNUNET_GNS_Records*/

};


GNUNET_NETWORK_STRUCT_END

#endif
