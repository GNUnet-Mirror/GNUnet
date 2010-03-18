/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2009 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 * @author Nathan Evans
 * @file dht/dht.h
 */

#ifndef DHT_H_
#define DHT_H_

#define DEBUG_DHT GNUNET_YES

typedef void (*GNUNET_DHT_MessageReceivedHandler) (void *cls,
                                                  struct GNUNET_MessageHeader *msg);

/**
 * Generic DHT message, wrapper for other message types
 */
struct GNUNET_DHT_StopMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_MESSAGE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID identifying this request
   */
  uint64_t unique_id;

};


/**
 * Generic DHT message, wrapper for other message types
 */
struct GNUNET_DHT_Message
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_MESSAGE
   */
  struct GNUNET_MessageHeader header;

  /**
   * The key to search for
   */
  GNUNET_HashCode key;

  /**
   * Replication level for this message
   */
  uint16_t desired_replication_level;

  /**
   * Message options
   */
  uint16_t options;

  /**
   * Is this message uniquely identified?  If so it will
   * be fire and forget, if not we will wait for a receipt
   * from the service.
   */
  uint16_t unique;


  /**
   * Unique ID identifying this request
   */
  uint64_t unique_id;

  /* */
  /* GNUNET_MessageHeader *enc actual DHT message, copied to end of this dealy do */

};

/**
 * Message to insert data into the DHT
 */
struct GNUNET_DHT_PutMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_PUT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The type of data to insert.
   */
  size_t type;

  /**
   * The size of the data, appended to the end of this message.
   */
  size_t data_size;

  /**
   * How long should this data persist?
   */
  struct GNUNET_TIME_Absolute expiration;

};


/**
 * Message to request data from the DHT
 */
struct GNUNET_DHT_GetMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_GET
   */
  struct GNUNET_MessageHeader header;

  /**
   * The type for the data for the GET request
   */
  size_t type;

};

/**
 * Message to return data from the DHT
 */
struct GNUNET_DHT_GetResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_GET_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The type for the data for the GET request
   */
  size_t type;

  /**
   * The key to search for
   */
  GNUNET_HashCode key;

  /**
   * The size of the data, appended to the end of this message.
   */
  size_t data_size;

};

/**
 * Message to request data from the DHT
 */
struct GNUNET_DHT_FindPeerMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_FIND_PEER
   */
  struct GNUNET_MessageHeader header;

};

/**
 * Message to return data from the DHT
 */
struct GNUNET_DHT_FindPeerResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_FIND_PEER_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The peer that was searched for
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * The size of the HELLO for the returned peer,
   * appended to the end of this message, 0 if
   * no hello.
   */
  size_t data_size;

};

#endif /* DHT_H_ */
