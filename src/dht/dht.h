/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2009 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 * @author Nathan Evans
 * @file dht/dht.h
 */

#ifndef DHT_H_
#define DHT_H_

#define DEBUG_DHT GNUNET_NO

typedef void (*GNUNET_DHT_MessageReceivedHandler) (void *cls,
                                                   const struct GNUNET_MessageHeader
                                                   * msg);

/**
 * Message which indicates the DHT should cancel outstanding
 * requests and discard any state.
 */
struct GNUNET_DHT_StopMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_STOP
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Unique ID identifying this request
   */
  uint64_t unique_id GNUNET_PACKED;

};


/**
 * Generic DHT message, indicates that a route request
 * should be issued.
 */
struct GNUNET_DHT_RouteMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_ROUTE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Message options
   */
  uint32_t options GNUNET_PACKED;

  /**
   * The key to search for
   */
  GNUNET_HashCode key;

  /**
   * Unique ID identifying this request, if 0 then
   * the client will not expect a response
   */
  uint64_t unique_id GNUNET_PACKED;

  /**
   * Replication level for this message
   */
  uint32_t desired_replication_level GNUNET_PACKED;


  /* GNUNET_MessageHeader *enc actual DHT message, copied to end of this dealy do */

};

struct GNUNET_DHT_RouteResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_ROUTE_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Message options
   */
  uint32_t options GNUNET_PACKED;

  /**
   * The key that was searched for
   */
  GNUNET_HashCode key;

  /**
   * Unique ID identifying this request
   */
  uint64_t unique_id GNUNET_PACKED;

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
  size_t type GNUNET_PACKED;

  /**
   * How long should this data persist?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /**
   * The size of the data, appended to the end of this message.
   */
  size_t data_size GNUNET_PACKED;

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
  uint32_t type;

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
  uint32_t type;

  /**
   * The key to search for
   */
  GNUNET_HashCode key;

  /**
   * When does this entry expire?
   */
  struct GNUNET_TIME_Absolute expiration;

};


#endif /* DHT_H_ */
