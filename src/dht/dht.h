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
   * The key to insert data under.
   */
  GNUNET_HashCode key;

  /**
   * The size of the data, appended to the end of this message.
   */
  size_t data_size;

  /**
   * How long should this data persist?
   */
  struct GNUNET_TIME_Relative timeout;

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

  /**
   * The key to search for
   */
  GNUNET_HashCode key;

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
 * Response to PUT request from the DHT
 */
struct GNUNET_DHT_PutResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_PUT_RESULT
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
   * Was the put successful?  GNUNET_YES or GNUNET_NO
   */
  size_t result;

};



#endif /* DHT_H_ */
