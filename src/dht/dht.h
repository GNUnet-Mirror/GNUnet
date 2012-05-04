/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2009, 2011 Christian Grothoff (and other contributing authors)

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

#ifndef DHT_H
#define DHT_H


/**
 * Size of the bloom filter the DHT uses to filter peers.
 */
#define DHT_BLOOM_SIZE 128


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message which indicates the DHT should cancel outstanding
 * requests and discard any state.
 */
struct GNUNET_DHT_ClientGetStopMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_GET_STOP
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

  /**
   * Key of this request
   */
  GNUNET_HashCode key;

};


/**
 * DHT GET message sent from clients to service. Indicates that a GET
 * request should be issued.
 */
struct GNUNET_DHT_ClientGetMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET
   */
  struct GNUNET_MessageHeader header;

  /**
   * Message options, actually an 'enum GNUNET_DHT_RouteOption' value.
   */
  uint32_t options GNUNET_PACKED;

  /**
   * Replication level for this message
   */
  uint32_t desired_replication_level GNUNET_PACKED;

  /**
   * The type for the data for the GET request; actually an 'enum
   * GNUNET_BLOCK_Type'.
   */
  uint32_t type;

  /**
   * The key to search for
   */
  GNUNET_HashCode key;

  /**
   * Unique ID identifying this request, if 0 then
   * the client will not expect a response
   */
  uint64_t unique_id GNUNET_PACKED;

  /* Possibly followed by xquery, copied to end of this dealy do */

};


/**
 * Reply to a GET send from the service to a client.
 */
struct GNUNET_DHT_ClientResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_CLIENT_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The type for the data.
   */
  uint32_t type;

  /**
   * Number of peers recorded in the outgoing path from source to the
   * storgage location of this message.
   */
  uint32_t put_path_length GNUNET_PACKED;

  /**
   * The number of peer identities recorded from the storage location
   * to this peer.
   */
  uint32_t get_path_length GNUNET_PACKED;

  /**
   * Unique ID of the matching GET request.
   */
  uint64_t unique_id GNUNET_PACKED;

  /**
   * When does this entry expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /**
   * The key that was searched for
   */
  GNUNET_HashCode key;

  /* put path, get path and actual data are copied to end of this dealy do */

};


/**
 * Message to insert data into the DHT, sent from clients to DHT service.
 */
struct GNUNET_DHT_ClientPutMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The type of data to insert.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Message options, actually an 'enum GNUNET_DHT_RouteOption' value.
   */
  uint32_t options GNUNET_PACKED;

  /**
   * Replication level for this message
   */
  uint32_t desired_replication_level GNUNET_PACKED;

  /**
   * Unique ID for the PUT message.
   */
  uint64_t unique_id GNUNET_PACKED;

  /**
   * How long should this data persist?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /**
   * The key to store the value under.
   */
  GNUNET_HashCode key;

  /* DATA copied to end of this message */

};


/**
 * Message to confirming receipt of PUT, sent from DHT service to clients.
 */
struct GNUNET_DHT_ClientPutConfirmationMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT_OK
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Unique ID from the PUT message that is being confirmed.
   */
  uint64_t unique_id GNUNET_PACKED;

};



/**
 * Message to monitor put requests going through peer, DHT service -> clients.
 */
struct GNUNET_DHT_MonitorPutMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Message options, actually an 'enum GNUNET_DHT_RouteOption' value.
   */
  uint32_t options GNUNET_PACKED;

  /**
   * The type of data in the request.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Hop count so far.
   */
  uint32_t hop_count GNUNET_PACKED;
  
  /**
   * Replication level for this message
   */
  uint32_t desired_replication_level GNUNET_PACKED;

  /**
   * Number of peers recorded in the outgoing path from source to the
   * storage location of this message.
   */
  uint32_t put_path_length GNUNET_PACKED;

  /**
   * How long should this data persist?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * The key to store the value under.
   */
  GNUNET_HashCode key;

  /* put path (if tracked) */

  /* Payload */

};


/**
 * Message to request monitoring messages, clients -> DHT service.
 */
struct GNUNET_DHT_MonitorStartStopMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_MONITOR_(START|STOP)
   */
  struct GNUNET_MessageHeader header;

  /**
   * The type of data desired, GNUNET_BLOCK_TYPE_ANY for all.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Flag whether to notify about GET messages.
   */
  int16_t get GNUNET_PACKED;

  /**
   * Flag whether to notify about GET_REPONSE messages.
   */
  int16_t get_resp GNUNET_PACKED;

  /**
   * Flag whether to notify about PUT messages.
   */
  int16_t put GNUNET_PACKED;

  /**
   * Flag whether to use the provided key to filter messages.
   */
  int16_t filter_key GNUNET_PACKED;

  /**
   * The key to filter messages by.
   */
  GNUNET_HashCode key;
};


/**
 * Message to monitor get requests going through peer, DHT service -> clients.
 */
struct GNUNET_DHT_MonitorGetMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Message options, actually an 'enum GNUNET_DHT_RouteOption' value.
   */
  uint32_t options GNUNET_PACKED;

  /**
   * The type of data in the request.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Hop count
   */
  uint32_t hop_count GNUNET_PACKED;
  
  /**
   * Replication level for this message
   */
  uint32_t desired_replication_level GNUNET_PACKED;

  /**
   * Number of peers recorded in the outgoing path from source to the
   * storage location of this message.
   */
  uint32_t get_path_length GNUNET_PACKED;

  /**
   * The key to store the value under.
   */
  GNUNET_HashCode key;

  /* get path (if tracked) */

};

/**
 * Message to monitor get results going through peer, DHT service -> clients.
 */
struct GNUNET_DHT_MonitorGetRespMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Content type.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Length of the PUT path that follows (if tracked).
   */
  uint32_t put_path_length GNUNET_PACKED;

  /**
   * Length of the GET path that follows (if tracked).
   */
  uint32_t get_path_length GNUNET_PACKED;

  /**
   * When does the content expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * The key of the corresponding GET request.
   */
  GNUNET_HashCode key;

  /* put path (if tracked) */

  /* get path (if tracked) */

  /* Payload */

};

GNUNET_NETWORK_STRUCT_END

#endif
