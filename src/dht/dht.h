/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2003, 2004, 2009, 2011 GNUnet e.V.

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
struct GNUNET_DHT_ClientGetStopMessage {
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_STOP
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
  struct GNUNET_HashCode key;
};


/**
 * DHT GET message sent from clients to service. Indicates that a GET
 * request should be issued.
 */
struct GNUNET_DHT_ClientGetMessage {
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET
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
  uint32_t type GNUNET_PACKED;

  /**
   * The key to search for
   */
  struct GNUNET_HashCode key GNUNET_PACKED;

  /**
   * Unique ID identifying this request, if 0 then
   * the client will not expect a response
   */
  uint64_t unique_id GNUNET_PACKED;

  /* Possibly followed by xquery, copied to end of this dealy do */
};


/**
 * DHT GET RESULTS KNOWN message sent from clients to service. Indicates that a GET
 * request should exclude certain results which are already known.
 */
struct GNUNET_DHT_ClientGetResultSeenMessage {
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_RESULTS_KNOWN
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved, always 0.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * The key we are searching for (to make it easy to find the corresponding
   * GET inside the service).
   */
  struct GNUNET_HashCode key GNUNET_PACKED;

  /**
   * Unique ID identifying this request.
   */
  uint64_t unique_id GNUNET_PACKED;

  /* Followed by an array of the hash codes of known results */
};



/**
 * Reply to a GET send from the service to a client.
 */
struct GNUNET_DHT_ClientResultMessage {
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_CLIENT_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The type for the data.
   */
  uint32_t type GNUNET_PACKED;

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
  struct GNUNET_HashCode key GNUNET_PACKED;

  /* put path, get path and actual data are copied to end of this dealy do */
};


/**
 * Message to insert data into the DHT, sent from clients to DHT service.
 */
struct GNUNET_DHT_ClientPutMessage {
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT
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
   * How long should this data persist?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /**
   * The key to store the value under.
   */
  struct GNUNET_HashCode key GNUNET_PACKED;

  /* DATA copied to end of this message */
};


/**
 * Message to monitor put requests going through peer, DHT service -> clients.
 */
struct GNUNET_DHT_MonitorPutMessage {
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT
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
  struct GNUNET_HashCode key GNUNET_PACKED;

  /* put path (if tracked) */

  /* Payload */
};


/**
 * Message to request monitoring messages, clients -> DHT service.
 */
struct GNUNET_DHT_MonitorStartStopMessage {
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_MONITOR_START or
   * #GNUNET_MESSAGE_TYPE_DHT_MONITOR_STOP
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
  struct GNUNET_HashCode key GNUNET_PACKED;
};


/**
 * Message to monitor get requests going through peer, DHT service -> clients.
 */
struct GNUNET_DHT_MonitorGetMessage {
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET
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
  struct GNUNET_HashCode key GNUNET_PACKED;

  /* get path (if tracked) */
};

/**
 * Message to monitor get results going through peer, DHT service -> clients.
 */
struct GNUNET_DHT_MonitorGetRespMessage {
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT
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
  struct GNUNET_HashCode key GNUNET_PACKED;

  /* put path (if tracked) */

  /* get path (if tracked) */

  /* Payload */
};

GNUNET_NETWORK_STRUCT_END

#endif
