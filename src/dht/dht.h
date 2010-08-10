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

#define DEBUG_DHT_ROUTING GNUNET_YES

#define DHT_BLOOM_SIZE 16

#define DHT_BLOOM_K 8

#define MAX_OUTSTANDING_FORWARDS 100

#define DHT_FORWARD_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 5)

#define DHT_SEND_PRIORITY 4

#define STAT_ROUTES "# DHT ROUTE Requests Seen"
#define STAT_ROUTE_FORWARDS "# DHT ROUTE Requests Forwarded"
#define STAT_RESULTS "# DHT ROUTE RESULT Requests Seen"
#define STAT_RESULTS_TO_CLIENT "# DHT ROUTE RESULT Sent to Client"
#define STAT_RESULT_FORWARDS "# DHT ROUTE RESULT Requests Forwarded"
#define STAT_GETS "# DHT GET Requests Handled"
#define STAT_PUTS "# DHT PUT Requests Handled"
#define STAT_PUTS_INSERTED "# DHT PUT Data Inserts"
#define STAT_FIND_PEER "# DHT FIND_PEER Requests Handled"
#define STAT_FIND_PEER_START "# DHT FIND_PEER Requests Initiated"
#define STAT_GET_START "# DHT GET Requests Initiated"
#define STAT_PUT_START "# DHT PUT Requests Initiated"
#define STAT_FIND_PEER_REPLY "# DHT FIND_PEER Responses Received"
#define STAT_GET_REPLY "# DHT GET Responses Received"
#define STAT_FIND_PEER_ANSWER "# DHT FIND_PEER Responses Initiated"
#define STAT_GET_RESPONSE_START "# DHT GET Responses Initiated"

typedef void (*GNUNET_DHT_MessageReceivedHandler) (void *cls,
                                                   const struct GNUNET_MessageHeader
                                                   *msg);

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

  /**
   * Key of this request
   */
  GNUNET_HashCode key;

};


/**
 * Generic DHT message, indicates that a route request
 * should be issued, if coming from a client.  Shared
 * usage for api->server and P2P message passing.
 */
struct GNUNET_DHT_RouteMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_LOCAL_ROUTE
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

/**
 * Generic local route result message
 */
struct GNUNET_DHT_RouteResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_LOCAL_ROUTE_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Message options
   */
  uint32_t options GNUNET_PACKED;

  /**
   * Unique ID identifying this request (necessary for
   * client to compare to sent requests)
   */
  uint64_t unique_id GNUNET_PACKED;

  /**
   * The key that was searched for
   */
  GNUNET_HashCode key;

  /* GNUNET_MessageHeader *enc actual DHT message, copied to end of this dealy do */
};

/**
 * Generic P2P DHT route message
 */
struct GNUNET_DHT_P2PRouteMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_P2P_ROUTE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Message options
   */
  uint32_t options GNUNET_PACKED;

  /**
   * Hop count
   */
  uint32_t hop_count GNUNET_PACKED;

  /**
   * Network size estimate
   */
  uint32_t network_size GNUNET_PACKED;

  /**
   * Replication level for this message
   */
  uint32_t desired_replication_level GNUNET_PACKED;

  /**
   * Unique ID identifying this request
   */
  uint64_t unique_id GNUNET_PACKED;

  /*
   * Bloomfilter to stop circular routes
   */
  char bloomfilter[DHT_BLOOM_SIZE];

  /**
   * FIXME: add DHT logging for analysis!
   */
#if LOG_SQL
  /*
   * Unique query id for sql database interaction.
   */
  uint64_t queryuid;

  /*
   * Unique trial id for sql database interaction
   */
  uint64_t trialuid;

#endif

  /**
   * The key to search for
   */
  GNUNET_HashCode key;

  /* GNUNET_MessageHeader *enc actual DHT message, copied to end of this dealy do */

};

/**
 * Generic P2P route result
 *
 * FIXME: One question is how much to include for a route result message.
 *        Assuming a peer receives such a message, but has no record of a
 *        route message, what should it do?  It can either drop the message
 *        or try to forward it towards the original peer...  However, for
 *        that to work we would need to include the original peer identity
 *        in the GET request, which adds more data to the message.
 */
struct GNUNET_DHT_P2PRouteResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_P2P_ROUTE_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Message options
   */
  uint32_t options GNUNET_PACKED;

  /**
   * Hop count
   */
  uint32_t hop_count GNUNET_PACKED;

  /**
   * Unique ID identifying this request (may not be set)
   */
  uint64_t unique_id GNUNET_PACKED;

  /*
   * Bloomfilter to stop circular routes
   */
  char bloomfilter[DHT_BLOOM_SIZE];

  /**
   * The key that was searched for
   */
  GNUNET_HashCode key;

#if FORWARD_UNKNOWN
  /**
   * Network size estimate
   */
  uint32_t network_size GNUNET_PACKED;
#endif

  /* GNUNET_MessageHeader *enc actual DHT message, copied to end of this dealy do */
};


/**
 * Message to insert data into the DHT, shared
 * between api->server communication and P2P communication.
 * The type must be different for the two purposes.
 */
struct GNUNET_DHT_PutMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_PUT / GNUNET_MESSAGE_TYPE_DHT_P2P_PUT
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
 * Message to request data from the DHT, shared
 * between P2P requests and local get requests.
 * Main difference is that if the request comes in
 * locally we need to remember it (for client response).
 */
struct GNUNET_DHT_GetMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_GET / GNUNET_MESSAGE_TYPE_DHT_P2P_GET
   */
  struct GNUNET_MessageHeader header;

  /**
   * The type for the data for the GET request
   */
  uint32_t type;

};

/**
 * Message to return data either to the client API
 * or to respond to a request received from another
 * peer.  Shared format, different types.
 */
struct GNUNET_DHT_GetResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_GET_RESULT / GNUNET_MESSAGE_TYPE_DHT_P2P_GET_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The type for the data for the GET request
   */
  uint32_t type;

  /**
   * The key that was searched for
   */
  //GNUNET_HashCode key;

  /**
   * When does this entry expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

};


#endif /* DHT_H_ */
