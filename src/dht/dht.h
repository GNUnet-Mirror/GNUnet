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

/**
 * Add a unique ID to every request to make testing/profiling easier.
 * Should NEVER be enabled in production and makes the DHT incompatible
 * (since this changes the message format).
 */
#define HAVE_UID_FOR_TESTING GNUNET_NO

/**
 * Needs to be GNUNET_YES for logging to dhtlog to work!
 */
#define DEBUG_DHT_ROUTING GNUNET_YES

/**
 * Size of the bloom filter the DHT uses to filter peers.
 */
#define DHT_BLOOM_SIZE 128

/**
 * Number of bits set per entry in the bloom filter for peers.
 */
#define DHT_BLOOM_K 6

/**
 * How many requests to remember for forwarding responses.
 */
#define MAX_OUTSTANDING_FORWARDS 100

/**
 * How long to remember requests so we can forward responses.
 */
#define DHT_FORWARD_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * Priority for routing results from other peers through
 * the DHT.
 */
#define DHT_SEND_PRIORITY 4


#define STAT_ROUTES "# DHT ROUTE Requests Seen"
#define STAT_ROUTE_FORWARDS "# DHT ROUTE Requests Forwarded"
#define STAT_ROUTE_FORWARDS_CLOSEST "# DHT ROUTE Requests Forwarded to Closest Known Peer"
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
#define STAT_BLOOM_FIND_PEER "# DHT FIND_PEER Responses Ignored (bloom match)"
#define STAT_GET_RESPONSE_START "# DHT GET Responses Initiated"
#define STAT_HELLOS_PROVIDED "# HELLO Messages given to transport"
#define STAT_DISCONNECTS "# Disconnects received"
#define STAT_DUPLICATE_UID "# Duplicate UID's encountered (bad if any!)"
#define STAT_RECENT_SEEN "# recent requests seen again (routing loops, alternate paths)"
#define STAT_PEERS_KNOWN "# DHT Peers known"


/**
 * FIXME: document.
 */
typedef void (*GNUNET_DHT_MessageReceivedHandler) (void *cls,
                                                   const struct
                                                   GNUNET_MessageHeader * msg);


/**
 * FIXME: document.
 */
struct GNUNET_DHT_ControlMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_CONTROL
   */
  struct GNUNET_MessageHeader header;

  /**
   * Command code of the message.
   */
  uint16_t command;

  /**
   * Variable parameter for the command.
   */
  uint16_t variable;
};


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
 * should be issued.
 */
struct GNUNET_DHT_RouteMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_LOCAL_ROUTE
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
   * For alignment, always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * The key to search for
   */
  GNUNET_HashCode key;

  /**
   * Unique ID identifying this request, if 0 then
   * the client will not expect a response
   */
  uint64_t unique_id GNUNET_PACKED;


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
   * Number of peers recorded in the outgoing
   * path from source to the final destination
   * of this message.
   */
  uint32_t outgoing_path_length GNUNET_PACKED;

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

  /* OUTGOING path */
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
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Message options
   */
  uint32_t options GNUNET_PACKED;

  /**
   * Hop count
   */
  uint32_t hop_count GNUNET_PACKED;

  /**
   * Replication level for this message
   */
  uint32_t desired_replication_level GNUNET_PACKED;

  /**
   * Network size estimate
   */
  uint32_t network_size GNUNET_PACKED;

  /**
   * Generic route path length for a message in the
   * DHT that arrived at a peer and generated
   * a reply. Copied to the end of this message.
   */
  uint32_t outgoing_path_length GNUNET_PACKED;

#if HAVE_UID_FOR_TESTING
  /**
   * Unique ID identifying this request (may not be set)
   */
  uint64_t unique_id GNUNET_PACKED;
#endif

  /**
   * Bloomfilter (for peer identities) to stop circular routes
   */
  char bloomfilter[DHT_BLOOM_SIZE];

  /**
   * The key to search for
   */
  GNUNET_HashCode key;

  /* GNUNET_MessageHeader *enc actual DHT message, copied to end of this dealy do */

  /* OUTGOING PATH */

};

/**
 * Generic P2P route result
 */
struct GNUNET_DHT_P2PRouteResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_P2P_ROUTE_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of peers recorded in the path
   * (inverse of the path the outgoing message took).
   * These peer identities follow this message.
   */
  uint32_t outgoing_path_length GNUNET_PACKED;

  /**
   * Message options
   */
  uint32_t options GNUNET_PACKED;

  /**
   * Hop count
   */
  uint32_t hop_count GNUNET_PACKED;

#if HAVE_UID_FOR_TESTING
  /**
   * Unique ID identifying this request (may not be set)
   */
  uint64_t unique_id GNUNET_PACKED;
#endif

  /**
   * The key that was searched for
   */
  GNUNET_HashCode key;

  /* GNUNET_MessageHeader *enc actual DHT message, copied to end of this dealy do */

  /* OUTGOING PATH */
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
  uint32_t type GNUNET_PACKED;

  /**
   * How long should this data persist?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /* DATA copied to end of this message */

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
   * The type for the data for the GET request; actually an 'enum
   * GNUNET_BLOCK_Type'.
   */
  uint32_t type;

  /**
   * Mutator used for the bloom filter (0 if no bf is used).
   */
  uint32_t bf_mutator;

  /**
   * Size of the eXtended query (xquery).
   */
  uint16_t xquery_size;

  /**
   * Size of the bloom filter.
   */
  uint16_t bf_size;

  /* Followed by the xquery which has 'xquery_size' bytes */

  /* Followed by the bloom filter (after xquery) with 'bf_size' bytes */
};


/**
 * Generic DHT message, indicates that a route request
 * should be issued, if coming from a client.  Shared
 * usage for api->server and P2P message passing.
 */
struct GNUNET_DHT_FindPeerMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_FIND_PEER
   */
  struct GNUNET_MessageHeader header;

  /**
   * Bloomfilter to reduce find peer responses
   */
  char bloomfilter[DHT_BLOOM_SIZE];
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
   * FIXME: use 32-bit types, as in block? What is this type exactly for?
   */
  uint16_t type;

  /**
   * The number of peer identities appended to the end of this
   * message. 
   */
  uint16_t put_path_length;

  /**
   * When does this entry expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /* OUTGOING path copied to end of this message */
  /* DATA result copied to end of this message */

};

/**
 * Entry for inserting data into datacache from the DHT.
 * Needed here so block library can verify entries that
 * are shoveled into the DHT.
 */
struct DHTPutEntry
{
  /**
   * Size of data.
   */
  uint16_t data_size;

  /**
   * Length of recorded path.
   */
  uint16_t path_length;

  /* PUT DATA */

  /* PATH ENTRIES */
};


#endif /* DHT_H_ */
