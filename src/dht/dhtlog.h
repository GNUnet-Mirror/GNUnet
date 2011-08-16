/*
     This file is part of GNUnet
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file src/dht/dhtlog.h
 *
 * @brief dhtlog is a service that implements logging of dht operations
 * for testing
 * @author Nathan Evans
 */

#ifndef GNUNET_DHTLOG_SERVICE_H
#define GNUNET_DHTLOG_SERVICE_H

#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

typedef enum
{
  /**
   * Type for a DHT GET message
   */
  DHTLOG_GET = 1,

  /**
   * Type for a DHT PUT message
   */
  DHTLOG_PUT = 2,

  /**
   * Type for a DHT FIND PEER message
   */
  DHTLOG_FIND_PEER = 3,

  /**
   * Type for a DHT RESULT message
   */
  DHTLOG_RESULT = 4,

  /**
   * Generic DHT ROUTE message
   */
  DHTLOG_ROUTE = 5,

} DHTLOG_MESSAGE_TYPES;

struct GNUNET_DHTLOG_TrialInfo
{
  /**
   * Outside of database identifier for the trial.
   */
  unsigned int other_identifier;

  /** Number of nodes in the trial */
  unsigned int num_nodes;

  /** Type of initial topology */
  unsigned int topology;

  /** Topology to blacklist peers to */
  unsigned int blacklist_topology;

  /** Initially connect peers in this topology */
  unsigned int connect_topology;

  /** Option to modify connect topology */
  unsigned int connect_topology_option;

  /** Modifier for the connect option */
  float connect_topology_option_modifier;

  /** Percentage parameter used for certain topologies */
  float topology_percentage;

  /** Probability parameter used for certain topologies */
  float topology_probability;

  /** Number of puts in the trial */
  unsigned int puts;

  /** Number of gets in the trial */
  unsigned int gets;

  /** Concurrent puts/gets in the trial (max allowed) */
  unsigned int concurrent;

  /** How long between initial connection and issuing puts/gets */
  unsigned int settle_time;

  /** How many times to do put/get loop */
  unsigned int num_rounds;

  /** Number of malicious getters */
  unsigned int malicious_getters;

  /** Number of malicious putters */
  unsigned int malicious_putters;

  /** Number of malicious droppers */
  unsigned int malicious_droppers;

  /** Frequency of malicious get requests */
  unsigned int malicious_get_frequency;

  /** Frequency of malicious put requests */
  unsigned int malicious_put_frequency;

  /** Stop forwarding put/find_peer requests when peer is closer than others */
  unsigned int stop_closest;

  /** Stop forwarding get requests when data found */
  unsigned int stop_found;

  /**
   * Routing behaves as it would in Kademlia (modified to work recursively,
   * and with our other GNUnet constraints).
   */
  unsigned int strict_kademlia;

  /** Number of gets that were reported successful */
  unsigned int gets_succeeded;

  /** Message for this trial */
  char *message;
};

struct GNUNET_DHTLOG_Handle
{

  /*
   * Inserts the specified query into the dhttests.queries table
   *
   * @param sqlqueruid inserted query uid
   * @param queryid dht query id
   * @param type type of the query
   * @param hops number of hops query traveled
   * @param succeeded whether or not query was successful
   * @param node the node the query hit
   * @param key the key of the query
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure.
   */
  int (*insert_query) (unsigned long long *sqlqueryuid,
                       unsigned long long queryid, DHTLOG_MESSAGE_TYPES type,
                       unsigned int hops, int succeeded,
                       const struct GNUNET_PeerIdentity * node,
                       const GNUNET_HashCode * key);

  /*
   * Inserts the specified trial into the dhttests.trials table
   *
   * @param trial_info general information about this trial
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure
   */
  int (*insert_trial) (struct GNUNET_DHTLOG_TrialInfo * trial_info);

  /*
   * Inserts the specified stats into the dhttests.node_statistics table
   *
   * @param peer the peer inserting the statistic
   * @param route_requests route requests seen
   * @param route_forwards route requests forwarded
   * @param result_requests route result requests seen
   * @param client_requests client requests initiated
   * @param result_forwards route results forwarded
   * @param gets get requests handled
   * @param puts put requests handle
   * @param data_inserts data inserted at this node
   * @param find_peer_requests find peer requests seen
   * @param find_peers_started find peer requests initiated at this node
   * @param gets_started get requests initiated at this node
   * @param puts_started put requests initiated at this node
   * @param find_peer_responses_received find peer responses received locally
   * @param get_responses_received get responses received locally
   * @param find_peer_responses_sent find peer responses sent from this node
   * @param get_responses_sent get responses sent from this node
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure
   */
  int (*insert_stat) (const struct GNUNET_PeerIdentity * peer,
                      unsigned int route_requests, unsigned int route_forwards,
                      unsigned int result_requests,
                      unsigned int client_requests,
                      unsigned int result_forwards, unsigned int gets,
                      unsigned int puts, unsigned int data_inserts,
                      unsigned int find_peer_requests,
                      unsigned int find_peers_started,
                      unsigned int gets_started, unsigned int puts_started,
                      unsigned int find_peer_responses_received,
                      unsigned int get_responses_received,
                      unsigned int find_peer_responses_sent,
                      unsigned int get_responses_sent);

  /*
   * Update dhttests.trials table with current server time as end time
   *
   * @param gets_succeeded how many gets did the trial report successful
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure.
   */
  int (*update_trial) (unsigned int gets_succeeded);

  /*
   * Update dhttests.nodes table setting the identified
   * node as a malicious dropper.
   *
   * @param peer the peer that was set to be malicious
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure.
   */
  int (*set_malicious) (struct GNUNET_PeerIdentity * peer);

  /*
   * Records the current topology (number of connections, time, trial)
   *
   * @param num_connections how many connections are in the topology
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure
   */
  int (*insert_topology) (int num_connections);

  /*
   * Records a connection between two peers in the current topology
   *
   * @param first one side of the connection
   * @param second other side of the connection
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure
   */
  int (*insert_extended_topology) (const struct GNUNET_PeerIdentity * first,
                                   const struct GNUNET_PeerIdentity * second);

  /*
   * Inserts the specified stats into the dhttests.generic_stats table
   *
   * @param peer the peer inserting the statistic
   * @param name the name of the statistic
   * @param section the section of the statistic
   * @param value the value of the statistic
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure
   */
  int (*add_generic_stat) (const struct GNUNET_PeerIdentity * peer,
                           const char *name, const char *section,
                           uint64_t value);

  /*
   * Inserts the specified round into the dhttests.rounds table
   *
   * @param round_type the type of round that is being started
   * @param round_count counter for the round (if applicable)
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure
   */
  int (*insert_round) (unsigned int round_type, unsigned int round_count);

  /*
   * Inserts the specified round results into the
   * dhttests.processed_round_details table
   *
   * @param round_type the type of round that is being started
   * @param round_count counter for the round (if applicable)
   * @param num_messages the total number of messages initiated
   * @param num_messages_succeeded the number of messages that succeeded
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure
   */
  int (*insert_round_details) (unsigned int round_type,
                               unsigned int round_count,
                               unsigned int num_messages,
                               unsigned int num_messages_succeeded);

  /*
   * Update dhttests.trials table with total connections information
   *
   * @param totalConnections the number of connections
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure.
   */
  int (*update_connections) (unsigned int totalConnections);

  /*
   * Update dhttests.trials table with total connections information
   *
   * @param connections the number of connections
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure.
   */
  int (*update_topology) (unsigned int connections);

  /*
   * Inserts the specified route information into the dhttests.routes table
   *
   * @param sqlqueruid inserted query uid
   * @param queryid dht query id
   * @param type type of the query
   * @param hops number of hops query traveled
   * @param succeeded whether or not query was successful
   * @param node the node the query hit
   * @param key the key of the query
   * @param from_node the node that sent the message to node
   * @param to_node next node to forward message to
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure.
   */
  int (*insert_route) (unsigned long long *sqlqueryuid,
                       unsigned long long queryid, unsigned int type,
                       unsigned int hops, int succeeded,
                       const struct GNUNET_PeerIdentity * node,
                       const GNUNET_HashCode * key,
                       const struct GNUNET_PeerIdentity * from_node,
                       const struct GNUNET_PeerIdentity * to_node);

  /*
   * Inserts the specified node into the dhttests.nodes table
   *
   * @param nodeuid the inserted node uid
   * @param node the node to insert
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure
   */
  int (*insert_node) (unsigned long long *nodeuid,
                      struct GNUNET_PeerIdentity * node);

  /*
   * Inserts the specified dhtkey into the dhttests.dhtkeys table,
   * stores return value of dhttests.dhtkeys.dhtkeyuid into dhtkeyuid
   *
   * @param dhtkeyuid return value
   * @param dhtkey hashcode of key to insert
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure
   */
  int (*insert_dhtkey) (unsigned long long *dhtkeyuid,
                        const GNUNET_HashCode * dhtkey);

};

struct GNUNET_DHTLOG_Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  struct GNUNET_DHTLOG_Handle *dhtlog_api;
};

/**
 * Connect to mysql server using the DHT log plugin.
 *
 * @param c a configuration to use
 */
struct GNUNET_DHTLOG_Handle *
GNUNET_DHTLOG_connect (const struct GNUNET_CONFIGURATION_Handle *c);

/**
 * Shutdown the module.
 */
void
GNUNET_DHTLOG_disconnect (struct GNUNET_DHTLOG_Handle *api);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of dhtlog.h */
#endif
