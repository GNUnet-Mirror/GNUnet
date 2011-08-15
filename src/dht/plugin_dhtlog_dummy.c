/*
     This file is part of GNUnet.
     (C) 2006 - 2009 Christian Grothoff (and other contributing authors)

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
 * @file src/dht/plugin_dhtlog_dummy.c
 * @brief Dummy logging plugin to test logging calls
 * @author Nathan Evans
 *
 * Database: NONE
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "dhtlog.h"

#define DEBUG_DHTLOG GNUNET_NO

/*
 * Inserts the specified trial into the dhttests.trials table
 *
 * @param trial_info struct containing the data to insert about this trial
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
add_trial (struct GNUNET_DHTLOG_TrialInfo *trial_info)
{
  return GNUNET_OK;
}

/*
 * Inserts the specified round into the dhttests.rounds table
 *
 * @param round_type the type of round that is being started
 * @param round_count counter for the round (if applicable)
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
add_round (unsigned int round_type, unsigned int round_count)
{
  return GNUNET_OK;
}

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
int
add_round_details (unsigned int round_type, unsigned int round_count,
                   unsigned int num_messages,
                   unsigned int num_messages_succeded)
{
  return GNUNET_OK;
}

/*
 * Inserts the specified dhtkey into the dhttests.dhtkeys table,
 * stores return value of dhttests.dhtkeys.dhtkeyuid into dhtkeyuid
 *
 * @param dhtkeyuid return value
 * @param dhtkey hashcode of key to insert
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
add_dhtkey (unsigned long long *dhtkeyuid, const GNUNET_HashCode * dhtkey)
{
  *dhtkeyuid = 1171;
  return GNUNET_OK;
}


/*
 * Inserts the specified node into the dhttests.nodes table
 *
 * @param nodeuid the inserted node uid
 * @param node the node to insert
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
add_node (unsigned long long *nodeuid, struct GNUNET_PeerIdentity *node)
{
  *nodeuid = 1337;
  return GNUNET_OK;
}

/*
 * Update dhttests.trials table with current server time as end time
 *
 * @param gets_succeeded how many gets did the testcase report as successful
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure.
 */
int
update_trials (unsigned int gets_succeeded)
{
  return GNUNET_OK;
}


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
int
add_generic_stat (const struct GNUNET_PeerIdentity *peer, const char *name,
                  const char *section, uint64_t value)
{
  return GNUNET_OK;
}

/*
 * Update dhttests.trials table with total connections information
 *
 * @param totalConnections the number of connections
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure.
 */
int
add_connections (unsigned int totalConnections)
{
  return GNUNET_OK;
}

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
int
add_query (unsigned long long *sqlqueryuid, unsigned long long queryid,
           unsigned int type, unsigned int hops, int succeeded,
           const struct GNUNET_PeerIdentity *node, const GNUNET_HashCode * key)
{
  *sqlqueryuid = 17;
  return GNUNET_OK;
}

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
int
add_route (unsigned long long *sqlqueryuid, unsigned long long queryid,
           unsigned int type, unsigned int hops, int succeeded,
           const struct GNUNET_PeerIdentity *node, const GNUNET_HashCode * key,
           const struct GNUNET_PeerIdentity *from_node,
           const struct GNUNET_PeerIdentity *to_node)
{
  *sqlqueryuid = 18;
  return GNUNET_OK;
}


/*
 * Records the current topology (number of connections, time, trial)
 *
 * @param num_connections how many connections are in the topology
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
add_topology (int num_connections)
{
  return GNUNET_OK;
}

/*
 * Records a connection between two peers in the current topology
 *
 * @param first one side of the connection
 * @param second other side of the connection
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
add_extended_topology (const struct GNUNET_PeerIdentity *first,
                       const struct GNUNET_PeerIdentity *second)
{
  return GNUNET_OK;
}

/*
 * Update dhttests.topology table with total connections information
 *
 * @param totalConnections the number of connections
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure.
 */
int
update_topology (unsigned int connections)
{
  return GNUNET_OK;
}

/*
 * Update dhttests.nodes table setting the identified
 * node as a malicious dropper.
 *
 * @param peer the peer that was set to be malicious
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure.
 */
int
set_malicious (struct GNUNET_PeerIdentity *peer)
{
  return GNUNET_OK;
}

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
int insert_stat (const struct GNUNET_PeerIdentity *peer,
                 unsigned int route_requests, unsigned int route_forwards,
                 unsigned int result_requests, unsigned int client_requests,
                 unsigned int result_forwards, unsigned int gets,
                 unsigned int puts, unsigned int data_inserts,
                 unsigned int find_peer_requests,
                 unsigned int find_peers_started, unsigned int gets_started,
                 unsigned int puts_started,
                 unsigned int find_peer_responses_received,
                 unsigned int get_responses_received,
                 unsigned int find_peer_responses_sent,
                 unsigned int get_responses_sent)
{
  return GNUNET_OK;
}

/*
 * Provides the dhtlog api
 *
 * @param c the configuration to use to connect to a server
 *
 * @return the handle to the server, or NULL on error
 */
void *
libgnunet_plugin_dhtlog_dummy_init (void *cls)
{
  struct GNUNET_DHTLOG_Plugin *plugin = cls;

#if DEBUG_DHTLOG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "DUMMY DHT Logger: initializing.\n");
#endif
  GNUNET_assert (plugin->dhtlog_api == NULL);
  plugin->dhtlog_api = GNUNET_malloc (sizeof (struct GNUNET_DHTLOG_Handle));
  plugin->dhtlog_api->add_generic_stat = &add_generic_stat;
  plugin->dhtlog_api->insert_round = &add_round;
  plugin->dhtlog_api->insert_round_details = &add_round_details;
  plugin->dhtlog_api->insert_stat = &insert_stat;
  plugin->dhtlog_api->insert_trial = &add_trial;
  plugin->dhtlog_api->insert_query = &add_query;
  plugin->dhtlog_api->update_trial = &update_trials;
  plugin->dhtlog_api->set_malicious = &set_malicious;
  plugin->dhtlog_api->insert_route = &add_route;
  plugin->dhtlog_api->insert_node = &add_node;
  plugin->dhtlog_api->insert_dhtkey = &add_dhtkey;
  plugin->dhtlog_api->update_connections = &add_connections;
  plugin->dhtlog_api->insert_topology = &add_topology;
  plugin->dhtlog_api->update_topology = &update_topology;
  plugin->dhtlog_api->insert_extended_topology = &add_extended_topology;
  return plugin;
}

/**
 * Shutdown the plugin.
 */
void *
libgnunet_plugin_dhtlog_dummy_done (void *cls)
{
#if DEBUG_DHTLOG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "DUMMY DHT Logger: shutdown\n");
#endif
  return NULL;
}

/* end of plugin_dhtlog_dummy.c */
