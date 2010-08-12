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
   * @param trialuid return the trialuid of the newly inserted trial
   * @param num_nodes how many nodes are in the trial
   * @param topology integer representing topology for this trial
   * @param blacklist_topology integer representing blacklist topology for this trial
   * @param connect_topology integer representing connect topology for this trial
   * @param connect_topology_option integer representing connect topology option
   * @param connect_topology_option_modifier float to modify connect option
   * @param topology_percentage percentage modifier for certain topologies
   * @param topology_probability probability modifier for certain topologies
   * @param puts number of puts to perform
   * @param gets number of gets to perform
   * @param concurrent number of concurrent requests
   * @param settle_time time to wait between creating topology and starting testing
   * @param num_rounds number of times to repeat the trial
   * @param malicious_getters number of malicious GET peers in the trial
   * @param malicious_putters number of malicious PUT peers in the trial
   * @param malicious_droppers number of malicious DROP peers in the trial
   * @param malicious_get_frequency how often malicious gets are sent
   * @param malicious_put_frequency how often malicious puts are sent
   * @param stop_closest stop forwarding PUTs if closest node found
   * @param stop_found stop forwarding GETs if data found
   * @param strict_kademlia test used kademlia routing algorithm
   * @param gets_succeeded how many gets did the test driver report success on
   * @param message string to put into DB for this trial
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on failure
   */
int add_trial (unsigned long long *trialuid, unsigned int num_nodes, unsigned int topology,
               unsigned int blacklist_topology, unsigned int connect_topology,
               unsigned int connect_topology_option, float connect_topology_option_modifier,
               float topology_percentage, float topology_probability,
               unsigned int puts, unsigned int gets, unsigned int concurrent, unsigned int settle_time,
               unsigned int num_rounds, unsigned int malicious_getters, unsigned int malicious_putters,
               unsigned int malicious_droppers, unsigned int malicious_get_frequency,
               unsigned int malicious_put_frequency, unsigned int stop_closest, unsigned int stop_found,
               unsigned int strict_kademlia, unsigned int gets_succeeded,
               char *message)
{
  *trialuid = 42;
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
add_node (unsigned long long *nodeuid, struct GNUNET_PeerIdentity * node)
{
  *nodeuid = 1337;
  return GNUNET_OK;
}

/*
 * Update dhttests.trials table with current server time as end time
 *
 * @param trialuid trial to update
 * @param gets_succeeded how many gets did the testcase report as successful
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure.
 */
int
update_trials (unsigned long long trialuid,
               unsigned int gets_succeeded)
{
  return GNUNET_OK;
}


/*
 * Update dhttests.trials table with total connections information
 *
 * @param trialuid the trialuid to update
 * @param totalConnections the number of connections
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure.
 */
int
add_connections (unsigned long long trialuid, unsigned int totalConnections)
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
           const struct GNUNET_PeerIdentity * node, const GNUNET_HashCode * key)
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
           unsigned int type, unsigned int hops,
           int succeeded, const struct GNUNET_PeerIdentity * node,
           const GNUNET_HashCode * key, const struct GNUNET_PeerIdentity * from_node,
           const struct GNUNET_PeerIdentity * to_node)
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
add_extended_topology (const struct GNUNET_PeerIdentity *first, const struct GNUNET_PeerIdentity *second)
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
 * Provides the dhtlog api
 *
 * @param c the configuration to use to connect to a server
 *
 * @return the handle to the server, or NULL on error
 */
void *
libgnunet_plugin_dhtlog_dummy_init (void * cls)
{
  struct GNUNET_DHTLOG_Plugin *plugin = cls;
#if DEBUG_DHTLOG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "DUMMY DHT Logger: initializing.\n");
#endif
  GNUNET_assert(plugin->dhtlog_api == NULL);
  plugin->dhtlog_api = GNUNET_malloc(sizeof(struct GNUNET_DHTLOG_Handle));
  plugin->dhtlog_api->insert_trial = &add_trial;
  plugin->dhtlog_api->insert_query = &add_query;
  plugin->dhtlog_api->update_trial = &update_trials;
  plugin->dhtlog_api->insert_route = &add_route;
  plugin->dhtlog_api->insert_node = &add_node;
  plugin->dhtlog_api->insert_dhtkey = &add_dhtkey;
  plugin->dhtlog_api->update_connections = &add_connections;
  plugin->dhtlog_api->insert_topology = &add_topology;
  plugin->dhtlog_api->update_topology = &update_topology;
  plugin->dhtlog_api->insert_extended_topology = &add_extended_topology;
  return NULL;
}

/**
 * Shutdown the plugin.
 */
void *
libgnunet_plugin_dhtlog_dummy_done (void * cls)
{
#if DEBUG_DHTLOG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "DUMMY DHT Logger: shutdown\n");
#endif
  return NULL;
}

/* end of plugin_dhtlog_dummy.c */
