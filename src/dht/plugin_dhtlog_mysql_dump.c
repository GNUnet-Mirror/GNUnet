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
 * @file src/dht/plugin_dhtlog_mysql_dump.c
 * @brief MySQL logging plugin to record DHT operations to MySQL server,
 *        but write all queries to file instead of the actual server
 *        so that they can be imported later.  The idea is that connecting
 *        to the MySQL server X times can be really problematic, but hopefully
 *        writing to a single file is more reliable.
 * @author Nathan Evans
 *
 * Database: MySQL
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "dhtlog.h"


#define DEBUG_DHTLOG GNUNET_YES

/**
 * Maximum number of supported parameters for a prepared
 * statement.  Increase if needed.
 */
#define MAX_PARAM 32


static unsigned long max_varchar_len;

/**
 * The configuration the DHT service is running with
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

#define INSERT_QUERIES_STMT "prepare insert_query from 'INSERT INTO queries (trialuid, querytype, hops, dhtkeyuid, dhtqueryid, succeeded, nodeuid, time) "\
                          "VALUES (@temp_trial, ?, ?, ?, ?, ?, ?, ?)'"

#define INSERT_ROUTES_STMT "prepare insert_route from 'INSERT INTO routes (trialuid, querytype, hops, dhtkeyuid, dhtqueryid, succeeded, nodeuid, from_node, to_node) "\
                          "VALUES (@temp_trial, ?, ?, ?, ?, ?, ?, ?, ?)'"

#define INSERT_NODES_STMT "prepare insert_node from 'INSERT ignore INTO nodes (trialuid, nodeid) "\
                          "VALUES (@temp_trial, ?)'"

#define INSERT_TOPOLOGY_STMT "prepare insert_topology from 'INSERT INTO topology (trialuid, date, connections) "\
                             "VALUES (@temp_trial, ?, ?)'"

#define INSERT_ROUND_STMT "prepare insert_round from 'INSERT INTO rounds (trialuid, round_type, round_count, starttime) VALUES (@temp_trial, @rtype, @rcount, @curr_time)'"

#define INSERT_ROUND_DETAILS_STMT "prepare insert_round_details from 'INSERT INTO processed_trial_rounds "\
                                  "(trialuid, round_type, round_count, starttime, endtime, num_messages, num_messages_succeeded)"\
                                  "VALUES (@temp_trial, @rtype, @rcount, @curr_time, @curr_time, @totalmsgs, @msgssucceeded)'"

#define EXTEND_TOPOLOGY_STMT "prepare extend_topology from 'INSERT INTO extended_topology (topology_uid, uid_first, uid_second) "\
                             "VALUES (@temp_topology, ?, ?)'"

#define UPDATE_TOPOLOGY_STMT "prepare update_topology from 'update topology set connections = ?  where topology_uid = @temp_topology'"

#define SET_MALICIOUS_STMT "prepare set_malicious from 'update nodes set malicious_dropper = 1  where trialuid = @temp_trial and nodeid = @temp_node'"

#define INSERT_TRIALS_STMT "prepare insert_trial from 'INSERT INTO trials"\
                           "(starttime, other_trial_identifier, numnodes, topology,"\
                           "topology_percentage, topology_probability,"\
                           "blacklist_topology, connect_topology, connect_topology_option,"\
                           "connect_topology_option_modifier, puts, gets, "\
                           "concurrent, settle_time, num_rounds, malicious_getters,"\
                           "malicious_putters, malicious_droppers, malicious_get_frequency,"\
                           "malicious_put_frequency, stop_closest, stop_found, strict_kademlia, "\
                           "gets_succeeded, message) "\
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'"

#define INSERT_GENERIC_STAT_STMT "prepare insert_generic_stat from 'INSERT INTO generic_stats" \
                                 "(trialuid, nodeuid, section, name, value)"\
                                 "VALUES (@temp_trial, @temp_node, @temp_section, @temp_stat, @temp_value)'"

#define INSERT_STAT_STMT "prepare insert_stat from 'INSERT INTO node_statistics"\
                            "(trialuid, nodeuid, route_requests,"\
                            "route_forwards, result_requests,"\
                            "client_results, result_forwards, gets,"\
                            "puts, data_inserts, find_peer_requests, "\
                            "find_peers_started, gets_started, puts_started, find_peer_responses_received,"\
                            "get_responses_received, find_peer_responses_sent, get_responses_sent) "\
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'"

#define INSERT_DHTKEY_STMT "prepare insert_dhtkey from 'INSERT ignore INTO dhtkeys (dhtkey, trialuid) "\
                           "VALUES (?, @temp_trial)'"

#define UPDATE_TRIALS_STMT "prepare update_trial from 'UPDATE trials set endtime= ?, gets_succeeded = ? where trialuid = @temp_trial'"

#define UPDATE_CONNECTIONS_STMT "prepare update_conn from 'UPDATE trials set totalConnections = ? where trialuid = @temp_trial'"

#define GET_TRIAL_STMT "prepare select_trial from 'SELECT MAX( trialuid ) FROM trials into @temp_trial'"

#define GET_TOPOLOGY_STMT "prepare select_topology from 'SELECT MAX( topology_uid ) FROM topology into @temp_topology'"

#define GET_DHTKEYUID_STMT "prepare get_dhtkeyuid from 'SELECT dhtkeyuid FROM dhtkeys where dhtkey = ? and trialuid = @temp_trial'"

#define GET_NODEUID_STMT "prepare get_nodeuid from 'SELECT nodeuid FROM nodes where trialuid = @temp_trial and nodeid = ?'"

#define DATE_STR_SIZE 50

/**
 * File to dump all sql statements to.
 */
FILE *outfile;


static char *
get_sql_time()
{
  static char date[DATE_STR_SIZE];
  time_t timetmp;
  struct tm *tmptr;

  time (&timetmp);
  memset (date, 0, DATE_STR_SIZE);
  tmptr = localtime (&timetmp);
  if (NULL != tmptr)
    strftime (date, DATE_STR_SIZE, "%Y-%m-%d %H:%M:%S", tmptr);
  else
    strcpy (date, "");

  return date;
}

/**
 * Create a prepared statement.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
prepared_statement_create (const char *statement)
{
  if (fprintf(outfile, "%s;\n", statement) > 0)
    return GNUNET_OK;

  return GNUNET_SYSERR;
}

/*
 * Initialize the prepared statements for use with dht test logging
 */
static int
iopen ()
{
#define PINIT(a) (GNUNET_OK != (prepared_statement_create(a)))
  if (PINIT (INSERT_QUERIES_STMT) ||
      PINIT (INSERT_ROUTES_STMT) ||
      PINIT (INSERT_ROUND_STMT) ||
      PINIT (INSERT_ROUND_DETAILS_STMT) ||
      PINIT (INSERT_TRIALS_STMT) ||
      PINIT (SET_MALICIOUS_STMT) ||
      PINIT (INSERT_GENERIC_STAT_STMT) ||
      PINIT (INSERT_STAT_STMT) ||
      PINIT (INSERT_NODES_STMT) ||
      PINIT (INSERT_DHTKEY_STMT) ||
      PINIT (UPDATE_TRIALS_STMT) ||
      PINIT (GET_DHTKEYUID_STMT) ||
      PINIT (GET_NODEUID_STMT) ||
      PINIT (UPDATE_CONNECTIONS_STMT) ||
      PINIT (INSERT_TOPOLOGY_STMT) ||
      PINIT (EXTEND_TOPOLOGY_STMT) ||
      PINIT (UPDATE_TOPOLOGY_STMT) ||
      PINIT (GET_TRIAL_STMT) ||
      PINIT (GET_TOPOLOGY_STMT))
    {
      return GNUNET_SYSERR;
    }
#undef PINIT

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
int add_round (unsigned int round_type, unsigned int round_count)
{
  int ret;
  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @curr_time = \"%s\", @rtype = \"%u\", @rcount = \"%u\";\n", get_sql_time(), round_type, round_count);

  if (ret < 0)
    return GNUNET_SYSERR;
  ret = fprintf(outfile, "execute insert_round;\n");

  if (ret >= 0)
    return GNUNET_OK;
  return GNUNET_SYSERR;
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
int add_round_details (unsigned int round_type, unsigned int round_count,
                       unsigned int num_messages, unsigned int num_messages_succeeded)
{
  int ret;
  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @curr_time = \"%s\", @rtype = \"%u\", @rcount = \"%u\", @totalmsgs = \"%u\", @msgssucceeded = \"%u\";\n",
                          get_sql_time(), round_type, round_count, num_messages, num_messages_succeeded);

  if (ret < 0)
    return GNUNET_SYSERR;
  ret = fprintf(outfile, "execute insert_round_details;\n");

  if (ret >= 0)
    return GNUNET_OK;
  return GNUNET_SYSERR;
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
  int ret;
  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @date = \"%s\", @num = %d;\n", get_sql_time(), num_connections);

  if (ret < 0)
    return GNUNET_SYSERR;
  ret = fprintf(outfile, "execute insert_topology using "
                         "@date, @num;\n");
  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "execute select_topology;\n");

  if (ret >= 0)
    return GNUNET_OK;
  return GNUNET_SYSERR;
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
  int ret;
  if (outfile == NULL)
    return GNUNET_SYSERR;

  if (first != NULL)
    ret = fprintf(outfile, "select nodeuid from nodes where trialuid = @temp_trial and nodeid = \"%s\" into @temp_first_node;\n", GNUNET_h2s_full(&first->hashPubKey));
  else
    ret = fprintf(outfile, "set @temp_first_node = 0;\n");

  if (ret < 0)
    return GNUNET_SYSERR;

  if (second != NULL)
    ret = fprintf(outfile, "select nodeuid from nodes where trialuid = @temp_trial and nodeid = \"%s\" into @temp_second_node;\n", GNUNET_h2s_full(&second->hashPubKey));
  else
    ret = fprintf(outfile, "set @temp_second_node = 0;\n");

  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "execute extend_topology using "
                         "@temp_first_node, @temp_second_node;\n");

  if (ret >= 0)
    return GNUNET_OK;
  return GNUNET_SYSERR;
}


/*
 * Inserts the specified trial into the dhttests.trials table
 *
 * @param trial_info struct containing the data to insert about this trial
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int add_trial (struct GNUNET_DHTLOG_TrialInfo *trial_info)
{
  int ret;

  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @date = \"%s\", @oid = %u, @num = %u, @topology = %u, @bl = %u, "
                   "@connect = %u, @c_t_o = %u, @c_t_o_m = %f, @t_p = %f, "
                   "@t_pr = %f, @puts = %u, @gets = %u, "
                   "@concurrent = %u, @settle = %u, @rounds = %u, "
                   "@m_gets = %u, @m_puts = %u, @m_drops = %u, "
                   "@m_g_f = %u, @m_p_f = %u, @s_c = %u, @s_f = %u,"
                   "@s_k = %u, @g_s = %u, @message = \"%s\";\n",
                   get_sql_time(), trial_info->other_identifier, trial_info->num_nodes, trial_info->topology,
                   trial_info->blacklist_topology, trial_info->connect_topology,
                   trial_info->connect_topology_option, trial_info->connect_topology_option_modifier,
                   trial_info->topology_percentage, trial_info->topology_probability,
                   trial_info->puts, trial_info->gets, trial_info->concurrent, trial_info->settle_time,
                   trial_info->num_rounds, trial_info->malicious_getters, trial_info->malicious_putters,
                   trial_info->malicious_droppers, trial_info->malicious_get_frequency, trial_info->malicious_put_frequency,
                   trial_info->stop_closest, trial_info->stop_found, trial_info->strict_kademlia, trial_info->gets_succeeded, trial_info->message);

  if (ret < 0)
    return GNUNET_SYSERR;
  ret = fprintf(outfile, "execute insert_trial using "
                         "@date, @oid, @num, @topology, @t_p, @t_pr,"
                         " @bl, @connect, @c_t_o,"
                         "@c_t_o_m, @puts, @gets,"
                         "@concurrent, @settle, @rounds,"
                         "@m_gets, @m_puts, @m_drops,"
                         "@m_g_f, @m_p_f, @s_c, @s_f,"
                         "@s_k, @g_s, @message;\n");
  if (ret < 0)
    return GNUNET_SYSERR;
  ret = fprintf(outfile, "execute select_trial;\n");

  if (ret >= 0)
    return GNUNET_OK;
  return GNUNET_SYSERR;
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
add_generic_stat (const struct GNUNET_PeerIdentity *peer,
                  const char *name,
                  const char *section, uint64_t value)
{
  int ret;
  if (outfile == NULL)
    return GNUNET_SYSERR;

  if (peer != NULL)
    ret = fprintf(outfile, "select nodeuid from nodes where trialuid = @temp_trial and nodeid = \"%s\" into @temp_node;\n", GNUNET_h2s_full(&peer->hashPubKey));
  else
    ret = fprintf(outfile, "set @temp_node = 0;\n");

  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @temp_section = \"%s\", @temp_stat = \"%s\", @temp_value = %llu;\n",
                         section, name, (unsigned long long)value);

  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "execute insert_generic_stat;\n");

  if (ret < 0)
    return GNUNET_SYSERR;
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
int
add_stat (const struct GNUNET_PeerIdentity *peer, unsigned int route_requests,
          unsigned int route_forwards, unsigned int result_requests,
          unsigned int client_requests, unsigned int result_forwards,
          unsigned int gets, unsigned int puts,
          unsigned int data_inserts, unsigned int find_peer_requests,
          unsigned int find_peers_started, unsigned int gets_started,
          unsigned int puts_started, unsigned int find_peer_responses_received,
          unsigned int get_responses_received, unsigned int find_peer_responses_sent,
          unsigned int get_responses_sent)
{
  int ret;
  if (outfile == NULL)
    return GNUNET_SYSERR;

  if (peer != NULL)
    ret = fprintf(outfile, "select nodeuid from nodes where trialuid = @temp_trial and nodeid = \"%s\" into @temp_node;\n", GNUNET_h2s_full(&peer->hashPubKey));
  else
    ret = fprintf(outfile, "set @temp_node = 0;\n");
  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @r_r = %u, @r_f = %u, @res_r = %u, @c_r = %u, "
                         "@res_f = %u, @gets = %u, @puts = %u, @d_i = %u, "
                         "@f_p_r = %u, @f_p_s = %u, @g_s = %u, @p_s = %u, "
                         "@f_p_r_r = %u, @g_r_r = %u, @f_p_r_s = %u, @g_r_s = %u;\n",
                         route_requests, route_forwards, result_requests,
                         client_requests, result_forwards, gets, puts,
                         data_inserts, find_peer_requests, find_peers_started,
                         gets_started, puts_started, find_peer_responses_received,
                         get_responses_received, find_peer_responses_sent,
                         get_responses_sent);

  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "execute insert_stat using "
                         "@temp_trial, @temp_node, @r_r, @r_f, @res_r, @c_r, "
                         "@res_f, @gets, @puts, @d_i, "
                         "@f_p_r, @f_p_s, @g_s, @p_s, "
                         "@f_p_r_r, @g_r_r, @f_p_r_s, @g_r_s;\n");
  if (ret < 0)
    return GNUNET_SYSERR;
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
  int ret;
  if (dhtkeyuid != NULL)
    *dhtkeyuid = 0;

  if (outfile == NULL)
    return GNUNET_SYSERR;

  if (dhtkey != NULL)
    ret = fprintf(outfile, "set @dhtkey = \"%s\";\n", GNUNET_h2s_full(dhtkey));
  else
    ret = fprintf(outfile, "set @dhtkey = XXXXX;\n");

  if (ret < 0)
    return GNUNET_SYSERR;
  ret = fprintf(outfile, "execute insert_dhtkey using @dhtkey;\n");

  if (ret >= 0)
    return GNUNET_OK;
  return GNUNET_SYSERR;
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
  int ret;

  if (node == NULL)
    return GNUNET_SYSERR;

  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @node = \"%s\";\n", GNUNET_h2s_full(&node->hashPubKey));

  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "execute insert_node using @node;\n");

  if (ret >= 0)
    return GNUNET_OK;
  return GNUNET_SYSERR;
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
  int ret;

  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @date = \"%s\", @g_s = %u;\n", get_sql_time(), gets_succeeded);

  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "execute update_trial using @date, @g_s;\n");

  if (ret >= 0)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
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
  int ret;

  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @temp_node = \"%s\";\n", GNUNET_h2s_full(&peer->hashPubKey));

  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "execute set_malicious;\n");

  if (ret >= 0)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
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
  int ret;

  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @conns = %u;\n", totalConnections);

  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "execute update_conn using @conns;\n");

  if (ret >= 0)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
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
  int ret;
  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @temp_conns = %u;\n", connections);

  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "execute update_topology using @temp_conns;\n");

  if (ret >= 0)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
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
  int ret;

  if (outfile == NULL)
    return GNUNET_SYSERR;

  if (sqlqueryuid != NULL)
    *sqlqueryuid = 0;

  if (key != NULL)
    ret = fprintf(outfile, "select dhtkeyuid from dhtkeys where trialuid = @temp_trial and dhtkey = \"%s\" into @temp_dhtkey;\n", GNUNET_h2s_full(key));
  else
    ret = fprintf(outfile, "set @temp_dhtkey = 0;\n");

  if (ret < 0)
    return GNUNET_SYSERR;

  if (node != NULL)
    ret = fprintf(outfile, "select nodeuid from nodes where trialuid = @temp_trial and nodeid = \"%s\" into @temp_node;\n", GNUNET_h2s_full(&node->hashPubKey));
  else
    ret = fprintf(outfile, "set @temp_node = 0;\n");

  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @qid = %llu, @type = %u, @hops = %u, @succ = %d, @time = \"%s\";\n", queryid, type, hops, succeeded, get_sql_time());

  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "execute insert_query using @type, @hops, @temp_dhtkey, @qid, @succ, @temp_node, @time;\n");

  if (ret >= 0)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
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
  int ret;

  if (outfile == NULL)
    return GNUNET_SYSERR;

  if (sqlqueryuid != NULL)
    *sqlqueryuid = 0;

  if (key != NULL)
    ret = fprintf(outfile, "select dhtkeyuid from dhtkeys where trialuid = @temp_trial and dhtkey = \"%s\" into @temp_dhtkey;\n", GNUNET_h2s_full(key));
  else
    ret = fprintf(outfile, "set @temp_dhtkey = 0;\n");

  if (ret < 0)
    return GNUNET_SYSERR;

  if (node != NULL)
    ret = fprintf(outfile, "select nodeuid from nodes where trialuid = @temp_trial and nodeid = \"%s\" into @temp_node;\n", GNUNET_h2s_full(&node->hashPubKey));
  else
    ret = fprintf(outfile, "set @temp_node = 0;\n");

  if (ret < 0)
    return GNUNET_SYSERR;

  if (from_node != NULL)
    ret = fprintf(outfile, "select nodeuid from nodes where trialuid = @temp_trial and nodeid = \"%s\" into @temp_from_node;\n", GNUNET_h2s_full(&from_node->hashPubKey));
  else
    ret = fprintf(outfile, "set @temp_from_node = 0;\n");

  if (ret < 0)
    return GNUNET_SYSERR;

  if (to_node != NULL)
    ret = fprintf(outfile, "select nodeuid from nodes where trialuid = @temp_trial and nodeid = \"%s\" into @temp_to_node;\n", GNUNET_h2s_full(&to_node->hashPubKey));
  else
    ret = fprintf(outfile, "set @temp_to_node = 0;\n");

  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @qid = %llu, @type = %u, @hops = %u, @succ = %d;\n", queryid, type, hops, succeeded);

  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "execute insert_route using @type, @hops, @temp_dhtkey, @qid, @succ, @temp_node, @temp_from_node, @temp_to_node;\n");

  if (ret >= 0)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
}

/*
 * Provides the dhtlog api
 *
 * @param c the configuration to use to connect to a server
 *
 * @return the handle to the server, or NULL on error
 */
void *
libgnunet_plugin_dhtlog_mysql_dump_init (void * cls)
{
  struct GNUNET_DHTLOG_Plugin *plugin = cls;
  char *outfile_name;
  char *outfile_path;
  char *fn;
  int dirwarn;

  cfg = plugin->cfg;
  max_varchar_len = 255;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MySQL (DUMP) DHT Logger: initializing\n");

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (plugin->cfg,
                                                         "MYSQLDUMP", "PATH",
                                                         &outfile_path))
    {
      outfile_path = GNUNET_strdup("");
    }

  GNUNET_asprintf (&outfile_name,
                   "%s%s-%d",
                   outfile_path,
                   "mysqldump",
                   getpid());

  fn = GNUNET_STRINGS_filename_expand (outfile_name);

  if (fn == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _("Failed to get full path for `%s'\n"), outfile_name);
      GNUNET_free(outfile_path);
      GNUNET_free(outfile_name);
      return NULL;
    }

  dirwarn = (GNUNET_OK !=  GNUNET_DISK_directory_create_for_file (fn));
  outfile = FOPEN (fn, "w");

  if (outfile == NULL)
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "fopen", fn);
      if (dirwarn)
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _("Failed to create or access directory for log file `%s'\n"),
                    fn);
      GNUNET_free(outfile_path);
      GNUNET_free(outfile_name);
      GNUNET_free (fn);
      return NULL;
    }

  GNUNET_free (outfile_path);
  GNUNET_free (outfile_name);
  GNUNET_free (fn);

  if (iopen () != GNUNET_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to create file for dhtlog.\n"));
      fclose (outfile);
      return NULL;
    }
  GNUNET_assert(plugin->dhtlog_api == NULL);
  plugin->dhtlog_api = GNUNET_malloc(sizeof(struct GNUNET_DHTLOG_Handle));
  plugin->dhtlog_api->insert_trial = &add_trial;
  plugin->dhtlog_api->insert_round = &add_round;
  plugin->dhtlog_api->insert_round_details = &add_round_details;
  plugin->dhtlog_api->insert_stat = &add_stat;
  plugin->dhtlog_api->insert_query = &add_query;
  plugin->dhtlog_api->update_trial = &update_trials;
  plugin->dhtlog_api->insert_route = &add_route;
  plugin->dhtlog_api->insert_node = &add_node;
  plugin->dhtlog_api->insert_dhtkey = &add_dhtkey;
  plugin->dhtlog_api->update_connections = &add_connections;
  plugin->dhtlog_api->insert_topology = &add_topology;
  plugin->dhtlog_api->insert_extended_topology = &add_extended_topology;
  plugin->dhtlog_api->update_topology = &update_topology;
  plugin->dhtlog_api->set_malicious = &set_malicious;
  plugin->dhtlog_api->add_generic_stat = &add_generic_stat;

  return plugin;
}

/**
 * Shutdown the plugin.
 */
void *
libgnunet_plugin_dhtlog_mysql_dump_done (void * cls)
{
  struct GNUNET_DHTLOG_Handle *dhtlog_api = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MySQL DHT Logger: database shutdown\n");
  GNUNET_assert(dhtlog_api != NULL);

  GNUNET_free(dhtlog_api);
  return NULL;
}

/* end of plugin_dhtlog_mysql.c */
