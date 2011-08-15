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
 * @file src/dht/plugin_dhtlog_mysql_dump_load.c
 * @brief MySQL logging plugin to record DHT operations to MySQL server,
 *        but write all queries to file instead of the actual server
 *        so that they can be imported later.  Since the first attempt
 *        (writing out SQL queries) seemed rather time consuming on insert,
 *        this plugin writes out tab separated values instead.
 *
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

#define DATE_STR_SIZE 50

static unsigned int topology_count;

/**
 * File(s) to dump all sql statements to.
 */
FILE *outfile;
FILE *generic_stat_outfile;
FILE *stat_outfile;
FILE *node_outfile;
FILE *query_outfile;
FILE *route_outfile;
FILE *dhtkey_outfile;
FILE *extended_topology_outfile;

static char *
get_sql_time ()
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

  ret =
      fprintf (outfile,
               "insert into topology (trialuid, date, connections) values (@temp_trial, \"%s\", %d);\n",
               get_sql_time (), num_connections);
  if (ret < 0)
    return GNUNET_SYSERR;
  ret =
      fprintf (outfile,
               "select max(topology_uid) from topology into @temp_topology;\n");
  if (ret >= 0)
    return GNUNET_OK;
  return GNUNET_SYSERR;
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
  int ret;

  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret =
      fprintf (outfile,
               "insert into rounds (trialuid, round_type, round_count, starttime) values (@temp_trial, \"%u\", \"%u\", \"%s\");\n",
               round_type, round_count, get_sql_time ());

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
int
add_round_details (unsigned int round_type, unsigned int round_count,
                   unsigned int num_messages,
                   unsigned int num_messages_succeeded)
{
  int ret;

  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret =
      fprintf (outfile,
               "insert into processed_trial_rounds (trialuid, round_type, round_count, starttime, endtime, num_messages, num_messages_succeeded) values (@temp_trial, \"%u\", \"%u\", \"%s\", \"%s\", \"%u\", \"%u\");\n",
               round_type, round_count, get_sql_time (), get_sql_time (),
               num_messages, num_messages_succeeded);

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
add_extended_topology (const struct GNUNET_PeerIdentity *first,
                       const struct GNUNET_PeerIdentity *second)
{
  int ret;

  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret =
      fprintf (extended_topology_outfile,
               "insert into extended_topology (topology_uid, uid_first, uid_second) values (%u, %s,",
               topology_count, GNUNET_h2s_full (&first->hashPubKey));
  if (ret < 0)
    return GNUNET_SYSERR;
  ret =
      fprintf (extended_topology_outfile, "%s);\n",
               GNUNET_h2s_full (&second->hashPubKey));

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
int
add_trial (struct GNUNET_DHTLOG_TrialInfo *trial_info)
{
  int ret;

  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret =
      fprintf (outfile,
               "INSERT INTO trials "
               "(starttime, other_trial_identifier, numnodes, topology,"
               "blacklist_topology, connect_topology, connect_topology_option,"
               "connect_topology_option_modifier, topology_percentage, topology_probability,"
               "puts, gets, "
               "concurrent, settle_time, num_rounds, malicious_getters,"
               "malicious_putters, malicious_droppers, malicious_get_frequency,"
               "malicious_put_frequency, stop_closest, stop_found, strict_kademlia, "
               "gets_succeeded, message) "
               "VALUES (\"%s\", %u, %u, %u, %u, %u, %u, %f, %f, %f, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, \"%s\");\n",
               get_sql_time (), trial_info->other_identifier,
               trial_info->num_nodes, trial_info->topology,
               trial_info->blacklist_topology, trial_info->connect_topology,
               trial_info->connect_topology_option,
               trial_info->connect_topology_option_modifier,
               trial_info->topology_percentage,
               trial_info->topology_probability, trial_info->puts,
               trial_info->gets, trial_info->concurrent,
               trial_info->settle_time, trial_info->num_rounds,
               trial_info->malicious_getters, trial_info->malicious_putters,
               trial_info->malicious_droppers,
               trial_info->malicious_get_frequency,
               trial_info->malicious_put_frequency, trial_info->stop_closest,
               trial_info->stop_found, trial_info->strict_kademlia,
               trial_info->gets_succeeded, trial_info->message);

  if (ret < 0)
    return GNUNET_SYSERR;

  ret =
      fprintf (outfile,
               "SELECT MAX( trialuid ) FROM trials into @temp_trial;\n");

  if (ret >= 0)
    return GNUNET_OK;
  else
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
add_generic_stat (const struct GNUNET_PeerIdentity *peer, const char *name,
                  const char *section, uint64_t value)
{
  if (outfile == NULL)
    return GNUNET_SYSERR;

  if (peer != NULL)
    fprintf (generic_stat_outfile, "TRIALUID\t%s\t%s\t%s\t%llu\n",
             GNUNET_h2s_full (&peer->hashPubKey), section, name,
             (unsigned long long) value);

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
          unsigned int gets, unsigned int puts, unsigned int data_inserts,
          unsigned int find_peer_requests, unsigned int find_peers_started,
          unsigned int gets_started, unsigned int puts_started,
          unsigned int find_peer_responses_received,
          unsigned int get_responses_received,
          unsigned int find_peer_responses_sent,
          unsigned int get_responses_sent)
{
  int ret;

  if (outfile == NULL)
    return GNUNET_SYSERR;

  if (peer != NULL)
    ret =
        fprintf (stat_outfile,
                 "TRIALUID\t%s\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
                 GNUNET_h2s_full (&peer->hashPubKey), route_requests,
                 route_forwards, result_requests, client_requests,
                 result_forwards, gets, puts, data_inserts, find_peer_requests,
                 find_peers_started, gets_started, puts_started,
                 find_peer_responses_received, get_responses_received,
                 find_peer_responses_sent, get_responses_sent);

  else
    return GNUNET_SYSERR;

  if (ret >= 0)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
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

  if ((dhtkey_outfile == NULL) || (dhtkey == NULL))
    return GNUNET_SYSERR;

  ret = fprintf (dhtkey_outfile, "TRIALUID\t%s\n", GNUNET_h2s_full (dhtkey));

  if (ret >= 0)
    return GNUNET_OK;
  else
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
add_node (unsigned long long *nodeuid, struct GNUNET_PeerIdentity *node)
{
  int ret;

  if ((node == NULL) || (node_outfile == NULL))
    return GNUNET_SYSERR;

  ret =
      fprintf (node_outfile, "TRIALUID\t%s\n",
               GNUNET_h2s_full (&node->hashPubKey));
  fflush (node_outfile);
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

  ret =
      fprintf (outfile,
               "update trials set endtime=\"%s\", gets_succeeded=%u where trialuid = @temp_trial;\n",
               get_sql_time (), gets_succeeded);
  fflush (node_outfile);
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

  ret =
      fprintf (outfile,
               "update nodes set malicious_dropper = 1 where trialuid = @temp_trial and nodeid = \"%s\";\n",
               GNUNET_h2s_full (&peer->hashPubKey));
  fflush (node_outfile);
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

  ret =
      fprintf (outfile,
               "update trials set totalConnections = %u where trialuid = @temp_trial;\n",
               totalConnections);
  fflush (node_outfile);
  if (ret >= 0)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
}


/*
 * Update dhttests.topology table with total connections information
 *
 * @param connections the number of connections
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure.
 */
int
update_topology (unsigned int connections)
{
  int ret;

  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret =
      fprintf (outfile,
               "update topology set connections = %u where topology_uid = @temp_topology;\n",
               connections);
  topology_count++;
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
           const struct GNUNET_PeerIdentity *node, const GNUNET_HashCode * key)
{
  int ret;

  if ((outfile == NULL) || (node == NULL) || (key == NULL))
    return GNUNET_SYSERR;

  if (sqlqueryuid != NULL)
    *sqlqueryuid = 0;

  ret = fprintf (query_outfile, "TRIALUID\t%s\t", GNUNET_h2s_full (key));

  if (ret < 0)
    return GNUNET_SYSERR;

  ret =
      fprintf (query_outfile, "%s\t%llu\t%u\t%u\t%u\t%s\n",
               GNUNET_h2s_full (&node->hashPubKey), queryid, type, hops,
               succeeded, get_sql_time ());

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
           unsigned int type, unsigned int hops, int succeeded,
           const struct GNUNET_PeerIdentity *node, const GNUNET_HashCode * key,
           const struct GNUNET_PeerIdentity *from_node,
           const struct GNUNET_PeerIdentity *to_node)
{
  int ret;

  if ((outfile == NULL) || (node == NULL) || (key == NULL))
    return GNUNET_SYSERR;

  if (sqlqueryuid != NULL)
    *sqlqueryuid = 0;

  ret = fprintf (route_outfile, "TRIALUID\t%s\t", GNUNET_h2s_full (key));
  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf (route_outfile, "%s\t", GNUNET_h2s_full (&node->hashPubKey));
  if (ret < 0)
    return GNUNET_SYSERR;
  if (from_node == NULL)
    ret = fprintf (route_outfile, "0\t");
  else
    ret =
        fprintf (route_outfile, "%s\t",
                 GNUNET_h2s_full (&from_node->hashPubKey));
  if (ret < 0)
    return GNUNET_SYSERR;

  if (to_node == NULL)
    ret =
        fprintf (route_outfile, "0\t%llu\t%u\t%u\t%d\n", queryid, type, hops,
                 succeeded);
  else
    ret =
        fprintf (route_outfile, "%s\t%llu\t%u\t%u\t%d\n",
                 GNUNET_h2s_full (&to_node->hashPubKey), queryid, type, hops,
                 succeeded);

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
libgnunet_plugin_dhtlog_mysql_dump_load_init (void *cls)
{
  struct GNUNET_DHTLOG_Plugin *plugin = cls;
  char *outfile_name;
  char *outfile_path;
  char *fn;
  int dirwarn;

  cfg = plugin->cfg;
  max_varchar_len = 255;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MySQL (DUMP) DHT Logger: initializing\n");

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (plugin->cfg, "MYSQLDUMP", "PATH",
                                             &outfile_path))
  {
    outfile_path = GNUNET_strdup ("");
  }

  GNUNET_asprintf (&outfile_name, "%s%s-%d", outfile_path, "mysqldump",
                   getpid ());

  fn = GNUNET_STRINGS_filename_expand (outfile_name);

  if (fn == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to get full path for `%s'\n"), outfile_name);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    return NULL;
  }

  dirwarn = (GNUNET_OK != GNUNET_DISK_directory_create_for_file (fn));
  outfile = FOPEN (fn, "w");

  if (outfile == NULL)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "fopen", fn);
    if (dirwarn)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to create or access directory for log file `%s'\n"),
                  fn);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    GNUNET_free (fn);
    return NULL;
  }

  GNUNET_free (outfile_name);
  GNUNET_asprintf (&outfile_name, "%s%s-%d", outfile_path, "mysqldump_nodes",
                   getpid ());
  GNUNET_free (fn);
  fn = GNUNET_STRINGS_filename_expand (outfile_name);

  if (fn == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to get full path for `%s'\n"), outfile_name);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    return NULL;
  }

  dirwarn = (GNUNET_OK != GNUNET_DISK_directory_create_for_file (fn));
  node_outfile = FOPEN (fn, "w");

  if (node_outfile == NULL)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "fopen", fn);
    if (dirwarn)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to create or access directory for log file `%s'\n"),
                  fn);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    GNUNET_free (fn);
    return NULL;
  }

  GNUNET_free (outfile_name);
  GNUNET_asprintf (&outfile_name, "%s%s-%d", outfile_path, "mysqldump_routes",
                   getpid ());

  GNUNET_free (fn);
  fn = GNUNET_STRINGS_filename_expand (outfile_name);

  if (fn == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to get full path for `%s'\n"), outfile_name);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    return NULL;
  }

  dirwarn = (GNUNET_OK != GNUNET_DISK_directory_create_for_file (fn));
  route_outfile = FOPEN (fn, "w");

  if (route_outfile == NULL)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "fopen", fn);
    if (dirwarn)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to create or access directory for log file `%s'\n"),
                  fn);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    GNUNET_free (fn);
    return NULL;
  }

  GNUNET_free (outfile_name);
  GNUNET_asprintf (&outfile_name, "%s%s-%d", outfile_path, "mysqldump_queries",
                   getpid ());

  GNUNET_free (fn);
  fn = GNUNET_STRINGS_filename_expand (outfile_name);

  if (fn == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to get full path for `%s'\n"), outfile_name);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    return NULL;
  }

  dirwarn = (GNUNET_OK != GNUNET_DISK_directory_create_for_file (fn));
  query_outfile = FOPEN (fn, "w");

  if (query_outfile == NULL)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "fopen", fn);
    if (dirwarn)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to create or access directory for log file `%s'\n"),
                  fn);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    GNUNET_free (fn);
    return NULL;
  }

  GNUNET_free (outfile_name);
  GNUNET_asprintf (&outfile_name, "%s%s-%d", outfile_path, "mysqldump_stats",
                   getpid ());

  GNUNET_free (fn);
  fn = GNUNET_STRINGS_filename_expand (outfile_name);

  if (fn == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to get full path for `%s'\n"), outfile_name);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    return NULL;
  }

  dirwarn = (GNUNET_OK != GNUNET_DISK_directory_create_for_file (fn));
  stat_outfile = FOPEN (fn, "w");

  if (stat_outfile == NULL)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "fopen", fn);
    if (dirwarn)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to create or access directory for log file `%s'\n"),
                  fn);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    GNUNET_free (fn);
    return NULL;
  }

  GNUNET_free (outfile_name);
  GNUNET_asprintf (&outfile_name, "%s%s-%d", outfile_path,
                   "mysqldump_generic_stats", getpid ());
  GNUNET_free (fn);
  fn = GNUNET_STRINGS_filename_expand (outfile_name);

  if (fn == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to get full path for `%s'\n"), outfile_name);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    return NULL;
  }

  dirwarn = (GNUNET_OK != GNUNET_DISK_directory_create_for_file (fn));
  generic_stat_outfile = FOPEN (fn, "w");

  if (generic_stat_outfile == NULL)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "fopen", fn);
    if (dirwarn)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to create or access directory for log file `%s'\n"),
                  fn);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    GNUNET_free (fn);
    return NULL;
  }

  GNUNET_free (outfile_name);
  GNUNET_asprintf (&outfile_name, "%s%s-%d", outfile_path, "mysqldump_dhtkey",
                   getpid ());
  GNUNET_free (fn);
  fn = GNUNET_STRINGS_filename_expand (outfile_name);

  if (fn == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to get full path for `%s'\n"), outfile_name);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    return NULL;
  }

  dirwarn = (GNUNET_OK != GNUNET_DISK_directory_create_for_file (fn));
  dhtkey_outfile = FOPEN (fn, "w");

  if (dhtkey_outfile == NULL)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "fopen", fn);
    if (dirwarn)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to create or access directory for log file `%s'\n"),
                  fn);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    GNUNET_free (fn);
    return NULL;
  }

  GNUNET_free (outfile_name);
  GNUNET_asprintf (&outfile_name, "%s%s-%d", outfile_path,
                   "mysqldump_extended_topology", getpid ());
  GNUNET_free (fn);
  fn = GNUNET_STRINGS_filename_expand (outfile_name);

  if (fn == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to get full path for `%s'\n"), outfile_name);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    return NULL;
  }

  dirwarn = (GNUNET_OK != GNUNET_DISK_directory_create_for_file (fn));
  extended_topology_outfile = FOPEN (fn, "w");

  if (extended_topology_outfile == NULL)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "fopen", fn);
    if (dirwarn)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to create or access directory for log file `%s'\n"),
                  fn);
    GNUNET_free (outfile_path);
    GNUNET_free (outfile_name);
    GNUNET_free (fn);
    return NULL;
  }

  GNUNET_free (outfile_path);
  GNUNET_free (outfile_name);
  GNUNET_free (fn);

  GNUNET_assert (plugin->dhtlog_api == NULL);
  plugin->dhtlog_api = GNUNET_malloc (sizeof (struct GNUNET_DHTLOG_Handle));
  plugin->dhtlog_api->insert_trial = &add_trial;
  plugin->dhtlog_api->insert_stat = &add_stat;
  plugin->dhtlog_api->insert_round = &add_round;
  plugin->dhtlog_api->insert_round_details = &add_round_details;
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
libgnunet_plugin_dhtlog_mysql_dump_load_done (void *cls)
{
  struct GNUNET_DHTLOG_Handle *dhtlog_api = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MySQL DHT Logger: database shutdown\n");
  GNUNET_assert (dhtlog_api != NULL);

  fclose (outfile);
  fclose (node_outfile);
  fclose (query_outfile);
  fclose (route_outfile);
  fclose (stat_outfile);
  fclose (generic_stat_outfile);
  fclose (extended_topology_outfile);
  GNUNET_free (dhtlog_api);
  return NULL;
}

/* end of plugin_dhtlog_mysql_dump_load.c */
