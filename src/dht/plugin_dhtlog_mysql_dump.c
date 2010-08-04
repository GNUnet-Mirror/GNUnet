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
 * @file src/dht/plugin_dhtlog_mysql.c
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


#define DEBUG_DHTLOG GNUNET_NO

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

#define INSERT_QUERIES_STMT "prepare insert_query from 'INSERT INTO queries (trialuid, querytype, hops, dhtkeyuid, dhtqueryid, succeeded, nodeuid) "\
                          "VALUES (@temp_trial, ?, ?, ?, ?, ?, ?)'"

#define INSERT_ROUTES_STMT "prepare insert_route from 'INSERT INTO routes (trialuid, querytype, hops, dhtkeyuid, dhtqueryid, succeeded, nodeuid, from_node, to_node) "\
                          "VALUES (@temp_trial, ?, ?, ?, ?, ?, ?, ?, ?)'"

#define INSERT_NODES_STMT "prepare insert_node from 'INSERT INTO nodes (trialuid, nodeid) "\
                          "VALUES (@temp_trial, ?)'"

#define INSERT_TOPOLOGY_STMT "prepare insert_topology from 'INSERT INTO topology (trialuid, date, connections) "\
                             "VALUES (@temp_trial, ?, ?)'"

#define EXTEND_TOPOLOGY_STMT "prepare extend_topology from 'INSERT INTO extended_topology (topology_uid, uid_first, uid_second) "\
                             "VALUES (@temp_topology, ?, ?)'"


#define INSERT_TRIALS_STMT "prepare insert_trial from 'INSERT INTO trials"\
                           "(starttime, numnodes, topology,"\
                           "topology_percentage, topology_probability,"\
                           "blacklist_topology, connect_topology, connect_topology_option,"\
                           "connect_topology_option_modifier, puts, gets, "\
                           "concurrent, settle_time, num_rounds, malicious_getters,"\
                           "malicious_putters, malicious_droppers, message) "\
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'"

#define INSERT_DHTKEY_STMT "prepare insert_dhtkey from 'INSERT ignore INTO dhtkeys (dhtkey, trialuid) "\
                           "VALUES (?, @temp_trial)'"

#define UPDATE_TRIALS_STMT "prepare update_trial from 'UPDATE trials set endtime= ?, total_messages_dropped = ?, total_bytes_dropped = ?, unknownPeers = ? where trialuid = @temp_trial'"

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
      PINIT (INSERT_TRIALS_STMT) ||
      PINIT (INSERT_NODES_STMT) ||
      PINIT (INSERT_DHTKEY_STMT) ||
      PINIT (UPDATE_TRIALS_STMT) ||
      PINIT (GET_DHTKEYUID_STMT) ||
      PINIT (GET_NODEUID_STMT) ||
      PINIT (UPDATE_CONNECTIONS_STMT) ||
      PINIT (GET_TRIAL_STMT))
    {
      return GNUNET_SYSERR;
    }
#undef PINIT

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
  int ret;
  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @date = \"%s\", @num = %d;\n", get_sql_time(), num_connections);

  if (ret < 0)
    return GNUNET_SYSERR;
  ret = fprintf(outfile, "execute insert_topology using "
                         "@date, @num;\n");

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
add_extended_topology (struct GNUNET_PeerIdentity *first, struct GNUNET_PeerIdentity *second)
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
 * @param message string to put into DB for this trial
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
add_trial (unsigned long long *trialuid, int num_nodes, int topology,
           int blacklist_topology, int connect_topology,
           int connect_topology_option, float connect_topology_option_modifier,
           float topology_percentage, float topology_probability,
           int puts, int gets, int concurrent, int settle_time,
           int num_rounds, int malicious_getters, int malicious_putters,
           int malicious_droppers, char *message)
{
  int ret;
  if (trialuid != NULL)
    *trialuid = 0;
  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @date = \"%s\", @num = %d, @topology = %d, @bl = %d, "
                   "@connect = %d, @c_t_o = %d, @c_t_o_m = %f, @t_p = %f, "
                   "@t_pr = %f, @puts = %d, @gets = %d, "
                   "@concurrent = %d, @settle = %d, @rounds = %d, "
                   "@m_gets = %d, @m_puts = %d, @m_drops = %d, "
                   "@message = \"%s\";\n", get_sql_time(), num_nodes, topology,
                   blacklist_topology, connect_topology,
                   connect_topology_option, connect_topology_option_modifier,
                   topology_percentage, topology_probability,
                   puts, gets, concurrent, settle_time,
                   num_rounds, malicious_getters, malicious_putters,
                   malicious_droppers, message);

  if (ret < 0)
    return GNUNET_SYSERR;
  ret = fprintf(outfile, "execute insert_trial using "
                         "@date, @num, @topology, @t_p, @t_pr,"
                         " @bl, @connect, @c_t_o,"
                         "@c_t_o_m, @puts, @gets,"
                         "@concurrent, @settle, @rounds,"
                         "@m_gets, @m_puts, @m_drops,"
                         "@message;\n");

  ret = fprintf(outfile, "execute select_trial;\n");

  if (ret >= 0)
    return GNUNET_OK;
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

  if (node != NULL)
    ret = fprintf(outfile, "set @node = \"%s\";\n", GNUNET_h2s_full(&node->hashPubKey));
  else
    return GNUNET_SYSERR;

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
 * @param trialuid trial to update
 * @param totalMessagesDropped stats value for messages dropped
 * @param totalBytesDropped stats value for total bytes dropped
 * @param unknownPeers stats value for unknown peers
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure.
 */
int
update_trials (unsigned long long trialuid,
               unsigned long long totalMessagesDropped,
               unsigned long long totalBytesDropped,
               unsigned long long unknownPeers)
{
  int ret;
#if DEBUG_DHTLOG
  if (trialuid != current_trial)
    {
      fprintf (stderr,
               _("Trialuid to update is not equal to current_trial\n"));
    }
#endif

  if (outfile == NULL)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "set @date = \"%s\", @m_dropped = %llu, @b_dropped = %llu, @unknown = %llu;\n", get_sql_time(), totalMessagesDropped, totalBytesDropped, unknownPeers);

  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "execute update_trial using @date, @m_dropped, @b_dropped, @unknown;\n");

  if (ret >= 0)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
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
  int ret;
#if DEBUG_DHTLOG
  if (trialuid != current_trial)
    {
      fprintf (stderr,
               _("Trialuid to update is not equal to current_trial(!)(?)\n"));
    }
#endif
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

  if (node != NULL)
    ret = fprintf(outfile, "select nodeuid from nodes where trialuid = @temp_trial and nodeid = \"%s\" into @temp_node;\n", GNUNET_h2s_full(&node->hashPubKey));
  else
    ret = fprintf(outfile, "set @temp_node = 0;\n");

  ret = fprintf(outfile, "set @qid = %llu, @type = %u, @hops = %u, @succ = %d;\n", queryid, type, hops, succeeded);

  if (ret < 0)
    return GNUNET_SYSERR;

  ret = fprintf(outfile, "execute insert_query using @type, @hops, @temp_dhtkey, @qid, @succ, @temp_node;\n");

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

  if (node != NULL)
    ret = fprintf(outfile, "select nodeuid from nodes where trialuid = @temp_trial and nodeid = \"%s\" into @temp_node;\n", GNUNET_h2s_full(&node->hashPubKey));
  else
    ret = fprintf(outfile, "set @temp_node = 0;\n");

  if (from_node != NULL)
    ret = fprintf(outfile, "select nodeuid from nodes where trialuid = @temp_trial and nodeid = \"%s\" into @temp_from_node;\n", GNUNET_h2s_full(&from_node->hashPubKey));
  else
    ret = fprintf(outfile, "set @temp_from_node = 0;\n");

  if (to_node != NULL)
    ret = fprintf(outfile, "select nodeuid from nodes where trialuid = @temp_trial and nodeid = \"%s\" into @temp_to_node;\n", GNUNET_h2s_full(&to_node->hashPubKey));
  else
    ret = fprintf(outfile, "set @temp_to_node = 0;\n");

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

#if DEBUG_DHTLOG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MySQL (DUMP) DHT Logger: initializing\n");
#endif

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
      return NULL;
    }
  GNUNET_assert(plugin->dhtlog_api == NULL);
  plugin->dhtlog_api = GNUNET_malloc(sizeof(struct GNUNET_DHTLOG_Handle));
  plugin->dhtlog_api->insert_trial = &add_trial;
  plugin->dhtlog_api->insert_query = &add_query;
  plugin->dhtlog_api->update_trial = &update_trials;
  plugin->dhtlog_api->insert_route = &add_route;
  plugin->dhtlog_api->insert_node = &add_node;
  plugin->dhtlog_api->insert_dhtkey = &add_dhtkey;
  plugin->dhtlog_api->update_connections = &add_connections;

  return NULL;
}

/**
 * Shutdown the plugin.
 */
void *
libgnunet_plugin_dhtlog_mysql_dump_done (void * cls)
{
  struct GNUNET_DHTLOG_Handle *dhtlog_api = cls;
#if DEBUG_DHTLOG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MySQL DHT Logger: database shutdown\n");
#endif
  GNUNET_assert(dhtlog_api != NULL);

  GNUNET_free(dhtlog_api);
  return NULL;
}

/* end of plugin_dhtlog_mysql.c */
