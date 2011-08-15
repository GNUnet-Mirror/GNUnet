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
 * @brief MySQL logging plugin to record DHT operations to MySQL server
 * @author Nathan Evans
 *
 * Database: MySQL
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "dhtlog.h"
#include <mysql/mysql.h>


#define DEBUG_DHTLOG GNUNET_YES

/**
 * Maximum number of supported parameters for a prepared
 * statement.  Increase if needed.
 */
#define MAX_PARAM 32

/**
 * A generic statement handle to use
 * for prepared statements.  This way,
 * once the statement is initialized
 * we don't redo work.
 */
struct StatementHandle
{
  /**
   * Internal statement
   */
  MYSQL_STMT *statement;

  /**
   * Textual query
   */
  char *query;

  /**
   * Whether or not the handle is valid
   */
  int valid;
};

/**
 * Type of a callback that will be called for each
 * data set returned from MySQL.
 *
 * @param cls user-defined argument
 * @param num_values number of elements in values
 * @param values values returned by MySQL
 * @return GNUNET_OK to continue iterating, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_MysqlDataProcessor) (void *cls, unsigned int num_values,
                                          MYSQL_BIND * values);

static unsigned long max_varchar_len;

/**
 * The configuration the DHT service is running with
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

static unsigned long long current_trial = 0;    /* I like to assign 0, just to remember */

/**
 * Connection to the MySQL Server.
 */
static MYSQL *conn;

#define INSERT_QUERIES_STMT "INSERT INTO queries (trialuid, querytype, hops, dhtkeyuid, dhtqueryid, succeeded, nodeuid, time) "\
                          "VALUES (?, ?, ?, ?, ?, ?, ?, NOW())"
static struct StatementHandle *insert_query;

#define INSERT_ROUTES_STMT "INSERT INTO routes (trialuid, querytype, hops, dhtkeyuid, dhtqueryid, succeeded, nodeuid, from_node, to_node) "\
                          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
static struct StatementHandle *insert_route;

#define INSERT_NODES_STMT "INSERT INTO nodes (trialuid, nodeid, nodebits) "\
                          "VALUES (?, ?, ?)"
static struct StatementHandle *insert_node;

#define INSERT_ROUNDS_STMT "INSERT INTO rounds (trialuid, round_type, round_count, starttime) "\
                          "VALUES (?, ?, ?, NOW())"

static struct StatementHandle *insert_round;

#define INSERT_ROUND_DETAILS_STMT "INSERT INTO rounds (trialuid, round_type, round_count, starttime, endtime, num_messages, num_messages_succeeded) "\
                          "VALUES (?, ?, ?, NOW(), NOW(), ?, ?)"

static struct StatementHandle *insert_round_details;

#define INSERT_TRIALS_STMT "INSERT INTO trials"\
                            "(starttime, other_trial_identifier, numnodes, topology,"\
                            "topology_percentage, topology_probability,"\
                            "blacklist_topology, connect_topology, connect_topology_option,"\
                            "connect_topology_option_modifier, puts, gets, "\
                            "concurrent, settle_time, num_rounds, malicious_getters,"\
                            "malicious_putters, malicious_droppers, malicious_get_frequency,"\
                            "malicious_put_frequency, stop_closest, stop_found, strict_kademlia, "\
                            "gets_succeeded, message) "\
                            "VALUES (NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

static struct StatementHandle *insert_trial;

#define INSERT_STAT_STMT "INSERT INTO node_statistics"\
                            "(trialuid, nodeuid, route_requests,"\
                            "route_forwards, result_requests,"\
                            "client_results, result_forwards, gets,"\
                            "puts, data_inserts, find_peer_requests, "\
                            "find_peers_started, gets_started, puts_started, find_peer_responses_received,"\
                            "get_responses_received, find_peer_responses_sent, get_responses_sent) "\
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

static struct StatementHandle *insert_stat;

#define INSERT_GENERIC_STAT_STMT "INSERT INTO generic_stats" \
                                 "(trialuid, nodeuid, section, name, value)"\
                                 "VALUES (?, ?, ?, ?, ?)"
static struct StatementHandle *insert_generic_stat;

#define INSERT_DHTKEY_STMT "INSERT INTO dhtkeys (dhtkey, trialuid, keybits) "\
                          "VALUES (?, ?, ?)"
static struct StatementHandle *insert_dhtkey;

#define UPDATE_TRIALS_STMT "UPDATE trials set endtime=NOW(), gets_succeeded = ? where trialuid = ?"
static struct StatementHandle *update_trial;

#define UPDATE_CONNECTIONS_STMT "UPDATE trials set totalConnections = ? where trialuid = ?"
static struct StatementHandle *update_connection;

#define GET_TRIAL_STMT "SELECT MAX( trialuid ) FROM trials"
static struct StatementHandle *get_trial;

#define GET_TOPOLOGY_STMT "SELECT MAX( topology_uid ) FROM topology"
static struct StatementHandle *get_topology;

#define GET_DHTKEYUID_STMT "SELECT dhtkeyuid FROM dhtkeys where dhtkey = ? and trialuid = ?"
static struct StatementHandle *get_dhtkeyuid;

#define GET_NODEUID_STMT "SELECT nodeuid FROM nodes where trialuid = ? and nodeid = ?"
static struct StatementHandle *get_nodeuid;

#define INSERT_TOPOLOGY_STMT "INSERT INTO topology (trialuid, date, connections) "\
                             "VALUES (?, NOW(), ?)"
static struct StatementHandle *insert_topology;

#define EXTEND_TOPOLOGY_STMT "INSERT INTO extended_topology (topology_uid, uid_first, uid_second) "\
                             "VALUES (?, ?, ?)"
static struct StatementHandle *extend_topology;

#define SET_MALICIOUS_STMT "update nodes set malicious_dropper = 1  where trialuid = ? and nodeid = ?"
static struct StatementHandle *update_node_malicious;

#define UPDATE_TOPOLOGY_STMT "update topology set connections = ?  where topology_uid = ?"
static struct StatementHandle *update_topology;

/**
 * Run a query (not a select statement)
 *
 * @return GNUNET_OK if executed, GNUNET_SYSERR if an error occurred
 */
int
run_statement (const char *statement)
{
  mysql_query (conn, statement);
  if (mysql_error (conn)[0])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "mysql_query");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

/*
 * Creates tables if they don't already exist for dht logging
 */
static int
itable ()
{
#define MRUNS(a) (GNUNET_OK != run_statement (a) )

  if (MRUNS
      ("CREATE TABLE IF NOT EXISTS `dhtkeys` ("
       "dhtkeyuid int(10) unsigned NOT NULL auto_increment COMMENT 'Unique Key given to each query',"
       "`dhtkey` varchar(255) NOT NULL COMMENT 'The ASCII value of the key being searched for',"
       "trialuid int(10) unsigned NOT NULL," "keybits blob NOT NULL,"
       "UNIQUE KEY `dhtkeyuid` (`dhtkeyuid`)"
       ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS
      ("CREATE TABLE IF NOT EXISTS `nodes` ("
       "`nodeuid` int(10) unsigned NOT NULL auto_increment,"
       "`trialuid` int(10) unsigned NOT NULL," "`nodeid` varchar(255) NOT NULL,"
       "`nodebits` blob NOT NULL," "PRIMARY KEY  (`nodeuid`)"
       ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS
      ("CREATE TABLE IF NOT EXISTS `queries` ("
       "`trialuid` int(10) unsigned NOT NULL,"
       "`queryuid` int(10) unsigned NOT NULL auto_increment,"
       "`dhtqueryid` bigint(20) NOT NULL,"
       "`querytype` enum('1','2','3','4','5') NOT NULL,"
       "`hops` int(10) unsigned NOT NULL," "`succeeded` tinyint NOT NULL,"
       "`nodeuid` int(10) unsigned NOT NULL,"
       "`time` timestamp NOT NULL default CURRENT_TIMESTAMP,"
       "`dhtkeyuid` int(10) unsigned NOT NULL," "PRIMARY KEY  (`queryuid`)"
       ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS
      ("CREATE TABLE IF NOT EXISTS `routes` ("
       "`trialuid` int(10) unsigned NOT NULL,"
       "`queryuid` int(10) unsigned NOT NULL auto_increment,"
       "`dhtqueryid` bigint(20) NOT NULL,"
       "`querytype` enum('1','2','3','4','5') NOT NULL,"
       "`hops` int(10) unsigned NOT NULL," "`succeeded` tinyint NOT NULL,"
       "`nodeuid` int(10) unsigned NOT NULL,"
       "`time` timestamp NOT NULL default CURRENT_TIMESTAMP,"
       "`dhtkeyuid` int(10) unsigned NOT NULL,"
       "`from_node` int(10) unsigned NOT NULL,"
       "`to_node` int(10) unsigned NOT NULL," "PRIMARY KEY  (`queryuid`)"
       ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS
      ("CREATE TABLE IF NOT EXISTS `trials` ("
       "`trialuid` int(10) unsigned NOT NULL auto_increment,"
       "`other_trial_identifier` int(10) unsigned NOT NULL default '0',"
       "`numnodes` int(10) unsigned NOT NULL," "`topology` int(10) NOT NULL,"
       "`blacklist_topology` int(11) NOT NULL,"
       "`connect_topology` int(11) NOT NULL,"
       "`connect_topology_option` int(11) NOT NULL,"
       "`topology_percentage` float NOT NULL,"
       "`topology_probability` float NOT NULL,"
       "`connect_topology_option_modifier` float NOT NULL,"
       "`starttime` datetime NOT NULL," "`endtime` datetime NOT NULL,"
       "`puts` int(10) unsigned NOT NULL," "`gets` int(10) unsigned NOT NULL,"
       "`concurrent` int(10) unsigned NOT NULL,"
       "`settle_time` int(10) unsigned NOT NULL,"
       "`totalConnections` int(10) unsigned NOT NULL,"
       "`message` text NOT NULL," "`num_rounds` int(10) unsigned NOT NULL,"
       "`malicious_getters` int(10) unsigned NOT NULL,"
       "`malicious_putters` int(10) unsigned NOT NULL,"
       "`malicious_droppers` int(10) unsigned NOT NULL,"
       "`topology_modifier` double NOT NULL,"
       "`malicious_get_frequency` int(10) unsigned NOT NULL,"
       "`malicious_put_frequency` int(10) unsigned NOT NULL,"
       "`stop_closest` int(10) unsigned NOT NULL,"
       "`stop_found` int(10) unsigned NOT NULL,"
       "`strict_kademlia` int(10) unsigned NOT NULL,"
       "`gets_succeeded` int(10) unsigned NOT NULL,"
       "PRIMARY KEY  (`trialuid`)," "UNIQUE KEY `trialuid` (`trialuid`)"
       ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS
      ("CREATE TABLE IF NOT EXISTS `topology` ("
       "`topology_uid` int(10) unsigned NOT NULL AUTO_INCREMENT,"
       "`trialuid` int(10) unsigned NOT NULL," "`date` datetime NOT NULL,"
       "`connections` int(10) unsigned NOT NULL,"
       "PRIMARY KEY (`topology_uid`)) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS
      ("CREATE TABLE IF NOT EXISTS `extended_topology` ("
       "`extended_uid` int(10) unsigned NOT NULL AUTO_INCREMENT,"
       "`topology_uid` int(10) unsigned NOT NULL,"
       "`uid_first` int(10) unsigned NOT NULL,"
       "`uid_second` int(10) unsigned NOT NULL," "PRIMARY KEY (`extended_uid`)"
       ") ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS
      ("CREATE TABLE IF NOT EXISTS `node_statistics` ("
       "`stat_uid` int(10) unsigned NOT NULL AUTO_INCREMENT,"
       "`trialuid` int(10) unsigned NOT NULL,"
       "`nodeuid` int(10) unsigned NOT NULL,"
       "`route_requests` int(10) unsigned NOT NULL,"
       "`route_forwards` int(10) unsigned NOT NULL,"
       "`result_requests` int(10) unsigned NOT NULL,"
       "`client_results` int(10) unsigned NOT NULL,"
       "`result_forwards` int(10) unsigned NOT NULL,"
       "`gets` int(10) unsigned NOT NULL," "`puts` int(10) unsigned NOT NULL,"
       "`data_inserts` int(10) unsigned NOT NULL,"
       "`find_peer_requests` int(10) unsigned NOT NULL,"
       "`find_peers_started` int(10) unsigned NOT NULL,"
       "`gets_started` int(10) unsigned NOT NULL,"
       "`puts_started` int(10) unsigned NOT NULL,"
       "`find_peer_responses_received` int(10) unsigned NOT NULL,"
       "`get_responses_received` int(10) unsigned NOT NULL,"
       "`find_peer_responses_sent` int(10) unsigned NOT NULL,"
       "`get_responses_sent` int(10) unsigned NOT NULL,"
       "PRIMARY KEY (`stat_uid`)"
       ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;"))
    return GNUNET_SYSERR;

  if (MRUNS ("SET AUTOCOMMIT = 1"))
    return GNUNET_SYSERR;

  return GNUNET_OK;
#undef MRUNS
}

/**
 * Create a prepared statement.
 *
 * @return NULL on error
 */
struct StatementHandle *
prepared_statement_create (const char *statement)
{
  struct StatementHandle *ret;

  ret = GNUNET_malloc (sizeof (struct StatementHandle));
  ret->query = GNUNET_strdup (statement);
  return ret;
}

/**
 * Close a prepared statement.
 *
 * @return NULL on error
 */
void
prepared_statement_close (struct StatementHandle *s)
{
  if (s == NULL)
  {
    return;
  }

  GNUNET_free_non_null (s->query);

  if (s->valid == GNUNET_YES)
    mysql_stmt_close (s->statement);
  GNUNET_free (s);
}

/*
 * Initialize the prepared statements for use with dht test logging
 */
static int
iopen (struct GNUNET_DHTLOG_Plugin *plugin)
{
  int ret;
  my_bool reconnect;
  unsigned int timeout;
  char *user;
  char *password;
  char *server;
  char *database;
  unsigned long long port;

  conn = mysql_init (NULL);
  if (conn == NULL)
    return GNUNET_SYSERR;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (plugin->cfg, "MYSQL", "DATABASE",
                                             &database))
  {
    database = GNUNET_strdup ("gnunet");
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (plugin->cfg, "MYSQL", "USER",
                                             &user))
  {
    user = GNUNET_strdup ("dht");
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (plugin->cfg, "MYSQL", "PASSWORD",
                                             &password))
  {
    password = GNUNET_strdup ("dhttest**");
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (plugin->cfg, "MYSQL", "SERVER",
                                             &server))
  {
    server = GNUNET_strdup ("localhost");
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (plugin->cfg, "MYSQL", "MYSQL_PORT",
                                             &port))
  {
    port = 0;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connecting to mysql with: user %s, pass %s, server %s, database %s, port %d\n",
              user, password, server, database, port);

  reconnect = 0;
  timeout = 60;                 /* in seconds */
  mysql_options (conn, MYSQL_OPT_RECONNECT, &reconnect);
  mysql_options (conn, MYSQL_OPT_CONNECT_TIMEOUT, (const void *) &timeout);
  mysql_options (conn, MYSQL_SET_CHARSET_NAME, "UTF8");
  mysql_options (conn, MYSQL_OPT_READ_TIMEOUT, (const void *) &timeout);
  mysql_options (conn, MYSQL_OPT_WRITE_TIMEOUT, (const void *) &timeout);
  mysql_real_connect (conn, server, user, password, database,
                      (unsigned int) port, NULL, CLIENT_IGNORE_SIGPIPE);

  GNUNET_free_non_null (server);
  GNUNET_free_non_null (password);
  GNUNET_free_non_null (user);
  GNUNET_free_non_null (database);

  if (mysql_error (conn)[0])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "mysql_real_connect");
    return GNUNET_SYSERR;
  }

#if OLD
  db = GNUNET_MYSQL_database_open (coreAPI->ectx, coreAPI->cfg);
  if (db == NULL)
    return GNUNET_SYSERR;
#endif

  ret = itable ();

#define PINIT(a,b) (NULL == (a = prepared_statement_create(b)))
  if (PINIT (insert_query, INSERT_QUERIES_STMT) ||
      PINIT (insert_route, INSERT_ROUTES_STMT) ||
      PINIT (insert_trial, INSERT_TRIALS_STMT) ||
      PINIT (insert_round, INSERT_ROUNDS_STMT) ||
      PINIT (insert_round_details, INSERT_ROUND_DETAILS_STMT) ||
      PINIT (insert_stat, INSERT_STAT_STMT) ||
      PINIT (insert_generic_stat, INSERT_GENERIC_STAT_STMT) ||
      PINIT (insert_node, INSERT_NODES_STMT) ||
      PINIT (insert_dhtkey, INSERT_DHTKEY_STMT) ||
      PINIT (update_trial, UPDATE_TRIALS_STMT) ||
      PINIT (get_dhtkeyuid, GET_DHTKEYUID_STMT) ||
      PINIT (get_nodeuid, GET_NODEUID_STMT) ||
      PINIT (update_connection, UPDATE_CONNECTIONS_STMT) ||
      PINIT (get_trial, GET_TRIAL_STMT) ||
      PINIT (get_topology, GET_TOPOLOGY_STMT) ||
      PINIT (insert_topology, INSERT_TOPOLOGY_STMT) ||
      PINIT (update_topology, UPDATE_TOPOLOGY_STMT) ||
      PINIT (extend_topology, EXTEND_TOPOLOGY_STMT) ||
      PINIT (update_node_malicious, SET_MALICIOUS_STMT))
  {
    return GNUNET_SYSERR;
  }
#undef PINIT

  return ret;
}

static int
return_ok (void *cls, unsigned int num_values, MYSQL_BIND * values)
{
  return GNUNET_OK;
}

/**
 * Prepare a statement for running.
 *
 * @return GNUNET_OK on success
 */
static int
prepare_statement (struct StatementHandle *ret)
{
  if (GNUNET_YES == ret->valid)
    return GNUNET_OK;

  ret->statement = mysql_stmt_init (conn);
  if (ret->statement == NULL)
    return GNUNET_SYSERR;

  if (mysql_stmt_prepare (ret->statement, ret->query, strlen (ret->query)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "mysql_stmt_prepare `%s', %s",
                ret->query, mysql_error (conn));
    mysql_stmt_close (ret->statement);
    ret->statement = NULL;
    return GNUNET_SYSERR;
  }
  ret->valid = GNUNET_YES;
  return GNUNET_OK;
}

/**
 * Bind the parameters for the given MySQL statement
 * and run it.
 *
 * @param s statement to bind and run
 * @param ap arguments for the binding
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
static int
init_params (struct StatementHandle *s, va_list ap)
{
  MYSQL_BIND qbind[MAX_PARAM];
  unsigned int pc;
  unsigned int off;
  enum enum_field_types ft;

  pc = mysql_stmt_param_count (s->statement);
  if (pc > MAX_PARAM)
  {
    /* increase internal constant! */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  memset (qbind, 0, sizeof (qbind));
  off = 0;
  ft = 0;
  while ((pc > 0) && (-1 != (ft = va_arg (ap, enum enum_field_types))))
  {
    qbind[off].buffer_type = ft;
    switch (ft)
    {
    case MYSQL_TYPE_FLOAT:
      qbind[off].buffer = va_arg (ap, float *);

      break;
    case MYSQL_TYPE_LONGLONG:
      qbind[off].buffer = va_arg (ap, unsigned long long *);
      qbind[off].is_unsigned = va_arg (ap, int);

      break;
    case MYSQL_TYPE_LONG:
      qbind[off].buffer = va_arg (ap, unsigned int *);
      qbind[off].is_unsigned = va_arg (ap, int);

      break;
    case MYSQL_TYPE_VAR_STRING:
    case MYSQL_TYPE_STRING:
    case MYSQL_TYPE_BLOB:
      qbind[off].buffer = va_arg (ap, void *);
      qbind[off].buffer_length = va_arg (ap, unsigned long);
      qbind[off].length = va_arg (ap, unsigned long *);

      break;
    default:
      /* unsupported type */
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    pc--;
    off++;
  }
  if (!((pc == 0) && (ft != -1) && (va_arg (ap, int) == -1)))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (mysql_stmt_bind_param (s->statement, qbind))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("`%s' failed at %s:%d with error: %s\n"),
                "mysql_stmt_bind_param", __FILE__, __LINE__,
                mysql_stmt_error (s->statement));
    return GNUNET_SYSERR;
  }

  if (mysql_stmt_execute (s->statement))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("`%s' failed at %s:%d with error: %s\n"),
                "mysql_stmt_execute", __FILE__, __LINE__,
                mysql_stmt_error (s->statement));
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}

/**
 * Run a prepared SELECT statement.
 *
 * @param s handle to the statement we should execute
 * @param result_size number of results in set
 * @param results pointer to already initialized MYSQL_BIND
 *        array (of sufficient size) for passing results
 * @param processor function to call on each result
 * @param processor_cls extra argument to processor
 * @param ... pairs and triplets of "MYSQL_TYPE_XXX" keys and their respective
 *        values (size + buffer-reference for pointers); terminated
 *        with "-1"
 *
 * @return GNUNET_SYSERR on error, otherwise
 *         the number of successfully affected (or queried) rows
 */
int
prepared_statement_run_select (struct StatementHandle *s,
                               unsigned int result_size, MYSQL_BIND * results,
                               GNUNET_MysqlDataProcessor processor,
                               void *processor_cls, ...)
{
  va_list ap;
  int ret;
  unsigned int rsize;
  int total;

  if (GNUNET_OK != prepare_statement (s))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  va_start (ap, processor_cls);
  if (GNUNET_OK != init_params (s, ap))
  {
    GNUNET_break (0);
    va_end (ap);
    return GNUNET_SYSERR;
  }
  va_end (ap);
  rsize = mysql_stmt_field_count (s->statement);
  if (rsize > result_size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (mysql_stmt_bind_result (s->statement, results))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("`%s' failed at %s:%d with error: %s\n"),
                "mysql_stmt_bind_result", __FILE__, __LINE__,
                mysql_stmt_error (s->statement));
    return GNUNET_SYSERR;
  }

  total = 0;
  while (1)
  {
    ret = mysql_stmt_fetch (s->statement);
    if (ret == MYSQL_NO_DATA)
      break;
    if (ret != 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("`%s' failed at %s:%d with error: %s\n"),
                  "mysql_stmt_fetch", __FILE__, __LINE__,
                  mysql_stmt_error (s->statement));
      return GNUNET_SYSERR;
    }
    if (processor != NULL)
      if (GNUNET_OK != processor (processor_cls, rsize, results))
        break;
    total++;
  }
  mysql_stmt_reset (s->statement);
  return total;
}


static int
get_node_uid (unsigned long long *nodeuid, const GNUNET_HashCode * peerHash)
{
  MYSQL_BIND rbind[1];
  struct GNUNET_CRYPTO_HashAsciiEncoded encPeer;
  unsigned long long p_len;

  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[0].buffer = nodeuid;
  rbind[0].is_unsigned = GNUNET_YES;

  GNUNET_CRYPTO_hash_to_enc (peerHash, &encPeer);
  p_len = strlen ((char *) &encPeer);

  if (1 !=
      prepared_statement_run_select (get_nodeuid, 1, rbind, return_ok, NULL,
                                     MYSQL_TYPE_LONGLONG, &current_trial,
                                     GNUNET_YES, MYSQL_TYPE_VAR_STRING,
                                     &encPeer, max_varchar_len, &p_len, -1))
  {
#if DEBUG_DHTLOG
    fprintf (stderr, "FAILED\n");
#endif
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

static int
get_current_trial (unsigned long long *trialuid)
{
  MYSQL_BIND rbind[1];

  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONG;
  rbind[0].is_unsigned = 1;
  rbind[0].buffer = trialuid;

  if ((GNUNET_OK !=
       prepared_statement_run_select (get_trial, 1, rbind, return_ok, NULL,
                                      -1)))
  {
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}

static int
get_current_topology (unsigned long long *topologyuid)
{
  MYSQL_BIND rbind[1];

  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[0].is_unsigned = 1;
  rbind[0].buffer = topologyuid;

  if ((GNUNET_OK !=
       prepared_statement_run_select (get_topology, 1, rbind, return_ok, NULL,
                                      -1)))
  {
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}

static int
get_dhtkey_uid (unsigned long long *dhtkeyuid, const GNUNET_HashCode * key)
{
  MYSQL_BIND rbind[1];
  struct GNUNET_CRYPTO_HashAsciiEncoded encKey;
  unsigned long long k_len;

  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONG;
  rbind[0].is_unsigned = 1;
  rbind[0].buffer = dhtkeyuid;
  GNUNET_CRYPTO_hash_to_enc (key, &encKey);
  k_len = strlen ((char *) &encKey);
#if DEBUG_DHTLOG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Searching for dhtkey `%s' in trial %llu\n", GNUNET_h2s (key),
              current_trial);
#endif
  if ((GNUNET_OK !=
       prepared_statement_run_select (get_dhtkeyuid, 1, rbind, return_ok, NULL,
                                      MYSQL_TYPE_VAR_STRING, &encKey,
                                      max_varchar_len, &k_len,
                                      MYSQL_TYPE_LONGLONG, &current_trial,
                                      GNUNET_YES, -1)))
  {
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}

/**
 * Run a prepared statement that does NOT produce results.
 *
 * @param s handle to the statement we should execute
 * @param insert_id NULL or address where to store the row ID of whatever
 *        was inserted (only for INSERT statements!)
 * @param ... pairs and triplets of "MYSQL_TYPE_XXX" keys and their respective
 *        values (size + buffer-reference for pointers); terminated
 *        with "-1"
 *
 * @return GNUNET_SYSERR on error, otherwise
 *         the number of successfully affected rows
 */
int
prepared_statement_run (struct StatementHandle *s,
                        unsigned long long *insert_id, ...)
{
  va_list ap;
  int affected;

  if (GNUNET_OK != prepare_statement (s))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_assert (s->valid == GNUNET_YES);
  if (s->statement == NULL)
    return GNUNET_SYSERR;

  va_start (ap, insert_id);

  if (GNUNET_OK != init_params (s, ap))
  {
    va_end (ap);
    return GNUNET_SYSERR;
  }

  va_end (ap);
  affected = mysql_stmt_affected_rows (s->statement);
  if (NULL != insert_id)
    *insert_id = (unsigned long long) mysql_stmt_insert_id (s->statement);
  mysql_stmt_reset (s->statement);

  return affected;
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
  MYSQL_STMT *stmt;
  int ret;
  unsigned long long m_len;

  m_len = strlen (trial_info->message);

  stmt = mysql_stmt_init (conn);
  if (GNUNET_OK !=
      (ret =
       prepared_statement_run (insert_trial, &current_trial, MYSQL_TYPE_LONG,
                               &trial_info->other_identifier, GNUNET_YES,
                               MYSQL_TYPE_LONG, &trial_info->num_nodes,
                               GNUNET_YES, MYSQL_TYPE_LONG,
                               &trial_info->topology, GNUNET_YES,
                               MYSQL_TYPE_FLOAT,
                               &trial_info->topology_percentage,
                               MYSQL_TYPE_FLOAT,
                               &trial_info->topology_probability,
                               MYSQL_TYPE_LONG, &trial_info->blacklist_topology,
                               GNUNET_YES, MYSQL_TYPE_LONG,
                               &trial_info->connect_topology, GNUNET_YES,
                               MYSQL_TYPE_LONG,
                               &trial_info->connect_topology_option, GNUNET_YES,
                               MYSQL_TYPE_FLOAT,
                               &trial_info->connect_topology_option_modifier,
                               MYSQL_TYPE_LONG, &trial_info->puts, GNUNET_YES,
                               MYSQL_TYPE_LONG, &trial_info->gets, GNUNET_YES,
                               MYSQL_TYPE_LONG, &trial_info->concurrent,
                               GNUNET_YES, MYSQL_TYPE_LONG,
                               &trial_info->settle_time, GNUNET_YES,
                               MYSQL_TYPE_LONG, &trial_info->num_rounds,
                               GNUNET_YES, MYSQL_TYPE_LONG,
                               &trial_info->malicious_getters, GNUNET_YES,
                               MYSQL_TYPE_LONG, &trial_info->malicious_putters,
                               GNUNET_YES, MYSQL_TYPE_LONG,
                               &trial_info->malicious_droppers, GNUNET_YES,
                               MYSQL_TYPE_LONG,
                               &trial_info->malicious_get_frequency, GNUNET_YES,
                               MYSQL_TYPE_LONG,
                               &trial_info->malicious_put_frequency, GNUNET_YES,
                               MYSQL_TYPE_LONG, &trial_info->stop_closest,
                               GNUNET_YES, MYSQL_TYPE_LONG,
                               &trial_info->stop_found, GNUNET_YES,
                               MYSQL_TYPE_LONG, &trial_info->strict_kademlia,
                               GNUNET_YES, MYSQL_TYPE_LONG,
                               &trial_info->gets_succeeded, GNUNET_YES,
                               MYSQL_TYPE_BLOB, trial_info->message,
                               max_varchar_len + max_varchar_len, &m_len, -1)))
  {
    if (ret == GNUNET_SYSERR)
    {
      mysql_stmt_close (stmt);
      return GNUNET_SYSERR;
    }
  }

  get_current_trial (&current_trial);

  mysql_stmt_close (stmt);
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

  MYSQL_STMT *stmt;
  int ret;

  stmt = mysql_stmt_init (conn);
  ret =
      prepared_statement_run (insert_round, NULL, MYSQL_TYPE_LONGLONG,
                              &current_trial, GNUNET_YES, MYSQL_TYPE_LONG,
                              &round_type, GNUNET_YES, MYSQL_TYPE_LONG,
                              &round_count, GNUNET_YES, -1);
  mysql_stmt_close (stmt);
  if (ret != GNUNET_OK)
    return GNUNET_SYSERR;
  return ret;
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
  MYSQL_STMT *stmt;
  int ret;

  stmt = mysql_stmt_init (conn);
  ret =
      prepared_statement_run (insert_round_details, NULL, MYSQL_TYPE_LONGLONG,
                              &current_trial, GNUNET_YES, MYSQL_TYPE_LONG,
                              &round_type, GNUNET_YES, MYSQL_TYPE_LONG,
                              &round_count, GNUNET_YES, MYSQL_TYPE_LONG,
                              &num_messages, GNUNET_YES, MYSQL_TYPE_LONG,
                              &num_messages_succeeded, GNUNET_YES, -1);
  mysql_stmt_close (stmt);
  if (ret != GNUNET_OK)
    return GNUNET_SYSERR;
  return ret;
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
  MYSQL_STMT *stmt;
  int ret;
  unsigned long long peer_uid;
  unsigned long long return_uid;

  if (peer == NULL)
    return GNUNET_SYSERR;

  if (GNUNET_OK != get_node_uid (&peer_uid, &peer->hashPubKey))
  {
    return GNUNET_SYSERR;
  }

  stmt = mysql_stmt_init (conn);
  if (GNUNET_OK !=
      (ret =
       prepared_statement_run (insert_stat, &return_uid, MYSQL_TYPE_LONGLONG,
                               &current_trial, GNUNET_YES, MYSQL_TYPE_LONGLONG,
                               &peer_uid, GNUNET_YES, MYSQL_TYPE_LONG,
                               &route_requests, GNUNET_YES, MYSQL_TYPE_LONG,
                               &route_forwards, GNUNET_YES, MYSQL_TYPE_LONG,
                               &result_requests, GNUNET_YES, MYSQL_TYPE_LONG,
                               &client_requests, GNUNET_YES, MYSQL_TYPE_LONG,
                               &result_forwards, GNUNET_YES, MYSQL_TYPE_LONG,
                               &gets, GNUNET_YES, MYSQL_TYPE_LONG, &puts,
                               GNUNET_YES, MYSQL_TYPE_LONG, &data_inserts,
                               GNUNET_YES, MYSQL_TYPE_LONG, &find_peer_requests,
                               GNUNET_YES, MYSQL_TYPE_LONG, &find_peers_started,
                               GNUNET_YES, MYSQL_TYPE_LONG, &gets_started,
                               GNUNET_YES, MYSQL_TYPE_LONG, &puts_started,
                               GNUNET_YES, MYSQL_TYPE_LONG,
                               &find_peer_responses_received, GNUNET_YES,
                               MYSQL_TYPE_LONG, &get_responses_received,
                               GNUNET_YES, MYSQL_TYPE_LONG,
                               &find_peer_responses_sent, GNUNET_YES,
                               MYSQL_TYPE_LONG, &get_responses_sent, GNUNET_YES,
                               -1)))
  {
    if (ret == GNUNET_SYSERR)
    {
      mysql_stmt_close (stmt);
      return GNUNET_SYSERR;
    }
  }

  mysql_stmt_close (stmt);
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
  unsigned long long peer_uid;
  unsigned long long section_len;
  unsigned long long name_len;
  int ret;

  if (peer == NULL)
    return GNUNET_SYSERR;

  if (GNUNET_OK != get_node_uid (&peer_uid, &peer->hashPubKey))
  {
    return GNUNET_SYSERR;
  }

  section_len = strlen (section);
  name_len = strlen (name);

  if (GNUNET_OK !=
      (ret =
       prepared_statement_run (insert_generic_stat, NULL, MYSQL_TYPE_LONGLONG,
                               &current_trial, GNUNET_YES, MYSQL_TYPE_LONGLONG,
                               &peer_uid, GNUNET_YES, MYSQL_TYPE_VAR_STRING,
                               &section, max_varchar_len, &section_len,
                               MYSQL_TYPE_VAR_STRING, &name, max_varchar_len,
                               &name_len, MYSQL_TYPE_LONGLONG, &value,
                               GNUNET_YES, -1)))
  {
    if (ret == GNUNET_SYSERR)
    {
      return GNUNET_SYSERR;
    }
  }
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
  struct GNUNET_CRYPTO_HashAsciiEncoded encKey;
  unsigned long long k_len;
  unsigned long long h_len;
  unsigned long long curr_dhtkeyuid;

  GNUNET_CRYPTO_hash_to_enc (dhtkey, &encKey);
  k_len = strlen ((char *) &encKey);
  h_len = sizeof (GNUNET_HashCode);
  curr_dhtkeyuid = 0;
  ret = get_dhtkey_uid (&curr_dhtkeyuid, dhtkey);
  if (curr_dhtkeyuid != 0)      /* dhtkey already exists */
  {
    if (dhtkeyuid != NULL)
      *dhtkeyuid = curr_dhtkeyuid;
    return GNUNET_OK;
  }
  else if (ret == GNUNET_SYSERR)
  {
#if DEBUG_DHTLOG
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to get dhtkeyuid!\n");
#endif
  }

  if (GNUNET_OK !=
      (ret =
       prepared_statement_run (insert_dhtkey, dhtkeyuid, MYSQL_TYPE_VAR_STRING,
                               &encKey, max_varchar_len, &k_len,
                               MYSQL_TYPE_LONG, &current_trial, GNUNET_YES,
                               MYSQL_TYPE_BLOB, dhtkey,
                               sizeof (GNUNET_HashCode), &h_len, -1)))
  {
    if (ret == GNUNET_SYSERR)
    {
      return GNUNET_SYSERR;
    }
  }

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
  struct GNUNET_CRYPTO_HashAsciiEncoded encPeer;
  unsigned long p_len;
  unsigned long h_len;
  int ret;

  if (node == NULL)
    return GNUNET_SYSERR;

  GNUNET_CRYPTO_hash_to_enc (&node->hashPubKey, &encPeer);
  p_len = (unsigned long) strlen ((char *) &encPeer);
  h_len = sizeof (GNUNET_HashCode);
  if (GNUNET_OK !=
      (ret =
       prepared_statement_run (insert_node, nodeuid, MYSQL_TYPE_LONGLONG,
                               &current_trial, GNUNET_YES,
                               MYSQL_TYPE_VAR_STRING, &encPeer, max_varchar_len,
                               &p_len, MYSQL_TYPE_BLOB, &node->hashPubKey,
                               sizeof (GNUNET_HashCode), &h_len, -1)))
  {
    if (ret == GNUNET_SYSERR)
    {
      return GNUNET_SYSERR;
    }
  }
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
  int ret;

  if (GNUNET_OK !=
      (ret =
       prepared_statement_run (update_trial, NULL, MYSQL_TYPE_LONG,
                               &gets_succeeded, GNUNET_YES, MYSQL_TYPE_LONGLONG,
                               &current_trial, GNUNET_YES, -1)))
  {
    if (ret == GNUNET_SYSERR)
    {
      return GNUNET_SYSERR;
    }
  }
  if (ret > 0)
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
  unsigned long long p_len;
  int ret;
  char *temp_str;

  temp_str = GNUNET_strdup (GNUNET_h2s_full (&peer->hashPubKey));
  p_len = strlen (temp_str);

  if (GNUNET_OK !=
      (ret =
       prepared_statement_run (update_node_malicious, NULL, MYSQL_TYPE_LONGLONG,
                               &current_trial, GNUNET_YES,
                               MYSQL_TYPE_VAR_STRING, temp_str, max_varchar_len,
                               &p_len, -1)))
  {
    if (ret == GNUNET_SYSERR)
    {
      return GNUNET_SYSERR;
    }
  }
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
  int ret;

  if (GNUNET_OK !=
      (ret =
       prepared_statement_run (update_connection, NULL, MYSQL_TYPE_LONG,
                               &totalConnections, GNUNET_YES,
                               MYSQL_TYPE_LONGLONG, &current_trial, GNUNET_YES,
                               -1)))
  {
    if (ret == GNUNET_SYSERR)
    {
      return GNUNET_SYSERR;
    }
  }
  if (ret > 0)
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
  unsigned long long peer_uid, key_uid;

  peer_uid = 0;
  key_uid = 0;

  if ((node != NULL) &&
      (GNUNET_OK == get_node_uid (&peer_uid, &node->hashPubKey)))
  {

  }
  else
  {
    return GNUNET_SYSERR;
  }

  if ((key != NULL) && (GNUNET_OK == get_dhtkey_uid (&key_uid, key)))
  {

  }
  else if ((key != NULL) && (key->bits[(512 / 8 / sizeof (unsigned int)) - 1] == 42))   /* Malicious marker */
  {
    key_uid = 0;
  }
  else
  {
    return GNUNET_SYSERR;
  }

  if (GNUNET_OK !=
      (ret =
       prepared_statement_run (insert_query, sqlqueryuid, MYSQL_TYPE_LONGLONG,
                               &current_trial, GNUNET_YES, MYSQL_TYPE_LONG,
                               &type, GNUNET_NO, MYSQL_TYPE_LONG, &hops,
                               GNUNET_YES, MYSQL_TYPE_LONGLONG, &key_uid,
                               GNUNET_YES, MYSQL_TYPE_LONGLONG, &queryid,
                               GNUNET_YES, MYSQL_TYPE_LONG, &succeeded,
                               GNUNET_NO, MYSQL_TYPE_LONGLONG, &peer_uid,
                               GNUNET_YES, -1)))
  {
    if (ret == GNUNET_SYSERR)
    {
      return GNUNET_SYSERR;
    }
  }
  if (ret > 0)
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
  unsigned long long peer_uid = 0;
  unsigned long long key_uid = 0;
  unsigned long long from_uid = 0;
  unsigned long long to_uid = 0;
  int ret;

  if (from_node != NULL)
    get_node_uid (&from_uid, &from_node->hashPubKey);

  if (to_node != NULL)
    get_node_uid (&to_uid, &to_node->hashPubKey);
  else
    to_uid = 0;

  if ((node != NULL))
  {
    if (1 != get_node_uid (&peer_uid, &node->hashPubKey))
    {
      return GNUNET_SYSERR;
    }
  }
  else
    return GNUNET_SYSERR;

  if ((key != NULL))
  {
    if (1 != get_dhtkey_uid (&key_uid, key))
    {
      return GNUNET_SYSERR;
    }
  }
  else
    return GNUNET_SYSERR;

  if (GNUNET_OK !=
      (ret =
       prepared_statement_run (insert_route, sqlqueryuid, MYSQL_TYPE_LONGLONG,
                               &current_trial, GNUNET_YES, MYSQL_TYPE_LONG,
                               &type, GNUNET_NO, MYSQL_TYPE_LONG, &hops,
                               GNUNET_YES, MYSQL_TYPE_LONGLONG, &key_uid,
                               GNUNET_YES, MYSQL_TYPE_LONGLONG, &queryid,
                               GNUNET_YES, MYSQL_TYPE_LONG, &succeeded,
                               GNUNET_NO, MYSQL_TYPE_LONGLONG, &peer_uid,
                               GNUNET_YES, MYSQL_TYPE_LONGLONG, &from_uid,
                               GNUNET_YES, MYSQL_TYPE_LONGLONG, &to_uid,
                               GNUNET_YES, -1)))
  {
    if (ret == GNUNET_SYSERR)
    {
      return GNUNET_SYSERR;
    }
  }
  if (ret > 0)
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
update_current_topology (unsigned int connections)
{
  int ret;
  unsigned long long topologyuid;

  get_current_topology (&topologyuid);

  if (GNUNET_OK !=
      (ret =
       prepared_statement_run (update_topology, NULL, MYSQL_TYPE_LONG,
                               &connections, GNUNET_YES, MYSQL_TYPE_LONGLONG,
                               &topologyuid, GNUNET_YES, -1)))
  {
    if (ret == GNUNET_SYSERR)
    {
      return GNUNET_SYSERR;
    }
  }
  if (ret > 0)
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

  if (GNUNET_OK !=
      (ret =
       prepared_statement_run (insert_topology, NULL, MYSQL_TYPE_LONGLONG,
                               &current_trial, GNUNET_YES, MYSQL_TYPE_LONG,
                               &num_connections, GNUNET_YES, -1)))
  {
    if (ret == GNUNET_SYSERR)
    {
      return GNUNET_SYSERR;
    }
  }
  if (ret > 0)
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
  unsigned long long first_uid;
  unsigned long long second_uid;
  unsigned long long topologyuid;

  if (GNUNET_OK != get_current_topology (&topologyuid))
    return GNUNET_SYSERR;
  if (GNUNET_OK != get_node_uid (&first_uid, &first->hashPubKey))
    return GNUNET_SYSERR;
  if (GNUNET_OK != get_node_uid (&second_uid, &second->hashPubKey))
    return GNUNET_SYSERR;

  if (GNUNET_OK !=
      (ret =
       prepared_statement_run (extend_topology, NULL, MYSQL_TYPE_LONGLONG,
                               &topologyuid, GNUNET_YES, MYSQL_TYPE_LONGLONG,
                               &first_uid, GNUNET_YES, MYSQL_TYPE_LONGLONG,
                               &second_uid, GNUNET_YES, -1)))
  {
    if (ret == GNUNET_SYSERR)
    {
      return GNUNET_SYSERR;
    }
  }
  if (ret > 0)
    return GNUNET_OK;
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
libgnunet_plugin_dhtlog_mysql_init (void *cls)
{
  struct GNUNET_DHTLOG_Plugin *plugin = cls;

  cfg = plugin->cfg;
  max_varchar_len = 255;
#if DEBUG_DHTLOG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MySQL DHT Logger: initializing database\n");
#endif

  if (iopen (plugin) != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Failed to initialize MySQL database connection for dhtlog.\n"));
    return NULL;
  }

  GNUNET_assert (plugin->dhtlog_api == NULL);
  plugin->dhtlog_api = GNUNET_malloc (sizeof (struct GNUNET_DHTLOG_Handle));
  plugin->dhtlog_api->insert_trial = &add_trial;
  plugin->dhtlog_api->insert_stat = &add_stat;
  plugin->dhtlog_api->insert_round = &add_round;
  plugin->dhtlog_api->insert_round_details = &add_round_details;
  plugin->dhtlog_api->add_generic_stat = &add_generic_stat;
  plugin->dhtlog_api->insert_query = &add_query;
  plugin->dhtlog_api->update_trial = &update_trials;
  plugin->dhtlog_api->insert_route = &add_route;
  plugin->dhtlog_api->insert_node = &add_node;
  plugin->dhtlog_api->insert_dhtkey = &add_dhtkey;
  plugin->dhtlog_api->update_connections = &add_connections;
  plugin->dhtlog_api->insert_topology = &add_topology;
  plugin->dhtlog_api->update_topology = &update_current_topology;
  plugin->dhtlog_api->insert_extended_topology = &add_extended_topology;
  plugin->dhtlog_api->set_malicious = &set_malicious;
  get_current_trial (&current_trial);

  return plugin;
}

/**
 * Shutdown the plugin.
 */
void *
libgnunet_plugin_dhtlog_mysql_done (void *cls)
{
  struct GNUNET_DHTLOG_Handle *dhtlog_api = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MySQL DHT Logger: database shutdown\n");
  GNUNET_assert (dhtlog_api != NULL);
  prepared_statement_close (insert_query);
  prepared_statement_close (insert_route);
  prepared_statement_close (insert_trial);
  prepared_statement_close (insert_round);
  prepared_statement_close (insert_round_details);
  prepared_statement_close (insert_node);
  prepared_statement_close (insert_dhtkey);
  prepared_statement_close (update_trial);
  prepared_statement_close (get_dhtkeyuid);
  prepared_statement_close (get_nodeuid);
  prepared_statement_close (update_connection);
  prepared_statement_close (get_trial);
  prepared_statement_close (get_topology);
  prepared_statement_close (insert_topology);
  prepared_statement_close (update_topology);
  prepared_statement_close (extend_topology);
  prepared_statement_close (update_node_malicious);

  if (conn != NULL)
    mysql_close (conn);
  conn = NULL;
  mysql_library_end ();
  GNUNET_free (dhtlog_api);
  return NULL;
}

/* end of plugin_dhtlog_mysql.c */
