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


#define DEBUG_DHTLOG GNUNET_NO

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
typedef int (*GNUNET_MysqlDataProcessor) (void *cls,
                                          unsigned int num_values,
                                          MYSQL_BIND * values);

static unsigned long max_varchar_len;

/**
 * The configuration the DHT service is running with
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

static unsigned long long current_trial = 0;    /* I like to assign 0, just to remember */

static char *user;

static char *password;

static char *server;

static char *database;

static unsigned long long port;

/**
 * Connection to the MySQL Server.
 */
static MYSQL *conn;

#define INSERT_QUERIES_STMT "INSERT INTO queries (trialuid, querytype, hops, dhtkeyuid, dhtqueryid, succeeded, nodeuid) "\
                          "VALUES (?, ?, ?, ?, ?, ?, ?)"
static struct StatementHandle *insert_query;

#define INSERT_ROUTES_STMT "INSERT INTO routes (trialuid, querytype, hops, dhtkeyuid, dhtqueryid, succeeded, nodeuid, from_node, to_node) "\
                          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
static struct StatementHandle *insert_route;

#define INSERT_NODES_STMT "INSERT INTO nodes (trialuid, nodeid, nodebits) "\
                          "VALUES (?, ?, ?)"
static struct StatementHandle *insert_node;

#define INSERT_TRIALS_STMT "INSERT INTO trials"\
                            "(starttime, numnodes, topology,"\
                            "topology_percentage, topology_probability,"\
                            "blacklist_topology, connect_topology, connect_topology_option,"\
                            "connect_topology_option_modifier, puts, gets, "\
                            "concurrent, settle_time, num_rounds, malicious_getters,"\
                            "malicious_putters, malicious_droppers, message) "\
                            "VALUES (NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

static struct StatementHandle *insert_trial;

#define INSERT_DHTKEY_STMT "INSERT INTO dhtkeys (dhtkey, trialuid, keybits) "\
                          "VALUES (?, ?, ?)"
static struct StatementHandle *insert_dhtkey;

#define UPDATE_TRIALS_STMT "UPDATE trials set endtime=NOW(), total_messages_dropped = ?, total_bytes_dropped = ?, unknownPeers = ? where trialuid = ?"
static struct StatementHandle *update_trial;

#define UPDATE_CONNECTIONS_STMT "UPDATE trials set totalConnections = ? where trialuid = ?"
static struct StatementHandle *update_connection;

#define GET_TRIAL_STMT "SELECT MAX( trialuid ) FROM trials"
static struct StatementHandle *get_trial;

#define GET_DHTKEYUID_STMT "SELECT dhtkeyuid FROM dhtkeys where dhtkey = ? and trialuid = ?"
static struct StatementHandle *get_dhtkeyuid;

#define GET_NODEUID_STMT "SELECT nodeuid FROM nodes where trialuid = ? and nodeid = ?"
static struct StatementHandle *get_nodeuid;

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
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                 "mysql_query");
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

  if (MRUNS ("CREATE TABLE IF NOT EXISTS `dhtkeys` ("
             "dhtkeyuid int(10) unsigned NOT NULL auto_increment COMMENT 'Unique Key given to each query',"
             "`dhtkey` varchar(255) NOT NULL COMMENT 'The ASCII value of the key being searched for',"
             "trialuid int(10) unsigned NOT NULL,"
             "keybits blob NOT NULL,"
             "UNIQUE KEY `dhtkeyuid` (`dhtkeyuid`)"
             ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS ("CREATE TABLE IF NOT EXISTS `nodes` ("
             "`nodeuid` int(10) unsigned NOT NULL auto_increment,"
             "`trialuid` int(10) unsigned NOT NULL,"
             "`nodeid` varchar(255) NOT NULL,"
             "`nodebits` blob NOT NULL,"
             "PRIMARY KEY  (`nodeuid`)"
             ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS ("CREATE TABLE IF NOT EXISTS `queries` ("
             "`trialuid` int(10) unsigned NOT NULL,"
             "`queryuid` int(10) unsigned NOT NULL auto_increment,"
             "`dhtqueryid` bigint(20) NOT NULL,"
             "`querytype` enum('1','2','3','4','5') NOT NULL,"
             "`hops` int(10) unsigned NOT NULL,"
             "`succeeded` tinyint NOT NULL,"
             "`nodeuid` int(10) unsigned NOT NULL,"
             "`time` timestamp NOT NULL default CURRENT_TIMESTAMP,"
             "`dhtkeyuid` int(10) unsigned NOT NULL,"
             "PRIMARY KEY  (`queryuid`)"
             ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS ("CREATE TABLE IF NOT EXISTS `routes` ("
             "`trialuid` int(10) unsigned NOT NULL,"
             "`queryuid` int(10) unsigned NOT NULL auto_increment,"
             "`dhtqueryid` bigint(20) NOT NULL,"
             "`querytype` enum('1','2','3','4','5') NOT NULL,"
             "`hops` int(10) unsigned NOT NULL,"
             "`succeeded` tinyint NOT NULL,"
             "`nodeuid` int(10) unsigned NOT NULL,"
             "`time` timestamp NOT NULL default CURRENT_TIMESTAMP,"
             "`dhtkeyuid` int(10) unsigned NOT NULL,"
             "`from_node` int(10) unsigned NOT NULL,"
             "`to_node` int(10) unsigned NOT NULL,"
             "PRIMARY KEY  (`queryuid`)"
             ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS ("CREATE TABLE IF NOT EXISTS `trials` ("
             "`trialuid` int(10) unsigned NOT NULL auto_increment,"
             "`numnodes` int(10) unsigned NOT NULL,"
             "`topology` int(10) NOT NULL,"
             "`starttime` datetime NOT NULL,"
             "`endtime` datetime NOT NULL,"
             "`puts` int(10) unsigned NOT NULL,"
             "`gets` int(10) unsigned NOT NULL,"
             "`concurrent` int(10) unsigned NOT NULL,"
             "`settle_time` int(10) unsigned NOT NULL,"
             "`totalConnections` int(10) unsigned NOT NULL,"
             "`message` text NOT NULL,"
             "`num_rounds` int(10) unsigned NOT NULL,"
             "`malicious_getters` int(10) unsigned NOT NULL,"
             "`malicious_putters` int(10) unsigned NOT NULL,"
             "`malicious_droppers` int(10) unsigned NOT NULL,"
             "`totalMessagesDropped` int(10) unsigned NOT NULL,"
             "`totalBytesDropped` int(10) unsigned NOT NULL,"
             "`topology_modifier` double NOT NULL,"
             "`logNMultiplier` double NOT NULL,"
             "`maxnetbps` bigint(20) unsigned NOT NULL,"
             "`unknownPeers` int(10) unsigned NOT NULL,"
             "PRIMARY KEY  (`trialuid`),"
             "UNIQUE KEY `trialuid` (`trialuid`)"
             ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
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
 * Create a prepared statement.
 *
 * @return NULL on error
 */
void
prepared_statement_close (struct StatementHandle *s)
{
  if (s == NULL)
    return;

  if (s->query != NULL)
    GNUNET_free(s->query);
  if (s->valid == GNUNET_YES)
    mysql_stmt_close(s->statement);
  GNUNET_free(s);
}

/*
 * Initialize the prepared statements for use with dht test logging
 */
static int
iopen ()
{
  int ret;

  conn = mysql_init (NULL);
  if (conn == NULL)
    return GNUNET_SYSERR;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting to mysql with: user %s, pass %s, server %s, database %s, port %d\n",
              user, password, server, database, port);

  mysql_real_connect (conn, server, user, password,
                      database, (unsigned int) port, NULL, 0);

  if (mysql_error (conn)[0])
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                 "mysql_real_connect");
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
      PINIT (insert_node, INSERT_NODES_STMT) ||
      PINIT (insert_dhtkey, INSERT_DHTKEY_STMT) ||
      PINIT (update_trial, UPDATE_TRIALS_STMT) ||
      PINIT (get_dhtkeyuid, GET_DHTKEYUID_STMT) ||
      PINIT (get_nodeuid, GET_NODEUID_STMT) ||
      PINIT (update_connection, UPDATE_CONNECTIONS_STMT) ||
      PINIT (get_trial, GET_TRIAL_STMT))
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
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                 "mysql_stmt_prepare `%s', %s", ret->query, mysql_error(conn));
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
                  "mysql_stmt_bind_param",
                   __FILE__, __LINE__, mysql_stmt_error (s->statement));
      return GNUNET_SYSERR;
    }

  if (mysql_stmt_execute (s->statement))
    {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
               _("`%s' failed at %s:%d with error: %s\n"),
               "mysql_stmt_execute",
               __FILE__, __LINE__, mysql_stmt_error (s->statement));
      return GNUNET_SYSERR;
    }

  return GNUNET_OK;
}

/**
 * Run a prepared SELECT statement.
 *
 * @param result_size number of elements in results array
 * @param results pointer to already initialized MYSQL_BIND
 *        array (of sufficient size) for passing results
 * @param processor function to call on each result
 * @param processor_cls extra argument to processor
 * @param ... pairs and triplets of "MYSQL_TYPE_XXX" keys and their respective
 *        values (size + buffer-reference for pointers); terminated
 *        with "-1"
 * @return GNUNET_SYSERR on error, otherwise
 *         the number of successfully affected (or queried) rows
 */
int
prepared_statement_run_select (struct StatementHandle
                               *s, unsigned int result_size,
                               MYSQL_BIND * results,
                               GNUNET_MysqlDataProcessor
                               processor, void *processor_cls,
                               ...)
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
                  "mysql_stmt_bind_result",
                  __FILE__, __LINE__, mysql_stmt_error (s->statement));
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
                       "mysql_stmt_fetch",
                       __FILE__, __LINE__, mysql_stmt_error (s->statement));
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
get_current_trial (unsigned long long *trialuid)
{
  MYSQL_BIND rbind[1];

  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONG;
  rbind[0].is_unsigned = 1;
  rbind[0].buffer = trialuid;

  if ((GNUNET_OK !=
       prepared_statement_run_select (get_trial,
                                      1,
                                      rbind,
                                      return_ok, NULL, -1)))
    {
      return GNUNET_SYSERR;
    }

  return GNUNET_OK;
}


/**
 * Run a prepared statement that does NOT produce results.
 *
 * @param ... pairs and triplets of "MYSQL_TYPE_XXX" keys and their respective
 *        values (size + buffer-reference for pointers); terminated
 *        with "-1"
 * @param insert_id NULL or address where to store the row ID of whatever
 *        was inserted (only for INSERT statements!)
 * @return GNUNET_SYSERR on error, otherwise
 *         the number of successfully affected rows
 */
int
prepared_statement_run (struct StatementHandle *s,
                        unsigned long long *insert_id, ...)
{
  va_list ap;
  int affected;

  if (GNUNET_OK != prepare_statement(s))
    {
      GNUNET_break(0);
      return GNUNET_SYSERR;
    }
  GNUNET_assert(s->valid == GNUNET_YES);
  if (s->statement == NULL)
    return GNUNET_SYSERR;

  va_start (ap, insert_id);

  if (mysql_stmt_prepare (s->statement, s->query, strlen (s->query)))
      {
        GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "mysql_stmt_prepare ERROR");
        return GNUNET_SYSERR;
      }

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
  MYSQL_STMT *stmt;
  int ret;
  unsigned long long m_len;
  m_len = strlen (message);

  stmt = mysql_stmt_init(conn);
  if (GNUNET_OK !=
      (ret = prepared_statement_run (insert_trial,
                                      trialuid,
                                      MYSQL_TYPE_LONG,
                                      &num_nodes,
                                      GNUNET_YES,
                                      MYSQL_TYPE_LONG,
                                      &topology,
                                      GNUNET_YES,
                                      MYSQL_TYPE_FLOAT,
                                      &topology_percentage,
                                      MYSQL_TYPE_FLOAT,
                                      &topology_probability,
                                      MYSQL_TYPE_LONG,
                                      &blacklist_topology,
                                      GNUNET_YES,
                                      MYSQL_TYPE_LONG,
                                      &connect_topology,
                                      GNUNET_YES,
                                      MYSQL_TYPE_LONG,
                                      &connect_topology_option,
                                      GNUNET_YES,
                                      MYSQL_TYPE_FLOAT,
                                      &connect_topology_option_modifier,
                                      MYSQL_TYPE_LONG,
                                      &puts,
                                      GNUNET_YES,
                                      MYSQL_TYPE_LONG,
                                      &gets,
                                      GNUNET_YES,
                                      MYSQL_TYPE_LONG,
                                      &concurrent,
                                      GNUNET_YES,
                                      MYSQL_TYPE_LONG,
                                      &settle_time,
                                      GNUNET_YES,
                                      MYSQL_TYPE_LONG,
                                      &num_rounds,
                                      GNUNET_YES,
                                      MYSQL_TYPE_LONG,
                                      &malicious_getters,
                                      GNUNET_YES,
                                      MYSQL_TYPE_LONG,
                                      &malicious_putters,
                                      GNUNET_YES,
                                      MYSQL_TYPE_LONG,
                                      &malicious_droppers,
                                      GNUNET_YES,
                                      MYSQL_TYPE_BLOB,
                                      message,
                                      max_varchar_len +
                                      max_varchar_len, &m_len,
                                      -1)))
    {
      if (ret == GNUNET_SYSERR)
        {
          mysql_stmt_close(stmt);
          return GNUNET_SYSERR;
        }
    }

  get_current_trial (&current_trial);
#if DEBUG_DHTLOG
  fprintf (stderr, "Current trial is %llu\n", current_trial);
#endif
  mysql_stmt_close(stmt);
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

  if ((GNUNET_OK !=
       prepared_statement_run_select (get_dhtkeyuid,
                                      1,
                                      rbind,
                                      return_ok, NULL,
                                      MYSQL_TYPE_VAR_STRING,
                                      &encKey,
                                      max_varchar_len,
                                      &k_len,
                                      MYSQL_TYPE_LONGLONG,
                                      &current_trial,
                                      GNUNET_YES, -1)))
    {
      return GNUNET_SYSERR;
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
  ret = get_dhtkey_uid(&curr_dhtkeyuid, dhtkey);
  if (curr_dhtkeyuid != 0) /* dhtkey already exists */
    {
      if (dhtkeyuid != NULL)
        *dhtkeyuid = curr_dhtkeyuid;
      return GNUNET_OK;
    }

  if (GNUNET_OK !=
      (ret = prepared_statement_run (insert_dhtkey,
                                     dhtkeyuid,
                                     MYSQL_TYPE_VAR_STRING,
                                     &encKey,
                                     max_varchar_len,
                                     &k_len,
                                     MYSQL_TYPE_LONG,
                                     &current_trial,
                                     GNUNET_YES,
                                     MYSQL_TYPE_BLOB,
                                     dhtkey,
                                     sizeof (GNUNET_HashCode),
                                     &h_len, -1)))
    {
      if (ret == GNUNET_SYSERR)
        {
          return GNUNET_SYSERR;
        }
    }

  return GNUNET_OK;
}


static int
get_node_uid (unsigned long long *nodeuid, const GNUNET_HashCode * peerHash)
{
  MYSQL_BIND rbind[1];
  struct GNUNET_CRYPTO_HashAsciiEncoded encPeer;
  unsigned long long p_len;

  int ret;
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONG;
  rbind[0].buffer = nodeuid;
  rbind[0].is_unsigned = GNUNET_YES;

  GNUNET_CRYPTO_hash_to_enc (peerHash, &encPeer);
  p_len = strlen ((char *) &encPeer);

  if (1 != (ret = prepared_statement_run_select (get_nodeuid,
                                                              1,
                                                              rbind,
                                                              return_ok,
                                                              NULL,
                                                              MYSQL_TYPE_LONG,
                                                              &current_trial,
                                                              GNUNET_YES,
                                                              MYSQL_TYPE_VAR_STRING,
                                                              &encPeer,
                                                              max_varchar_len,
                                                              &p_len, -1)))
    {
#if DEBUG_DHTLOG
      fprintf (stderr, "FAILED\n");
#endif
      return GNUNET_SYSERR;
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
add_node (unsigned long long *nodeuid, struct GNUNET_PeerIdentity * node)
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
      (ret = prepared_statement_run (insert_node,
                                                  nodeuid,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &current_trial,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_VAR_STRING,
                                                  &encPeer,
                                                  max_varchar_len,
                                                  &p_len,
                                                  MYSQL_TYPE_BLOB,
                                                  &node->hashPubKey,
                                                  sizeof (GNUNET_HashCode),
                                                  &h_len, -1)))
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
  if (GNUNET_OK !=
      (ret = prepared_statement_run (update_trial,
                                    NULL,
                                    MYSQL_TYPE_LONGLONG,
                                    &totalMessagesDropped,
                                    GNUNET_YES,
                                    MYSQL_TYPE_LONGLONG,
                                    &totalBytesDropped,
                                    GNUNET_YES,
                                    MYSQL_TYPE_LONGLONG,
                                    &unknownPeers,
                                    GNUNET_YES,
                                    MYSQL_TYPE_LONGLONG,
                                    &trialuid, GNUNET_YES, -1)))
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
  if (GNUNET_OK !=
      (ret = prepared_statement_run (update_connection,
                                                  NULL,
                                                  MYSQL_TYPE_LONG,
                                                  &totalConnections,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &trialuid, GNUNET_YES, -1)))
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
           const struct GNUNET_PeerIdentity * node, const GNUNET_HashCode * key)
{
  int ret;
  unsigned long long peer_uid, key_uid;
  peer_uid = 0;
  key_uid = 0;

  if ((node != NULL)
      && (GNUNET_OK == get_node_uid (&peer_uid, &node->hashPubKey)))
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
      (ret = prepared_statement_run (insert_query,
                                                  sqlqueryuid,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &current_trial,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &type,
                                                  GNUNET_NO,
                                                  MYSQL_TYPE_LONG,
                                                  &hops,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &key_uid,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &queryid,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &succeeded,
                                                  GNUNET_NO,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &peer_uid, GNUNET_YES, -1)))
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
           unsigned int type, unsigned int hops,
           int succeeded, const struct GNUNET_PeerIdentity * node,
           const GNUNET_HashCode * key, const struct GNUNET_PeerIdentity * from_node,
           const struct GNUNET_PeerIdentity * to_node)
{
  unsigned long long peer_uid = 0;
  unsigned long long key_uid = 0;
  unsigned long long from_uid = 0;
  unsigned long long to_uid = 0;
  int ret;

  if (from_node != NULL)
    get_node_uid (&from_uid, &from_node->hashPubKey);
  else
    from_uid = 0;

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
      (ret = prepared_statement_run (insert_route,
                                    sqlqueryuid,
                                    MYSQL_TYPE_LONGLONG,
                                    &current_trial,
                                    GNUNET_YES,
                                    MYSQL_TYPE_LONG,
                                    &type,
                                    GNUNET_NO,
                                    MYSQL_TYPE_LONG,
                                    &hops,
                                    GNUNET_YES,
                                    MYSQL_TYPE_LONGLONG,
                                    &key_uid,
                                    GNUNET_YES,
                                    MYSQL_TYPE_LONGLONG,
                                    &queryid,
                                    GNUNET_YES,
                                    MYSQL_TYPE_LONG,
                                    &succeeded,
                                    GNUNET_NO,
                                    MYSQL_TYPE_LONGLONG,
                                    &peer_uid,
                                    GNUNET_YES,
                                    MYSQL_TYPE_LONGLONG,
                                    &from_uid,
                                    GNUNET_YES,
                                    MYSQL_TYPE_LONGLONG,
                                    &to_uid, GNUNET_YES, -1)))
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
 * Provides the dhtlog api
 *
 * @param c the configuration to use to connect to a server
 *
 * @return the handle to the server, or NULL on error
 */
void *
libgnunet_plugin_dhtlog_mysql_init (void * cls)
{
  struct GNUNET_DHTLOG_Plugin *plugin = cls;

  cfg = plugin->cfg;
  max_varchar_len = 255;
#if DEBUG_DHTLOG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MySQL DHT Logger: initializing database\n");
#endif

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (plugin->cfg,
                                                         "MYSQL", "DATABASE",
                                                         &database))
    {
      database = GNUNET_strdup("gnunet");
    }

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (plugin->cfg,
                                                          "MYSQL", "USER", &user))
    {
      user = GNUNET_strdup("dht");
    }

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (plugin->cfg,
                                                          "MYSQL", "PASSWORD", &password))
    {
      password = GNUNET_strdup("dhttest**");
    }

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (plugin->cfg,
                                                          "MYSQL", "SERVER", &server))
    {
      server = GNUNET_strdup("localhost");
    }

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (plugin->cfg,
                                                          "MYSQL", "MYSQL_PORT", &port))
    {
      port = 0;
    }

  if (iopen () != GNUNET_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to initialize MySQL database connection for dhtlog.\n"));
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
  get_current_trial (&current_trial);

  return NULL;
}

/**
 * Shutdown the plugin.
 */
void *
libgnunet_plugin_dhtlog_mysql_done (void * cls)
{
  struct GNUNET_DHTLOG_Handle *dhtlog_api = cls;
#if DEBUG_DHTLOG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MySQL DHT Logger: database shutdown\n");
#endif
  GNUNET_assert(dhtlog_api != NULL);
  prepared_statement_close(insert_query);
  prepared_statement_close(insert_route);
  prepared_statement_close(insert_trial);
  prepared_statement_close(insert_node);
  prepared_statement_close(insert_dhtkey);
  prepared_statement_close(update_trial);
  prepared_statement_close(get_dhtkeyuid);
  prepared_statement_close(get_nodeuid);
  prepared_statement_close(update_connection);
  prepared_statement_close(get_trial);

  if (conn != NULL)
    mysql_close (conn);

  GNUNET_free(dhtlog_api);
  return NULL;
}

/* end of plugin_dhtlog_mysql.c */
