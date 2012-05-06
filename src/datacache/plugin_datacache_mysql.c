/*
     This file is part of GNUnet
     (C) 2006, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file datacache/plugin_datacache_mysql.c
 * @brief mysql for an implementation of a database backend for the datacache
 * @author Christian Grothoff
 *
 * SETUP INSTRUCTIONS:
 *
 * 1) Access mysql as root,
 *    <pre>
 *
 *    $ mysql -u root -p
 *
 *    </pre>
 *    and do the following. [You should replace $USER with the username
 *    that will be running the gnunetd process].
 * @verbatim
      CREATE DATABASE gnunet;
      GRANT select,insert,update,delete,create,alter,drop,create temporary tables
         ON gnunet.* TO $USER@localhost;
      SET PASSWORD FOR $USER@localhost=PASSWORD('$the_password_you_like');
      FLUSH PRIVILEGES;
   @endverbatim
 * 2) In the $HOME directory of $USER, create a ".my.cnf" file
 *    with the following lines
 * @verbatim
      [client]
      user=$USER
      password=$the_password_you_like
   @endverbatim
 *
 * Thats it -- now you can configure your datastores in GNUnet to
 * use MySQL. Note that .my.cnf file is a security risk unless its on
 * a safe partition etc. The $HOME/.my.cnf can of course be a symbolic
 * link. Even greater security risk can be achieved by setting no
 * password for $USER.  Luckily $USER has only priviledges to mess
 * up GNUnet's tables, nothing else (unless you give him more,
 * of course).<p>
 *
 * 3) Still, perhaps you should briefly try if the DB connection
 *    works. First, login as $USER. Then use,
 * @verbatim
      $ mysql -u $USER -p $the_password_you_like
      mysql> use gnunet;
   @endverbatim
 *
 *    If you get the message &quot;Database changed&quot; it probably works.
 *
 *    [If you get &quot;ERROR 2002: Can't connect to local MySQL server
 *     through socket '/tmp/mysql.sock' (2)&quot; it may be resolvable by
 *     &quot;ln -s /var/run/mysqld/mysqld.sock /tmp/mysql.sock&quot;
 *     so there may be some additional trouble depending on your mysql setup.]
 *
 * PROBLEMS?
 *
 * If you have problems related to the mysql module, your best
 * friend is probably the mysql manual. The first thing to check
 * is that mysql is basically operational, that you can connect
 * to it, create tables, issue queries etc.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_datacache_plugin.h"
#include "gnunet_mysql_lib.h"
#include <mysql/mysql.h>


/**
 * Estimate of the per-entry overhead (including indices).
 */
#define OVERHEAD ((4*2+4*2+8*2+8*2+sizeof(GNUNET_HashCode)*5+8))

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_MYSQL(cmd, dbh) do { GNUNET_log(GNUNET_ERROR_TYPE__ERROR, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error((dbh)->dbf)); GNUNET_abort(); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_MYSQL(level, cmd, dbh) do { GNUNET_log(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error((dbh)->dbf)); } while(0);


/**
 * Context for all functions in this plugin.
 */
struct Plugin
{
  /**
   * Our execution environment.
   */
  struct GNUNET_DATACACHE_PluginEnvironment *env;

  /**
   * Handle to the mysql database.
   */
  struct GNUNET_MYSQL_Context *mc;

#define SELECT_VALUE_STMT "SELECT value,expire FROM gn080dstore FORCE INDEX (hashidx) WHERE hash=? AND type=? AND expire >= ? LIMIT 1 OFFSET ?"
  struct GNUNET_MYSQL_StatementHandle *select_value;

#define COUNT_VALUE_STMT "SELECT count(*) FROM gn080dstore FORCE INDEX (hashidx) WHERE hash=? AND type=? AND expire >= ?"
  struct GNUNET_MYSQL_StatementHandle *count_value;

#define SELECT_OLD_VALUE_STMT "SELECT hash, vhash, type, value FROM gn080dstore FORCE INDEX (expireidx) ORDER BY puttime ASC LIMIT 1"
  struct GNUNET_MYSQL_StatementHandle *select_old_value;

#define DELETE_VALUE_STMT "DELETE FROM gn080dstore WHERE hash = ? AND vhash = ? AND type = ? AND value = ?"
  struct GNUNET_MYSQL_StatementHandle *delete_value;

#define INSERT_VALUE_STMT "INSERT INTO gn080dstore (type, puttime, expire, hash, vhash, value) "\
                          "VALUES (?, ?, ?, ?, ?, ?)"
  struct GNUNET_MYSQL_StatementHandle *insert_value;

#define UPDATE_VALUE_STMT "UPDATE gn080dstore FORCE INDEX (allidx) SET puttime=?, expire=? "\
                          "WHERE hash=? AND vhash=? AND type=?"
  struct GNUNET_MYSQL_StatementHandle *update_value;

};


/**
 * Create temporary table and prepare statements.
 *
 * @param plugin plugin context
 * @return GNUNET_OK on success
 */
static int
itable (struct Plugin *plugin)
{
#define MRUNS(a) (GNUNET_OK != GNUNET_MYSQL_statement_run (plugin->mc, a) )
  if (MRUNS
      ("CREATE TEMPORARY TABLE gn080dstore ("
       "  type INT(11) UNSIGNED NOT NULL DEFAULT 0,"
       "  puttime BIGINT UNSIGNED NOT NULL DEFAULT 0,"
       "  expire BIGINT UNSIGNED NOT NULL DEFAULT 0,"
       "  hash BINARY(64) NOT NULL DEFAULT '',"
       "  vhash BINARY(64) NOT NULL DEFAULT '',"
       "  value BLOB NOT NULL DEFAULT '',"
       "  INDEX hashidx (hash(64),type,expire),"
       "  INDEX allidx (hash(64),vhash(64),type)," "  INDEX expireidx (puttime)"
       ") ENGINE=InnoDB") || MRUNS ("SET AUTOCOMMIT = 1"))
    return GNUNET_SYSERR;
#undef MRUNS
#define PINIT(a,b) (NULL == (a = GNUNET_MYSQL_statement_prepare (plugin->mc, b)))
  if (PINIT (plugin->select_value, SELECT_VALUE_STMT) ||
      PINIT (plugin->count_value, COUNT_VALUE_STMT) ||
      PINIT (plugin->select_old_value, SELECT_OLD_VALUE_STMT) ||
      PINIT (plugin->delete_value, DELETE_VALUE_STMT) ||
      PINIT (plugin->insert_value, INSERT_VALUE_STMT) ||
      PINIT (plugin->update_value, UPDATE_VALUE_STMT))
    return GNUNET_SYSERR;
#undef PINIT
  return GNUNET_OK;
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure (our "struct Plugin")
 * @param key key to store data under
 * @param size number of bytes in data
 * @param data data to store
 * @param type type of the value
 * @param discard_time when to discard the value in any case
 * @return 0 on error, number of bytes used otherwise
 */
static size_t
mysql_plugin_put (void *cls, const GNUNET_HashCode * key, size_t size,
                  const char *data, enum GNUNET_BLOCK_Type type,
                  struct GNUNET_TIME_Absolute discard_time)
{
  struct Plugin *plugin = cls;
  struct GNUNET_TIME_Absolute now;
  unsigned long k_length;
  unsigned long h_length;
  unsigned long v_length;
  unsigned long long v_now;
  unsigned long long v_discard_time;
  unsigned int v_type;
  GNUNET_HashCode vhash;
  int ret;

  if (size > GNUNET_SERVER_MAX_MESSAGE_SIZE)
    return GNUNET_SYSERR;
  GNUNET_CRYPTO_hash (data, size, &vhash);
  now = GNUNET_TIME_absolute_get ();

  /* first try UPDATE */
  h_length = sizeof (GNUNET_HashCode);
  k_length = sizeof (GNUNET_HashCode);
  v_length = size;
  v_type = type;
  v_now = (unsigned long long) now.abs_value;
  v_discard_time = (unsigned long long) discard_time.abs_value;
  if (GNUNET_OK ==
      GNUNET_MYSQL_statement_run_prepared (plugin->mc, plugin->update_value, NULL,
                              MYSQL_TYPE_LONGLONG, &v_now, GNUNET_YES,
                              MYSQL_TYPE_LONGLONG, &v_discard_time, GNUNET_YES,
                              MYSQL_TYPE_BLOB, key, sizeof (GNUNET_HashCode),
                              &k_length, MYSQL_TYPE_BLOB, &vhash,
                              sizeof (GNUNET_HashCode), &h_length,
                              MYSQL_TYPE_LONG, &v_type, GNUNET_YES, -1))
    return GNUNET_OK;

  /* now try INSERT */
  h_length = sizeof (GNUNET_HashCode);
  k_length = sizeof (GNUNET_HashCode);
  v_length = size;
  if (GNUNET_OK !=
      (ret =
       GNUNET_MYSQL_statement_run_prepared (plugin->mc, plugin->insert_value, NULL,
                               MYSQL_TYPE_LONG, &type, GNUNET_YES,
                               MYSQL_TYPE_LONGLONG, &v_now, GNUNET_YES,
                               MYSQL_TYPE_LONGLONG, &v_discard_time, GNUNET_YES,
                               MYSQL_TYPE_BLOB, key, sizeof (GNUNET_HashCode),
                               &k_length, MYSQL_TYPE_BLOB, &vhash,
                               sizeof (GNUNET_HashCode), &h_length,
                               MYSQL_TYPE_BLOB, data, (unsigned long) size,
                               &v_length, -1)))
  {
    if (ret == GNUNET_SYSERR)
      itable (plugin);
    return GNUNET_SYSERR;
  }
  return size + OVERHEAD;
}


static int
return_ok (void *cls, unsigned int num_values, MYSQL_BIND * values)
{
  return GNUNET_OK;
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param cls closure (our "struct Plugin")
 * @param key
 * @param type entries of which type are relevant?
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for iter
 * @return the number of results found
 */
static unsigned int
mysql_plugin_get (void *cls, const GNUNET_HashCode * key,
                  enum GNUNET_BLOCK_Type type, GNUNET_DATACACHE_Iterator iter,
                  void *iter_cls)
{
  struct Plugin *plugin = cls;
  MYSQL_BIND rbind[3];
  unsigned long h_length;
  unsigned long v_length;
  unsigned long long v_expire;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Absolute expire;
  unsigned int cnt;
  unsigned long long total;
  unsigned long long v_now;
  unsigned int off;
  unsigned int v_type;
  int ret;
  char buffer[GNUNET_SERVER_MAX_MESSAGE_SIZE];

  now = GNUNET_TIME_absolute_get ();
  h_length = sizeof (GNUNET_HashCode);
  v_length = sizeof (buffer);
  total = -1;
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[0].buffer = &total;
  rbind[0].is_unsigned = GNUNET_YES;
  v_type = type;
  v_now = (unsigned long long) now.abs_value;
  if ((GNUNET_OK !=
       (ret =
        GNUNET_MYSQL_statement_run_prepared_select (plugin->mc, plugin->count_value, 1, rbind,
                                       return_ok, NULL, MYSQL_TYPE_BLOB, key,
                                       sizeof (GNUNET_HashCode), &h_length,
                                       MYSQL_TYPE_LONG, &v_type, GNUNET_YES,
                                       MYSQL_TYPE_LONGLONG, &v_now, GNUNET_YES,
                                       -1))) || (-1 == total))
  {
    if (ret == GNUNET_SYSERR)
      itable (plugin);
    return GNUNET_SYSERR;
  }
  if ((iter == NULL) || (total == 0))
    return (int) total;

  off = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, total);
  cnt = 0;
  while (cnt < total)
  {
    memset (rbind, 0, sizeof (rbind));
    rbind[0].buffer_type = MYSQL_TYPE_BLOB;
    rbind[0].buffer_length = sizeof (buffer);
    rbind[0].length = &v_length;
    rbind[0].buffer = buffer;
    rbind[1].buffer_type = MYSQL_TYPE_LONGLONG;
    rbind[1].is_unsigned = 1;
    rbind[1].buffer = &v_expire;
    off = (off + 1) % total;
    if (GNUNET_OK !=
        (ret =
         GNUNET_MYSQL_statement_run_prepared_select (plugin->mc, plugin->select_value, 2, rbind,
                                        return_ok, NULL, MYSQL_TYPE_BLOB, key,
                                        sizeof (GNUNET_HashCode), &h_length,
                                        MYSQL_TYPE_LONG, &v_type, GNUNET_YES,
                                        MYSQL_TYPE_LONGLONG, &v_now, GNUNET_YES,
                                        MYSQL_TYPE_LONG, &off, GNUNET_YES, -1)))
    {
      if (ret == GNUNET_SYSERR)
        itable (plugin);
      return GNUNET_SYSERR;
    }
    cnt++;
    expire.abs_value = v_expire;
    if (GNUNET_OK != iter (iter_cls, expire, key, v_length, buffer, type))
      break;
  }
  return cnt;
}


/**
 * Delete the entry with the lowest expiration value
 * from the datacache right now.
 *
 * @param cls closure (our "struct Plugin")
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
mysql_plugin_del (void *cls)
{
  struct Plugin *plugin = cls;

  MYSQL_BIND rbind[5];
  unsigned int v_type;
  GNUNET_HashCode v_key;
  GNUNET_HashCode vhash;
  unsigned long k_length;
  unsigned long h_length;
  unsigned long v_length;
  int ret;
  char buffer[GNUNET_SERVER_MAX_MESSAGE_SIZE];

  k_length = sizeof (GNUNET_HashCode);
  h_length = sizeof (GNUNET_HashCode);
  v_length = sizeof (buffer);
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_BLOB;
  rbind[0].buffer_length = sizeof (GNUNET_HashCode);
  rbind[0].length = &k_length;
  rbind[0].buffer = &v_key;
  rbind[1].buffer_type = MYSQL_TYPE_BLOB;
  rbind[1].buffer_length = sizeof (GNUNET_HashCode);
  rbind[1].length = &h_length;
  rbind[1].buffer = &vhash;
  rbind[2].buffer_type = MYSQL_TYPE_LONG;
  rbind[2].is_unsigned = 1;
  rbind[2].buffer = &v_type;
  rbind[3].buffer_type = MYSQL_TYPE_BLOB;
  rbind[3].buffer_length = sizeof (buffer);
  rbind[3].length = &v_length;
  rbind[3].buffer = buffer;
  if ((GNUNET_OK !=
       (ret =
        GNUNET_MYSQL_statement_run_prepared_select (plugin->mc, plugin->select_old_value, 4,
                                       rbind, return_ok, NULL, -1))) ||
      (GNUNET_OK !=
       (ret =
        GNUNET_MYSQL_statement_run_prepared (plugin->mc, plugin->delete_value, NULL,
                                MYSQL_TYPE_BLOB, &v_key,
                                sizeof (GNUNET_HashCode), &k_length,
                                MYSQL_TYPE_BLOB, &vhash,
                                sizeof (GNUNET_HashCode), &h_length,
                                MYSQL_TYPE_LONG, &v_type, GNUNET_YES,
                                MYSQL_TYPE_BLOB, buffer,
                                (unsigned long) sizeof (buffer), &v_length,
                                -1))))
  {
    if (ret == GNUNET_SYSERR)
      itable (plugin);
    return GNUNET_SYSERR;
  }
  plugin->env->delete_notify (plugin->env->cls, &v_key, v_length + OVERHEAD);

  return GNUNET_OK;
}


/**
 * Entry point for the plugin.
 *
 * @param cls closure (the "struct GNUNET_DATACACHE_PluginEnvironmnet")
 * @return the plugin's closure (our "struct Plugin")
 */
void *
libgnunet_plugin_datacache_mysql_init (void *cls)
{
  struct GNUNET_DATACACHE_PluginEnvironment *env = cls;
  struct GNUNET_DATACACHE_PluginFunctions *api;
  struct Plugin *plugin;

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  plugin->mc = GNUNET_MYSQL_context_create (env->cfg, "datacache-mysql");
  if ( (NULL == plugin->mc) ||
       (GNUNET_OK != itable (plugin)) )
  {
    if (NULL != plugin->mc)
      GNUNET_MYSQL_context_destroy (plugin->mc);
    GNUNET_free (plugin);
    return NULL;
  }
  api = GNUNET_malloc (sizeof (struct GNUNET_DATACACHE_PluginFunctions));
  api->cls = plugin;
  api->get = &mysql_plugin_get;
  api->put = &mysql_plugin_put;
  api->del = &mysql_plugin_del;
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "mysql",
                   _("MySQL datacache running\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls closure (our "struct Plugin")
 * @return NULL
 */
void *
libgnunet_plugin_datacache_mysql_done (void *cls)
{
  struct GNUNET_DATACACHE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  GNUNET_MYSQL_context_destroy (plugin->mc);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}


/* end of plugin_datacache_mysql.c */
