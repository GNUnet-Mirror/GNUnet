/*
     This file is part of GNUnet
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file datastore/plugin_datastore_mysql.c
 * @brief mysql-based datastore backend
 * @author Igor Wronsky
 * @author Christian Grothoff
 *
 * NOTE: This db module does NOT work with mysql prior to 4.1 since
 * it uses prepared statements.  MySQL 5.0.46 promises to fix a bug
 * in MyISAM that is causing us grief.  At the time of this writing,
 * that version is yet to be released.  In anticipation, the code
 * will use MyISAM with 5.0.46 (and higher).  If you run such a
 * version, please run "make check" to verify that the MySQL bug
 * was actually fixed in your version (and if not, change the
 * code below to use MyISAM for gn071).
 *
 * HIGHLIGHTS
 *
 * Pros
 * + On up-to-date hardware where mysql can be used comfortably, this
 *   module will have better performance than the other db choices
 *   (according to our tests).
 * + Its often possible to recover the mysql database from internal
 *   inconsistencies. The other db choices do not support repair!
 * Cons
 * - Memory usage (Comment: "I have 1G and it never caused me trouble")
 * - Manual setup
 *
 * MANUAL SETUP INSTRUCTIONS
 *
 * 1) in /etc/gnunet.conf, set
 * @verbatim
       [datastore]
       DATABASE = "mysql"
   @endverbatim
 * 2) Then access mysql as root,
 * @verbatim
     $ mysql -u root -p
   @endverbatim
 *    and do the following. [You should replace $USER with the username
 *    that will be running the gnunetd process].
 * @verbatim
      CREATE DATABASE gnunet;
      GRANT select,insert,update,delete,create,alter,drop,create temporary tables
         ON gnunet.* TO $USER@localhost;
      SET PASSWORD FOR $USER@localhost=PASSWORD('$the_password_you_like');
      FLUSH PRIVILEGES;
   @endverbatim
 * 3) In the $HOME directory of $USER, create a ".my.cnf" file
 *    with the following lines
 * @verbatim
      [client]
      user=$USER
      password=$the_password_you_like
   @endverbatim
 *
 * Thats it. Note that .my.cnf file is a security risk unless its on
 * a safe partition etc. The $HOME/.my.cnf can of course be a symbolic
 * link. Even greater security risk can be achieved by setting no
 * password for $USER.  Luckily $USER has only priviledges to mess
 * up GNUnet's tables, nothing else (unless you give him more,
 * of course).<p>
 *
 * 4) Still, perhaps you should briefly try if the DB connection
 *    works. First, login as $USER. Then use,
 *
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
 * REPAIRING TABLES
 *
 * - Its probably healthy to check your tables for inconsistencies
 *   every now and then.
 * - If you get odd SEGVs on gnunetd startup, it might be that the mysql
 *   databases have been corrupted.
 * - The tables can be verified/fixed in two ways;
 *   1) by running mysqlcheck -A, or
 *   2) by executing (inside of mysql using the GNUnet database):
 * @verbatim
     mysql> REPAIR TABLE gn090;
   @endverbatim
 *
 * PROBLEMS?
 *
 * If you have problems related to the mysql module, your best
 * friend is probably the mysql manual. The first thing to check
 * is that mysql is basically operational, that you can connect
 * to it, create tables, issue queries etc.
 */

#include "platform.h"
#include "gnunet_datastore_plugin.h"
#include "gnunet_util_lib.h"
#include "gnunet_mysql_lib.h"


#define MAX_DATUM_SIZE 65536


/**
 * Context for all functions in this plugin.
 */
struct Plugin
{
  /**
   * Our execution environment.
   */
  struct GNUNET_DATASTORE_PluginEnvironment *env;

  /**
   * Handle to talk to MySQL.
   */
  struct GNUNET_MYSQL_Context *mc;

  /**
   * Prepared statements.
   */
#define INSERT_ENTRY "INSERT INTO gn090 (repl,type,prio,anonLevel,expire,rvalue,hash,vhash,value) VALUES (?,?,?,?,?,?,?,?,?)"
  struct GNUNET_MYSQL_StatementHandle *insert_entry;

#define DELETE_ENTRY_BY_UID "DELETE FROM gn090 WHERE uid=?"
  struct GNUNET_MYSQL_StatementHandle *delete_entry_by_uid;

#define COUNT_ENTRY_BY_HASH "SELECT count(*) FROM gn090 FORCE INDEX (idx_hash) WHERE hash=?"
  struct GNUNET_MYSQL_StatementHandle *count_entry_by_hash;

#define SELECT_ENTRY_BY_HASH "SELECT type,prio,anonLevel,expire,hash,value,uid FROM gn090 FORCE INDEX (idx_hash) WHERE hash=? ORDER BY uid LIMIT 1 OFFSET ?"
  struct GNUNET_MYSQL_StatementHandle *select_entry_by_hash;

#define COUNT_ENTRY_BY_HASH_AND_VHASH "SELECT count(*) FROM gn090 FORCE INDEX (idx_hash_vhash) WHERE hash=? AND vhash=?"
  struct GNUNET_MYSQL_StatementHandle *count_entry_by_hash_and_vhash;

#define SELECT_ENTRY_BY_HASH_AND_VHASH "SELECT type,prio,anonLevel,expire,hash,value,uid FROM gn090 FORCE INDEX (idx_hash_vhash) WHERE hash=? AND vhash=? ORDER BY uid LIMIT 1 OFFSET ?"
  struct GNUNET_MYSQL_StatementHandle *select_entry_by_hash_and_vhash;

#define COUNT_ENTRY_BY_HASH_AND_TYPE "SELECT count(*) FROM gn090 FORCE INDEX (idx_hash_type_uid) WHERE hash=? AND type=?"
  struct GNUNET_MYSQL_StatementHandle *count_entry_by_hash_and_type;

#define SELECT_ENTRY_BY_HASH_AND_TYPE "SELECT type,prio,anonLevel,expire,hash,value,uid FROM gn090 FORCE INDEX (idx_hash_type_uid) WHERE hash=? AND type=? ORDER BY uid LIMIT 1 OFFSET ?"
  struct GNUNET_MYSQL_StatementHandle *select_entry_by_hash_and_type;

#define COUNT_ENTRY_BY_HASH_VHASH_AND_TYPE "SELECT count(*) FROM gn090 FORCE INDEX (idx_hash_vhash) WHERE hash=? AND vhash=? AND type=?"
  struct GNUNET_MYSQL_StatementHandle *count_entry_by_hash_vhash_and_type;

#define SELECT_ENTRY_BY_HASH_VHASH_AND_TYPE "SELECT type,prio,anonLevel,expire,hash,value,uid FROM gn090 FORCE INDEX (idx_hash_vhash) WHERE hash=? AND vhash=? AND type=? ORDER BY uid ASC LIMIT 1 OFFSET ?"
  struct GNUNET_MYSQL_StatementHandle *select_entry_by_hash_vhash_and_type;

#define UPDATE_ENTRY "UPDATE gn090 SET prio=prio+?,expire=IF(expire>=?,expire,?) WHERE uid=?"
  struct GNUNET_MYSQL_StatementHandle *update_entry;

#define DEC_REPL "UPDATE gn090 SET repl=GREATEST (0, repl - 1) WHERE uid=?"
  struct GNUNET_MYSQL_StatementHandle *dec_repl;

#define SELECT_SIZE "SELECT SUM(BIT_LENGTH(value) DIV 8) FROM gn090"
  struct GNUNET_MYSQL_StatementHandle *get_size;

#define SELECT_IT_NON_ANONYMOUS "SELECT type,prio,anonLevel,expire,hash,value,uid "\
   "FROM gn090 FORCE INDEX (idx_anonLevel_type_rvalue) "\
   "WHERE anonLevel=0 AND type=? AND "\
   "(rvalue >= ? OR"\
   "  NOT EXISTS (SELECT 1 FROM gn090 FORCE INDEX (idx_anonLevel_type_rvalue) WHERE anonLevel=0 AND type=? AND rvalue>=?)) "\
   "ORDER BY rvalue ASC LIMIT 1"
  struct GNUNET_MYSQL_StatementHandle *zero_iter;

#define SELECT_IT_EXPIRATION "SELECT type,prio,anonLevel,expire,hash,value,uid FROM gn090 FORCE INDEX (idx_expire) WHERE expire < ? ORDER BY expire ASC LIMIT 1"
  struct GNUNET_MYSQL_StatementHandle *select_expiration;

#define SELECT_IT_PRIORITY "SELECT type,prio,anonLevel,expire,hash,value,uid FROM gn090 FORCE INDEX (idx_prio) ORDER BY prio ASC LIMIT 1"
  struct GNUNET_MYSQL_StatementHandle *select_priority;

#define SELECT_IT_REPLICATION "SELECT type,prio,anonLevel,expire,hash,value,uid "\
  "FROM gn090 FORCE INDEX (idx_repl_rvalue) "\
  "WHERE repl=? AND "\
  " (rvalue>=? OR"\
  "  NOT EXISTS (SELECT 1 FROM gn090 FORCE INDEX (idx_repl_rvalue) WHERE repl=? AND rvalue>=?)) "\
  "ORDER BY rvalue ASC "\
  "LIMIT 1"
  struct GNUNET_MYSQL_StatementHandle *select_replication;

#define SELECT_MAX_REPL "SELECT MAX(repl) FROM gn090"
  struct GNUNET_MYSQL_StatementHandle *max_repl;

#define GET_ALL_KEYS "SELECT hash from gn090"
  struct GNUNET_MYSQL_StatementHandle *get_all_keys;

};


/**
 * Delete an entry from the gn090 table.
 *
 * @param plugin plugin context
 * @param uid unique ID of the entry to delete
 * @return GNUNET_OK on success, GNUNET_NO if no such value exists, GNUNET_SYSERR on error
 */
static int
do_delete_entry (struct Plugin *plugin, unsigned long long uid)
{
  int ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deleting value %llu from gn090 table\n",
              uid);
  ret = GNUNET_MYSQL_statement_run_prepared (plugin->mc,
					     plugin->delete_entry_by_uid, NULL,
					     MYSQL_TYPE_LONGLONG, &uid, GNUNET_YES, -1);
  if (ret >= 0)
    return GNUNET_OK;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Deleting value %llu from gn090 table failed\n", uid);
  return ret;
}


/**
 * Get an estimate of how much space the database is
 * currently using.
 *
 * @param cls our "struct Plugin *"
 * @return number of bytes used on disk
 */
static unsigned long long
mysql_plugin_estimate_size (void *cls)
{
  struct Plugin *plugin = cls;
  MYSQL_BIND cbind[1];
  long long total;

  memset (cbind, 0, sizeof (cbind));
  total = 0;
  cbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
  cbind[0].buffer = &total;
  cbind[0].is_unsigned = GNUNET_NO;
  if (GNUNET_OK !=
      GNUNET_MYSQL_statement_run_prepared_select (plugin->mc, plugin->get_size, 1, cbind, NULL, NULL, -1))
    return 0;
  return total;
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure
 * @param key key for the item
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param msg set to error message
 * @return GNUNET_OK on success
 */
static int
mysql_plugin_put (void *cls, const GNUNET_HashCode * key, uint32_t size,
                  const void *data, enum GNUNET_BLOCK_Type type,
                  uint32_t priority, uint32_t anonymity, uint32_t replication,
                  struct GNUNET_TIME_Absolute expiration, char **msg)
{
  struct Plugin *plugin = cls;
  unsigned int irepl = replication;
  unsigned int ipriority = priority;
  unsigned int ianonymity = anonymity;
  unsigned long long lexpiration = expiration.abs_value;
  unsigned long long lrvalue =
      (unsigned long long) GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                                     UINT64_MAX);
  unsigned long hashSize;
  unsigned long hashSize2;
  unsigned long lsize;
  GNUNET_HashCode vhash;

  if (size > MAX_DATUM_SIZE)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  hashSize = sizeof (GNUNET_HashCode);
  hashSize2 = sizeof (GNUNET_HashCode);
  lsize = size;
  GNUNET_CRYPTO_hash (data, size, &vhash);
  if (GNUNET_OK !=
      GNUNET_MYSQL_statement_run_prepared (plugin->mc, plugin->insert_entry, NULL,
                              MYSQL_TYPE_LONG, &irepl, GNUNET_YES,
                              MYSQL_TYPE_LONG, &type, GNUNET_YES,
                              MYSQL_TYPE_LONG, &ipriority, GNUNET_YES,
                              MYSQL_TYPE_LONG, &ianonymity, GNUNET_YES,
                              MYSQL_TYPE_LONGLONG, &lexpiration, GNUNET_YES,
                              MYSQL_TYPE_LONGLONG, &lrvalue, GNUNET_YES,
                              MYSQL_TYPE_BLOB, key, hashSize, &hashSize,
                              MYSQL_TYPE_BLOB, &vhash, hashSize2, &hashSize2,
                              MYSQL_TYPE_BLOB, data, lsize, &lsize, -1))
    return GNUNET_SYSERR;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Inserted value `%s' with size %u into gn090 table\n",
              GNUNET_h2s (key), (unsigned int) size);
  if (size > 0)
    plugin->env->duc (plugin->env->cls, size);
  return GNUNET_OK;
}


/**
 * Update the priority for a particular key in the datastore.  If
 * the expiration time in value is different than the time found in
 * the datastore, the higher value should be kept.  For the
 * anonymity level, the lower value is to be used.  The specified
 * priority should be added to the existing priority, ignoring the
 * priority in value.
 *
 * Note that it is possible for multiple values to match this put.
 * In that case, all of the respective values are updated.
 *
 * @param cls our "struct Plugin*"
 * @param uid unique identifier of the datum
 * @param delta by how much should the priority
 *     change?  If priority + delta < 0 the
 *     priority should be set to 0 (never go
 *     negative).
 * @param expire new expiration time should be the
 *     MAX of any existing expiration time and
 *     this value
 * @param msg set to error message
 * @return GNUNET_OK on success
 */
static int
mysql_plugin_update (void *cls, uint64_t uid, int delta,
                     struct GNUNET_TIME_Absolute expire, char **msg)
{
  struct Plugin *plugin = cls;
  unsigned long long vkey = uid;
  unsigned long long lexpire = expire.abs_value;
  int ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Updating value %llu adding %d to priority and maxing exp at %llu\n",
              vkey, delta, lexpire);
  ret =
    GNUNET_MYSQL_statement_run_prepared (plugin->mc, plugin->update_entry, NULL,
					 MYSQL_TYPE_LONG, &delta, GNUNET_NO,
                              MYSQL_TYPE_LONGLONG, &lexpire, GNUNET_YES,
                              MYSQL_TYPE_LONGLONG, &lexpire, GNUNET_YES,
                              MYSQL_TYPE_LONGLONG, &vkey, GNUNET_YES, -1);
  if (ret != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Failed to update value %llu\n",
                vkey);
  }
  return ret;
}


/**
 * Run the given select statement and call 'proc' on the resulting
 * values (which must be in particular positions).
 *
 * @param plugin the plugin handle
 * @param stmt select statement to run
 * @param proc function to call on result
 * @param proc_cls closure for proc
 * @param ... arguments to initialize stmt
 */
static void
execute_select (struct Plugin *plugin, struct GNUNET_MYSQL_StatementHandle *stmt,
                PluginDatumProcessor proc, void *proc_cls, ...)
{
  va_list ap;
  int ret;
  unsigned int type;
  unsigned int priority;
  unsigned int anonymity;
  unsigned long long exp;
  unsigned long hashSize;
  unsigned long size;
  unsigned long long uid;
  char value[GNUNET_DATASTORE_MAX_VALUE_SIZE];
  GNUNET_HashCode key;
  struct GNUNET_TIME_Absolute expiration;
  MYSQL_BIND rbind[7];

  hashSize = sizeof (GNUNET_HashCode);
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONG;
  rbind[0].buffer = &type;
  rbind[0].is_unsigned = 1;
  rbind[1].buffer_type = MYSQL_TYPE_LONG;
  rbind[1].buffer = &priority;
  rbind[1].is_unsigned = 1;
  rbind[2].buffer_type = MYSQL_TYPE_LONG;
  rbind[2].buffer = &anonymity;
  rbind[2].is_unsigned = 1;
  rbind[3].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[3].buffer = &exp;
  rbind[3].is_unsigned = 1;
  rbind[4].buffer_type = MYSQL_TYPE_BLOB;
  rbind[4].buffer = &key;
  rbind[4].buffer_length = hashSize;
  rbind[4].length = &hashSize;
  rbind[5].buffer_type = MYSQL_TYPE_BLOB;
  rbind[5].buffer = value;
  rbind[5].buffer_length = size = sizeof (value);
  rbind[5].length = &size;
  rbind[6].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[6].buffer = &uid;
  rbind[6].is_unsigned = 1;

  va_start (ap, proc_cls);
  ret = GNUNET_MYSQL_statement_run_prepared_select_va (plugin->mc, stmt, 7, rbind, NULL, NULL, ap);
  va_end (ap);
  if (ret <= 0)
  {
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  GNUNET_assert (size <= sizeof (value));
  if ((rbind[4].buffer_length != sizeof (GNUNET_HashCode)) ||
      (hashSize != sizeof (GNUNET_HashCode)))
  {
    GNUNET_break (0);
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Found %u-byte value under key `%s' with prio %u, anon %u, expire %llu selecting from gn090 table\n",
              (unsigned int) size, GNUNET_h2s (&key), priority, anonymity, exp);
  GNUNET_assert (size < MAX_DATUM_SIZE);
  expiration.abs_value = exp;
  ret =
      proc (proc_cls, &key, size, value, type, priority, anonymity, expiration,
            uid);
  if (ret == GNUNET_NO)
  {
    do_delete_entry (plugin, uid);
    if (size != 0)
      plugin->env->duc (plugin->env->cls, -size);
  }
}



/**
 * Get one of the results for a particular key in the datastore.
 *
 * @param cls closure
 * @param offset offset of the result (modulo num-results);
 *               specific ordering does not matter for the offset
 * @param key key to match, never NULL
 * @param vhash hash of the value, maybe NULL (to
 *        match all values that have the right key).
 *        Note that for DBlocks there is no difference
 *        betwen key and vhash, but for other blocks
 *        there may be!
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param proc function to call on the matching value,
 *        with NULL for if no value matches
 * @param proc_cls closure for proc
 */
static void
mysql_plugin_get_key (void *cls, uint64_t offset, const GNUNET_HashCode * key,
                      const GNUNET_HashCode * vhash,
                      enum GNUNET_BLOCK_Type type, PluginDatumProcessor proc,
                      void *proc_cls)
{
  struct Plugin *plugin = cls;
  int ret;
  MYSQL_BIND cbind[1];
  long long total;
  unsigned long hashSize;
  unsigned long hashSize2;
  unsigned long long off;

  GNUNET_assert (key != NULL);
  GNUNET_assert (NULL != proc);
  hashSize = sizeof (GNUNET_HashCode);
  hashSize2 = sizeof (GNUNET_HashCode);
  memset (cbind, 0, sizeof (cbind));
  total = -1;
  cbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
  cbind[0].buffer = &total;
  cbind[0].is_unsigned = GNUNET_NO;
  if (type != 0)
  {
    if (vhash != NULL)
    {
      ret =
	GNUNET_MYSQL_statement_run_prepared_select (plugin->mc,
                                         plugin->
                                         count_entry_by_hash_vhash_and_type, 1,
						    cbind, NULL, NULL, MYSQL_TYPE_BLOB, key, hashSize,
                                         &hashSize, MYSQL_TYPE_BLOB, vhash,
                                         hashSize2, &hashSize2, MYSQL_TYPE_LONG,
                                         &type, GNUNET_YES, -1);
    }
    else
    {
      ret =
	GNUNET_MYSQL_statement_run_prepared_select (plugin->mc,
                                         plugin->count_entry_by_hash_and_type,
						    1, cbind, NULL, NULL, MYSQL_TYPE_BLOB, key,
                                         hashSize, &hashSize, MYSQL_TYPE_LONG,
                                         &type, GNUNET_YES, -1);
    }
  }
  else
  {
    if (vhash != NULL)
    {
      ret =
	GNUNET_MYSQL_statement_run_prepared_select (plugin->mc,
                                         plugin->count_entry_by_hash_and_vhash,
						    1, cbind, NULL, NULL, MYSQL_TYPE_BLOB, key,
                                         hashSize, &hashSize, MYSQL_TYPE_BLOB,
                                         vhash, hashSize2, &hashSize2, -1);

    }
    else
    {
      ret =
	GNUNET_MYSQL_statement_run_prepared_select (plugin->mc, plugin->count_entry_by_hash, 1,
						    cbind, NULL, NULL, MYSQL_TYPE_BLOB, key, hashSize,
                                         &hashSize, -1);
    }
  }
  if ((ret != GNUNET_OK) || (0 >= total))
  {
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  offset = offset % total;
  off = (unsigned long long) offset;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Obtaining %llu/%lld result for GET `%s'\n", off, total,
              GNUNET_h2s (key));
  if (type != GNUNET_BLOCK_TYPE_ANY)
  {
    if (NULL != vhash)
    {
      execute_select (plugin, plugin->select_entry_by_hash_vhash_and_type, proc,
                      proc_cls, MYSQL_TYPE_BLOB, key, hashSize, &hashSize,
                      MYSQL_TYPE_BLOB, vhash, hashSize, &hashSize,
                      MYSQL_TYPE_LONG, &type, GNUNET_YES, MYSQL_TYPE_LONGLONG,
                      &off, GNUNET_YES, -1);
    }
    else
    {
      execute_select (plugin, plugin->select_entry_by_hash_and_type, proc,
                      proc_cls, MYSQL_TYPE_BLOB, key, hashSize, &hashSize,
                      MYSQL_TYPE_LONG, &type, GNUNET_YES, MYSQL_TYPE_LONGLONG,
                      &off, GNUNET_YES, -1);
    }
  }
  else
  {
    if (NULL != vhash)
    {
      execute_select (plugin, plugin->select_entry_by_hash_and_vhash, proc,
                      proc_cls, MYSQL_TYPE_BLOB, key, hashSize, &hashSize,
                      MYSQL_TYPE_BLOB, vhash, hashSize, &hashSize,
                      MYSQL_TYPE_LONGLONG, &off, GNUNET_YES, -1);
    }
    else
    {
      execute_select (plugin, plugin->select_entry_by_hash, proc, proc_cls,
                      MYSQL_TYPE_BLOB, key, hashSize, &hashSize,
                      MYSQL_TYPE_LONGLONG, &off, GNUNET_YES, -1);
    }
  }
}


/**
 * Get a zero-anonymity datum from the datastore.
 *
 * @param cls our "struct Plugin*"
 * @param offset offset of the result
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param proc function to call on a matching value or NULL
 * @param proc_cls closure for iter
 */
static void
mysql_plugin_get_zero_anonymity (void *cls, uint64_t offset,
                                 enum GNUNET_BLOCK_Type type,
                                 PluginDatumProcessor proc, void *proc_cls)
{
  struct Plugin *plugin = cls;
  unsigned long long rvalue =
      (unsigned long long) GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                                     UINT64_MAX);

  execute_select (plugin, plugin->zero_iter, proc, proc_cls, MYSQL_TYPE_LONG,
                  &type, GNUNET_YES, MYSQL_TYPE_LONGLONG, &rvalue, GNUNET_YES,
                  MYSQL_TYPE_LONG, &type, GNUNET_YES, MYSQL_TYPE_LONGLONG,
                  &rvalue, GNUNET_YES, -1);
}


/**
 * Context for 'repl_proc' function.
 */
struct ReplCtx
{

  /**
   * Plugin handle.
   */
  struct Plugin *plugin;

  /**
   * Function to call for the result (or the NULL).
   */
  PluginDatumProcessor proc;

  /**
   * Closure for proc.
   */
  void *proc_cls;
};


/**
 * Wrapper for the processor for 'mysql_plugin_get_replication'.
 * Decrements the replication counter and calls the original
 * iterator.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 *
 * @return GNUNET_SYSERR to abort the iteration, GNUNET_OK to continue
 *         (continue on call to "next", of course),
 *         GNUNET_NO to delete the item and continue (if supported)
 */
static int
repl_proc (void *cls, const GNUNET_HashCode * key, uint32_t size,
           const void *data, enum GNUNET_BLOCK_Type type, uint32_t priority,
           uint32_t anonymity, struct GNUNET_TIME_Absolute expiration,
           uint64_t uid)
{
  struct ReplCtx *rc = cls;
  struct Plugin *plugin = rc->plugin;
  unsigned long long oid;
  int ret;
  int iret;

  ret =
      rc->proc (rc->proc_cls, key, size, data, type, priority, anonymity,
                expiration, uid);
  if (NULL != key)
  {
    oid = (unsigned long long) uid;
    iret =
      GNUNET_MYSQL_statement_run_prepared (plugin->mc, plugin->dec_repl, NULL,
					   MYSQL_TYPE_LONGLONG, &oid, GNUNET_YES, -1);
    if (iret == GNUNET_SYSERR)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Failed to reduce replication counter\n");
      return GNUNET_SYSERR;
    }
  }
  return ret;
}


/**
 * Get a random item for replication.  Returns a single, not expired,
 * random item from those with the highest replication counters.  The
 * item's replication counter is decremented by one IF it was positive
 * before.  Call 'proc' with all values ZERO or NULL if the datastore
 * is empty.
 *
 * @param cls closure
 * @param proc function to call the value (once only).
 * @param proc_cls closure for proc
 */
static void
mysql_plugin_get_replication (void *cls, PluginDatumProcessor proc,
                              void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct ReplCtx rc;
  unsigned long long rvalue;
  unsigned long repl;
  MYSQL_BIND results;

  rc.plugin = plugin;
  rc.proc = proc;
  rc.proc_cls = proc_cls;
  memset (&results, 0, sizeof (results));
  results.buffer_type = MYSQL_TYPE_LONG;
  results.buffer = &repl;
  results.is_unsigned = GNUNET_YES;

  if (1 !=
      GNUNET_MYSQL_statement_run_prepared_select (plugin->mc, plugin->max_repl, 1, &results, NULL, NULL, -1))
  {
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }

  rvalue =
      (unsigned long long) GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                                     UINT64_MAX);
  execute_select (plugin, plugin->select_replication, &repl_proc, &rc,
                  MYSQL_TYPE_LONG, &repl, GNUNET_YES, MYSQL_TYPE_LONGLONG,
                  &rvalue, GNUNET_YES, MYSQL_TYPE_LONG, &repl, GNUNET_YES,
                  MYSQL_TYPE_LONGLONG, &rvalue, GNUNET_YES, -1);

}


/**
 * Get all of the keys in the datastore.
 *
 * @param cls closure
 * @param proc function to call on each key
 * @param proc_cls closure for proc
 */
static void
mysql_plugin_get_keys (void *cls,
			PluginKeyProcessor proc,
			void *proc_cls)
{
  struct Plugin *plugin = cls;
  const char *query = "SELECT hash FROM gn090";
  int ret;
  MYSQL_STMT *statement;
  GNUNET_HashCode key;
  MYSQL_BIND cbind[1];
  unsigned long length;
 
  statement = GNUNET_MYSQL_statement_get_stmt (plugin->mc,
					       plugin->get_all_keys);
  if (statement == NULL)
  {
    GNUNET_MYSQL_statements_invalidate (plugin->mc);
    return;
  }
  if (mysql_stmt_prepare (statement, query, strlen (query)))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "mysql",
                     _("Failed to prepare statement `%s'\n"), query);
    GNUNET_MYSQL_statements_invalidate (plugin->mc);
    return;
  }
  GNUNET_assert (proc != NULL);
  if (mysql_stmt_execute (statement))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("`%s' for `%s' failed at %s:%d with error: %s\n"),
                "mysql_stmt_execute", query, __FILE__, __LINE__,
                mysql_stmt_error (statement));
    GNUNET_MYSQL_statements_invalidate (plugin->mc);
    return;
  }
  memset (cbind, 0, sizeof (cbind));
  cbind[0].buffer_type = MYSQL_TYPE_BLOB;
  cbind[0].buffer = &key;
  cbind[0].buffer_length = sizeof (key);
  cbind[0].length = &length;
  cbind[0].is_unsigned = GNUNET_NO;
  if (mysql_stmt_bind_result (statement, cbind))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("`%s' failed at %s:%d with error: %s\n"),
                "mysql_stmt_bind_result", __FILE__, __LINE__,
                mysql_stmt_error (statement));
    GNUNET_MYSQL_statements_invalidate (plugin->mc);
    return;
  }
  while (0 == (ret = mysql_stmt_fetch (statement)))
  {
    if (sizeof (GNUNET_HashCode) == length)
      proc (proc_cls, &key, 1);    
  }
  if (ret != MYSQL_NO_DATA)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("`%s' failed at %s:%d with error: %s\n"),
		     "mysql_stmt_fetch", __FILE__, __LINE__,
		     mysql_stmt_error (statement));    
    GNUNET_MYSQL_statements_invalidate (plugin->mc);
    return;
  }
  mysql_stmt_reset (statement);
}


/**
 * Context for 'expi_proc' function.
 */
struct ExpiCtx
{

  /**
   * Plugin handle.
   */
  struct Plugin *plugin;

  /**
   * Function to call for the result (or the NULL).
   */
  PluginDatumProcessor proc;

  /**
   * Closure for proc.
   */
  void *proc_cls;
};



/**
 * Wrapper for the processor for 'mysql_plugin_get_expiration'.
 * If no expired value was found, we do a second query for
 * low-priority content.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 *
 * @return GNUNET_SYSERR to abort the iteration, GNUNET_OK to continue
 *         (continue on call to "next", of course),
 *         GNUNET_NO to delete the item and continue (if supported)
 */
static int
expi_proc (void *cls, const GNUNET_HashCode * key, uint32_t size,
           const void *data, enum GNUNET_BLOCK_Type type, uint32_t priority,
           uint32_t anonymity, struct GNUNET_TIME_Absolute expiration,
           uint64_t uid)
{
  struct ExpiCtx *rc = cls;
  struct Plugin *plugin = rc->plugin;

  if (NULL == key)
  {
    execute_select (plugin, plugin->select_priority, rc->proc, rc->proc_cls,
                    -1);
    return GNUNET_SYSERR;
  }
  return rc->proc (rc->proc_cls, key, size, data, type, priority, anonymity,
                   expiration, uid);
}


/**
 * Get a random item for expiration.
 * Call 'proc' with all values ZERO or NULL if the datastore is empty.
 *
 * @param cls closure
 * @param proc function to call the value (once only).
 * @param proc_cls closure for proc
 */
static void
mysql_plugin_get_expiration (void *cls, PluginDatumProcessor proc,
                             void *proc_cls)
{
  struct Plugin *plugin = cls;
  long long nt;
  struct ExpiCtx rc;

  rc.plugin = plugin;
  rc.proc = proc;
  rc.proc_cls = proc_cls;
  nt = (long long) GNUNET_TIME_absolute_get ().abs_value;
  execute_select (plugin, plugin->select_expiration, expi_proc, &rc,
                  MYSQL_TYPE_LONGLONG, &nt, GNUNET_YES, -1);

}


/**
 * Drop database.
 *
 * @param cls the "struct Plugin*"
 */
static void
mysql_plugin_drop (void *cls)
{
  struct Plugin *plugin = cls;

  if (GNUNET_OK != GNUNET_MYSQL_statement_run (plugin->mc, "DROP TABLE gn090"))
    return;                     /* error */
  plugin->env->duc (plugin->env->cls, 0);
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_DATASTORE_PluginEnvironment*"
 * @return our "struct Plugin*"
 */
void *
libgnunet_plugin_datastore_mysql_init (void *cls)
{
  struct GNUNET_DATASTORE_PluginEnvironment *env = cls;
  struct GNUNET_DATASTORE_PluginFunctions *api;
  struct Plugin *plugin;

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  plugin->mc = GNUNET_MYSQL_context_create (env->cfg, "datastore-mysql");
  if (NULL == plugin->mc)
  {
    GNUNET_free (plugin);
    return NULL;
  }
#define MRUNS(a) (GNUNET_OK != GNUNET_MYSQL_statement_run (plugin->mc, a) )
#define PINIT(a,b) (NULL == (a = GNUNET_MYSQL_statement_prepare (plugin->mc, b)))
  if (MRUNS
      ("CREATE TABLE IF NOT EXISTS gn090 ("
       " repl INT(11) UNSIGNED NOT NULL DEFAULT 0,"
       " type INT(11) UNSIGNED NOT NULL DEFAULT 0,"
       " prio INT(11) UNSIGNED NOT NULL DEFAULT 0,"
       " anonLevel INT(11) UNSIGNED NOT NULL DEFAULT 0,"
       " expire BIGINT UNSIGNED NOT NULL DEFAULT 0,"
       " rvalue BIGINT UNSIGNED NOT NULL,"
       " hash BINARY(64) NOT NULL DEFAULT '',"
       " vhash BINARY(64) NOT NULL DEFAULT '',"
       " value BLOB NOT NULL DEFAULT ''," " uid BIGINT NOT NULL AUTO_INCREMENT,"
       " PRIMARY KEY (uid)," " INDEX idx_hash (hash(64)),"
       " INDEX idx_hash_uid (hash(64),uid),"
       " INDEX idx_hash_vhash (hash(64),vhash(64)),"
       " INDEX idx_hash_type_uid (hash(64),type,rvalue),"
       " INDEX idx_prio (prio)," " INDEX idx_repl_rvalue (repl,rvalue),"
       " INDEX idx_expire (expire),"
       " INDEX idx_anonLevel_type_rvalue (anonLevel,type,rvalue)"
       ") ENGINE=InnoDB") || MRUNS ("SET AUTOCOMMIT = 1") ||
      PINIT (plugin->insert_entry, INSERT_ENTRY) ||
      PINIT (plugin->delete_entry_by_uid, DELETE_ENTRY_BY_UID) ||
      PINIT (plugin->select_entry_by_hash, SELECT_ENTRY_BY_HASH) ||
      PINIT (plugin->select_entry_by_hash_and_vhash,
             SELECT_ENTRY_BY_HASH_AND_VHASH) ||
      PINIT (plugin->select_entry_by_hash_and_type,
             SELECT_ENTRY_BY_HASH_AND_TYPE) ||
      PINIT (plugin->select_entry_by_hash_vhash_and_type,
             SELECT_ENTRY_BY_HASH_VHASH_AND_TYPE) ||
      PINIT (plugin->count_entry_by_hash, COUNT_ENTRY_BY_HASH) ||
      PINIT (plugin->get_size, SELECT_SIZE) ||
      PINIT (plugin->count_entry_by_hash_and_vhash,
             COUNT_ENTRY_BY_HASH_AND_VHASH) ||
      PINIT (plugin->count_entry_by_hash_and_type, COUNT_ENTRY_BY_HASH_AND_TYPE)
      || PINIT (plugin->count_entry_by_hash_vhash_and_type,
                COUNT_ENTRY_BY_HASH_VHASH_AND_TYPE) ||
      PINIT (plugin->update_entry, UPDATE_ENTRY) ||
      PINIT (plugin->dec_repl, DEC_REPL) ||
      PINIT (plugin->zero_iter, SELECT_IT_NON_ANONYMOUS) ||
      PINIT (plugin->select_expiration, SELECT_IT_EXPIRATION) ||
      PINIT (plugin->select_priority, SELECT_IT_PRIORITY) ||
      PINIT (plugin->max_repl, SELECT_MAX_REPL) ||
      PINIT (plugin->get_all_keys, GET_ALL_KEYS) ||
      PINIT (plugin->select_replication, SELECT_IT_REPLICATION))
  {
    GNUNET_MYSQL_context_destroy (plugin->mc);
    GNUNET_free (plugin);
    return NULL;
  }
#undef PINIT
#undef MRUNS

  api = GNUNET_malloc (sizeof (struct GNUNET_DATASTORE_PluginFunctions));
  api->cls = plugin;
  api->estimate_size = &mysql_plugin_estimate_size;
  api->put = &mysql_plugin_put;
  api->update = &mysql_plugin_update;
  api->get_key = &mysql_plugin_get_key;
  api->get_replication = &mysql_plugin_get_replication;
  api->get_expiration = &mysql_plugin_get_expiration;
  api->get_zero_anonymity = &mysql_plugin_get_zero_anonymity;
  api->get_keys = &mysql_plugin_get_keys;
  api->drop = &mysql_plugin_drop;
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "mysql",
                   _("Mysql database running\n"));
  return api;
}


/**
 * Exit point from the plugin.
 * @param cls our "struct Plugin*"
 * @return always NULL
 */
void *
libgnunet_plugin_datastore_mysql_done (void *cls)
{
  struct GNUNET_DATASTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  GNUNET_MYSQL_context_destroy (plugin->mc);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_datastore_mysql.c */
