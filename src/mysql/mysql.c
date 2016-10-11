/*
     This file is part of GNUnet
     Copyright (C) 2012 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file mysql/mysql.c
 * @brief library to help with access to a MySQL database
 * @author Christian Grothoff
 */
#include "platform.h"
#include <mysql/mysql.h>
#include "gnunet_mysql_lib.h"

/**
 * Maximum number of supported parameters for a prepared
 * statement.  Increase if needed.
 */
#define MAX_PARAM 16


/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_MYSQL(cmd, dbh) do { GNUNET_log_from (GNUNET_ERROR_TYPE__ERROR, "mysql", _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error((dbh)->dbf)); GNUNET_assert (0); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_MYSQL(level, cmd, dbh) do { GNUNET_log_from (level, "mysql", _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error((dbh)->dbf)); } while(0);


/**
 * Mysql context.
 */
struct GNUNET_MYSQL_Context
{

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Our section.
   */
  const char *section;

  /**
   * Handle to the mysql database.
   */
  MYSQL *dbf;

  /**
   * Head of list of our prepared statements.
   */
  struct GNUNET_MYSQL_StatementHandle *shead;

  /**
   * Tail of list of our prepared statements.
   */
  struct GNUNET_MYSQL_StatementHandle *stail;

  /**
   * Filename of "my.cnf" (msyql configuration).
   */
  char *cnffile;

};


/**
 * Handle for a prepared statement.
 */
struct GNUNET_MYSQL_StatementHandle
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_MYSQL_StatementHandle *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_MYSQL_StatementHandle *prev;

  /**
   * Mysql Context the statement handle belongs to.
   */
  struct GNUNET_MYSQL_Context *mc;

  /**
   * Original query string.
   */
  char *query;

  /**
   * Handle to MySQL prepared statement.
   */
  MYSQL_STMT *statement;

  /**
   * Is the MySQL prepared statement valid, or do we need to re-initialize it?
   */
  int valid;

};


/**
 * Obtain the location of ".my.cnf".
 *
 * @param cfg our configuration
 * @param section the section
 * @return NULL on error
 */
static char *
get_my_cnf_path (const struct GNUNET_CONFIGURATION_Handle *cfg,
                 const char *section)
{
  char *cnffile;
  char *home_dir;
  struct stat st;

#ifndef WINDOWS
  struct passwd *pw;
#endif
  int configured;

#ifndef WINDOWS
  pw = getpwuid (getuid ());
  if (!pw)
  {
    GNUNET_log_from_strerror (GNUNET_ERROR_TYPE_ERROR, "mysql", "getpwuid");
    return NULL;
  }
  if (GNUNET_YES == GNUNET_CONFIGURATION_have_value (cfg, section, "CONFIG"))
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONFIGURATION_get_value_filename (cfg, section,
                                                            "CONFIG",
                                                            &cnffile));
    configured = GNUNET_YES;
  }
  else
  {
    home_dir = GNUNET_strdup (pw->pw_dir);
    GNUNET_asprintf (&cnffile, "%s/.my.cnf", home_dir);
    GNUNET_free (home_dir);
    configured = GNUNET_NO;
  }
#else
  home_dir = (char *) GNUNET_malloc (_MAX_PATH + 1);
  plibc_conv_to_win_path ("~/", home_dir);
  GNUNET_asprintf (&cnffile, "%s/.my.cnf", home_dir);
  GNUNET_free (home_dir);
  configured = GNUNET_NO;
#endif
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "mysql",
                   _("Trying to use file `%s' for MySQL configuration.\n"),
                   cnffile);
  if ((0 != STAT (cnffile, &st)) || (0 != ACCESS (cnffile, R_OK)) ||
      (!S_ISREG (st.st_mode)))
  {
    if (configured == GNUNET_YES)
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "mysql",
                       _("Could not access file `%s': %s\n"), cnffile,
                       STRERROR (errno));
    GNUNET_free (cnffile);
    return NULL;
  }
  return cnffile;
}


/**
 * Open the connection with the database (and initialize
 * our default options).
 *
 * @param mc database context to initialze
 * @return #GNUNET_OK on success
 */
static int
iopen (struct GNUNET_MYSQL_Context *mc)
{
  char *mysql_dbname;
  char *mysql_server;
  char *mysql_user;
  char *mysql_password;
  unsigned long long mysql_port;
  my_bool reconnect;
  unsigned int timeout;

  mc->dbf = mysql_init (NULL);
  if (mc->dbf == NULL)
    return GNUNET_SYSERR;
  if (mc->cnffile != NULL)
    mysql_options (mc->dbf, MYSQL_READ_DEFAULT_FILE, mc->cnffile);
  mysql_options (mc->dbf, MYSQL_READ_DEFAULT_GROUP, "client");
  reconnect = 0;
  mysql_options (mc->dbf, MYSQL_OPT_RECONNECT, &reconnect);
  mysql_options (mc->dbf, MYSQL_OPT_CONNECT_TIMEOUT, (const void *) &timeout);
  mysql_options (mc->dbf, MYSQL_SET_CHARSET_NAME, "UTF8");
  timeout = 60;                 /* in seconds */
  mysql_options (mc->dbf, MYSQL_OPT_READ_TIMEOUT, (const void *) &timeout);
  mysql_options (mc->dbf, MYSQL_OPT_WRITE_TIMEOUT, (const void *) &timeout);
  mysql_dbname = NULL;
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_have_value (mc->cfg, mc->section, "DATABASE"))
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONFIGURATION_get_value_string (mc->cfg, mc->section,
                                                          "DATABASE",
                                                          &mysql_dbname));
  else
    mysql_dbname = GNUNET_strdup ("gnunet");
  mysql_user = NULL;
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_have_value (mc->cfg, mc->section, "USER"))
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONFIGURATION_get_value_string (mc->cfg, mc->section,
                                                          "USER", &mysql_user));
  }
  mysql_password = NULL;
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_have_value (mc->cfg, mc->section, "PASSWORD"))
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONFIGURATION_get_value_string (mc->cfg, mc->section,
                                                          "PASSWORD",
                                                          &mysql_password));
  }
  mysql_server = NULL;
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_have_value (mc->cfg, mc->section, "HOST"))
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONFIGURATION_get_value_string (mc->cfg, mc->section,
                                                          "HOST",
                                                          &mysql_server));
  }
  mysql_port = 0;
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_have_value (mc->cfg, mc->section, "PORT"))
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONFIGURATION_get_value_number (mc->cfg, mc->section,
                                                          "PORT", &mysql_port));
  }

  GNUNET_assert (mysql_dbname != NULL);
  mysql_real_connect (mc->dbf, mysql_server, mysql_user, mysql_password,
                      mysql_dbname, (unsigned int) mysql_port, NULL,
                      CLIENT_IGNORE_SIGPIPE);
  GNUNET_free_non_null (mysql_server);
  GNUNET_free_non_null (mysql_user);
  GNUNET_free_non_null (mysql_password);
  GNUNET_free (mysql_dbname);
  if (mysql_error (mc->dbf)[0])
  {
    LOG_MYSQL (GNUNET_ERROR_TYPE_ERROR, "mysql_real_connect", mc);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Create a mysql context.
 *
 * @param cfg configuration
 * @param section configuration section to use to get MySQL configuration options
 * @return the mysql context
 */
struct GNUNET_MYSQL_Context *
GNUNET_MYSQL_context_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
                             const char *section)
{
  struct GNUNET_MYSQL_Context *mc;

  mc = GNUNET_new (struct GNUNET_MYSQL_Context);
  mc->cfg = cfg;
  mc->section = section;
  mc->cnffile = get_my_cnf_path (cfg,
                                 section);

  return mc;
}


/**
 * Close database connection and all prepared statements (we got a DB
 * error).
 *
 * @param mc mysql context
 */
void
GNUNET_MYSQL_statements_invalidate (struct GNUNET_MYSQL_Context *mc)
{
  struct GNUNET_MYSQL_StatementHandle *sh;

  for (sh = mc->shead; NULL != sh; sh = sh->next)
  {
    if (GNUNET_YES == sh->valid)
    {
      mysql_stmt_close (sh->statement);
      sh->valid = GNUNET_NO;
    }
    sh->statement = NULL;
  }
  if (NULL != mc->dbf)
  {
    mysql_close (mc->dbf);
    mc->dbf = NULL;
  }
}


/**
 * Destroy a mysql context.  Also frees all associated prepared statements.
 *
 * @param mc context to destroy
 */
void
GNUNET_MYSQL_context_destroy (struct GNUNET_MYSQL_Context *mc)
{
  struct GNUNET_MYSQL_StatementHandle *sh;

  GNUNET_MYSQL_statements_invalidate (mc);
  while (NULL != (sh = mc->shead))
  {
    GNUNET_CONTAINER_DLL_remove (mc->shead, mc->stail, sh);
    GNUNET_free (sh->query);
    GNUNET_free (sh);
  }
  GNUNET_free (mc);
  mysql_library_end ();
}


/**
 * Prepare a statement.  Prepared statements are automatically discarded
 * when the MySQL context is destroyed.
 *
 * @param mc mysql context
 * @param query query text
 * @return prepared statement, NULL on error
 */
struct GNUNET_MYSQL_StatementHandle *
GNUNET_MYSQL_statement_prepare (struct GNUNET_MYSQL_Context *mc,
                                const char *query)
{
  struct GNUNET_MYSQL_StatementHandle *sh;

  sh = GNUNET_new (struct GNUNET_MYSQL_StatementHandle);
  sh->mc = mc;
  sh->query = GNUNET_strdup (query);
  GNUNET_CONTAINER_DLL_insert (mc->shead, mc->stail, sh);
  return sh;
}


/**
 * Run a SQL statement.
 *
 * @param mc mysql context
 * @param sql SQL statement to run
 * @return #GNUNET_OK on success
 *         #GNUNET_SYSERR if there was a problem
 */
int
GNUNET_MYSQL_statement_run (struct GNUNET_MYSQL_Context *mc,
                            const char *sql)
{
  if ( (NULL == mc->dbf) &&
       (GNUNET_OK != iopen (mc)) )
    return GNUNET_SYSERR;
  mysql_query (mc->dbf, sql);
  if (mysql_error (mc->dbf)[0])
  {
    LOG_MYSQL (GNUNET_ERROR_TYPE_ERROR,
               "mysql_query",
               mc);
    GNUNET_MYSQL_statements_invalidate (mc);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Prepare a statement for running.
 *
 * @param mc mysql context
 * @param sh statement handle to prepare
 * @return #GNUNET_OK on success
 */
static int
prepare_statement (struct GNUNET_MYSQL_StatementHandle *sh)
{
  struct GNUNET_MYSQL_Context *mc = sh->mc;

  if (GNUNET_YES == sh->valid)
    return GNUNET_OK;
  if ((NULL == mc->dbf) && (GNUNET_OK != iopen (mc)))
    return GNUNET_SYSERR;
  sh->statement = mysql_stmt_init (mc->dbf);
  if (NULL == sh->statement)
  {
    GNUNET_MYSQL_statements_invalidate (mc);
    return GNUNET_SYSERR;
  }
  if (0 != mysql_stmt_prepare (sh->statement, sh->query, strlen (sh->query)))
  {
    LOG_MYSQL (GNUNET_ERROR_TYPE_ERROR, "mysql_stmt_prepare", mc);
    mysql_stmt_close (sh->statement);
    sh->statement = NULL;
    GNUNET_MYSQL_statements_invalidate (mc);
    return GNUNET_SYSERR;
  }
  sh->valid = GNUNET_YES;
  return GNUNET_OK;
}


/**
 * Get internal handle for a prepared statement.  This function should rarely
 * be used, and if, with caution!  On failures during the interaction with
 * the handle, you must call 'GNUNET_MYSQL_statements_invalidate'!
 *
 * @param sh prepared statement to introspect
 * @return MySQL statement handle, NULL on error
 */
MYSQL_STMT *
GNUNET_MYSQL_statement_get_stmt (struct GNUNET_MYSQL_StatementHandle *sh)
{
  (void) prepare_statement (sh);
  return sh->statement;
}


/* end of mysql.c */
