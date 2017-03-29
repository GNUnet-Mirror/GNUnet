/*
     This file is part of GNUnet
     Copyright (C) 2009, 2010, 2012 GNUnet e.V.

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
 * @file postgres/postgres.c
 * @brief library to help with access to a Postgres database
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_postgres_lib.h"


/**
 * Check if the result obtained from Postgres has
 * the desired status code.  If not, log an error, clear the
 * result and return GNUNET_SYSERR.
 *
 * @param dbh database handle
 * @param ret return value from database operation to check
 * @param expected_status desired status
 * @param command description of the command that was run
 * @param args arguments given to the command
 * @param filename name of the source file where the command was run
 * @param line line number in the source file
 * @return #GNUNET_OK if the result is acceptable
 */
int
GNUNET_POSTGRES_check_result_ (PGconn *dbh,
			       PGresult *ret,
                               int expected_status,
			       const char *command,
                               const char *args,
			       const char *filename,
			       int line)
{
  if (ret == NULL)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                     "postgres",
                     "Postgres failed to allocate result for `%s:%s' at %s:%d\n",
                     command,
		     args,
		     filename,
		     line);
    return GNUNET_SYSERR;
  }
  if (PQresultStatus (ret) != expected_status)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                     "postgres",
		     _("`%s:%s' failed at %s:%d with error: %s\n"),
                     command,
		     args,
		     filename,
		     line,
		     PQerrorMessage (dbh));
    PQclear (ret);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Run simple SQL statement (without results).
 *
 * @param dbh database handle
 * @param sql statement to run
 * @param filename filename for error reporting
 * @param line code line for error reporting
 * @return #GNUNET_OK on success
 */
int
GNUNET_POSTGRES_exec_ (PGconn * dbh,
		       const char *sql,
		       const char *filename,
                       int line)
{
  PGresult *ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Executing SQL statement `%s' at %s:%d\n",
	      sql,
	      filename,
	      line);
  ret = PQexec (dbh,
		sql);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result_ (dbh,
				     ret,
				     PGRES_COMMAND_OK,
				     "PQexec",
				     sql,
                                     filename,
				     line))
    return GNUNET_SYSERR;
  PQclear (ret);
  return GNUNET_OK;
}


/**
 * Prepare SQL statement.
 *
 * @param dbh database handle
 * @param name name for the prepared SQL statement
 * @param sql SQL code to prepare
 * @param nparams number of parameters in sql
 * @param filename filename for error reporting
 * @param line code line for error reporting
 * @return #GNUNET_OK on success
 */
int
GNUNET_POSTGRES_prepare_ (PGconn *dbh,
			  const char *name,
			  const char *sql,
                          int nparams,
			  const char *filename,
			  int line)
{
  PGresult *ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Preparing SQL statement `%s' as `%s' at %s:%d\n",
	      sql,
	      name,
	      filename,
	      line);
  ret = PQprepare (dbh,
		   name,
		   sql,
		   nparams, NULL);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result_ (dbh,
				     ret,
				     PGRES_COMMAND_OK,
				     "PQprepare",
                                     sql,
				     filename,
				     line))
    return GNUNET_SYSERR;
  PQclear (ret);
  return GNUNET_OK;
}


/**
 * Connect to a postgres database
 *
 * @param cfg configuration
 * @param section configuration section to use to get Postgres configuration options
 * @return the postgres handle
 */
PGconn *
GNUNET_POSTGRES_connect (const struct GNUNET_CONFIGURATION_Handle * cfg,
                         const char *section)
{
  PGconn *dbh;
  char *conninfo;

  /* Open database and precompile statements */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
					     section,
					     "CONFIG",
					     &conninfo))
    conninfo = NULL;
  dbh = PQconnectdb (conninfo == NULL ? "" : conninfo);

  if (NULL != dbh)
  {
    if (PQstatus (dbh) != CONNECTION_OK)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "postgres",
                       _("Unable to connect to Postgres database '%s': %s\n"),
                       conninfo,
                       PQerrorMessage (dbh));
      PQfinish (dbh);
      dbh = NULL;
    }
  }
  // FIXME: warn about out-of-memory when dbh is NULL?
  GNUNET_free_non_null (conninfo);
  return dbh;
}


/**
 * Delete the row identified by the given rowid (qid
 * in postgres).
 *
 * @param dbh database handle
 * @param stmt name of the prepared statement
 * @param rowid which row to delete
 * @return #GNUNET_OK on success
 */
int
GNUNET_POSTGRES_delete_by_rowid (PGconn * dbh,
				 const char *stmt,
				 uint32_t rowid)
{
  uint32_t brow = htonl (rowid);
  const char *paramValues[] = { (const char *) &brow };
  int paramLengths[] = { sizeof (brow) };
  const int paramFormats[] = { 1 };
  PGresult *ret;

  ret = PQexecPrepared (dbh,
			stmt,
			1,
			paramValues,
			paramLengths,
			paramFormats,
			1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result_ (dbh, ret,
				     PGRES_COMMAND_OK,
                                     "PQexecPrepared",
				     "delrow",
				     __FILE__,
                                     __LINE__))
  {
    return GNUNET_SYSERR;
  }
  PQclear (ret);
  return GNUNET_OK;
}


/* end of postgres.c */
