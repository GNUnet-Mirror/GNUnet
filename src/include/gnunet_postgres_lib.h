/*
     This file is part of GNUnet
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_postgres_lib.h
 * @brief library to help with access to a Postgres database
 * @author Christian Grothoff
 */
#ifndef GNUNET_POSTGRES_LIB_H
#define GNUNET_POSTGRES_LIB_H

#include "gnunet_util_lib.h"
#include <postgresql/libpq-fe.h>

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


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
 * @return GNUNET_OK if the result is acceptable
 */
int
GNUNET_POSTGRES_check_result_ (PGconn *dbh, PGresult * ret, int expected_status,
			       const char *command, const char *args,
			       const char *filename, int line);


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
 * @return GNUNET_OK if the result is acceptable
 */
#define GNUNET_POSTGRES_check_result(dbh,ret,expected_status,command,args) GNUNET_POSTGRES_check_result_(dbh,ret,expected_status,command,args,__FILE__,__LINE__)


/**
 * Run simple SQL statement (without results).
 *
 * @param dbh database handle
 * @param sql statement to run
 * @param filename filename for error reporting
 * @param line code line for error reporting 
 * @return GNUNET_OK on success
 */
int
GNUNET_POSTGRES_exec_ (PGconn *dbh, const char *sql, const char *filename, int line);


/**
 * Run simple SQL statement (without results).
 *
 * @param dbh database handle
 * @param sql statement to run
 * @return GNUNET_OK on success
 */
#define GNUNET_POSTGRES_exec(dbh,sql) GNUNET_POSTGRES_exec_(dbh,sql,__FILE__,__LINE__)


/**
 * Prepare SQL statement.
 *
 * @param dbh database handle
 * @param name name for the prepared SQL statement
 * @param sql SQL code to prepare
 * @param nparms number of parameters in sql
 * @param filename filename for error reporting
 * @param line code line for error reporting
 * @return GNUNET_OK on success
 */
int
GNUNET_POSTGRES_prepare_ (PGconn *dbh, const char *name, const char *sql,
			  int nparms,
			  const char *filename, int line);


/**
 * Prepare SQL statement.
 *
 * @param dbh database handle
 * @param name name for the prepared SQL statement
 * @param sql SQL code to prepare
 * @param nparams number of parameters in sql
 * @return GNUNET_OK on success
 */
#define GNUNET_POSTGRES_prepare(dbh,name,sql,nparams) GNUNET_POSTGRES_prepare_(dbh,name,sql,nparams,__FILE__,__LINE__)


/**
 * Connect to a postgres database
 *
 * @param cfg configuration
 * @param section configuration section to use to get Postgres configuration options
 * @return the postgres handle
 */
PGconn *
GNUNET_POSTGRES_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
			 const char *section);


/**
 * Delete the row identified by the given rowid (qid
 * in postgres).
 *
 * @param dbh database handle
 * @param stmt name of the prepared statement
 * @param rowid which row to delete
 * @return GNUNET_OK on success
 */
int
GNUNET_POSTGRES_delete_by_rowid (PGconn *dbh,
				 const char *stmt,
				 uint32_t rowid);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_postgres_lib.h */
#endif
