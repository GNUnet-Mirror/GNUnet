/*
   This file is part of GNUnet
   Copyright (C) 2017, 2019 GNUnet e.V.

   GNUnet is free software: you can redistribute it and/or modify it
   under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License,
   or (at your option) any later version.

   GNUnet is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file pq/pq.h
 * @brief shared internal data structures of libgnunetpq
 * @author Christian Grothoff
 */
#ifndef PQ_H
#define PQ_H

#include "gnunet_util_lib.h"
#include "gnunet_pq_lib.h"

/**
 * Handle to Postgres database.
 */
struct GNUNET_PQ_Context
{
  /**
   * Actual connection.
   */
  PGconn *conn;

  /**
   * Statements to execute upon connection.
   */
  struct GNUNET_PQ_ExecuteStatement *es;

  /**
   * Prepared statements.
   */
  struct GNUNET_PQ_PreparedStatement *ps;

  /**
   * Configuration to use to connect to the DB.
   */
  char *config_str;
};

#endif
