/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file lockmanager/lockmanager_api.c
 * @brief API implementation of gnunet_lockmanager_service.h
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_client_lib.h"

#include "lockmanager.h"

#define LOG(kind,...) \
  GNUNET_log_from (kind, "gnunet-service-lockmanager",__VA_ARGS__)

/**
 * Handler for the lockmanager service
 */
struct GNUNET_LOCKMANAGER_Handle
{
  /**
   * The client connection to the service
   */
  struct GNUNET_CLIENT_Connection *conn;
};


/**
 * Connect to the lockmanager service
 *
 * @param cfg the configuration to use
 *
 * @return upon success the handle to the service; NULL upon error
 */
struct GNUNET_LOCKMANAGER_Handle *
GNUNET_LOCKMANAGER_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_LOCKMANAGER_Handle *h;

  h = GNUNET_malloc (sizeof (struct GNUNET_LOCKMANAGER_Handle));
  h->conn = GNUNET_CLIENT_connect ("lockmanager", cfg);
  if (NULL == h->conn)
    {
      GNUNET_free (h);
      return NULL;
    }
  return NULL;
}

/**
 * Disconnect from the lockmanager service
 *
 * @param handle the handle to the lockmanager service
 */
void
GNUNET_LOCKMANAGER_disconnect (struct GNUNET_LOCKMANAGER_Handle *handle)
{
  
}
