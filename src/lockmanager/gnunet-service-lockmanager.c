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
 * @file lockmanager/gnunet-service-lockmanager.c
 * @brief implementation of the LOCKMANAGER service
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_server_lib.h"

#include "lockmanager.h"

#define LOG(kind,...) \
  GNUNET_log_from (kind, "gnunet-service-lockmanager",__VA_ARGS__)


/**
 * Handler for GNUNET_MESSAGE_TYPE_LOCKMANAGER_ACQUIRE
 *
 * @param 
 * @return 
 */
static void
handle_acquire (void *cls,
                struct GNUNET_SERVER_Client *client,
                const struct GNUNET_MessageHeader *message)
{
  // const struct GNUNET_LOCKMANAGER_Message *msg = message;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received a ACQUIRE message\n");

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle for GNUNET_MESSAGE_TYPE_LOCKMANAGER_RELEASE
 *
 * @param 
 * @return 
 */
static void
handle_release (void *cls,
                struct GNUNET_SERVER_Client *client,
                const struct GNUNET_MessageHeader *message)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received a RELEASE message\n");

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Lock manager setup
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void 
lockmanager_run (void *cls,
                 struct GNUNET_SERVER_Handle * server,
                 const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_SERVER_MessageHandler message_handlers[] =
    {
      {&handle_acquire, NULL, GNUNET_MESSAGE_TYPE_LOCKMANAGER_ACQUIRE, 0},
      {&handle_release, NULL, GNUNET_MESSAGE_TYPE_LOCKMANAGER_RELEASE, 0},
      {NULL}
    };
  
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Starting lockmanager\n");
  GNUNET_SERVER_add_handlers (server,
                              message_handlers);
  
}

/**
 * The starting point of execution
 */
int main (int argc, char *const *argv)
{
  int ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "main()\n");
  ret = 
    (GNUNET_OK ==
     GNUNET_SERVICE_run (argc,
                         argv,
                         "lockmanager",
                         GNUNET_SERVICE_OPTION_NONE,
                         &lockmanager_run,
                         NULL)) ? 0 : 1;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "main() END\n");
  return ret;
}
