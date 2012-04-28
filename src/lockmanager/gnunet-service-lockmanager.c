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

#define TIME_REL_MINS(min) \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, min)

#define TIMEOUT TIME_REL_MINS(3)

/**
 * Transmit notify for sending message to client
 *
 * @param cls the message to send
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t 
transmit_notify (void *cls, size_t size, void *buf)
{
  struct GNUNET_LOCKMANAGER_Message *msg = cls;
  uint16_t msg_size;

  if ((0 == size) || (NULL == buf))
    {
      /* FIXME: Timed out -- requeue? */
      return 0;
    }
  msg_size = ntohs (msg->header.size);
  GNUNET_assert (size >= msg_size);
  memcpy (buf, msg, msg_size);
  GNUNET_free (msg);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Message of size %u sent\n", msg_size);
  return msg_size;
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_LOCKMANAGER_ACQUIRE
 *
 * @param cls NULL
 * @param client the client sending this message
 * @param message GNUNET_MESSAGE_TYPE_LOCKMANAGER_ACQUIRE message
 */
static void
handle_acquire (void *cls,
                struct GNUNET_SERVER_Client *client,
                const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_LOCKMANAGER_Message *request;
  struct GNUNET_LOCKMANAGER_Message *reply;
  int16_t request_size;
  

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received an ACQUIRE message\n");
  
  request = (struct GNUNET_LOCKMANAGER_Message *) message;

  /* FIXME: Dummy implementation; just echos success for every lock */
  request_size = ntohs (message->size);
  reply = GNUNET_malloc (request_size);
  memcpy (reply, request, request_size);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_LOCKMANAGER_SUCCESS);
  GNUNET_SERVER_notify_transmit_ready (client,
                                       request_size,
                                       TIMEOUT,
                                       &transmit_notify,
                                       reply);

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
  static const struct GNUNET_SERVER_MessageHandler message_handlers[] =
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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "main()\n");
  ret = 
    (GNUNET_OK ==
     GNUNET_SERVICE_run (argc,
                         argv,
                         "lockmanager",
                         GNUNET_SERVICE_OPTION_NONE,
                         &lockmanager_run,
                         NULL)) ? 0 : 1;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "main() END\n");
  return ret;
}
