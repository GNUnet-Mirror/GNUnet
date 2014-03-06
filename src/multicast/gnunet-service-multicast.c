/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file multicast/gnunet-service-multicast.c
 * @brief program that does multicast
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  /* FIXME: do clean up here */
}


/**
 * Handle a connecting client starting an origin.
 */
static void
handle_origin_start (void *cls, struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *msg)
{

}


/**
 * Handle a client stopping an origin.
 */
static void
handle_origin_stop (void *cls, struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *msg)
{

}


/**
 * Handle a connecting client joining a group.
 */
static void
handle_member_join (void *cls, struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *msg)
{

}


/**
 * Handle a client parting a group.
 */
static void
handle_member_part (void *cls, struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *msg)
{

}


/**
 * Incoming message from a client.
 */
static void
handle_multicast_message (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *msg)
{

}


/**
 * Incoming request from a client.
 */
static void
handle_multicast_request (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *msg)
{

}

/**
 * Process multicast requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    { &handle_origin_start, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_ORIGIN_START, 0 },

    { &handle_origin_stop, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_ORIGIN_STOP, 0 },

    { &handle_member_join, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_MEMBER_JOIN, 0 },

    { &handle_member_part, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_MEMBER_PART, 0 },

    { &handle_multicast_message, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE, 0 },

    { &handle_multicast_request, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST, 0 },

    {NULL, NULL, 0, 0}
  };
  /* FIXME: do setup here */
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                NULL);
}


/**
 * The main function for the multicast service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "multicast",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-multicast.c */
