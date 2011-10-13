/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats.c
 * @brief ats service
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-ats_performance.h"
#include "gnunet-service-ats_scheduling.h"
#include "gnunet-service-ats_addresses.h"
#include "ats.h"


static void
handle_ats_start (void *cls, struct GNUNET_SERVER_Client *client,
		  const struct GNUNET_MessageHeader *message)
{
  const struct ClientStartMessage * msg = (const struct ClientStartMessage *) message;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received `%s' message\n",
	      "ATS_START");
  switch (ntohl (msg->start_flag))
  {
  case START_FLAG_SCHEDULING:
    GAS_add_scheduling_client (client);
    break;
  case START_FLAG_PERFORMANCE_WITH_PIC:
    GAS_add_performance_client (client);
    break;
  case START_FLAG_PERFORMANCE_NO_PIC:
    break;
  default:
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);    
}


/**
 * A client disconnected from us.  Tear down the local client
 * record.
 *
 * @param cls unused
 * @param client handle of the client
 */
static void
client_disconnect_handler (void *cls, struct GNUNET_SERVER_Client *client)
{
  GAS_remove_scheduling_client (client);
  GAS_remove_performance_client (client);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GAS_addresses_done ();
}


/**
 * Process template requests.
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
    { &handle_ats_start, NULL, 
      GNUNET_MESSAGE_TYPE_ATS_START, sizeof (struct ClientStartMessage)},
    { &GAS_handle_request_address, NULL,
      GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS, sizeof (struct RequestAddressMessage)},
    { &GAS_handle_address_update, NULL, 
      GNUNET_MESSAGE_TYPE_ATS_ADDRESS_UPDATE, 0},
    { &GAS_handle_address_destroyed, NULL, 
      GNUNET_MESSAGE_TYPE_ATS_ADDRESS_DESTROYED, 0},
    { &GAS_handle_reservation_request, NULL, 
      GNUNET_MESSAGE_TYPE_ATS_RESERVATION_REQUEST, sizeof (struct ReservationRequestMessage)},
    { &GAS_handle_preference_change, NULL, 
      GNUNET_MESSAGE_TYPE_ATS_PREFERENCE_CHANGE, 0},
    {NULL, NULL, 0, 0}
  };
  GAS_addresses_init ();
  GNUNET_SERVER_disconnect_notify (server, 
				   &client_disconnect_handler,
                                   NULL);
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                NULL);
}


/**
 * The main function for the ats service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "ats",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-ats.c */
