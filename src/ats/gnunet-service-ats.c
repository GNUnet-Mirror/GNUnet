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
// #include "gnunet-service-ats_performance.h"
#include "ats.h"

struct ATS_Address
{
  struct GNUNET_PeerIdentity peer;

  size_t addr_len;

  uint32_t session_id;

  uint32_t ats_count;

  void * addr;

  char * plugin;

  struct GNUNET_TRANSPORT_ATS_Information * ats;
};

static struct GNUNET_CONTAINER_MultiHashMap * addresses;



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


struct CompareAddressContext
{
  struct ATS_Address * search;
  struct ATS_Address * result;
};

int compare_address_it (void *cls,
               const GNUNET_HashCode * key,
               void *value)
{
  struct CompareAddressContext * cac = cls;
  struct ATS_Address * aa = (struct ATS_Address *) value;
  if (0 == strcmp(aa->plugin, cac->search->plugin))
  {
    if ((aa->addr_len == cac->search->addr_len) &&
        (0 == memcmp (aa->addr, cac->search->addr, aa->addr_len)))
      cac->result = aa;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


static int 
free_address_it (void *cls,
		 const GNUNET_HashCode * key,
		 void *value)
{
  struct ATS_Address * aa = cls;
  GNUNET_free (aa);
  return GNUNET_OK;
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
  GNUNET_CONTAINER_multihashmap_iterate (addresses, &free_address_it, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (addresses);
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
  addresses = GNUNET_CONTAINER_multihashmap_create(128);
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
