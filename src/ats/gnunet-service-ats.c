/*
     This file is part of GNUnet.
     Copyright (C) 2011 GNUnet e.V.

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
 * @file ats/gnunet-service-ats.c
 * @brief ats service
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-ats.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_connectivity.h"
#include "gnunet-service-ats_normalization.h"
#include "gnunet-service-ats_performance.h"
#include "gnunet-service-ats_preferences.h"
#include "gnunet-service-ats_scheduling.h"
#include "gnunet-service-ats_reservations.h"
#include "gnunet-service-ats_plugins.h"
#include "ats.h"

/**
 * Handle for statistics.
 */
struct GNUNET_STATISTICS_Handle *GSA_stats;


/**
 * We have received a `struct ClientStartMessage` from a client.  Find
 * out which type of client it is and notify the respective subsystem.
 *
 * @param cls handle to the client
 * @param msg the start message
 */
static void
handle_ats_start (void *cls,
                  const struct ClientStartMessage *msg)
{
  struct GNUNET_SERVICE_Client *client = cls;
  enum StartFlag flag;

  flag = ntohl (msg->start_flag);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ATS_START (%d) message\n",
              (int) flag);
  switch (flag)
  {
  case START_FLAG_SCHEDULING:
    if (GNUNET_OK !=
	GAS_scheduling_add_client (client))
    {
      GNUNET_SERVICE_client_drop (client);
      return;
    }
    break;
  case START_FLAG_PERFORMANCE_WITH_PIC:
    GAS_performance_add_client (client,
                                flag);
    break;
  case START_FLAG_PERFORMANCE_NO_PIC:
    GAS_performance_add_client (client,
                                flag);
    break;
  case START_FLAG_CONNECTION_SUGGESTION:
    /* This client won't receive messages from us, no need to 'add' */
    break;
  default:
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  GNUNET_SERVICE_client_continue (client);
}



/**
 * Handle 'reservation request' messages from clients.
 *
 * @param cls client that sent the request
 * @param message the request message
 */
static void
handle_reservation_request (void *cls,
			    const struct ReservationRequestMessage *message)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GAS_handle_reservation_request (client,
				  message);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Check 'preference feedback' message is well-formed
 *
 * @param cls client that sent the request
 * @param message the request message
 * @return #GNUNET_OK if @a message is well-formed
 */
static int
check_feedback (void *cls,
		const struct FeedbackPreferenceMessage *message)
{
  uint16_t msize;
  uint32_t nump;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received PREFERENCE_FEEDBACK message\n");
  msize = ntohs (message->header.size);
  nump = ntohl (message->num_feedback);
  if (msize !=
      sizeof (struct FeedbackPreferenceMessage) +
      nump * sizeof (struct PreferenceInformation))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle 'preference feedback' messages from clients.
 *
 * @param cls client that sent the request
 * @param msg the request message
 */
static void
handle_feedback (void *cls,
		 const struct FeedbackPreferenceMessage *msg)
{
  struct GNUNET_SERVICE_Client *client = cls;
  const struct PreferenceInformation *pi;
  uint32_t nump;

  nump = ntohl (msg->num_feedback);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_multipeermap_contains (GSA_addresses,
					      &msg->peer))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
	       "Received PREFERENCE FEEDBACK for unknown peer `%s'\n",
	       GNUNET_i2s (&msg->peer));
    GNUNET_SERVICE_client_continue (client);
    return;
  }

  GNUNET_STATISTICS_update (GSA_stats,
                            "# preference feedbacks requests processed",
                            1,
                            GNUNET_NO);
  pi = (const struct PreferenceInformation *) &msg[1];
  for (uint32_t i = 0; i < nump; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Received PREFERENCE FEEDBACK for peer `%s'\n",
		GNUNET_i2s (&msg->peer));
    GAS_plugin_notify_feedback (client,
				&msg->peer,
				GNUNET_TIME_relative_ntoh (msg->scope),
				(enum GNUNET_ATS_PreferenceKind) ntohl (pi[i].preference_kind),
				pi[i].preference_value);
  }
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Handle 'request address list' messages from clients.
 *
 * @param cls client that sent the request
 * @param message the request message
 */
static void
handle_request_address_list (void *cls,
			     const struct AddressListRequestMessage *message)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GAS_handle_request_address_list (client,
				   message);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Handle 'request address' messages from clients.
 *
 * @param cls client that sent the request
 * @param message the request message
 */
static void
handle_request_address (void *cls,
			const struct RequestAddressMessage * message)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GAS_handle_request_address (client,
			      message);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Cancel 'request address' messages from clients.
 *
 * @param cls client that sent the request
 * @param message the request message
 */
static void
handle_request_address_cancel (void *cls,
			       const struct RequestAddressMessage *message)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GAS_handle_request_address_cancel (client,
				     message);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Handle 'address add' messages from clients.
 *
 * @param cls client that sent the request
 * @param m the request message
 */
static int
check_address_add (void *cls,
		   const struct AddressAddMessage *m)
{
  const char *address;
  const char *plugin_name;
  uint16_t address_length;
  uint16_t plugin_name_length;
  uint16_t size;

  size = ntohs (m->header.size);
  address_length = ntohs (m->address_length);
  plugin_name_length = ntohs (m->plugin_name_length);
  address = (const char *) &m[1];
  if (plugin_name_length != 0)
    plugin_name = &address[address_length];
  else
    plugin_name = "";

  if ( (address_length + plugin_name_length +
	sizeof (struct AddressAddMessage) != size) ||
       ( (plugin_name_length > 0) &&
	 (plugin_name[plugin_name_length - 1] != '\0') ) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle 'address add' messages from clients.
 *
 * @param cls client that sent the request
 * @param message the request message
 */
static void
handle_address_add (void *cls,
		    const struct AddressAddMessage *message)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GAS_handle_address_add (message);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Handle 'address update' messages from clients.
 *
 * @param cls client that sent the request
 * @param message the request message
 */
static void
handle_address_update (void *cls,
		       const struct AddressUpdateMessage *message)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GAS_handle_address_update (message);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Handle 'address destroyed' messages from clients.
 *
 * @param cls client that sent the request
 * @param message the request message
 */
static void
handle_address_destroyed (void *cls,
			  const struct AddressDestroyedMessage *message)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GAS_handle_address_destroyed (message);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Check that 'change preference' message is well-formed.
 *
 * @param cls client that sent the request
 * @param message the request message
 * @return #GNUNET_OK if @a message is well-formed
 */
static int
check_preference_change (void *cls,
			 const struct ChangePreferenceMessage *message)
{
  uint16_t msize;
  uint32_t nump;

  msize = ntohs (message->header.size);
  nump = ntohl (message->num_preferences);
  if ( (msize !=
        sizeof (struct ChangePreferenceMessage) +
        nump * sizeof (struct PreferenceInformation)) ||
       (UINT16_MAX / sizeof (struct PreferenceInformation) < nump) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle 'change preference' messages from clients.
 *
 * @param cls client that sent the request
 * @param message the request message
 */
static void
handle_preference_change (void *cls,
			  const struct ChangePreferenceMessage *message)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GAS_handle_preference_change (client,
				message);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * A client connected to us. Setup the local client
 * record.
 *
 * @param cls unused
 * @param client handle of the client
 * @param mq message queue to talk to @a client
 * @return @a client
 */
static void *
client_connect_cb (void *cls,
		   struct GNUNET_SERVICE_Client *client,
		   struct GNUNET_MQ_Handle *mq)
{
  return client;
}


/**
 * A client disconnected from us.  Tear down the local client
 * record.
 *
 * @param cls unused
 * @param client handle of the client
 * @param app_ctx
 */
static void
client_disconnect_cb (void *cls,
		      struct GNUNET_SERVICE_Client *client,
		      void *app_ctx)
{
  if (NULL == client)
    return;
  GAS_scheduling_remove_client (client);
  GAS_connectivity_remove_client (client);
  GAS_preference_client_disconnect (client);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
cleanup_task (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "ATS shutdown initiated\n");
  GAS_connectivity_done ();
  GAS_addresses_done ();
  GAS_plugin_done ();
  GAS_normalization_stop ();
  GAS_performance_done ();
  GAS_preference_done ();
  GAS_reservations_done ();
  if (NULL != GSA_stats)
  {
    GNUNET_STATISTICS_destroy (GSA_stats, GNUNET_NO);
    GSA_stats = NULL;
  }
}


/**
 * Process template requests.
 *
 * @param cls closure
 * @param cfg configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_SERVICE_Handle *service)
{
  GSA_stats = GNUNET_STATISTICS_create ("ats",
					cfg);
  GAS_reservations_init ();
  GAS_connectivity_init ();
  GAS_preference_init ();
  GAS_normalization_start ();
  GAS_addresses_init ();
  if (GNUNET_OK !=
      GAS_plugin_init (cfg))
  {
    GNUNET_break (0);
    GAS_addresses_done ();
    GAS_normalization_stop ();
    GAS_reservations_done ();
    GAS_connectivity_done ();
    GAS_preference_done ();
    if (NULL != GSA_stats)
    {
      GNUNET_STATISTICS_destroy (GSA_stats,
				 GNUNET_NO);
      GSA_stats = NULL;
    }
    return;
  }
  GAS_performance_init ();
  GNUNET_SCHEDULER_add_shutdown (&cleanup_task,
				 NULL);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("ats",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_fixed_size (ats_start,
			  GNUNET_MESSAGE_TYPE_ATS_START,
			  struct ClientStartMessage,
			  NULL),
 GNUNET_MQ_hd_fixed_size (request_address,
			  GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS,
			  struct RequestAddressMessage,
			  NULL),
 GNUNET_MQ_hd_fixed_size (request_address_cancel, 
			  GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS_CANCEL,
			  struct RequestAddressMessage,
			  NULL),
 GNUNET_MQ_hd_fixed_size (request_address_list, 
			  GNUNET_MESSAGE_TYPE_ATS_ADDRESSLIST_REQUEST,
			  struct AddressListRequestMessage,
			  NULL),
 GNUNET_MQ_hd_var_size (address_add, 
			GNUNET_MESSAGE_TYPE_ATS_ADDRESS_ADD,
			struct AddressAddMessage,
			NULL),
 GNUNET_MQ_hd_fixed_size (address_update, 
			  GNUNET_MESSAGE_TYPE_ATS_ADDRESS_UPDATE,
			  struct AddressUpdateMessage,
			  NULL),
 GNUNET_MQ_hd_fixed_size (address_destroyed, 
			  GNUNET_MESSAGE_TYPE_ATS_ADDRESS_DESTROYED,
			  struct AddressDestroyedMessage,
			  NULL),
 GNUNET_MQ_hd_fixed_size (reservation_request, 
			  GNUNET_MESSAGE_TYPE_ATS_RESERVATION_REQUEST,
			  struct ReservationRequestMessage,
			  NULL),
 GNUNET_MQ_hd_var_size (preference_change, 
			GNUNET_MESSAGE_TYPE_ATS_PREFERENCE_CHANGE,
			struct ChangePreferenceMessage,
			NULL),
 GNUNET_MQ_hd_var_size (feedback, 
			GNUNET_MESSAGE_TYPE_ATS_PREFERENCE_FEEDBACK,
			struct FeedbackPreferenceMessage,
			NULL),
 GNUNET_MQ_handler_end ());


/* end of gnunet-service-ats.c */
