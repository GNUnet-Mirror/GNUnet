/*
   This file is part of GNUnet.
   Copyright (C) 2009 GNUnet e.V.

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
 * @file auction/gnunet-service-auction.c
 * @brief service for executing auctions
 * @author Markus Teich
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#include "auction.h"

/**
 * Check AUCTION CREATE messages from the client.
 *
 * @param cls the client we received this message from
 * @param msg the actual message received
 * @return #GNUNET_OK (always)
 */
static int
check_create (void *cls, const struct GNUNET_AUCTION_ClientCreateMessage *msg)
{
	/* always well-formed due to arbitrary length description */
	return GNUNET_OK;
}


/**
 * Handler for CREATE messages.
 *
 * @param cls the client we received this message from
 * @param msg the actual message received
 */
static void
handle_create (void *cls, const struct GNUNET_AUCTION_ClientCreateMessage *msg)
{
	struct GNUNET_SERVICE_Client *client = cls;
//	struct GNUNET_MQ_Handle *mq;
//	struct GNUNET_MQ_Envelope *env;
//	struct GNUNET_AUCTION_blabla em;
	uint16_t size;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	            "Received CREATE message from client\n");

	size = ntohs (msg->header.size);

	/**TODO: create auction and return auction object */
//	mq = GNUNET_SERVICE_client_get_mq (client);
//	setup_info_message (&em);
//	env = GNUNET_MQ_msg_copy (&em.header);
//	GNUNET_MQ_send (mq, env);

	GNUNET_SERVICE_client_continue (client);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
cleanup_task (void *cls)
{
	/* FIXME: do clean up here */
}


/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return @a c
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *c,
                   struct GNUNET_MQ_Handle *mq)
{
	return c;
}


/**
 * Callback called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls should be equal to @a c
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *c,
                      void *internal_cls)
{
	GNUNET_assert (c == internal_cls);
}


/**
 * Process auction requests.
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
	/* FIXME: do setup here */
	GNUNET_SCHEDULER_add_shutdown (&cleanup_task, NULL);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("auction",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (create,
                        GNUNET_MESSAGE_TYPE_AUCTION_CLIENT_CREATE,
                        struct GNUNET_AUCTION_ClientCreateMessage,
                        NULL),
 GNUNET_MQ_handler_end ())


/* end of gnunet-service-auction.c */
