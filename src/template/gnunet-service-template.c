/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
 * @file template/gnunet-service-template.c
 * @brief program that does template
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"


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
  /* FIXME: do setup here */
  GNUNET_SCHEDULER_add_shutdown (&cleanup_task, NULL);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN ("template",
                     GNUNET_SERVICE_OPTION_NONE,
                     &run,
                     &client_connect_cb,
                     &client_disconnect_cb,
                     NULL,
                     GNUNET_MQ_handler_end ());


/* end of gnunet-service-template.c */
