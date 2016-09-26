/*
     This file is part of GNUnet.
     Copyright (C) 2007, 2008, 2009, 2016 GNUnet e.V.

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

#include <stdlib.h>
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"


static int special_ret = 0;

/**
 * Handler for STOP message.
 *
 * @param cls client identification of the client
 * @param message the actual message
 */
static void
handle_stop (void *cls,
             const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Initiating shutdown as requested by client.\n"));
  GNUNET_SERVICE_client_persist (client);
  GNUNET_SCHEDULER_shutdown ();
  /* ARM won't exponentially increase restart delay if we
   * terminate normally. This changes the return code.
   */
  special_ret = 1;
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


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_SERVICE_Handle *service)
{
  /* nothing to do */
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("do-nothing",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_fixed_size (stop,
			  GNUNET_MESSAGE_TYPE_ARM_STOP,
			  struct GNUNET_MessageHeader,
			  NULL),
 GNUNET_MQ_handler_end ());


/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((destructor))
GNUNET_mockup_done ()
{
  _exit (special_ret);
}
