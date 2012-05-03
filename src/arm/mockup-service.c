/*
     This file is part of GNUnet.
     (C) 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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

#include <stdlib.h>
#include "platform.h"
#include "gnunet_disk_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_strings_lib.h"
#include "gnunet_time_lib.h"


/**
 * Handler for SHUTDOWN message.
 *
 * @param cls closure (refers to service)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_shutdown (void *cls, struct GNUNET_SERVER_Client *client,
                 const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Initiating shutdown as requested by client.\n"));
  GNUNET_SERVER_client_persist_ (client);
  GNUNET_SCHEDULER_shutdown ();
}


static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_shutdown, NULL, GNUNET_MESSAGE_TYPE_ARM_SHUTDOWN,
     sizeof (struct GNUNET_MessageHeader)},
    {NULL, NULL, 0, 0}
  };
  /* process client requests */
  GNUNET_SERVER_add_handlers (server, handlers);
}


int
main (int argc, char *const *argv)
{
  int ret;

  ret =
      (GNUNET_OK ==
       GNUNET_SERVICE_run (argc, argv, "do-nothing", GNUNET_SERVICE_OPTION_NONE,
                           &run, NULL)) ? 0 : 1;
  return ret;
}
