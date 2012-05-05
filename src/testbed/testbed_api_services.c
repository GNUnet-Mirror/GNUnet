/*
      This file is part of GNUnet
      (C) 2008--2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_services.c
 * @brief convenience functions for accessing services
 * @author Christian Grothoff
 */
#include "platform.h"
#include "testbed_api_peers.h"


/**
 * Connect to a service offered by the given peer.  Will ensure that
 * the request is queued to not overwhelm our ability to create and
 * maintain connections with other systems.  The actual service
 * handle is then returned via the 'op_result' member in the event
 * callback.  The 'ca' callback is used to create the connection
 * when the time is right; the 'da' callback will be used to 
 * destroy the connection (upon 'GNUNET_TESTBED_operation_done').
 * 'GNUNET_TESTBED_operation_cancel' can be used to abort this
 * operation until the event callback has been called.
 *
 * @param op_cls closure to pass in operation event
 * @param peer peer that runs the service
 * @param service_name name of the service to connect to
 * @param ca helper function to establish the connection
 * @param da helper function to close the connection
 * @param cada_cls closure for ca and da
 * @return handle for the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_service_connect (void *op_cls,
				struct GNUNET_TESTBED_Peer *peer,
				const char *service_name,
				GNUNET_TESTBED_ConnectAdapter ca,
				GNUNET_TESTBED_DisconnectAdapter da,
				void *cada_cls)
{
  GNUNET_break (0);
  return NULL;
}

/* end of testbed_api_services.c */
