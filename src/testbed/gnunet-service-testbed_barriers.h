/*
  This file is part of GNUnet.
  Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-service-testbed_barriers.h
 * @brief Interface for the barrier initialisation handler routine
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#ifndef GNUNET_SERVER_TESTBED_BARRIERS_H_
#define GNUNET_SERVER_TESTBED_BARRIERS_H_

/**
 * Function to initialise barrriers component
 *
 * @param cfg the configuration to use for initialisation
 */
void
GST_barriers_init (struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Function to stop the barrier service
 */
void
GST_barriers_destroy ();


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_INIT messages.  This
 * message should always come from a parent controller or the testbed API if we
 * are the root controller.
 *
 * This handler is queued in the main service and will handle the messages sent
 * either from the testbed driver or from a high level controller
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_barrier_init (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message);


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_CANCEL messages.  This
 * message should always come from a parent controller or the testbed API if we
 * are the root controller.
 *
 * This handler is queued in the main service and will handle the messages sent
 * either from the testbed driver or from a high level controller
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_barrier_cancel (void *cls, struct GNUNET_SERVER_Client *client,
                           const struct GNUNET_MessageHeader *message);


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_STATUS messages.
 * This handler is queued in the main service and will handle the messages sent
 * either from the testbed driver or from a high level controller
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_barrier_status (void *cls, struct GNUNET_SERVER_Client *client,
                           const struct GNUNET_MessageHeader *message);

#endif  /* GNUNET_SERVER_TESTBED_BARRIERS_H_ */

/* end of gnunet-service-testbed_barriers.h */
