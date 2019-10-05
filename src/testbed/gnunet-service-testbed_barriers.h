/*
   This file is part of GNUnet.
   Copyright (C) 2008--2013 GNUnet e.V.

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
GST_barriers_destroy (void);


/**
 * Check #GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_INIT messages.
 *
 * @param cls identification of the client
 * @param msg the actual message
 * @return #GNUNET_OK if @a msg is well-formed
 */
int
check_barrier_init (void *cls,
                    const struct GNUNET_TESTBED_BarrierInit *msg);


/**
 * Message handler for #GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_INIT messages.  This
 * message should always come from a parent controller or the testbed API if we
 * are the root controller.
 *
 * This handler is queued in the main service and will handle the messages sent
 * either from the testbed driver or from a high level controller
 *
 * @param cls identification of the client
 * @param msg the actual message
 */
void
handle_barrier_init (void *cls,
                     const struct GNUNET_TESTBED_BarrierInit *msg);


/**
 * Check #GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_CANCEL messages.
 *
 * @param cls identification of the client
 * @param msg the actual message
 * @return #GNUNET_OK if @a msg is well-formed
 */
int
check_barrier_cancel (void *cls,
                      const struct GNUNET_TESTBED_BarrierCancel *msg);


/**
 * Message handler for #GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_CANCEL messages.  This
 * message should always come from a parent controller or the testbed API if we
 * are the root controller.
 *
 * This handler is queued in the main service and will handle the messages sent
 * either from the testbed driver or from a high level controller
 *
 * @param cls identification of the client
 * @param msg the actual message
 */
void
handle_barrier_cancel (void *cls,
                       const struct GNUNET_TESTBED_BarrierCancel *msg);


/**
 * Check #GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_STATUS messages.
 *
 * @param cls identification of the client
 * @param msg the actual message
 * @return #GNUNET_OK if @a msg is well-formed
 */
int
check_barrier_status (void *cls,
                      const struct GNUNET_TESTBED_BarrierStatusMsg *msg);


/**
 * Message handler for #GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_STATUS messages.
 * This handler is queued in the main service and will handle the messages sent
 * either from the testbed driver or from a high level controller
 *
 * @param cls identification of the client
 * @param msg the actual message
 */
void
handle_barrier_status (void *cls,
                       const struct GNUNET_TESTBED_BarrierStatusMsg *msg);

#endif  /* GNUNET_SERVER_TESTBED_BARRIERS_H_ */

/* end of gnunet-service-testbed_barriers.h */
