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
 * @file testbed/testbed_api_barriers.h
 * @brief interface for barriers API function that are used internally (not
 *   exposed as user API)
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "gnunet_testbed_service.h"


/**
 * Initialise a barrier and call the given callback when the required percentage
 * of peers (quorum) reach the barrier OR upon error.
 *
 * @param controller the handle to the controller
 * @param name identification name of the barrier
 * @param quorum the percentage of peers that is required to reach the barrier.
 *   Peers signal reaching a barrier by calling
 *   GNUNET_TESTBED_barrier_reached().
 * @param cb the callback to call when the barrier is reached or upon error.
 *   Cannot be NULL.
 * @param cls closure for the above callback
 * @param echo GNUNET_YES to echo the barrier crossed status message back to the
 *   controller
 * @return barrier handle; NULL upon error
 */
struct GNUNET_TESTBED_Barrier *
GNUNET_TESTBED_barrier_init_ (struct GNUNET_TESTBED_Controller *controller,
                              const char *name,
                              unsigned int quorum,
                              GNUNET_TESTBED_barrier_status_cb cb, void *cls,
                              int echo);
