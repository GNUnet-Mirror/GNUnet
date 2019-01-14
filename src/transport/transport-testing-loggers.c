
/*
     This file is part of GNUnet.
     Copyright (C) 2016 GNUnet e.V.

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
 * @file transport-testing-loggers.c
 * @brief convenience functions for logging common events in tests
 * @author Christian Grothoff
 */
#include "transport-testing.h"


/**
 * Log a connect event.
 *
 * @param cls NULL
 * @param me peer that had the event
 * @param other peer that connected.
 */
void
GNUNET_TRANSPORT_TESTING_log_connect (void *cls,
                                      struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
                                      const struct GNUNET_PeerIdentity *other)
{
  char *ps;

  ps = GNUNET_strdup (GNUNET_i2s (&me->id));
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peer %s connected to %u (%s)!\n",
              GNUNET_i2s (other),
              me->no,
              ps);
  GNUNET_free (ps);
}



/**
 * Log a disconnect event.
 *
 * @param cls NULL
 * @param me peer that had the event
 * @param other peer that disconnected.
 */
void
GNUNET_TRANSPORT_TESTING_log_disconnect (void *cls,
                                         struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
                                         const struct GNUNET_PeerIdentity *other)
{
  char *ps;

  ps = GNUNET_strdup (GNUNET_i2s (&me->id));
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peer `%s' disconnected from %u (%s)!\n",
              GNUNET_i2s (other),
              me->no,
              ps);
  GNUNET_free (ps);
}

/* end of transport-testing-loggers.c */
