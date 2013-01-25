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
 * @file testbed/testbed_api_statistics.c
 * @brief high-level statistics function
 * @author Christian Grothoff
 * @author Sree Harsha Totakura
 */
#include "platform.h"
#include "gnunet_testbed_service.h"


/**
 * Convenience method that iterates over all (running) peers
 * and retrieves all statistics from each peer.
 *
 * @param num_peers number of peers to iterate over
 * @param peers array of peers to iterate over
 * @param proc processing function for each statistic retrieved
 * @param cont continuation to call once call is completed(?)
 * @param cls closure to pass to proc and cont
 * @return operation handle to cancel the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_get_statistics (unsigned int num_peers,
                               struct GNUNET_TESTBED_Peer **peers,
                               GNUNET_TESTBED_StatisticsIterator proc,
                               GNUNET_TESTBED_OperationCompletionCallback cont,
                               void *cls)
{
  // FIXME: not implemented, but clients will kind-of work if we do this:
  GNUNET_break (0);
  cont (cls, NULL, "not implemented");
  return NULL;
}


/* end of testbed_api_statistics.c */
