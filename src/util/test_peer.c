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
 * @file util/test_peer.c
 * @brief testcase for peer.c
 * @author Safey Mohammed
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>

#define NUMBER_OF_PEERS 10

/**
 * A list of Peer ID's to play with
 */
static struct GNUNET_PeerIdentity pidArr[NUMBER_OF_PEERS];


static void
generatePeerIdList ()
{
  for (unsigned int i = 0; i < NUMBER_OF_PEERS; i++)
  {
    gcry_randomize (&pidArr[i],
                    sizeof (struct GNUNET_PeerIdentity),
                    GCRY_STRONG_RANDOM);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer %u: %s\n",
                i,
                GNUNET_i2s (&pidArr[i]));
  }
}


static int
check ()
{
  GNUNET_PEER_Id pid;
  struct GNUNET_PeerIdentity res;
  GNUNET_PEER_Id ids[] = { 1, 2, 3 };

  GNUNET_assert (0 == GNUNET_PEER_intern (NULL));
  /* Insert Peers into PeerEntry table and hashmap */
  for (unsigned int i = 0; i < NUMBER_OF_PEERS; i++)
  {
    pid = GNUNET_PEER_intern (&pidArr[i]);
    if (pid != (i + 1))
    {
      FPRINTF (stderr, "%s",  "Unexpected Peer ID returned by intern function\n");
      return 1;
    }
  }

  /* Referencing the first 3 peers once again */
  for (unsigned int i = 0; i < 3; i++)
  {
    pid = GNUNET_PEER_intern (&pidArr[i]);
    if (pid != (i + 1))
    {
      FPRINTF (stderr, "%s",  "Unexpected Peer ID returned by intern function\n");
      return 1;
    }
  }

  /* Dereferencing the first 3 peers once [decrementing their reference count] */
  GNUNET_PEER_decrement_rcs (ids, 3);

  /* re-referencing the first 3 peers using the change_rc function */
  for (unsigned int i = 1; i <= 3; i++)
    GNUNET_PEER_change_rc (i, 1);

  /* Removing the second Peer from the PeerEntry hash map */
  GNUNET_PEER_change_rc (2, -2);

  /* convert the pid of the first PeerEntry into that of the third */
  GNUNET_PEER_resolve (1,
                       &res);
  GNUNET_assert (0 ==
                 GNUNET_memcmp (&res,
                                &pidArr[0]));

  /*
   * Attempt to convert pid = 0 (which is reserved)
   * into a peer identity object, the peer identity memory
   * is expected to be set to zero
   */
  GNUNET_log_skip (1, GNUNET_YES);
  GNUNET_PEER_resolve (0, &res);
  GNUNET_assert (0 ==
                 GNUNET_is_zero (&res));

  /* Removing peer entries 1 and 3 from table using the list decrement function */
  /* If count = 0, nothing should be done whatsoever */
  GNUNET_PEER_decrement_rcs (ids, 0);

  ids[1] = 3;
  GNUNET_PEER_decrement_rcs (ids, 2);
  GNUNET_PEER_decrement_rcs (ids, 2);

  return 0;
}


int
main ()
{
  GNUNET_log_setup ("test-peer",
                    "ERROR",
                    NULL);
  for (unsigned int i = 0; i < 1; i++)
  {
    generatePeerIdList ();
    if (0 != check ())
      return 1;
  }
  return 0;
}

/* end of test_peer.c */
