/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/test_peer.c
 * @brief testcase for peer.c
 * @author Safey Mohammed
 */

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_peer_lib.h"

#define NUMBER_OF_PEERS 10

#define VERBOSE GNUNET_NO

/**
 * A list of Peer ID's to play with
 */
static struct GNUNET_PeerIdentity pidArr[NUMBER_OF_PEERS];


static void
generatePeerIdList ()
{
  int i;

  for (i = 0; i < NUMBER_OF_PEERS; i++)
  {
    GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK,
                                      &pidArr[i].hashPubKey);
#if VERBOSE
    printf ("Peer %d: %s\n", i, GNUNET_i2s (&pidArr[i]));
#endif
  }
}


static int
check ()
{
  int i;
  GNUNET_PEER_Id pid;
  struct GNUNET_PeerIdentity res;
  struct GNUNET_PeerIdentity zero;
  GNUNET_PEER_Id ids[] = { 1, 2, 3 };

  GNUNET_assert (0 == GNUNET_PEER_intern (NULL));
  /* Insert Peers into PeerEntry table and hashmap */
  for (i = 0; i < NUMBER_OF_PEERS; i++)
  {
    pid = GNUNET_PEER_intern (&pidArr[i]);
    if (pid != (i + 1))
    {
      FPRINTF (stderr, "%s",  "Unexpected Peer ID returned by intern function\n");
      return 1;
    }
  }

  /* Referencing the first 3 peers once again */
  for (i = 0; i < 3; i++)
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
  for (i = 1; i <= 3; i++)
    GNUNET_PEER_change_rc (i, 1);

  /* Removing the second Peer from the PeerEntry hash map */
  GNUNET_PEER_change_rc (2, -2);

  /* convert the pid of the first PeerEntry into that of the third */
  GNUNET_PEER_resolve (1, &res);
  GNUNET_assert (0 == memcmp (&res, &pidArr[0], sizeof (res)));

  /*
   * Attempt to convert pid = 0 (which is reserved)
   * into a peer identity object, the peer identity memory
   * is expected to be set to zero
   */
  memset (&zero, 0, sizeof (struct GNUNET_PeerIdentity));
  GNUNET_log_skip (1, GNUNET_YES);
  GNUNET_PEER_resolve (0, &res);
  GNUNET_assert (0 == memcmp (&res, &zero, sizeof (res)));

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
  int i;

  GNUNET_log_setup ("test-peer", "ERROR", NULL);
  for (i = 0; i < 1; i++)
  {
    generatePeerIdList ();
    if (0 != check ())
      return 1;
  }
  return 0;
}

/* end of test_peer.c */
