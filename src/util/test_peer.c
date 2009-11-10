/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
/*#define DEBUG*/

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
#ifdef DEBUG
      printf ("Peer %d: %s\n", i, GNUNET_i2s (&pidArr[i]));
#endif
    }
}


static int
check ()
{
  int i;
  GNUNET_PEER_Id pid;

  /* Insert Peers into PeerEntry table and hashmap */
  for (i = 0; i < NUMBER_OF_PEERS; i++)
    {
      pid = GNUNET_PEER_intern (&pidArr[i]);
      if (pid != (i + 1))
        {
          fprintf (stderr,
                   "Unexpected Peer ID returned by intern function \n");
          return 1;
        }
    }

  /* Referencing the first 3 peers once again */
  for (i = 0; i < 3; i++)
    {
      pid = GNUNET_PEER_intern (&pidArr[i]);
      if (pid != (i + 1))
        {
          fprintf (stderr,
                   "Unexpcted Peer ID returned by intern function \n");
          return 1;
        }
    }

  /* Dereferencing the first 3 peers once [decrementing their reference count] */
  {
    GNUNET_PEER_Id ids[] = { 1, 2, 3 };
    GNUNET_PEER_decrement_rcs (ids, 3);
  }

  /* re-referencing the first 3 peers using the change_rc function */
  for (i = 0; i < 3; i++)
    {
      GNUNET_PEER_change_rc (i, 1);
    }

  /* Removing the second Peer from the PeerEntry hash map */
  GNUNET_PEER_change_rc (2, -2);

  /* convert the pid of the first PeerEntry into that of the third */
  GNUNET_PEER_resolve (1, &pidArr[3]);

  return 0;
}


int
main ()
{
  GNUNET_log_setup ("test-peer", "ERROR", NULL);
  generatePeerIdList ();
  return check ();
}

/* end of test_peer.c */
