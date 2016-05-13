/*
     This file is part of GNUnet.
     Copyright (C)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file rps/test_service_rps_peers.c
 * @brief testcase for gnunet-service-rps_peers.c
 */
#include <platform.h>
#include "gnunet-service-rps_peers.h"

#define ABORT() { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); Peers_terminate (); return 1; }
#define CHECK(c) { if (! (c)) ABORT(); }


/**
 * @brief Dummy implementation of #PeerOp (Operation on peer)
 *
 * @param cls closure
 * @param peer peer
 */
void peer_op (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert (NULL != peer);
}

/**
 * @brief Function that is called on a peer for later execution
 *
 * @param cls closure
 * @param peer peer to execute function upon
 */
void
peer_op (void *cls, const struct GNUNET_PeerIdentity *peer);


static int
check ()
{
  struct GNUNET_PeerIdentity k1;
  struct GNUNET_PeerIdentity own_id;
  
  memset (&k1, 0, sizeof (k1));
  memset (&own_id, 1, sizeof (own_id));

  /* Do nothing */
  Peers_initialise ("", NULL, &own_id);
  Peers_terminate ();


  /* Create peer */
  Peers_initialise ("", NULL, &own_id);
  CHECK (GNUNET_YES == Peers_insert_peer (&k1));
  Peers_terminate ();


  /* Create peer */
  Peers_initialise ("", NULL, &own_id);
  CHECK (GNUNET_YES == Peers_insert_peer (&k1));
  CHECK (GNUNET_YES == Peers_remove_peer (&k1));
  Peers_terminate ();


  /* Insertion and Removal */
  Peers_initialise ("", NULL, &own_id);
  CHECK (GNUNET_NO  == Peers_check_peer_known (&k1));

  CHECK (GNUNET_YES == Peers_insert_peer (&k1));
  CHECK (GNUNET_NO  == Peers_insert_peer (&k1));
  CHECK (GNUNET_YES == Peers_check_peer_known (&k1));

  CHECK (GNUNET_YES == Peers_remove_peer (&k1));
  CHECK (GNUNET_NO  == Peers_remove_peer (&k1));
  CHECK (GNUNET_NO  == Peers_check_peer_known (&k1));


  /* Flags */
  Peers_insert_peer (&k1);

  CHECK (GNUNET_NO == Peers_check_peer_flag (&k1, Peers_PULL_REPLY_PENDING));
  CHECK (GNUNET_NO == Peers_check_peer_flag (&k1, Peers_ONLINE));
  CHECK (GNUNET_NO == Peers_check_peer_flag (&k1, Peers_TO_DESTROY));

  CHECK (GNUNET_NO  == Peers_check_peer_flag (&k1, Peers_ONLINE));

  Peers_set_peer_flag (&k1, Peers_ONLINE);
  CHECK (GNUNET_YES == Peers_check_peer_flag (&k1, Peers_ONLINE));
  CHECK (GNUNET_NO  == Peers_check_peer_flag (&k1, Peers_TO_DESTROY));
  CHECK (GNUNET_YES == Peers_check_peer_flag (&k1, Peers_ONLINE));
  CHECK (GNUNET_NO  == Peers_check_peer_flag (&k1, Peers_TO_DESTROY));

  /* Check send intention */
  CHECK (GNUNET_NO == Peers_check_peer_send_intention (&k1));

  /* Check existence of sending channel */
  CHECK (GNUNET_NO == Peers_check_sending_channel_exists (&k1));

  /* Check role of channels */
  CHECK (GNUNET_YES == Peers_check_channel_role (&k1,
                                                 NULL,
                                                 Peers_CHANNEL_ROLE_SENDING));
  CHECK (GNUNET_YES == Peers_check_channel_role (&k1,
                                                 NULL,
                                                 Peers_CHANNEL_ROLE_RECEIVING));

  CHECK (GNUNET_YES == Peers_schedule_operation (&k1, peer_op));

  Peers_terminate ();
  return 0;
}


int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test_service_rps_peers", 
		    "WARNING",
		    NULL);
  return check ();
}

/* end of test_service_rps_peers.c */
