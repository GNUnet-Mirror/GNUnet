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

#define ABORT() { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); if (NULL != c_m) CustomPeerMap_destroy(c_m); return 1; }
#define CHECK(c) { if (! (c)) ABORT(); }


static int
check ()
{

  struct CustomPeerMap *c_m;
  struct GNUNET_PeerIdentity k1;
  struct GNUNET_PeerIdentity k2;
  int j;

  CHECK (NULL != (c_m = CustomPeerMap_create (4)));
  memset (&k1, 0, sizeof (k1));
  memset (&k2, 1, sizeof (k2));
  CHECK (GNUNET_NO == CustomPeerMap_contains_peer (c_m, &k1));
  CHECK (GNUNET_NO == CustomPeerMap_contains_peer (c_m, &k2));
  CHECK (GNUNET_NO == CustomPeerMap_remove_peer (c_m, &k1));
  CHECK (GNUNET_NO == CustomPeerMap_remove_peer (c_m, &k2));
  CHECK (GNUNET_NO == CustomPeerMap_remove_peer_by_index (c_m, 0));
  CHECK (GNUNET_NO == CustomPeerMap_remove_peer_by_index (c_m, 0));
  CHECK (GNUNET_NO == CustomPeerMap_remove_peer_by_index (c_m, 1));
  CHECK (GNUNET_NO == CustomPeerMap_remove_peer_by_index (c_m, 1));
  CHECK (NULL == CustomPeerMap_get_peer_by_index (c_m, 0));
  CHECK (NULL == CustomPeerMap_get_peer_by_index (c_m, 0));
  CHECK (NULL == CustomPeerMap_get_peer_by_index (c_m, 1));
  CHECK (NULL == CustomPeerMap_get_peer_by_index (c_m, 1));
  CustomPeerMap_clear (c_m); /* See if assertions trigger */
  CHECK (0 == CustomPeerMap_size (c_m));

  CHECK (GNUNET_OK == CustomPeerMap_put (c_m, &k1));
  CHECK (1 == CustomPeerMap_size (c_m));
  CHECK (GNUNET_NO == CustomPeerMap_put (c_m, &k1));
  CHECK (1 == CustomPeerMap_size (c_m));
  CHECK (GNUNET_YES == CustomPeerMap_contains_peer (c_m, &k1));
  CHECK (GNUNET_OK == CustomPeerMap_remove_peer (c_m, &k1));
  CHECK (0 == CustomPeerMap_size (c_m));
  CHECK (GNUNET_NO == CustomPeerMap_contains_peer (c_m, &k1));
  CHECK (GNUNET_NO == CustomPeerMap_contains_peer (c_m, &k2));

  CHECK (GNUNET_OK == CustomPeerMap_put (c_m, &k1));
  CHECK (1 == CustomPeerMap_size (c_m));
  for (j = 0; j < 16; j++)
  {
    CHECK (GNUNET_NO == CustomPeerMap_put (c_m, &k1));
  }
  CHECK (1 == CustomPeerMap_size (c_m));
  CHECK (GNUNET_OK == CustomPeerMap_put (c_m, &k2));
  CHECK (2 == CustomPeerMap_size (c_m));
  for (j = 0; j < 16; j++)
  {
    CHECK (GNUNET_NO == CustomPeerMap_put (c_m, &k2));
  }
  CHECK (2 == CustomPeerMap_size (c_m));

  /* iterate */
  for (j = 0; j < CustomPeerMap_size (c_m); j++)
  {
    CHECK (NULL != CustomPeerMap_get_peer_by_index (c_m, j));
  }
  CHECK ((0 == memcmp (CustomPeerMap_get_peer_by_index (c_m, 0),
                       &k1, sizeof (k1))));
  CHECK ((0 == memcmp (CustomPeerMap_get_peer_by_index (c_m, 1),
                       &k2, sizeof (k2))));
  CHECK (GNUNET_OK == CustomPeerMap_remove_peer (c_m, &k1));
  CHECK (1 == CustomPeerMap_size (c_m));
  CHECK (GNUNET_NO == CustomPeerMap_contains_peer (c_m, &k1));
  CHECK (GNUNET_YES == CustomPeerMap_contains_peer (c_m, &k2));
  CHECK (NULL != CustomPeerMap_get_peer_by_index (c_m, 0));

  CustomPeerMap_clear (c_m);
  CHECK (0 == CustomPeerMap_size (c_m));

  CHECK (GNUNET_OK == CustomPeerMap_put (c_m, &k1));
  CHECK (1 == CustomPeerMap_size (c_m));
  CHECK (GNUNET_OK == CustomPeerMap_put (c_m, &k2));
  CHECK (2 == CustomPeerMap_size (c_m));
  CustomPeerMap_clear (c_m);
  CHECK (0 == CustomPeerMap_size (c_m));

  CustomPeerMap_destroy (c_m);

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

/* end of test_rps_api.c */
