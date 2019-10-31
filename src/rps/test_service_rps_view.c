/*
     This file is part of GNUnet.
     Copyright (C)

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
 * @file rps/test_service_rps_view.c
 * @brief testcase for gnunet-service-rps_view.c
 */
#include <platform.h>
#include "gnunet-service-rps_view.h"

#define ABORT() { fprintf (stderr, "Error at %s:%d\n", __FILE__, __LINE__); \
                  View_destroy (view); return 1; }
#define CHECK(c) { if (! (c)) ABORT (); }


static int
check ()
{
  struct View *view;
  struct GNUNET_PeerIdentity k1;
  struct GNUNET_PeerIdentity k2;
  const struct GNUNET_PeerIdentity *array;
  unsigned int j;

  view = View_create (3);
  memset (&k1, 0, sizeof(k1));
  memset (&k2, 1, sizeof(k2));
  CHECK (GNUNET_NO == View_contains_peer (view, &k1));
  CHECK (GNUNET_NO == View_contains_peer (view, &k2));
  CHECK (GNUNET_NO == View_remove_peer (view, &k1));
  CHECK (GNUNET_NO == View_remove_peer (view, &k2));
  CHECK (NULL == View_get_peer_by_index (view, 0));
  CHECK (NULL == View_get_peer_by_index (view, 1));
  View_clear (view);  /* See if assertions trigger */
  CHECK (0 == View_size (view));

  CHECK (GNUNET_OK == View_put (view, &k1));
  CHECK (1 == View_size (view));
  CHECK (GNUNET_NO == View_put (view, &k1));
  CHECK (1 == View_size (view));
  CHECK (GNUNET_YES == View_contains_peer (view, &k1));
  CHECK (GNUNET_OK == View_remove_peer (view, &k1));
  CHECK (0 == View_size (view));
  CHECK (GNUNET_NO == View_contains_peer (view, &k1));
  CHECK (GNUNET_NO == View_contains_peer (view, &k2));

  CHECK (GNUNET_OK == View_put (view, &k1));
  CHECK (1 == View_size (view));
  for (j = 0; j < 16; j++)
  {
    CHECK (GNUNET_NO == View_put (view, &k1));
  }
  CHECK (1 == View_size (view));
  CHECK (GNUNET_OK == View_put (view, &k2));
  CHECK (2 == View_size (view));
  for (j = 0; j < 16; j++)
  {
    CHECK (GNUNET_NO == View_put (view, &k2));
  }
  CHECK (2 == View_size (view));

  /* iterate */
  for (j = 0; j < View_size (view); j++)
  {
    CHECK (NULL != View_get_peer_by_index (view, j));
  }
  CHECK ((0 == memcmp (View_get_peer_by_index (view, 0),
                       &k1, sizeof(k1))));
  CHECK ((0 == memcmp (View_get_peer_by_index (view, 1),
                       &k2, sizeof(k2))));
  CHECK (GNUNET_OK == View_remove_peer (view, &k1));
  CHECK (1 == View_size (view));
  CHECK (GNUNET_NO == View_contains_peer (view, &k1));
  CHECK (GNUNET_YES == View_contains_peer (view, &k2));
  CHECK (NULL != View_get_peer_by_index (view, 0));
  CHECK (NULL == View_get_peer_by_index (view, 1));

  View_clear (view);
  CHECK (0 == View_size (view));

  CHECK (GNUNET_OK == View_put (view, &k1));
  CHECK (1 == View_size (view));
  CHECK (GNUNET_YES == View_contains_peer (view, &k1));
  CHECK (GNUNET_OK == View_put (view, &k2));
  CHECK (2 == View_size (view));
  CHECK (GNUNET_YES == View_contains_peer (view, &k2));
  array = View_get_as_array (view);
  CHECK (0 == memcmp (&array[0], &k1, sizeof(k1)));
  CHECK (0 == memcmp (&array[1], &k2, sizeof(k2)));
  View_clear (view);
  CHECK (0 == View_size (view));

  /*View_change_len () */
  CHECK (GNUNET_OK == View_put (view, &k1));
  CHECK (GNUNET_OK == View_put (view, &k2));
  CHECK (2 == View_size (view));
  View_change_len (view, 4);
  CHECK (2 == View_size (view));
  CHECK (GNUNET_YES == View_contains_peer (view, &k1));
  CHECK (GNUNET_YES == View_contains_peer (view, &k2));
  array = View_get_as_array (view);
  CHECK (0 == memcmp (&array[0], &k1, sizeof(k1)));
  CHECK (0 == memcmp (&array[1], &k2, sizeof(k2)));
  View_change_len (view, 1);
  CHECK (1 == View_size (view));
  CHECK (GNUNET_YES == View_contains_peer (view, &k1));
  CHECK (GNUNET_NO == View_contains_peer (view, &k2));
  array = View_get_as_array (view);
  CHECK (0 == memcmp (&array[0], &k1, sizeof(k1)));
  View_clear (view);
  CHECK (0 == View_size (view));

  View_destroy (view);

  return 0;
}


int
main ()
{
  GNUNET_log_setup ("test_service_rps_peers",
                    "WARNING",
                    NULL);
  return check ();
}


/* end of test_service_rps_view.c */
