/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @file util/test_container_multihashmap.c
 * @brief Test for container_multihashmap.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_container_lib.h"

#define ABORT() { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); if (m != NULL) GNUNET_CONTAINER_multihashmap_destroy(m); return 1; }
#define CHECK(c) { if (! (c)) ABORT(); }

static int
testMap (int i)
{
  struct GNUNET_CONTAINER_MultiHashMap *m;
  GNUNET_HashCode k1;
  GNUNET_HashCode k2;
  const char *ret;
  int j;

  CHECK (NULL != (m = GNUNET_CONTAINER_multihashmap_create (i)));
  memset (&k1, 0, sizeof (k1));
  memset (&k2, 1, sizeof (k2));
  CHECK (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (m, &k1));
  CHECK (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (m, &k2));
  CHECK (GNUNET_NO == GNUNET_CONTAINER_multihashmap_remove (m, &k1, NULL));
  CHECK (GNUNET_NO == GNUNET_CONTAINER_multihashmap_remove (m, &k2, NULL));
  CHECK (NULL == GNUNET_CONTAINER_multihashmap_get (m, &k1));
  CHECK (NULL == GNUNET_CONTAINER_multihashmap_get (m, &k2));
  CHECK (0 == GNUNET_CONTAINER_multihashmap_remove_all (m, &k1));
  CHECK (0 == GNUNET_CONTAINER_multihashmap_size (m));
  CHECK (0 == GNUNET_CONTAINER_multihashmap_iterate (m, NULL, NULL));
  CHECK (0 == GNUNET_CONTAINER_multihashmap_get_multiple (m, &k1, NULL, NULL));

  CHECK (GNUNET_OK ==
         GNUNET_CONTAINER_multihashmap_put (m, &k1, "v1",
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE));
  CHECK (1 == GNUNET_CONTAINER_multihashmap_size (m));
  ret = GNUNET_CONTAINER_multihashmap_get (m, &k1);
  GNUNET_assert (ret != NULL);
  CHECK (0 == strcmp ("v1", ret));
  CHECK (GNUNET_NO ==
         GNUNET_CONTAINER_multihashmap_put (m, &k1, "v1",
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE));
  CHECK (1 == GNUNET_CONTAINER_multihashmap_size (m));
  CHECK (GNUNET_OK ==
         GNUNET_CONTAINER_multihashmap_put (m, &k1, "v2",
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  CHECK (GNUNET_OK ==
         GNUNET_CONTAINER_multihashmap_put (m, &k1, "v3",
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  CHECK (3 == GNUNET_CONTAINER_multihashmap_size (m));
  CHECK (GNUNET_OK == GNUNET_CONTAINER_multihashmap_remove (m, &k1, "v3"));
  CHECK (2 == GNUNET_CONTAINER_multihashmap_size (m));
  CHECK (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (m, &k1));
  CHECK (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (m, &k2));
  CHECK (2 == GNUNET_CONTAINER_multihashmap_get_multiple (m, &k1, NULL, NULL));
  CHECK (0 == GNUNET_CONTAINER_multihashmap_get_multiple (m, &k2, NULL, NULL));
  CHECK (2 == GNUNET_CONTAINER_multihashmap_iterate (m, NULL, NULL));
  CHECK (2 == GNUNET_CONTAINER_multihashmap_remove_all (m, &k1));
  for (j = 0; j < 1024; j++)
    CHECK (GNUNET_OK ==
           GNUNET_CONTAINER_multihashmap_put (m, &k1, "v2",
                                              GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  GNUNET_CONTAINER_multihashmap_destroy (m);
  return 0;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;
  int i;

  GNUNET_log_setup ("test-container-multihashmap", "WARNING", NULL);
  for (i = 1; i < 255; i++)
    failureCount += testMap (i);
  if (failureCount != 0)
    return 1;
  return 0;
}

/* end of test_container_multihashmap.c */
