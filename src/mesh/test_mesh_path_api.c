/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file mesh/test_mesh_path.c
 * @brief test mesh path: test of path management api
 * @author Bartlomiej Polot
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_mesh_service_new.h"
#include "mesh.h"
#include "mesh_tunnel_tree.h"

#define VERBOSE 1

/**
 * Convert an integer int oa peer identity
 */
static struct GNUNET_PeerIdentity *
get_pi (uint32_t id)
{
  struct GNUNET_PeerIdentity *pi;

  pi = GNUNET_malloc(sizeof(struct GNUNET_PeerIdentity));
  pi->hashPubKey.bits[0] = id;
  return pi;
}

int
main (int argc, char *argv[])
{
  struct GNUNET_PeerIdentity* pi;
  int result;

  GNUNET_log_setup ("test_mesh_api_path",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  pi = get_pi(1);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Peer 1: %s\n", GNUNET_h2s(&pi->hashPubKey));

  result = GNUNET_OK;

  if (GNUNET_SYSERR == result)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "test failed\n");
    return 1;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test ok\n");
  return 0;
}
