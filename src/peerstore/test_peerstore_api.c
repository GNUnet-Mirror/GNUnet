/*
     This file is part of GNUnet.
     (C)

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
 * @file peerstore/test_peerstore_api.c
 * @brief testcase for peerstore_api.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_peerstore_service.h"

static int ok = 1;

struct GNUNET_PEERSTORE_Handle *h;

static void
run (void *cls,
    const struct GNUNET_CONFIGURATION_Handle *cfg,
    struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_PeerIdentity pid;
  char *val = "peerstore-test-value";
  size_t val_size = strlen(val);

  ok = 0;
  memset (&pid, 32, sizeof (pid));
  h = GNUNET_PEERSTORE_connect(cfg);
  GNUNET_assert(NULL != h);
  GNUNET_PEERSTORE_store(h,
      &pid,
      "peerstore-test",
      val,
      val_size,
      GNUNET_TIME_UNIT_FOREVER_REL,
      NULL,
      NULL);
  GNUNET_PEERSTORE_disconnect(h);

}

int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_service_run ("test-gnunet-peerstore",
                 "peerstore",
                 "test_peerstore_api_data.conf",
                 &run, NULL))
    return 1;
  return ok;
}

/* end of test_peerstore_api.c */
