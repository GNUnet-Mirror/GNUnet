/*
     This file is part of GNUnet.
     Copyright (C) 2014 Christian Grothoff (and other contributing authors)

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
 * @file secretsharing/test_secretsharing_api.c
 * @brief testcase for the secretsharing api
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_secretsharing_service.h"


static int success;

static struct GNUNET_SECRETSHARING_Session *keygen;


static void secret_ready_cb (void *cls,
                             struct GNUNET_SECRETSHARING_Share *my_share,
                             struct GNUNET_SECRETSHARING_PublicKey *public_key,
                             unsigned int num_ready_peers,
                             struct GNUNET_PeerIdentity *ready_peers)
{
  keygen = NULL;
  if (num_ready_peers == 1)
    success = 1;
  // FIXME: check that our share is valid, which we can do as there's only
  // one peer.
  GNUNET_SCHEDULER_shutdown ();
}

static void
handle_shutdown (void *cls,
                 const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  if (NULL != keygen)
  {
    GNUNET_SECRETSHARING_session_destroy (keygen);
    keygen = NULL;
  }
}

static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_HashCode session_id; 
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_TIME_Absolute deadline;

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                handle_shutdown, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "testing secretsharing api\n");

  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &session_id);

  start = GNUNET_TIME_absolute_get ();
  deadline = GNUNET_TIME_absolute_add (start, GNUNET_TIME_UNIT_SECONDS);

  keygen = GNUNET_SECRETSHARING_create_session (cfg,
                                                0, NULL, /* only the local peer */
                                                &session_id,
                                                start, deadline,
                                                1,
                                                secret_ready_cb, NULL);


}


int
main (int argc, char **argv)
{

  int ret;
  ret = GNUNET_TESTING_peer_run ("test_secretsharing_api",
                                 "test_secretsharing.conf",
                                 &run, NULL);
  if (0 != ret)
    return ret;
  return (GNUNET_YES == success) ? 0 : 1;
}

