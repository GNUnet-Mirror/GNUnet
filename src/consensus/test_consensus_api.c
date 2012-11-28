/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file consensus/test_consensus_api.c
 * @brief testcase for consensus_api.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_consensus_service.h"
#include "gnunet_testing_lib-new.h"


static struct GNUNET_CONSENSUS_Handle *consensus1;
static struct GNUNET_CONSENSUS_Handle *consensus2;

static int concluded1;
static int concluded2;

static int insert1;
static int insert2;

static struct GNUNET_HashCode session_id;


static void conclude_done (void *cls, 
                           unsigned int num_peers_in_consensus,
                           const struct GNUNET_PeerIdentity *peers_in_consensus)
{
  struct GNUNET_CONSENSUS_Handle *consensus;
  consensus = (struct GNUNET_CONSENSUS_Handle *) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "concluded\n");
}

static void
on_new_element (void *cls,
                struct GNUNET_CONSENSUS_Element *element)
{
  struct GNUNET_CONSENSUS_Handle *consensus;

  GNUNET_assert (NULL != element);

  consensus = *(struct GNUNET_CONSENSUS_Handle **) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "received new element\n");

  GNUNET_CONSENSUS_conclude (consensus, GNUNET_TIME_UNIT_FOREVER_REL, &conclude_done, consensus);

}

static void
insert_done (void *cls, int success)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "insert done\n");
}



static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  char *str = "foo";

  struct GNUNET_CONSENSUS_Element el1 = {"foo", 4, 0};
  struct GNUNET_CONSENSUS_Element el2 = {"bar", 4, 0};

  GNUNET_log_setup ("test_consensus_api",
                    "DEBUG",
                    NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "testing consensus api\n");

  GNUNET_CRYPTO_hash (str, strlen (str), &session_id);
  consensus1 = GNUNET_CONSENSUS_create (cfg, 0, NULL, &session_id, on_new_element, &consensus1);
  /*
  consensus2 = GNUNET_CONSENSUS_create (cfg, 0, NULL, &session_id, on_new_element, &consensus2);
  GNUNET_assert (consensus1 != NULL);
  GNUNET_assert (consensus2 != NULL);
  GNUNET_CONSENSUS_insert (consensus1, &el1, &insert_done, &consensus1);
  GNUNET_CONSENSUS_insert (consensus2, &el2, &insert_done, &consensus2);
  */
}


int
main (int argc, char **argv)
{
  int ret;

  ret = GNUNET_TESTING_peer_run ("test_consensus_api",
                                 "test_consensus.conf",
                                 &run, NULL);
  return ret;
}

