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
#include "gnunet_testing_lib.h"


static struct GNUNET_CONSENSUS_Handle *consensus;

static struct GNUNET_HashCode session_id;


static int
conclude_done (void *cls, const struct GNUNET_CONSENSUS_Group *group)
{
  if (NULL == group)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "conclude over\n");
    GNUNET_SCHEDULER_shutdown ();
    return GNUNET_NO;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "concluded\n");
  return GNUNET_YES;
}

static int
on_new_element (void *cls,
                struct GNUNET_CONSENSUS_Element *element)
{
  GNUNET_assert (0);
  return GNUNET_YES;
}

static void
insert_done (void *cls, int success)
{
  /* make sure cb is only called once */
  static int called = GNUNET_NO;
  GNUNET_assert (GNUNET_NO == called);
  called = GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "insert done\n");
  GNUNET_CONSENSUS_conclude (consensus, GNUNET_TIME_UNIT_SECONDS, 0, &conclude_done, NULL);
}


/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
on_shutdown (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != consensus)
  {
    GNUNET_CONSENSUS_destroy (consensus);
    consensus = NULL;
  }
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
                    "INFO",
                    NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "testing consensus api\n");

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &on_shutdown, NULL);

  GNUNET_CRYPTO_hash (str, strlen (str), &session_id);
  consensus = GNUNET_CONSENSUS_create (cfg, 0, NULL, &session_id, on_new_element, &consensus);
  GNUNET_assert (consensus != NULL);

  GNUNET_CONSENSUS_insert (consensus, &el1, NULL, &consensus);
  GNUNET_CONSENSUS_insert (consensus, &el2, &insert_done, &consensus);
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

