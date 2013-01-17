/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file consensus/gnunet-consensus.c
 * @brief profiling tool for gnunet-consensus
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_consensus_service.h"
#include "gnunet_testbed_service.h"

static unsigned int num_peers = 2;

static unsigned int replication = 1;

static unsigned int num_values = 5;

static struct GNUNET_TIME_Relative conclude_timeout;

static struct GNUNET_CONSENSUS_Handle **consensus_handles;

static unsigned int num_connected_handles;

static struct GNUNET_TESTBED_Peer **peers;

static struct GNUNET_PeerIdentity *peer_ids;

static unsigned int num_retrieved_peer_ids;

static struct GNUNET_HashCode session_id;


/**
 * Signature of the event handler function called by the
 * respective event controller.
 *
 * @param cls closure
 * @param event information about the event
 */
static void
controller_cb(void *cls,
              const struct GNUNET_TESTBED_EventInformation *event)
{
  GNUNET_assert (0);
}


/**
 * Called when a conclusion was successful.
 *
 * @param cls
 * @param group
 * @return GNUNET_YES if more consensus groups should be offered, GNUNET_NO if not
 */
static int
conclude_cb (void *cls, const struct GNUNET_CONSENSUS_Group *group)
{
  return GNUNET_NO;
}



static void
generate_indices (int *indices)
{
  int j;
  j = 0;
  while (j < replication)
  {
    int n;
    int k;
    int repeat;
    n = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
    repeat = GNUNET_NO;
    for (k = 0; k < j; k++)
      if (indices[k] == n)
      {
        repeat = GNUNET_YES;
        break;
      }
    if (GNUNET_NO == repeat)
      indices[j++] = n;
  }
}


static void
do_consensus ()
{
  int unique_indices[replication];
  int i;

  for (i = 0; i < num_values; i++)
  {
    int j;
    struct GNUNET_HashCode *val;
    struct GNUNET_CONSENSUS_Element *element;
    generate_indices(unique_indices);

    val = GNUNET_malloc (sizeof *val);
    GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, val);

    element = GNUNET_malloc (sizeof *element);
    element->data = val;
    element->size = sizeof *val;

    for (j = 0; j < replication; j++)
    {
      int cid;
      cid = unique_indices[j];
      GNUNET_CONSENSUS_insert (consensus_handles[cid], element, NULL, NULL);
    }
  }

  for (i = 0; i < num_peers; i++)
    GNUNET_CONSENSUS_conclude (consensus_handles[i], conclude_timeout, 0, conclude_cb, consensus_handles[i]);
}


/**
 * Callback to be called when a service connect operation is completed
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param ca_result the service handle returned from GNUNET_TESTBED_ConnectAdapter()
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
connect_complete (void *cls,
                  struct GNUNET_TESTBED_Operation *op,
                  void *ca_result,
                  const char *emsg)
{
  struct GNUNET_CONSENSUS_Handle **chp;

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "testbed connect emsg: %s\n", emsg);
    GNUNET_assert (0);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "connect complete\n");

  chp = (struct GNUNET_CONSENSUS_Handle **) cls;
  *chp = (struct GNUNET_CONSENSUS_Handle *) ca_result;
  num_connected_handles++;

  if (num_connected_handles == num_peers)
  {
    do_consensus ();
  }
}


static int
new_element_cb (void *cls,
                struct GNUNET_CONSENSUS_Element *element)
{
  return GNUNET_YES;
}


/**
 * Adapter function called to establish a connection to
 * a service.
 *
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
connect_adapter (void *cls,
                 const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CONSENSUS_Handle *consensus;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "connect adapter, %d peers\n", num_peers);
  consensus = GNUNET_CONSENSUS_create (cfg, num_peers, peer_ids, &session_id, new_element_cb, NULL);
  GNUNET_assert (NULL != consensus);
  return consensus;
}


/**
 * Adapter function called to destroy a connection to
 * a service.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
disconnect_adapter(void *cls, void *op_result)
{
  /* FIXME: what to do here? */
}


/**
 * Callback to be called when the requested peer information is available
 *
 * @param cb_cls the closure from GNUNET_TETSBED_peer_get_information()
 * @param op the operation this callback corresponds to
 * @param pinfo the result; will be NULL if the operation has failed
 * @param emsg error message if the operation has failed; will be NULL if the
 *          operation is successfull
 */
static void
peer_info_cb (void *cb_cls,
              struct GNUNET_TESTBED_Operation *op,
              const struct GNUNET_TESTBED_PeerInformation *pinfo,
              const char *emsg)
{
  struct GNUNET_PeerIdentity *p;
  int i;

  GNUNET_assert (NULL == emsg);

  p = (struct GNUNET_PeerIdentity *) cb_cls;

  if (pinfo->pit == GNUNET_TESTBED_PIT_IDENTITY)
  {
    *p = *pinfo->result.id;
    num_retrieved_peer_ids++;
    if (num_retrieved_peer_ids == num_peers)
      for (i = 0; i < num_peers; i++)
        GNUNET_TESTBED_service_connect (NULL, peers[i], "consensus", connect_complete, &consensus_handles[i],
                                        connect_adapter, disconnect_adapter, NULL);
  }
  else
  {
    GNUNET_assert (0);
  }
}


static void
test_master (void *cls,
             unsigned int num_peers,
             struct GNUNET_TESTBED_Peer **started_peers)
{
  int i;


  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "test master\n");

  peers = started_peers;

  peer_ids = GNUNET_malloc (num_peers * sizeof (struct GNUNET_PeerIdentity));

  consensus_handles = GNUNET_malloc (num_peers * sizeof (struct ConsensusHandle *));

  for (i = 0; i < num_peers; i++)
    GNUNET_TESTBED_peer_get_information (peers[i],
                                         GNUNET_TESTBED_PIT_IDENTITY,
                                         peer_info_cb,
                                         &peer_ids[i]);
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static char *session_str = "gnunet-consensus/test";


  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "running gnunet-consensus\n");

  GNUNET_CRYPTO_hash (session_str, strlen(session_str), &session_id);

  (void) GNUNET_TESTBED_test_run ("gnunet-consensus",
                                  cfgfile,
                                  num_peers,
                                  0,
                                  controller_cb,
                                  NULL,
                                  test_master,
                                  NULL);
}


int
main (int argc, char **argv)
{
   static const struct GNUNET_GETOPT_CommandLineOption options[] = {
      { 'n', "num-peers", NULL,
        gettext_noop ("number of peers in consensus"),
        GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_peers },
      { 'k', "value-replication", NULL,
        gettext_noop ("how many peers receive one value?"),
        GNUNET_YES, &GNUNET_GETOPT_set_uint, &replication },
      { 'x', "num-values", NULL,
        gettext_noop ("number of values"),
        GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_values },
      { 't', "timeout", NULL,
        gettext_noop ("consensus timeout"),
        GNUNET_YES, &GNUNET_GETOPT_set_relative_time, &conclude_timeout },
      GNUNET_GETOPT_OPTION_END
  };
  conclude_timeout = GNUNET_TIME_UNIT_SECONDS;
  GNUNET_PROGRAM_run2 (argc, argv, "gnunet-consensus",
		      "help",
		      options, &run, NULL, GNUNET_YES);
  return 0;
}

