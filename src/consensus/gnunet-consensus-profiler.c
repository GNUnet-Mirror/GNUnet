/*
      This file is part of GNUnet
      Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file consensus/gnunet-consensus-profiler.c
 * @brief profiling tool for gnunet-consensus
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_consensus_service.h"
#include "gnunet_testbed_service.h"

static unsigned int num_peers = 2;

static unsigned int replication = 1;

static unsigned int num_values = 5;

static struct GNUNET_TIME_Relative conclude_timeout;

static struct GNUNET_TIME_Relative consensus_delay;

static struct GNUNET_CONSENSUS_Handle **consensus_handles;

static struct GNUNET_TESTBED_Operation **testbed_operations;

static unsigned int num_connected_handles;

static struct GNUNET_TESTBED_Peer **peers;

static struct GNUNET_PeerIdentity *peer_ids;

static unsigned int num_retrieved_peer_ids;

static struct GNUNET_HashCode session_id;

static unsigned int peers_done = 0;

static unsigned *results_for_peer;

static int verbose;

/**
 * Start time for all consensuses.
 */
static struct GNUNET_TIME_Absolute start;

/**
 * Deadline for all consensuses.
 */
static struct GNUNET_TIME_Absolute deadline;


/**
 * Signature of the event handler function called by the
 * respective event controller.
 *
 * @param cls closure
 * @param event information about the event
 */
static void
controller_cb (void *cls,
               const struct GNUNET_TESTBED_EventInformation *event)
{
  GNUNET_assert (0);
}


static void
destroy (void *cls, const struct GNUNET_SCHEDULER_TaskContext *ctx)
{
  struct GNUNET_CONSENSUS_Handle *consensus = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "destroying consensus\n");
  GNUNET_CONSENSUS_destroy (consensus);
  peers_done++;
  if (peers_done == num_peers)
  {
    unsigned int i;
    for (i = 0; i < num_peers; i++)
      GNUNET_TESTBED_operation_done (testbed_operations[i]);
    for (i = 0; i < num_peers; i++)
      printf ("P%u got %u of %u elements\n",
              i,
              results_for_peer[i],
              num_values);
    GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * Called when a conclusion was successful.
 *
 * @param cls closure, the consensus handle
 * @return #GNUNET_YES if more consensus groups should be offered,
 *         #GNUNET_NO if not
 */
static void
conclude_cb (void *cls)
{
  struct GNUNET_CONSENSUS_Handle **chp = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "consensus %d done\n",
              chp - consensus_handles);
  GNUNET_SCHEDULER_add_now (destroy, *chp);
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
  unsigned int i;

  for (i = 0; i < num_values; i++)
  {
    unsigned int j;
    struct GNUNET_HashCode val;
    struct GNUNET_SET_Element element;

    generate_indices (unique_indices);
    GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &val);

    element.data = &val;
    element.size = sizeof (val);
    for (j = 0; j < replication; j++)
    {
      int cid;

      cid = unique_indices[j];
      GNUNET_CONSENSUS_insert (consensus_handles[cid],
                               &element,
                               NULL, NULL);
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "all elements inserted, calling conclude\n");

  for (i = 0; i < num_peers; i++)
    GNUNET_CONSENSUS_conclude (consensus_handles[i],
                               conclude_cb, &consensus_handles[i]);
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

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "testbed connect emsg: %s\n",
                emsg);
    GNUNET_assert (0);
  }

  num_connected_handles++;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "connect complete\n");

  if (num_connected_handles == num_peers)
  {
    do_consensus ();
  }
}


static void
new_element_cb (void *cls,
                const struct GNUNET_SET_Element *element)
{
  struct GNUNET_CONSENSUS_Handle **chp = cls;
  int idx = chp - consensus_handles;

  GNUNET_assert (NULL != cls);

  results_for_peer[idx]++;

  GNUNET_assert (sizeof (struct GNUNET_HashCode) == element->size);

  if (GNUNET_YES == verbose)
  {
    printf ("P%d received %s\n",
            idx,
            GNUNET_h2s ((struct GNUNET_HashCode *) element->data));
  }
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
  struct GNUNET_CONSENSUS_Handle **chp = cls;
  struct GNUNET_CONSENSUS_Handle *consensus;
  chp = (struct GNUNET_CONSENSUS_Handle **) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "connect adapter, %d peers\n",
              num_peers);
  consensus = GNUNET_CONSENSUS_create (cfg,
                                       num_peers, peer_ids,
                                       &session_id,
                                       start,
                                       deadline,
                                       &new_element_cb, chp);
  *chp = (struct GNUNET_CONSENSUS_Handle *) consensus;
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
        testbed_operations[i] =
            GNUNET_TESTBED_service_connect (NULL, peers[i], "consensus", connect_complete, NULL,
                                            connect_adapter, disconnect_adapter, &consensus_handles[i]);
  }
  else
  {
    GNUNET_assert (0);
  }

  GNUNET_TESTBED_operation_done (op);
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param h the run handle
 * @param num_peers number of peers in 'peers'
 * @param started_peers handle to peers run in the testbed.  NULL upon timeout (see
 *          GNUNET_TESTBED_test_run()).
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 */
static void
test_master (void *cls,
             struct GNUNET_TESTBED_RunHandle *h,
             unsigned int num_peers,
             struct GNUNET_TESTBED_Peer **started_peers,
             unsigned int links_succeeded,
             unsigned int links_failed)
{
  int i;

  GNUNET_log_setup ("gnunet-consensus", "INFO", NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "test master\n");

  peers = started_peers;

  peer_ids = GNUNET_malloc (num_peers * sizeof (struct GNUNET_PeerIdentity));

  results_for_peer = GNUNET_malloc (num_peers * sizeof (unsigned int));
  consensus_handles = GNUNET_malloc (num_peers * sizeof (struct ConsensusHandle *));
  testbed_operations = GNUNET_malloc (num_peers * sizeof (struct ConsensusHandle *));

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
  char *topology;
  int topology_cmp_result;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg, "testbed", "OVERLAY_TOPOLOGY", &topology))
  {
    fprintf (stderr,
             "'OVERLAY_TOPOLOGY' not found in 'testbed' config section, "
             "seems like you passed the wrong configuration file\n");
    return;
  }

  topology_cmp_result = strcasecmp (topology, "NONE");
  GNUNET_free (topology);

  if (0 == topology_cmp_result)
  {
    fprintf (stderr,
             "'OVERLAY_TOPOLOGY' set to 'NONE', "
             "seems like you passed the wrong configuration file\n");
    return;
  }

  if (num_peers < replication)
  {
    fprintf (stderr, "k must be <=n\n");
    return;
  }

  start = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (), consensus_delay);
  deadline = GNUNET_TIME_absolute_add (start, conclude_timeout);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "running gnunet-consensus\n");

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
      { 'd', "delay", NULL,
        gettext_noop ("delay until consensus starts"),
        GNUNET_YES, &GNUNET_GETOPT_set_relative_time, &consensus_delay },
      { 'V', "verbose", NULL,
        gettext_noop ("be more verbose (print received values)"),
        GNUNET_NO, &GNUNET_GETOPT_set_one, &verbose },
      GNUNET_GETOPT_OPTION_END
  };
  conclude_timeout = GNUNET_TIME_UNIT_SECONDS;
  GNUNET_PROGRAM_run2 (argc, argv, "gnunet-consensus-profiler",
		      "help",
		      options, &run, NULL, GNUNET_YES);
  return 0;
}

