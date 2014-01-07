/*
      This file is part of GNUnet
      (C) 2014 Christian Grothoff (and other contributing authors)

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
 * @file secretsharing/gnunet-secretsharing-profiler.c
 * @brief profiling tool for distributed key generation and decryption
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_secretsharing_service.h"
#include "gnunet_testbed_service.h"

static unsigned int num_peers = 3;

static unsigned int threshold = 2;

static struct GNUNET_TIME_Relative timeout;

static struct GNUNET_SECRETSHARING_Session **session_handles;

static struct GNUNET_TESTBED_Operation **testbed_operations;

static unsigned int num_connected_handles;

static struct GNUNET_TESTBED_Peer **peers;

static struct GNUNET_PeerIdentity *peer_ids;

static unsigned int num_retrieved_peer_ids;

static struct GNUNET_HashCode session_id;

static int verbose;


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
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "all peers connected\n");
  }
}


static void
secret_ready_cb (void *cls,
                 const struct GNUNET_SECRETSHARING_Share *my_share,
                 const struct GNUNET_SECRETSHARING_PublicKey *public_key,
                 unsigned int num_ready_peers,
                 const struct GNUNET_PeerIdentity *ready_peers)
{
  struct GNUNET_SECRETSHARING_Session **sp = cls;
  unsigned int n = sp - session_handles;
  if (NULL == my_share || NULL == public_key)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "key generation failed for peer #%u\n", n);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "secret ready for peer #%u\n", n);
  // FIXME: end profiler or try decryption if all secrets are ready
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
  struct GNUNET_SECRETSHARING_Session **sp = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "connect adapter, %d peers\n",
              num_peers);
  *sp = GNUNET_SECRETSHARING_create_session (cfg,
                                             num_peers,
                                             peer_ids,
                                             &session_id,
                                             GNUNET_TIME_relative_to_absolute (timeout),
                                             threshold,
                                             &secret_ready_cb, sp);
  return *sp;
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
            GNUNET_TESTBED_service_connect (NULL, peers[i], "secretsharing", connect_complete, NULL,
                                            connect_adapter, disconnect_adapter, &session_handles[i]);
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

  GNUNET_log_setup ("gnunet-secretsharing-profiler", "INFO", NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "test master\n");

  peers = started_peers;

  peer_ids = GNUNET_malloc (num_peers * sizeof (struct GNUNET_PeerIdentity));

  session_handles = GNUNET_malloc (num_peers * sizeof (struct GNUNET_SECRETSHARING_Session *));
  testbed_operations = GNUNET_malloc (num_peers * sizeof (struct GNUNET_TESTBED_Operation *));

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
  static char *session_str = "gnunet-secretsharing/test";
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

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "running gnunet-secretsharing-profiler\n");

  GNUNET_CRYPTO_hash (session_str, strlen (session_str), &session_id);

  (void) GNUNET_TESTBED_test_run ("gnunet-secretsharing-profiler",
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
      { 't', "timeout", NULL,
        gettext_noop ("dkg timeout"),
        GNUNET_YES, &GNUNET_GETOPT_set_relative_time, &timeout },
      { 'k', "threshold", NULL,
        gettext_noop ("threshold"),
        GNUNET_YES, &GNUNET_GETOPT_set_uint, &threshold },
      { 'V', "verbose", NULL,
        gettext_noop ("be more verbose (print received values)"),
        GNUNET_NO, &GNUNET_GETOPT_set_one, &verbose },
      GNUNET_GETOPT_OPTION_END
  };
  timeout = GNUNET_TIME_UNIT_SECONDS;
  GNUNET_PROGRAM_run2 (argc, argv, "gnunet-secretsharing-profiler",
		      "help",
		      options, &run, NULL, GNUNET_YES);
  return 0;
}

