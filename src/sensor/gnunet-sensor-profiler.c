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
 * TODO:
 * - Run X peers
 * - Rewrite interval time (optional)
 * - Run 1 dashboard
 * - Monitor dashboard records
 * - Prompt for anomalies when ready:
 *  -- Cut Y peers (remove their connections to other X-Y peers but not the connections among themselves)
 */

/**
 * @file sensor/gnunet-sensor-profiler.c
 * @brief Profiler for the sensor service
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"

/**
 * Information about a single peer
 */
struct PeerInfo
{

  /**
   * Peer Identity
   */
  struct GNUNET_PeerIdentity peer_id;

  /**
   * Testbed peer handle
   */
  struct GNUNET_TESTBED_Peer *testbed_peer;

};

/**
 * Number of peers to run
 */
static unsigned int num_peers;

/**
 * Return value of the program
 */
static int ok = 1;

/**
 * Array of peer info for all peers
 */
static struct PeerInfo *all_peers_info;

/**
 * Number of peers that we already collected and start their info
 */
static int peers_known = 0;

/**
 * Name of the configuration file used
 */
static char *cfg_filename = "gnunet-sensor-profiler.conf";


/**
 * Do clean up and shutdown scheduler
 */
static void
do_shutdown ()                  // TODO: schedule timeout shutdown
{
  if (NULL != all_peers_info)
  {
    GNUNET_free (all_peers_info);
    all_peers_info = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
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
peer_info_cb (void *cb_cls, struct GNUNET_TESTBED_Operation *op,
              const struct GNUNET_TESTBED_PeerInformation *pinfo,
              const char *emsg)
{
  struct GNUNET_TESTBED_Peer *testbed_peer = cb_cls;
  struct PeerInfo *peer = &all_peers_info[peers_known];

  peer->testbed_peer = testbed_peer;
  GNUNET_CRYPTO_get_peer_identity (pinfo->result.cfg, &peer->peer_id);
  peers_known++;
  if (peers_known == num_peers) //TODO: remove
  {
    do_shutdown ();
  }
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param h the run handle
 * @param num number of peers in 'peers'
 * @param peers handle to peers run in the testbed.  NULL upon timeout (see
 *          GNUNET_TESTBED_test_run()).
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 * @see GNUNET_TESTBED_test_run()
 */
static void
test_master (void *cls, struct GNUNET_TESTBED_RunHandle *h, unsigned int num,
             struct GNUNET_TESTBED_Peer **peers, unsigned int links_succeeded,
             unsigned int links_failed)
{
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%d peers started. %d links succeeded. %d links failed.\n",
              num_peers, links_succeeded, links_failed);
  GNUNET_assert (num == num_peers);
  GNUNET_assert (0 == links_failed);
  /* Collect peer information */
  all_peers_info = GNUNET_new_array (num_peers, struct PeerInfo);

  for (i = 0; i < num_peers; i++)
  {
    GNUNET_TESTBED_peer_get_information (peers[i],
                                         GNUNET_TESTBED_PIT_CONFIGURATION,
                                         &peer_info_cb, peers[i]);
  }
}


/**
 * Verify that the user passed correct CL args
 *
 * @return #GNUNET_OK if arguments are valid, #GNUNET_SYSERR otherwise
 */
static int
verify_args ()
{
  if (num_peers < 3)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Invalid or missing number of peers. Set at least 3 peers.\n"));
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Actual main function.
 *
 * @param cls unused
 * @param args remaining args, unused
 * @param cfgfile name of the configuration
 * @param cfg configuration handle
 */
static void
run (void *cls, char *const *args, const char *cf,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  double links;

  if (GNUNET_OK != verify_args ())
  {
    do_shutdown ();
    return;
  }
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_load (cfg, cfg_filename);
  links = log (num_peers) * log (num_peers) * num_peers / 2;
  GNUNET_CONFIGURATION_set_value_number ((struct GNUNET_CONFIGURATION_Handle *)
                                         cfg, "TESTBED", "OVERLAY_RANDOM_LINKS",
                                         (unsigned long long int) links);
  GNUNET_TESTBED_run (NULL, cfg, num_peers, 0, NULL, NULL, &test_master, NULL);
}


/**
 * Main function.
 *
 * @return 0 on success
 */
int
main (int argc, char *const *argv)
{
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'p', "peers", "COUNT", gettext_noop ("Number of peers to run"), GNUNET_YES,
     &GNUNET_GETOPT_set_uint, &num_peers},
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-sensor-profiler",
                              gettext_noop ("Profiler for sensor service"),
                              options, &run, NULL)) ? ok : 1;
}

/* end of gnunet-sensor-profiler.c */
