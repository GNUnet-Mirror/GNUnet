  /*
   * This file is part of GNUnet.
   * Copyright (C)
   *
   * GNUnet is free software; you can redistribute it and/or modify
   * it under the terms of the GNU General Public License as published
   * by the Free Software Foundation; either version 3, or (at your
   * option) any later version.
   *
   * GNUnet is distributed in the hope that it will be useful, but
   * WITHOUT ANY WARRANTY; without even the implied warranty of
   * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   * General Public License for more details.
   *
   * You should have received a copy of the GNU General Public License
   * along with GNUnet; see the file COPYING.  If not, write to the
   * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   * Boston, MA 02111-1307, USA.
   */
/**
 * @file sensor/test_pow_sign.c
 * @brief testcase for proof-of-work and signature library functions
 */
#include <inttypes.h>
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_sensor_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_signatures.h"

/**
 * Number of peers to start for the test
 */
#define NUM_PEERS 1

/**
 * Size of the message exchanged
 */
#define MSG_SIZE 1024

/**
 * Number of matching bits to use for generating proof-of-work
 */
#define MATCHING_BITS 5

/**
 * Test timeout
 */
#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 1)

/**
 * Test name
 */
static const char *testname = "test_pow_sign";

/**
 * Name of GNUNET config file used in this test
 */
static const char *cfg_filename = "test_pow_sign.conf";

/**
 * Status of the test to be returned by main()
 */
static int ok = 1;

/**
 * Task used to shutdown / expire the test
 */
static struct GNUNET_SCHEDULER_Task * shutdown_task;

/**
 * Message to be exchanged
 */
static char msg[MSG_SIZE];

/**
 * Private key of sending peer
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *private_key;

/**
 * Public key of sending peer
 */
static struct GNUNET_CRYPTO_EddsaPublicKey *public_key;


/**
 * Shutdown task
 *
 * @param cls Closure (unused)
 * @param tc Task context (unused)
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != private_key)
  {
    GNUNET_free (private_key);
    private_key = NULL;
  }
  if (NULL != public_key)
  {
    GNUNET_free (public_key);
    public_key = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
}


static void
pow_cb (void *cls, struct GNUNET_SENSOR_crypto_pow_block *block)
{
  void *response;
  struct GNUNET_TIME_Absolute end_time;
  struct GNUNET_TIME_Relative duration;

  end_time = GNUNET_TIME_absolute_get();
  duration = GNUNET_TIME_absolute_get_difference (block->timestamp, end_time);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received block:\n" "pow: %" PRIu64 ".\n", block->pow);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Block generation toke %s.\n",
              GNUNET_STRINGS_relative_time_to_string (duration, GNUNET_NO));
  /* Test that the block is valid */
  GNUNET_assert (MSG_SIZE ==
                 GNUNET_SENSOR_crypto_verify_pow_sign (block, MATCHING_BITS,
                                                       public_key, &response));
  GNUNET_assert (0 == memcmp (msg, response, MSG_SIZE));
  /* Modify the payload and test that verification returns invalid */
  block->pow++;
  GNUNET_assert (0 ==
                 GNUNET_SENSOR_crypto_verify_pow_sign (block, MATCHING_BITS,
                                                       public_key, &response));
  ok = 0;
  GNUNET_SCHEDULER_cancel (shutdown_task);
  GNUNET_SCHEDULER_add_now (do_shutdown, NULL);
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
  struct GNUNET_TIME_Absolute timestamp;

  /* generate random data block */
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK, msg, MSG_SIZE);
  /* get private and public keys */
  private_key =
      GNUNET_CRYPTO_eddsa_key_create_from_configuration (pinfo->result.cfg);
  GNUNET_assert (NULL != private_key);
  public_key = GNUNET_new (struct GNUNET_CRYPTO_EddsaPublicKey);

  GNUNET_CRYPTO_eddsa_key_get_public (private_key, public_key);
  /* create pow and sign */
  timestamp = GNUNET_TIME_absolute_get ();
  GNUNET_SENSOR_crypto_pow_sign (msg, MSG_SIZE, &timestamp, public_key,
                                 private_key, MATCHING_BITS, &pow_cb, NULL);
  GNUNET_TESTBED_operation_done (op);
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param h the run handle
 * @param num_peers number of peers in 'peers'
 * @param peers handle to peers run in the testbed.  NULL upon timeout (see
 *          GNUNET_TESTBED_test_run()).
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 * @see GNUNET_TESTBED_test_run()
 */
static void
test_master (void *cls, struct GNUNET_TESTBED_RunHandle *h,
             unsigned int num_peers, struct GNUNET_TESTBED_Peer **peers,
             unsigned int links_succeeded, unsigned int links_failed)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%d peers started. %d links succeeded. %d links failed.\n",
              num_peers, links_succeeded, links_failed);
  GNUNET_assert (NUM_PEERS == num_peers);
  GNUNET_assert (0 == links_failed);
  /* Schedule test timeout */
  shutdown_task =
      GNUNET_SCHEDULER_add_delayed (TEST_TIMEOUT, &do_shutdown, NULL);
  GNUNET_TESTBED_peer_get_information (peers[0],
                                       GNUNET_TESTBED_PIT_CONFIGURATION,
                                       &peer_info_cb, peers[0]);
}


int
main (int argc, char *argv[])
{
  GNUNET_log_setup (testname, "INFO", NULL);
  if (GNUNET_OK ==
      GNUNET_TESTBED_test_run (testname, cfg_filename, NUM_PEERS, 0, NULL, NULL,
                               &test_master, NULL))
    return ok;
  return 1;
}
