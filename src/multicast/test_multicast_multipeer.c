/*
 * This file is part of GNUnet
 * Copyright (C) 2013 GNUnet e.V.
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
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

/**
 * @file multicast/test_multicast_multipeers.c
 * @brief Tests for the Multicast API with multiple peers.
 * @author xrs
 */

#include <inttypes.h>

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_core_service.h"
#include "gnunet_multicast_service.h"

#define NUM_PEERS 2

static struct GNUNET_TESTBED_Operation *peer0;
static struct GNUNET_TESTBED_Operation *peer1;

static struct GNUNET_SCHEDULER_Task *timeout_tid;

struct GNUNET_CRYPTO_EddsaPrivateKey *group_key;
struct GNUNET_CRYPTO_EddsaPublicKey group_pub_key;

struct GNUNET_CRYPTO_EcdsaPrivateKey *member1_key;
struct GNUNET_CRYPTO_EcdsaPublicKey member1_pub_key;


enum
{
  TEST_INIT          = 0,
  TEST_ORIGIN_START  = 1,
  TEST_MEMBER_JOIN   = 2,
} test;


/**
 * Global result for testcase.
 */
static int result;


/**
 * Function run on CTRL-C or shutdown (i.e. success/timeout/etc.).
 * Cleans up.
 */
static void
shutdown_task (void *cls)
{
  if (NULL != peer0)
  {
    GNUNET_TESTBED_operation_done (peer0);
    peer0 = NULL;
  }
  if (NULL != timeout_tid)
    {
      GNUNET_SCHEDULER_cancel (timeout_tid);
      timeout_tid = NULL;
    }
}


static void
timeout_task (void *cls)
{
  timeout_tid = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
	      "Timeout!\n");
  result = GNUNET_SYSERR;
  GNUNET_SCHEDULER_shutdown ();
}


static void
origin_recv_replay_msg (void *cls,
                        const struct GNUNET_CRYPTO_EcdsaPublicKey *member_key,
                        uint64_t message_id,
                        uint64_t fragment_offset,
                        uint64_t flags,
                        struct GNUNET_MULTICAST_ReplayHandle *rh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: origin_recv_replay_msg()\n", test);
  GNUNET_assert (0);
}


static void
member_recv_replay_msg (void *cls,
                        const struct GNUNET_CRYPTO_EcdsaPublicKey *member_key,
                        uint64_t message_id,
                        uint64_t fragment_offset,
                        uint64_t flags,
                        struct GNUNET_MULTICAST_ReplayHandle *rh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: member_recv_replay_msg()\n", test);
  GNUNET_assert (0);
}


static void
origin_recv_replay_frag (void *cls,
                         const struct GNUNET_CRYPTO_EcdsaPublicKey *member_key,
                         uint64_t fragment_id,
                         uint64_t flags,
                         struct GNUNET_MULTICAST_ReplayHandle *rh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: origin_recv_replay_frag()"
              " - fragment_id=%" PRIu64 " flags=%" PRIu64 "\n",
              test, fragment_id, flags);
}


/**
 * Test: origin receives join request
 */
static void
origin_recv_join_request (void *cls,
                          const struct GNUNET_CRYPTO_EcdsaPublicKey *mem_key,
                          const struct GNUNET_MessageHeader *join_msg,
                          struct GNUNET_MULTICAST_JoinHandle *jh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: origin_recv_join_request()\n", test);
}


static void
origin_recv_request (void *cls,
                     const struct GNUNET_MULTICAST_RequestHeader *req)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: origin_recv_request()\n",
              test);
}


static void
origin_recv_message (void *cls,
                     const struct GNUNET_MULTICAST_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: origin_recv_message()\n",
              test);
}


static void
service_close_peer0 (void *cls,
		     void *op_result)
{
  struct GNUNET_MULTICAST_Origin *orig = op_result;

  GNUNET_MULTICAST_origin_stop (orig, NULL, NULL);
}


/**
 * Function run when service multicast has started and is providing us
 * with a configuration file.
 */
static void *
service_conf_peer0 (void *cls,
		    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  group_key = GNUNET_CRYPTO_eddsa_key_create ();
  GNUNET_CRYPTO_eddsa_key_get_public (group_key, &group_pub_key);

  return GNUNET_MULTICAST_origin_start (cfg, group_key, 0,
                                        origin_recv_join_request,
                                        origin_recv_replay_frag,
                                        origin_recv_replay_msg,
                                        origin_recv_request,
                                        origin_recv_message,
					NULL);
}


/**
 * Test logic of peer "0" being origin starts here.
 *
 * @param cls closure, for the example: NULL
 * @param op should be equal to "dht_op"
 * @param ca_result result of the connect operation, the
 *        connection to the DHT service
 * @param emsg error message, if testbed somehow failed to
 *        connect to the DHT.
 */
static void
service_connect_peer0 (void *cls,
		       struct GNUNET_TESTBED_Operation *op,
		       void *ca_result,
		       const char *emsg)
{
  struct GNUNET_MULTICAST_Origin *orig = ca_result;

  /* Connection to service successful. Here we'd usually do something with
   * the service. */
  result = GNUNET_OK;
  GNUNET_SCHEDULER_shutdown (); /* Also kills the testbed */
}


/**
 * Main function inovked from TESTBED once all of the
 * peers are up and running.  This one then connects
 * just to the multicast service of peer 0 and 1.
 * Peer 0 is going to be origin.
 * Peer 1 is going to be one member.
 * Origin will start a multicast group and the member will try to join it.
 * After that we execute some multicast test.
 *
 * @param cls closure
 * @param h the run handle
 * @param peers started peers for the test
 * @param num_peers size of the 'peers' array
 * @param links_succeeded number of links between peers that were created
 * @param links_failed number of links testbed was unable to establish
 */
static void
run (void *cls,
     struct GNUNET_TESTBED_RunHandle *h,
     unsigned int num_peers,
     struct GNUNET_TESTBED_Peer **peers,
     unsigned int links_succeeded,
     unsigned int links_failed)
{
  /* Testbed is ready with peers running and connected in a pre-defined overlay
     topology (FIXME)  */

  /* connect to a peers service */
  peer0 = GNUNET_TESTBED_service_connect
      (NULL,                    /* Closure for operation */
       peers[0],                /* The peer whose service to connect to */
       "multicast",             /* The name of the service */
       &service_connect_peer0,   /* callback to call after a handle to service
                                   is opened */
       NULL,                    /* closure for the above callback */
       &service_conf_peer0,      /* callback to call with peer's configuration;
                                   this should open the needed service connection */
       &service_close_peer0,     /* callback to be called when closing the
                                   opened service connection */
       NULL);                   /* closure for the above two callbacks */
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
  timeout_tid = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
					      &timeout_task, NULL);
}


int
main (int argc, char *argv[])
{
  int ret;

  result = GNUNET_SYSERR;
  ret = GNUNET_TESTBED_test_run
      ("test-multicast-multipeer",  /* test case name */
       "test_multicast.conf", /* template configuration */
       NUM_PEERS,       /* number of peers to start */
       0LL, /* Event mask - set to 0 for no event notifications */
       NULL, /* Controller event callback */
       NULL, /* Closure for controller event callback */
       run, /* continuation callback to be called when testbed setup is complete */
       NULL); /* Closure for the test_master callback */
  if ( (GNUNET_OK != ret) || (GNUNET_OK != result) )
    return 1;
  return 0;
}

/* end of test_multicast_multipeer.c */
