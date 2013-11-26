/*
     This file is part of GNUnet.
     (C) 2009, 2013 Christian Grothoff (and other contributing authors)

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
 * @file dv/test_transport_dv.c
 * @brief base testcase for testing distance vector transport
 */
#include "platform.h"
#include "gnunet_core_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_revocation_service.h"
#include "gnunet_testbed_service.h"

#define NUM_TEST_PEERS 2

struct TestPeer
{
  struct GNUNET_TESTBED_Peer *p;
  struct GNUNET_TESTBED_Operation *identity_op;
  struct GNUNET_IDENTITY_Handle *idh;
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey;
  struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;
  struct GNUNET_CRYPTO_EcdsaSignature sig;
  uint64_t pow;
};

struct TestPeer testpeers[2];



/**
 * Return value from main, set to 0 on success.
 */
static int ok;

static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int c;
  for (c = 0; c < NUM_TEST_PEERS; c++)
  {
    GNUNET_TESTBED_operation_done (testpeers[c].identity_op);
    testpeers[c].identity_op = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
  ok = 0;
}

static void
do_shutdown_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  do_shutdown (NULL, NULL);
  ok = 1;
}

static void *
identity_connect_adapter (void *cls,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct TestPeer *me = cls;
  me->cfg = cfg;
  me->idh = GNUNET_IDENTITY_connect(cfg, NULL, NULL);
  if (NULL == me->idh)
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        "Failed to create IDENTITY handle \n");
  return me->idh;
}

static void
identity_disconnect_adapter (void *cls, void *op_result)
{
  struct TestPeer *me = cls;
  GNUNET_IDENTITY_disconnect(me->idh);
  me->idh = NULL;
}

static void check_revocation ();

static void revocation_remote_cb (void *cls,
                           int is_valid)
{
  static int repeat = 0;
  if  (GNUNET_NO == is_valid)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Local revocation successful\n");
    GNUNET_SCHEDULER_add_now(&do_shutdown, NULL);
  }
  else if (repeat < 10)
  {
    GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_SECONDS, &check_revocation, NULL);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Flooding of revocation failed\n");
    GNUNET_SCHEDULER_add_now(&do_shutdown_badly, NULL);
  }
  repeat++;
}

static void check_revocation ()
{
  GNUNET_REVOCATION_query (testpeers[0].cfg, &testpeers[1].pubkey, &revocation_remote_cb, NULL);
}

static void revocation_cb (void *cls,
                           int is_valid)
{
  if  (GNUNET_NO == is_valid)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Revocation successful\n");
    check_revocation();
  }
}

static void ego_cb (void *cls, const struct GNUNET_IDENTITY_Ego *ego)
{
  static int completed = 0;
  if ((NULL != ego) && (cls == &testpeers[0]))
  {
    testpeers[0].privkey = GNUNET_IDENTITY_ego_get_private_key(ego);
    GNUNET_IDENTITY_ego_get_public_key(ego, &testpeers[0].pubkey);
    completed ++;
  }
  if ((NULL != ego) && (cls == &testpeers[1]))
  {
    testpeers[1].privkey = GNUNET_IDENTITY_ego_get_private_key(ego);
    GNUNET_IDENTITY_ego_get_public_key(ego, &testpeers[1].pubkey);
    GNUNET_REVOCATION_sign_revocation(testpeers[1].privkey, &testpeers[1].sig);

    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Calculating proof of work...\n");
    testpeers[1].pow = 0;
    int res = GNUNET_REVOCATION_check_pow (&testpeers[1].pubkey, testpeers[1].pow, 5);
    while (GNUNET_OK != res)
    {
      testpeers[1].pow++;
      res = GNUNET_REVOCATION_check_pow (&testpeers[1].pubkey, testpeers[1].pow, 5);
    }
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Done calculating proof of work\n");
    completed ++;
  }
  if (2 == completed)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Egos retrieved\n");
    GNUNET_REVOCATION_revoke (testpeers[1].cfg, &testpeers[1].pubkey, &testpeers[1].sig, testpeers[1].pow, revocation_cb, NULL);
  }
}

void identity_create_cb (void *cls, const char *emsg)
{
  static int completed = 0;
  if ((NULL == emsg) && (cls == &testpeers[0]))
  {
    completed ++;
  }
  if ((NULL == emsg) && (cls == &testpeers[1]))
  {
    completed ++;
  }
  if (2 == completed)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Identities created\n");
    GNUNET_IDENTITY_ego_lookup (testpeers[0].cfg, "client", ego_cb, &testpeers[0]);
    GNUNET_IDENTITY_ego_lookup (testpeers[1].cfg, "toberevoked", ego_cb, &testpeers[1]);
  }
}


static void
identity_completion_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
    void *ca_result, const char *emsg)
{
  static int completed = 0;
  completed ++;
  if (NUM_TEST_PEERS == completed)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Connected to identity\n");
   GNUNET_IDENTITY_create (testpeers[0].idh, "client", identity_create_cb, &testpeers[0]);
   GNUNET_IDENTITY_create (testpeers[1].idh, "toberevoked", identity_create_cb, &testpeers[1]);
  }
}

static void
test_connection (void *cls,
                 struct GNUNET_TESTBED_RunHandle *h,
		 unsigned int num_peers,
		 struct GNUNET_TESTBED_Peer **peers,
                 unsigned int links_succeeded,
                 unsigned int links_failed)
{
  int c;
  if (NUM_TEST_PEERS != num_peers)
  {
    ok = 1;
    fprintf (stderr, "Only %u out of 2 peers were started ...\n",
        num_peers);
  }

  if (0 == links_failed)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Testbed connected peers\n");
    for (c = 0; c< num_peers; c++)
    {
      testpeers[c].p = peers[c];

      /* Connect to identity service */
      testpeers[c].identity_op = GNUNET_TESTBED_service_connect (NULL, testpeers[c].p,
          "identity", identity_completion_cb, NULL, &identity_connect_adapter,
          &identity_disconnect_adapter, &testpeers[c]);
    }
  }
}


int
main (int argc, char *argv[])
{
  ok = 1;
  /* Connecting initial topology */
  (void) GNUNET_TESTBED_test_run ("test-revocation",
				  "test_revocation.conf",
				  NUM_TEST_PEERS,
				  0, NULL, NULL,
				  &test_connection, NULL);
  return ok;
}

/* end of test_transport_dv.c */
