/*
   This file is part of GNUnet.
   Copyright (C) 2009, 2013, 2016 GNUnet e.V.

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
 * @file revocation/test_revocation.c
 * @brief base testcase for revocation exchange
 * @author Matthias Wachs
 * @author Christian Grothoff
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
  struct GNUNET_TESTBED_Operation *core_op;
  struct GNUNET_IDENTITY_Handle *idh;
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey;
  struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;
  struct GNUNET_CRYPTO_EcdsaSignature sig;
  struct GNUNET_IDENTITY_Operation *create_id_op;
  struct GNUNET_IDENTITY_EgoLookup *ego_lookup;
  struct GNUNET_REVOCATION_Handle *revok_handle;
  struct GNUNET_CORE_Handle *ch;
  uint64_t pow;
};

static struct TestPeer testpeers[2];

/**
 * Return value from main, set to 0 on success.
 */
static int ok;


static void
do_shutdown (void *cls)
{
  unsigned int c;

  for (c = 0; c < NUM_TEST_PEERS; c++)
  {
    if (NULL != testpeers[c].create_id_op)
    {
      GNUNET_IDENTITY_cancel (testpeers[c].create_id_op);
      testpeers[c].create_id_op = NULL;
    }
    if (NULL != testpeers[c].ego_lookup)
    {
      GNUNET_IDENTITY_ego_lookup_cancel (testpeers[c].ego_lookup);
      testpeers[c].ego_lookup = NULL;
    }
    if (NULL != testpeers[c].revok_handle)
    {
      GNUNET_REVOCATION_revoke_cancel (testpeers[c].revok_handle);
      testpeers[c].revok_handle = NULL;
    }
    if (NULL != testpeers[c].identity_op)
    {
      GNUNET_TESTBED_operation_done (testpeers[c].identity_op);
      testpeers[c].identity_op = NULL;
    }
    if (NULL != testpeers[c].core_op)
    {
      GNUNET_TESTBED_operation_done (testpeers[c].core_op);
      testpeers[c].core_op = NULL;
    }
  }
}


static void
check_revocation (void *cls);


static void
revocation_remote_cb (void *cls,
                      int is_valid)
{
  static int repeat = 0;

  if (GNUNET_NO == is_valid)
  {
    fprintf (stderr,
             "Local revocation successful\n");
    ok = 0;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (repeat < 10)
  {
    repeat++;
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                  &check_revocation,
                                  NULL);
    return;
  }
  fprintf (stderr,
           "Flooding of revocation failed\n");
  ok = 2;
  GNUNET_SCHEDULER_shutdown ();
}


static void
check_revocation (void *cls)
{
  GNUNET_REVOCATION_query (testpeers[0].cfg,
                           &testpeers[1].pubkey,
                           &revocation_remote_cb, NULL);
}


static void
revocation_cb (void *cls,
               int is_valid)
{
  testpeers[1].revok_handle = NULL;
  if (GNUNET_NO == is_valid)
  {
    fprintf (stderr,
             "Revocation successful\n");
    check_revocation (NULL);
  }
}


static void
ego_cb (void *cls,
        const struct GNUNET_IDENTITY_Ego *ego)
{
  static int completed = 0;

  if ((NULL != ego) && (cls == &testpeers[0]))
  {
    testpeers[0].ego_lookup = NULL;
    testpeers[0].privkey = GNUNET_IDENTITY_ego_get_private_key (ego);
    GNUNET_IDENTITY_ego_get_public_key (ego, &testpeers[0].pubkey);
    completed++;
  }
  if ((NULL != ego) && (cls == &testpeers[1]))
  {
    testpeers[1].ego_lookup = NULL;
    testpeers[1].privkey = GNUNET_IDENTITY_ego_get_private_key (ego);
    GNUNET_IDENTITY_ego_get_public_key (ego, &testpeers[1].pubkey);
    GNUNET_REVOCATION_sign_revocation (testpeers[1].privkey, &testpeers[1].sig);

    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
               "Calculating proof of work...\n");
    testpeers[1].pow = 0;
    int res = GNUNET_REVOCATION_check_pow (&testpeers[1].pubkey,
        testpeers[1].pow, 5);
    while (GNUNET_OK != res)
    {
      testpeers[1].pow++;
      res = GNUNET_REVOCATION_check_pow (&testpeers[1].pubkey,
                                         testpeers[1].pow,
                                         5);
    }
    fprintf (stderr,
             "Done calculating proof of work\n");
    completed++;
  }
  if (2 == completed)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
               "Egos retrieved\n");
    testpeers[1].revok_handle
      = GNUNET_REVOCATION_revoke (testpeers[1].cfg,
                                  &testpeers[1].pubkey,
                                  &testpeers[1].sig,
                                  testpeers[1].pow,
                                  &revocation_cb, NULL);
  }
}


static void
identity_create_cb (void *cls,
                    const char *emsg)
{
  static int completed = 0;

  if ((NULL == emsg) && (cls == &testpeers[0]))
  {
    testpeers[0].create_id_op = NULL;
    completed++;
  }
  if ((NULL == emsg) && (cls == &testpeers[1]))
  {
    testpeers[1].create_id_op = NULL;
    completed++;
  }
  if (2 != completed)
    return;
  fprintf (stderr,
           "Identities created\n");
  testpeers[0].ego_lookup = GNUNET_IDENTITY_ego_lookup (testpeers[0].cfg,
                                                        "client",
                                                        &ego_cb,
                                                        &testpeers[0]);
  testpeers[1].ego_lookup = GNUNET_IDENTITY_ego_lookup (testpeers[1].cfg,
                                                        "toberevoked",
                                                        &ego_cb,
                                                        &testpeers[1]);
}


static void
identity_completion_cb (void *cls,
                        struct GNUNET_TESTBED_Operation *op,
                        void *ca_result,
                        const char *emsg)
{
  static int completed = 0;

  completed++;
  if (NUM_TEST_PEERS != completed)
    return;
  fprintf (stderr,
           "All peers connected @ IDENTITY ...\n");
  testpeers[0].create_id_op
    = GNUNET_IDENTITY_create (testpeers[0].idh,
                              "client",
                              &identity_create_cb,
                              &testpeers[0]);
  testpeers[1].create_id_op
    = GNUNET_IDENTITY_create (testpeers[1].idh,
                              "toberevoked",
                              &identity_create_cb,
                              &testpeers[1]);
}


static void *
identity_connect_adapter (void *cls,
                          const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct TestPeer *me = cls;

  me->cfg = cfg;
  me->idh = GNUNET_IDENTITY_connect (cfg, NULL, NULL);
  if (NULL == me->idh)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to create IDENTITY handle \n");
  return me->idh;
}


static void
identity_disconnect_adapter (void *cls,
                             void *op_result)
{
  struct TestPeer *me = cls;
  GNUNET_IDENTITY_disconnect (me->idh);
  me->idh = NULL;
}


static void *
connect_cb (void *cls,
            const struct GNUNET_PeerIdentity *peer,
	    struct GNUNET_MQ_Handle *mq)
{
  static int connects = 0;

  connects++;
  if (NUM_TEST_PEERS * NUM_TEST_PEERS == connects)
  {
    fprintf (stderr,
             "All peers connected @ CORE ...\n");

    /* Connect to identity service */
    testpeers[0].identity_op
      = GNUNET_TESTBED_service_connect (NULL,
                                        testpeers[0].p, "identity",
                                        &identity_completion_cb, NULL,
                                        &identity_connect_adapter,
                                        &identity_disconnect_adapter,
                                        &testpeers[0]);
    testpeers[1].identity_op
      = GNUNET_TESTBED_service_connect (NULL,
                                        testpeers[1].p, "identity",
                                        *identity_completion_cb, NULL,
                                        &identity_connect_adapter,
                                        &identity_disconnect_adapter,
                                        &testpeers[1]);
  }
  return NULL;
}


static void
core_completion_cb (void *cls,
                    struct GNUNET_TESTBED_Operation *op,
                    void *ca_result,
                    const char *emsg)
{
  static int completed = 0;

  completed++;
  if (NUM_TEST_PEERS == completed)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Connected to CORE\n");
  }
}


static void *
core_connect_adapter (void *cls,
                      const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct TestPeer *me = cls;

  me->cfg = cfg;
  me->ch = GNUNET_CORE_connect (cfg,
				me,
				NULL,
                                &connect_cb,
				NULL,
                                NULL);
  if (NULL == me->ch)
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Failed to create CORE handle \n");
  return me->ch;
}


static void
core_disconnect_adapter (void *cls,
                         void *op_result)
{
  struct TestPeer *me = cls;

  GNUNET_CORE_disconnect (me->ch);
  me->ch = NULL;
}


static void
test_connection (void *cls,
                 struct GNUNET_TESTBED_RunHandle *h,
                 unsigned int num_peers,
                 struct GNUNET_TESTBED_Peer **peers,
                 unsigned int links_succeeded,
                 unsigned int links_failed)
{
  unsigned int c;

  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  if (NUM_TEST_PEERS != num_peers)
  {
    ok = 4;
    fprintf (stderr,
             "Only %u out of %u peers were started ...\n",
             num_peers,
             NUM_TEST_PEERS);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
   /* We are generating a CLIQUE */
  if (NUM_TEST_PEERS * (NUM_TEST_PEERS -1) == links_succeeded)
  {
    fprintf (stderr,
             "Testbed connected peers, initializing test\n");
    for (c = 0; c < num_peers; c++)
    {
      testpeers[c].p = peers[c];
      testpeers[c].core_op
        = GNUNET_TESTBED_service_connect (NULL,
                                          testpeers[c].p,
                                          "core",
                                          &core_completion_cb, NULL,
                                          &core_connect_adapter,
                                          &core_disconnect_adapter,
                                          &testpeers[c]);
    }
  }
  else
  {
    fprintf (stderr,
             "Testbed failed to connect peers\n");
    ok = 5;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


int
main (int argc,
      char *argv[])
{
  ok = 1;
  /* Connecting initial topology */
  (void) GNUNET_TESTBED_test_run ("test-revocation",
                                  "test_revocation.conf",
                                  NUM_TEST_PEERS, 0,
                                  NULL, NULL,
                                  &test_connection, NULL);
  return ok;
}

/* end of test_revocation.c */
