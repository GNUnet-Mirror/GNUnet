/*
 * This file is part of GNUnet
 * Copyright (C) 2013 GNUnet e.V.
 *
 * GNUnet is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Affero General Public License for more details.
 */

/**
 * @file psyc/test_psyc2.c
 * @brief Testbed test for the PSYC API.
 * @author xrs
 */

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_psyc_util_lib.h"
#include "gnunet_psyc_service.h"

#define PEERS_REQUESTED 2

static int result;

static struct GNUNET_SCHEDULER_Task *timeout_tid;
static struct pctx **pctx;

static struct GNUNET_CRYPTO_EddsaPrivateKey *channel_key;
static struct GNUNET_CRYPTO_EddsaPublicKey channel_pub_key;

static struct GNUNET_CRYPTO_EcdsaPrivateKey *slave_key;
static struct GNUNET_CRYPTO_EcdsaPublicKey slave_pub_key;

/**
 * Task To perform tests
 */
static struct GNUNET_SCHEDULER_Task *test_task;

/**
 * Peer id couter
 */
static unsigned int pids;

struct pctx
{
  int idx;
  struct GNUNET_TESTBED_Peer *peer;
  const struct GNUNET_PeerIdentity *id;

  struct GNUNET_TESTBED_Operation *op; 

  /**
   * psyc service handle
   */
  void *psyc;
  struct GNUNET_PSYC_Master *mst;
  struct GNUNET_PSYC_Slave *slv;

  /**
   * result for test on peer
   */
  int test_ok;
};

static void
shutdown_task (void *cls)
{
  if (NULL != pctx)
  {
    if (NULL != pctx[0]->mst)
      GNUNET_PSYC_master_stop (pctx[0]->mst, GNUNET_NO, NULL, NULL);  

    for (int i=0; i < PEERS_REQUESTED; i++)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Operation done.\n");
      GNUNET_TESTBED_operation_done (pctx[i]->op);
      GNUNET_free_non_null (pctx[i]);
    }
    GNUNET_free (pctx);
  }

  if (NULL != timeout_tid)
    GNUNET_SCHEDULER_cancel (timeout_tid);
}

static void
timeout_task (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Timeout!\n");
  result = GNUNET_SYSERR;
  GNUNET_SCHEDULER_shutdown ();
}

static void 
start_test (void *cls)
{
}

static void
pinfo_cb (void *cls,
          struct GNUNET_TESTBED_Operation *operation,
          const struct GNUNET_TESTBED_PeerInformation *pinfo,
          const char *emsg)
{
  struct pctx *pc = (struct pctx*) cls;

  pc->id = pinfo->result.id;

  pids++;
  if (pids < (PEERS_REQUESTED - 1))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got all IDs, starting test\n");
  test_task = GNUNET_SCHEDULER_add_now (&start_test, NULL);
}

static void
mst_start_cb () 
{
}

static void 
join_request_cb ()
{
}

static void
mst_message_cb ()
{
}

static void
mst_message_part_cb ()
{
}

static void 
slv_message_cb ()
{
}

static void 
slv_message_part_cb ()
{
}

static void
slv_connect_cb () 
{
}

static void
join_decision_cb ()
{
}

static void *
psyc_ca (void *cls,
         const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_PSYC_Message *join_msg = NULL;
  struct pctx *pc = (struct pctx *) cls;

  if (0 == pc->idx)
  {
    pc->mst = GNUNET_PSYC_master_start (cfg, channel_key, 
                                        GNUNET_PSYC_CHANNEL_PRIVATE,
                                        &mst_start_cb, &join_request_cb,
                                        &mst_message_cb, &mst_message_part_cb,
                                        NULL);
    return pc->mst;
  }

  pc->slv = GNUNET_PSYC_slave_join (cfg, &channel_pub_key, slave_key,
                                    GNUNET_PSYC_SLAVE_JOIN_NONE,
                                    &pid, 0, NULL, &slv_message_cb, 
                                    &slv_message_part_cb,
                                    &slv_connect_cb, &join_decision_cb, 
                                    NULL, join_msg);
  return pc->slv;
} 

static void
psyc_da (void *cls,
         void *op_result)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Disconnected from service.\n");
} 

static void
service_connect (void *cls,
                 struct GNUNET_TESTBED_Operation *op,
                 void *ca_result,
                 const char *emsg)
{
  struct pctx *pc = (struct pctx *) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Connected to service\n");

  GNUNET_assert (NULL != ca_result);

  // FIXME: we need a simple service handle to connect to the service, then 
  // get peer information and AFTER that make PSYC ops. Compare to CADET. 
  pc->psyc = ca_result;

  GNUNET_TESTBED_peer_get_information (pc->peer, 
                                       GNUNET_TESTBED_PIT_IDENTITY, 
                                       pinfo_cb, pc);
}

static void
testbed_master (void *cls,
     struct GNUNET_TESTBED_RunHandle *h,
     unsigned int num_peers,
     struct GNUNET_TESTBED_Peer **p,
     unsigned int links_succeeded,
     unsigned int links_failed)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Connected to testbed_master()\n");

  // Create ctx for peers
  pctx = GNUNET_new_array (PEERS_REQUESTED, struct pctx*);
  for (int i = 0; i<PEERS_REQUESTED; i++) 
  {
    pctx[i] = GNUNET_new (struct pctx);
    pctx[i]->idx = i;
    pctx[i]->peer = p[i];
    pctx[i]->id = NULL;
    pctx[i]->mst = NULL;
    pctx[i]->op = NULL;
    pctx[i]->test_ok = GNUNET_NO;
  }

  channel_key = GNUNET_CRYPTO_eddsa_key_create ();
  slave_key = GNUNET_CRYPTO_ecdsa_key_create ();

  GNUNET_CRYPTO_eddsa_key_get_public (channel_key, &channel_pub_key);
  GNUNET_CRYPTO_ecdsa_key_get_public (slave_key, &slave_pub_key);

  pctx[0]->op = 
    GNUNET_TESTBED_service_connect (NULL, p[0], "psyc", service_connect, 
                                    pctx[0], psyc_ca, psyc_da, pctx[0]);

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL); 

  timeout_tid = 
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5),
                                  &timeout_task, NULL);
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "test\n");

  result = GNUNET_SYSERR;

  ret = GNUNET_TESTBED_test_run ("test-psyc2", "test_psyc.conf",
                                 PEERS_REQUESTED, 0LL, NULL, NULL, 
                                 testbed_master, NULL);

  if ((GNUNET_OK != ret) || (GNUNET_OK != result))
    return 1;

  return 0;
}

/* end of test-psyc2.c */
