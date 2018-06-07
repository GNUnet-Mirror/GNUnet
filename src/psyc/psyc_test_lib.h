/*
 * This file is part of GNUnet
 * Copyright (C) 2013 GNUnet e.V.
 *
 * GNUnet is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file psyc/test_psyc_api_join.c
 * @brief library for writing psyc tests
 * @author xrs
 */

#define MAX_TESTBED_OPS 32

struct pctx
{
  int idx;
  
  struct GNUNET_TESTBED_Peer *testbed_peer;
  
  const struct GNUNET_PeerIdentity *peer_id;

  const struct GNUNET_PeerIdentity *peer_id_master;

  /**
   * Used to simulate egos (not peerid)
   */
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *id_key;

  const struct GNUNET_CRYPTO_EcdsaPublicKey *id_pub_key;

  /**
   * Used to store either GNUNET_PSYC_Master or GNUNET_PSYC_Slave handle
   */
  void *psyc;

  struct GNUNET_PSYC_Channel *channel;

  const struct GNUNET_CRYPTO_EddsaPrivateKey *channel_key;

  struct GNUNET_CRYPTO_EddsaPublicKey *channel_pub_key;

  int test_ok;
};

static struct GNUNET_SCHEDULER_Task *timeout_task_id;

static int result = GNUNET_SYSERR;

static struct GNUNET_TESTBED_Operation *op[MAX_TESTBED_OPS];

static int op_cnt = 0;

