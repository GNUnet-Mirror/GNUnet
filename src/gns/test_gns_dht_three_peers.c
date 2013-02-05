/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file gns/test_gns_dht_threepeer.c
 * @brief tests dht lookup over 3 peers
 *
 * topology:
 * alice <----> bob <-----> dave
 *
 * alice queries for www.buddy.bob.gads
 *
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_disk_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_core_service.h"
#include "gnunet_dht_service.h"
#include "block_dns.h"
#include "gnunet_signatures.h"
#include "gnunet_namestore_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_gns_service.h"

#define ZONE_PUT_WAIT_TIME GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 10)

#define TEST_DOMAIN "www.buddy.bob.gads"
#define TEST_IP "1.1.1.1"
#define TEST_DAVE_PSEU "hagbard"


/* Timeout for entire testcase */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 60)
#define SETUP_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 60)

/* Global return value (0 for success, anything else for failure) */
static int ok;

/* Task handle to use to schedule test failure */
static GNUNET_SCHEDULER_TaskIdentifier die_task;

static GNUNET_SCHEDULER_TaskIdentifier wait_task;

static GNUNET_SCHEDULER_TaskIdentifier setup_task;

static struct GNUNET_CRYPTO_ShortHashCode dave_hash;

static struct GNUNET_CRYPTO_ShortHashCode bob_hash;

static struct GNUNET_TESTBED_Peer **cpeers;

static struct GNUNET_GNS_Handle *gh;
static struct GNUNET_GNS_LookupRequest *lookup_handle;

static struct GNUNET_TESTBED_Operation *get_cfg_ops[3];
static struct GNUNET_TESTBED_Operation *topology_op;
static struct GNUNET_CONFIGURATION_Handle *cfg_handles[3];
static struct GNUNET_NAMESTORE_Handle *nh[3];

static int dave_is_setup;
static int bob_is_setup;
static int alice_is_setup;

/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;
  int c;

  if (GNUNET_SCHEDULER_NO_TASK != wait_task)
  {
      GNUNET_SCHEDULER_cancel (wait_task);
      wait_task = GNUNET_SCHEDULER_NO_TASK;
  }

  for (c = 0; c < 3; c++)
  {
    if (NULL != nh[c])
    {
      GNUNET_NAMESTORE_disconnect(nh[c]);
      nh[c] = NULL;
    }

    if (NULL != get_cfg_ops[c])
    {
        GNUNET_TESTBED_operation_done(get_cfg_ops[c]);
        get_cfg_ops[c] = NULL;
    }
    if (NULL != cfg_handles[c])
    {
      GNUNET_CONFIGURATION_destroy (cfg_handles[c]);
      cfg_handles[c] = NULL;
    }
  }
  if (NULL != topology_op)
  {
    GNUNET_TESTBED_operation_done (topology_op);
    topology_op = NULL;
  }
  if (NULL != lookup_handle)
  {
    GNUNET_GNS_cancel_lookup_request (lookup_handle);
    lookup_handle = NULL;
  }
  if (NULL != gh)
  {
    GNUNET_GNS_disconnect(gh);
    gh = NULL;
  }
  
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Test failed \n");
  GNUNET_SCHEDULER_shutdown ();
  ok = 1;
}

static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Finished\n");
  int c;
  if (GNUNET_SCHEDULER_NO_TASK != die_task)
  {
      GNUNET_SCHEDULER_cancel (die_task);
      die_task = GNUNET_SCHEDULER_NO_TASK;
  }

  for (c = 0; c < 3; c++)
  {
    if (NULL != nh[c])
    {
      GNUNET_NAMESTORE_disconnect(nh[c]);
      nh[c] = NULL;
    }
    if (NULL != cfg_handles[c])
    {
      GNUNET_CONFIGURATION_destroy (cfg_handles[c]);
      cfg_handles[c] = NULL;
    }
  }

  if (NULL != gh)
  {
    GNUNET_GNS_disconnect(gh);
    gh = NULL;
  }

  if (0 == ok)
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Test ended successful\n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Test failed\n");
  GNUNET_SCHEDULER_shutdown ();
}

static void
setup_end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  setup_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Timeout during setup, test failed\n");

  if (NULL != topology_op)
  {
    GNUNET_TESTBED_operation_done (topology_op);
    topology_op = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
  ok = GNUNET_SYSERR;
}

static void
end_now ()
{
  GNUNET_SCHEDULER_add_now (&end, NULL);
}


static void
disconnect_ns (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  GNUNET_NAMESTORE_disconnect (cls);
  if (cls == nh[0])
    nh[0] = NULL;
  if (cls == nh[1])
    nh[1] = NULL;
  if (cls == nh[2])
    nh[2] = NULL;
}


static void
cont_ns (void* cls, int32_t s, const char* emsg)
{
  GNUNET_SCHEDULER_add_now (&disconnect_ns, cls);
}

static void
on_lookup_result(void *cls, uint32_t rd_count,
                 const struct GNUNET_NAMESTORE_RecordData *rd)
{
  int i;
  char* string_val;

  if (rd_count == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Lookup failed!\n");
    ok = 2;
  }
  else
  {
    ok = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "name: %s\n", (char*)cls);
    for (i=0; i<rd_count; i++)
    {
      string_val = GNUNET_NAMESTORE_value_to_string(rd[i].record_type,
                                                    rd[i].data,
                                                    rd[i].data_size);
      if (0 == strcmp(string_val, TEST_IP))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "%s correctly resolved to %s!\n", TEST_DOMAIN, string_val);
        ok = 0;
      }
      GNUNET_free (string_val);
    }
  }
  end_now ();
}

static void
commence_testing(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static int wait = 0;
  wait++;
  if ((ZONE_PUT_WAIT_TIME.rel_value / 1000) == wait)
  {
    fprintf (stderr, "\n");
    wait_task = GNUNET_SCHEDULER_NO_TASK;
    lookup_handle = GNUNET_GNS_lookup(gh, TEST_DOMAIN, GNUNET_GNS_RECORD_A,
                      GNUNET_NO,
                      NULL,
                      &on_lookup_result, TEST_DOMAIN);
    if (GNUNET_SCHEDULER_NO_TASK != die_task)
      GNUNET_SCHEDULER_cancel(die_task);
    die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, "from lookup");
  }
  else
  {
      fprintf (stderr, ".");
      wait_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &commence_testing, NULL);
  }
}

void
all_connected ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Created all connections! Waiting for PUTs\n");
  if (GNUNET_SCHEDULER_NO_TASK != setup_task)
  {
      GNUNET_SCHEDULER_cancel (setup_task);
      setup_task = GNUNET_SCHEDULER_NO_TASK;
  }
  wait_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &commence_testing, NULL);
}


static void connect_peers ()
{
  static int started;
  started ++;
  if (3 == started)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All peers started\n");

      topology_op = 
          GNUNET_TESTBED_overlay_configure_topology  (NULL, 3, cpeers, NULL,
                                                      NULL,
                                                      NULL,
                                                      GNUNET_TESTBED_TOPOLOGY_RING,
                                                      GNUNET_TESTBED_TOPOLOGY_OPTION_END);
  }
}

static int
setup_dave (const struct GNUNET_CONFIGURATION_Handle * cfg)
{
  char* keyfile;
  struct GNUNET_CRYPTO_RsaPrivateKey *key;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  struct in_addr *web;
  struct GNUNET_NAMESTORE_RecordData rd;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting up dave\n");
  cfg_handles[0] = GNUNET_CONFIGURATION_dup (cfg);
  GNUNET_assert (NULL != cfg_handles[0]);
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                            "ZONEKEY",
                                                            &keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    return GNUNET_SYSERR;
  }

  key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  if (NULL == key)
  {

    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    GNUNET_free (keyfile);
    return GNUNET_SYSERR;
  }
  nh[0] = GNUNET_NAMESTORE_connect (cfg_handles[0]);
  if (NULL == nh[0])
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to connect to namestore\n");
    GNUNET_CRYPTO_rsa_key_free (key);
    GNUNET_free (keyfile);
    return GNUNET_SYSERR;
  }

  GNUNET_CRYPTO_rsa_key_get_public (key, &pkey);
  GNUNET_CRYPTO_short_hash(&pkey, sizeof(pkey), &dave_hash);

  rd.expiration_time = UINT64_MAX;

  web = GNUNET_malloc(sizeof(struct in_addr));
  GNUNET_assert(1 == inet_pton (AF_INET, TEST_IP, web));
  rd.data_size = sizeof(struct in_addr);
  rd.data = web;
  rd.record_type = GNUNET_GNS_RECORD_A;
  rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY;

  GNUNET_NAMESTORE_record_create (nh[0], key, "www", &rd, NULL, NULL);

  rd.data_size = strlen(TEST_DAVE_PSEU);
  rd.data = TEST_DAVE_PSEU;
  rd.record_type = GNUNET_GNS_RECORD_PSEU;


  GNUNET_NAMESTORE_record_create (nh[0], key, GNUNET_GNS_MASTERZONE_STR, &rd, &cont_ns, nh[0]);

  GNUNET_CRYPTO_rsa_key_free(key);
  GNUNET_free(keyfile);
  GNUNET_free(web);
  dave_is_setup = GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting up dave done\n");
  return GNUNET_OK;
}

static int
setup_bob (const struct GNUNET_CONFIGURATION_Handle * cfg)
{
  char* keyfile;
  struct GNUNET_CRYPTO_RsaPrivateKey *key;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  struct GNUNET_NAMESTORE_RecordData rd;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting up bob\n");
  cfg_handles[1] = GNUNET_CONFIGURATION_dup (cfg);
  GNUNET_assert (NULL != cfg_handles[1]);
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                            "ZONEKEY",
                                                            &keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    return GNUNET_SYSERR;
  }

  key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  if (NULL == key)
  {

    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    GNUNET_free (keyfile);
    return GNUNET_SYSERR;
  }

  nh[1] = GNUNET_NAMESTORE_connect (cfg_handles[1]);
  if (NULL == nh[1])
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to connect to namestore\n");
    GNUNET_CRYPTO_rsa_key_free (key);
    GNUNET_free (keyfile);
    return GNUNET_SYSERR;
  }
  
  GNUNET_CRYPTO_rsa_key_get_public (key, &pkey);
  GNUNET_CRYPTO_short_hash(&pkey, sizeof(pkey), &bob_hash);

  rd.expiration_time = UINT64_MAX;
  rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
  rd.data = &dave_hash;
  rd.record_type = GNUNET_GNS_RECORD_PKEY;
  rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY;

  GNUNET_NAMESTORE_record_create (nh[1], key, "buddy", &rd, &cont_ns, nh[1]);

  GNUNET_CRYPTO_rsa_key_free(key);
  GNUNET_free(keyfile);
  bob_is_setup = GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting up bob done\n");
  return GNUNET_OK;
}

static int
setup_alice (const struct GNUNET_CONFIGURATION_Handle * cfg)
{
  char* keyfile;
  struct GNUNET_CRYPTO_RsaPrivateKey *key;
  struct GNUNET_NAMESTORE_RecordData rd;

  cfg_handles[2] = GNUNET_CONFIGURATION_dup (cfg);
  GNUNET_assert (NULL != cfg);
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                            "ZONEKEY",
                                                            &keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    return GNUNET_SYSERR;
  }

  key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  if (NULL == key)
  {

    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    GNUNET_free (keyfile);
    return GNUNET_SYSERR;
  }

  nh[2] = GNUNET_NAMESTORE_connect (cfg_handles[2]);
  if (NULL == nh[2])
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to connect to namestore\n");
    GNUNET_CRYPTO_rsa_key_free (key);
    GNUNET_free (keyfile);
    return GNUNET_SYSERR;
  }

  rd.expiration_time = UINT64_MAX;
  rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
  rd.data = &bob_hash;
  rd.record_type = GNUNET_GNS_RECORD_PKEY;
  rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY;

  GNUNET_NAMESTORE_record_create (nh[2], key, "bob", &rd, &cont_ns, nh[2]);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting up alice gns\n");
  gh = GNUNET_GNS_connect (cfg_handles[2]);
  if (NULL == gh)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to connect to gns\n");
    GNUNET_CRYPTO_rsa_key_free (key);
    GNUNET_free (keyfile);
    return GNUNET_SYSERR;
  }

  GNUNET_CRYPTO_rsa_key_free (key);
  GNUNET_free (keyfile);
  alice_is_setup = GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting up alice  done\n");
  return GNUNET_OK;
}

static void
end_badly_now ()
{
  if (GNUNET_SCHEDULER_NO_TASK != die_task)
    GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
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
peerinfo_cb (void *cb_cls, struct GNUNET_TESTBED_Operation *op,
	     const struct GNUNET_TESTBED_PeerInformation *pinfo,
	     const char *emsg)
{
  int res;
  GNUNET_assert (GNUNET_TESTBED_PIT_CONFIGURATION == pinfo->pit);
  if (GNUNET_NO == dave_is_setup)
    res = setup_dave (pinfo->result.cfg);
  else if (GNUNET_NO == bob_is_setup)
    res = setup_bob (pinfo->result.cfg);
  else
    res = setup_alice (pinfo->result.cfg);
  
  if (get_cfg_ops[0] == op)
    get_cfg_ops[0] = NULL;
  else if (get_cfg_ops[1] == op)
    get_cfg_ops[1] = NULL;
  else
    get_cfg_ops[2] = NULL;
  GNUNET_TESTBED_operation_done (op);
  op = NULL;
  if (GNUNET_SYSERR == res)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to setup peer \n");
    end_badly_now();
  }
  else
    connect_peers ();
  /*if (get_cfg_ops[0] == op)
  {
    GNUNET_assert (GNUNET_TESTBED_PIT_CONFIGURATION == pinfo->pit);
    res = setup_dave (pinfo->result.cfg);
    GNUNET_TESTBED_operation_done (get_cfg_ops[0]);
    get_cfg_ops[0] = NULL;
    if (GNUNET_SYSERR == res)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to setup dave \n");
      end_badly_now();
    }
    else
    {
      connect_peers ();
    }
  }
  else if (get_cfg_ops[1] == op)
  {
    GNUNET_assert (GNUNET_TESTBED_PIT_CONFIGURATION == pinfo->pit);
    res = setup_bob (pinfo->result.cfg);
    GNUNET_TESTBED_operation_done (get_cfg_ops[1]);
    get_cfg_ops[1] = NULL;
    if (GNUNET_SYSERR == res)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to setup dave \n");
      end_badly_now();
    }
    else
    {
      connect_peers ();
    }
  }
  else if (get_cfg_ops[2] == op)
  {
    GNUNET_assert (GNUNET_TESTBED_PIT_CONFIGURATION == pinfo->pit);
    res = setup_alice (pinfo->result.cfg);
    GNUNET_TESTBED_operation_done (get_cfg_ops[2]);
    get_cfg_ops[2] = NULL;
    if (GNUNET_SYSERR == res)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to setup dave \n");
      end_badly_now();
    }
    else
    {
      connect_peers ();
    }
  }*/
}


void testbed_master (void *cls,
                     unsigned int num_peers,
                     struct GNUNET_TESTBED_Peer **peers)
{
  GNUNET_assert (NULL != peers);
  cpeers = peers;

  setup_task = GNUNET_SCHEDULER_add_delayed (SETUP_TIMEOUT, &setup_end_badly, NULL);

  /* peer 0: dave */
  GNUNET_assert (NULL != peers[0]);
  get_cfg_ops[0] = GNUNET_TESTBED_peer_get_information (peers[0],
							GNUNET_TESTBED_PIT_CONFIGURATION,
							&peerinfo_cb, NULL);

  /* peer 1: bob */
  GNUNET_assert (NULL != peers[1]);
  get_cfg_ops[1] = GNUNET_TESTBED_peer_get_information (peers[1],
							GNUNET_TESTBED_PIT_CONFIGURATION,
							&peerinfo_cb, NULL );

  /* peer 2: alice */
  GNUNET_assert (NULL != peers[2]);
  get_cfg_ops[2] = GNUNET_TESTBED_peer_get_information (peers[2],
							GNUNET_TESTBED_PIT_CONFIGURATION,
							&peerinfo_cb, NULL);

}

void testbed_controller_cb (void *cls, const struct GNUNET_TESTBED_EventInformation *event)
{
  static int connections = 0;

  switch (event->type)
  {
    case GNUNET_TESTBED_ET_OPERATION_FINISHED:
      /* This part will still be called when
	 GNUNET_TESTBED_peer_get_information() succeeds. However, the code is
	 now more relevant in operation completion callback */
      break;
    case GNUNET_TESTBED_ET_CONNECT:
      connections ++;
      if (connections == 3)
      {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All peers connected\n");
          GNUNET_TESTBED_operation_done (topology_op);
          topology_op = NULL;
          all_connected ();
      }
      break;
    default:
      /* whatever ... */
      break;
  }
}

int
main (int argc, char *argv[])
{
  uint64_t event_mask;
  ok = 0;
  event_mask = 0;
  event_mask |= (1LL << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  (void) GNUNET_TESTBED_test_run ("test_gns_dht_three_peers", "test_gns_dht_default.conf",
                                  3, event_mask,
                                  &testbed_controller_cb, NULL,
                                  &testbed_master, NULL);
  if (GNUNET_SYSERR == ok)
    return 1;
  return 0;
}

/* end of test_gns_dht_three_peers.c */

