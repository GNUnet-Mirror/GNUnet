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
#include "gnunet_multicast_service.h"

#define NUM_PEERS 3

struct multicast_peer
{
  int peer; /* peer number */
  struct GNUNET_TESTBED_Operation *op; /* not yet in use */
  struct GNUNET_TESTBED_Operation *pi_op; /* not yet in use */
  uint8_t test_ok;
};

static void service_connect (void *cls,
                             struct GNUNET_TESTBED_Operation *op,
                             void *ca_result,
                             const char *emsg);

static struct multicast_peer **mc_peers;
static struct GNUNET_TESTBED_Peer **peers;

// FIXME: refactor
static struct GNUNET_TESTBED_Operation *op[NUM_PEERS];
static struct GNUNET_TESTBED_Operation *pi_op[NUM_PEERS];
static const struct GNUNET_PeerIdentity *peer_id[NUM_PEERS];

static struct GNUNET_MULTICAST_Origin *origin;
static struct GNUNET_MULTICAST_Member *member[NUM_PEERS]; /* first element always empty */

static struct GNUNET_SCHEDULER_Task *timeout_tid;

static struct GNUNET_CRYPTO_EddsaPrivateKey *group_key;
static struct GNUNET_CRYPTO_EddsaPublicKey *group_pub_key;

static struct GNUNET_CRYPTO_EcdsaPrivateKey *member_key[NUM_PEERS];
static struct GNUNET_CRYPTO_EcdsaPublicKey *member_pub_key[NUM_PEERS];


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
  if (NULL != mc_peers)
  {
    for (int i=0; i < NUM_PEERS; i++)
    {
      GNUNET_free (mc_peers[i]);
      mc_peers[i] = NULL;
    }
    GNUNET_free (mc_peers);
  }

  for (int i=0;i<NUM_PEERS;i++)
  {
    if (NULL != op[i])
    {
      GNUNET_TESTBED_operation_done(op[i]);
      op[i] = NULL;
    }
    if (NULL != pi_op[i])
    {
      GNUNET_TESTBED_operation_done (pi_op[i]);
      pi_op[i] = NULL;
    }
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
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
	      "Timeout!\n");
  result = GNUNET_SYSERR;
  GNUNET_SCHEDULER_shutdown ();
}


static void
member_join_request (void *cls,
                     const struct GNUNET_CRYPTO_EcdsaPublicKey *member_pub_key,
                     const struct GNUNET_MessageHeader *join_msg,
                     struct GNUNET_MULTICAST_JoinHandle *jh)
{
  struct multicast_peer *mc_peer = (struct multicast_peer*)cls;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peer #%u sent a join request.\n", mc_peer->peer);

}


static int 
notify (void *cls,
        size_t *data_size,
        void *data)
{
  struct multicast_peer *mc_peer = (struct multicast_peer*)cls;

  char text[] = "ping";
  *data_size = strlen(text)+1;
  GNUNET_memcpy(data, text, *data_size);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
              "Peer #%u sents message to origin: %s\n", mc_peer->peer, text);

  return GNUNET_YES;
}


static void
member_join_decision (void *cls,
                      int is_admitted,
                      const struct GNUNET_PeerIdentity *peer,
                      uint16_t relay_count,
                      const struct GNUNET_PeerIdentity *relays,
                      const struct GNUNET_MessageHeader *join_msg)
{
  struct multicast_peer *mc_peer = (struct multicast_peer*)cls;
  struct GNUNET_MULTICAST_MemberTransmitHandle *req;
  
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
              "Peer #%u received a decision from origin: %s\n", mc_peer->peer, (GNUNET_YES == is_admitted)?"accepted":"rejected");
  
  if (GNUNET_YES == is_admitted)
  {
    req = GNUNET_MULTICAST_member_to_origin (member[mc_peer->peer],
                                             0,
                                             notify,
                                             cls);
    
  }
}


static void
member_replay_frag ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "member replay frag...\n");
}


static void
member_replay_msg ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "member replay msg...\n");
}


static void
member_message (void *cls, 
                const struct GNUNET_MULTICAST_MessageHeader *msg)
{
  struct multicast_peer *mc_peer = (struct multicast_peer*)cls;

  if (0 != strncmp ("pong", (char *)&msg[1], 4)) 
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "peer #%i did not receive pong\n", 
                mc_peer->peer);

    result = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "peer #%i receives: %s\n", 
              mc_peer->peer,
              (char *)&msg[1]);

  mc_peer->test_ok = GNUNET_OK;

  // FIXME: ugly test function
  /*
  for (int i=1; i<NUM_PEERS; i++)
    if (!mc_peers[i]->test_ok)
      return;

  result = GNUNET_YES;
  GNUNET_SCHEDULER_shutdown();
  */
}


static void
origin_join_request (void *cls,
                 const struct GNUNET_CRYPTO_EcdsaPublicKey *member_pub_key,
                 const struct GNUNET_MessageHeader *join_msg,
                 struct GNUNET_MULTICAST_JoinHandle *jh)
{
  struct GNUNET_MessageHeader *join_resp;

  uint8_t data_size = ntohs (join_msg->size);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
              "origin got a join request...\n");
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
              "origin receives: '%s'\n", (char *)&join_msg[1]);

  char data[] = "Come in!";
  data_size = strlen (data) + 1;
  join_resp = GNUNET_malloc (sizeof (join_resp) + data_size);
  join_resp->size = htons (sizeof (join_resp) + data_size);
  join_resp->type = htons (123);
  GNUNET_memcpy (&join_resp[1], data, data_size);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
              "origin sends: '%s'\n", data);

  GNUNET_MULTICAST_join_decision (jh,
                                  GNUNET_YES,
                                  0,
                                  NULL,
                                  join_resp);

  result = GNUNET_OK;
}


static void
origin_replay_frag (void *cls,
                    const struct GNUNET_CRYPTO_EcdsaPublicKey *member_pub_key,
                    uint64_t fragment_id,
                    uint64_t flags,
                    struct GNUNET_MULTICAST_ReplayHandle *rh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "origin replay fraq msg\n");
}


static void
origin_replay_msg (void *cls,
                   const struct GNUNET_CRYPTO_EcdsaPublicKey *member_pub_key,
                   uint64_t message_id,
                   uint64_t fragment_offset,
                   uint64_t flags,
                   struct GNUNET_MULTICAST_ReplayHandle *rh) 
{

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "origin replay msg\n");
}


static int
origin_notify (void *cls, 
               size_t *data_size, 
               void *data)
{
  char text[] = "pong";
  *data_size = strlen(text)+1;
  memcpy(data, text, *data_size); 

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "origin sends (to all): %s\n", text);

  return GNUNET_YES; 
}


static void
origin_request (void *cls,
                const struct GNUNET_MULTICAST_RequestHeader *req)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "origin receives: %s\n", (char *)&req[1]);
  
  if (0 != strncmp ("ping", (char *)&req[1], 4)) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "origin didn't reveice a correct request");
  }

  GNUNET_MULTICAST_origin_to_all (origin,
                                  0,
                                  0,
                                  origin_notify,
                                  cls);
}


static void
origin_message (void *cls,
                const struct GNUNET_MULTICAST_MessageHeader *msg) 
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "origin message msg\n");
}


static void
multicast_da (void *cls,
              void *op_result)
{
  struct multicast_peer *mc_peer = (struct multicast_peer*)cls;

  if (0 == mc_peer->peer)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Origin closes multicast group\n");

    GNUNET_MULTICAST_origin_stop (origin, NULL, cls);
  }
  else 
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "peer #%u parting from multicast group\n", mc_peer->peer);

    GNUNET_MULTICAST_member_part (member[mc_peer->peer], NULL, cls);
  }
}


static void *
multicast_ca (void *cls,
              const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct multicast_peer *mc_peer = (struct multicast_peer*)cls;
  struct GNUNET_MessageHeader *join_msg;
  char data[64];
  
  if (0 == mc_peer->peer)
  {
    group_pub_key = GNUNET_new (struct GNUNET_CRYPTO_EddsaPublicKey);
    group_key = GNUNET_CRYPTO_eddsa_key_create ();
    GNUNET_CRYPTO_eddsa_key_get_public (group_key, group_pub_key);

    return GNUNET_MULTICAST_origin_start (cfg,
                                          group_key,
                                          0,
                                          origin_join_request,
                                          origin_replay_frag,
                                          origin_replay_msg,
                                          origin_request,
                                          origin_message,
                                          cls);
  }
  else
  {
    // Get members keys
    member_pub_key[mc_peer->peer] = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPublicKey);
    member_key[mc_peer->peer] = GNUNET_CRYPTO_ecdsa_key_create ();
    GNUNET_CRYPTO_ecdsa_key_get_public (member_key[mc_peer->peer], member_pub_key[mc_peer->peer]);
    
    sprintf(data, "Hi, I am peer #%u. Can I enter?", mc_peer->peer);
    uint8_t data_size = strlen (data) + 1;
    join_msg = GNUNET_malloc (sizeof (join_msg) + data_size);
    join_msg->size = htons (sizeof (join_msg) + data_size);
    join_msg->type = htons (123);
    GNUNET_memcpy (&join_msg[1], data, data_size);

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Peer #%u tries to join multicast group\n", mc_peer->peer);

    return GNUNET_MULTICAST_member_join (cfg,
                                         group_pub_key,
                                         member_key[mc_peer->peer],
                                         peer_id[0],
                                         0,
                                         NULL,
                                         join_msg, /* join message */
                                         member_join_request,
                                         member_join_decision,
                                         member_replay_frag,
                                         member_replay_msg,
                                         member_message,
                                         cls);
  }
}


static void
peer_information_cb (void *cls,
                     struct GNUNET_TESTBED_Operation *operation,
                     const struct GNUNET_TESTBED_PeerInformation *pinfo,
                     const char *emsg)
{
  struct multicast_peer *mc_peer = (struct multicast_peer*)cls;

  if (NULL == pinfo) {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "got no peer information\n");
    result = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
  }

  peer_id[mc_peer->peer] = pinfo->result.id;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Got peer information of %s (%s)\n", (0==mc_peer->peer)?"origin":"member" ,GNUNET_i2s(pinfo->result.id));

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Create peer #%u\n", mc_peer->peer);

  if (0 != mc_peer->peer)
  {
    /* connect to multicast service of members */
    op[mc_peer->peer] = GNUNET_TESTBED_service_connect (NULL,                    /* Closure for operation */
                                                        peers[mc_peer->peer],                /* The peer whose service to connect to */
                                                        "multicast",             /* The name of the service */
                                                        service_connect,         /* callback to call after a handle to service
                                                                                    is opened */
                                                        cls,               /* closure for the above callback */
                                                        multicast_ca,            /* callback to call with peer's configuration;
                                                                                    this should open the needed service connection */
                                                        multicast_da,            /* callback to be called when closing the
                                                                                    opened service connection */
                                                        cls);              /* closure for the above two callbacks */
  }
}


static void
service_connect (void *cls,
                 struct GNUNET_TESTBED_Operation *op,
                 void *ca_result,
                 const char *emsg)
{
  struct multicast_peer *mc_peer = (struct multicast_peer*)cls;

  if (NULL == ca_result)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
                "Connection adapter not created for peer #%u\n", mc_peer->peer);
    result = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown();
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
              "Connected to multicast service of peer #%u\n", mc_peer->peer);

  if (0 == mc_peer->peer)
  {
    origin = ca_result;

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Connected to multicast service of origin\n");

    // Get GNUnet identity of members
    for (int i = 0; i<NUM_PEERS; i++) 
    {
      pi_op[i] = GNUNET_TESTBED_peer_get_information (peers[i],
                                                      GNUNET_TESTBED_PIT_IDENTITY,
                                                      peer_information_cb,
                                                      mc_peers[i]);
    }
  }
  else 
  {
    member[mc_peer->peer] = ca_result;
  }
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
testbed_master (void *cls,
     struct GNUNET_TESTBED_RunHandle *h,
     unsigned int num_peers,
     struct GNUNET_TESTBED_Peer **p,
     unsigned int links_succeeded,
     unsigned int links_failed)
{
  /* Testbed is ready with peers running and connected in a pre-defined overlay
     topology (FIXME)  */
  
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Connected to testbed_master()\n");

  peers = p;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Create origin peer\n");

  mc_peers = GNUNET_new_array (NUM_PEERS, struct multicast_peer*);

  // Create test contexts for members
  for (int i = 0; i<NUM_PEERS; i++) 
  {
    mc_peers[i] = GNUNET_new (struct multicast_peer);
    mc_peers[i]->peer = i;
    mc_peers[i]->test_ok = GNUNET_NO;
  }

  op[0] = GNUNET_TESTBED_service_connect (NULL,                    /* Closure for operation */
                                          peers[0],                /* The peer whose service to connect to */
                                          "multicast",             /* The name of the service */
                                          service_connect,   /* callback to call after a handle to service
                                                                 is opened */
                                          mc_peers[0],                    /* closure for the above callback */
                                          multicast_ca,      /* callback to call with peer's configuration;
                                                                 this should open the needed service connection */
                                          multicast_da,     /* callback to be called when closing the
                                                                opened service connection */
                                          mc_peers[0]);                   /* closure for the above two callbacks */

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL); /* Schedule a new task on shutdown */

  /* Schedule the shutdown task with a delay of a few Seconds */
  timeout_tid = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 80),
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
       testbed_master, /* continuation callback to be called when testbed setup is complete */
       NULL); /* Closure for the test_master callback */
  if ( (GNUNET_OK != ret) || (GNUNET_OK != result) )
    return 1;
  return 0;
}

/* end of test_multicast_multipeer.c */
