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
 * @file multicast/test_multicast_2peers.c
 * @brief Tests for the Multicast API with two peers doing the ping 
 *        pong test.
 * @author xrs
 */

#include <inttypes.h>

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_multicast_service.h"

#define NUM_PEERS 2

static struct GNUNET_TESTBED_Operation *op0;
static struct GNUNET_TESTBED_Operation *op1;
static struct GNUNET_TESTBED_Operation *pi_op0;
static struct GNUNET_TESTBED_Operation *pi_op1;

static struct GNUNET_TESTBED_Peer **peers;
const struct GNUNET_PeerIdentity *peer_id[2];

static struct GNUNET_SCHEDULER_Task *timeout_tid;

static struct GNUNET_MULTICAST_Origin *origin;
static struct GNUNET_MULTICAST_Member *member;

struct GNUNET_CRYPTO_EddsaPrivateKey *group_key;
struct GNUNET_CRYPTO_EddsaPublicKey group_pub_key;

struct GNUNET_CRYPTO_EcdsaPrivateKey *member_key;
struct GNUNET_CRYPTO_EcdsaPublicKey member_pub_key;

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
  if (NULL != op0)
  {
    GNUNET_TESTBED_operation_done (op0);
    op0 = NULL;
  }
  if (NULL != op1)
  {
    GNUNET_TESTBED_operation_done (op1);
    op1 = NULL;
  }
  if (NULL != pi_op0)
  {
    GNUNET_TESTBED_operation_done (pi_op0);
    pi_op0 = NULL;
  }
  if (NULL != pi_op1)
  {
    GNUNET_TESTBED_operation_done (pi_op1);
    pi_op1 = NULL;
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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Member sent a join request.\n");

}

int notify (void *cls,
            size_t *data_size,
            void *data)
{

  char text[] = "ping";
  *data_size = strlen(text)+1;
  GNUNET_memcpy(data, text, *data_size);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
              "Member sents message to origin: %s\n", text);

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
  struct GNUNET_MULTICAST_MemberTransmitHandle *req;
  
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
              "Member received a decision from origin: %s\n", (GNUNET_YES == is_admitted)?"accepted":"rejected");
  
  if (GNUNET_YES == is_admitted)
  {
    req = GNUNET_MULTICAST_member_to_origin (member,
                                             0,
                                             notify,
                                             NULL);
  }
}

static void
member_message (void *cls, 
                const struct GNUNET_MULTICAST_MessageHeader *msg)
{
  if (0 != strncmp ("pong", (char *)&msg[1], 4)) 
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "member did not receive pong\n");
    result = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "member receives: %s\n", (char *)&msg[1]);

  // Testcase ends here.
  result = GNUNET_YES;
  GNUNET_SCHEDULER_shutdown ();
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

int
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
  
  if (0 != strncmp ("ping", (char *)&req[1], 4)) 
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "origin didn't reveice a correct request");

  GNUNET_MULTICAST_origin_to_all (origin,
                                  0,
                                  0,
                                  origin_notify,
                                  NULL);
}

static void
origin_message (void *cls,
                const struct GNUNET_MULTICAST_MessageHeader *msg) 
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "origin message msg\n");
}


static void
service_connect1 (void *cls,
                  struct GNUNET_TESTBED_Operation *op,
                  void *ca_result,
                  const char *emsg)
{
  member = ca_result;

  if (NULL != member) 
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Connected to multicast service of member\n");
  }
  else
  {
    result = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
  }
}

static void
multicast_da1 (void *cls,
               void * op_result)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Member parting from multicast group\n");

  GNUNET_MULTICAST_member_part (member, NULL, NULL);
}


static void *
multicast_ca1 (void *cls,
               const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_MessageHeader *join_msg;

  // Get members keys
  member_key = GNUNET_CRYPTO_ecdsa_key_create ();
  GNUNET_CRYPTO_ecdsa_key_get_public (member_key, &member_pub_key);
  
  char data[] = "Hi, can I enter?";
  uint8_t data_size = strlen (data) + 1;
  join_msg = GNUNET_malloc (sizeof (join_msg) + data_size);
  join_msg->size = htons (sizeof (join_msg) + data_size);
  join_msg->type = htons (123);
  GNUNET_memcpy (&join_msg[1], data, data_size);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Members tries to join multicast group\n");

  return GNUNET_MULTICAST_member_join (cfg,
                                       &group_pub_key,
                                       member_key,
                                       peer_id[0],
                                       0,
                                       NULL,
                                       join_msg, /* join message */
                                       member_join_request,
                                       member_join_decision,
                                       NULL, /* no test for member_replay_frag */
                                       NULL, /* no test for member_replay_msg */
                                       member_message,
                                       NULL);
}


static void
peer_information_cb (void *cls,
                     struct GNUNET_TESTBED_Operation *op,
                     const struct GNUNET_TESTBED_PeerInformation *pinfo,
                     const char *emsg)
{
  int i = (int) (long) cls;

  if (NULL == pinfo) 
  {
    result = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
  }

  peer_id[i] = pinfo->result.id;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Got peer information of %s (%s)\n", (0==i)?"origin":"member" ,GNUNET_i2s(pinfo->result.id));

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Create member peer\n");

  if (0 == i) 
  {
    /* connect to multicast service of member */
    op1 = GNUNET_TESTBED_service_connect (NULL,                    /* Closure for operation */
                                          peers[1],                /* The peer whose service to connect to */
                                          "multicast",             /* The name of the service */
                                          service_connect1,   /* callback to call after a handle to service
                                                                 is opened */
                                          NULL,                    /* closure for the above callback */
                                          multicast_ca1,      /* callback to call with peer's configuration;
                                                                 this should open the needed service connection */
                                          multicast_da1,     /* callback to be called when closing the
                                                                opened service connection */
                                          NULL);                   /* closure for the above two callbacks */
    }
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
service_connect0 (void *cls,
                  struct GNUNET_TESTBED_Operation *op,
                  void *ca_result,
                  const char *emsg)
{
  origin = ca_result;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Connected to multicast service of origin\n");

  // Get GNUnet identity of origin
  pi_op0 = GNUNET_TESTBED_peer_get_information (peers[0],
                                               GNUNET_TESTBED_PIT_IDENTITY,
                                               peer_information_cb,
                                               (void *) 0);
  // Get GNUnet identity of member
  pi_op1 = GNUNET_TESTBED_peer_get_information (peers[1],
                                               GNUNET_TESTBED_PIT_IDENTITY,
                                               peer_information_cb,
                                               (void *) 1);

  /* Connection to service successful. Here we'd usually do something with
   * the service. */
  result = GNUNET_OK;
  //GNUNET_SCHEDULER_shutdown (); /* Also kills the testbed */
}



/**
 * Function run when service multicast has started and is providing us
 * with a configuration file.
 */
static void *
multicast_ca0 (void *cls,
               const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  group_key = GNUNET_CRYPTO_eddsa_key_create ();
  GNUNET_CRYPTO_eddsa_key_get_public (group_key, &group_pub_key);

  return GNUNET_MULTICAST_origin_start (cfg,
                                        group_key,
                                        0,
                                        origin_join_request,
                                        NULL, /* no test for origin_replay_frag */
                                        NULL, /* no test for origin_replay_msg */
                                        origin_request,
                                        origin_message,
                                        NULL);
}

static void
multicast_da0 (void *cls,
               void *op_result)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Origin closes multicast group\n");

  GNUNET_MULTICAST_origin_stop (origin, NULL, NULL);
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
  op0 = GNUNET_TESTBED_service_connect (NULL,                    /* Closure for operation */
                                        peers[0],                /* The peer whose service to connect to */
                                        "multicast",             /* The name of the service */
                                        service_connect0,   /* callback to call after a handle to service
                                                               is opened */
                                        NULL,                    /* closure for the above callback */
                                        multicast_ca0,      /* callback to call with peer's configuration;
                                                               this should open the needed service connection */
                                        multicast_da0,     /* callback to be called when closing the
                                                              opened service connection */
                                        NULL);                   /* closure for the above two callbacks */

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL); /* Schedule a new task on shutdown */

  /* Schedule the shutdown task with a delay of a few Seconds */
  timeout_tid = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 50),
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
