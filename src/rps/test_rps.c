/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2012 Christian Grothoff (and other contributing authors)

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
 * @file rps/test_rps_multipeer.c
 * @brief Testcase for the random peer sampling service.  Starts
 *        a peergroup with a given number of peers, then waits to
 *        receive size pushes/pulls from each peer.  Expects to wait
 *        for one message from each peer.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"

#include "gnunet_rps_service.h"
#include "rps-test_util.h"
#include "gnunet-service-rps_sampler_elem.h"

#include <inttypes.h>


/**
 * How many peers do we start?
 */
uint32_t num_peers;

/**
 * How long do we run the test?
 */
//#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)
static struct GNUNET_TIME_Relative timeout;


/**
 * Portion of malicious peers
 */
static double portion = .1;

/**
 * Type of malicious peer to test
 */
static unsigned int mal_type = 0;

/**
 * Handles to all of the running peers
 */
static struct GNUNET_TESTBED_Peer **testbed_peers;


/**
 * Operation map entry
 */
struct OpListEntry
{
  /**
   * DLL next ptr
   */
  struct OpListEntry *next;

  /**
   * DLL prev ptr
   */
  struct OpListEntry *prev;

  /**
   * The testbed operation
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Depending on whether we start or stop NSE service at the peer set this to 1
   * or -1
   */
  int delta;

  /**
   * Index of the regarding peer
   */
  unsigned int index;
};

/**
 * OpList DLL head
 */
static struct OpListEntry *oplist_head;

/**
 * OpList DLL tail
 */
static struct OpListEntry *oplist_tail;


/**
 * Information we track for each peer.
 */
struct RPSPeer
{
  /**
   * Index of the peer.
   */
  unsigned int index;

  /**
   * Handle for RPS connect operation.
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Handle to RPS service.
   */
  struct GNUNET_RPS_Handle *rps_handle;

  /**
   * ID of the peer.
   */
  struct GNUNET_PeerIdentity *peer_id;

  /**
   * A request handle to check for an request
   */
  //struct GNUNET_RPS_Request_Handle *req_handle;

  /**
   * Peer on- or offline?
   */
  int online;

  /**
   * Received PeerIDs
   */
  struct GNUNET_PeerIdentity *rec_ids;

  /**
   * Number of received PeerIDs
   */
  unsigned int num_rec_ids;
};


/**
 * Information for all the peers.
 */
static struct RPSPeer *rps_peers;

/**
 * Peermap to get the index of a given peer ID quick.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *peer_map;

/**
 * IDs of the peers.
 */
static struct GNUNET_PeerIdentity *rps_peer_ids;

/**
 * Number of online peers.
 */
static unsigned int num_peers_online;

/**
 * Return value from 'main'.
 */
static int ok;


/**
 * Identifier for the churn task that runs periodically
 */
static struct GNUNET_SCHEDULER_Task *churn_task;


/**
 * Called directly after connecting to the service
 */
typedef void (*PreTest) (void *cls, struct GNUNET_RPS_Handle *h);

/**
 * Called from within #rps_connect_complete_cb ()
 * Executes functions to test the api/service
 */
typedef void (*MainTest) (struct RPSPeer *rps_peer);

/**
 * Callback called once the requested random peers are available
 */
typedef void (*ReplyHandle) (void *cls,
                             uint64_t n,
                             const struct GNUNET_PeerIdentity *recv_peers);

/**
 * Called directly before disconnecting from the service
 */
typedef void (*PostTest) (void *cls, struct GNUNET_RPS_Handle *h);

/**
 * Function called after disconnect to evaluate test success
 */
typedef int (*EvaluationCallback) (void);


/**
 * Structure to define a single test
 */
struct SingleTestRun
{
  /**
   * Name of the test
   */
  char *name;

  /**
   * Called directly after connecting to the service
   */
  PreTest pre_test;

  /**
   * Function to execute the functions to be tested
   */
  MainTest main_test;

  /**
   * Callback called once the requested peers are available
   */
  ReplyHandle reply_handle;

  /**
   * Called directly before disconnecting from the service
   */
  PostTest post_test;

  /**
   * Function to evaluate the test results
   */
  EvaluationCallback eval_cb;

  /**
   * Request interval
   */
  uint32_t request_interval;

  /**
   * Number of Requests to make.
   */
  uint32_t num_requests;
} cur_test_run;


/**
 * Append arguments to file
 */
static void
tofile_ (const char *file_name, char *line)
{
  struct GNUNET_DISK_FileHandle *f;
  /* char output_buffer[512]; */
  size_t size;
  /* int size; */
  size_t size2;

  if (NULL == (f = GNUNET_DISK_file_open (file_name,
                                          GNUNET_DISK_OPEN_APPEND |
                                          GNUNET_DISK_OPEN_WRITE |
                                          GNUNET_DISK_OPEN_CREATE,
                                          GNUNET_DISK_PERM_USER_READ |
                                          GNUNET_DISK_PERM_USER_WRITE |
                                          GNUNET_DISK_PERM_GROUP_READ |
                                          GNUNET_DISK_PERM_OTHER_READ)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Not able to open file %s\n",
                file_name);
    return;
  }
  /* size = GNUNET_snprintf (output_buffer,
                          sizeof (output_buffer),
                          "%llu %s\n",
                          GNUNET_TIME_absolute_get ().abs_value_us,
                          line);
  if (0 > size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to write string to buffer (size: %i)\n",
                size);
    return;
  } */

  size = strlen (line) * sizeof (char);

  size2 = GNUNET_DISK_file_write (f, line, size);
  if (size != size2)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Unable to write to file! (Size: %u, size2: %u)\n",
                size,
                size2);
    return;
  }

  if (GNUNET_YES != GNUNET_DISK_file_close (f))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Unable to close file\n");
}

/**
 * This function is used to facilitate writing important information to disk
 */
#define tofile(file_name, ...) do {\
  char tmp_buf[512];\
    int size;\
    size = GNUNET_snprintf(tmp_buf,sizeof(tmp_buf),__VA_ARGS__);\
    if (0 > size)\
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,\
                     "Failed to create tmp_buf\n");\
    else\
      tofile_(file_name,tmp_buf);\
  } while (0);


/**
 * Write the ids and their according index in the given array to a file 
 * Unused
 */
/* static void
ids_to_file (char *file_name,
             struct GNUNET_PeerIdentity *peer_ids,
             unsigned int num_peer_ids)
{
  unsigned int i;

  for (i=0 ; i < num_peer_ids ; i++)
  {
    to_file (file_name,
             "%u\t%s",
             i,
             GNUNET_i2s_full (&peer_ids[i]));
  }
} */

/**
 * Test the success of a single test
 */
static int
evaluate (struct RPSPeer *loc_rps_peers,
          unsigned int num_loc_rps_peers,
          unsigned int expected_recv)
{
  unsigned int i;
  int tmp_ok;

  tmp_ok = (1 == loc_rps_peers[0].num_rec_ids);

  for (i = 0 ; i < num_loc_rps_peers ; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%u. peer [%s] received %u of %u expected peer_ids: %i\n",
                i,
                GNUNET_i2s (loc_rps_peers[i].peer_id),
                loc_rps_peers[i].num_rec_ids,
                expected_recv,
                (1 == loc_rps_peers[i].num_rec_ids));
    tmp_ok &= (1 == loc_rps_peers[i].num_rec_ids);
  }
  return tmp_ok? 0 : 1;
}


/**
 * Creates an oplist entry and adds it to the oplist DLL
 */
static struct OpListEntry *
make_oplist_entry ()
{
  struct OpListEntry *entry;

  entry = GNUNET_new (struct OpListEntry);
  GNUNET_CONTAINER_DLL_insert_tail (oplist_head, oplist_tail, entry);
  return entry;
}


/**
 * Callback to be called when RPS service is started or stopped at peers
 *
 * @param cls NULL
 * @param op the operation handle
 * @param emsg NULL on success; otherwise an error description
 */
static void
churn_cb (void *cls,
          struct GNUNET_TESTBED_Operation *op,
          const char *emsg)
{
  // FIXME
  struct OpListEntry *entry = cls;

  GNUNET_TESTBED_operation_done (entry->op);
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to start/stop RPS at a peer\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_assert (0 != entry->delta);

  num_peers_online += entry->delta;

  if (0 > entry->delta)
  { /* Peer hopefully just went offline */
    if (GNUNET_YES != rps_peers[entry->index].online)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "peer %s was expected to go offline but is still marked as online\n",
                  GNUNET_i2s (rps_peers[entry->index].peer_id));
      GNUNET_break (0);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "peer %s probably went offline as expected\n",
                  GNUNET_i2s (rps_peers[entry->index].peer_id));
    }
    rps_peers[entry->index].online = GNUNET_NO;
  }

  else if (0 < entry->delta)
  { /* Peer hopefully just went online */
    if (GNUNET_NO != rps_peers[entry->index].online)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "peer %s was expected to go online but is still marked as offline\n",
                  GNUNET_i2s (rps_peers[entry->index].peer_id));
      GNUNET_break (0);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "peer %s probably went online as expected\n",
                  GNUNET_i2s (rps_peers[entry->index].peer_id));
      if (NULL != cur_test_run.pre_test)
      {
        cur_test_run.pre_test (&rps_peers[entry->index],
            rps_peers[entry->index].rps_handle);
      }
    }
    rps_peers[entry->index].online = GNUNET_YES;
  }

  GNUNET_CONTAINER_DLL_remove (oplist_head, oplist_tail, entry);
  GNUNET_free (entry);
  //if (num_peers_in_round[current_round] == peers_running)
  //  run_round ();
}


/**
 * Task run on timeout to shut everything down.
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int i;

  if (NULL != churn_task)
    GNUNET_SCHEDULER_cancel (churn_task);

  for (i = 0 ; i < num_peers ; i++)
    GNUNET_TESTBED_operation_done (rps_peers[i].op);
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Seed peers.
 */
  void
seed_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int amount;
  struct RPSPeer *peer = (struct RPSPeer *) cls;
  unsigned int i;

  // TODO if malicious don't seed mal peers
  amount = round (.5 * num_peers);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Seeding peers:\n");
  for (i = 0 ; i < amount ; i++)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Seeding %u. peer: %s\n",
                i,
                GNUNET_i2s (&rps_peer_ids[i]));

  GNUNET_RPS_seed_ids (peer->rps_handle, amount, rps_peer_ids);
}


/**
 * Get the id of peer i.
 */
  void
info_cb (void *cb_cls,
         struct GNUNET_TESTBED_Operation *op,
         const struct GNUNET_TESTBED_PeerInformation *pinfo,
         const char *emsg)
{
  struct OpListEntry *entry = (struct OpListEntry *) cb_cls;

  if (NULL == pinfo || NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Got Error: %s\n", emsg);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %u is %s\n",
              entry->index,
              GNUNET_i2s (pinfo->result.id));

  rps_peer_ids[entry->index] = *(pinfo->result.id);
  rps_peers[entry->index].peer_id = &rps_peer_ids[entry->index];
  rps_peers[entry->index].rec_ids = NULL;
  rps_peers[entry->index].num_rec_ids = 0;

  GNUNET_CONTAINER_multipeermap_put (peer_map,
      &rps_peer_ids[entry->index],
      &rps_peers[entry->index],
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);

  tofile ("/tmp/rps/peer_ids",
           "%u\t%s\n",
           entry->index,
           GNUNET_i2s_full (&rps_peer_ids[entry->index]));

  GNUNET_TESTBED_operation_done (entry->op);

  GNUNET_CONTAINER_DLL_remove (oplist_head, oplist_tail, entry);
  GNUNET_free (entry);
}


/**
 * Callback to be called when RPS service connect operation is completed
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param ca_result the RPS service handle returned from rps_connect_adapter
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
rps_connect_complete_cb (void *cls,
			 struct GNUNET_TESTBED_Operation *op,
			 void *ca_result,
			 const char *emsg)
{
  struct RPSPeer *rps_peer = cls;
  struct GNUNET_RPS_Handle *rps = ca_result;

  rps_peer->rps_handle = rps;
  rps_peer->online = GNUNET_YES;
  num_peers_online++;

  GNUNET_assert (op == rps_peer->op);
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to connect to RPS service: %s\n",
                emsg);
    ok = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Started client successfully\n");

  cur_test_run.main_test (rps_peer);
}


/**
 * Adapter function called to establish a connection to
 * the RPS service.
 *
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
rps_connect_adapter (void *cls,
		                 const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_RPS_Handle *h;

  h = GNUNET_RPS_connect (cfg);

  if (NULL != cur_test_run.pre_test)
    cur_test_run.pre_test (cls, h);

  return h;
}


/**
 * Adapter function called to destroy connection to
 * RPS service.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
rps_disconnect_adapter (void *cls,
			                  void *op_result)
{
  struct GNUNET_RPS_Handle *h = op_result;
  GNUNET_RPS_disconnect (h);
}


/***********************************************************************
 * Definition of tests
***********************************************************************/

// TODO check whether tests can be stopped earlier
static int
default_eval_cb (void)
{
  return evaluate (rps_peers, num_peers, 1);
}

static int
no_eval (void)
{
  return 1;
}

/**
 * Callback to call on receipt of a reply
 *
 * @param cls closure
 * @param n number of peers
 * @param recv_peers the received peers
 */
static void
default_reply_handle (void *cls,
                      uint64_t n,
                      const struct GNUNET_PeerIdentity *recv_peers)
{
  struct RPSPeer *rps_peer = (struct RPSPeer *) cls;
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "[%s] got %" PRIu64 " peers:\n",
              GNUNET_i2s (rps_peer->peer_id),
              n);
  
  for (i = 0 ; i < n ; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%u: %s\n",
                i,
                GNUNET_i2s (&recv_peers[i]));

    GNUNET_array_append (rps_peer->rec_ids, rps_peer->num_rec_ids, recv_peers[i]);
  }
}

/**
 * Request random peers.
 */
static void
request_peers (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RPSPeer *rps_peer = (struct RPSPeer *) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Requesting one peer\n");

  GNUNET_free (GNUNET_RPS_request_peers (rps_peer->rps_handle,
                                         1,
                                         cur_test_run.reply_handle,
                                         rps_peer));
  //rps_peer->req_handle = GNUNET_RPS_request_peers (rps_peer->rps_handle, 1, handle_reply, rps_peer);
}


/***********************************
 * MALICIOUS
***********************************/
static void
mal_pre (void *cls, struct GNUNET_RPS_Handle *h)
{
  #ifdef ENABLE_MALICIOUS
  uint32_t num_mal_peers;
  struct RPSPeer *rps_peer = (struct RPSPeer *) cls;

  GNUNET_assert (1 >= portion
                 && 0 <  portion);
  num_mal_peers = round (portion * num_peers);

  if (rps_peer->index < num_mal_peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%u. peer [%s] of %" PRIu32 " malicious peers turning malicious\n",
                rps_peer->index,
                GNUNET_i2s (rps_peer->peer_id),
                num_mal_peers);

    GNUNET_RPS_act_malicious (h, mal_type, num_mal_peers, rps_peer_ids);
  }
  #endif /* ENABLE_MALICIOUS */
}

static void
mal_cb (struct RPSPeer *rps_peer)
{
  uint32_t num_mal_peers;

  #ifdef ENABLE_MALICIOUS
  GNUNET_assert (1 >= portion
                 && 0 <  portion);
  num_mal_peers = round (portion * num_peers);

  if (rps_peer->index >= num_mal_peers)
  { /* It's useless to ask a malicious peer about a random sample -
       it's not sampling */
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2),
                                  seed_peers, rps_peer);
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
                                  request_peers, rps_peer);
  }
  #endif /* ENABLE_MALICIOUS */
}

static int
mal_eval (void)
{
  unsigned int num_mal_peers;

  num_mal_peers = round (num_peers * portion);
  return evaluate (&rps_peers[num_mal_peers],
                   num_peers - (num_mal_peers),
                   1);
}


/***********************************
 * SINGLE_REQUEST
***********************************/
static void
single_req_cb (struct RPSPeer *rps_peer)
{
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
                                request_peers, rps_peer);
}

/***********************************
 * DELAYED_REQUESTS
***********************************/
static void
delay_req_cb (struct RPSPeer *rps_peer)
{
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
                                request_peers, rps_peer);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
                                request_peers, rps_peer);
}

/***********************************
 * SEED
***********************************/
static void
seed_cb (struct RPSPeer *rps_peer)
{
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
                                seed_peers, rps_peer);
}

/***********************************
 * SEED_BIG
***********************************/
static void
seed_big_cb (struct RPSPeer *rps_peer)
{
  // TODO test seeding > GNUNET_SERVER_MAX_MESSAGE_SIZE peers
}

/***********************************
 * SINGLE_PEER_SEED
***********************************/
static void
single_peer_seed_cb (struct RPSPeer *rps_peer)
{
  // TODO
}

/***********************************
 * SEED_REQUEST
***********************************/
static void
seed_req_cb (struct RPSPeer *rps_peer)
{
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2),
                                seed_peers, rps_peer);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15),
                                request_peers, rps_peer);
}

//TODO start big mal

/***********************************
 * REQUEST_CANCEL
***********************************/
static void
req_cancel_cb (struct RPSPeer *rps_peer)
{
  // TODO
}

/***********************************
 * PROFILER
***********************************/
static void
churn (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct OpListEntry *entry;
  unsigned int i;
  unsigned int j;
  double portion_online;
  unsigned int *permut;
  double prob_go_offline;
  double portion_go_online;
  double portion_go_offline;
  uint32_t prob;

  /* Compute the probability for an online peer to go offline
   * this round */
  portion_online = num_peers_online * 1.0 / num_peers;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Portion online: %f\n",
              portion_online);
  portion_go_online = ((1 - portion_online) * .5 * .66);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Portion that should go online: %f\n",
              portion_go_online);
  portion_go_offline = (portion_online + portion_go_online) - .75;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Portion that probably goes offline: %f\n",
              portion_go_offline);
  prob_go_offline = portion_go_offline / (portion_online * .5);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Probability of a selected online peer to go offline: %f\n",
              prob_go_offline);

  permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK,
                                         (unsigned int) num_peers);

  /* Go over 50% randomly chosen peers */
  for (i = 0 ; i < .5 * num_peers ; i++)
  {
    j = permut[i];

    /* If online, shut down with certain probability */
    if (GNUNET_YES == rps_peers[j].online)
    {
      prob = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                       UINT32_MAX);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%u. selected peer (%u: %s) is online.\n",
                  i,
                  j,
                  GNUNET_i2s (rps_peers[j].peer_id));
      if (prob < prob_go_offline * UINT32_MAX)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "%s goes offline\n",
                    GNUNET_i2s (rps_peers[j].peer_id));

        entry = make_oplist_entry ();
        entry->delta = -1;
        entry->index = j;
        entry->op = GNUNET_TESTBED_peer_manage_service (NULL,
                                                        testbed_peers[j],
                                                        "rps",
                                                        &churn_cb,
                                                        entry,
                                                        0);
      }
   }

   /* If offline, restart with certain probability */
   else if (GNUNET_NO == rps_peers[j].online)
   {
     prob = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                      UINT32_MAX);
     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                 "%u. selected peer (%u: %s) is offline.\n",
                 i,
                 j,
                 GNUNET_i2s (rps_peers[j].peer_id));
     if (prob < .66 * UINT32_MAX)
     {
       GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                   "%s goes online\n",
                   GNUNET_i2s (rps_peers[j].peer_id));

       entry = make_oplist_entry ();
       entry->delta = 1;
       entry->index = j;
       entry->op = GNUNET_TESTBED_peer_manage_service (NULL,
                                                       testbed_peers[j],
                                                       "rps",
                                                       &churn_cb,
                                                       entry,
                                                       1);
     }
   }
  }

  GNUNET_free (permut);

  churn_task = GNUNET_SCHEDULER_add_delayed (
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2),
        churn,
        NULL);
}


static void
profiler_pre (void *cls, struct GNUNET_RPS_Handle *h)
{
  //churn_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
  //                                                                          10),
  //                                           churn, NULL);
  mal_pre (cls, h);

  /* if (NULL == churn_task)
  {
    churn_task = GNUNET_SCHEDULER_add_delayed (
          GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
          churn,
          NULL);
  } */
}


/**
 * Callback to call on receipt of a reply
 *
 * @param cls closure
 * @param n number of peers
 * @param recv_peers the received peers
 */
static void
profiler_reply_handle (void *cls,
                      uint64_t n,
                      const struct GNUNET_PeerIdentity *recv_peers)
{
  struct RPSPeer *rps_peer = (struct RPSPeer *) cls;
  struct RPSPeer *rcv_rps_peer;
  char *file_name;
  char *file_name_dh;
  unsigned int i;

  file_name = "/tmp/rps/received_ids";
  file_name_dh = "/tmp/rps/diehard_input";

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "[%s] got %" PRIu64 " peers:\n",
              GNUNET_i2s (rps_peer->peer_id),
              n);
  
  for (i = 0 ; i < n ; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%u: %s\n",
                i,
                GNUNET_i2s (&recv_peers[i]));

    /* GNUNET_array_append (rps_peer->rec_ids, rps_peer->num_rec_ids, recv_peers[i]); */
    tofile (file_name,
             "%s\n",
             GNUNET_i2s_full (&recv_peers[i]));

    rcv_rps_peer = GNUNET_CONTAINER_multipeermap_get (peer_map, &recv_peers[i]);

    tofile (file_name_dh,
             "%" PRIu32 "\n",
             (uint32_t) rcv_rps_peer->index);
  }
}


static void
profiler_cb (struct RPSPeer *rps_peer)
{
  uint32_t i;

  /* Churn only at peers that do not request peers for evaluation */
  if (NULL == churn_task &&
      rps_peer->index != num_peers - 2)
  {
    churn_task = GNUNET_SCHEDULER_add_delayed (
          GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
          churn,
          NULL);
  }

  /* Only request peer ids at one peer.
   * (It's the before-last because last one is target of the focussed attack.)
   */
  if (rps_peer->index == num_peers - 2)
  {
    for (i = 0 ; i < cur_test_run.num_requests ; i++)
    {
      GNUNET_SCHEDULER_add_delayed (
          GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                         cur_test_run.request_interval * i),
          request_peers,
          rps_peer);
    }
  }
}

/**
 * Function called from #profiler_eval with a filename.
 *
 * @param cls closure
 * @param filename complete filename (absolute path)
 * @return #GNUNET_OK to continue to iterate,
 *  #GNUNET_NO to stop iteration with no error,
 *  #GNUNET_SYSERR to abort iteration with error!
 */
int
file_name_cb (void *cls, const char *filename)
{
  if (NULL != strstr (filename, "sampler_el"))
  {
    struct RPS_SamplerElement *s_elem;
    struct GNUNET_CRYPTO_AuthKey auth_key;
    const char *key_char;
    uint32_t i;

    key_char = filename + 20; /* Length of "/tmp/rps/sampler_el-" */
    tofile (filename, "--------------------------\n");

    auth_key = string_to_auth_key (key_char);
    s_elem = RPS_sampler_elem_create ();
    RPS_sampler_elem_set (s_elem, auth_key);

    for (i = 0; i < num_peers; i++)
    {
      RPS_sampler_elem_next (s_elem, &rps_peer_ids[i]);
    }
  }
  return GNUNET_OK;
}

/**
 * This is run after the test finished.
 *
 * Compute all perfect samples.
 */
int
profiler_eval (void)
{
  /* Compute perfect sample for each sampler element */
  if (-1 == GNUNET_DISK_directory_scan ("/tmp/rps/", file_name_cb, NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Scan of directory failed\n");
  }

  return 0;
}


/***********************************************************************
 * /Definition of tests
***********************************************************************/


/**
 * Actual "main" function for the testcase.
 *
 * @param cls closure
 * @param h the run handle
 * @param n_peers number of peers in 'peers'
 * @param peers handle to peers run in the testbed
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 */
static void
run (void *cls,
     struct GNUNET_TESTBED_RunHandle *h,
     unsigned int n_peers,
     struct GNUNET_TESTBED_Peer **peers,
     unsigned int links_succeeded,
     unsigned int links_failed)
{
  unsigned int i;
  struct OpListEntry *entry;

  testbed_peers = peers;
  num_peers_online = 0;

  for (i = 0 ; i < num_peers ; i++)
  {
    entry = make_oplist_entry ();
    entry->index = i;
    entry->op = GNUNET_TESTBED_peer_get_information (peers[i],
                                                     GNUNET_TESTBED_PIT_IDENTITY,
                                                     &info_cb,
                                                     entry);
  }


  // This seems not to work
  //if (NULL != strstr (cur_test_run.name, "profiler"))
  //{
  //  churn_task = GNUNET_SCHEDULER_add_delayed (
  //      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
  //      churn,
  //      NULL);
  //}

  GNUNET_assert (num_peers == n_peers);
  for (i = 0 ; i < n_peers ; i++)
  {
    rps_peers[i].index = i;
    rps_peers[i].op =
      GNUNET_TESTBED_service_connect (&rps_peers[i],
                                      peers[i],
                                      "rps",
                                      &rps_connect_complete_cb,
                                      &rps_peers[i],
                                      &rps_connect_adapter,
                                      &rps_disconnect_adapter,
                                      &rps_peers[i]);
  }
  GNUNET_SCHEDULER_add_delayed (timeout, &shutdown_task, NULL);
}


/**
 * Entry point for the testcase, sets up the testbed.
 *
 * @param argc unused
 * @param argv unused
 * @return 0 on success
 */
int
main (int argc, char *argv[])
{
  int ret_value;

  cur_test_run.name = "test-rps-default";
  cur_test_run.pre_test = NULL;
  cur_test_run.reply_handle = default_reply_handle;
  cur_test_run.eval_cb = default_eval_cb;
  churn_task = NULL;

  num_peers = 5;
  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30);

  if (strstr (argv[0], "malicious") != NULL)
  {
    cur_test_run.pre_test = mal_pre;
    cur_test_run.main_test = mal_cb;
    cur_test_run.eval_cb = mal_eval;

    if (strstr (argv[0], "_1") != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test malicious peer type 1\n");
      cur_test_run.name = "test-rps-malicious_1";
      mal_type = 1;
    }
    else if (strstr (argv[0], "_2") != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test malicious peer type 2\n");
      cur_test_run.name = "test-rps-malicious_2";
      mal_type = 2;
    }
    else if (strstr (argv[0], "_3") != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test malicious peer type 3\n");
      cur_test_run.name = "test-rps-malicious_3";
      mal_type = 3;
    }
  }

  else if (strstr (argv[0], "_single_req") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Test single request\n");
    cur_test_run.name = "test-rps-single-req";
    cur_test_run.main_test = single_req_cb;
  }

  else if (strstr (argv[0], "_delayed_reqs") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test delayed requests\n");
    cur_test_run.name = "test-rps-delayed-reqs";
    cur_test_run.main_test = delay_req_cb;
  }

  else if (strstr (argv[0], "_seed_big") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test seeding (num_peers > GNUNET_SERVER_MAX_MESSAGE_SIZE)\n");
    cur_test_run.name = "test-rps-seed-big";
    cur_test_run.main_test = seed_big_cb;
  }

  else if (strstr (argv[0], "_single_peer_seed") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test seeding and requesting on a single peer\n");
    cur_test_run.name = "test-rps-single-peer-seed";
    cur_test_run.main_test = single_peer_seed_cb;
  }

  else if (strstr (argv[0], "_seed_request") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test seeding and requesting on multiple peers\n");
    cur_test_run.name = "test-rps-seed-request";
    cur_test_run.main_test = seed_req_cb;
  }

  else if (strstr (argv[0], "_seed") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test seeding\n");
    cur_test_run.name = "test-rps-seed";
    cur_test_run.main_test = seed_cb;
    cur_test_run.eval_cb = no_eval;
  }

  else if (strstr (argv[0], "_req_cancel") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test cancelling a request\n");
    cur_test_run.name = "test-rps-req-cancel";
    cur_test_run.main_test = req_cancel_cb;
  }

  else if (strstr (argv[0], "profiler") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "This is the profiler\n");
    cur_test_run.name = "test-rps-profiler";
    mal_type = 3;
    cur_test_run.pre_test = profiler_pre;
    cur_test_run.main_test = profiler_cb;
    cur_test_run.reply_handle = profiler_reply_handle;
    cur_test_run.eval_cb = profiler_eval;
    cur_test_run.request_interval = 2;
    cur_test_run.num_requests = 50;

    num_peers = 50;

    (void) GNUNET_DISK_directory_remove ("/tmp/rps/");
    GNUNET_DISK_directory_create ("/tmp/rps/");
    timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 90);
  }

  rps_peers = GNUNET_new_array (num_peers, struct RPSPeer);
  rps_peer_ids = GNUNET_new_array (num_peers, struct GNUNET_PeerIdentity);
  peer_map = GNUNET_CONTAINER_multipeermap_create (num_peers, GNUNET_NO);

  ok = 1;
  (void) GNUNET_TESTBED_test_run (cur_test_run.name,
                                  "test_rps.conf",
                                  num_peers,
                                  0, NULL, NULL,
                                  &run, NULL);

  ret_value = cur_test_run.eval_cb();

  GNUNET_free (rps_peers );
  GNUNET_free (rps_peer_ids);
  GNUNET_CONTAINER_multipeermap_destroy (peer_map);

  return ret_value;
}

/* end of test_rps_multipeer.c */
