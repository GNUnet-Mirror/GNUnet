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
 * A pending reply: A request was sent and the reply is pending.
 */
struct PendingReply
{
  /**
   * DLL next,prev ptr
   */
  struct PendingReply *next;
  struct PendingReply *prev;

  /**
   * Handle to the request we are waiting for
   */
  struct GNUNET_RPS_Request_Handle *req_handle;

  /**
   * The peer that requested
   */
  struct RPSPeer *rps_peer;
};


/**
 * A pending request: A request was not made yet but is scheduled for later.
 */
struct PendingRequest
{
  /**
   * DLL next,prev ptr
   */
  struct PendingRequest *next;
  struct PendingRequest *prev;

  /**
   * Handle to the request we are waiting for
   */
  struct GNUNET_SCHEDULER_Task *request_task;

  /**
   * The peer that requested
   */
  struct RPSPeer *rps_peer;
};


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
   * Number of Peer IDs to request
   */
  unsigned int num_ids_to_request;

  /**
   * Pending requests DLL
   */
  struct PendingRequest *pending_req_head;
  struct PendingRequest *pending_req_tail;

  /**
   * Number of pending requests
   */
  unsigned int num_pending_reqs;

  /**
   * Pending replies DLL
   */
  struct PendingReply *pending_rep_head;
  struct PendingReply *pending_rep_tail;

  /**
   * Number of pending replies
   */
  unsigned int num_pending_reps;

  /**
   * Number of received PeerIDs
   */
  unsigned int num_recv_ids;
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
 * ID of the targeted peer.
 */
static struct GNUNET_PeerIdentity *target_peer;

/**
 * ID of the peer that requests for the evaluation.
 */
static struct RPSPeer *eval_peer;

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
 * Identifier for the churn task that runs periodically
 */
static struct GNUNET_SCHEDULER_Task *shutdown_task;


/**
 * Called to initialise the given RPSPeer
 */
typedef void (*InitPeer) (struct RPSPeer *rps_peer);

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
   * Called to initialise peer
   */
  InitPeer init_peer;

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
 * Are we shutting down?
 */
static int in_shutdown;

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
evaluate (void)
{
  unsigned int i;
  int tmp_ok;

  tmp_ok = 1;

  for (i = 0; i < num_peers; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "%u. peer [%s] received %u of %u expected peer_ids: %i\n",
        i,
        GNUNET_i2s (rps_peers[i].peer_id),
        rps_peers[i].num_recv_ids,
        rps_peers[i].num_ids_to_request,
        (rps_peers[i].num_ids_to_request == rps_peers[i].num_recv_ids));
    tmp_ok &= (rps_peers[i].num_ids_to_request == rps_peers[i].num_recv_ids);
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
 * Task run on timeout to shut everything down.
 */
static void
shutdown_op (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int i;

  in_shutdown = GNUNET_YES;
  if (NULL != churn_task)
    GNUNET_SCHEDULER_cancel (churn_task);

  for (i = 0; i < num_peers; i++)
    if (NULL != rps_peers[i].op)
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
 * Seed peers.
 */
  void
seed_peers_big (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RPSPeer *peer = (struct RPSPeer *) cls;
  unsigned int seed_msg_size;
  uint32_t num_peers_max;
  unsigned int amount;
  unsigned int i;

  seed_msg_size = 8; /* sizeof (struct GNUNET_RPS_CS_SeedMessage) */
  num_peers_max = (GNUNET_SERVER_MAX_MESSAGE_SIZE - seed_msg_size) /
    sizeof (struct GNUNET_PeerIdentity);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Peers that fit in one seed msg; %u\n",
      num_peers_max);
  amount = num_peers_max + (0.5 * num_peers_max);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Seeding many (%u) peers:\n",
      amount);
  struct GNUNET_PeerIdentity ids_to_seed[amount];
  for (i = 0; i < amount; i++)
  {
    ids_to_seed[i] = *peer->peer_id;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Seeding %u. peer: %s\n",
                i,
                GNUNET_i2s (&ids_to_seed[i]));
  }

  GNUNET_RPS_seed_ids (peer->rps_handle, amount, ids_to_seed);
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
    GNUNET_TESTBED_operation_done (entry->op);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %u is %s\n",
              entry->index,
              GNUNET_i2s (pinfo->result.id));

  rps_peer_ids[entry->index] = *(pinfo->result.id);
  rps_peers[entry->index].peer_id = &rps_peer_ids[entry->index];

  GNUNET_CONTAINER_multipeermap_put (peer_map,
      &rps_peer_ids[entry->index],
      &rps_peers[entry->index],
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  tofile ("/tmp/rps/peer_ids",
           "%u\t%s\n",
           entry->index,
           GNUNET_i2s_full (&rps_peer_ids[entry->index]));

  GNUNET_CONTAINER_DLL_remove (oplist_head, oplist_tail, entry);
  GNUNET_TESTBED_operation_done (entry->op);
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
  struct RPSPeer *peer = cls;
  struct GNUNET_RPS_Handle *h = op_result;
  GNUNET_assert (NULL != peer);
  GNUNET_RPS_disconnect (h);
  peer->rps_handle = NULL;
}


/***********************************************************************
 * Definition of tests
***********************************************************************/

// TODO check whether tests can be stopped earlier
static int
default_eval_cb (void)
{
  return evaluate ();
}

static int
no_eval (void)
{
  return 0;
}

/**
 * Initialise given RPSPeer
 */
static void default_init_peer (struct RPSPeer *rps_peer)
{
  rps_peer->num_ids_to_request = 1;
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
  struct RPSPeer *rps_peer;
  struct PendingReply *pending_rep = (struct PendingReply *) cls;
  unsigned int i;

  rps_peer = pending_rep->rps_peer;
  GNUNET_CONTAINER_DLL_remove (rps_peer->pending_rep_head,
                               rps_peer->pending_rep_tail,
                               pending_rep);
  rps_peer->num_pending_reps--;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "[%s] got %" PRIu64 " peers:\n",
              GNUNET_i2s (rps_peer->peer_id),
              n);
  
  for (i = 0; i < n; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%u: %s\n",
                i,
                GNUNET_i2s (&recv_peers[i]));

    rps_peer->num_recv_ids++;
  }

  if (0 == evaluate ())
  {
    GNUNET_SCHEDULER_cancel (shutdown_task);
    shutdown_task = GNUNET_SCHEDULER_add_now (&shutdown_op, NULL);
  }
}

/**
 * Request random peers.
 */
static void
request_peers (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RPSPeer *rps_peer;
  struct PendingRequest *pending_req = (struct PendingRequest *) cls;
  struct PendingReply *pending_rep;

  if (GNUNET_YES == in_shutdown)
    return;
  rps_peer = pending_req->rps_peer;
  GNUNET_assert (1 <= rps_peer->num_pending_reqs);
  GNUNET_CONTAINER_DLL_remove (rps_peer->pending_req_head,
                               rps_peer->pending_req_tail,
                               pending_req);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Requesting one peer\n");
  pending_rep = GNUNET_new (struct PendingReply);
  pending_rep->rps_peer = rps_peer;
  pending_rep->req_handle = GNUNET_RPS_request_peers (rps_peer->rps_handle,
      1,
      cur_test_run.reply_handle,
      pending_rep);
  GNUNET_CONTAINER_DLL_insert_tail (rps_peer->pending_rep_head,
                                    rps_peer->pending_rep_tail,
                                    pending_rep);
  rps_peer->num_pending_reps++;
  rps_peer->num_pending_reqs--;
}

static void
cancel_pending_req (struct PendingRequest *pending_req)
{
  struct RPSPeer *rps_peer;

  rps_peer = pending_req->rps_peer;
  GNUNET_CONTAINER_DLL_remove (rps_peer->pending_req_head,
                               rps_peer->pending_req_tail,
                               pending_req);
  rps_peer->num_pending_reqs--;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cancelling pending request\n");
  GNUNET_SCHEDULER_cancel (pending_req->request_task);
  GNUNET_free (pending_req);
}

static void
cancel_request (struct PendingReply *pending_rep)
{
  struct RPSPeer *rps_peer;

  rps_peer = pending_rep->rps_peer;
  GNUNET_CONTAINER_DLL_remove (rps_peer->pending_rep_head,
                               rps_peer->pending_rep_tail,
                               pending_rep);
  rps_peer->num_pending_reps--;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cancelling request\n");
  GNUNET_RPS_request_cancel (pending_rep->req_handle);
  GNUNET_free (pending_rep);
}

/**
 * Cancel a request.
 */
static void
cancel_request_cb (void *cls,
                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PendingReply *pending_rep;
  struct RPSPeer *rps_peer = (struct RPSPeer *) cls;

  if (GNUNET_YES == in_shutdown)
    return;
  pending_rep = rps_peer->pending_rep_head;
  GNUNET_assert (1 <= rps_peer->num_pending_reps);
  cancel_request (pending_rep);
}


/**
 * Schedule requests for peer @a rps_peer that have neither been scheduled, nor
 * issued, nor replied
 */
void
schedule_missing_requests (struct RPSPeer *rps_peer)
{
  unsigned int i;
  struct PendingRequest *pending_req;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Scheduling %u - %u missing requests\n",
      rps_peer->num_ids_to_request,
      rps_peer->num_pending_reqs + rps_peer->num_pending_reps);
  GNUNET_assert (rps_peer->num_pending_reqs + rps_peer->num_pending_reps <=
      rps_peer->num_ids_to_request);
  for (i = rps_peer->num_pending_reqs + rps_peer->num_pending_reps;
       i < rps_peer->num_ids_to_request; i++)
  {
    pending_req = GNUNET_new (struct PendingRequest);
    pending_req->rps_peer = rps_peer;
    pending_req->request_task = GNUNET_SCHEDULER_add_delayed (
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
          cur_test_run.request_interval * i),
        request_peers,
        pending_req);
    GNUNET_CONTAINER_DLL_insert_tail (rps_peer->pending_req_head,
                                      rps_peer->pending_req_tail,
                                      pending_req);
    rps_peer->num_pending_reqs++;
  }
}

void
cancel_pending_req_rep (struct RPSPeer *rps_peer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Cancelling all (pending) requests.\n");
  while (NULL != rps_peer->pending_req_head)
    cancel_pending_req (rps_peer->pending_req_head);
  GNUNET_assert (0 == rps_peer->num_pending_reqs);
  while (NULL != rps_peer->pending_rep_head)
    cancel_request (rps_peer->pending_rep_head);
  GNUNET_assert (0 == rps_peer->num_pending_reps);
}

/***********************************
 * MALICIOUS
***********************************/

/**
 * Initialise only non-mal RPSPeers
 */
static void mal_init_peer (struct RPSPeer *rps_peer)
{
  if (rps_peer->index >= round (portion * num_peers))
    rps_peer->num_ids_to_request = 1;
}

static void
mal_pre (void *cls, struct GNUNET_RPS_Handle *h)
{
  #ifdef ENABLE_MALICIOUS
  uint32_t num_mal_peers;
  struct RPSPeer *rps_peer = (struct RPSPeer *) cls;

  GNUNET_assert ( (1 >= portion) &&
                  (0 <  portion) );
  num_mal_peers = round (portion * num_peers);

  if (rps_peer->index < num_mal_peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%u. peer [%s] of %" PRIu32 " malicious peers turning malicious\n",
                rps_peer->index,
                GNUNET_i2s (rps_peer->peer_id),
                num_mal_peers);

    GNUNET_RPS_act_malicious (h, mal_type, num_mal_peers,
                              rps_peer_ids, target_peer);
  }
  #endif /* ENABLE_MALICIOUS */
}

static void
mal_cb (struct RPSPeer *rps_peer)
{
  uint32_t num_mal_peers;

  #ifdef ENABLE_MALICIOUS
  GNUNET_assert ( (1 >= portion) &&
                  (0 <  portion) );
  num_mal_peers = round (portion * num_peers);

  if (rps_peer->index >= num_mal_peers)
  { /* It's useless to ask a malicious peer about a random sample -
       it's not sampling */
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2),
                                  seed_peers, rps_peer);
    schedule_missing_requests (rps_peer);
  }
  #endif /* ENABLE_MALICIOUS */
}


/***********************************
 * SINGLE_REQUEST
***********************************/
static void
single_req_cb (struct RPSPeer *rps_peer)
{
  schedule_missing_requests (rps_peer);
}

/***********************************
 * DELAYED_REQUESTS
***********************************/
static void
delay_req_cb (struct RPSPeer *rps_peer)
{
  schedule_missing_requests (rps_peer);
}

/***********************************
 * SEED
***********************************/
static void
seed_cb (struct RPSPeer *rps_peer)
{
  GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
      seed_peers, rps_peer);
}

/***********************************
 * SEED_BIG
***********************************/
static void
seed_big_cb (struct RPSPeer *rps_peer)
{
  // TODO test seeding > GNUNET_SERVER_MAX_MESSAGE_SIZE peers
  GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2),
      seed_peers_big, rps_peer);
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
  GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2),
      seed_peers, rps_peer);
  schedule_missing_requests (rps_peer);
}

//TODO start big mal

/***********************************
 * REQUEST_CANCEL
***********************************/
static void
req_cancel_cb (struct RPSPeer *rps_peer)
{
  schedule_missing_requests (rps_peer);
  GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                     (cur_test_run.request_interval + 1)),
      cancel_request_cb, rps_peer);
}

/***********************************
 * PROFILER
***********************************/

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
        schedule_missing_requests (&rps_peers[entry->index]);
      }
    }
    rps_peers[entry->index].online = GNUNET_YES;
  }

  GNUNET_CONTAINER_DLL_remove (oplist_head, oplist_tail, entry);
  GNUNET_free (entry);
  //if (num_peers_in_round[current_round] == peers_running)
  //  run_round ();
}

static void
manage_service_wrapper (unsigned int i, unsigned int j, int delta,
    double prob_go_on_off)
{
  struct OpListEntry *entry;
  uint32_t prob;

  prob = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                   UINT32_MAX);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%u. selected peer (%u: %s) is %s.\n",
              i,
              j,
              GNUNET_i2s (rps_peers[j].peer_id),
              (0 > delta) ? "online" : "offline");
  if (prob < prob_go_on_off * UINT32_MAX)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s goes %s\n",
                GNUNET_i2s (rps_peers[j].peer_id),
                (0 > delta) ? "offline" : "online");

    if (0 > delta)
      cancel_pending_req_rep (&rps_peers[j]);
    entry = make_oplist_entry ();
    entry->delta = delta;
    entry->index = j;
    entry->op = GNUNET_TESTBED_peer_manage_service (NULL,
                                                    testbed_peers[j],
                                                    "rps",
                                                    &churn_cb,
                                                    entry,
                                                    (0 > delta) ? 0 : 1);
  }
}

static void
churn (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int i;
  unsigned int j;
  double portion_online;
  unsigned int *permut;
  double prob_go_offline;
  double portion_go_online;
  double portion_go_offline;

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
  for (i = 0; i < .5 * num_peers; i++)
  {
    j = permut[i];

    /* If online, shut down with certain probability */
    if (GNUNET_YES == rps_peers[j].online)
    {
      manage_service_wrapper (i, j, -1, prob_go_offline);
    }

    /* If offline, restart with certain probability */
    else if (GNUNET_NO == rps_peers[j].online)
    {
      manage_service_wrapper (i, j, 1, 0.66);
    }
  }

  GNUNET_free (permut);

  churn_task = GNUNET_SCHEDULER_add_delayed (
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2),
        churn,
        NULL);
}


/**
 * Initialise given RPSPeer
 */
static void profiler_init_peer (struct RPSPeer *rps_peer)
{
  if (num_peers - 1 == rps_peer->index)
    rps_peer->num_ids_to_request = cur_test_run.num_requests;
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
  struct RPSPeer *rps_peer;
  struct RPSPeer *rcv_rps_peer;
  char *file_name;
  char *file_name_dh;
  unsigned int i;
  struct PendingReply *pending_rep = (struct PendingReply *) cls;

  rps_peer = pending_rep->rps_peer;
  file_name = "/tmp/rps/received_ids";
  file_name_dh = "/tmp/rps/diehard_input";
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "[%s] got %" PRIu64 " peers:\n",
              GNUNET_i2s (rps_peer->peer_id),
              n);
  for (i = 0; i < n; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%u: %s\n",
                i,
                GNUNET_i2s (&recv_peers[i]));
    tofile (file_name,
             "%s\n",
             GNUNET_i2s_full (&recv_peers[i]));
    rcv_rps_peer = GNUNET_CONTAINER_multipeermap_get (peer_map, &recv_peers[i]);
    tofile (file_name_dh,
             "%" PRIu32 "\n",
             (uint32_t) rcv_rps_peer->index);
  }
  default_reply_handle (cls, n, recv_peers);
}


static void
profiler_cb (struct RPSPeer *rps_peer)
{
  /* Start churn */
  if (NULL == churn_task)
  {
    churn_task = GNUNET_SCHEDULER_add_delayed (
          GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
          churn,
          NULL);
  }

  /* Only request peer ids at one peer.
   * (It's the before-last because last one is target of the focussed attack.)
   */
  if (eval_peer == rps_peer)
    schedule_missing_requests (rps_peer);
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

  return evaluate ();
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
  uint32_t num_mal_peers;

  testbed_peers = peers;
  num_peers_online = 0;
  for (i = 0; i < num_peers; i++)
  {
    entry = make_oplist_entry ();
    entry->index = i;
    rps_peers[i].index = i;
    if (NULL != cur_test_run.init_peer)
      cur_test_run.init_peer (&rps_peers[i]);
    entry->op = GNUNET_TESTBED_peer_get_information (peers[i],
                                                     GNUNET_TESTBED_PIT_IDENTITY,
                                                     &info_cb,
                                                     entry);
  }

  num_mal_peers = round (portion * num_peers);
  GNUNET_assert (num_peers == n_peers);
  for (i = 0; i < n_peers; i++)
  {
    rps_peers[i].index = i;
    if ( (rps_peers[i].num_recv_ids < rps_peers[i].num_ids_to_request) ||
         (i < num_mal_peers) )
    {
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
  }

  if (NULL != churn_task)
    GNUNET_SCHEDULER_cancel (churn_task);
  shutdown_task = GNUNET_SCHEDULER_add_delayed (timeout, &shutdown_op, NULL);
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

  num_peers = 5;
  cur_test_run.name = "test-rps-default";
  cur_test_run.init_peer = default_init_peer;
  cur_test_run.pre_test = NULL;
  cur_test_run.reply_handle = default_reply_handle;
  cur_test_run.eval_cb = default_eval_cb;
  churn_task = NULL;
  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30);

  if (strstr (argv[0], "malicious") != NULL)
  {
    cur_test_run.pre_test = mal_pre;
    cur_test_run.main_test = mal_cb;
    cur_test_run.init_peer = mal_init_peer;

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
    num_peers = 1;
    cur_test_run.name = "test-rps-seed-big";
    cur_test_run.main_test = seed_big_cb;
    cur_test_run.eval_cb = no_eval;
    timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10);
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
    num_peers = 1;
    cur_test_run.main_test = req_cancel_cb;
    cur_test_run.eval_cb = no_eval;
    timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10);
  }

  else if (strstr (argv[0], "profiler") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "This is the profiler\n");
    cur_test_run.name = "test-rps-profiler";
    num_peers = 10;
    mal_type = 3;
    cur_test_run.init_peer = profiler_init_peer;
    cur_test_run.pre_test = mal_pre;
    cur_test_run.main_test = profiler_cb;
    cur_test_run.reply_handle = profiler_reply_handle;
    cur_test_run.eval_cb = profiler_eval;
    cur_test_run.request_interval = 2;
    cur_test_run.num_requests = 5;
    timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 90);

    /* 'Clean' directory */
    (void) GNUNET_DISK_directory_remove ("/tmp/rps/");
    GNUNET_DISK_directory_create ("/tmp/rps/");
  }

  rps_peers = GNUNET_new_array (num_peers, struct RPSPeer);
  peer_map = GNUNET_CONTAINER_multipeermap_create (num_peers, GNUNET_NO);
  rps_peer_ids = GNUNET_new_array (num_peers, struct GNUNET_PeerIdentity);
  if ( (2 == mal_type) ||
       (3 == mal_type))
    target_peer = &rps_peer_ids[num_peers - 2];
  if (profiler_eval == cur_test_run.eval_cb)
    eval_peer = &rps_peers[num_peers - 1];

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
