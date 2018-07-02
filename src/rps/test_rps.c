/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2012 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * @file rps/test_rps.c
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
static uint32_t num_peers;

/**
 * How long do we run the test?
 * In seconds.
 */
static uint32_t timeout_s;

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
 * @brief Indicates whether peer should go off- or online
 */
enum PEER_ONLINE_DELTA {
  /**
   * @brief Indicates peer going online
   */
  PEER_GO_ONLINE = 1,
  /**
   * @brief Indicates peer going offline
   */
  PEER_GO_OFFLINE = -1,
};

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
   * Depending on whether we start or stop RPS service at the peer, set this to
   * #PEER_GO_ONLINE (1) or #PEER_GO_OFFLINE (-1)
   */
  enum PEER_ONLINE_DELTA delta;

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
   * Number of Peer IDs to request during the whole test
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

  /**
   * Pending operation on that peer
   */
  const struct OpListEntry *entry_op_manage;

  /**
   * Testbed operation to connect to statistics service
   */
  struct GNUNET_TESTBED_Operation *stat_op;

  /**
   * Handle to the statistics service
   */
  struct GNUNET_STATISTICS_Handle *stats_h;

  /**
   * @brief flags to indicate which statistics values have been already
   * collected from the statistics service.
   * Used to check whether we are able to shutdown.
   */
  uint32_t stat_collected_flags;

  /**
   * @brief File name of the file the stats are finally written to
   */
  const char *file_name_stats;

  /**
   * @brief File name of the file the stats are finally written to
   */
  const char *file_name_probs;

  /**
   * @brief The current view
   */
  struct GNUNET_PeerIdentity *cur_view;

  /**
   * @brief Number of peers in the #cur_view.
   */
  uint32_t cur_view_count;

  /**
   * @brief Number of occurrences in other peer's view
   */
  uint32_t count_in_views;

  /**
   * @brief statistics values
   */
  uint64_t num_rounds;
  uint64_t num_blocks;
  uint64_t num_blocks_many_push;
  uint64_t num_blocks_no_push;
  uint64_t num_blocks_no_pull;
  uint64_t num_blocks_many_push_no_pull;
  uint64_t num_blocks_no_push_no_pull;
  uint64_t num_issued_push;
  uint64_t num_issued_pull_req;
  uint64_t num_issued_pull_rep;
  uint64_t num_sent_push;
  uint64_t num_sent_pull_req;
  uint64_t num_sent_pull_rep;
  uint64_t num_recv_push;
  uint64_t num_recv_pull_req;
  uint64_t num_recv_pull_rep;
};

enum STAT_TYPE
{
  STAT_TYPE_ROUNDS                    =    0x1, /*   1 */
  STAT_TYPE_BLOCKS                    =    0x2, /*   2 */
  STAT_TYPE_BLOCKS_MANY_PUSH          =    0x4, /*   3 */
  STAT_TYPE_BLOCKS_NO_PUSH            =    0x8, /*   4 */
  STAT_TYPE_BLOCKS_NO_PULL            =   0x10, /*   5 */
  STAT_TYPE_BLOCKS_MANY_PUSH_NO_PULL  =   0x20, /*   6 */
  STAT_TYPE_BLOCKS_NO_PUSH_NO_PULL    =   0x40, /*   7 */
  STAT_TYPE_ISSUED_PUSH_SEND          =   0x80, /*   8 */
  STAT_TYPE_ISSUED_PULL_REQ           =  0x100, /*   9 */
  STAT_TYPE_ISSUED_PULL_REP           =  0x200, /*  10 */
  STAT_TYPE_SENT_PUSH_SEND            =  0x400, /*  11 */
  STAT_TYPE_SENT_PULL_REQ             =  0x800, /*  12 */
  STAT_TYPE_SENT_PULL_REP             = 0x1000, /*  13 */
  STAT_TYPE_RECV_PUSH_SEND            = 0x2000, /*  14 */
  STAT_TYPE_RECV_PULL_REQ             = 0x4000, /*  15 */
  STAT_TYPE_RECV_PULL_REP             = 0x8000, /*  16 */
  STAT_TYPE_MAX          = 0x80000000, /*  32 */
};

struct STATcls
{
  struct RPSPeer *rps_peer;
  enum STAT_TYPE stat_type;
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
 * @brief The added sizes of the peer's views
 */
static unsigned int view_sizes;

/**
 * Return value from 'main'.
 */
static int ok;

/**
 * Identifier for the churn task that runs periodically
 */
static struct GNUNET_SCHEDULER_Task *post_test_task;

/**
 * Identifier for the churn task that runs periodically
 */
static struct GNUNET_SCHEDULER_Task *shutdown_task;

/**
 * Identifier for the churn task that runs periodically
 */
static struct GNUNET_SCHEDULER_Task *churn_task;

/**
 * Called to initialise the given RPSPeer
 */
typedef void (*InitPeer) (struct RPSPeer *rps_peer);

/**
 * @brief Called directly after connecting to the service
 *
 * @param rps_peer Specific peer the function is called on
 * @param h the handle to the rps service
 */
typedef void (*PreTest) (struct RPSPeer *rps_peer, struct GNUNET_RPS_Handle *h);

/**
 * @brief Executes functions to test the api/service for a given peer
 *
 * Called from within #rps_connect_complete_cb ()
 * Implemented by #churn_test_cb, #profiler_cb, #mal_cb, #single_req_cb,
 * #delay_req_cb, #seed_big_cb, #single_peer_seed_cb, #seed_cb, #req_cancel_cb
 *
 * @param rps_peer the peer the task runs on
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
typedef void (*PostTest) (struct RPSPeer *peer);

/**
 * Function called after disconnect to evaluate test success
 */
typedef int (*EvaluationCallback) (void);

/**
 * @brief Do we have Churn?
 */
enum OPTION_CHURN {
  /**
   * @brief If we have churn this is set
   */
  HAVE_CHURN,
  /**
   * @brief If we have no churn this is set
   */
  HAVE_NO_CHURN,
};

/**
 * @brief Is it ok to quit the test before the timeout?
 */
enum OPTION_QUICK_QUIT {
  /**
   * @brief It is ok for the test to quit before the timeout triggers
   */
  HAVE_QUICK_QUIT,

  /**
   * @brief It is NOT ok for the test to quit before the timeout triggers
   */
  HAVE_NO_QUICK_QUIT,
};

/**
 * @brief Do we collect statistics at the end?
 */
enum OPTION_COLLECT_STATISTICS {
  /**
   * @brief We collect statistics at the end
   */
  COLLECT_STATISTICS,

  /**
   * @brief We do not collect statistics at the end
   */
  NO_COLLECT_STATISTICS,
};

/**
 * @brief Do we collect views during run?
 */
enum OPTION_COLLECT_VIEW {
  /**
   * @brief We collect view during run
   */
  COLLECT_VIEW,

  /**
   * @brief We do not collect the view during run
   */
  NO_COLLECT_VIEW,
};

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
   * Called with a single peer in order to initialise that peer
   */
  InitPeer init_peer;

  /**
   * Called directly after connecting to the service
   */
  PreTest pre_test;

  /**
   * Main function for each peer
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

  /**
   * Run with (-out) churn
   */
  enum OPTION_CHURN have_churn;

  /**
   * Quit test before timeout?
   */
  enum OPTION_QUICK_QUIT have_quick_quit;

  /**
   * Collect statistics at the end?
   */
  enum OPTION_COLLECT_STATISTICS have_collect_statistics;

  /**
   * Collect view during run?
   */
  enum OPTION_COLLECT_VIEW have_collect_view;

  /**
   * @brief Mark which values from the statistics service to collect at the end
   * of the run
   */
  uint32_t stat_collect_flags;
} cur_test_run;

/**
 * Did we finish the test?
 */
static int post_test;

/**
 * Are we shutting down?
 */
static int in_shutdown;

/**
 * Append arguments to file
 */
static void
tofile_ (const char *file_name, const char *line)
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
                "Unable to write to file! (Size: %lu, size2: %lu)\n",
                size,
                size2);
    if (GNUNET_YES != GNUNET_DISK_file_close (f))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Unable to close file\n");
    }
    return;
  }

  if (GNUNET_YES != GNUNET_DISK_file_close (f))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Unable to close file\n");
  }
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
 * @brief Checks if given peer already received its statistics value from the
 * statistics service.
 *
 * @param rps_peer the peer to check for
 *
 * @return #GNUNET_YES if so
 *         #GNUNET_NO otherwise
 */
static int check_statistics_collect_completed_single_peer (
    const struct RPSPeer *rps_peer)
{
  if (cur_test_run.stat_collect_flags !=
        (cur_test_run.stat_collect_flags &
          rps_peer->stat_collected_flags))
  {
    return GNUNET_NO;
  }
  return GNUNET_YES;
}
/**
 * @brief Checks if all peers already received their statistics value from the
 * statistics service.
 *
 * @return #GNUNET_YES if so
 *         #GNUNET_NO otherwise
 */
static int check_statistics_collect_completed ()
{
  uint32_t i;

  for (i = 0; i < num_peers; i++)
  {
    if (GNUNET_NO == check_statistics_collect_completed_single_peer (&rps_peers[i]))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
          "At least Peer %" PRIu32 " did not yet receive all statistics values\n",
          i);
      return GNUNET_NO;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "All peers received their statistics values\n");
  return GNUNET_YES;
}

/**
 * Task run on timeout to shut everything down.
 */
static void
shutdown_op (void *cls)
{
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Shutdown task scheduled, going down.\n");
  in_shutdown = GNUNET_YES;
  if (NULL != post_test_task)
  {
    GNUNET_SCHEDULER_cancel (post_test_task);
  }
  if (NULL != churn_task)
  {
    GNUNET_SCHEDULER_cancel (churn_task);
    churn_task = NULL;
  }
  for (i = 0; i < num_peers; i++)
  {
    if (NULL != rps_peers[i].rps_handle)
    {
      GNUNET_RPS_disconnect (rps_peers[i].rps_handle);
    }
    if (NULL != rps_peers[i].op)
    {
      GNUNET_TESTBED_operation_done (rps_peers[i].op);
    }
  }
}


/**
 * Task run on timeout to collect statistics and potentially shut down.
 */
static void
post_test_op (void *cls)
{
  unsigned int i;

  post_test_task = NULL;
  post_test = GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Post test task scheduled, going down.\n");
  if (NULL != churn_task)
  {
    GNUNET_SCHEDULER_cancel (churn_task);
    churn_task = NULL;
  }
  for (i = 0; i < num_peers; i++)
  {
    if (NULL != rps_peers[i].op)
    {
      GNUNET_TESTBED_operation_done (rps_peers[i].op);
      rps_peers[i].op = NULL;
    }
    if (NULL != cur_test_run.post_test)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Executing post_test for peer %u\n", i);
      cur_test_run.post_test (&rps_peers[i]);
    }
  }
  /* If we do not collect statistics, shut down directly */
  if (NO_COLLECT_STATISTICS == cur_test_run.have_collect_statistics ||
      GNUNET_YES == check_statistics_collect_completed())
  {
    GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * Seed peers.
 */
static void
seed_peers (void *cls)
{
  struct RPSPeer *peer = cls;
  unsigned int amount;
  unsigned int i;

  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
  {
    return;
  }

  GNUNET_assert (NULL != peer->rps_handle);

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
static void
seed_peers_big (void *cls)
{
  struct RPSPeer *peer = cls;
  unsigned int seed_msg_size;
  uint32_t num_peers_max;
  unsigned int amount;
  unsigned int i;

  seed_msg_size = 8; /* sizeof (struct GNUNET_RPS_CS_SeedMessage) */
  num_peers_max = (GNUNET_MAX_MESSAGE_SIZE - seed_msg_size) /
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

  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
  {
    return;
  }

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

  GNUNET_assert (GNUNET_OK ==
      GNUNET_CONTAINER_multipeermap_put (peer_map,
        &rps_peer_ids[entry->index],
        &rps_peers[entry->index],
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
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

  GNUNET_assert (NULL != ca_result);

  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
  {
    return;
  }

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
  GNUNET_assert (NULL != h);

  if (NULL != cur_test_run.pre_test)
    cur_test_run.pre_test (cls, h);
  GNUNET_assert (NULL != h);

  return h;
}

/**
 * Called to open a connection to the peer's statistics
 *
 * @param cls peer context
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
stat_connect_adapter (void *cls,
                      const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct RPSPeer *peer = cls;

  peer->stats_h = GNUNET_STATISTICS_create ("rps-profiler", cfg);
  return peer->stats_h;
}

/**
 * Called to disconnect from peer's statistics service
 *
 * @param cls peer context
 * @param op_result service handle returned from the connect adapter
 */
static void
stat_disconnect_adapter (void *cls, void *op_result)
{
  struct RPSPeer *peer = cls;

  //GNUNET_break (GNUNET_OK == GNUNET_STATISTICS_watch_cancel
  //              (peer->stats_h, "core", "# peers connected",
  //               stat_iterator, peer));
  //GNUNET_break (GNUNET_OK == GNUNET_STATISTICS_watch_cancel
  //              (peer->stats_h, "nse", "# peers connected",
  //               stat_iterator, peer));
  GNUNET_STATISTICS_destroy (op_result, GNUNET_NO);
  peer->stats_h = NULL;
}

/**
 * Called after successfully opening a connection to a peer's statistics
 * service; we register statistics monitoring for CORE and NSE here.
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param ca_result the service handle returned from GNUNET_TESTBED_ConnectAdapter()
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
stat_complete_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
                  void *ca_result, const char *emsg )
{
  //struct GNUNET_STATISTICS_Handle *sh = ca_result;
  //struct RPSPeer *peer = (struct RPSPeer *) cls;

  if (NULL != emsg)
  {
    GNUNET_break (0);
    return;
  }
  //GNUNET_break (GNUNET_OK == GNUNET_STATISTICS_watch
  //              (sh, "core", "# peers connected",
  //               stat_iterator, peer));
  //GNUNET_break (GNUNET_OK == GNUNET_STATISTICS_watch
  //              (sh, "nse", "# peers connected",
  //               stat_iterator, peer));
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

  if (0 == evaluate () && HAVE_QUICK_QUIT == cur_test_run.have_quick_quit)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test succeeded before timeout\n");
    GNUNET_assert (NULL != post_test_task);
    GNUNET_SCHEDULER_cancel (post_test_task);
    post_test_task = GNUNET_SCHEDULER_add_now (&post_test_op, NULL);
    GNUNET_assert (NULL!= post_test_task);
  }
}

/**
 * Request random peers.
 */
static void
request_peers (void *cls)
{
  struct PendingRequest *pending_req = cls;
  struct RPSPeer *rps_peer;
  struct PendingReply *pending_rep;

  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
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
cancel_request_cb (void *cls)
{
  struct RPSPeer *rps_peer = cls;
  struct PendingReply *pending_rep;

  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
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


/**
 * @brief Set peers to (non-)malicious before execution
 *
 * Of signature #PreTest
 *
 * @param rps_peer the peer to set (non-) malicious
 * @param h the handle to the service
 */
static void
mal_pre (struct RPSPeer *rps_peer, struct GNUNET_RPS_Handle *h)
{
  #ifdef ENABLE_MALICIOUS
  uint32_t num_mal_peers;

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

  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
  {
    return;
  }

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
  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
  {
    return;
  }

  schedule_missing_requests (rps_peer);
}

/***********************************
 * DELAYED_REQUESTS
***********************************/
static void
delay_req_cb (struct RPSPeer *rps_peer)
{
  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
  {
    return;
  }

  schedule_missing_requests (rps_peer);
}

/***********************************
 * SEED
***********************************/
static void
seed_cb (struct RPSPeer *rps_peer)
{
  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
  {
    return;
  }

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
  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
  {
    return;
  }

  // TODO test seeding > GNUNET_MAX_MESSAGE_SIZE peers
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
  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
  {
    return;
  }

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
  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
  {
    return;
  }

  schedule_missing_requests (rps_peer);
  GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                     (cur_test_run.request_interval + 1)),
      cancel_request_cb, rps_peer);
}

/***********************************
 * CHURN
***********************************/

static void
churn (void *cls);

/**
 * @brief Starts churn
 *
 * Has signature of #MainTest
 *
 * This is not implemented too nicely as this is called for each peer, but we
 * only need to call it once. (Yes we check that we only schedule the task
 * once.)
 *
 * @param rps_peer The peer it's called for
 */
static void
churn_test_cb (struct RPSPeer *rps_peer)
{
  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
  {
    return;
  }

  /* Start churn */
  if (HAVE_CHURN == cur_test_run.have_churn && NULL == churn_task)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting churn task\n");
    churn_task = GNUNET_SCHEDULER_add_delayed (
          GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
          churn,
          NULL);
  } else {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Not starting churn task\n");
  }

  schedule_missing_requests (rps_peer);
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

  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
  {
    return;
  }

  GNUNET_TESTBED_operation_done (entry->op);
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to start/stop RPS at a peer\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_assert (0 != entry->delta);

  num_peers_online += entry->delta;

  if (PEER_GO_OFFLINE == entry->delta)
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

  else if (PEER_GO_ONLINE < entry->delta)
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
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Invalid value for delta: %i\n", entry->delta);
    GNUNET_break (0);
  }

  GNUNET_CONTAINER_DLL_remove (oplist_head, oplist_tail, entry);
  rps_peers[entry->index].entry_op_manage = NULL;
  GNUNET_free (entry);
  //if (num_peers_in_round[current_round] == peers_running)
  //  run_round ();
}

/**
 * @brief Set the rps-service up or down for a specific peer
 *
 * @param i index of action
 * @param j index of peer
 * @param delta (#PEER_ONLINE_DELTA) down (-1) or up (1)
 * @param prob_go_on_off the probability of the action
 */
static void
manage_service_wrapper (unsigned int i, unsigned int j,
                        enum PEER_ONLINE_DELTA delta,
                        double prob_go_on_off)
{
  struct OpListEntry *entry = NULL;
  uint32_t prob;

  /* make sure that management operation is not already scheduled */
  if (NULL != rps_peers[j].entry_op_manage)
  {
    return;
  }

  prob = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                   UINT32_MAX);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%u. selected peer (%u: %s) is %s.\n",
              i,
              j,
              GNUNET_i2s (rps_peers[j].peer_id),
              (PEER_GO_ONLINE == delta) ? "online" : "offline");
  if (prob < prob_go_on_off * UINT32_MAX)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s goes %s\n",
                GNUNET_i2s (rps_peers[j].peer_id),
                (PEER_GO_OFFLINE == delta) ? "offline" : "online");

    if (PEER_GO_OFFLINE == delta)
      cancel_pending_req_rep (&rps_peers[j]);
    entry = make_oplist_entry ();
    entry->delta = delta;
    entry->index = j;
    entry->op = GNUNET_TESTBED_peer_manage_service (NULL,
                                                    testbed_peers[j],
                                                    "rps",
                                                    &churn_cb,
                                                    entry,
                                                    (PEER_GO_OFFLINE == delta) ? 0 : 1);
    rps_peers[j].entry_op_manage = entry;
  }
}


static void
churn (void *cls)
{
  unsigned int i;
  unsigned int j;
  double portion_online;
  unsigned int *permut;
  double prob_go_offline;
  double portion_go_online;
  double portion_go_offline;

  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
  {
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Churn function executing\n");

  churn_task = NULL; /* Should be invalid by now */

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
    GNUNET_assert (NULL != rcv_rps_peer);
    tofile (file_name_dh,
             "%" PRIu32 "\n",
             (uint32_t) rcv_rps_peer->index);
  }
  default_reply_handle (cls, n, recv_peers);
}


static void
profiler_cb (struct RPSPeer *rps_peer)
{
  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test)
  {
    return;
  }

  /* Start churn */
  if (HAVE_CHURN == cur_test_run.have_churn && NULL == churn_task)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting churn task\n");
    churn_task = GNUNET_SCHEDULER_add_delayed (
          GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
          churn,
          NULL);
  } else {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Not starting churn task\n");
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
    RPS_sampler_elem_destroy (s_elem);
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

static uint32_t fac (uint32_t x)
{
  if (1 >= x)
  {
    return x;
  }
  return x * fac (x - 1);
}

static uint32_t binom (uint32_t n, uint32_t k)
{
  //GNUNET_assert (n >= k);
  if (k > n) return 0;
  if (0 > n) return 0;
  if (0 > k) return 0;
  if (0 == k) return 1;
  return fac (n)
    /
    fac(k) * fac(n - k);
}

/**
 * @brief is b in view of a?
 *
 * @param a
 * @param b
 *
 * @return
 */
static int is_in_view (uint32_t a, uint32_t b)
{
  uint32_t i;
  for (i = 0; i < rps_peers[a].cur_view_count; i++)
  {
    if (0 == memcmp (rps_peers[b].peer_id,
          &rps_peers[a].cur_view[i],
          sizeof (struct GNUNET_PeerIdentity)))
    {
      return GNUNET_YES;
    }
  }
  return GNUNET_NO;
}

static uint32_t get_idx_of_pid (const struct GNUNET_PeerIdentity *pid)
{
  uint32_t i;

  for (i = 0; i < num_peers; i++)
  {
    if (0 == memcmp (pid,
          rps_peers[i].peer_id,
          sizeof (struct GNUNET_PeerIdentity)))
    {
      return i;
    }
  }
  //return 0; /* Should not happen - make compiler happy */
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
             "No known _PeerIdentity %s!\n",
             GNUNET_i2s_full (pid));
  GNUNET_assert (0);
}

/**
 * @brief Counts number of peers in view of a that have b in their view
 *
 * @param a
 * @param uint32_tb
 *
 * @return
 */
static uint32_t count_containing_views (uint32_t a, uint32_t b)
{
  uint32_t i;
  uint32_t peer_idx;
  uint32_t count = 0;

  for (i = 0; i < rps_peers[a].cur_view_count; i++)
  {
    peer_idx = get_idx_of_pid (&rps_peers[a].cur_view[i]);
    if (GNUNET_YES == is_in_view (peer_idx, b))
    {
      count++;
    }
  }
  return count;
}

/**
 * @brief Computes the probability for each other peer to be selected by the
 * sampling process based on the views of all peers
 *
 * @param peer_idx index of the peer that is about to sample
 */
static void compute_probabilities (uint32_t peer_idx)
{
  //double probs[num_peers] = { 0 };
  double probs[num_peers];
  size_t probs_as_str_size = (num_peers * 10 + 1) * sizeof (char);
  char *probs_as_str = GNUNET_malloc (probs_as_str_size);
  char *probs_as_str_cpy;
  uint32_t i;
  double prob_push;
  double prob_pull;
  uint32_t view_size;
  uint32_t cont_views;
  uint32_t number_of_being_in_pull_events;
  int tmp;
  uint32_t count_non_zero_prob = 0;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Computing probabilities for peer %" PRIu32 "\n", peer_idx);
  /* Firstly without knowledge of old views */
  for (i = 0; i < num_peers; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "\tfor peer %" PRIu32 ":\n", i);
    view_size = rps_peers[i].cur_view_count;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "\t\tview_size: %" PRIu32 "\n", view_size);
    /* For peer i the probability of being sampled is
     * evenly distributed among all possibly observed peers. */
    /* We could have observed a peer in three cases:
     *   1. peer sent a push
     *   2. peer was contained in a pull reply
     *   3. peer was in history (sampler) - ignored for now */
    /* 1. Probability of having received a push from peer i */
    if ((GNUNET_YES == is_in_view (i, peer_idx)) &&
        (1 <= (0.45 * view_size)))
    {
      prob_push = 1.0 * binom (0.45 * view_size, 1)
        /
        binom (view_size, 0.45 * view_size);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                 "\t\t%" PRIu32 " is in %" PRIu32 "'s view, prob: %f\n",
                 peer_idx,
                 i,
                 prob_push);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                 "\t\tposs choices from view: %" PRIu32 ", containing i: %" PRIu32 "\n",
                 binom (view_size, 0.45 * view_size),
                 binom (0.45 * view_size, 1));
    } else {
      prob_push = 0;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                 "\t\t%" PRIu32 " is not in %" PRIu32 "'s view, prob: 0\n",
                 peer_idx,
                 i);
    }
    /* 2. Probability of peer i being contained in pulls */
    view_size = rps_peers[peer_idx].cur_view_count;
    cont_views = count_containing_views (peer_idx, i);
    number_of_being_in_pull_events =
      (binom (view_size, 0.45 * view_size) -
       binom (view_size - cont_views, 0.45 * view_size));
    if (0 != number_of_being_in_pull_events)
    {
      prob_pull = number_of_being_in_pull_events
        /
        (1.0 * binom (view_size, 0.45 * view_size));
    } else
    {
      prob_pull = 0;
    }
    probs[i] = prob_push + prob_pull - (prob_push * prob_pull);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
               "\t\t%" PRIu32 " has %" PRIu32 " of %" PRIu32
               " peers in its view who know %" PRIu32 " prob: %f\n",
               peer_idx,
               cont_views,
               view_size,
               i,
               prob_pull);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
               "\t\tnumber of possible pull combinations: %" PRIu32 "\n",
               binom (view_size, 0.45 * view_size));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
               "\t\tnumber of possible pull combinations without %" PRIu32
               ": %" PRIu32 "\n",
               i,
               binom (view_size - cont_views, 0.45 * view_size));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
               "\t\tnumber of possible pull combinations with %" PRIu32
               ": %" PRIu32 "\n",
               i,
               number_of_being_in_pull_events);

    if (0 != probs[i]) count_non_zero_prob++;
  }
  /* normalize */
  if (0 != count_non_zero_prob)
  {
    for (i = 0; i < num_peers; i++)
    {
      probs[i] = probs[i] * (1.0 / count_non_zero_prob);
    }
  } else {
    for (i = 0; i < num_peers; i++)
    {
      probs[i] = 0;
    }
  }
  /* str repr */
  for (i = 0; i < num_peers; i++)
  {
    probs_as_str_cpy = GNUNET_strndup (probs_as_str, probs_as_str_size);
    tmp = GNUNET_snprintf (probs_as_str,
                           probs_as_str_size,
                           "%s %7.6f", probs_as_str_cpy, probs[i]);
    GNUNET_free (probs_as_str_cpy);
    GNUNET_assert (0 <= tmp);
  }

  to_file_w_len (rps_peers[peer_idx].file_name_probs,
                 probs_as_str_size,
                 probs_as_str);
  GNUNET_free (probs_as_str);
}

/**
 * @brief This counts the number of peers in which views a given peer occurs.
 *
 * It also stores this value in the rps peer.
 *
 * @param peer_idx the index of the peer to count the representation
 *
 * @return the number of occurrences
 */
static uint32_t count_peer_in_views_2 (uint32_t peer_idx)
{
  uint32_t i, j;
  uint32_t count = 0;

  for (i = 0; i < num_peers; i++) /* Peer in which view is counted */
  {
    for (j = 0; j < rps_peers[i].cur_view_count; j++) /* entry in view */
    {
      if (0 == memcmp (rps_peers[peer_idx].peer_id,
            &rps_peers[i].cur_view[j],
            sizeof (struct GNUNET_PeerIdentity)))
      {
        count++;
        break;
      }
    }
  }
  rps_peers[peer_idx].count_in_views = count;
  return count;
}

static uint32_t cumulated_view_sizes ()
{
  uint32_t i;

  view_sizes = 0;
  for (i = 0; i < num_peers; i++) /* Peer in which view is counted */
  {
    view_sizes += rps_peers[i].cur_view_count;
  }
  return view_sizes;
}

static void count_peer_in_views (uint32_t *count_peers)
{
  uint32_t i, j;

  for (i = 0; i < num_peers; i++) /* Peer in which view is counted */
  {
    for (j = 0; j < rps_peers[i].cur_view_count; j++) /* entry in view */
    {
      if (0 == memcmp (rps_peers[i].peer_id,
            &rps_peers[i].cur_view[j],
            sizeof (struct GNUNET_PeerIdentity)))
      {
        count_peers[i]++;
      }
    }
  }
}

void compute_diversity ()
{
  uint32_t i;
  /* ith entry represents the numer of occurrences in other peer's views */
  uint32_t *count_peers = GNUNET_new_array (num_peers, uint32_t);
  uint32_t views_total_size;
  double expected;
  /* deviation from expected number of peers */
  double *deviation = GNUNET_new_array (num_peers, double);

  views_total_size = 0;
  expected = 0;

  /* For each peer count its representation in other peer's views*/
  for (i = 0; i < num_peers; i++) /* Peer to count */
  {
    views_total_size += rps_peers[i].cur_view_count;
    count_peer_in_views (count_peers);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
               "Counted representation of %" PRIu32 "th peer [%s]: %" PRIu32"\n",
               i,
               GNUNET_i2s (rps_peers[i].peer_id),
               count_peers[i]);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
             "size of all views combined: %" PRIu32 "\n",
             views_total_size);
  expected = ((double) 1/num_peers) * views_total_size;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
             "Expected number of occurrences of each peer in all views: %f\n",
             expected);
  for (i = 0; i < num_peers; i++) /* Peer to count */
  {
    deviation[i] = expected - count_peers[i];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
               "Deviation from expectation: %f\n", deviation[i]);
  }
  GNUNET_free (count_peers);
  GNUNET_free (deviation);
}

void print_view_sizes()
{
  uint32_t i;

  for (i = 0; i < num_peers; i++) /* Peer to count */
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
               "View size of %" PRIu32 ". [%s] is %" PRIu32 "\n",
               i,
               GNUNET_i2s (rps_peers[i].peer_id),
               rps_peers[i].cur_view_count);
  }
}

void all_views_updated_cb()
{
  compute_diversity();
  print_view_sizes();
}

void view_update_cb (void *cls,
                     uint64_t view_size,
                     const struct GNUNET_PeerIdentity *peers)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "View was updated (%" PRIu64 ")\n", view_size);
  struct RPSPeer *rps_peer = (struct RPSPeer *) cls;
  to_file ("/tmp/rps/view_sizes.txt",
         "%" PRIu64 " %" PRIu32 "",
         rps_peer->index,
         view_size);
  for (int i = 0; i < view_size; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
               "\t%s\n", GNUNET_i2s (&peers[i]));
  }
  GNUNET_array_grow (rps_peer->cur_view,
                     rps_peer->cur_view_count,
                     view_size);
  //*rps_peer->cur_view = *peers;
  GNUNET_memcpy (rps_peer->cur_view,
                 peers,
                 view_size * sizeof (struct GNUNET_PeerIdentity));
  to_file ("/tmp/rps/count_in_views.txt",
         "%" PRIu64 " %" PRIu32 "",
         rps_peer->index,
         count_peer_in_views_2 (rps_peer->index));
  cumulated_view_sizes();
  if (0 != view_size)
  {
    to_file ("/tmp/rps/repr.txt",
           "%" PRIu64 /* index */
           " %" PRIu32 /* occurrence in views */
           " %" PRIu32 /* view sizes */
           " %f" /* fraction of repr in views */
           " %f" /* average view size */
           " %f" /* prob of occurrence in view slot */
           " %f" "", /* exp frac of repr in views */
           rps_peer->index,
           count_peer_in_views_2 (rps_peer->index),
           view_sizes,
           count_peer_in_views_2 (rps_peer->index) / (view_size * 1.0), /* fraction of representation in views */
           view_sizes / (view_size * 1.0), /* average view size */
           1.0 /view_size, /* prob of occurrence in view slot */
           (1.0/view_size) * (view_sizes/view_size) /* expected fraction of repr in views */
           );
  }
  compute_probabilities (rps_peer->index);
  all_views_updated_cb();
}

static void
pre_profiler (struct RPSPeer *rps_peer, struct GNUNET_RPS_Handle *h)
{
  rps_peer->file_name_probs =
    store_prefix_file_name (rps_peer->peer_id, "probs");
  GNUNET_RPS_view_request (h, 0, view_update_cb, rps_peer);
}

void write_final_stats (void){
  uint32_t i;

  for (i = 0; i < num_peers; i++)
  {
    to_file ("/tmp/rps/final_stats.dat",
             "%" PRIu32 " " /* index */
             "%s %" /* id */
             PRIu64 " %" /* rounds */
             PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" /* blocking */
             PRIu64 " %" PRIu64 " %" PRIu64 " %" /* issued */
             PRIu64 " %" PRIu64 " %" PRIu64 " %" /* sent */
             PRIu64 " %" PRIu64 " %" PRIu64 /* recv */,
             i,
             GNUNET_i2s (rps_peers[i].peer_id),
             rps_peers[i].num_rounds,
             rps_peers[i].num_blocks,
             rps_peers[i].num_blocks_many_push,
             rps_peers[i].num_blocks_no_push,
             rps_peers[i].num_blocks_no_pull,
             rps_peers[i].num_blocks_many_push_no_pull,
             rps_peers[i].num_blocks_no_push_no_pull,
             rps_peers[i].num_issued_push,
             rps_peers[i].num_issued_pull_req,
             rps_peers[i].num_issued_pull_rep,
             rps_peers[i].num_sent_push,
             rps_peers[i].num_sent_pull_req,
             rps_peers[i].num_sent_pull_rep,
             rps_peers[i].num_recv_push,
             rps_peers[i].num_recv_pull_req,
             rps_peers[i].num_recv_pull_rep);
  }
}

/**
 * Continuation called by #GNUNET_STATISTICS_get() functions.
 *
 * Remembers that this specific statistics value was received for this peer.
 * Checks whether all peers received their statistics yet.
 * Issues the shutdown.
 *
 * @param cls closure
 * @param success #GNUNET_OK if statistics were
 *        successfully obtained, #GNUNET_SYSERR if not.
 */
void
post_test_shutdown_ready_cb (void *cls,
                             int success)
{
  struct STATcls *stat_cls = (struct STATcls *) cls;
  struct RPSPeer *rps_peer = stat_cls->rps_peer;
  if (GNUNET_OK == success)
  {
    /* set flag that we we got the value */
    rps_peer->stat_collected_flags |= stat_cls->stat_type;
  } else {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Peer %u did not receive statistics value\n",
        rps_peer->index);
    GNUNET_free (stat_cls);
    GNUNET_break (0);
  }

  if (NULL != rps_peer->stat_op &&
      GNUNET_YES == check_statistics_collect_completed_single_peer (rps_peer))
  {
    GNUNET_TESTBED_operation_done (rps_peer->stat_op);
  }

  write_final_stats ();
  if (GNUNET_YES == check_statistics_collect_completed())
  {
    //write_final_stats ();
    GNUNET_free (stat_cls);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "Shutting down\n");
    GNUNET_SCHEDULER_shutdown ();
  } else {
    GNUNET_free (stat_cls);
  }
}

/**
 * @brief Converts string representation to the corresponding #STAT_TYPE enum.
 *
 * @param stat_str string representation of statistics specifier
 *
 * @return corresponding enum
 */
enum STAT_TYPE stat_str_2_type (const char *stat_str)
{
  if (0 == strncmp ("# rounds blocked - no pull replies", stat_str, strlen ("# rounds blocked - no pull replies")))
  {
    return STAT_TYPE_BLOCKS_NO_PULL;
  }
  else if (0 == strncmp ("# rounds blocked - too many pushes, no pull replies", stat_str, strlen ("# rounds blocked - too many pushes, no pull replies")))
  {
    return STAT_TYPE_BLOCKS_MANY_PUSH_NO_PULL;
  }
  else if (0 == strncmp ("# rounds blocked - too many pushes", stat_str, strlen ("# rounds blocked - too many pushes")))
  {
    return STAT_TYPE_BLOCKS_MANY_PUSH;
  }
  else if (0 == strncmp ("# rounds blocked - no pushes, no pull replies", stat_str, strlen ("# rounds blocked - no pushes, no pull replies")))
  {
    return STAT_TYPE_BLOCKS_NO_PUSH_NO_PULL;
  }
  else if (0 == strncmp ("# rounds blocked - no pushes", stat_str, strlen ("# rounds blocked - no pushes")))
  {
    return STAT_TYPE_BLOCKS_NO_PUSH;
  }
  else if (0 == strncmp ("# rounds blocked", stat_str, strlen ("# rounds blocked")))
  {
    return STAT_TYPE_BLOCKS;
  }
  else if (0 == strncmp ("# rounds", stat_str, strlen ("# rounds")))
  {
    return STAT_TYPE_ROUNDS;
  }
  else if (0 == strncmp ("# push send issued", stat_str, strlen ("# push send issued")))
  {
    return STAT_TYPE_ISSUED_PUSH_SEND;
  }
  else if (0 == strncmp ("# pull request send issued", stat_str, strlen ("# pull request send issued")))
  {
    return STAT_TYPE_ISSUED_PULL_REQ;
  }
  else if (0 == strncmp ("# pull reply send issued", stat_str, strlen ("# pull reply send issued")))
  {
    return STAT_TYPE_ISSUED_PULL_REP;
  }
  else if (0 == strncmp ("# pushes sent", stat_str, strlen ("# pushes sent")))
  {
    return STAT_TYPE_SENT_PUSH_SEND;
  }
  else if (0 == strncmp ("# pull requests sent", stat_str, strlen ("# pull requests sent")))
  {
    return STAT_TYPE_SENT_PULL_REQ;
  }
  else if (0 == strncmp ("# pull replys sent", stat_str, strlen ("# pull replys sent")))
  {
    return STAT_TYPE_SENT_PULL_REP;
  }
  else if (0 == strncmp ("# push message received", stat_str, strlen ("# push message received")))
  {
    return STAT_TYPE_RECV_PUSH_SEND;
  }
  else if (0 == strncmp ("# pull request message received", stat_str, strlen ("# pull request message received")))
  {
    return STAT_TYPE_RECV_PULL_REQ;
  }
  else if (0 == strncmp ("# pull reply messages received", stat_str, strlen ("# pull reply messages received")))
  {
    return STAT_TYPE_RECV_PULL_REP;
  }
  return STAT_TYPE_MAX;
}


/**
 * @brief Converts #STAT_TYPE enum to the equivalent string representation that
 * is stored with the statistics service.
 *
 * @param stat_type #STAT_TYPE enum
 *
 * @return string representation that matches statistics value
 */
char* stat_type_2_str (enum STAT_TYPE stat_type)
{
  switch (stat_type)
  {
    case STAT_TYPE_ROUNDS:
      return "# rounds";
    case STAT_TYPE_BLOCKS:
      return "# rounds blocked";
    case STAT_TYPE_BLOCKS_MANY_PUSH:
      return "# rounds blocked - too many pushes";
    case STAT_TYPE_BLOCKS_NO_PUSH:
      return "# rounds blocked - no pushes";
    case STAT_TYPE_BLOCKS_NO_PULL:
      return "# rounds blocked - no pull replies";
    case STAT_TYPE_BLOCKS_MANY_PUSH_NO_PULL:
      return "# rounds blocked - too many pushes, no pull replies";
    case STAT_TYPE_BLOCKS_NO_PUSH_NO_PULL:
      return "# rounds blocked - no pushes, no pull replies";
    case STAT_TYPE_ISSUED_PUSH_SEND:
      return "# push send issued";
    case STAT_TYPE_ISSUED_PULL_REQ:
      return "# pull request send issued";
    case STAT_TYPE_ISSUED_PULL_REP:
      return "# pull reply send issued";
    case STAT_TYPE_SENT_PUSH_SEND:
      return "# pushes sent";
    case STAT_TYPE_SENT_PULL_REQ:
      return "# pull requests sent";
    case STAT_TYPE_SENT_PULL_REP:
      return "# pull replys sent";
    case STAT_TYPE_RECV_PUSH_SEND:
      return "# push message received";
    case STAT_TYPE_RECV_PULL_REQ:
      return "# pull request message received";
    case STAT_TYPE_RECV_PULL_REP:
      return "# pull reply messages received";
    case STAT_TYPE_MAX:
    default:
      return "ERROR";
      ;
  }
}

/**
 * Callback function to process statistic values.
 *
 * @param cls closure
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent #GNUNET_YES if the value is persistent, #GNUNET_NO if not
 * @return #GNUNET_OK to continue, #GNUNET_SYSERR to abort iteration
 */
int
stat_iterator (void *cls,
               const char *subsystem,
               const char *name,
               uint64_t value,
               int is_persistent)
{
  const struct STATcls *stat_cls = (const struct STATcls *) cls;
  struct RPSPeer *rps_peer = (struct RPSPeer *) stat_cls->rps_peer;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got stat value: %s - %" PRIu64 "\n",
      //stat_type_2_str (stat_cls->stat_type),
      name,
      value);
  to_file (rps_peer->file_name_stats,
          "%s: %" PRIu64 "\n",
          name,
          value);
  switch (stat_str_2_type (name))
  {
    case STAT_TYPE_ROUNDS:
      rps_peer->num_rounds = value;
      break;
    case STAT_TYPE_BLOCKS:
      rps_peer->num_blocks = value;
      break;
    case STAT_TYPE_BLOCKS_MANY_PUSH:
      rps_peer->num_blocks_many_push = value;
      break;
    case STAT_TYPE_BLOCKS_NO_PUSH:
      rps_peer->num_blocks_no_push = value;
      break;
    case STAT_TYPE_BLOCKS_NO_PULL:
      rps_peer->num_blocks_no_pull = value;
      break;
    case STAT_TYPE_BLOCKS_MANY_PUSH_NO_PULL:
      rps_peer->num_blocks_many_push_no_pull = value;
      break;
    case STAT_TYPE_BLOCKS_NO_PUSH_NO_PULL:
      rps_peer->num_blocks_no_push_no_pull = value;
      break;
    case STAT_TYPE_ISSUED_PUSH_SEND:
      rps_peer->num_issued_push = value;
      break;
    case STAT_TYPE_ISSUED_PULL_REQ:
      rps_peer->num_issued_pull_req = value;
      break;
    case STAT_TYPE_ISSUED_PULL_REP:
      rps_peer->num_issued_pull_rep = value;
      break;
    case STAT_TYPE_SENT_PUSH_SEND:
      rps_peer->num_sent_push = value;
      break;
    case STAT_TYPE_SENT_PULL_REQ:
      rps_peer->num_sent_pull_req = value;
      break;
    case STAT_TYPE_SENT_PULL_REP:
      rps_peer->num_sent_pull_rep = value;
      break;
    case STAT_TYPE_RECV_PUSH_SEND:
      rps_peer->num_recv_push = value;
      break;
    case STAT_TYPE_RECV_PULL_REQ:
      rps_peer->num_recv_pull_req = value;
      break;
    case STAT_TYPE_RECV_PULL_REP:
      rps_peer->num_recv_pull_rep = value;
      break;
    case STAT_TYPE_MAX:
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                 "Unknown statistics string: %s\n",
                 name);
      break;
  }
  return GNUNET_OK;
}

void post_profiler (struct RPSPeer *rps_peer)
{
  if (COLLECT_STATISTICS != cur_test_run.have_collect_statistics)
  {
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Going to request statistic values with mask 0x%" PRIx32 "\n",
      cur_test_run.stat_collect_flags);

  struct STATcls *stat_cls;
  uint32_t stat_type;
  for (stat_type = STAT_TYPE_ROUNDS;
      stat_type < STAT_TYPE_MAX;
      stat_type = stat_type <<1)
  {
    if (stat_type & cur_test_run.stat_collect_flags)
    {
      stat_cls = GNUNET_malloc (sizeof (struct STATcls));
      stat_cls->rps_peer = rps_peer;
      stat_cls->stat_type = stat_type;
      rps_peer->file_name_stats =
        store_prefix_file_name (rps_peer->peer_id, "stats");
      GNUNET_STATISTICS_get (rps_peer->stats_h,
                             "rps",
                             stat_type_2_str (stat_type),
                             post_test_shutdown_ready_cb,
                             stat_iterator,
                             (struct STATcls *) stat_cls);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
          "Requested statistics for %s (peer %" PRIu32 ")\n",
          stat_type_2_str (stat_type),
          rps_peer->index);
    }
  }
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "RUN was called\n");

  /* Check whether we timed out */
  if (n_peers != num_peers ||
      NULL == peers ||
      0 == links_succeeded)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Going down due to args (eg. timeout)\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\tn_peers: %u\n", n_peers);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\tnum_peers: %" PRIu32 "\n", num_peers);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\tpeers: %p\n", peers);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\tlinks_succeeded: %u\n", links_succeeded);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }


  /* Initialize peers */
  testbed_peers = peers;
  num_peers_online = 0;
  for (i = 0; i < num_peers; i++)
  {
    entry = make_oplist_entry ();
    entry->index = i;
    rps_peers[i].index = i;
    if (NULL != cur_test_run.init_peer)
      cur_test_run.init_peer (&rps_peers[i]);
    if (NO_COLLECT_VIEW == cur_test_run.have_collect_view)
    {
      rps_peers->cur_view_count = 0;
      rps_peers->cur_view = NULL;
    }
    entry->op = GNUNET_TESTBED_peer_get_information (peers[i],
                                                     GNUNET_TESTBED_PIT_IDENTITY,
                                                     &info_cb,
                                                     entry);
  }

  /* Bring peers up */
  GNUNET_assert (num_peers == n_peers);
  for (i = 0; i < n_peers; i++)
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
    /* Connect all peers to statistics service */
    if (COLLECT_STATISTICS == cur_test_run.have_collect_statistics)
    {
      rps_peers[i].stat_op =
        GNUNET_TESTBED_service_connect (NULL,
                                        peers[i],
                                        "statistics",
                                        stat_complete_cb,
                                        &rps_peers[i],
                                        &stat_connect_adapter,
                                        &stat_disconnect_adapter,
                                        &rps_peers[i]);
    }
  }

  if (NULL != churn_task)
    GNUNET_SCHEDULER_cancel (churn_task);
  post_test_task = GNUNET_SCHEDULER_add_delayed (timeout, &post_test_op, NULL);
  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
      (timeout_s * 1.2) + 0.1 * num_peers);
  shutdown_task = GNUNET_SCHEDULER_add_delayed (timeout, &shutdown_op, NULL);
  shutdown_task = GNUNET_SCHEDULER_add_shutdown (shutdown_op, NULL);

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

  /* Defaults for tests */
  num_peers = 5;
  cur_test_run.name = "test-rps-default";
  cur_test_run.init_peer = default_init_peer;
  cur_test_run.pre_test = NULL;
  cur_test_run.reply_handle = default_reply_handle;
  cur_test_run.eval_cb = default_eval_cb;
  cur_test_run.post_test = NULL;
  cur_test_run.have_churn = HAVE_CHURN;
  cur_test_run.have_collect_statistics = NO_COLLECT_STATISTICS;
  cur_test_run.stat_collect_flags = 0;
  cur_test_run.have_collect_view = NO_COLLECT_VIEW;
  churn_task = NULL;
  timeout_s = 30;

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
    cur_test_run.have_churn = HAVE_NO_CHURN;
  }

  else if (strstr (argv[0], "_delayed_reqs") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test delayed requests\n");
    cur_test_run.name = "test-rps-delayed-reqs";
    cur_test_run.main_test = delay_req_cb;
    cur_test_run.have_churn = HAVE_NO_CHURN;
  }

  else if (strstr (argv[0], "_seed_big") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test seeding (num_peers > GNUNET_MAX_MESSAGE_SIZE)\n");
    num_peers = 1;
    cur_test_run.name = "test-rps-seed-big";
    cur_test_run.main_test = seed_big_cb;
    cur_test_run.eval_cb = no_eval;
    cur_test_run.have_churn = HAVE_NO_CHURN;
    timeout_s = 10;
  }

  else if (strstr (argv[0], "_single_peer_seed") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test seeding and requesting on a single peer\n");
    cur_test_run.name = "test-rps-single-peer-seed";
    cur_test_run.main_test = single_peer_seed_cb;
    cur_test_run.have_churn = HAVE_NO_CHURN;
  }

  else if (strstr (argv[0], "_seed_request") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test seeding and requesting on multiple peers\n");
    cur_test_run.name = "test-rps-seed-request";
    cur_test_run.main_test = seed_req_cb;
    cur_test_run.have_churn = HAVE_NO_CHURN;
  }

  else if (strstr (argv[0], "_seed") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test seeding\n");
    cur_test_run.name = "test-rps-seed";
    cur_test_run.main_test = seed_cb;
    cur_test_run.eval_cb = no_eval;
    cur_test_run.have_churn = HAVE_NO_CHURN;
  }

  else if (strstr (argv[0], "_req_cancel") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test cancelling a request\n");
    cur_test_run.name = "test-rps-req-cancel";
    num_peers = 1;
    cur_test_run.main_test = req_cancel_cb;
    cur_test_run.eval_cb = no_eval;
    cur_test_run.have_churn = HAVE_NO_CHURN;
    timeout_s = 10;
  }

  else if (strstr (argv[0], "_churn") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test churn\n");
    cur_test_run.name = "test-rps-churn";
    num_peers = 5;
    cur_test_run.init_peer = default_init_peer;
    cur_test_run.main_test = churn_test_cb;
    cur_test_run.reply_handle = default_reply_handle;
    cur_test_run.eval_cb = default_eval_cb;
    cur_test_run.have_churn = HAVE_NO_CHURN;
    cur_test_run.have_quick_quit = HAVE_NO_QUICK_QUIT;
    timeout_s = 10;
  }

  else if (strstr (argv[0], "profiler") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "This is the profiler\n");
    cur_test_run.name = "test-rps-profiler";
    num_peers = 100;
    mal_type = 3;
    cur_test_run.init_peer = profiler_init_peer;
    //cur_test_run.pre_test = mal_pre;
    cur_test_run.pre_test = pre_profiler;
    cur_test_run.main_test = profiler_cb;
    cur_test_run.reply_handle = profiler_reply_handle;
    cur_test_run.eval_cb = profiler_eval;
    cur_test_run.post_test = post_profiler;
    cur_test_run.request_interval = 2;
    cur_test_run.num_requests = 5;
    //cur_test_run.have_churn = HAVE_CHURN;
    cur_test_run.have_churn = HAVE_NO_CHURN;
    cur_test_run.have_quick_quit = HAVE_NO_QUICK_QUIT;
    cur_test_run.have_collect_statistics = COLLECT_STATISTICS;
    cur_test_run.stat_collect_flags = STAT_TYPE_ROUNDS |
                                      STAT_TYPE_BLOCKS |
                                      STAT_TYPE_BLOCKS_MANY_PUSH |
                                      STAT_TYPE_BLOCKS_NO_PUSH |
                                      STAT_TYPE_BLOCKS_NO_PULL |
                                      STAT_TYPE_BLOCKS_MANY_PUSH_NO_PULL |
                                      STAT_TYPE_BLOCKS_NO_PUSH_NO_PULL |
                                      STAT_TYPE_ISSUED_PUSH_SEND |
                                      STAT_TYPE_ISSUED_PULL_REQ |
                                      STAT_TYPE_ISSUED_PULL_REP |
                                      STAT_TYPE_SENT_PUSH_SEND |
                                      STAT_TYPE_SENT_PULL_REQ |
                                      STAT_TYPE_SENT_PULL_REP |
                                      STAT_TYPE_RECV_PUSH_SEND |
                                      STAT_TYPE_RECV_PULL_REQ |
                                      STAT_TYPE_RECV_PULL_REP;
    cur_test_run.have_collect_view = COLLECT_VIEW;
    timeout_s = 150;

    /* 'Clean' directory */
    (void) GNUNET_DISK_directory_remove ("/tmp/rps/");
    GNUNET_DISK_directory_create ("/tmp/rps/");
  }
  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, timeout_s);

  rps_peers = GNUNET_new_array (num_peers, struct RPSPeer);
  peer_map = GNUNET_CONTAINER_multipeermap_create (num_peers, GNUNET_NO);
  rps_peer_ids = GNUNET_new_array (num_peers, struct GNUNET_PeerIdentity);
  if ( (2 == mal_type) ||
       (3 == mal_type))
    target_peer = &rps_peer_ids[num_peers - 2];
  if (profiler_eval == cur_test_run.eval_cb)
    eval_peer = &rps_peers[num_peers - 1];    /* FIXME: eval_peer could be a
                                                 malicious peer if not careful
                                                 with the malicious portion */

  ok = 1;
  ret_value = GNUNET_TESTBED_test_run (cur_test_run.name,
                                       "test_rps.conf",
                                       num_peers,
                                       0, NULL, NULL,
                                       &run, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "_test_run returned.\n");
  if (GNUNET_OK != ret_value)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Test did not run successfully!\n");
  }

  ret_value = cur_test_run.eval_cb();
  
  if (NO_COLLECT_VIEW == cur_test_run.have_collect_view)
  {
    GNUNET_array_grow (rps_peers->cur_view,
                       rps_peers->cur_view_count,
                       0);
  }
  GNUNET_free (rps_peers);
  GNUNET_free (rps_peer_ids);
  GNUNET_CONTAINER_multipeermap_destroy (peer_map);
  return ret_value;
}

/* end of test_rps.c */
