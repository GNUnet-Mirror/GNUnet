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

     SPDX-License-Identifier: AGPL3.0-or-later
*/
/**
 * @file rps/test_rps.c
 * @brief Testcase for the random peer sampling service.  Starts
 *        a peergroup with a given number of peers, then waits to
 *        receive size pushes/pulls from each peer.  Expects to wait
 *        for one message from each peer.
 */
#include "platform.h"
//#include "rps_test_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"

#include "gnunet_rps_service.h"
#include "rps-test_util.h"
#include "gnunet-service-rps_sampler_elem.h"

#include <inttypes.h>


#define BIT(n) (1 << (n))

/**
 * How many peers do we start?
 */
static uint32_t num_peers;

/**
 * @brief numer of bits required to represent the largest peer id
 */
static unsigned bits_needed;

/**
 * How long do we run the test?
 */
static struct GNUNET_TIME_Relative duration;

/**
 * When do we do a hard shutdown?
 */
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

enum STAT_TYPE
{
  STAT_TYPE_ROUNDS,                   /*   0 */
  STAT_TYPE_BLOCKS,                   /*   1 */
  STAT_TYPE_BLOCKS_MANY_PUSH,         /*   2 */
  STAT_TYPE_BLOCKS_NO_PUSH,           /*   3 */
  STAT_TYPE_BLOCKS_NO_PULL,           /*   4 */
  STAT_TYPE_BLOCKS_MANY_PUSH_NO_PULL, /*   5 */
  STAT_TYPE_BLOCKS_NO_PUSH_NO_PULL,   /*   6 */
  STAT_TYPE_ISSUED_PUSH_SEND,         /*   7 */
  STAT_TYPE_ISSUED_PULL_REQ,          /*   8 */
  STAT_TYPE_ISSUED_PULL_REQ_MH,       /*   9 */
  STAT_TYPE_ISSUED_PULL_REP,          /*  10 */
  STAT_TYPE_SENT_PUSH_SEND,           /*  11 */
  STAT_TYPE_SENT_PULL_REQ,            /*  12 */
  STAT_TYPE_SENT_PULL_REQ_MH,         /*  13 */
  STAT_TYPE_SENT_PULL_REP,            /*  14 */
  STAT_TYPE_RECV_PUSH_SEND,           /*  15 */
  STAT_TYPE_RECV_PULL_REQ,            /*  16 */
  STAT_TYPE_RECV_PULL_REQ_MH,         /*  17 */
  STAT_TYPE_RECV_PULL_REP,            /*  18 */
  STAT_TYPE_RECV_PULL_REP_MH,         /*  19 */
  STAT_TYPE_VIEW_SIZE,                /*  20 */
  STAT_TYPE_KNOWN_PEERS,              /*  21 */
  STAT_TYPE_VALID_PEERS,              /*  22 */
  STAT_TYPE_LEARND_PEERS,             /*  23 */
  STAT_TYPE_PENDING_ONLINE_CHECKS,    /*  24 */
  STAT_TYPE_UNREQUESTED_PULL_REPLIES, /*  25 */
  STAT_TYPE_PEERS_IN_PUSH_MAP,        /*  26 */
  STAT_TYPE_PEERS_IN_PULL_MAP,        /*  27 */
  STAT_TYPE_PEERS_IN_VIEW,            /*  28 */
  STAT_TYPE_VIEW_SIZE_AIM,            /*  29 */
  STAT_TYPE_MAX,                      /*  30 */
};

static char* stat_type_strings[] = {
  "# rounds",
  "# rounds blocked",
  "# rounds blocked - too many pushes",
  "# rounds blocked - no pushes",
  "# rounds blocked - no pull replies",
  "# rounds blocked - too many pushes, no pull replies",
  "# rounds blocked - no pushes, no pull replies",
  "# push send issued",
  "# pull request send issued",
  "# pull request send issued (multi-hop peer)",
  "# pull reply send issued",
  "# pushes sent",
  "# pull requests sent",
  "# pull requests sent (multi-hop peer)",
  "# pull replys sent",
  "# push message received",
  "# pull request message received",
  "# pull request message received (multi-hop peer)",
  "# pull reply messages received",
  "# pull reply messages received (multi-hop peer)",
  "view size",
  "# known peers",
  "# valid peers",
  "# learnd peers",
  "# pending online checks",
  "# unrequested pull replies",
  "# peers in push map at end of round",
  "# peers in pull map at end of round",
  "# peers in view at end of round",
  "view size aim",
};

struct STATcls
{
  struct RPSPeer *rps_peer;
  enum STAT_TYPE stat_type;
};


/**
 * @brief Converts string representation to the corresponding #STAT_TYPE enum.
 *
 * @param stat_str string representation of statistics specifier
 *
 * @return corresponding enum
 */
enum STAT_TYPE stat_str_2_type (const char *stat_str)
{
  if (0 == strncmp (stat_type_strings[STAT_TYPE_BLOCKS_NO_PULL],
                    stat_str,
                    strlen (stat_type_strings[STAT_TYPE_BLOCKS_NO_PULL])))
  {
    return STAT_TYPE_BLOCKS_NO_PULL;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_BLOCKS_MANY_PUSH_NO_PULL],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_BLOCKS_MANY_PUSH_NO_PULL])))
  {
    return STAT_TYPE_BLOCKS_MANY_PUSH_NO_PULL;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_BLOCKS_MANY_PUSH],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_BLOCKS_MANY_PUSH])))
  {
    return STAT_TYPE_BLOCKS_MANY_PUSH;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_BLOCKS_NO_PUSH_NO_PULL],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_BLOCKS_NO_PUSH_NO_PULL])))
  {
    return STAT_TYPE_BLOCKS_NO_PUSH_NO_PULL;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_BLOCKS_NO_PUSH],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_BLOCKS_NO_PUSH])))
  {
    return STAT_TYPE_BLOCKS_NO_PUSH;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_BLOCKS],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_BLOCKS])))
  {
    return STAT_TYPE_BLOCKS;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_ROUNDS],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_ROUNDS])))
  {
    return STAT_TYPE_ROUNDS;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_ISSUED_PUSH_SEND],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_ISSUED_PUSH_SEND])))
  {
    return STAT_TYPE_ISSUED_PUSH_SEND;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_ISSUED_PULL_REQ],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_ISSUED_PULL_REQ])))
  {
    return STAT_TYPE_ISSUED_PULL_REQ;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_ISSUED_PULL_REQ_MH],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_ISSUED_PULL_REQ_MH])))
  {
    return STAT_TYPE_ISSUED_PULL_REQ_MH;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_ISSUED_PULL_REP],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_ISSUED_PULL_REP])))
  {
    return STAT_TYPE_ISSUED_PULL_REP;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_SENT_PUSH_SEND],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_SENT_PUSH_SEND])))
  {
    return STAT_TYPE_SENT_PUSH_SEND;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_SENT_PULL_REQ],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_SENT_PULL_REQ])))
  {
    return STAT_TYPE_SENT_PULL_REQ;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_SENT_PULL_REQ_MH],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_SENT_PULL_REQ_MH])))
  {
    return STAT_TYPE_SENT_PULL_REQ_MH;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_SENT_PULL_REP],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_SENT_PULL_REP])))
  {
    return STAT_TYPE_SENT_PULL_REP;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_RECV_PUSH_SEND],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_RECV_PUSH_SEND])))
  {
    return STAT_TYPE_RECV_PUSH_SEND;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_RECV_PULL_REQ],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_RECV_PULL_REQ])))
  {
    return STAT_TYPE_RECV_PULL_REQ;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_RECV_PULL_REQ_MH],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_RECV_PULL_REQ_MH])))
  {
    return STAT_TYPE_RECV_PULL_REQ_MH;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_RECV_PULL_REP],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_RECV_PULL_REP])))
  {
    return STAT_TYPE_RECV_PULL_REP;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_RECV_PULL_REP_MH],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_RECV_PULL_REP_MH])))
  {
    return STAT_TYPE_RECV_PULL_REP_MH;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_VIEW_SIZE],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_VIEW_SIZE])))
  {
    return STAT_TYPE_VIEW_SIZE;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_KNOWN_PEERS],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_KNOWN_PEERS])))
  {
    return STAT_TYPE_KNOWN_PEERS;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_VALID_PEERS],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_VALID_PEERS])))
  {
    return STAT_TYPE_VALID_PEERS;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_LEARND_PEERS],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_LEARND_PEERS])))
  {
    return STAT_TYPE_LEARND_PEERS;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_PENDING_ONLINE_CHECKS],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_PENDING_ONLINE_CHECKS])))
  {
    return STAT_TYPE_PENDING_ONLINE_CHECKS;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_UNREQUESTED_PULL_REPLIES],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_UNREQUESTED_PULL_REPLIES])))
  {
    return STAT_TYPE_UNREQUESTED_PULL_REPLIES;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_PEERS_IN_PUSH_MAP],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_PEERS_IN_PUSH_MAP])))
  {
    return STAT_TYPE_PEERS_IN_PUSH_MAP;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_PEERS_IN_PULL_MAP],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_PEERS_IN_PULL_MAP])))
  {
    return STAT_TYPE_PEERS_IN_PULL_MAP;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_PEERS_IN_VIEW],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_PEERS_IN_VIEW])))
  {
    return STAT_TYPE_PEERS_IN_VIEW;
  }
  else if (0 == strncmp (stat_type_strings[STAT_TYPE_VIEW_SIZE_AIM],
                         stat_str,
                         strlen (stat_type_strings[STAT_TYPE_VIEW_SIZE_AIM])))
  {
    return STAT_TYPE_VIEW_SIZE_AIM;
  }
  return STAT_TYPE_MAX;
}


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
  uint64_t stats[STAT_TYPE_MAX];
  /**
   * @brief Handle for the statistics get request
   */
  struct GNUNET_STATISTICS_GetHandle *h_stat_get[STAT_TYPE_MAX];
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
 * Identifier for the task that runs after the test to collect results
 */
static struct GNUNET_SCHEDULER_Task *post_test_task;

/**
 * Identifier for the shutdown task
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

static void
rps_disconnect_adapter (void *cls,
                        void *op_result);

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
              "Cancelling pending rps get request\n");
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
              "Cancelling rps get reply\n");
  GNUNET_assert (NULL != pending_rep->req_handle);
  GNUNET_RPS_request_cancel (pending_rep->req_handle);
  GNUNET_free (pending_rep);
}

void
clean_peer (unsigned peer_index)
{
  struct PendingRequest *pending_req;

  while (NULL != (pending_req = rps_peers[peer_index].pending_req_head))
  {
    cancel_pending_req (pending_req);
  }
  pending_req = rps_peers[peer_index].pending_req_head;
  rps_disconnect_adapter (&rps_peers[peer_index],
                          &rps_peers[peer_index].rps_handle);
  for (unsigned stat_type = STAT_TYPE_ROUNDS;
       stat_type < STAT_TYPE_MAX;
       stat_type++)
  {
    if (NULL != rps_peers[peer_index].h_stat_get[stat_type])
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "(%u) did not yet receive stat value for `%s'\n",
                  rps_peers[peer_index].index,
                  stat_type_strings[stat_type]);
      GNUNET_STATISTICS_get_cancel (
          rps_peers[peer_index].h_stat_get[stat_type]);
    }
  }
  if (NULL != rps_peers[peer_index].op)
  {
    GNUNET_TESTBED_operation_done (rps_peers[peer_index].op);
    rps_peers[peer_index].op = NULL;
  }
}

/**
 * Task run on timeout to shut everything down.
 */
static void
shutdown_op (void *cls)
{
  unsigned int i;
  struct OpListEntry *entry;
  (void) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Shutdown task scheduled, going down.\n");
  in_shutdown = GNUNET_YES;

  if (NULL != shutdown_task)
  {
    GNUNET_SCHEDULER_cancel (shutdown_task);
    shutdown_task = NULL;
  }
  if (NULL != post_test_task)
  {
    GNUNET_SCHEDULER_cancel (post_test_task);
    post_test_task = NULL;
  }
  if (NULL != churn_task)
  {
    GNUNET_SCHEDULER_cancel (churn_task);
    churn_task = NULL;
  }
  entry = oplist_head;
  while (NULL != (entry = oplist_head))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Operation still pending on shutdown (%u)\n",
                entry->index);
    GNUNET_TESTBED_operation_done (entry->op);
    GNUNET_CONTAINER_DLL_remove (oplist_head, oplist_tail, entry);
    GNUNET_free (entry);
  }
  for (i = 0; i < num_peers; i++)
  {
    clean_peer (i);
  }
  close_all_files();
}

static void
trigger_shutdown (void *cls)
{
  (void) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Shutdown was triggerd by timeout, going down.\n");
  shutdown_task = NULL;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Task run after #duration to collect statistics and potentially shut down.
 */
static void
post_test_op (void *cls)
{
  unsigned int i;
  (void) cls;

  post_test_task = NULL;
  post_test = GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Executing post test op.\n");
  if (NULL != churn_task)
  {
    GNUNET_SCHEDULER_cancel (churn_task);
    churn_task = NULL;
  }
  for (i = 0; i < num_peers; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Executing post test op. (peer %" PRIu32 ")\n",
                rps_peers[i].index);
    if (NULL != rps_peers[i].op)
    {
      GNUNET_TESTBED_operation_done (rps_peers[i].op);
      rps_peers[i].op = NULL;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Cancelled testbed operation\n");
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
    GNUNET_SCHEDULER_cancel (shutdown_task);
    shutdown_task = NULL;
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
  (void) op;

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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Started client successfully (%u)\n",
              rps_peer->index);

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
stat_complete_cb (void *cls,
                  struct GNUNET_TESTBED_Operation *op,
                  void *ca_result,
                  const char *emsg )
{
  //struct GNUNET_STATISTICS_Handle *sh = ca_result;
  //struct RPSPeer *peer = (struct RPSPeer *) cls;
  (void) cls;
  (void) op;
  (void) ca_result;

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
  struct PendingReply *pending_rep;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "disconnect_adapter (%u)\n",
              peer->index);
  GNUNET_assert (NULL != peer);
  if (NULL != peer->rps_handle)
  {
    while (NULL != (pending_rep = peer->pending_rep_head))
    {
      cancel_request (pending_rep);
    }
    GNUNET_assert (h == peer->rps_handle);
    if (NULL != h)
    {
      GNUNET_RPS_disconnect (h);
      h = NULL;
    }
    peer->rps_handle = NULL;
  }
}


/***********************************************************************
 * Definition of tests
***********************************************************************/

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

  if (GNUNET_YES != post_test) return;
  if (HAVE_QUICK_QUIT != cur_test_run.have_quick_quit) return;
  if (0 == evaluate())
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Test succeeded before end of duration\n");
    if (NULL != post_test_task) GNUNET_SCHEDULER_cancel (post_test_task);
    post_test_task = GNUNET_SCHEDULER_add_now (&post_test_op, NULL);
    GNUNET_assert (NULL != post_test_task);
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

  rps_peer = pending_req->rps_peer;
  GNUNET_assert (1 <= rps_peer->num_pending_reqs);
  GNUNET_CONTAINER_DLL_remove (rps_peer->pending_req_head,
                               rps_peer->pending_req_tail,
                               pending_req);
  rps_peer->num_pending_reqs--;
  if (GNUNET_YES == in_shutdown || GNUNET_YES == post_test) return;
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
  #if ENABLE_MALICIOUS
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

  #if ENABLE_MALICIOUS
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
  (void) op;

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
  (void) cls;

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
  rps_peer->num_ids_to_request = cur_test_run.num_requests;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "peer shall request %i peers\n",
              rps_peer->num_ids_to_request);
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
  char file_name_buf[128];
  char file_name_dh_buf[128];
  char file_name_dhr_buf[128];
  char file_name_dhru_buf[128];
  char *file_name = file_name_buf;
  char *file_name_dh = file_name_dh_buf;
  char *file_name_dhr = file_name_dhr_buf;
  char *file_name_dhru = file_name_dhru_buf;
  unsigned int i;
  struct PendingReply *pending_rep = (struct PendingReply *) cls;

  pending_rep->req_handle = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "profiler_reply_handle()\n");
  rps_peer = pending_rep->rps_peer;
  (void) GNUNET_asprintf (&file_name,
                                       "/tmp/rps/received_ids-%u",
                                       rps_peer->index);

  (void) GNUNET_asprintf (&file_name_dh,
                                       "/tmp/rps/diehard_input-%u",
                                       rps_peer->index);
  (void) GNUNET_asprintf (&file_name_dhr,
                                       "/tmp/rps/diehard_input_raw-%u",
                                       rps_peer->index);
  (void) GNUNET_asprintf (&file_name_dhru,
                                       "/tmp/rps/diehard_input_raw_aligned-%u",
                                       rps_peer->index);
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
#ifdef TO_FILE
    to_file_raw (file_name_dhr,
                (char *) &rcv_rps_peer->index,
                 sizeof (uint32_t));
    to_file_raw_unaligned (file_name_dhru,
                          (char *) &rcv_rps_peer->index,
                           sizeof (uint32_t),
                           bits_needed);
#endif /* TO_FILE */
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
  if (0 < rps_peer->num_ids_to_request)
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
static int
file_name_cb (void *cls, const char *filename)
{
  if (NULL != strstr (filename, "sampler_el"))
  {
    struct RPS_SamplerElement *s_elem;
    struct GNUNET_CRYPTO_AuthKey auth_key;
    const char *key_char;
    uint32_t i;
    (void) cls;

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
static int
profiler_eval (void)
{
#ifdef TO_FILE
  /* Compute perfect sample for each sampler element */
  if (-1 == GNUNET_DISK_directory_scan ("/tmp/rps/", file_name_cb, NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Scan of directory failed\n");
  }
#endif /* TO_FILE */

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
  /* if (0 > n) return 0;  - always false */
  /* if (0 > k) return 0;  - always false */
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
      if (0 == binom (view_size, 0.45 * view_size)) prob_push = 0;
      else
      {
        prob_push = 1.0 * binom (0.45 * view_size, 1)
          /
          binom (view_size, 0.45 * view_size);
      }
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
  for (uint64_t i = 0; i < view_size; i++)
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
  uint64_t sums[STAT_TYPE_MAX] = { 0 };

  for (uint32_t i = 0; i < num_peers; i++)
  {
    to_file ("/tmp/rps/final_stats.csv",
             "%" PRIu32 ", " /* index */
             "%s, %" /* id */
             PRIu64 ", %" /* rounds */
             PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" /* blocking */
             PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" /* issued */
             PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" /* sent */
             PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" /* recv */
             PRIu64 ", %" /* view size */
             PRIu64 ", %" /* known peers */
             PRIu64 ", %" /* valid peers */
             PRIu64 ", %" /* learned peers */
             PRIu64 ", %" /* pending online checks */
             PRIu64 ", %" /* unrequested pull replies */
             PRIu64 ", %" /* peers in push map */
             PRIu64 ", %" /* peers in pull map */
             PRIu64 ", %" /* peers in view */
             PRIu64 "\n"/* view size aim */,
             i,
             GNUNET_i2s (rps_peers[i].peer_id),
             rps_peers[i].stats[STAT_TYPE_ROUNDS],
             rps_peers[i].stats[STAT_TYPE_BLOCKS],
             rps_peers[i].stats[STAT_TYPE_BLOCKS_MANY_PUSH],
             rps_peers[i].stats[STAT_TYPE_BLOCKS_NO_PUSH],
             rps_peers[i].stats[STAT_TYPE_BLOCKS_NO_PULL],
             rps_peers[i].stats[STAT_TYPE_BLOCKS_MANY_PUSH_NO_PULL],
             rps_peers[i].stats[STAT_TYPE_BLOCKS_NO_PUSH_NO_PULL],
             rps_peers[i].stats[STAT_TYPE_ISSUED_PUSH_SEND],
             rps_peers[i].stats[STAT_TYPE_ISSUED_PULL_REQ],
             rps_peers[i].stats[STAT_TYPE_ISSUED_PULL_REQ_MH],
             rps_peers[i].stats[STAT_TYPE_ISSUED_PULL_REP],
             rps_peers[i].stats[STAT_TYPE_SENT_PUSH_SEND],
             rps_peers[i].stats[STAT_TYPE_SENT_PULL_REQ],
             rps_peers[i].stats[STAT_TYPE_SENT_PULL_REQ_MH],
             rps_peers[i].stats[STAT_TYPE_SENT_PULL_REP],
             rps_peers[i].stats[STAT_TYPE_RECV_PUSH_SEND],
             rps_peers[i].stats[STAT_TYPE_RECV_PULL_REQ],
             rps_peers[i].stats[STAT_TYPE_RECV_PULL_REQ_MH],
             rps_peers[i].stats[STAT_TYPE_RECV_PULL_REP_MH],
             rps_peers[i].stats[STAT_TYPE_RECV_PULL_REP],
             rps_peers[i].stats[STAT_TYPE_VIEW_SIZE],
             rps_peers[i].stats[STAT_TYPE_KNOWN_PEERS],
             rps_peers[i].stats[STAT_TYPE_VALID_PEERS],
             rps_peers[i].stats[STAT_TYPE_LEARND_PEERS],
             rps_peers[i].stats[STAT_TYPE_PENDING_ONLINE_CHECKS],
             rps_peers[i].stats[STAT_TYPE_UNREQUESTED_PULL_REPLIES],
             rps_peers[i].stats[STAT_TYPE_PEERS_IN_PUSH_MAP],
             rps_peers[i].stats[STAT_TYPE_PEERS_IN_PULL_MAP],
             rps_peers[i].stats[STAT_TYPE_PEERS_IN_VIEW],
             rps_peers[i].stats[STAT_TYPE_VIEW_SIZE_AIM]);
    for (enum STAT_TYPE stat_type = STAT_TYPE_ROUNDS;
         stat_type < STAT_TYPE_MAX;
         stat_type++)
    {
      sums[stat_type] += rps_peers[i].stats[stat_type];
    }
  }
  to_file ("/tmp/rps/final_stats.dat",
           "SUM %"
           PRIu64 " %" /* rounds */
           PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" /* blocking */
           PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" /* issued */
           PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" /* sent */
           PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" /* recv */
           PRIu64 ", %" /* view size */
           PRIu64 ", %" /* known peers */
           PRIu64 ", %" /* valid peers */
           PRIu64 ", %" /* learned peers */
           PRIu64 ", %" /* pending online checks */
           PRIu64 ", %" /* unrequested pull replies */
           PRIu64 ", %" /* peers in push map */
           PRIu64 ", %" /* peers in pull map */
           PRIu64 ", %" /* peers in view */
           PRIu64 "\n"/* view size aim */,
           sums[STAT_TYPE_ROUNDS],
           sums[STAT_TYPE_BLOCKS],
           sums[STAT_TYPE_BLOCKS_MANY_PUSH],
           sums[STAT_TYPE_BLOCKS_NO_PUSH],
           sums[STAT_TYPE_BLOCKS_NO_PULL],
           sums[STAT_TYPE_BLOCKS_MANY_PUSH_NO_PULL],
           sums[STAT_TYPE_BLOCKS_NO_PUSH_NO_PULL],
           sums[STAT_TYPE_ISSUED_PUSH_SEND],
           sums[STAT_TYPE_ISSUED_PULL_REQ],
           sums[STAT_TYPE_ISSUED_PULL_REQ_MH],
           sums[STAT_TYPE_ISSUED_PULL_REP],
           sums[STAT_TYPE_SENT_PUSH_SEND],
           sums[STAT_TYPE_SENT_PULL_REQ],
           sums[STAT_TYPE_SENT_PULL_REQ_MH],
           sums[STAT_TYPE_SENT_PULL_REP],
           sums[STAT_TYPE_RECV_PUSH_SEND],
           sums[STAT_TYPE_RECV_PULL_REQ],
           sums[STAT_TYPE_RECV_PULL_REQ_MH],
           sums[STAT_TYPE_RECV_PULL_REP],
           sums[STAT_TYPE_RECV_PULL_REP_MH],
           sums[STAT_TYPE_VIEW_SIZE],
           sums[STAT_TYPE_KNOWN_PEERS],
           sums[STAT_TYPE_VALID_PEERS],
           sums[STAT_TYPE_LEARND_PEERS],
           sums[STAT_TYPE_PENDING_ONLINE_CHECKS],
           sums[STAT_TYPE_UNREQUESTED_PULL_REPLIES],
           sums[STAT_TYPE_PEERS_IN_PUSH_MAP],
           sums[STAT_TYPE_PEERS_IN_PULL_MAP],
           sums[STAT_TYPE_PEERS_IN_VIEW],
           sums[STAT_TYPE_VIEW_SIZE_AIM]);
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

  rps_peer->h_stat_get[stat_cls->stat_type] = NULL;
  if (GNUNET_OK == success)
  {
    /* set flag that we we got the value */
    rps_peer->stat_collected_flags |= BIT(stat_cls->stat_type);
  } else {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Peer %u did not receive statistics value\n",
        rps_peer->index);
    GNUNET_free (stat_cls);
    GNUNET_break (0);
    return;
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
  enum STAT_TYPE stat_type;
  (void) subsystem;
  (void) is_persistent;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got stat value: %s - %" PRIu64 " (%u)\n",
              name,
              value,
              rps_peer->index);
  to_file (rps_peer->file_name_stats,
          "%s: %" PRIu64 "\n",
          name,
          value);
  stat_type = stat_str_2_type (name);
  GNUNET_assert (STAT_TYPE_ROUNDS <= stat_type &&
                 STAT_TYPE_MAX > stat_type);
  rps_peer->stats[stat_type] = value;
  return GNUNET_OK;
}


void
post_profiler (struct RPSPeer *rps_peer)
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
      stat_type++)
  {
    if (BIT(stat_type) & cur_test_run.stat_collect_flags)
    {
      stat_cls = GNUNET_malloc (sizeof (struct STATcls));
      stat_cls->rps_peer = rps_peer;
      stat_cls->stat_type = stat_type;
      rps_peer->file_name_stats =
        store_prefix_file_name (rps_peer->peer_id, "stats");
      rps_peer->h_stat_get[stat_type] =
        GNUNET_STATISTICS_get (rps_peer->stats_h,
                               "rps",
                               stat_type_strings [stat_type],
                               post_test_shutdown_ready_cb,
                               stat_iterator,
                               (struct STATcls *) stat_cls);
      GNUNET_assert (NULL != rps_peer->h_stat_get);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Requested statistics for %s (peer %" PRIu32 ")\n",
                  stat_type_strings [stat_type],
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
test_run (void *cls,
     struct GNUNET_TESTBED_RunHandle *h,
     unsigned int n_peers,
     struct GNUNET_TESTBED_Peer **peers,
     unsigned int links_succeeded,
     unsigned int links_failed)
{
  unsigned int i;
  struct OpListEntry *entry;
  (void) cls;
  (void) h;
  (void) links_failed;

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
    ok = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }


  /* Initialize peers */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "going to initialise peers\n");
  testbed_peers = peers;
  num_peers_online = 0;
  for (i = 0; i < num_peers; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "initialising %u\n", i);
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
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                 "Connecting to statistics service\n");
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
  post_test_task = GNUNET_SCHEDULER_add_delayed (duration, &post_test_op, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "timeout for shutdown is %lu\n", timeout.rel_value_us/1000000);
  shutdown_task = GNUNET_SCHEDULER_add_delayed (timeout,
                                                &trigger_shutdown,
                                                NULL);
  GNUNET_SCHEDULER_add_shutdown (shutdown_op, NULL);
}


/**
 * Entry point for the testcase, sets up the testbed.
 *
 * @param argc unused
 * @param argv unused
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  //int ret_value;
  (void) cls;
  (void) args;
  (void) cfgfile;

  /* Defaults for tests */
  churn_task = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "This is the profiler\n");
  cur_test_run.name = "test-rps-profiler";
  if (0 == num_peers)
    num_peers = 10;
  mal_type = 3;
  cur_test_run.init_peer = profiler_init_peer;
  //cur_test_run.pre_test = mal_pre;
  cur_test_run.pre_test = pre_profiler;
  cur_test_run.main_test = profiler_cb;
  cur_test_run.reply_handle = profiler_reply_handle;
  cur_test_run.eval_cb = profiler_eval;
  cur_test_run.post_test = post_profiler;
  cur_test_run.request_interval = 2;
  if (0 == cur_test_run.num_requests) cur_test_run.num_requests = 5;
  //cur_test_run.have_churn = HAVE_CHURN;
  cur_test_run.have_churn = HAVE_NO_CHURN;
  cur_test_run.have_quick_quit = HAVE_QUICK_QUIT;
  cur_test_run.have_collect_statistics = COLLECT_STATISTICS;
  cur_test_run.stat_collect_flags = BIT(STAT_TYPE_ROUNDS) |
                                    BIT(STAT_TYPE_BLOCKS) |
                                    BIT(STAT_TYPE_BLOCKS_MANY_PUSH) |
                                    BIT(STAT_TYPE_BLOCKS_NO_PUSH) |
                                    BIT(STAT_TYPE_BLOCKS_NO_PULL) |
                                    BIT(STAT_TYPE_BLOCKS_MANY_PUSH_NO_PULL) |
                                    BIT(STAT_TYPE_BLOCKS_NO_PUSH_NO_PULL) |
                                    BIT(STAT_TYPE_ISSUED_PUSH_SEND) |
                                    BIT(STAT_TYPE_ISSUED_PULL_REQ) |
                                    BIT(STAT_TYPE_ISSUED_PULL_REQ_MH) |
                                    BIT(STAT_TYPE_ISSUED_PULL_REP) |
                                    BIT(STAT_TYPE_SENT_PUSH_SEND) |
                                    BIT(STAT_TYPE_SENT_PULL_REQ) |
                                    BIT(STAT_TYPE_SENT_PULL_REQ_MH) |
                                    BIT(STAT_TYPE_SENT_PULL_REP) |
                                    BIT(STAT_TYPE_RECV_PUSH_SEND) |
                                    BIT(STAT_TYPE_RECV_PULL_REQ) |
                                    BIT(STAT_TYPE_RECV_PULL_REQ_MH) |
                                    BIT(STAT_TYPE_RECV_PULL_REP) |
                                    BIT(STAT_TYPE_RECV_PULL_REP_MH) |
                                    BIT(STAT_TYPE_VIEW_SIZE) |
                                    BIT(STAT_TYPE_KNOWN_PEERS) |
                                    BIT(STAT_TYPE_VALID_PEERS) |
                                    BIT(STAT_TYPE_LEARND_PEERS) |
                                    BIT(STAT_TYPE_PENDING_ONLINE_CHECKS) |
                                    BIT(STAT_TYPE_UNREQUESTED_PULL_REPLIES) |
                                    BIT(STAT_TYPE_PEERS_IN_PUSH_MAP) |
                                    BIT(STAT_TYPE_PEERS_IN_PULL_MAP) |
                                    BIT(STAT_TYPE_PEERS_IN_VIEW) |
                                    BIT(STAT_TYPE_VIEW_SIZE_AIM);
  cur_test_run.have_collect_view = COLLECT_VIEW;

  /* 'Clean' directory */
  (void) GNUNET_DISK_directory_remove ("/tmp/rps/");
  GNUNET_DISK_directory_create ("/tmp/rps/");
  if (0 == duration.rel_value_us)
  {
    if (0 == timeout.rel_value_us)
    {
      duration = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 90);
      timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                               (90 * 1.2) +
                                                 (0.01 * num_peers));
    }
    else
    {
      duration = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                                (timeout.rel_value_us/1000000)
                                                  * 0.75);
    }
  }
  else
  {
    if (0 == timeout.rel_value_us)
    {
      timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                               ((duration.rel_value_us/1000000)
                                                  * 1.2) + (0.01 * num_peers));
    }
  }
  GNUNET_assert (duration.rel_value_us < timeout.rel_value_us);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "duration is %lus\n",
              duration.rel_value_us/1000000);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "timeout is %lus\n",
              timeout.rel_value_us/1000000);

  /* Compute number of bits for representing largest peer id */
  for (bits_needed = 1; (1 << bits_needed) < num_peers; bits_needed++)
    ;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
            "Need %u bits to represent %" PRIu32 " peers\n",
             bits_needed,
             num_peers);

  rps_peers = GNUNET_new_array (num_peers, struct RPSPeer);
  peer_map = GNUNET_CONTAINER_multipeermap_create (num_peers, GNUNET_NO);
  rps_peer_ids = GNUNET_new_array (num_peers, struct GNUNET_PeerIdentity);
  if ( (2 == mal_type) ||
       (3 == mal_type))
    target_peer = &rps_peer_ids[num_peers - 2];

  ok = 1;
  GNUNET_TESTBED_run (NULL,
                      cfg,
                      num_peers,
                      0, /* event mask */
                      NULL,
                      NULL,
                      &test_run,
                      NULL);
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
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_uint ('n',
                               "num-peers",
                               "COUNT",
                               gettext_noop ("number of peers to start"),
                               &num_peers),
    GNUNET_GETOPT_option_relative_time ('d',
                                        "duration",
                                        "DURATION",
                                        gettext_noop ("duration of the profiling"),
                                        &duration),
    GNUNET_GETOPT_option_relative_time ('t',
                                        "timeout",
                                        "TIMEOUT",
                                        gettext_noop ("timeout for the profiling"),
                                        &timeout),
    GNUNET_GETOPT_option_uint ('r',
                               "num-requests",
                               "COUNT",
                               gettext_noop ("number of PeerIDs to request"),
                               &cur_test_run.num_requests),
    GNUNET_GETOPT_OPTION_END
  };

  unsetenv ("XDG_DATA_HOME");
  unsetenv ("XDG_CONFIG_HOME");
  //if (GNUNET_OK !=
  //    GNUNET_STRINGS_get_utf8_args (argc, argv,
  //                                  &argc, &argv))
  //  return 2;
  ret_value = 0;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc,
                          argv,
                          "gnunet-rps-profiler",
                          gettext_noop ("Measure quality and performance of the RPS service."),
                          options,
                          &run,
                          NULL))
  {
    ret_value = 1;
  }
  if (0 != ret_value)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Test did not run successfully!\n");
  }
  else
  {
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
  }
  return ret_value;
}

/* end of test_rps.c */
