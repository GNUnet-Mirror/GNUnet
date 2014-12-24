/*
      This file is part of GNUnet
      (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_statistics.c
 * @brief high-level statistics function
 * @author Christian Grothoff
 * @author Sree Harsha Totakura
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"

#include "testbed_api_operations.h"


/**
 * Generic logging shorthand
 */
#define LOG(kind,...)                           \
  GNUNET_log_from (kind, "testbed-api-statistics", __VA_ARGS__)

/**
 * Debug logging shorthand
 */
#define LOG_DEBUG(...)                          \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)


/**
 * Context information for use in GNUNET_TESTBED_get_statistics()
 */
struct GetStatsContext
{
  /**
   * The main operation we generate while creating this context
   */
  struct GNUNET_TESTBED_Operation *main_op;

  /**
   * The service connect operations we create to open connection to the
   * statistics service of each given peer
   */
  struct  GNUNET_TESTBED_Operation **ops;

  /**
   * The array of peers whose statistics services are to be accessed
   */
  struct GNUNET_TESTBED_Peer **peers;

  /**
   * The subsystem of peers for which statistics are requested
   */
  char *subsystem;

  /**
   * The particular statistics value of interest
   */
  char *name;

  /**
   * The iterator to call with statistics information
   */
  GNUNET_TESTBED_StatisticsIterator proc;

  /**
   * The callback to call when we are done iterating through all peers'
   * statistics services
   */
  GNUNET_TESTBED_OperationCompletionCallback cont;

  /**
   * The closure for the above callbacks
   */
  void *cb_cls;

  /**
   * The task for calling the continuation callback
   */
  struct GNUNET_SCHEDULER_Task * call_completion_task_id;

  /**
   * The number of peers present in the peers array.  This number also
   * represents the number of service connect operations in the ops array
   */
  unsigned int num_peers;

  /**
   * How many peers' statistics have we iterated through
   */
  unsigned int num_completed;

};


/**
 * Context information with respect to a particular peer
 */
struct PeerGetStatsContext
{
  /**
   * The GetStatsContext which is associated with this context
   */
  struct GetStatsContext *sc;

  /**
   * The handle from GNUNET_STATISTICS_get()
   */
  struct GNUNET_STATISTICS_GetHandle *get_handle;

  /**
   * Task to mark the statistics service connect operation as done
   */
  struct GNUNET_SCHEDULER_Task * op_done_task_id;

  /**
   * The index of this peer in the peers array of GetStatsContext
   */
  unsigned int peer_index;
};


/**
 * A no-wait operation queue
 */
static struct OperationQueue *no_wait_queue;


/**
 * Call statistics operation completion.  We call it in a separate task because
 * the iteration_completion_cb() cannot destroy statistics handle which will be
 * the case if the user calles GNUNET_TESTBED_operation_done() on the
 * get_statistics operation.
 *
 * @param cls the GetStatsContext
 * @param tc the scheduler task context
 */
static void
call_completion_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GetStatsContext *sc = cls;

  GNUNET_assert (sc->call_completion_task_id != NULL);
  sc->call_completion_task_id = NULL;
  LOG_DEBUG ("Calling get_statistics() continuation callback\n");
  sc->cont (sc->cb_cls, sc->main_op, NULL);
}


/**
 * Task to mark statistics service connect operation as done.  We call it here
 * as we cannot destroy the statistics handle in iteration_completion_cb()
 *
 * @param cls the PeerGetStatsContext
 * @param tc the scheduler task context
 */
static void
op_done_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerGetStatsContext *peer_sc = cls;
  struct GetStatsContext *sc;
  struct GNUNET_TESTBED_Operation **op;

  sc = peer_sc->sc;
  peer_sc->op_done_task_id = NULL;
  op = &sc->ops[peer_sc->peer_index];
  GNUNET_assert (NULL != *op);
  GNUNET_TESTBED_operation_done (*op);
  *op = NULL;
}


/**
 * Continuation called by the "get_all" and "get" functions.
 *
 * @param cls the PeerGetStatsContext
 * @param success GNUNET_OK if statistics were
 *        successfully obtained, GNUNET_SYSERR if not.
 */
static void
iteration_completion_cb (void *cls, int success)
{
  struct PeerGetStatsContext *peer_sc = cls;
  struct GetStatsContext *sc;

  GNUNET_break (GNUNET_OK == success);
  sc = peer_sc->sc;
  peer_sc->get_handle = NULL;
  sc->num_completed++;
  peer_sc->op_done_task_id = GNUNET_SCHEDULER_add_now (&op_done_task, peer_sc);
  if (sc->num_completed == sc->num_peers)
  {
    LOG_DEBUG ("Scheduling to call iteration completion callback\n");
    sc->call_completion_task_id =
        GNUNET_SCHEDULER_add_now (&call_completion_task, sc);
  }
}


/**
 * Callback function to process statistic values.
 *
 * @param cls the PeerGetStatsContext
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
iterator_cb (void *cls, const char *subsystem,
             const char *name, uint64_t value,
             int is_persistent)
{
  struct PeerGetStatsContext *peer_sc = cls;
  struct GetStatsContext *sc;
  struct GNUNET_TESTBED_Peer *peer;
  int ret;

  sc = peer_sc->sc;
  peer = sc->peers[peer_sc->peer_index];
  LOG_DEBUG ("Peer %u: [%s,%s] -> %lu\n", peer_sc->peer_index,
             subsystem, name, (unsigned long) value);
  ret = sc->proc (sc->cb_cls, peer,
                  subsystem, name, value, is_persistent);
  if (GNUNET_SYSERR == ret)
    LOG_DEBUG ("Aborting iteration for peer %u\n", peer_sc->peer_index);
  return ret;
}


/**
 * Called after opening a connection to the statistics service of a peer
 *
 * @param cls the PeerGetStatsContext
 * @param op the operation that has been finished
 * @param ca_result the service handle returned from GNUNET_TESTBED_ConnectAdapter()
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
service_connect_comp (void *cls,
                      struct GNUNET_TESTBED_Operation *op,
                      void *ca_result,
                      const char *emsg)
{
  struct PeerGetStatsContext *peer_sc = cls;
  struct GNUNET_STATISTICS_Handle *h = ca_result;

  LOG_DEBUG ("Retrieving statistics of peer %u\n", peer_sc->peer_index);
  peer_sc->get_handle =
      GNUNET_STATISTICS_get (h, peer_sc->sc->subsystem, peer_sc->sc->name,
                             GNUNET_TIME_UNIT_FOREVER_REL,
                             &iteration_completion_cb,
                             iterator_cb, peer_sc);
}


/**
 * Adapter function called to establish a connection to the statistics service
 * of a peer.
 *
 * @param cls the PeerGetStatsContext
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
statistics_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct PeerGetStatsContext *peer_sc = cls;

  LOG_DEBUG ("Connecting to statistics service of peer %u\n",
             peer_sc->peer_index);
  return GNUNET_STATISTICS_create ("<testbed-api>", cfg);
}


/**
 * Adapter function called to destroy statistics connection
 *
 * @param cls the PeerGetStatsContext
 * @param op_result service handle returned from the connect adapter
 */
static void
statistics_da (void *cls, void *op_result)
{
  struct PeerGetStatsContext *peer_sc = cls;
  struct GNUNET_STATISTICS_Handle *sh = op_result;

  if (NULL != peer_sc->get_handle)
  {
    GNUNET_STATISTICS_get_cancel (peer_sc->get_handle);
    peer_sc->get_handle = NULL;
  }
  GNUNET_STATISTICS_destroy (sh, GNUNET_NO);
  if (NULL != peer_sc->op_done_task_id)
    GNUNET_SCHEDULER_cancel (peer_sc->op_done_task_id);
  GNUNET_free (peer_sc);
}


/**
 * Function called when get_statistics operation is ready
 *
 * @param cls the GetStatsContext
 */
static void
opstart_get_stats (void *cls)
{
  struct GetStatsContext *sc = cls;
  struct PeerGetStatsContext *peer_sc;
  unsigned int peer;

  LOG_DEBUG ("Starting get_statistics operation\n");
  sc->ops = GNUNET_malloc (sc->num_peers *
                           sizeof (struct GNUNET_TESTBED_Operation *));
  for (peer = 0; peer < sc->num_peers; peer++)
  {
    if (NULL == sc->peers[peer])
    {
      GNUNET_break (0);
      continue;
    }
    peer_sc = GNUNET_new (struct PeerGetStatsContext);
    peer_sc->sc = sc;
    peer_sc->peer_index = peer;
    sc->ops[peer] =
        GNUNET_TESTBED_service_connect (sc, sc->peers[peer], "statistics",
                                        &service_connect_comp,
                                        peer_sc,
                                        &statistics_ca,
                                        &statistics_da,
                                        peer_sc);
  }
}


/**
 * Function called when get_statistics operation is cancelled or marked as done
 *
 * @param cls the GetStatsContext
 */
static void
oprelease_get_stats (void *cls)
{
  struct GetStatsContext *sc = cls;
  unsigned int peer;

  LOG_DEBUG ("Cleaning up get_statistics operation\n");
  if (NULL != sc->call_completion_task_id)
    GNUNET_SCHEDULER_cancel (sc->call_completion_task_id);
  if (NULL != sc->ops)
  {
    for (peer = 0; peer < sc->num_peers; peer++)
    {
      if (NULL != sc->ops[peer])
      {
        GNUNET_TESTBED_operation_done (sc->ops[peer]);
        sc->ops[peer] = NULL;
      }
    }
    GNUNET_free (sc->ops);
  }
  GNUNET_free_non_null (sc->subsystem);
  GNUNET_free_non_null (sc->name);
  GNUNET_free (sc);
  if (GNUNET_YES ==
      GNUNET_TESTBED_operation_queue_destroy_empty_ (no_wait_queue))
    no_wait_queue = NULL;
}


/**
 * Convenience method that iterates over all (running) peers
 * and retrieves all statistics from each peer.
 *
 * @param num_peers number of peers to iterate over
 * @param peers array of peers to iterate over
 * @param subsystem limit to the specified subsystem, NULL for all subsystems
 * @param name name of the statistic value, NULL for all values
 * @param proc processing function for each statistic retrieved
 * @param cont continuation to call once call is completed(?)
 * @param cls closure to pass to proc and cont
 * @return operation handle to cancel the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_get_statistics (unsigned int num_peers,
                               struct GNUNET_TESTBED_Peer **peers,
                               const char *subsystem, const char *name,
                               GNUNET_TESTBED_StatisticsIterator proc,
                               GNUNET_TESTBED_OperationCompletionCallback cont,
                               void *cls)
{
  struct GetStatsContext *sc;

  GNUNET_assert (NULL != proc);
  GNUNET_assert (NULL != cont);
  if (NULL == no_wait_queue)
    no_wait_queue = GNUNET_TESTBED_operation_queue_create_
        (OPERATION_QUEUE_TYPE_FIXED, UINT_MAX);
  sc = GNUNET_new (struct GetStatsContext);
  sc->peers = peers;
  sc->subsystem = (NULL == subsystem) ? NULL : GNUNET_strdup (subsystem);
  sc->name = (NULL == name) ? NULL : GNUNET_strdup (name);
  sc->proc = proc;
  sc->cont = cont;
  sc->cb_cls = cls;
  sc->num_peers = num_peers;
  sc->main_op =
      GNUNET_TESTBED_operation_create_ (sc, &opstart_get_stats,
                                        &oprelease_get_stats);
  GNUNET_TESTBED_operation_queue_insert_ (no_wait_queue, sc->main_op);
  GNUNET_TESTBED_operation_begin_wait_ (sc->main_op);
  return sc->main_op;
}


/* end of testbed_api_statistics.c */
