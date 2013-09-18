/*
     This file is part of GNUnet.
     (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file ats/perf_ats.c
 * @brief ats benchmark: start peers and modify preferences, monitor change over time
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_ats_service.h"
#include "gnunet_core_service.h"

#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
#define BENCHMARK_DURATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)
#define TESTNAME_PREFIX "perf_ats_"
#define DEFAULT_SLAVES_NUM 3
#define DEFAULT_MASTERS_NUM 1

#define TEST_MESSAGE_TYPE_PING 12345
#define TEST_MESSAGE_TYPE_PONG 12346
#define TEST_MESSAGE_SIZE 1000
#define TEST_MESSAGE_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)


/**
 * Information about a benchmarking partner
 */
struct BenchmarkPartner
{
  /**
   * The peer itself this partner belongs to
   */
  struct BenchmarkPeer *me;

  /**
   * The partner peer
   */
  struct BenchmarkPeer *dest;

  /**
   * Core transmit handles
   */
  void *cth;

  /**
   * Number of messages sent to this partner
   */
  unsigned int messages_sent;

  /**
   * Number of bytes sent to this partner
   */
  unsigned int bytes_sent;

  /**
     * Number of messages received from this partner
     */
  unsigned int messages_received;

  /**
   * Number of bytes received from this partner
   */
  unsigned int bytes_received;
};


struct MasterInformation
{
  int core_slave_connections;

  /**
   * Testbed connect operation
   */
};


/**
 * Connect peers with testbed
 */
struct TestbedConnectOperation
{
  /**
   * The benchmarking master initiating this connection
   */
  struct BenchmarkPeer *master;

  /**
   * The benchmarking slave to connect to
   */
  struct BenchmarkPeer *slave;

  /**
   * Testbed operation to connect peers
   */
  struct GNUNET_TESTBED_Operation *connect_op;
};



/**
 * Information we track for a peer in the testbed.
 */
struct BenchmarkPeer
{
  /**
   * Handle with testbed.
   */
  struct GNUNET_TESTBED_Peer *peer;

  /**
   * Unique identifier
   */
  int no;

  /**
   * Is this peer a measter: GNUNET_YES/GNUNET_NO
   */
  int master;

  /**
   *  Peer ID
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Testbed operation to get peer information
   */
  struct GNUNET_TESTBED_Operation *peer_id_op;

  /**
   * Testbed operation to connect to ATS performance service
   */
  struct GNUNET_TESTBED_Operation *ats_perf_op;

  /**
   * Testbed operation to connect to core
   */
  struct GNUNET_TESTBED_Operation *core_op;

  /**
   * ATS performance handle
   */
  struct GNUNET_ATS_PerformanceHandle *ats_perf_handle;

  /**
   * Testbed connect operations to connect masters to slaves
   * For masters peers only
   */
  struct TestbedConnectOperation *core_connect_ops;

  /**
   *  Core handle
   */
  struct GNUNET_CORE_Handle *ch;

  /**
   * Array of partners with num_slaves entries (if master) or
   * num_master entries (if slave)
   */
  struct BenchmarkPartner *partners;

  int core_connections;

  struct MasterInformation mi;

  /**
   * Total number of messages this peer has sent
   */
  unsigned int total_messages_sent;

  /**
   * Total number of bytes this peer has sent
   */
  unsigned int total_bytes_sent;

  /**
   * Total number of messages this peer has received
   */
  unsigned int total_messages_received;

  /**
   * Total number of bytes this peer has received
   */
  unsigned int total_bytes_received;
};


/**
 * Overall state of the performance benchmark
 */
struct BenchmarkState
{
  /* Are we connected to ATS service of all peers: GNUNET_YES/NO */
  int connected_ATS_service;

  /* Are we connected to CORE service of all peers: GNUNET_YES/NO */
  int connected_CORE_service;

  /* Are we connected to all peers: GNUNET_YES/NO */
  int connected_PEERS;

  /* Are we connected to all slave peers on CORE level: GNUNET_YES/NO */
  int connected_CORE;

  /* Are we connected to CORE service of all peers: GNUNET_YES/NO */
  int benchmarking;
};


/**
 * Shutdown task
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

/**
 * Test result
 */
static int result;

/**
 * Solver string
 */
static char *solver;

/**
 * Preference string
 */
static char *pref_str;

/**
 * ATS preference value
 */
static int pref_val;

/**
 * Number master peers
 */
static int num_masters;

/**
 * Array of master peers
 */
struct BenchmarkPeer *mps;

/**
 * Number slave peers
 */
static int num_slaves;
/**
 * Array of slave peers
 */
struct BenchmarkPeer *sps;

/**
 * Benchmark state
 */
static struct BenchmarkState state;


static void
evaluate ()
{
  int c_m;
  int c_s;
  unsigned int duration;
  struct BenchmarkPeer *mp;

  duration = (BENCHMARK_DURATION.rel_value_us / (1000 * 1000));
  for (c_m = 0; c_m < num_masters; c_m++)
  {
    mp = &mps[c_m];
    fprintf (stderr, _("Master [%u]: sent: %u KiB in %u sec. = %u KiB/s, received: %u KiB in %u sec. = %u KiB/s\n"),
        mp->no,
        mp->total_bytes_sent / 1024,
        duration,
        (mp->total_bytes_sent / 1024) / duration ,
        mp->total_bytes_received / 1024,
        duration,
        (mp->total_bytes_received / 1024) / duration);

    for (c_s = 0; c_s < num_slaves; c_s ++)
    {
      fprintf (stderr, "Master [%u] -> Slave [%u]: sent %u KiB/s, received %u KiB/s \n",
          mp->no,
          mp->partners[c_s].dest->no,
          (mp->partners[c_s].bytes_sent / 1024) / duration,
          (mp->partners[c_s].bytes_received / 1024) / duration);
    }
  }
}


/**
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int c_m;
  int c_s;
  int c_op;

  shutdown_task = GNUNET_SCHEDULER_NO_TASK;
  evaluate();
  state.benchmarking = GNUNET_NO;
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Benchmarking done\n"));

  for (c_m = 0; c_m < num_masters; c_m++)
  {
    if (NULL != mps[c_m].peer_id_op)
    {
      GNUNET_TESTBED_operation_done (mps[c_m].peer_id_op);
      mps[c_m].peer_id_op = NULL;
    }

    for (c_op = 0; c_op < num_slaves; c_op++)
    {

      if (NULL != mps[c_m].partners[c_op].cth)
      {
        GNUNET_CORE_notify_transmit_ready_cancel (mps[c_m].partners[c_op].cth);
        mps[c_m].partners[c_op].cth = NULL;
      }

      if (NULL != mps[c_m].core_connect_ops[c_op].connect_op)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_INFO,
            _("Failed to connect peer 0 and %u\n"), c_op);
        GNUNET_TESTBED_operation_done (
            mps[c_m].core_connect_ops[c_op].connect_op);
        mps[c_m].core_connect_ops[c_op].connect_op = NULL;
        result = 1;
      }
    }

    if (NULL != mps[c_m].ats_perf_op)
    {
      GNUNET_TESTBED_operation_done (mps[c_m].ats_perf_op);
      mps[c_m].ats_perf_op = NULL;
    }

    if (NULL != mps[c_m].core_op)
    {
      GNUNET_TESTBED_operation_done (mps[c_m].core_op);
      mps[c_m].core_op = NULL;
    }
    GNUNET_free (mps[c_m].core_connect_ops);
    GNUNET_free (mps[c_m].partners);
    mps[c_m].partners = NULL;
  }


  for (c_s = 0; c_s < num_slaves; c_s++)
  {
    if (NULL != sps[c_s].peer_id_op)
    {
      GNUNET_TESTBED_operation_done (sps[c_s].peer_id_op);
      sps[c_s].peer_id_op = NULL;
    }

    for (c_op = 0; c_op < num_slaves; c_op++)
    {
      if (NULL != sps[c_s].partners[c_op].cth)
      {
        GNUNET_CORE_notify_transmit_ready_cancel (sps[c_s].partners[c_op].cth);
        sps[c_s].partners[c_op].cth = NULL;
      }
    }


    if (NULL != sps[c_s].ats_perf_op)
    {
      GNUNET_TESTBED_operation_done (sps[c_s].ats_perf_op);
      sps[c_s].ats_perf_op = NULL;
    }
    if (NULL != sps[c_s].core_op)
    {
      GNUNET_TESTBED_operation_done (sps[c_s].core_op);
      sps[c_s].core_op = NULL;
    }

    GNUNET_free (sps[c_s].partners);
    sps[c_s].partners = NULL;
  }

  GNUNET_SCHEDULER_shutdown ();
}


static struct BenchmarkPeer *
find_peer (const struct GNUNET_PeerIdentity * peer)
{
  int c_p;

  for (c_p = 0; c_p < num_masters; c_p++)
  {
    if (0
        == memcmp (&mps[c_p].id, peer,
            sizeof(struct GNUNET_PeerIdentity)))
      return &mps[c_p];
  }

  for (c_p = 0; c_p < num_slaves; c_p++)
  {
    if (0 == memcmp (&sps[c_p].id, peer,
            sizeof(struct GNUNET_PeerIdentity)))
      return &sps[c_p];
  }
  return NULL;
}


/**
 * Controller event callback
 *
 * @param cls NULL
 * @param event the controller event
 */
static void
controller_event_cb (void *cls,
    const struct GNUNET_TESTBED_EventInformation *event)
{
  //struct BenchmarkPeer *p = cls;
  switch (event->type)
  {
  case GNUNET_TESTBED_ET_CONNECT:
    break;
  case GNUNET_TESTBED_ET_OPERATION_FINISHED:
    break;
  default:
    GNUNET_break(0);
    result = 2;
    GNUNET_SCHEDULER_cancel (shutdown_task);
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL );
  }
}


static size_t
core_send_ready (void *cls, size_t size, void *buf)
{
  static char msgbuf[TEST_MESSAGE_SIZE];
  struct BenchmarkPartner *partner = cls;
  struct GNUNET_MessageHeader *msg;

  partner->cth = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Master [%u]: Sending PING to [%u]\n",
        partner->me->no, partner->dest->no);

  partner->messages_sent ++;
  partner->bytes_sent += TEST_MESSAGE_SIZE;
  partner->me->total_messages_sent ++;
  partner->me->total_bytes_sent += TEST_MESSAGE_SIZE;

  msg = (struct GNUNET_MessageHeader *) &msgbuf;
  memset (&msgbuf, 'a', TEST_MESSAGE_SIZE);
  msg->type = htons (TEST_MESSAGE_TYPE_PING);
  msg->size = htons (TEST_MESSAGE_SIZE);
  memcpy (buf, msg, TEST_MESSAGE_SIZE);
  return TEST_MESSAGE_SIZE;
}


static void
do_benchmark ()
{
  int c_m;
  int c_s;

  if ((state.connected_ATS_service == GNUNET_NO)
      || (state.connected_CORE_service == GNUNET_NO)
      || (state.connected_PEERS == GNUNET_NO)
      || (state.connected_CORE == GNUNET_NO))
    return;

  state.benchmarking = GNUNET_YES;
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Benchmarking start\n"));

  if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
    GNUNET_SCHEDULER_cancel (shutdown_task);
  shutdown_task = GNUNET_SCHEDULER_add_delayed (BENCHMARK_DURATION,
      &do_shutdown, NULL );

  /* Start sending test messages */
  for (c_s = 0; c_s < num_slaves; c_s++)
  {
    for (c_m = 0; c_m < num_masters; c_m++)
    {

      sps[c_s].partners[c_m].me = &sps[c_s];
      sps[c_s].partners[c_m].dest = &mps[c_m];
    }
  }

  for (c_m = 0; c_m < num_masters; c_m++)
  {
    for (c_s = 0; c_s < num_slaves; c_s++)
    {
      mps[c_m].partners[c_s].me = &mps[c_m];
      mps[c_m].partners[c_s].dest = &sps[c_s];
      mps[c_m].partners[c_s].cth = GNUNET_CORE_notify_transmit_ready (mps[c_m].ch,
          GNUNET_NO, 0, GNUNET_TIME_UNIT_MINUTES, &sps[c_s].id,
          TEST_MESSAGE_SIZE, &core_send_ready, &mps[c_m].partners[c_s]);
    }
  }
}


static void
connect_completion_callback (void *cls, struct GNUNET_TESTBED_Operation *op,
    const char *emsg)
{
  struct TestbedConnectOperation *cop = cls;
  static int ops = 0;
  int c;
  if (NULL == emsg)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
        _("Connected master peer %u with peer %u\n"), cop->master->no,
        cop->slave->no);
  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        _("Failed to connect master peer%u with peer %u\n"), cop->master->no,
        cop->slave->no);
    GNUNET_break(0);
    if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
      GNUNET_SCHEDULER_cancel (shutdown_task);
    shutdown_task = GNUNET_SCHEDULER_add_now (do_shutdown, NULL );
  }
  GNUNET_TESTBED_operation_done (op);
  ops++;
  for (c = 0; c < num_slaves; c++)
  {
    if (cop == &cop->master->core_connect_ops[c])
      cop->master->core_connect_ops[c].connect_op = NULL;
  }
  if (ops == num_masters * num_slaves)
  {
    state.connected_PEERS = GNUNET_YES;
    GNUNET_SCHEDULER_add_now (&do_benchmark, NULL );
  }
}


static void
do_connect_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int c_m;
  int c_s;
  struct BenchmarkPeer *p;

  if ((state.connected_ATS_service == GNUNET_NO)
      || (state.connected_CORE_service == GNUNET_NO))
  {
    return;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Connecting peers on CORE level\n"));

  for (c_m = 0; c_m < num_masters; c_m++)
  {
    p = &mps[c_m];
    p->core_connect_ops = GNUNET_malloc (num_slaves *
        sizeof (struct TestbedConnectOperation));

    for (c_s = 0; c_s < num_slaves; c_s++)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          _("Connecting master peer %u with slave peer %u\n"), p->no,
          sps[c_s].no);
      p->core_connect_ops[c_s].master = p;
      p->core_connect_ops[c_s].slave = &sps[c_s];
      p->core_connect_ops[c_s].connect_op = GNUNET_TESTBED_overlay_connect (NULL,
          &connect_completion_callback, &p->core_connect_ops[c_s],
          sps[c_s].peer, p->peer);
      if (NULL == p->core_connect_ops[c_s].connect_op)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
            _("Could not connect master peer %u and slave peer %u\n"), p->no,
            sps[c_s].no);
        GNUNET_break(0);
        if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
          GNUNET_SCHEDULER_cancel (shutdown_task);
        shutdown_task = GNUNET_SCHEDULER_add_now (do_shutdown, NULL );
        return;
      }
    }
  }
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_connect_cb (void *cls, const struct GNUNET_PeerIdentity * peer)
{
  struct BenchmarkPeer *p = cls;
  struct BenchmarkPeer *t;
  char *id;
  int c;
  int completed;

  t = find_peer (peer);
  if (NULL == t)
  {
    GNUNET_break(0);
    return;
  }

  id = GNUNET_strdup (GNUNET_i2s (&p->id));
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "%s %s connected to %s %s\n",
      (p->master == GNUNET_YES) ? "Master": "Slave", id,
      (t->master == GNUNET_YES) ? "Master": "Slave", GNUNET_i2s (peer));

  p->core_connections++;
  if ((GNUNET_YES == p->master) && (GNUNET_NO == t->master)
      && (GNUNET_NO == state.connected_CORE))
  {
    p->mi.core_slave_connections++;

    if (p->mi.core_slave_connections == num_slaves)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Master %u connected all slaves\n",
          p->no);
    }
    completed = GNUNET_YES;
    for (c = 0; c < num_masters; c++)
    {
      if (mps[c].mi.core_slave_connections != num_slaves)
        completed = GNUNET_NO;
    }
    if (GNUNET_YES == completed)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "All master peers connected all slave peers\n", id,
          GNUNET_i2s (peer));
      state.connected_CORE = GNUNET_YES;
      GNUNET_SCHEDULER_add_now (&do_benchmark, NULL );
    }
  }
  GNUNET_free(id);
}


static void
core_disconnect_cb (void *cls, const struct GNUNET_PeerIdentity * peer)
{
  struct BenchmarkPeer *p = cls;
  struct BenchmarkPeer *t;
  char *id;

  t = find_peer (peer);
  if (NULL == t)
  {
    GNUNET_break(0);
    return;
  }

  id = GNUNET_strdup (GNUNET_i2s (&p->id));
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "%s disconnected from %s \n", id,
      GNUNET_i2s (peer));
  GNUNET_assert(p->core_connections > 0);
  p->core_connections--;

  if ((GNUNET_YES == state.benchmarking)
      && ((GNUNET_YES == p->master) || (GNUNET_YES == t->master)))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        "%s disconnected from %s while benchmarking \n", id, GNUNET_i2s (peer));
  }
  GNUNET_free(id);
}

static size_t
core_send_echo_ready (void *cls, size_t size, void *buf)
{
  static char msgbuf[TEST_MESSAGE_SIZE];
  struct BenchmarkPartner *p = cls;
  struct GNUNET_MessageHeader *msg;

  p->cth = NULL;

  p->messages_sent ++;
  p->bytes_sent += TEST_MESSAGE_SIZE;
  p->me->total_messages_sent ++;
  p->me->total_bytes_sent += TEST_MESSAGE_SIZE;

  msg = (struct GNUNET_MessageHeader *) &msgbuf;
  memset (&msgbuf, 'a', TEST_MESSAGE_SIZE);
  msg->type = htons (TEST_MESSAGE_TYPE_PONG);
  msg->size = htons (TEST_MESSAGE_SIZE);
  memcpy (buf, msg, TEST_MESSAGE_SIZE);

  return TEST_MESSAGE_SIZE;
}


static int
core_handle_ping (void *cls, const struct GNUNET_PeerIdentity *other,
    const struct GNUNET_MessageHeader *message)
{
  int c_m;
  struct BenchmarkPeer *me = cls;
  struct BenchmarkPartner *p = NULL;
  for (c_m = 0; c_m < num_masters; c_m++)
  {
    if (0 == memcmp (other, &me->partners[c_m].dest->id, sizeof (struct GNUNET_PeerIdentity)))
    {
      p = &me->partners[c_m];
      break;
    }
  }
  if (NULL == p)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_assert (NULL == p->cth);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Slave [%u]: Received PING from [%u], sending PONG\n",
      me->no, p->dest->no);

  p->messages_received ++;
  p->bytes_received += TEST_MESSAGE_SIZE;
  p->me->total_messages_received ++;
  p->me->total_bytes_received += TEST_MESSAGE_SIZE;

  p->cth = GNUNET_CORE_notify_transmit_ready (me->ch, GNUNET_NO, 0,
      GNUNET_TIME_UNIT_MINUTES, &p->dest->id, TEST_MESSAGE_SIZE,
      &core_send_echo_ready, p);
  return GNUNET_OK;
}

static int
core_handle_pong (void *cls, const struct GNUNET_PeerIdentity *other,
    const struct GNUNET_MessageHeader *message)
{
  int c_s;
  struct BenchmarkPeer *me = cls;
  struct BenchmarkPartner *p = NULL;

  for (c_s = 0; c_s < num_slaves; c_s++)
  {
    if (0 == memcmp (other, &me->partners[c_s].dest->id, sizeof (struct GNUNET_PeerIdentity)))
    {
      p = &me->partners[c_s];
      break;
    }
  }
  if (NULL == p)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_assert (NULL == p->cth);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Master [%u]: Received PONG from [%u], next message\n",
      me->no, p->dest->no);

  p->messages_received ++;
  p->bytes_received += TEST_MESSAGE_SIZE;
  p->me->total_messages_received ++;
  p->me->total_bytes_received += TEST_MESSAGE_SIZE;

  p->cth = GNUNET_CORE_notify_transmit_ready (me->ch,
            GNUNET_NO, 0, GNUNET_TIME_UNIT_MINUTES, &p->dest->id,
            TEST_MESSAGE_SIZE, &core_send_ready, p);

  return GNUNET_OK;
}

static void *
core_connect_adapter (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct BenchmarkPeer *peer = cls;

  static const struct GNUNET_CORE_MessageHandler handlers[] = {
      {&core_handle_ping, TEST_MESSAGE_TYPE_PING, 0 },
      {&core_handle_pong, TEST_MESSAGE_TYPE_PONG, 0 },
      { NULL, 0, 0 } };

  peer->ch = GNUNET_CORE_connect (cfg, peer, NULL, core_connect_cb,
      core_disconnect_cb, NULL, GNUNET_NO, NULL, GNUNET_NO, handlers);
  if (NULL == peer->ch)
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to create core connection \n");
  return peer->ch;
}


static void
core_disconnect_adapter (void *cls, void *op_result)
{
  struct BenchmarkPeer *peer = cls;

  GNUNET_CORE_disconnect (peer->ch);
  peer->ch = NULL;
}


static void
core_connect_completion_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
    void *ca_result, const char *emsg)
{
  static int core_done = 0;
  if ((NULL != emsg) || (NULL == ca_result))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Initialization failed, shutdown\n"));
    GNUNET_break(0);
    if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
      GNUNET_SCHEDULER_cancel (shutdown_task);
    shutdown_task = GNUNET_SCHEDULER_add_now (do_shutdown, NULL );
    return;
  }
  core_done++;

  if (core_done == num_slaves + num_masters)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Connected to all CORE services\n");
    state.connected_CORE_service = GNUNET_YES;
    GNUNET_SCHEDULER_add_now (&do_connect_peers, NULL );
  }
}


static void
do_connect_core (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int c_s;
  int c_m;
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Connecting to all CORE services\n");
  for (c_m = 0; c_m < num_masters; c_m++)
  {
    mps[c_m].core_op = GNUNET_TESTBED_service_connect (NULL,
        mps[c_m].peer, "core", core_connect_completion_cb, NULL,
        &core_connect_adapter, &core_disconnect_adapter, &mps[c_m]);
  }

  for (c_s = 0; c_s < num_slaves; c_s++)
  {
    sps[c_s].core_op = GNUNET_TESTBED_service_connect (NULL,
        sps[c_s].peer, "core", core_connect_completion_cb, NULL,
        &core_connect_adapter, &core_disconnect_adapter, &sps[c_s]);
  }
}

static void
ats_performance_info_cb (void *cls, const struct GNUNET_HELLO_Address *address,
    int address_active, struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
    const struct GNUNET_ATS_Information *ats, uint32_t ats_count)
{
  struct BenchmarkPeer *p = cls;
  int c_a;
  char *peer_id;

  peer_id = GNUNET_strdup (GNUNET_i2s (&p->id));
  for (c_a = 0; c_a < ats_count; c_a++)
  {
    /*GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("%c %03u: %s %s %u\n"),
     (GNUNET_YES == p->master) ? 'M' : 'S',
     p->no,
     GNUNET_i2s (&address->peer),
     GNUNET_ATS_print_property_type(ntohl(ats[c_a].type)),
     ntohl(ats[c_a].value));*/
  }
#if 0
  if ((GNUNET_YES == p->master)
      && (0 == memcmp (&address->peer, &p->destination->id,
                       sizeof(struct GNUNET_PeerIdentity))))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Bandwidth for master %u: %lu %lu\n",
        p->no, (long unsigned int ) ntohl (bandwidth_in.value__),
        (long unsigned int ) ntohl (bandwidth_in.value__));
  }

  store_information (&bp->id, address, address_active, bandwidth_in,
      bandwidth_out, ats, ats_count);
#endif
  GNUNET_free(peer_id);
}


static void *
ats_perf_connect_adapter (void *cls,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct BenchmarkPeer *peer = cls;

  peer->ats_perf_handle = GNUNET_ATS_performance_init (cfg, &ats_performance_info_cb,
      peer);
  if (NULL == peer->ats_perf_handle)
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        "Failed to create ATS performance handle \n");
  return peer->ats_perf_handle;
}


static void
ats_perf_disconnect_adapter (void *cls, void *op_result)
{
  struct BenchmarkPeer *peer = cls;

  GNUNET_ATS_performance_done (peer->ats_perf_handle);
  peer->ats_perf_handle = NULL;
}

static void
ats_connect_completion_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
    void *ca_result, const char *emsg)
{
  static int op_done = 0;

  if ((NULL != emsg) || (NULL == ca_result))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Initialization failed, shutdown\n"));
    GNUNET_break(0);
    if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
      GNUNET_SCHEDULER_cancel (shutdown_task);
    shutdown_task = GNUNET_SCHEDULER_add_now (do_shutdown, NULL );
    return;
  }
  op_done++;
  if (op_done == (num_masters+ num_slaves))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Connected to all ATS services\n");
    state.connected_ATS_service = GNUNET_YES;
    GNUNET_SCHEDULER_add_now (&do_connect_core, NULL );
  }
}


static void
do_connect_ats (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int c_m;
  int c_s;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Connecting to all ATS services\n");
  for (c_m = 0; c_m < num_masters; c_m++)
  {
    mps[c_m].ats_perf_op = GNUNET_TESTBED_service_connect (NULL,
        mps[c_m].peer, "ats", ats_connect_completion_cb, NULL,
        &ats_perf_connect_adapter, &ats_perf_disconnect_adapter,
        &mps[c_m]);

  }

  for (c_s = 0; c_s < num_slaves; c_s++)
  {
    sps[c_s].ats_perf_op = GNUNET_TESTBED_service_connect (NULL,
        sps[c_s].peer, "ats", ats_connect_completion_cb, NULL,
        &ats_perf_connect_adapter, &ats_perf_disconnect_adapter,
        &sps[c_s]);
  }

}

static void
peerinformation_cb (void *cb_cls, struct GNUNET_TESTBED_Operation *op,
    const struct GNUNET_TESTBED_PeerInformation*pinfo, const char *emsg)
{
  struct BenchmarkPeer *p = cb_cls;
  static int done = 0;

  GNUNET_assert (pinfo->pit == GNUNET_TESTBED_PIT_IDENTITY);

  p->id = *pinfo->result.id;
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "[%c %03u] Peers %s\n",
      (p->master == GNUNET_YES) ? 'M' : 'S', p->no, GNUNET_i2s (&p->id));

  GNUNET_TESTBED_operation_done (op);
  p->peer_id_op = NULL;
  done++;

  if (done == num_slaves + num_masters)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
        "Retrieved all peer ID, connect to ATS\n");
    GNUNET_SCHEDULER_add_now (&do_connect_ats, NULL );
  }
}

/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param num_peers number of peers in 'peers'
 * @param peers_ handle to peers run in the testbed
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 */
static void
main_run (void *cls, struct GNUNET_TESTBED_RunHandle *h,
    unsigned int num_peers, struct GNUNET_TESTBED_Peer **peers_,
    unsigned int links_succeeded, unsigned int links_failed)
{
  int c_m;
  int c_s;
  GNUNET_assert(NULL == cls);
  GNUNET_assert(num_masters + num_slaves == num_peers);
  GNUNET_assert(NULL != peers_);

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      _("Benchmarking solver `%s' on preference `%s' with %u master and %u slave peers\n"),
      solver, pref_str, num_masters, num_slaves);

  shutdown_task = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (TEST_TIMEOUT,
          num_masters + num_slaves), &do_shutdown, NULL );

  /* Setup master peers */
  for (c_m = 0; c_m < num_masters; c_m++)
  {
    GNUNET_assert(NULL != peers_[c_m]);
    mps[c_m].peer = peers_[c_m];
    mps[c_m].no = c_m;
    mps[c_m].master = GNUNET_YES;
    mps[c_m].partners = GNUNET_malloc (num_slaves * sizeof (struct BenchmarkPeer));
    mps[c_m].peer_id_op = GNUNET_TESTBED_peer_get_information (
            mps[c_m].peer, GNUNET_TESTBED_PIT_IDENTITY,
            &peerinformation_cb,
            &mps[c_m]);
  }

  /* Setup slave peers */
  for (c_s = 0; c_s < num_slaves; c_s++)
  {
    GNUNET_assert(NULL != peers_[c_s + num_masters]);
    sps[c_s].peer = peers_[c_s + num_masters];
    sps[c_s].no = c_s + num_masters;
    sps[c_s].master = GNUNET_NO;
    sps[c_s].partners = GNUNET_malloc (num_masters * sizeof (struct BenchmarkPeer));
    sps[c_s].peer_id_op = GNUNET_TESTBED_peer_get_information (
            sps[c_s].peer, GNUNET_TESTBED_PIT_IDENTITY,
            &peerinformation_cb,
            &sps[c_s]);
  }
}

int
main (int argc, char *argv[])
{
  char *tmp;
  char *tmp_sep;
  char *test_name;
  char *conf_name;
  char *dotexe;
  char *prefs[GNUNET_ATS_PreferenceCount] = GNUNET_ATS_PreferenceTypeString;
  int c;

  result = 0;

  /* figure out testname */
  tmp = strstr (argv[0], TESTNAME_PREFIX);
  if (NULL == tmp)
  {
    fprintf (stderr, "Unable to parse test name `%s'\n", argv[0]);
    return GNUNET_SYSERR;
  }
  tmp += strlen (TESTNAME_PREFIX);
  solver = GNUNET_strdup (tmp);
  if (NULL != (dotexe = strstr (solver, ".exe")) && dotexe[4] == '\0')
    dotexe[0] = '\0';
  tmp_sep = strchr (solver, '_');
  if (NULL == tmp_sep)
  {
    fprintf (stderr, "Unable to parse test name `%s'\n", argv[0]);
    GNUNET_free(solver);
    return GNUNET_SYSERR;
  }
  tmp_sep[0] = '\0';
  pref_str = GNUNET_strdup(tmp_sep + 1);

  GNUNET_asprintf (&conf_name, "%s%s_%s.conf", TESTNAME_PREFIX, solver,
      pref_str);
  GNUNET_asprintf (&test_name, "%s%s_%s", TESTNAME_PREFIX, solver, pref_str);

  for (c = 0; c <= strlen (pref_str); c++)
    pref_str[c] = toupper (pref_str[c]);
  pref_val = -1;

  if (0 != strcmp (pref_str, "NONE"))
  {
    for (c = 1; c < GNUNET_ATS_PreferenceCount; c++)
    {
      if (0 == strcmp (pref_str, prefs[c]))
      {
        pref_val = c;
        break;
      }
    }
  }
  else
  {
    /* abuse terminator to indicate no pref */
    pref_val = GNUNET_ATS_PREFERENCE_END;
  }
  if (-1 == pref_val)
  {
    fprintf (stderr, "Unknown preference: `%s'\n", pref_str);
    GNUNET_free (solver);
    GNUNET_free (pref_str);
    return -1;
  }

  for (c = 0; c < (argc -1); c++)
  {
  	if (0 == strcmp(argv[c], "-s"))
  		break;
  }
  if (c < argc-1)
  {
    if ((0L != (num_slaves = strtol (argv[c + 1], NULL, 10))) && (num_slaves >= 1))
      fprintf (stderr, "Starting %u slave peers\n", num_slaves);
    else
    	num_slaves = DEFAULT_SLAVES_NUM;
  }
  else
  	num_slaves = DEFAULT_SLAVES_NUM;

  for (c = 0; c < (argc -1); c++)
  {
  	if (0 == strcmp(argv[c], "-m"))
  		break;
  }
  if (c < argc-1)
  {
    if ((0L != (num_masters = strtol (argv[c + 1], NULL, 10))) && (num_masters >= 2))
      fprintf (stderr, "Starting %u master peers\n", num_masters);
    else
    	num_masters = DEFAULT_MASTERS_NUM;
  }
  else
  	num_masters = DEFAULT_MASTERS_NUM;

  state.connected_ATS_service = GNUNET_NO;
  state.connected_CORE_service = GNUNET_NO;
  state.connected_PEERS = GNUNET_NO;

  mps = GNUNET_malloc (num_masters * sizeof (struct BenchmarkPeer));
  sps = GNUNET_malloc (num_slaves * sizeof (struct BenchmarkPeer));

  /* Start topology */
  uint64_t event_mask;
  event_mask = 0;
  event_mask |= (1LL << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  (void) GNUNET_TESTBED_test_run ("perf_ats",
                                  conf_name, num_slaves + num_masters,
                                  event_mask, &controller_event_cb, NULL,
                                  &main_run, NULL);

  GNUNET_free (solver);
  GNUNET_free (pref_str);
  GNUNET_free (conf_name);
  GNUNET_free (test_name);
  GNUNET_free (mps);
  GNUNET_free (sps);

  return result;
}

/* end of file perf_ats.c */
