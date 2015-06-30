/*
 This file is part of GNUnet.
 Copyright (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file ats-tests/ats-testing.c
 * @brief ats testing library: setup topology
 * solvers
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "ats-testing.h"


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

struct GNUNET_CONFIGURATION_Handle *cfg;

struct GNUNET_ATS_TEST_Topology *top;

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
  struct BenchmarkPeer *p;

  top->shutdown_task = NULL;
  top->state.benchmarking = GNUNET_NO;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Benchmarking done\n"));

  GNUNET_ATS_TEST_generate_traffic_stop_all ();

  for (c_m = 0; c_m < top->num_masters; c_m++)
  {
    p = &top->mps[c_m];
    if (NULL != top->mps[c_m].peer_id_op)
    {
      GNUNET_TESTBED_operation_done (p->peer_id_op);
      p->peer_id_op = NULL;
    }

    if (NULL != p->ats_task)
      GNUNET_SCHEDULER_cancel (p->ats_task);
    p->ats_task = NULL;

    for (c_op = 0; c_op < p->num_partners; c_op++)
    {
      if (NULL != p->partners[c_op].cth)
      {
        GNUNET_CORE_notify_transmit_ready_cancel (p->partners[c_op].cth);
        p->partners[c_op].cth = NULL;
      }
      if (NULL != p->partners[c_op].tth)
      {
        GNUNET_TRANSPORT_notify_transmit_ready_cancel (p->partners[c_op].tth);
        p->partners[c_op].tth = NULL;
      }
      if ( (NULL != p->core_connect_ops) &&
           (NULL != p->core_connect_ops[c_op].connect_op) )
      {
        GNUNET_log(GNUNET_ERROR_TYPE_INFO,
            _("Failed to connect peer 0 and %u\n"), c_op);
        GNUNET_TESTBED_operation_done (
            p->core_connect_ops[c_op].connect_op);
        p->core_connect_ops[c_op].connect_op = NULL;
      }
    }

    if (NULL != p->ats_perf_op)
    {
      GNUNET_TESTBED_operation_done (p->ats_perf_op);
      p->ats_perf_op = NULL;
    }

    if (NULL != p->comm_op)
    {
      GNUNET_TESTBED_operation_done (p->comm_op);
      p->comm_op = NULL;
    }
    GNUNET_free_non_null (p->core_connect_ops);
    GNUNET_free(p->partners);
    p->partners = NULL;
  }

  for (c_s = 0; c_s < top->num_slaves; c_s++)
  {
    p = &top->sps[c_s];
    if (NULL != p->peer_id_op)
    {
      GNUNET_TESTBED_operation_done (p->peer_id_op);
      p->peer_id_op = NULL;
    }

    for (c_op = 0; c_op < p->num_partners; c_op++)
    {
      if (NULL != p->partners[c_op].cth)
      {
        GNUNET_CORE_notify_transmit_ready_cancel (p->partners[c_op].cth);
        p->partners[c_op].cth = NULL;
      }
      if (NULL != p->partners[c_op].tth)
      {
        GNUNET_TRANSPORT_notify_transmit_ready_cancel (p->partners[c_op].tth);
        p->partners[c_op].tth = NULL;
      }
    }
    if (NULL != p->ats_perf_op)
    {
      GNUNET_TESTBED_operation_done (p->ats_perf_op);
      p->ats_perf_op = NULL;
    }
    if (NULL != p->comm_op)
    {
      GNUNET_TESTBED_operation_done (p->comm_op);
      p->comm_op = NULL;
    }
    GNUNET_free(p->partners);
    p->partners = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
  GNUNET_free (top);
  top = NULL;
}

static struct BenchmarkPartner *
find_partner (struct BenchmarkPeer *me, const struct GNUNET_PeerIdentity * peer)
{
  int c_m;
  GNUNET_assert (NULL != me);
  GNUNET_assert (NULL != peer);

  for (c_m = 0; c_m < me->num_partners; c_m++)
  {
    /* Find a partner with other as destination */
    if (0 == memcmp (peer, &me->partners[c_m].dest->id,
            sizeof(struct GNUNET_PeerIdentity)))
    {
      return &me->partners[c_m];
    }
  }

  return NULL;
}


static struct BenchmarkPeer *
find_peer (const struct GNUNET_PeerIdentity * peer)
{
  int c_p;

  for (c_p = 0; c_p < top->num_masters; c_p++)
  {
    if (0 == memcmp (&top->mps[c_p].id, peer, sizeof(struct GNUNET_PeerIdentity)))
      return &top->mps[c_p];
  }

  for (c_p = 0; c_p < top->num_slaves; c_p++)
  {
    if (0 == memcmp (&top->sps[c_p].id, peer, sizeof(struct GNUNET_PeerIdentity)))
      return &top->sps[c_p];
  }
  return NULL ;
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
comm_connect_cb (void *cls, const struct GNUNET_PeerIdentity * peer)
{
  struct BenchmarkPeer *me = cls;
  struct BenchmarkPeer *remote;
  char *id;
  int c;
  int completed;

  remote = find_peer (peer);
  if (NULL == remote)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Unknown peer connected: `%s'\n", GNUNET_i2s (peer));
    GNUNET_break(0);
    return;
  }

  id = GNUNET_strdup (GNUNET_i2s (&me->id));
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "%s [%u] `%s' connected to %s [%u] %s\n",
      (me->master == GNUNET_YES) ? "Master": "Slave", me->no, id,
      (remote->master == GNUNET_YES) ? "Master": "Slave", remote->no,
      GNUNET_i2s (peer));

  me->core_connections++;
  if ((GNUNET_YES == me->master) && (GNUNET_NO == remote->master)
      && (GNUNET_NO == top->state.connected_CORE))
  {
    me->core_slave_connections++;

    if (me->core_slave_connections == top->num_slaves)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Master [%u] connected all slaves\n",
          me->no);
    }
    completed = GNUNET_YES;
    for (c = 0; c < top->num_masters; c++)
    {
      if (top->mps[c].core_slave_connections != top->num_slaves)
        completed = GNUNET_NO;
    }
    if (GNUNET_YES == completed)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "All master peers connected all slave peers\n", id,
          GNUNET_i2s (peer));
      top->state.connected_CORE = GNUNET_YES;
      /* Notify about setup done */
      if (NULL != top->done_cb)
        top->done_cb (top->done_cb_cls, top->mps, top->sps);
    }
  }
  GNUNET_free(id);
}

static void
comm_disconnect_cb (void *cls, const struct GNUNET_PeerIdentity * peer)
{
  struct BenchmarkPeer *me = cls;
  struct BenchmarkPartner *p;
  char *id;

  if (NULL == (p = find_partner (me, peer)))
    return;

  id = GNUNET_strdup (GNUNET_i2s (&me->id));
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "%s disconnected from %s \n", id,
      GNUNET_i2s (peer));
  GNUNET_assert(me->core_connections > 0);
  me->core_connections--;

  if ((GNUNET_YES == top->state.benchmarking)
      && ((GNUNET_YES == me->master) || (GNUNET_YES == p->dest->master)))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        "%s disconnected from %s while benchmarking \n", id, GNUNET_i2s (peer));
    if (NULL != p->tth)
    {
      GNUNET_TRANSPORT_notify_transmit_ready_cancel (p->tth);
      p->tth = NULL;
    }
    if (NULL != p->cth)
    {
      GNUNET_CORE_notify_transmit_ready_cancel (p->cth);
      p->cth = NULL;
    }
  }
  GNUNET_free(id);
}


static void *
core_connect_adapter (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct BenchmarkPeer *me = cls;

  me->ch = GNUNET_CORE_connect (cfg, me, NULL, comm_connect_cb,
      comm_disconnect_cb, NULL, GNUNET_NO, NULL, GNUNET_NO, top->handlers);
  if (NULL == me->ch)
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to create core connection \n");
  return me->ch;
}

static void
core_disconnect_adapter (void *cls, void *op_result)
{
  struct BenchmarkPeer *me = cls;

  GNUNET_CORE_disconnect (me->ch);
  me->ch = NULL;
}




static int
comm_handle_pong (void *cls, const struct GNUNET_PeerIdentity *other,
    const struct GNUNET_MessageHeader *message)
{
  struct BenchmarkPeer *me = cls;
  struct BenchmarkPartner *p = NULL;

  if (NULL == (p = find_partner (me, other)))
  {
    GNUNET_break(0);
    return GNUNET_SYSERR;
  }

  GNUNET_ATS_TEST_traffic_handle_pong (p);

  return GNUNET_OK;
}

static int
comm_handle_ping (void *cls, const struct GNUNET_PeerIdentity *other,
    const struct GNUNET_MessageHeader *message)
{
  struct BenchmarkPeer *me = cls;
  struct BenchmarkPartner *p = NULL;

  if (NULL == (p = find_partner(me, other)))
  {
    GNUNET_break(0);
    return GNUNET_SYSERR;
  }
  GNUNET_ATS_TEST_traffic_handle_ping (p);
  return GNUNET_OK;
}

static void
test_recv_cb (void *cls,
                     const struct GNUNET_PeerIdentity * peer,
                     const struct GNUNET_MessageHeader * message)
{
  if (TEST_MESSAGE_SIZE != ntohs (message->size) ||
      (TEST_MESSAGE_TYPE_PING != ntohs (message->type) &&
     TEST_MESSAGE_TYPE_PONG != ntohs (message->type)))
  {
    return;
  }
  if (TEST_MESSAGE_TYPE_PING == ntohs (message->type))
    comm_handle_ping (cls, peer, message);
  if (TEST_MESSAGE_TYPE_PONG == ntohs (message->type))
    comm_handle_pong (cls, peer, message);
}


static void *
transport_connect_adapter (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct BenchmarkPeer *me = cls;

  me->th = GNUNET_TRANSPORT_connect (cfg, &me->id, me, &test_recv_cb,
      &comm_connect_cb, &comm_disconnect_cb);
  if (NULL == me->th)
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to create transport connection \n");
  return me->th;
}

static void
transport_disconnect_adapter (void *cls, void *op_result)
{
  struct BenchmarkPeer *me = cls;

  GNUNET_TRANSPORT_disconnect (me->th);
  me->th = NULL;
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
        _("Connected master [%u] with slave [%u]\n"), cop->master->no,
        cop->slave->no);
  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        _("Failed to connect master peer [%u] with slave [%u]\n"),
        cop->master->no, cop->slave->no);
    GNUNET_break(0);
    if (NULL != top->shutdown_task)
      GNUNET_SCHEDULER_cancel (top->shutdown_task);
    top->shutdown_task = GNUNET_SCHEDULER_add_now (do_shutdown, NULL );
  }
  GNUNET_TESTBED_operation_done (op);
  ops++;
  for (c = 0; c < top->num_slaves; c++)
  {
    if (cop == &cop->master->core_connect_ops[c])
      cop->master->core_connect_ops[c].connect_op = NULL;
  }
  if (ops == top->num_masters * top->num_slaves)
  {
    top->state.connected_PEERS = GNUNET_YES;
  }
}

static void
do_connect_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int c_m;
  int c_s;
  struct BenchmarkPeer *p;

  if ((top->state.connected_ATS_service == GNUNET_NO) ||
      (top->state.connected_COMM_service == GNUNET_NO))
    return;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Connecting peers on CORE level\n"));

  for (c_m = 0; c_m < top->num_masters; c_m++)
  {
    p = &top->mps[c_m];
    p->core_connect_ops = GNUNET_malloc (top->num_slaves *
        sizeof (struct TestbedConnectOperation));

    for (c_s = 0; c_s < top->num_slaves; c_s++)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          _("Connecting master [%u] with slave [%u]\n"), p->no, top->sps[c_s].no);
      p->core_connect_ops[c_s].master = p;
      p->core_connect_ops[c_s].slave = &top->sps[c_s];
      p->core_connect_ops[c_s].connect_op = GNUNET_TESTBED_overlay_connect (
          NULL, &connect_completion_callback, &p->core_connect_ops[c_s],
          top->sps[c_s].peer, p->peer);
      if (NULL == p->core_connect_ops[c_s].connect_op)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
            _("Could not connect master [%u] and slave [%u]\n"), p->no,
            top->sps[c_s].no);
        GNUNET_break(0);
        if (NULL != top->shutdown_task)
          GNUNET_SCHEDULER_cancel (top->shutdown_task);
        top->shutdown_task = GNUNET_SCHEDULER_add_now (do_shutdown, NULL );
        return;
      }
    }
  }
}


static void
comm_connect_completion_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
    void *ca_result, const char *emsg)
{
  static int comm_done = 0;
  if ((NULL != emsg) || (NULL == ca_result))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Initialization failed, shutdown\n"));
    GNUNET_break(0);
    if (NULL != top->shutdown_task)
      GNUNET_SCHEDULER_cancel (top->shutdown_task);
    top->shutdown_task = GNUNET_SCHEDULER_add_now (do_shutdown, NULL );
    return;
  }
  comm_done++;

  if (comm_done == top->num_slaves + top->num_masters)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Connected to all %s services\n",
        (GNUNET_YES == top->test_core) ? "CORE" : "TRANSPORT");
    top->state.connected_COMM_service = GNUNET_YES;
    GNUNET_SCHEDULER_add_now (&do_connect_peers, NULL );
  }
}

static void
do_comm_connect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int c_s;
  int c_m;
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Connecting to all %s services\n",
      (GNUNET_YES == top->test_core) ? "CORE" : "TRANSPORT");
  for (c_m = 0; c_m < top->num_masters; c_m++)
  {
    if (GNUNET_YES == top->test_core)
      top->mps[c_m].comm_op = GNUNET_TESTBED_service_connect (NULL, top->mps[c_m].peer,
        "core", &comm_connect_completion_cb, NULL, &core_connect_adapter,
        &core_disconnect_adapter, &top->mps[c_m]);
    else
    {
      top->mps[c_m].comm_op = GNUNET_TESTBED_service_connect (NULL, top->mps[c_m].peer,
        "transport", &comm_connect_completion_cb, NULL, &transport_connect_adapter,
        &transport_disconnect_adapter, &top->mps[c_m]);
    }
  }

  for (c_s = 0; c_s < top->num_slaves; c_s++)
  {
    if (GNUNET_YES == top->test_core)
      top->sps[c_s].comm_op = GNUNET_TESTBED_service_connect (NULL, top->sps[c_s].peer,
        "core", &comm_connect_completion_cb, NULL, &core_connect_adapter,
        &core_disconnect_adapter, &top->sps[c_s]);
    else
    {
      top->sps[c_s].comm_op = GNUNET_TESTBED_service_connect (NULL, top->sps[c_s].peer,
        "transport", &comm_connect_completion_cb, NULL, &transport_connect_adapter,
        &transport_disconnect_adapter, &top->sps[c_s]);
    }
  }
}


static void
ats_performance_info_cb (void *cls,
                         const struct GNUNET_HELLO_Address *address,
                         int address_active,
                         struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                         struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                         const struct GNUNET_ATS_Properties *ats_prop)
{
  struct BenchmarkPeer *me = cls;
  struct BenchmarkPartner *p;
  int log;
  char *peer_id;

  if (NULL == address)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Peer %u: ATS Service disconnected!\n",
        me->no);
    return;
  }

  p = find_partner (me, &address->peer);
  if (NULL == p)
  {
    /* This is not one of my partners
     * Will happen since the peers will connect to each other due to gossiping
     */
    return;
  }
  peer_id = GNUNET_strdup (GNUNET_i2s (&me->id));

  log = GNUNET_NO;
  if ((p->bandwidth_in != ntohl (bandwidth_in.value__)) ||
      (p->bandwidth_out != ntohl (bandwidth_out.value__)))
      log = GNUNET_YES;
  p->bandwidth_in = ntohl (bandwidth_in.value__);
  p->bandwidth_out = ntohl (bandwidth_out.value__);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s [%u] received ATS information: %s\n",
      (GNUNET_YES == p->me->master) ? "Master" : "Slave",
      p->me->no,
      GNUNET_i2s (&p->dest->id));

  p->props.utilization_out = ats_prop->utilization_out;
  p->props.utilization_in = ats_prop->utilization_in;
  p->props.scope = ats_prop->scope;
  p->props.delay = ats_prop->delay;
  p->props.distance = ats_prop->distance;

  if (GNUNET_YES == log)
    top->ats_perf_cb (cls, address,
                      address_active,
                      bandwidth_out,
                      bandwidth_in,
                      ats_prop);
  GNUNET_free(peer_id);
}


static void *
ats_perf_connect_adapter (void *cls,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct BenchmarkPeer *me = cls;

  me->ats_perf_handle = GNUNET_ATS_performance_init (cfg,
      &ats_performance_info_cb, me);
  if (NULL == me->ats_perf_handle)
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        "Failed to create ATS performance handle \n");
  return me->ats_perf_handle;
}

static void
ats_perf_disconnect_adapter (void *cls, void *op_result)
{
  struct BenchmarkPeer *me = cls;

  GNUNET_ATS_performance_done (me->ats_perf_handle);
  me->ats_perf_handle = NULL;
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
    if (NULL != top->shutdown_task)
      GNUNET_SCHEDULER_cancel (top->shutdown_task);
    top->shutdown_task = GNUNET_SCHEDULER_add_now (do_shutdown, NULL );
    return;
  }
  op_done++;
  if (op_done == (top->num_masters + top->num_slaves))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Connected to all ATS services\n");
    top->state.connected_ATS_service = GNUNET_YES;
    GNUNET_SCHEDULER_add_now (&do_comm_connect, NULL );
  }
}


static void
do_connect_ats (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int c_m;
  int c_s;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Connecting to all ATS services\n");
  for (c_m = 0; c_m < top->num_masters; c_m++)
  {
    top->mps[c_m].ats_perf_op = GNUNET_TESTBED_service_connect (NULL,
        top->mps[c_m].peer,
        "ats", ats_connect_completion_cb, NULL,
        &ats_perf_connect_adapter,
        &ats_perf_disconnect_adapter, &top->mps[c_m]);
  }

  for (c_s = 0; c_s < top->num_slaves; c_s++)
  {
    top->sps[c_s].ats_perf_op = GNUNET_TESTBED_service_connect (NULL, top->sps[c_s].peer,
        "ats", ats_connect_completion_cb, NULL, &ats_perf_connect_adapter,
        &ats_perf_disconnect_adapter, &top->sps[c_s]);
  }
}



static void
peerinformation_cb (void *cb_cls, struct GNUNET_TESTBED_Operation *op,
    const struct GNUNET_TESTBED_PeerInformation*pinfo, const char *emsg)
{
  struct BenchmarkPeer *p = cb_cls;
  static int done = 0;

  GNUNET_assert(pinfo->pit == GNUNET_TESTBED_PIT_IDENTITY);

  p->id = *pinfo->result.id;
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "%s [%u] has peer id `%s'\n",
      (p->master == GNUNET_YES) ? "Master" : "Slave", p->no,
      GNUNET_i2s (&p->id));

  GNUNET_TESTBED_operation_done (op);
  p->peer_id_op = NULL;
  done++;

  if (done == top->num_slaves + top->num_masters)
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
 * @param h testbed handle
 * @param num_peers number of peers in 'peers'
 * @param peers_ handle to peers run in the testbed
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 */
static void
main_run (void *cls, struct GNUNET_TESTBED_RunHandle *h,
          unsigned int num_peers,
          struct GNUNET_TESTBED_Peer **peers_,
          unsigned int links_succeeded,
          unsigned int links_failed)
{
  int c_m;
  int c_s;
  GNUNET_assert(NULL == cls);
  GNUNET_assert(top->num_masters + top->num_slaves == num_peers);
  GNUNET_assert(NULL != peers_);

  top->shutdown_task = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_UNIT_FOREVER_REL, &do_shutdown, top);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Setting up %u masters and %u slaves\n",
      top->num_masters, top->num_slaves);

  /* Setup master peers */
  for (c_m = 0; c_m < top->num_masters; c_m++)
  {
    GNUNET_assert(NULL != peers_[c_m]);
    top->mps[c_m].peer = peers_[c_m];
    top->mps[c_m].no = c_m;
    top->mps[c_m].master = GNUNET_YES;
    top->mps[c_m].pref_partner = &top->sps[c_m];
    top->mps[c_m].pref_value = TEST_ATS_PREFERENCE_DEFAULT;
    top->mps[c_m].partners =
        GNUNET_malloc (top->num_slaves * sizeof (struct BenchmarkPartner));
    top->mps[c_m].num_partners = top->num_slaves;
    /* Initialize partners */
    for (c_s = 0; c_s < top->num_slaves; c_s++)
    {
      top->mps[c_m].partners[c_s].me = &top->mps[c_m];
      top->mps[c_m].partners[c_s].dest = &top->sps[c_s];
    }
    /* Get configuration */
    top->mps[c_m].peer_id_op = GNUNET_TESTBED_peer_get_information (top->mps[c_m].peer,
        GNUNET_TESTBED_PIT_IDENTITY, &peerinformation_cb, &top->mps[c_m]);
  }

  /* Setup slave peers */
  for (c_s = 0; c_s < top->num_slaves; c_s++)
  {
    GNUNET_assert(NULL != peers_[c_s + top->num_masters]);
    top->sps[c_s].peer = peers_[c_s + top->num_masters];
    top->sps[c_s].no = c_s + top->num_masters;
    top->sps[c_s].master = GNUNET_NO;
    top->sps[c_s].partners =
        GNUNET_malloc (top->num_masters * sizeof (struct BenchmarkPartner));
    top->sps[c_s].num_partners = top->num_masters;
    /* Initialize partners */
    for (c_m = 0; c_m < top->num_masters; c_m++)
    {
      top->sps[c_s].partners[c_m].me = &top->sps[c_s];
      top->sps[c_s].partners[c_m].dest = &top->mps[c_m];

      /* Initialize properties */
      top->sps[c_s].partners[c_m].props.delay = GNUNET_TIME_UNIT_ZERO;
      top->sps[c_s].partners[c_m].props.distance = 0;
      top->sps[c_s].partners[c_m].props.scope = GNUNET_ATS_NET_UNSPECIFIED;
      top->sps[c_s].partners[c_m].props.utilization_in = 0;
      top->sps[c_s].partners[c_m].props.utilization_out = 0;
    }
    /* Get configuration */
    top->sps[c_s].peer_id_op = GNUNET_TESTBED_peer_get_information (top->sps[c_s].peer,
        GNUNET_TESTBED_PIT_IDENTITY, &peerinformation_cb, &top->sps[c_s]);
  }
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
  struct GNUNET_ATS_TEST_Topology *top = cls;
  switch (event->type)
  {
  case GNUNET_TESTBED_ET_CONNECT:
    break;
  case GNUNET_TESTBED_ET_OPERATION_FINISHED:
    break;
  default:
    GNUNET_break(0);
    GNUNET_SCHEDULER_cancel (top->shutdown_task);
    top->shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL );
  }
}

struct BenchmarkPeer *
GNUNET_ATS_TEST_get_peer (int src)
{
  if (src > top->num_masters)
    return NULL;
  return &top->mps[src];
}

struct BenchmarkPartner *
GNUNET_ATS_TEST_get_partner (int src, int dest)
{
  if (src > top->num_masters)
    return NULL;
  if (dest > top->num_slaves)
    return NULL;
  return &top->mps[src].partners[dest];
}


/**
 * Create a topology for ats testing
 *
 * @param name test name
 * @param cfg_file configuration file to use for the peers
 * @param num_slaves number of slaves
 * @param num_masters number of masters
 * @param test_core connect to CORE service (GNUNET_YES) or transport (GNUNET_NO)
 * @param done_cb function to call when topology is setup
 * @param done_cb_cls cls for callback
 * @param transport_recv_cb callback to call when data are received
 * @param log_request_cb callback to call when logging is required
 */
void
GNUNET_ATS_TEST_create_topology (char *name, char *cfg_file,
                                 unsigned int num_slaves,
                                 unsigned int num_masters,
                                 int test_core,
                                 GNUNET_ATS_TEST_TopologySetupDoneCallback done_cb,
                                 void *done_cb_cls,
                                 GNUNET_TRANSPORT_ReceiveCallback transport_recv_cb,
                                 GNUNET_ATS_AddressInformationCallback log_request_cb)
{
  static struct GNUNET_CORE_MessageHandler handlers[] = {
      {&comm_handle_ping, TEST_MESSAGE_TYPE_PING, 0 },
      {&comm_handle_pong, TEST_MESSAGE_TYPE_PONG, 0 },
      { NULL, 0, 0 } };

  top = GNUNET_new (struct GNUNET_ATS_TEST_Topology);
  top->num_masters = num_masters;
  top->num_slaves = num_slaves;
  top->handlers = handlers;
  top->done_cb = done_cb;
  top->done_cb_cls = done_cb_cls;
  top->test_core = test_core;
  top->transport_recv_cb = transport_recv_cb;
  top->ats_perf_cb = log_request_cb;

  top->mps = GNUNET_malloc (num_masters * sizeof (struct BenchmarkPeer));
  top->sps = GNUNET_malloc (num_slaves * sizeof (struct BenchmarkPeer));

  /* Start topology */
  uint64_t event_mask;
  event_mask = 0;
  event_mask |= (1LL << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  (void) GNUNET_TESTBED_test_run (name, cfg_file,
                                  num_slaves + num_masters,
                                  event_mask,
                                  &controller_event_cb, NULL,
                                  &main_run, NULL);
}


/**
 * Shutdown topology
 */
void
GNUNET_ATS_TEST_shutdown_topology (void)
{
  if (NULL == top)
    return;
  GNUNET_SCHEDULER_shutdown();
}





/* end of file ats-testing.c */
