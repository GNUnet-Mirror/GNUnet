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

#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)
#define BENCHMARK_DURATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
#define LOGGING_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 500)
#define TESTNAME_PREFIX "perf_ats_"
#define DEFAULT_SLAVES_NUM 2
#define DEFAULT_MASTERS_NUM 1

#define TEST_ATS_PREFRENCE_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)
#define TEST_ATS_PREFRENCE_START 1.0
#define TEST_ATS_PREFRENCE_DELTA 1.0

#define TEST_MESSAGE_TYPE_PING 12345
#define TEST_MESSAGE_TYPE_PONG 12346
#define TEST_MESSAGE_SIZE 1000
#define TEST_MESSAGE_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)


/**
 * Overall state of the performance benchmark
 */
struct BenchmarkState
{
  /**
   * Are we connected to ATS service of all peers: GNUNET_YES/NO
   */
  int connected_ATS_service;

  /**
   * Are we connected to CORE service of all peers: GNUNET_YES/NO
   */
  int connected_COMM_service;

  /**
   * Are we connected to all peers: GNUNET_YES/NO
   */
  int connected_PEERS;

  /**
   * Are we connected to all slave peers on CORE level: GNUNET_YES/NO
   */
  int connected_CORE;

  /**
   * Are we connected to CORE service of all peers: GNUNET_YES/NO
   */
  int benchmarking;
};


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
  struct GNUNET_CORE_TransmitHandle *cth;

  /**
   * Transport transmit handles
   */
  struct GNUNET_TRANSPORT_TransmitHandle *tth;

  /**
   * Timestamp to calculate communication layer delay
   */
  struct GNUNET_TIME_Absolute last_message_sent;

  /**
   * Accumulated RTT for all messages
   */
  unsigned int total_app_rtt;

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

  /* Current ATS properties */

  uint32_t ats_distance;

  uint32_t ats_delay;

  uint32_t bandwidth_in;

  uint32_t bandwidth_out;

  uint32_t ats_utilization_up;

  uint32_t ats_utilization_down;

  uint32_t ats_network_type;

  uint32_t ats_cost_wan;

  uint32_t ats_cost_lan;

  uint32_t ats_cost_wlan;
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
  struct GNUNET_TESTBED_Operation *comm_op;

  /**
   * ATS performance handle
   */
  struct GNUNET_ATS_PerformanceHandle *ats_perf_handle;

  /**
   * Masters only:
   * Testbed connect operations to connect masters to slaves
   */
  struct TestbedConnectOperation *core_connect_ops;

  /**
   *  Core handle
   */
  struct GNUNET_CORE_Handle *ch;

  /**
   *  Core handle
   */
  struct GNUNET_TRANSPORT_Handle *th;

  /**
   * Masters only:
   * Peer to set ATS preferences for
   */
  struct BenchmarkPeer *pref_partner;

  /**
   * Masters only
   * Progress task
   */
  GNUNET_SCHEDULER_TaskIdentifier ats_task;

  /**
   * Masters only
   * Progress task
   */
  double pref_value;

  /**
   * Array of partners with num_slaves entries (if master) or
   * num_master entries (if slave)
   */
  struct BenchmarkPartner *partners;

  /**
   * Number of partners
   */
  int num_partners;

  /**
   * Number of core connections
   */
  int core_connections;

  /**
   * Masters only:
   * Number of connections to slave peers
   */
  int core_slave_connections;

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


struct GNUNET_ATS_TEST_Topology
{
  /**
   * Shutdown task
   */
  GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

  /**
   * Progress task
   */
  GNUNET_SCHEDULER_TaskIdentifier progress_task;

  /**
   * Test result
   */
  int result;

  /**
   * Test result logging
   */
  int logging;

  /**Test core (GNUNET_YES) or transport (GNUNET_NO)
   */
  int test_core;

  /**
   * Solver string
   */
  char *solver;

  /**
   * Preference string
   */
  char *testname;

  /**
   * Preference string
   */
  char *pref_str;

  /**
   * ATS preference value
   */
  int pref_val;

  /**
   * Number master peers
   */
  unsigned int num_masters;

  /**
   * Array of master peers
   */
  struct BenchmarkPeer *mps;

  /**
   * Number slave peers
   */
  unsigned int num_slaves;

  /**
   * Array of slave peers
   */
  struct BenchmarkPeer *sps;

  /**
   * Benchmark duration
   */
  struct GNUNET_TIME_Relative perf_duration;

  /**
   * Logging frequency
   */
  struct GNUNET_TIME_Relative log_frequency;

  /**
   * Benchmark state
   */
  struct BenchmarkState state;

  struct GNUNET_CORE_MessageHandler *handlers;

  GNUNET_TRANSPORT_ReceiveCallback transport_recv_cb;

};


struct GNUNET_ATS_TEST_Topology *
GNUNET_ATS_TEST_create_topology (char *name, char *cfg_file,
    unsigned int num_slaves,
    unsigned int num_masters,
    struct GNUNET_CORE_MessageHandler *handlers,
    GNUNET_TRANSPORT_ReceiveCallback transport_recv_cb);

void
GNUNET_ATS_TEST_destroy_topology (struct GNUNET_ATS_TEST_Topology *top);

/* end of file perf_ats.c */
