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
 * @file ats-tests/ats-testing.h
 * @brief ats testing library: setup topology and provide logging to test ats
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_ats_service.h"
#include "gnunet_core_service.h"

#define TEST_ATS_PREFERENCE_DEFAULT 1.0

/**
 * Message type sent for traffic generation
 */
#define TEST_MESSAGE_TYPE_PING 12345

/**
 * Message type sent as response during traffic generation
 */
#define TEST_MESSAGE_TYPE_PONG 12346

/**
 * Size of test messages
 */
#define TEST_MESSAGE_SIZE 100

struct BenchmarkPartner;

struct BenchmarkPeer;

struct GNUNET_ATS_TEST_Topology;

struct TrafficGenerator;

struct LoggingHandle;

enum TrafficGeneratorType
{
  GNUNET_ATS_TEST_TG_LINEAR,
  GNUNET_ATS_TEST_TG_CONSTANT,
  GNUNET_ATS_TEST_TG_RANDOM,
  GNUNET_ATS_TEST_TG_SINUS
};


/**
 * Callback to call when topology setup is completed
 *
 * @param cls the closure
 * @param masters array of master peers
 * @param slaves array of master peers
 */
typedef void (*GNUNET_ATS_TEST_TopologySetupDoneCallback) (void *cls,
    struct BenchmarkPeer *masters,
    struct BenchmarkPeer *slaves);

/**
 * Callback called when logging is required for the data contained
 *
 * @param cls the closure
 * @param address an address
 * @param address_active is address active
 * @param bandwidth_out bandwidth outbound
 * @param bandwidth_in bandwidth inbound
 * @param ats ats information
 * @param ats_count number of ats inforation
 */
typedef void
(*GNUNET_ATS_TEST_LogRequest) (void *cls,
    const struct GNUNET_HELLO_Address *address,
    int address_active,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
    const struct GNUNET_ATS_Information *ats,
    uint32_t ats_count);

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

struct TrafficGenerator
{
  struct TrafficGenerator *prev;
  struct TrafficGenerator *next;

  enum TrafficGeneratorType type;

  struct BenchmarkPeer *src;
  struct BenchmarkPartner *dest;

  long int base_rate;
  long int max_rate;
  struct GNUNET_TIME_Relative duration_period;

  GNUNET_SCHEDULER_TaskIdentifier send_task;
  struct GNUNET_TIME_Absolute next_ping_transmission;
  struct GNUNET_TIME_Absolute time_start;
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

  struct TrafficGenerator *tg;

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

  GNUNET_ATS_TEST_TopologySetupDoneCallback done_cb;
  GNUNET_ATS_AddressInformationCallback ats_perf_cb;
  void *done_cb_cls;
};

enum OperationType
{
  START_SEND,
  STOP_SEND,
  SET_RATE,
  SET_PREFERENCE
};

struct Episode;

struct Experiment;

typedef void (*GNUNET_ATS_TESTING_EpisodeDoneCallback) (
    struct Episode *e);

typedef void (*GNUNET_ATS_TESTING_ExperimentDoneCallback) (struct Experiment *e,
    struct GNUNET_TIME_Relative duration,int success);

struct Operation
{
  struct Operation *next;
  struct Operation *prev;
  long long unsigned int src_id;
  long long unsigned int dest_id;
  long long unsigned int value;
  enum OperationType type;
};

struct Episode
{
  int id;
  struct Episode *next;
  struct GNUNET_TIME_Relative duration;

  struct Operation *head;
  struct Operation *tail;
};


struct Experiment
{
  char *name;
  char *cfg_file;
  unsigned long long int num_masters;
  unsigned long long int num_slaves;
  struct GNUNET_TIME_Relative max_duration;
  struct GNUNET_TIME_Relative total_duration;
  struct GNUNET_TIME_Absolute start_time;
  unsigned int num_episodes;
  struct Episode *start;

  GNUNET_SCHEDULER_TaskIdentifier experiment_timeout_task;
  GNUNET_SCHEDULER_TaskIdentifier episode_timeout_task;
  struct Episode *cur;

  GNUNET_ATS_TESTING_EpisodeDoneCallback ep_done_cb;
  GNUNET_ATS_TESTING_ExperimentDoneCallback e_done_cb;
};

/*
 * Experiment related functions
 */


/**
 * Execute the specified experiment
 *
 * @param e the Experiment
 * @param ep_done_cb a episode is completed
 * @param e_done_cb the experiment is completed
 */
void
GNUNET_ATS_TEST_experimentation_run (struct Experiment *e,
    GNUNET_ATS_TESTING_EpisodeDoneCallback ep_done_cb,
    GNUNET_ATS_TESTING_ExperimentDoneCallback e_done_cb);

/**
 * Load an experiment from a file
 *
 * @param filename the file
 * @return the Experiment or NULL on failure
 */
struct Experiment *
GNUNET_ATS_TEST_experimentation_load (char *filename);


/**
 * Stop an experiment
 *
 * @param e the experiment
 */
void
GNUNET_ATS_TEST_experimentation_stop (struct Experiment *e);

/*
 * Traffic related functions
 */

void
GNUNET_ATS_TEST_traffic_handle_ping (struct BenchmarkPartner *p);

void
GNUNET_ATS_TEST_traffic_handle_pong (struct BenchmarkPartner *p);


struct TrafficGenerator *
GNUNET_ATS_TEST_generate_traffic_start (struct BenchmarkPeer *src,
    struct BenchmarkPartner *dest,
    enum TrafficGeneratorType type,
    long int base_rate,
    long int max_rate,
    struct GNUNET_TIME_Relative period,
    struct GNUNET_TIME_Relative duration);

void
GNUNET_ATS_TEST_generate_traffic_stop (struct TrafficGenerator *tg);

/**
 * Stop all traffic generators
 */
void
GNUNET_ATS_TEST_generate_traffic_stop_all ();


/*
 * Logging related functions
 */

/**
 * Start logging
 *
 * @param log_frequency the logging frequency
 * @param testname the testname
 * @param masters the master peers used for benchmarking
 * @param num_master the number of master peers
 * @return the logging handle or NULL on error
 */
struct LoggingHandle *
GNUNET_ATS_TEST_logging_start (struct GNUNET_TIME_Relative log_frequency,
    char * testname,
    struct BenchmarkPeer *masters,
    int num_masters);

/**
 * Stop logging
 *
 * @param l the logging handle
 */
void
GNUNET_ATS_TEST_logging_clean_up (struct LoggingHandle *l);

/**
 * Stop logging
 *
 * @param l the logging handle
 */
void
GNUNET_ATS_TEST_logging_stop (struct LoggingHandle *l);

/**
 * Log all data now
 *
 * @param llogging handle to use
 */
void
GNUNET_ATS_TEST_logging_now (struct LoggingHandle *l);


/**
 * Write logging data to file
 *
 * @param l logging handle to use
 * @param test_name name of the current test
 * @param plots create gnuplots: GNUNET_YES or GNUNET_NO
 */
void
GNUNET_ATS_TEST_logging_write_to_file (struct LoggingHandle *l,
    char *test_name, int plots);

/*
 * Topology related functions
 */

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
 * @param recv_cb callback to call when data are received
 * @param perf_cb callback to call when performance info are received
 */
void
GNUNET_ATS_TEST_create_topology (char *name, char *cfg_file,
    unsigned int num_slaves,
    unsigned int num_masters,
    int test_core,
    GNUNET_ATS_TEST_TopologySetupDoneCallback done_cb,
    void *done_cb_cls,
    GNUNET_TRANSPORT_ReceiveCallback recv_cb,
    GNUNET_ATS_TEST_LogRequest ats_perf_cb);

/**
 * Shutdown topology
 */
void
GNUNET_ATS_TEST_shutdown_topology (void);

/* end of file ats-testing.h */
