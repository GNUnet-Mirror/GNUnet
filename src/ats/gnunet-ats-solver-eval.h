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
 * @file ats-tests/ats-testing-experiment.c
 * @brief ats benchmark: controlled experiment execution
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_plugin.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_normalization.h"
#include "test_ats_api_common.h"

enum GeneratorType
{
  GNUNET_ATS_TEST_TG_LINEAR,
  GNUNET_ATS_TEST_TG_CONSTANT,
  GNUNET_ATS_TEST_TG_RANDOM,
  GNUNET_ATS_TEST_TG_SINUS
};


enum OperationType
{
  SOLVER_OP_ADD_ADDRESS,
  SOLVER_OP_DEL_ADDRESS,
  SOLVER_OP_START_SET_PROPERTY,
  SOLVER_OP_STOP_SET_PROPERTY,
  SOLVER_OP_START_SET_PREFERENCE,
  SOLVER_OP_STOP_SET_PREFERENCE,
  SOLVER_OP_START_REQUEST,
  SOLVER_OP_STOP_REQUEST,
};

struct SolverHandle
{
  /**
   * Solver plugin name
   */
  char *plugin;

  /**
   * Solver environment
   */
  struct GNUNET_ATS_PluginEnvironment env;

  /**
   * Solver handle
   */
  void *solver;

  /**
   * Address hashmap
   */
  struct GNUNET_CONTAINER_MultiPeerMap *addresses;
};

enum GNUNET_ATS_Solvers
{
  GNUNET_ATS_SOLVER_PROPORTIONAL,
  GNUNET_ATS_SOLVER_MLP,
  GNUNET_ATS_SOLVER_RIL,
};


struct TestPeer
{
  struct TestPeer *prev;
  struct TestPeer *next;

  int id;
  struct GNUNET_PeerIdentity peer_id;
};


struct Episode;

struct Experiment;

typedef void (*GNUNET_ATS_TESTING_EpisodeDoneCallback) (
    struct Episode *e);

typedef void (*GNUNET_ATS_TESTING_ExperimentDoneCallback) (struct Experiment *e,
    struct GNUNET_TIME_Relative duration,int success);

/**
 * An operation in an experiment
 */
struct GNUNET_ATS_TEST_Operation
{
  struct GNUNET_ATS_TEST_Operation *next;
  struct GNUNET_ATS_TEST_Operation *prev;

  long long unsigned int address_id;
  long long unsigned int peer_id;
  long long unsigned int address_session;
  long long unsigned int address_network;
  char*address;
  char*plugin;


  long long unsigned int base_rate;
  long long unsigned int max_rate;
  struct GNUNET_TIME_Relative period;
  struct GNUNET_TIME_Relative frequency;

  enum OperationType type;
  enum GeneratorType gen_type;
  enum GNUNET_ATS_PreferenceKind pref_type;
  enum GNUNET_ATS_Property prop_type;
};

struct Episode
{
  int id;
  struct Episode *next;
  struct GNUNET_TIME_Relative duration;

  struct GNUNET_ATS_TEST_Operation *head;
  struct GNUNET_ATS_TEST_Operation *tail;
};

struct LoggingHandle
{
  GNUNET_SCHEDULER_TaskIdentifier logging_task;
  struct GNUNET_TIME_Relative log_freq;
};

struct Experiment
{
  char *name;
  char *cfg_file;
  unsigned long long int num_masters;
  unsigned long long int num_slaves;
  struct GNUNET_TIME_Relative log_freq;
  struct GNUNET_TIME_Relative max_duration;
  struct GNUNET_TIME_Relative total_duration;
  struct GNUNET_TIME_Absolute start_time;
  unsigned int num_episodes;
  struct Episode *start;

  struct GNUNET_CONFIGURATION_Handle *cfg;

  GNUNET_SCHEDULER_TaskIdentifier experiment_timeout_task;
  GNUNET_SCHEDULER_TaskIdentifier episode_timeout_task;
  struct Episode *cur;

  GNUNET_ATS_TESTING_EpisodeDoneCallback ep_done_cb;
  GNUNET_ATS_TESTING_ExperimentDoneCallback e_done_cb;
};

struct PreferenceGenerator
{
  struct PreferenceGenerator *prev;
  struct PreferenceGenerator *next;

  enum GeneratorType type;

  unsigned int peer;
  unsigned int address_id;

  enum GNUNET_ATS_PreferenceKind kind;

  long int base_value;
  long int max_value;
  struct GNUNET_TIME_Relative duration_period;
  struct GNUNET_TIME_Relative frequency;

  GNUNET_SCHEDULER_TaskIdentifier set_task;
  struct GNUNET_TIME_Absolute next_ping_transmission;
  struct GNUNET_TIME_Absolute time_start;
};


struct PropertyGenerator
{
  struct PropertyGenerator *prev;
  struct PropertyGenerator *next;

  enum GeneratorType type;

  unsigned int peer;
  unsigned int address_id;

  struct ATS_Address *address;
  uint32_t ats_property;

  long int base_value;
  long int max_value;
  struct GNUNET_TIME_Relative duration_period;
  struct GNUNET_TIME_Relative frequency;

  GNUNET_SCHEDULER_TaskIdentifier set_task;
  struct GNUNET_TIME_Absolute next_ping_transmission;
  struct GNUNET_TIME_Absolute time_start;
};


/* LEGACY */

#if 0
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
    const struct GNUNET_HELLO_Address *address_id,
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

  enum GeneratorType type;

  struct BenchmarkPeer *src;
  struct BenchmarkPartner *dest;

  long int base_rate;
  long int max_rate;
  struct GNUNET_TIME_Relative duration_period;

  GNUNET_SCHEDULER_TaskIdentifier send_task;
  struct GNUNET_TIME_Absolute next_ping_transmission;
  struct GNUNET_TIME_Absolute time_start;
};


struct PreferenceGenerator
{
  struct PreferenceGenerator *prev;
  struct PreferenceGenerator *next;

  enum GeneratorType type;

  struct BenchmarkPeer *src;
  struct BenchmarkPartner *dest;

  enum GNUNET_ATS_PreferenceKind kind;

  long int base_value;
  long int max_value;
  struct GNUNET_TIME_Relative duration_period;
  struct GNUNET_TIME_Relative frequency;

  GNUNET_SCHEDULER_TaskIdentifier set_task;
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
  struct PreferenceGenerator *pg;

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

  double pref_bandwidth;
  double pref_delay;
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


/**
 * Generate between the source master and the partner and send traffic with a
 * maximum rate.
 *
 * @param src traffic source
 * @param dest traffic partner
 * @param type type of traffic to generate
 * @param base_rate traffic base rate to send data with
 * @param max_rate  traffic maximum rate to send data with
 * @param period duration of a period of traffic generation (~ 1/frequency)
 * @param duration how long to generate traffic
 * @return the traffic generator
 */
struct TrafficGenerator *
GNUNET_ATS_TEST_generate_traffic_start (struct BenchmarkPeer *src,
    struct BenchmarkPartner *dest,
    enum GeneratorType type,
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

struct PreferenceGenerator *
GNUNET_ATS_TEST_generate_preferences_start (struct BenchmarkPeer *src,
    struct BenchmarkPartner *dest,
    enum GeneratorType type,
    long int base_value,
    long int value_rate,
    struct GNUNET_TIME_Relative period,
    struct GNUNET_TIME_Relative frequency,
    enum GNUNET_ATS_PreferenceKind kind);

void
GNUNET_ATS_TEST_generate_preferences_stop (struct PreferenceGenerator *pg);

void
GNUNET_ATS_TEST_generate_preferences_stop_all ();

/*
 * Logging related functions
 */



/*
 * Topology related functions
 */

struct BenchmarkPeer *
GNUNET_ATS_TEST_get_peer (int src);

struct BenchmarkPartner *
GNUNET_ATS_TEST_get_partner (int src, int dest);

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
#endif
/* end of file ats-testing.h */
