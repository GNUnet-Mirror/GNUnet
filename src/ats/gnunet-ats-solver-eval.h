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
 Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 Boston, MA 02111-1307, USA.
 */
/**
 * @file ats-tests/ats-testing-experiment.c
 * @brief ats benchmark: controlled experiment execution
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#ifndef GNUNET_ATS_SOLVER_EVAL_H
#define GNUNET_ATS_SOLVER_EVAL_H

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
  struct GNUNET_ATS_SolverFunctions *sf;

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

struct LoggingFileHandle
{
  /* DLL list for logging time steps */
  struct LoggingFileHandle *next;
  struct LoggingFileHandle *prev;

  /* peer id */
  long long unsigned int pid;

  /* address id */
  long long unsigned int aid;

  struct GNUNET_DISK_FileHandle *f_hd;

};

struct LoggingTimeStep
{
  struct LoggingTimeStep *prev;
  struct LoggingTimeStep *next;

  struct LoggingPeer *head;
  struct LoggingPeer *tail;

  struct GNUNET_TIME_Absolute timestamp;
  struct GNUNET_TIME_Relative delta;
};

struct LoggingPeer
{
  struct LoggingPeer *prev;
  struct LoggingPeer *next;

  long long unsigned int id;
  struct GNUNET_PeerIdentity peer_id;
  double pref_abs[GNUNET_ATS_PREFERENCE_END];
  double pref_norm[GNUNET_ATS_PREFERENCE_END];
  int is_requested;

  struct LoggingAddress *addr_head;
  struct LoggingAddress *addr_tail;
};

struct LoggingAddress
{
  struct LoggingAddress *next;
  struct LoggingAddress *prev;

  long long unsigned int aid;
  int active;
  uint32_t network;
  uint32_t assigned_bw_in;
  uint32_t assigned_bw_out;

  double prop_abs[GNUNET_ATS_PropertyCount];
  double prop_norm[GNUNET_ATS_PropertyCount];
};


struct TestPeer
{
  struct TestPeer *prev;
  struct TestPeer *next;


  long long unsigned int id;
  int is_requested;
  struct GNUNET_PeerIdentity peer_id;

  double pref_abs[GNUNET_ATS_PreferenceCount];
  double pref_norm[GNUNET_ATS_PreferenceCount];

  uint32_t assigned_bw_in;
  uint32_t assigned_bw_out;

  struct TestAddress *addr_head;
  struct TestAddress *addr_tail;
};


struct TestAddress
{
  struct TestAddress *next;
  struct TestAddress *prev;

  long long unsigned int aid;
  struct ATS_Address *ats_addr;
  uint32_t network;

  double prop_abs[GNUNET_ATS_PropertyCount];
  double prop_norm[GNUNET_ATS_PropertyCount];
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
  long long unsigned int client_id;

  long long unsigned int address_session;
  unsigned int address_network;
  char*address;
  char*plugin;


  long long unsigned int base_rate;
  long long unsigned int max_rate;
  struct GNUNET_TIME_Relative period;
  struct GNUNET_TIME_Relative frequency;
  struct GNUNET_TIME_Relative feedback_delay;

  enum OperationType type;
  enum GeneratorType gen_type;
  enum GNUNET_ATS_PreferenceKind pref_type;
  // enum GNUNET_ATS_Property prop_type;
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
  struct GNUNET_SCHEDULER_Task * logging_task;
  struct GNUNET_TIME_Relative log_freq;

  /* DLL list for logging time steps */
  struct LoggingTimeStep *head;
  struct LoggingTimeStep *tail;
};

struct Experiment
{
  char *name;
  char *log_prefix;
  char *cfg_file;
  char *log_output_dir;
  int log_append_time_stamp;

  struct GNUNET_TIME_Relative log_freq;
  struct GNUNET_TIME_Relative max_duration;
  struct GNUNET_TIME_Relative total_duration;
  struct GNUNET_TIME_Absolute start_time;
  unsigned int num_episodes;
  struct Episode *start;

  struct GNUNET_CONFIGURATION_Handle *cfg;

  struct GNUNET_SCHEDULER_Task * experiment_timeout_task;
  struct GNUNET_SCHEDULER_Task * episode_timeout_task;
  struct Episode *cur;

  GNUNET_ATS_TESTING_EpisodeDoneCallback ep_done_cb;
  GNUNET_ATS_TESTING_ExperimentDoneCallback e_done_cb;
};

struct PreferenceGenerator
{
  struct PreferenceGenerator *prev;
  struct PreferenceGenerator *next;

  enum GeneratorType type;

  long long unsigned int peer;
  unsigned int client_id;

  enum GNUNET_ATS_PreferenceKind kind;

  long int base_value;
  long int max_value;
  struct GNUNET_TIME_Relative duration_period;
  struct GNUNET_TIME_Relative frequency;
  struct GNUNET_TIME_Relative feedback_frequency;

  struct GNUNET_SCHEDULER_Task * set_task;
  struct GNUNET_SCHEDULER_Task * feedback_task;
  struct GNUNET_TIME_Absolute next_ping_transmission;
  struct GNUNET_TIME_Absolute time_start;


  /* Feedback */
  uint32_t feedback_bw_out_acc;
  uint32_t feedback_bw_in_acc;
  uint32_t feedback_delay_acc;

  double pref_bw_old;
  double pref_latency_old;

  struct GNUNET_TIME_Absolute feedback_last;

  struct GNUNET_TIME_Absolute feedback_last_bw_update;
  struct GNUNET_TIME_Absolute feedback_last_delay_update;
  uint32_t last_assigned_bw_in;
  uint32_t last_assigned_bw_out;
  double last_delay_value;

};


struct PropertyGenerator
{
  struct PropertyGenerator *prev;
  struct PropertyGenerator *next;

  enum GeneratorType type;

  long long unsigned int peer;
  long long unsigned int address_id;

  struct TestPeer *test_peer;
  struct TestAddress *test_address;
  uint32_t ats_property;

  long int base_value;
  long int max_value;
  struct GNUNET_TIME_Relative duration_period;
  struct GNUNET_TIME_Relative frequency;

  struct GNUNET_SCHEDULER_Task * set_task;
  struct GNUNET_TIME_Absolute next_ping_transmission;
  struct GNUNET_TIME_Absolute time_start;
};

#endif /* #ifndef GNUNET_ATS_SOLVER_EVAL_H */
/* end of file ats-testing.h */
