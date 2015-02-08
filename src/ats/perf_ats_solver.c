/*
 This file is part of GNUnet.
 Copyright (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/perf_ats_solver.c
 * @brief generic performance test for ATS solvers
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_plugins.h"
#include "gnunet-service-ats_normalization.h"
#include "gnunet-service-ats_preferences.h"
#include "gnunet_ats_service.h"
#include "gnunet_ats_plugin.h"
#include "test_ats_api_common.h"

#define DEFAULT_UPDATE_PERCENTAGE       20
#define DEFAULT_PEERS_START     10
#define DEFAULT_PEERS_END       10
#define DEFAULT_ADDRESSES       10
#define DEFAULT_ATS_COUNT       2


/**
 * Handle for statistics.
 */
struct GNUNET_STATISTICS_Handle *GSA_stats;

/**
 * Handle for ATS address component
 */
struct PerfHandle
{
  /**
   * Performance peers
   */
  struct PerfPeer *peers;

  /**
   *  Solver handle
   */
  struct GNUNET_ATS_SolverFunctions *sf;

  /**
   * Statistics stat;
   */
  struct GNUNET_STATISTICS_Handle *stat;

  /**
   * A multihashmap to store all addresses
   */
  struct GNUNET_CONTAINER_MultiPeerMap *addresses;

  /**
   * Solver functions
   * */
  struct GNUNET_ATS_PluginEnvironment env;

  /**
   * Array for results for each iteration with length iterations
   */
  struct Iteration *iterations_results;

  /**
   * The current result
   */
  struct Result *current_result;

  /**
   * Current number of peers benchmarked
   */
  int current_p;

  /**
   * Current number of addresses benchmarked
   */
  int current_a;

  /**
   * Solver description as string
   */
  char *ats_string;

  /**
   * Configured ATS solver
   */
  int ats_mode;

  /**
   * #peers to start benchmarking with
   */
  int N_peers_start;

  /**
   * #peers to end benchmarking with
   */
  int N_peers_end;

  /**
   * #addresses to benchmarking with
   */
  int N_address;

  /**
   * Percentage of peers to update
   */
  int opt_update_percent;

  /**
   * Create gnuplot file
   */
  int create_datafile;

  /**
   * Measure updates
   */
  int measure_updates;

  /**
   * Number of iterations
   */
  int total_iterations;

  /**
   * Current iteration
   */
  int current_iteration;

  /**
   * Is a bulk operation running?
   */
  int bulk_running;

  /**
   * Is a bulk operation running?
   */
  int expecting_solution;

  /**
   * Was the problem just updates?
   */
  int performed_update;
};

/**
 * Data structure to store results for a single iteration
 */
struct Iteration
{
  struct Result **results_array;

  struct Result **update_results_array;
};


/**
 * Result for a solver calculcation
 */
struct Result
{
  /**
   * Previous element in the linked list
   */
  struct Result *prev;

  /**
   * Next element in the linked list
   */
  struct Result *next;

  /**
   * Number of peers this solution included
   */
  int peers;

  /**
   * Number of addresses per peer this solution included
   */
  int addresses;

  /**
   * Is this an update or a full solution
   */
  int update;

  /**
   * Was the solution valid or did the solver fail
   */
  int valid;

  /**
   * Result of the solver
   */
  enum GAS_Solver_Additional_Information info;

  /**
   * Duration of setting up the problem in the solver
   */
  struct GNUNET_TIME_Relative d_setup_full;

  /**
   * Duration of solving the LP problem in the solver
   * MLP solver only
   */
  struct GNUNET_TIME_Relative d_lp_full;

  /**
   * Duration of solving the MLP problem in the solver
   * MLP solver only
   */
  struct GNUNET_TIME_Relative d_mlp_full;

  /**
   * Duration of solving whole problem in the solver
   */
  struct GNUNET_TIME_Relative d_total_full;

  /**
   * Start time of setting up the problem in the solver
   */
  struct GNUNET_TIME_Absolute s_setup;

  /**
   * Start time of solving the LP problem in the solver
   * MLP solver only
   */
  struct GNUNET_TIME_Absolute s_lp;

  /**
   * Start time of solving the MLP problem in the solver
   * MLP solver only
   */
  struct GNUNET_TIME_Absolute s_mlp;

  /**
   * Start time of solving whole problem in the solver
   */
  struct GNUNET_TIME_Absolute s_total;

  /**
   * End time of setting up the problem in the solver
   */
  struct GNUNET_TIME_Absolute e_setup;

  /**
   * End time of solving the LP problem in the solver
   * MLP solver only
   */
  struct GNUNET_TIME_Absolute e_lp;

  /**
   * End time of solving the MLP problem in the solver
   * MLP solver only
   */
  struct GNUNET_TIME_Absolute e_mlp;

  /**
   * End time of solving whole problem in the solver
   */
  struct GNUNET_TIME_Absolute e_total;
};

/**
 * Peer used for the benchmarking
 */
struct PerfPeer
{
  /**
   * Peer identitity
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Head of linked list of addresses used with this peer
   */
  struct ATS_Address *head;

  /**
   * Head of linked list of addresses used with this peer
   */
  struct ATS_Address *tail;
};


/**
 * ATS performance handle
 */
static struct PerfHandle ph;

/**
 * Return value
 */
static int ret;


/**
 * Do shutdown
 */
static void
end_now (int res)
{
  if (NULL != ph.stat)
  {
    GNUNET_STATISTICS_destroy (ph.stat, GNUNET_NO);
    ph.stat = NULL;
  }

  GNUNET_free_non_null (ph.peers);
  GNUNET_free_non_null (ph.iterations_results);

  GAS_normalization_stop ();
  GAS_preference_done ();
  ret = res;
}


/**
 * Create a peer used for benchmarking
 *
 * @param cp the number of the peer
 */
static void
perf_create_peer (int cp)
{

  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
      &ph.peers[cp].id, sizeof (struct GNUNET_PeerIdentity));
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Creating peer #%u: %s \n", cp,
      GNUNET_i2s (&ph.peers[cp].id));
}


/**
 * Perform an update for an address
 *
 * @param cur the address to update
 */
static void
perf_update_address (struct ATS_Address *cur)
{
  int r_type;
  int abs_val;
  double rel_val;

  r_type = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 2);
  switch (r_type)
  {
  case 0:
    abs_val = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 100);
    rel_val = (100 + (double) abs_val) / 100;

    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
        "Updating peer `%s' address %p type %s abs val %u rel val %.3f\n",
        GNUNET_i2s (&cur->peer), cur,
        "GNUNET_ATS_QUALITY_NET_DELAY",
        abs_val, rel_val);
    ph.sf->s_address_update_property (ph.sf->cls, cur,
        GNUNET_ATS_QUALITY_NET_DELAY,
        abs_val, rel_val);
    break;
  case 1:
    abs_val = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 10);
    rel_val = (100 + (double) abs_val) / 100;

    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
        "Updating peer `%s' address %p type %s abs val %u rel val %.3f\n",
        GNUNET_i2s (&cur->peer), cur, "GNUNET_ATS_QUALITY_NET_DISTANCE",
        abs_val, rel_val);
    ph.sf->s_address_update_property (ph.sf->cls, cur,
        GNUNET_ATS_QUALITY_NET_DISTANCE,
        abs_val, rel_val);
    break;
  default:
    break;
  }
}


static void
bandwidth_changed_cb (void *cls,
                      struct ATS_Address *address)
{
  if ( (0 == address->assigned_bw_out) && (0 == address->assigned_bw_in) )
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Bandwidth changed addresses %s %p to %u Bps out / %u Bps in\n",
              GNUNET_i2s (&address->peer),
              address,
              address->assigned_bw_out,
              address->assigned_bw_in);
  if (GNUNET_YES == ph.bulk_running)
    GNUNET_break (0);
  return;
}


static const double *
get_preferences_cb (void *cls, const struct GNUNET_PeerIdentity *id)
{
  return GAS_preference_get_by_peer (NULL, id);
}


static void
perf_address_initial_update (void *dead,
    struct GNUNET_CONTAINER_MultiPeerMap * addresses,
    struct ATS_Address *address)
{
  double delay;
  double distance;
  uint32_t random = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 100);
  delay = (100 + (double) random) / 100;
  ph.sf->s_address_update_property (ph.sf->cls,
                                    address, GNUNET_ATS_QUALITY_NET_DELAY,
      100,  delay);

  random = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 100);
  distance = (100 + (double) random) / 100;

  ph.sf->s_address_update_property (ph.sf->cls, address,
                                    GNUNET_ATS_QUALITY_NET_DISTANCE,
                                    10, distance);

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
             "Initial update address %p : %.2f  %.2f\n",
             address, delay, distance);
}


struct DUA_Ctx
{
  int r;
  int c_cur_a;
};


static int
do_update_address (void *cls,
                   const struct GNUNET_PeerIdentity *pid,
                   void *value)
{
  struct DUA_Ctx *ctx = cls;
  struct ATS_Address *addr = value;

  if (ctx->c_cur_a == ctx->r)
    perf_update_address (addr);
  ctx->c_cur_a++;
  return GNUNET_OK;
}


/**
 * Update a certain percentage of peers
 *
 * @param cp the current number of peers
 * @param ca the current number of addresses
 * @param percentage_peers the percentage of peers to update
 */
static void
perf_update_all_addresses (unsigned int cp, unsigned int ca, unsigned int percentage_peers)
{
  int c_peer;
  int c_select;
  int c_cur_p;
  int r;
  int count;
  unsigned int m[cp];
  struct DUA_Ctx dua_ctx;

  count = cp * ((double) percentage_peers / 100);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Updating %u of %u peers \n", count, cp);

  for (c_peer = 0; c_peer < cp; c_peer++)
    m[c_peer] = 0;

  c_select = 0;

  while (c_select < count)
  {
    r = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, cp);
    if (0 == m[r])
    {
      m[r] = 1;
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Updating peer [%u] \n", r);
      c_select++;
    }
  }
  for (c_cur_p = 0; c_cur_p < cp; c_cur_p++)
  {
    if (1 == m[c_cur_p])
    {
      r = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, ca);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Updating peer [%u] address [%u]\n", c_cur_p, r);

      dua_ctx.c_cur_a = 0;
      dua_ctx.r = r;
      GNUNET_CONTAINER_multipeermap_get_multiple (ph.addresses,
                                                  &ph.peers[c_cur_p].id,
                                                  &do_update_address,
                                                  &dua_ctx);
    }
  }
}

/**
 * Create an address for a peer
 *
 * @param cp index of the peer
 * @param ca index of the address
 * @return the address
 */
static struct ATS_Address *
perf_create_address (int cp, int ca)
{
  struct ATS_Address *a;

  a = create_address (&ph.peers[cp].id,
      "Test 1", "test 1", strlen ("test 1") + 1, 0);
  GNUNET_CONTAINER_multipeermap_put (ph.addresses, &ph.peers[cp].id, a,
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  return a;
}


/**
 * Information callback for the solver
 *
 * @param op the solver operation
 * @param stat status of the solver operation
 * @param add additional solver information
 */
static void
solver_info_cb (void *cls,
    enum GAS_Solver_Operation op,
    enum GAS_Solver_Status stat,
    enum GAS_Solver_Additional_Information add)
{
  char *add_info;
  switch (add) {
    case GAS_INFO_NONE:
      add_info = "GAS_INFO_NONE";
      break;
    case GAS_INFO_FULL:
      add_info = "GAS_INFO_MLP_FULL";
      break;
    case GAS_INFO_UPDATED:
      add_info = "GAS_INFO_MLP_UPDATED";
      break;
    case GAS_INFO_PROP_ALL:
      add_info = "GAS_INFO_PROP_ALL";
      break;
    case GAS_INFO_PROP_SINGLE:
      add_info = "GAS_INFO_PROP_SINGLE";
      break;
    default:
      add_info = "INVALID";
      break;
  }

  struct Result *tmp;
  switch (op)
  {
    case GAS_OP_SOLVE_START:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s' `%s'\n", "GAS_OP_SOLVE_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL", add_info);
      if (GNUNET_NO == ph.expecting_solution)
      {
        /* We do not expect a solution at the moment */
        GNUNET_break (0);
        return;
      }

      if ((GAS_STAT_SUCCESS == stat) && (NULL == ph.current_result))
      {
        tmp = GNUNET_new (struct Result);
        /* Create new result */
        if ((add == GAS_INFO_UPDATED) || (GNUNET_YES == ph.performed_update))
        {
          ph.current_result = tmp;
          //fprintf (stderr,"UPDATE %u %u\n",ph.current_iteration-1, ph.current_p);
          ph.iterations_results[ph.current_iteration-1].update_results_array[ph.current_p] = tmp;
        }
        else
        {
          ph.current_result = tmp;
          //fprintf (stderr,"FULL %u %u\n",ph.current_iteration-1, ph.current_p);
          ph.iterations_results[ph.current_iteration-1].results_array[ph.current_p] = tmp;
        }

        ph.current_result->addresses = ph.current_a;
        ph.current_result->peers = ph.current_p;
        ph.current_result->s_total = GNUNET_TIME_absolute_get();
        ph.current_result->d_total_full = GNUNET_TIME_UNIT_FOREVER_REL;
        ph.current_result->d_setup_full = GNUNET_TIME_UNIT_FOREVER_REL;
        ph.current_result->d_lp_full = GNUNET_TIME_UNIT_FOREVER_REL;
        ph.current_result->d_mlp_full = GNUNET_TIME_UNIT_FOREVER_REL;
        ph.current_result->info = add;
        if ((add == GAS_INFO_UPDATED) || (GNUNET_YES == ph.performed_update))
        {
          ph.current_result->update = GNUNET_YES;
        }
        else
        {
          ph.current_result->update = GNUNET_NO;
        }

      }
      return;
    case GAS_OP_SOLVE_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s', `%s'\n", "GAS_OP_SOLVE_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL", add_info);
      if ((GNUNET_NO == ph.expecting_solution) || (NULL == ph.current_result))
      {
        /* We do not expect a solution at the moment */
        GNUNET_break (0);
        return;
      }

      if (GAS_STAT_SUCCESS == stat)
        ph.current_result->valid = GNUNET_YES;
      else
        ph.current_result->valid = GNUNET_NO;

      if (NULL != ph.current_result)
      {
        /* Finalize result */
        ph.current_result->e_total = GNUNET_TIME_absolute_get ();
        ph.current_result->d_total_full = GNUNET_TIME_absolute_get_difference (
            ph.current_result->s_total, ph.current_result->e_total);
      }
      ph.current_result = NULL;
      return;

    case GAS_OP_SOLVE_SETUP_START:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_SETUP_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      if ((GNUNET_NO == ph.expecting_solution) || (NULL == ph.current_result))
      {
        GNUNET_break(0);
        return;
      }

      if (GAS_STAT_SUCCESS == stat)
        ph.current_result->valid = GNUNET_YES;
      else
        ph.current_result->valid = GNUNET_NO;

      ph.current_result->s_setup = GNUNET_TIME_absolute_get ();
      return;

    case GAS_OP_SOLVE_SETUP_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_SETUP_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      if ((GNUNET_NO == ph.expecting_solution) || (NULL == ph.current_result))
      {
        GNUNET_break(0);
        return;
      }

      if (GAS_STAT_SUCCESS == stat)
        ph.current_result->valid = GNUNET_YES;
      else
        ph.current_result->valid = GNUNET_NO;

      ph.current_result->e_setup = GNUNET_TIME_absolute_get ();
      ph.current_result->d_setup_full = GNUNET_TIME_absolute_get_difference (
          ph.current_result->s_setup, ph.current_result->e_setup);
      return;

    case GAS_OP_SOLVE_MLP_LP_START:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_LP_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      if ((GNUNET_NO == ph.expecting_solution) || (NULL == ph.current_result))
      {
        GNUNET_break(0);
        return;
      }

      if (GAS_STAT_SUCCESS == stat)
        ph.current_result->valid = GNUNET_YES;
      else
        ph.current_result->valid = GNUNET_NO;

      ph.current_result->s_lp = GNUNET_TIME_absolute_get ();
      return;
    case GAS_OP_SOLVE_MLP_LP_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_LP_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      if ((GNUNET_NO == ph.expecting_solution) || (NULL == ph.current_result))
      {
        GNUNET_break(0);
        return;
      }

      if (GAS_STAT_SUCCESS == stat)
        ph.current_result->valid = GNUNET_YES;
      else
        ph.current_result->valid = GNUNET_NO;

      ph.current_result->e_lp = GNUNET_TIME_absolute_get ();
      ph.current_result->d_lp_full = GNUNET_TIME_absolute_get_difference (
          ph.current_result->s_lp, ph.current_result->e_lp);
      return;

    case GAS_OP_SOLVE_MLP_MLP_START:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_MLP_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      if ((GNUNET_NO == ph.expecting_solution) || (NULL == ph.current_result))
      {
        GNUNET_break(0);
        return;
      }

      if (GAS_STAT_SUCCESS == stat)
        ph.current_result->valid = GNUNET_YES;
      else
        ph.current_result->valid = GNUNET_NO;

      ph.current_result->s_mlp = GNUNET_TIME_absolute_get ();
      return;
    case GAS_OP_SOLVE_MLP_MLP_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_MLP_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      if ((GNUNET_NO == ph.expecting_solution) || (NULL == ph.current_result))
      {
        GNUNET_break(0);
        return;
      }

      if (GAS_STAT_SUCCESS == stat)
        ph.current_result->valid = GNUNET_YES;
      else
        ph.current_result->valid = GNUNET_NO;

      ph.current_result->e_mlp = GNUNET_TIME_absolute_get ();
      ph.current_result->d_mlp_full = GNUNET_TIME_absolute_get_difference (
      ph.current_result->s_mlp, ph.current_result->e_mlp);
      return;
    case GAS_OP_SOLVE_UPDATE_NOTIFICATION_START:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_UPDATE_NOTIFICATION_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;
    case GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      if (GAS_STAT_SUCCESS != stat)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
            "Solver `%s' failed to update problem with %u peers and %u address!\n",
            ph.ats_string, ph.current_p, ph.current_a);
      }

      return;
    default:
      break;
    }
}

/**
 * Evaluate results for a specific iteration
 *
 * @param iteration the iteration to evaluate
 */
static void
evaluate (int iteration)
{
  struct Result *cur;
  int cp;

  for (cp = ph.N_peers_start; cp <= ph.N_peers_end; cp ++)
  {
    cur = ph.iterations_results[ph.current_iteration-1].results_array[cp];
    if (0 == cp)
      continue;
    if (NULL == cur)
    {
      GNUNET_break (0);
      fprintf (stderr,
               "Missing result for %u peers\n", cp);
      continue;
    }


    if (GNUNET_NO == cur->valid)
    {
      fprintf (stderr,
               "Total time to solve %s for %u peers %u addresses: %s\n",
               (GNUNET_YES == cur->update) ? "updated" : "full",
               cur->peers, cur->addresses, "Failed to solve!");
      continue;
    }


    if (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us != cur->d_total_full.rel_value_us)
    {
      fprintf (stderr,
         "Total time to solve %s for %u peers %u addresses: %llu us\n",
         (GNUNET_YES == cur->update) ? "updated" : "full",
         cur->peers, cur->addresses,
         (unsigned long long) cur->d_total_full.rel_value_us);
    }


    if (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us != cur->d_setup_full.rel_value_us)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Total time to setup %s %u peers %u addresses: %llu us\n",
          (GNUNET_YES == cur->update) ? "updated" : "full",
          cur->peers, cur->addresses,
          (unsigned long long) cur->d_setup_full.rel_value_us);
    }

    if (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us != cur->d_lp_full.rel_value_us)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
         "Total time to solve %s LP for %u peers %u addresses: %llu us\n",
         (GNUNET_YES == cur->update) ? "updated" : "full",
         cur->peers,
         cur->addresses,
         (unsigned long long )cur->d_lp_full.rel_value_us);
    }

    if (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us != cur->d_mlp_full.rel_value_us)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Total time to solve %s MLP for %u peers %u addresses: %llu us\n",
          (GNUNET_YES == cur->update) ? "updated" : "full",
          cur->peers, cur->addresses,
          (unsigned long long )cur->d_mlp_full.rel_value_us);
    }
  }
}


/**
 * Evaluate average results for all iterations
 */
static void
write_all_iterations (void)
{
  int c_iteration;
  int c_peer;

  struct GNUNET_DISK_FileHandle *f_full;
  struct GNUNET_DISK_FileHandle *f_update;
  char * data_fn_full;
  char * data_fn_update;
  char * data;

  f_full = NULL;
  f_update = NULL;

  data_fn_full = NULL;

  if (GNUNET_NO == ph.create_datafile)
    return;

  GNUNET_asprintf (&data_fn_full,
                   "perf_%s_full_%u-%u_%u_%u.data",
                   ph.ats_string,
                   ph.total_iterations,
                   ph.N_peers_start,
                   ph.N_peers_end,
                   ph.N_address);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Using data file `%s'\n",
              data_fn_full);

  f_full = GNUNET_DISK_file_open (data_fn_full,
      GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE,
      GNUNET_DISK_PERM_USER_EXEC | GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
  if (NULL == f_full)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Cannot open data file `%s'\n",
                data_fn_full);
    GNUNET_free (data_fn_full);
    return;
  }

  data = "#peers;addresses;time total in us;#time setup in us;#time lp in us;#time mlp in us;\n";
  if (GNUNET_SYSERR == GNUNET_DISK_file_write(f_full, data, strlen(data)))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Cannot write data to log file `%s'\n",
                data_fn_full);

  data_fn_update = NULL;
  if (GNUNET_YES == ph.measure_updates)
  {
    GNUNET_asprintf (&data_fn_update, "perf_%s_update_%u-%u_%u_%u.data",
        ph.ats_string,
        ph.total_iterations,
        ph.N_peers_start,
        ph.N_peers_end,
        ph.N_address);
    f_update = GNUNET_DISK_file_open (data_fn_update,
        GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE,
        GNUNET_DISK_PERM_USER_EXEC | GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
    if (NULL == f_update)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Cannot open gnuplot file `%s'\n", data_fn_update);
      GNUNET_free (data_fn_update);
      if (NULL != f_full)
        GNUNET_DISK_file_close (f_full);
      GNUNET_free (data_fn_full);
      return;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Using update data file `%s'\n",
                data_fn_update);

    data = "#peers;addresses;time total in us;#time setup in us;#time lp in us;#time mlp in us;\n";
    if (GNUNET_SYSERR == GNUNET_DISK_file_write (f_update, data, strlen(data)))
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Cannot write data to log file `%s'\n",
                  data_fn_update);
  }

  for (c_peer = ph.N_peers_start; c_peer <= ph.N_peers_end; c_peer ++)
  {
    char * data_str;
    char * data_tmp;
    char * data_upd_str;
    char * data_upd_tmp;
    GNUNET_asprintf(&data_str, "%u;%u",c_peer, ph.N_address);
    if (ph.measure_updates)
      GNUNET_asprintf(&data_upd_str, "%u;%u",c_peer, ph.N_address);
    for (c_iteration = 0; c_iteration < ph.total_iterations; c_iteration ++)
    {
      struct Result *cur_full_res;
      struct Result *cur_upd_res;



      //fprintf (stderr, "P: %u I: %u  == %p \n", c_peer, c_iteration, cur_res);
      cur_full_res = ph.iterations_results[c_iteration].results_array[c_peer];
      if (c_peer == 0)
        continue;
      if (NULL == cur_full_res)
        continue;

      if (ph.measure_updates)
      {
        cur_upd_res = ph.iterations_results[c_iteration].update_results_array[c_peer];
        data_upd_tmp = GNUNET_strdup (data_upd_str);
        GNUNET_free (data_upd_str);
        if (GNUNET_YES == cur_full_res->valid)
        {
          GNUNET_asprintf (&data_upd_str, "%s;%llu", data_upd_tmp,
            (NULL == cur_upd_res) ? 0 : cur_upd_res->d_total_full.rel_value_us);
        }
        else
        {
            GNUNET_asprintf (&data_upd_str, "%s;", data_upd_tmp);
        }
        GNUNET_free (data_upd_tmp);

      }

      //fprintf (stderr, "P: %u I: %u: P %i  A %i\n", c_peer, c_iteration, cur_res->peers, cur_res->addresses);
      //fprintf (stderr, "D total: %llu\n", (long long unsigned int) cur_res->d_total.rel_value_us);

      data_tmp = GNUNET_strdup (data_str);
      GNUNET_free (data_str);
      if (GNUNET_YES == cur_full_res->valid)
      {
          GNUNET_asprintf (&data_str, "%s;%llu", data_tmp,
              cur_full_res->d_total_full.rel_value_us);
      }
      else
      {
          GNUNET_asprintf (&data_str, "%s;", data_tmp);
      }

      GNUNET_free (data_tmp);
    }
    data_tmp = GNUNET_strdup (data_str);
    GNUNET_free (data_str);
    GNUNET_asprintf (&data_str, "%s\n", data_tmp);
    GNUNET_free (data_tmp);

    fprintf (stderr, "Result full solution: %s\n", data_str);
    if (GNUNET_SYSERR == GNUNET_DISK_file_write (f_full, data_str, strlen(data_str)))
      GNUNET_break (0);
    GNUNET_free (data_str);

    if (ph.measure_updates)
    {
      data_upd_tmp = GNUNET_strdup (data_upd_str);
      GNUNET_free (data_upd_str);
      GNUNET_asprintf (&data_upd_str, "%s\n", data_upd_tmp);
      GNUNET_free (data_upd_tmp);

      fprintf (stderr, "Result updated solution: `%s'\n", data_upd_str);
      if (GNUNET_SYSERR == GNUNET_DISK_file_write (f_update, data_upd_str, strlen(data_upd_str)))
        GNUNET_break (0);
      GNUNET_free (data_upd_str);
    }
  }

  if ((NULL != f_full) && (GNUNET_SYSERR == GNUNET_DISK_file_close (f_full)))
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Cannot close log file `%s'\n",
        data_fn_full);
  GNUNET_free_non_null (data_fn_full);

  if ((NULL != f_update) && (GNUNET_SYSERR == GNUNET_DISK_file_close (f_update)))
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Cannot close log file `%s'\n",
        data_fn_update);
  GNUNET_free_non_null (data_fn_update);
}


static int
do_delete_address (void *cls,
                   const struct GNUNET_PeerIdentity *pid,
                   void *value)
{
  struct ATS_Address *cur = value;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Deleting addresses for peer %u\n",
             pid);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_remove (ph.addresses,
                                                       pid,
                                                       cur));
  ph.sf->s_del (ph.sf->cls, cur, GNUNET_NO);
  GNUNET_free_non_null (cur->atsi);
  GNUNET_free (cur);
  return GNUNET_OK;
}


/**
 * Run a performance iteration
 */
static void
perf_run_iteration (void)
{
  int cp;
  int ca;
  int count_p = ph.N_peers_end;
  int count_a = ph.N_address;
  struct ATS_Address * cur_addr;
  uint32_t net;

  ph.iterations_results[ph.current_iteration-1].results_array = GNUNET_malloc ((count_p + 1) * sizeof (struct Result *));
  if (ph.measure_updates)
    ph.iterations_results[ph.current_iteration-1].update_results_array = GNUNET_malloc ((count_p + 1) * sizeof (struct Result *));
  ph.peers = GNUNET_malloc ((count_p) * sizeof (struct PerfPeer));
  for (cp = 0; cp < count_p; cp++)
    perf_create_peer (cp);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Iteration %u of %u, added %u peers\n", ph.current_iteration, ph.total_iterations, cp);

  for (cp = 0; cp < count_p; cp++)
  {
    fprintf (stderr,"%u..", cp);
    if (GNUNET_NO == ph.bulk_running)
    {
      ph.bulk_running = GNUNET_YES;
      ph.sf->s_bulk_start (ph.sf->cls);
    }
    ph.current_p = cp + 1;
    for (ca = 0; ca < count_a; ca++)
    {
      cur_addr = perf_create_address (cp, ca);
      /* Add address */

      /* Random network selection */
      //net = 1 + GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, GNUNET_ATS_NetworkTypeCount - 1);
      /* Random equally distributed network selection */
      net = 1 + (ca %  (GNUNET_ATS_NetworkTypeCount - 1));
      /* fprintf (stderr, "Network: %u `%s'\n",
       * mod_net , GNUNET_ATS_print_network_type(mod_net)); */

      cur_addr->atsi = GNUNET_new (struct GNUNET_ATS_Information);
      cur_addr->atsi_count = 1;
      cur_addr->atsi[0].type = htonl (GNUNET_ATS_NETWORK_TYPE);
      cur_addr->atsi[0].value = htonl (net);
      ph.sf->s_add (ph.sf->cls, cur_addr, net);

      ph.current_a = ca + 1;
      perf_address_initial_update (NULL, ph.addresses, cur_addr);
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Adding address for peer %u address %u in network %s\n", cp, ca,
          GNUNET_ATS_print_network_type(net));
    }
    /* Notify solver about request */
    ph.sf->s_get (ph.sf->cls, &ph.peers[cp].id);

    if (cp + 1 >= ph.N_peers_start)
    {
      /* Disable bulk to solve the problem */
      if (GNUNET_YES == ph.bulk_running)
      {
        ph.expecting_solution = GNUNET_YES;
        ph.bulk_running = GNUNET_NO;
        ph.sf->s_bulk_stop (ph.sf->cls);
      }
      else
        GNUNET_break (0);

      /* Problem is solved by the solver here due to unlocking */
      ph.expecting_solution = GNUNET_NO;

      /* Update the problem */
      if ((0 < ph.opt_update_percent) && (GNUNET_YES == ph.measure_updates))
      {
        /* Update */
        GNUNET_log(GNUNET_ERROR_TYPE_INFO,
            "Updating problem with %u peers and %u addresses\n", cp + 1, ca);

        ph.expecting_solution = GNUNET_YES;
        ph.performed_update = GNUNET_YES;
        if (GNUNET_NO == ph.bulk_running)
        {
          ph.bulk_running = GNUNET_YES;
          ph.sf->s_bulk_start (ph.sf->cls);
        }
        perf_update_all_addresses (cp + 1, ca, ph.opt_update_percent);
        ph.bulk_running = GNUNET_NO;
        ph.sf->s_bulk_stop (ph.sf->cls);
        /* Problem is solved by the solver here due to unlocking */
        ph.performed_update = GNUNET_NO;
        ph.expecting_solution = GNUNET_NO;
      }
      GNUNET_assert (GNUNET_NO == ph.bulk_running);
    }
  }
  fprintf (stderr,"\n");
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Done, cleaning up addresses\n");
  if (GNUNET_NO == ph.bulk_running)
  {
    ph.sf->s_bulk_start (ph.sf->cls);
    ph.bulk_running = GNUNET_YES;
  }

  for (cp = 0; cp < count_p; cp++)
  {
    GNUNET_CONTAINER_multipeermap_get_multiple (ph.addresses,
                                                &ph.peers[cp].id,
                                                &do_delete_address,
                                                NULL);
  }

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Iteration done\n");
  GNUNET_free(ph.peers);
}


static void
run (void *cls, char * const *args, const char *cfgfile,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_log_setup ("perf-ats-solver", "WARNING", NULL);
  char *sep;
  char *src_filename = GNUNET_strdup (__FILE__);
  char *test_filename = cls;
  char *solver;
  char *plugin;
  struct GNUNET_CONFIGURATION_Handle *solver_cfg;
  unsigned long long quotas_in[GNUNET_ATS_NetworkTypeCount];
  unsigned long long quotas_out[GNUNET_ATS_NetworkTypeCount];
  int c;
  int c2;

  /* Extract test name */
  if (NULL == (sep  = (strstr (src_filename,".c"))))
  {
    GNUNET_free (src_filename);
    GNUNET_break (0);
    ret = 1;
    return ;
  }
  sep[0] = '\0';

  if (NULL != (sep = strstr (test_filename, ".exe")))
    sep[0] = '\0';

  if (NULL == (solver = strstr (test_filename, src_filename)))
  {
    GNUNET_free (src_filename);
    GNUNET_break (0);
    ret = 1;
    return ;
  }
  solver += strlen (src_filename) +1;

  if (0 == strcmp(solver, "proportional"))
  {
    ph.ats_string = "proportional";
  }
  else if (0 == strcmp(solver, "mlp"))
  {
    ph.ats_string = "mlp";
  }
  else if ((0 == strcmp(solver, "ril")))
  {
    ph.ats_string = "ril";
  }
  else
  {
    GNUNET_free (src_filename);
    GNUNET_break (0);
    ret = 1;
    return ;
  }
  GNUNET_free (src_filename);

  /* Calculcate peers */
  if ((0 == ph.N_peers_start) && (0 == ph.N_peers_end))
  {
    ph.N_peers_start = DEFAULT_PEERS_START;
    ph.N_peers_end = DEFAULT_PEERS_END;
  }
  if (0 == ph.N_address)
    ph.N_address = DEFAULT_ADDRESSES;


  if (ph.N_peers_start != ph.N_peers_end)
    fprintf (stderr, "Benchmarking solver `%s' with %u to %u peers and %u addresses in %u iterations\n",
        ph.ats_string, ph.N_peers_start, ph.N_peers_end, ph.N_address, ph.total_iterations);
  else
    fprintf (stderr, "Benchmarking solver `%s' with %u peers and %u addresses in %u iterations\n",
        ph.ats_string, ph.N_peers_end, ph.N_address, ph.total_iterations);

  if (0 == ph.opt_update_percent)
    ph.opt_update_percent = DEFAULT_UPDATE_PERCENTAGE;

  /* Load quotas */
  solver_cfg = GNUNET_CONFIGURATION_create();
  if ((NULL == solver_cfg) || (GNUNET_SYSERR == (GNUNET_CONFIGURATION_load ( solver_cfg, "perf_ats_solver.conf"))))
  {
    GNUNET_break(0);
    end_now (1);
    return;
  }
  if (GNUNET_ATS_NetworkTypeCount != load_quotas (solver_cfg,
      quotas_out, quotas_in, GNUNET_ATS_NetworkTypeCount))
  {
    GNUNET_break(0);
    end_now (1);
    return;
  }

  /* Create array of DLL to store results for iterations */
  ph.iterations_results = GNUNET_malloc (sizeof (struct Iteration) * ph.total_iterations);

  /* Load solver */
  ph.env.cfg = solver_cfg;
  ph.stat = GNUNET_STATISTICS_create ("ats", cfg);
  ph.env.stats = ph.stat;
  ph.addresses = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_NO);
  ph.env.addresses = ph.addresses;
  ph.env.bandwidth_changed_cb = bandwidth_changed_cb;
  ph.env.get_preferences = &get_preferences_cb;
  ph.env.network_count = GNUNET_ATS_NetworkTypeCount;
  ph.env.info_cb = &solver_info_cb;

  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
    ph.env.out_quota[c] = quotas_out[c];
    ph.env.in_quota[c] = quotas_in[c];
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Loading network quotas: `%s' %llu %llu \n",
                GNUNET_ATS_print_network_type (c),
                ph.env.out_quota[c],
                ph.env.in_quota[c]);
  }
  GAS_normalization_start ();
  GAS_preference_init ();

  GNUNET_asprintf (&plugin, "libgnunet_plugin_ats_%s", ph.ats_string);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Initializing solver `%s'\n"), ph.ats_string);
  if  (NULL == (ph.sf = GNUNET_PLUGIN_load (plugin, &ph.env)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to initialize solver `%s'!\n"), plugin);
    ret = 1;
    return;
  }

  /* Do the benchmark */
  for (ph.current_iteration = 1; ph.current_iteration <= ph.total_iterations; ph.current_iteration++)
  {
    fprintf (stderr, "Iteration %u of %u starting\n", ph.current_iteration, ph.total_iterations);
    perf_run_iteration ();
    evaluate (ph.current_iteration);
    fprintf (stderr, "Iteration %u of %u done\n", ph.current_iteration, ph.total_iterations);
  }
  if (ph.create_datafile)
    write_all_iterations ();

  /* Unload solver*/
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Unloading solver `%s'\n"), ph.ats_string);
  GNUNET_PLUGIN_unload (plugin, ph.sf);
  ph.sf = NULL;
  GNUNET_free (plugin);
  for (c = 0; c < ph.total_iterations; c++ )
  {
    for (c2 = ph.N_peers_start; c2 < ph.N_peers_end; c2++ )
    {
      if (0 == c2)
        continue;
      if (ph.measure_updates)
        GNUNET_free_non_null (ph.iterations_results[c].update_results_array[c2]);
      GNUNET_free (ph.iterations_results[c].results_array[c2]);
    }
    if (ph.measure_updates)
      GNUNET_free (ph.iterations_results[c].update_results_array);
    GNUNET_free(ph.iterations_results[c].results_array);
  }
  GNUNET_free (ph.iterations_results);

  GNUNET_CONFIGURATION_destroy (solver_cfg);
  GNUNET_STATISTICS_destroy (ph.stat, GNUNET_NO);
}

/**
 * Main function of the benchmark
 *
 * @param argc argument count
 * @param argv argument values
 */
int
main (int argc, char *argv[])
{
  /* extract command line arguments */
  ph.opt_update_percent = 0;
  ph.N_peers_start = 0;
  ph.N_peers_end = 0;
  ph.N_address = 0;
  ph.ats_string = NULL;
  ph.create_datafile = GNUNET_NO;
  ph.measure_updates = GNUNET_NO;
  ph.total_iterations = 1;

  static struct GNUNET_GETOPT_CommandLineOption options[] = {
      { 'a', "addresses", NULL,
          gettext_noop ("addresses to use"),
          1, &GNUNET_GETOPT_set_uint, &ph.N_address },
      { 's', "start", NULL,
          gettext_noop ("start with peer"),
          1, &GNUNET_GETOPT_set_uint, &ph.N_peers_start },
      { 'e', "end", NULL,
          gettext_noop ("end with peer"),
          1, &GNUNET_GETOPT_set_uint, &ph.N_peers_end },
      { 'i', "iterations", NULL,
          gettext_noop ("number of iterations used for averaging (default: 1)"),
          1, &GNUNET_GETOPT_set_uint, &ph.total_iterations },
      { 'p', "percentage", NULL,
          gettext_noop ("update a fix percentage of addresses"),
          1, &GNUNET_GETOPT_set_uint, &ph.opt_update_percent },
      { 'd', "data", NULL,
          gettext_noop ("create data file"),
          0, &GNUNET_GETOPT_set_one, &ph.create_datafile},
      { 'u', "update", NULL,
          gettext_noop ("measure updates"),
          0, &GNUNET_GETOPT_set_one, &ph.measure_updates},
      GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run (argc, argv, argv[0], NULL, options, &run, argv[0]);
  return ret;
}

/* end of file perf_ats_solver.c */
