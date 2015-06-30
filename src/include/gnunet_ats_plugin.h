/*
 This file is part of GNUnet
 Copyright (C) 2009-2015 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_ats_plugin.h
 * @brief API for the ATS solvers.  This header
 *        specifies the struct that is given to the plugin's entry
 *        method and the other struct that must be returned.
 *        Note that the destructors of ATS plugins will
 *        be given the value returned by the constructor
 *        and is expected to return a NULL pointer.
 * @author Christian Grothoff
 */
#ifndef PLUGIN_ATS_H
#define PLUGIN_ATS_H

#include "gnunet_ats_service.h"
#include "gnunet_statistics_service.h"

/**
 * Representation of an address the plugin can choose from.
 */
struct ATS_Address;

/**
 * Change the preference for a peer
 *
 * @param handle the solver handle
 * @param client the client sending this request
 * @param peer the peer id
 * @param kind the preference kind to change
 * @param score the new preference score
 * @param pref_rel the normalized preference value for this kind over all clients
 */
typedef void
(*GAS_solver_address_change_preference) (void *solver,
                                         const struct GNUNET_PeerIdentity *peer,
                                         enum GNUNET_ATS_PreferenceKind kind,
                                         double pref_rel);


/**
 * Give feedback about the current assignment
 *
 * @param handle the solver handle
 * @param application the application sending this request
 * @param peer the peer id
 * @param scope the time interval for this feedback: [now - scope .. now]
 * @param kind the preference kind for this feedback
 * @param score the feedback score
 */
typedef void
(*GAS_solver_address_feedback_preference) (void *solver,
                                           struct GNUNET_SERVER_Client *application,
                                           const struct GNUNET_PeerIdentity *peer,
                                           const struct GNUNET_TIME_Relative scope,
                                           enum GNUNET_ATS_PreferenceKind kind,
                                           double score);

/**
 * Notify the solver about a bulk operation changing possibly a lot of values
 * Solver will not resolve until all bulk operations are marked as done
 *
 * @param solver the solver
 */
typedef void
(*GAS_solver_bulk_start) (void *solver);


/**
 * Mark a bulk operation as done
 * Solver will resolve if values have changed
 *
 * @param solver the solver
 */
typedef void
(*GAS_solver_bulk_stop) (void *solver);


/**
 * Add a single address within a network to the solver
 *
 * @param solver the solver Handle
 * @param address the address to add
 * @param network network type of this address
 */
typedef void
(*GAS_solver_address_add) (void *solver,
                           struct ATS_Address *address,
                           uint32_t network);


/**
 * Delete an address or just the session from the solver
 *
 * @param solver the solver Handle
 * @param address the address to delete
 */
typedef void
(*GAS_solver_address_delete) (void *solver,
                              struct ATS_Address *address);


/**
 * Transport properties for this address have changed
 *
 * @param solver solver handle
 * @param address the address
 */
typedef void
(*GAS_solver_address_property_changed) (void *solver,
                                        struct ATS_Address *address);


/**
 * Get the prefered address for a peer from solver
 *
 * @param solver the solver to use
 * @param peer the peer
 */
typedef void
(*GAS_solver_get_preferred_address) (void *solver,
                                     const struct GNUNET_PeerIdentity *peer);


/**
 * Stop getting the prefered address for a peer from solver
 *
 * @param solver the solver to use
 * @param peer the peer
 */
typedef void
(*GAS_solver_stop_get_preferred_address) (void *solver,
                                          const struct GNUNET_PeerIdentity *peer);


/**
 * Solver functions.
 *
 * Each solver is required to set up and return an instance
 * of this struct during initialization.
 */
struct GNUNET_ATS_SolverFunctions
{

  /**
   * Closure to pass to all solver functions in this struct.
   */
  void *cls;

  /**
   * Add a new address for a peer to the solver
   *
   * The address is already contained in the addresses hashmap!
   */
  GAS_solver_address_add s_add;

  /**
   * Update the properties of an address in the solver
   */
  GAS_solver_address_property_changed s_address_update_property;

  /**
   * Tell solver to notify ATS if the address to use changes for a specific
   * peer using the bandwidth changed callback
   *
   * The solver must only notify about changes for peers with pending address
   * requests!
   */
  GAS_solver_get_preferred_address s_get;

  /**
   * Tell solver stop notifying ATS about changes for this peers
   *
   * The solver must only notify about changes for peers with pending address
   * requests!
   */
  GAS_solver_stop_get_preferred_address s_get_stop;

  /**
   * Delete an address in the solver
   *
   * The address is not contained in the address hashmap anymore!
   */
  GAS_solver_address_delete s_del;

  /**
   * Change relative preference for quality in solver
   */
  GAS_solver_address_change_preference s_pref;

  /**
   * Give feedback about the current assignment
   */
  GAS_solver_address_feedback_preference s_feedback;

  /**
   * Start a bulk operation
   *
   * Used if many values have to be updated at the same time.
   * When a bulk operation is pending the solver does not have to resolve
   * the problem since more updates will follow anyway
   *
   * For each call to bulk_start, a call to bulk_stop is required!
   */
  GAS_solver_bulk_start s_bulk_start;

  /**
   * Bulk operation done
   *
   * If no more bulk operations are pending, the solver can solve the problem
   * with the updated values
   */
  GAS_solver_bulk_stop s_bulk_stop;
};


/**
 * Operation codes for solver information callback
 *
 * Order of calls is expected to be:
 * #GAS_OP_SOLVE_START
 * #GAS_OP_SOLVE_STOP
 * #GAS_OP_SOLVE_UPDATE_NOTIFICATION_START
 * #GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP
 *
 */
enum GAS_Solver_Operation
{
  /**
   * A solution iteration has been started
   */
  GAS_OP_SOLVE_START,

  /**
   * A solution iteration has been finished
   */
  GAS_OP_SOLVE_STOP,

  /**
   * The setup of the problem as a preparation to solve it was started
   */
  GAS_OP_SOLVE_SETUP_START,

  /**
   * The setup of the problem as a preparation to solve is finished
   */
  GAS_OP_SOLVE_SETUP_STOP,

  /**
   * Solving of the LP problem was started
   * MLP solver only
   */
  GAS_OP_SOLVE_MLP_LP_START,

  /**
   * Solving of the LP problem is done
   * MLP solver only
   */
  GAS_OP_SOLVE_MLP_LP_STOP,

  /**
   * Solving of the MLP problem was started
   * MLP solver only
   */
  GAS_OP_SOLVE_MLP_MLP_START,

  /**
   * Solving of the MLP problem is done
   * MLP solver only
   */
  GAS_OP_SOLVE_MLP_MLP_STOP,

  /**
   * After the problem was finished, start notifications about changes
   * to addresses
   */
  GAS_OP_SOLVE_UPDATE_NOTIFICATION_START,

  /**
   * After the problem was finished, notifications about changes to addresses
   * are done
   */
  GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP
};


/**
 * Status of a GAS_Solver_Operation operation
 */
enum GAS_Solver_Status
{
  /**
   * Success
   */
  GAS_STAT_SUCCESS,

  /**
   * Failure
   */
  GAS_STAT_FAIL
};


/**
 * Status of the operation
 */
enum GAS_Solver_Additional_Information
{
  /**
   * No more specific information
   */
  GAS_INFO_NONE,

  /**
   * A full solution process is performed
   * Quite specific to the MLP solver
   */
  GAS_INFO_FULL,

  /**
   * An existing solution was reused
   * Quite specific to the MLP solver
   */
  GAS_INFO_UPDATED,

  /**
   * The proportional solver had to recalculate for a single network
   */
  GAS_INFO_PROP_SINGLE,

  /**
   * The proportional solver had to recalculate for all networks
   */
  GAS_INFO_PROP_ALL
};


/**
 * Callback to call with additional information
 * Used for measurement
 *
 * @param cls the closure
 * @param op the operation
 */
typedef void
(*GAS_solver_information_callback) (void *cls,
                                    enum GAS_Solver_Operation op,
                                    enum GAS_Solver_Status stat,
                                    enum GAS_Solver_Additional_Information);


/**
 * Callback to call from solver when bandwidth for address has changed
 *
 * @param address the with changed bandwidth assigned
 */
typedef void
(*GAS_bandwidth_changed_cb) (void *cls,
                             struct ATS_Address *address);


/**
 * Callback to call from solver to obtain application preference
 * values for a peer.
 *
 * @param cls the cls
 * @param id the peer id
 * @return carry of double values containing the preferences with
 *      GNUNET_ATS_PreferenceCount elements
 */
typedef const double *
(*GAS_get_preferences) (void *cls,
                        const struct GNUNET_PeerIdentity *id);


/**
 * Callback to call from solver to obtain application connectivity
 * preferences for a peer.
 *
 * @param cls the cls
 * @param id the peer id
 * @return 0 if connectivity is not desired, non-null if address
 *      suggestions are requested
 */
typedef unsigned int
(*GAS_get_connectivity) (void *cls,
                         const struct GNUNET_PeerIdentity *id);


/**
 * The ATS plugin will pass a pointer to a struct
 * of this type as to the initialization function
 * of the ATS plugins.
 */
struct GNUNET_ATS_PluginEnvironment
{
  /**
   * Configuration handle to be used by the solver
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Statistics handle to be used by the solver
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Closure to pass to all callbacks in this struct.
   */
  void *cls;

  /**
   * Hashmap containing all addresses available
   */
  struct GNUNET_CONTAINER_MultiPeerMap *addresses;

  /**
   * ATS addresses callback to be notified about bandwidth assignment changes
   */
  GAS_bandwidth_changed_cb bandwidth_changed_cb;

  /**
   * ATS addresses function to obtain preference values
   */
  GAS_get_preferences get_preferences;

  /**
   * ATS addresses function to obtain preference values
   */
  GAS_get_connectivity get_connectivity;

  /**
   * Callback for solver to call with status information,
   * can be NULL
   */
  GAS_solver_information_callback info_cb;

  /**
   * Number of networks available, size of the @e out_quota
   * and @e in_quota arrays.
   */
  unsigned int network_count;

  /**
   * Array of configured outbound quotas
   * Order according to networks in network array
   */
  unsigned long long out_quota[GNUNET_ATS_NetworkTypeCount];

  /**
   * Array of configured inbound quotas
   * Order according to networks in network array
   */
  unsigned long long in_quota[GNUNET_ATS_NetworkTypeCount];
};

#endif
