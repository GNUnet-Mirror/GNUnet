/*
 This file is part of GNUnet
 (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_solver_plugin.h
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

struct ATS_Address;


/*
 * Solver API
 * ----------
 */


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
    const struct GNUNET_PeerIdentity *peer, enum GNUNET_ATS_PreferenceKind kind,
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
(*GAS_solver_address_feedback_preference) (void *solver, void *application,
    const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_TIME_Relative scope,
    enum GNUNET_ATS_PreferenceKind kind, double score);

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
 * @param addresses the address hashmap containing all addresses
 * @param address the address to add
 * @param network network type of this address
 */
typedef void
(*GAS_solver_address_add) (void *solver, struct ATS_Address *address,
    uint32_t network);

/**
 * Delete an address or just the session from the solver
 *
 * @param solver the solver Handle
 * @param addresses the address hashmap containing all addresses
 * @param address the address to delete
 * @param session_only remove address or just session
 */
typedef void
(*GAS_solver_address_delete) (void *solver, struct ATS_Address *address,
    int session_only);

/**
 * Transport properties for this address have changed
 *
 * @param solver solver handle
 * @param address the address
 * @param type the ATSI type in HBO
 * @param abs_value the absolute value of the property
 * @param rel_value the normalized value
 */
typedef void
(*GAS_solver_address_property_changed) (void *solver,
    struct ATS_Address *address, uint32_t type, uint32_t abs_value,
    double rel_value);

/**
 * Transport session for this address has changed
 *
 * NOTE: values in addresses are already updated
 *
 * @param solver solver handle
 * @param address the address
 * @param cur_session the current session
 * @param new_session the new session
 */
typedef void
(*GAS_solver_address_session_changed) (void *solver,
    struct ATS_Address *address, uint32_t cur_session, uint32_t new_session);

/**
 * Transport session for this address has changed
 *
 * NOTE: values in addresses are already updated
 *
 * @param solver solver handle
 * @param address the address
 * @param in_use usage state
 */
typedef void
(*GAS_solver_address_inuse_changed) (void *solver, struct ATS_Address *address,
    int in_use);

/**
 * Network scope for this address has changed
 *
 * NOTE: values in addresses are already updated
 *
 * @param solver solver handle
 * @param address the address
 * @param current_network the current network
 * @param new_network the new network
 */
typedef void
(*GAS_solver_address_network_changed) (void *solver,
    struct ATS_Address *address, uint32_t current_network, uint32_t new_network);

/**
 * Get the prefered address for a peer from solver
 *
 * @param solver the solver to use
 * @param addresses the address hashmap containing all addresses
 * @param peer the peer
 */
typedef const struct ATS_Address *
(*GAS_solver_get_preferred_address) (void *solver,
    const struct GNUNET_PeerIdentity *peer);

/**
 * Stop getting the prefered address for a peer from solver
 *
 * @param solver the solver to use
 * @param addresses the address hashmap containing all addresses
 * @param peer the peer
 */
typedef void
(*GAS_solver_stop_get_preferred_address) (void *solver,
    const struct GNUNET_PeerIdentity *peer);


/**
 * Each plugin is required to return a pointer to a struct of this
 * type as the return value from its entry point.
 */
struct GNUNET_ATS_SolverFunctions
{

  /**
   * Closure for all of the callbacks.
   */
  void *cls;

  /**
   * Add an address to the solver
   */
  GAS_solver_address_add s_add;

  GAS_solver_address_property_changed s_address_update_property;

  GAS_solver_address_session_changed s_address_update_session;

  GAS_solver_address_inuse_changed s_address_update_inuse;

  GAS_solver_address_network_changed s_address_update_network;

  /**
   * Get address from solver
   */
  GAS_solver_get_preferred_address s_get;

  /**
   * Get address from solver
   */
  GAS_solver_stop_get_preferred_address s_get_stop;

  /**
   * Delete address in solver
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
   */
  GAS_solver_bulk_start s_bulk_start;

  /**
   * Bulk operation done
   */
  GAS_solver_bulk_stop s_bulk_stop;

};


/**
 * Callback to call from solver when bandwidth for address has changed
 *
 * @param address the with changed bandwidth assigned
 */
typedef void
(*GAS_bandwidth_changed_cb) (void *cls, struct ATS_Address *address);

/**
 * Callback to call from solver to obtain application preference values for a
 * peer
 *
 * @param cls the cls
 * @param id the peer id
 * @return carry of double values containing the preferences with
 *      GNUNET_ATS_PreferenceCount elements
 */
typedef const double *
(*GAS_get_preferences) (void *cls, const struct GNUNET_PeerIdentity *id);

/**
 * Callback to call from solver to obtain transport properties for an
 * address
 *
 * @param cls the cls
 * @param address the address
 * @return carry of double values containing the preferences with
 *      GNUNET_ATS_PreferenceCount elements
 */
typedef const double *
(*GAS_get_properties) (void *cls, const struct ATS_Address *address);


/**
 * The transport service will pass a pointer to a struct
 * of this type as the first and only argument to the
 * entry point of each transport plugin.
 */
struct GNUNET_ATS_PluginEnvironment
{
  /**
   * Closure for the various callbacks.
   */
  void *cls;

  GAS_bandwidth_changed_cb bandwidth_changed_cb;
  void *bw_changed_cb_cls;

  GAS_get_preferences get_preferences_cb;
  void *get_preference_cls;

  GAS_get_properties get_property_cb;
  void *get_property_cls;

  struct GNUNET_ATS_SolverFunctions sf;

  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_STATISTICS_Handle *stats;
  struct GNUNET_CONTAINER_MultiPeerMap *addresses;

  /* Available networks */
  int networks[GNUNET_ATS_NetworkTypeCount];
  int network_count;

  unsigned long long out_quota[GNUNET_ATS_NetworkTypeCount];
  unsigned long long in_quota[GNUNET_ATS_NetworkTypeCount];
};

#endif
