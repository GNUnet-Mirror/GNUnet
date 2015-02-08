/*
 This file is part of GNUnet.
 Copyright (C) 2011-2014 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_plugins.c
 * @brief ats service plugin management
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_ats_plugin.h"
#include "gnunet-service-ats_connectivity.h"
#include "gnunet-service-ats_performance.h"
#include "gnunet-service-ats_preferences.h"
#include "gnunet-service-ats_plugins.h"
#include "gnunet-service-ats_scheduling.h"
#include "gnunet-service-ats_normalization.h"


/**
 * Solver handle.
 */
static struct GNUNET_ATS_SolverFunctions *sf;

/**
 * Solver environment.
 */
static struct GNUNET_ATS_PluginEnvironment env;

/**
 * Solver plugin name as string
 */
static char *plugin;


/**
 * The preference changed for a peer, update solver.
 *
 * @param peer the peer
 * @param kind the ATS kind
 * @param pref_rel the new relative preference value
 */
void
GAS_plugin_notify_preference_changed (const struct GNUNET_PeerIdentity *peer,
                                      enum GNUNET_ATS_PreferenceKind kind,
                                      double pref_rel)
{
  sf->s_pref (sf->cls,
              peer,
              kind,
              pref_rel);
}


/**
 * The relative value for a property changed
 *
 * @param address the peer
 * @param type the ATS type
 * @param prop_rel the new relative preference value
 */
void
GAS_plugin_notify_property_changed (struct ATS_Address *address,
                                    enum GNUNET_ATS_Property type,
                                    double prop_rel)
{
  sf->s_address_update_property (sf->cls,
                                 address,
                                 type,
                                 0,
                                 prop_rel);
}


/**
 * Solver information callback
 *
 * @param cls the closure
 * @param op the operation
 * @param status operation status
 * @param add additional information
 */
static void
solver_info_cb (void *cls,
		enum GAS_Solver_Operation op,
		enum GAS_Solver_Status status,
		enum GAS_Solver_Additional_Information add)
{
  const char *add_info;

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
  switch (op)
  {
  case GAS_OP_SOLVE_START:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Solver notifies `%s' with result `%s' `%s'\n",
                "GAS_OP_SOLVE_START",
                (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL",
                add_info);
    return;
  case GAS_OP_SOLVE_STOP:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Solver notifies `%s' with result `%s'\n",
                "GAS_OP_SOLVE_STOP",
                (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL",
                add_info);
    return;
  case GAS_OP_SOLVE_SETUP_START:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Solver notifies `%s' with result `%s'\n",
                "GAS_OP_SOLVE_SETUP_START",
                (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL");
    return;
  case GAS_OP_SOLVE_SETUP_STOP:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Solver notifies `%s' with result `%s'\n",
                "GAS_OP_SOLVE_SETUP_STOP",
                (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL");
    return;
  case GAS_OP_SOLVE_MLP_LP_START:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Solver notifies `%s' with result `%s'\n",
                "GAS_OP_SOLVE_LP_START",
                (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL");
    return;
  case GAS_OP_SOLVE_MLP_LP_STOP:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Solver notifies `%s' with result `%s'\n",
                "GAS_OP_SOLVE_LP_STOP",
                (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL");
    return;
  case GAS_OP_SOLVE_MLP_MLP_START:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Solver notifies `%s' with result `%s'\n",
                "GAS_OP_SOLVE_MLP_START",
                (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL");
    return;
  case GAS_OP_SOLVE_MLP_MLP_STOP:
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Solver notifies `%s' with result `%s'\n",
               "GAS_OP_SOLVE_MLP_STOP",
               (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL");
    return;
  case GAS_OP_SOLVE_UPDATE_NOTIFICATION_START:
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Solver notifies `%s' with result `%s'\n",
               "GAS_OP_SOLVE_UPDATE_NOTIFICATION_START",
               (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL");
    return;
  case GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP:
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Solver notifies `%s' with result `%s'\n",
               "GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP",
               (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL");
    return;
  default:
    break;
  }
}


/**
 * Callback for solver to notify about assignment changes
 *
 * @param cls NULL
 * @param address the address with changes
 */
static void
bandwidth_changed_cb (void *cls,
		      struct ATS_Address *address)
{
  uint32_t diff_out;
  uint32_t diff_in;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Bandwidth assignment changed for peer %s \n",
              GNUNET_i2s (&address->peer));

  /* Notify performance clients about changes to address */
  GAS_performance_notify_all_clients (&address->peer,
				      address->plugin,
				      address->addr,
				      address->addr_len,
				      address->active,
				      address->atsi,
				      address->atsi_count,
				      GNUNET_BANDWIDTH_value_init (address->assigned_bw_out),
				      GNUNET_BANDWIDTH_value_init (address->assigned_bw_in));

  if ( (0 == address->assigned_bw_in) &&
       (0 == address->assigned_bw_out) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
               "Telling transport to disconnect peer `%s'\n",
                GNUNET_i2s (&address->peer));

    /* Notify scheduling clients about suggestion */
    GAS_scheduling_transmit_address_suggestion (&address->peer,
                                                address->session_id,
                                                GNUNET_BANDWIDTH_ZERO,
                                                GNUNET_BANDWIDTH_ZERO);
    return;
  }

  /* Do bandwidth stability check */
  diff_out = abs (address->assigned_bw_out - address->last_notified_bw_out);
  diff_in = abs (address->assigned_bw_in - address->last_notified_bw_in);

  if ( (diff_out < htonl(GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__)) &&
       (diff_in < htonl(GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__)) )
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Sending bandwidth update for peer `%s': %u/%u\n",
              GNUNET_i2s (&address->peer),
              address->assigned_bw_out,
              address->assigned_bw_out);

  /* *Notify scheduling clients about suggestion */
  GAS_scheduling_transmit_address_suggestion (&address->peer,
                                              address->session_id,
                                              GNUNET_BANDWIDTH_value_init (address->assigned_bw_out),
                                              GNUNET_BANDWIDTH_value_init (address->assigned_bw_in));

  address->last_notified_bw_out = address->assigned_bw_out;
  address->last_notified_bw_in = address->assigned_bw_in;
}


/**
 * Convert quota from text to numeric value.
 *
 * @param quota_str the value found in the configuration
 * @param direction direction of the quota
 * @param network network the quota applies to
 * @return numeric quota value to use
 */
static unsigned long long
parse_quota (const char *quota_str,
             const char *direction,
             enum GNUNET_ATS_Network_Type network)
{
  int res;
  unsigned long long ret;

  res = GNUNET_NO;
  if (0 == strcmp (quota_str, GNUNET_ATS_MaxBandwidthString))
  {
    ret = GNUNET_ATS_MaxBandwidth;
    res = GNUNET_YES;
  }
  if ((GNUNET_NO == res) &&
      (GNUNET_OK ==
       GNUNET_STRINGS_fancy_size_to_bytes (quota_str,
                                           &ret)))
    res = GNUNET_YES;
  if ((GNUNET_NO == res) &&
      (1 ==
       sscanf (quota_str,
               "%llu",
               &ret)))
    res = GNUNET_YES;
  if (GNUNET_NO == res)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not load %s quota for network `%s':  `%s', assigning default bandwidth %llu\n"),
                direction,
                GNUNET_ATS_print_network_type (network),
                quota_str,
                GNUNET_ATS_DefaultBandwidth);
    ret = GNUNET_ATS_DefaultBandwidth;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("%s quota configured for network `%s' is %llu\n"),
                direction,
                GNUNET_ATS_print_network_type (network),
                ret);
  }
  return ret;
}


/**
 * Load quota value from the configuration @a cfg for the
 * given network @a type and @a direction.
 *
 * @param cfg configuration to parse
 * @param type network type to parse for
 * @param direction traffic direction to parse for
 * @return quota to apply
 */
static unsigned long long
load_quota (const struct GNUNET_CONFIGURATION_Handle *cfg,
            enum GNUNET_ATS_Network_Type type,
            const char *direction)
{
  char *entry;
  char *quota_str;
  unsigned long long ret;

  GNUNET_asprintf (&entry,
                   "%s_QUOTA_%s",
                   GNUNET_ATS_print_network_type (type),
                   direction);
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "ats",
                                             entry,
                                             &quota_str))
  {
    ret = parse_quota (quota_str,
                       direction,
                       type);
    GNUNET_free (quota_str);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("No %s-quota configured for network `%s', assigning default bandwidth %llu\n"),
                direction,
                GNUNET_ATS_print_network_type (type),
                GNUNET_ATS_DefaultBandwidth);
    ret = GNUNET_ATS_DefaultBandwidth;
  }
  GNUNET_free (entry);
  return ret;
}


/**
 * Load quotas for networks from configuration
 *
 * @param cfg configuration handle
 * @param out_dest where to write outbound quotas
 * @param in_dest where to write inbound quotas
 * @param dest_length length of inbound and outbound arrays
 * @return number of networks loaded
 */
static unsigned int
load_quotas (const struct GNUNET_CONFIGURATION_Handle *cfg,
             unsigned long long *out_dest,
             unsigned long long *in_dest,
             int dest_length)
{
  unsigned int c;

  for (c = 0; (c < GNUNET_ATS_NetworkTypeCount) && (c < dest_length); c++)
  {
    in_dest[c] = load_quota (cfg,
                             c,
                             "out");
    out_dest[c] = load_quota (cfg,
                              c,
                              "in");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Loaded quota for network `%s' (in/out): %llu %llu\n",
                GNUNET_ATS_print_network_type (c),
                in_dest[c],
                out_dest[c]);
  }
  return c;
}


/**
 * Initialize plugins subsystem.
 *
 * @param cfg configuration to use
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error (failed to load
 *         solver plugin)
 */
int
GAS_plugin_init (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *mode_str;

  /* Figure out configured solution method */
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "ats",
                                             "MODE",
                                             &mode_str))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "No resource assignment method configured, using proportional approach\n");
    mode_str = GNUNET_strdup ("proportional");
  }
  env.cls = NULL;
  env.info_cb = &solver_info_cb;
  env.bandwidth_changed_cb = &bandwidth_changed_cb;
  env.get_preferences = &GAS_preference_get_by_peer;
  env.get_connectivity = &GAS_connectivity_has_peer;
  env.cfg = cfg;
  env.stats = GSA_stats;
  env.addresses = GSA_addresses;
  env.network_count = GNUNET_ATS_NetworkTypeCount;
  load_quotas (cfg,
               env.out_quota,
               env.in_quota,
               GNUNET_ATS_NetworkTypeCount);
  GNUNET_asprintf (&plugin,
                   "libgnunet_plugin_ats_%s",
                   mode_str);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Initializing solver `%s'\n",
              mode_str);
  GNUNET_free (mode_str);
  if (NULL == (sf = GNUNET_PLUGIN_load (plugin, &env)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to initialize solver `%s'!\n"),
                plugin);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Shutdown address subsystem.
 */
void
GAS_plugin_done ()
{
  GNUNET_PLUGIN_unload (plugin,
                        sf);
  sf = NULL;
  GNUNET_free (plugin);
  plugin = NULL;
}


/**
 * Tell the solver that the given address can now be used
 * for talking to the respective peer.
 *
 * @param new_address the new address
 * @param addr_net network scope the address is in
 */
void
GAS_plugin_new_address (struct ATS_Address *new_address,
			enum GNUNET_ATS_Network_Type addr_net)
{
  sf->s_add (sf->cls,
             new_address,
             addr_net);
}


/**
 * Tell the solver that the given address is no longer valid
 * can cannot be used any longer.
 *
 * @param address address that was deleted
 */
void
GAS_plugin_delete_address (struct ATS_Address *address)
{
  sf->s_del (sf->cls,
             address);
}


/**
 * Tell the solver that the given client has expressed its
 * appreciation for the past performance of a given connection.
 *
 * @param application client providing the feedback
 * @param peer peer the feedback is about
 * @param scope timeframe the feedback applies to
 * @param kind performance property the feedback relates to
 * @param score_abs degree of the appreciation
 */
void
GAS_plugin_notify_feedback (struct GNUNET_SERVER_Client *application,
                            const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_TIME_Relative scope,
                            enum GNUNET_ATS_PreferenceKind kind,
                            float score_abs)
{
  sf->s_feedback (sf->cls,
                  application,
                  peer,
                  scope,
                  kind,
                  score_abs);
}


/**
 * Stop instant solving, there are many state updates
 * happening in bulk right now.
 */
void
GAS_plugin_solver_lock ()
{
  sf->s_bulk_start (sf->cls);
}


/**
 * Resume instant solving, we are done with the bulk state updates.
 */
void
GAS_plugin_solver_unlock ()
{
  sf->s_bulk_start (sf->cls);
}


/**
 * Notify the plugin that a request to connect to
 * a particular peer was given to us.
 *
 * @param pid identity of peer we now care about
 */
void
GAS_plugin_request_connect_start (const struct GNUNET_PeerIdentity *pid)
{
  sf->s_get (sf->cls,
             pid);
}


/**
 * Notify the plugin that a request to connect to
 * a particular peer was dropped.
 *
 * @param pid identity of peer we care now less about
 */
void
GAS_plugin_request_connect_stop (const struct GNUNET_PeerIdentity *pid)
{
  sf->s_get_stop (sf->cls,
                  pid);
}


/* end of gnunet-service-ats_plugins.c */
