/*
 This file is part of GNUnet.
 (C) 2011-2014 Christian Grothoff (and other contributing authors)

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
 * Configured ATS solver
 */
static int ats_mode;

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
GAS_normalized_preference_changed (const struct GNUNET_PeerIdentity *peer,
				   enum GNUNET_ATS_PreferenceKind kind,
				   double pref_rel)
{
  /* Tell solver about update */
  sf->s_pref (sf->cls, peer, kind, pref_rel);
}


/**
 * The relative value for a property changed
 *
 * @param address the peer
 * @param type the ATS type
 * @param prop_rel the new relative preference value
 */
void
GAS_normalized_property_changed (struct ATS_Address *address,
				 uint32_t type,
				 double prop_rel)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Normalized property %s for peer `%s' changed to %.3f \n",
	      GNUNET_ATS_print_property_type (type),
	      GNUNET_i2s (&address->peer),
	      prop_rel);
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
  switch (op)
  {
    case GAS_OP_SOLVE_START:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s' `%s'\n", "GAS_OP_SOLVE_START",
          (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL", add_info);
      return;
    case GAS_OP_SOLVE_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_STOP",
          (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL", add_info);
      return;

    case GAS_OP_SOLVE_SETUP_START:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_SETUP_START",
          (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL");
      return;

    case GAS_OP_SOLVE_SETUP_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_SETUP_STOP",
          (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL");
      return;

    case GAS_OP_SOLVE_MLP_LP_START:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_LP_START",
          (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL");
      return;
    case GAS_OP_SOLVE_MLP_LP_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_LP_STOP",
          (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL");
      return;

    case GAS_OP_SOLVE_MLP_MLP_START:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_MLP_START",
          (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL");
      return;
    case GAS_OP_SOLVE_MLP_MLP_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_MLP_STOP",
          (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL");
      return;
    case GAS_OP_SOLVE_UPDATE_NOTIFICATION_START:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_UPDATE_NOTIFICATION_START",
          (GAS_STAT_SUCCESS == status) ? "SUCCESS" : "FAIL");
      return;
    case GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP",
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

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Sending bandwidth update for peer `%s': %u %u\n",
      GNUNET_i2s (&address->peer), address->assigned_bw_out,
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
  char *entry_in = NULL;
  char *entry_out = NULL;
  char *quota_out_str;
  char *quota_in_str;
  int c;
  int res;

  for (c = 0; (c < GNUNET_ATS_NetworkTypeCount) && (c < dest_length); c++)
  {
    in_dest[c] = 0;
    out_dest[c] = 0;
    GNUNET_asprintf (&entry_out,
                     "%s_QUOTA_OUT",
                     GNUNET_ATS_print_network_type (c));
    GNUNET_asprintf (&entry_in,
                     "%s_QUOTA_IN",
                     GNUNET_ATS_print_network_type (c));

    /* quota out */
    if (GNUNET_OK
        == GNUNET_CONFIGURATION_get_value_string (cfg, "ats", entry_out,
            &quota_out_str))
    {
      res = GNUNET_NO;
      if (0 == strcmp (quota_out_str, GNUNET_ATS_MaxBandwidthString))
      {
        out_dest[c] = GNUNET_ATS_MaxBandwidth;
        res = GNUNET_YES;
      }
      if ((GNUNET_NO == res)
          && (GNUNET_OK
              == GNUNET_STRINGS_fancy_size_to_bytes (quota_out_str,
                  &out_dest[c])))
        res = GNUNET_YES;
      if ((GNUNET_NO == res)
          && (GNUNET_OK
              == GNUNET_CONFIGURATION_get_value_number (cfg, "ats", entry_out,
                  &out_dest[c])))
        res = GNUNET_YES;

      if (GNUNET_NO == res)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
                   _("Could not load quota for network `%s':  `%s', assigning default bandwidth %llu\n"),
                   GNUNET_ATS_print_network_type (c),
                   quota_out_str,
                   GNUNET_ATS_DefaultBandwidth);
        out_dest[c] = GNUNET_ATS_DefaultBandwidth;
      }
      else
      {
        GNUNET_log(GNUNET_ERROR_TYPE_INFO,
                   _("Outbound quota configure for network `%s' is %llu\n"),
                   GNUNET_ATS_print_network_type (c),
                   out_dest[c]);
      }
      GNUNET_free(quota_out_str);
    }
    else
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
                 _("No outbound quota configured for network `%s', assigning default bandwidth %llu\n"),
                 GNUNET_ATS_print_network_type (c),
                 GNUNET_ATS_DefaultBandwidth);
      out_dest[c] = GNUNET_ATS_DefaultBandwidth;
    }

    /* quota in */
    if (GNUNET_OK
        == GNUNET_CONFIGURATION_get_value_string (cfg, "ats", entry_in,
            &quota_in_str))
    {
      res = GNUNET_NO;
      if (0 == strcmp (quota_in_str, GNUNET_ATS_MaxBandwidthString))
      {
        in_dest[c] = GNUNET_ATS_MaxBandwidth;
        res = GNUNET_YES;
      }
      if ((GNUNET_NO == res)
          && (GNUNET_OK
              == GNUNET_STRINGS_fancy_size_to_bytes (quota_in_str, &in_dest[c])))
        res = GNUNET_YES;
      if ((GNUNET_NO == res)
          && (GNUNET_OK
              == GNUNET_CONFIGURATION_get_value_number (cfg, "ats", entry_in,
                  &in_dest[c])))
        res = GNUNET_YES;

      if (GNUNET_NO == res)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Could not load quota for network `%s':  `%s', assigning default bandwidth %llu\n"),
                    GNUNET_ATS_print_network_type (c),
                    quota_in_str,
                    GNUNET_ATS_DefaultBandwidth);
        in_dest[c] = GNUNET_ATS_DefaultBandwidth;
      }
      else
      {
        GNUNET_log(GNUNET_ERROR_TYPE_INFO,
                   _("Inbound quota configured for network `%s' is %llu\n"),
                   GNUNET_ATS_print_network_type (c),
                   in_dest[c]);
      }
      GNUNET_free(quota_in_str);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("No outbound quota configure for network `%s', assigning default bandwidth %llu\n"),
                  GNUNET_ATS_print_network_type (c),
                  GNUNET_ATS_DefaultBandwidth);
      in_dest[c] = GNUNET_ATS_DefaultBandwidth;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Loaded quota for network `%s' (in/out): %llu %llu\n",
                GNUNET_ATS_print_network_type (c),
                in_dest[c],
                out_dest[c]);
    GNUNET_free(entry_out);
    GNUNET_free(entry_in);
  }
  return GNUNET_ATS_NetworkTypeCount;
}


/**
 * Initialize plugins subsystem.
 *
 * @param cfg configuration to use
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error (failed to load
 *         solver plugin)
 */
int
GAS_plugins_init (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  unsigned long long quotas_in[GNUNET_ATS_NetworkTypeCount];
  unsigned long long quotas_out[GNUNET_ATS_NetworkTypeCount];
  char *mode_str;
  char *plugin_short;
  int c;

  /* Figure out configured solution method */
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "ats", "MODE", &mode_str))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
               "No resource assignment method configured, using proportional approach\n");
    ats_mode = MODE_PROPORTIONAL;
  }
  else
  {
    for (c = 0; c < strlen (mode_str); c++)
      mode_str[c] = toupper (mode_str[c]);
    if (0 == strcmp (mode_str, "PROPORTIONAL"))
      ats_mode = MODE_PROPORTIONAL;
    else if (0 == strcmp (mode_str, "MLP"))
    {
      ats_mode = MODE_MLP;
#if !HAVE_LIBGLPK
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
                 "Assignment method `%s' configured, but GLPK is not available, please install \n",
                 mode_str);
      ats_mode = MODE_PROPORTIONAL;
#endif
    }
    else if (0 == strcmp (mode_str, "RIL"))
      ats_mode = MODE_RIL;
    else
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
                 "Invalid resource assignment method `%s' configured, using proportional approach\n",
                 mode_str);
      ats_mode = MODE_PROPORTIONAL;
    }
    GNUNET_free(mode_str);
  }

  load_quotas (cfg,
               quotas_out,
               quotas_in,
               GNUNET_ATS_NetworkTypeCount);
  env.cls = NULL;
  env.info_cb = &solver_info_cb;
  env.bandwidth_changed_cb = &bandwidth_changed_cb;
  env.get_preferences = &GAS_normalization_get_preferences_by_peer;
  env.get_property = &GAS_normalization_get_properties;
  env.cfg = cfg;
  env.stats = GSA_stats;
  env.addresses = GSA_addresses;
  env.network_count = GNUNET_ATS_NetworkTypeCount;
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
    env.out_quota[c] = quotas_out[c];
    env.in_quota[c] = quotas_in[c];
  }

  switch (ats_mode) {
    case MODE_PROPORTIONAL:
      plugin_short = "proportional";
      break;
    case MODE_MLP:
      plugin_short = "mlp";
      break;
    case MODE_RIL:
      plugin_short = "ril";
      break;
    default:
      plugin_short = NULL;
      break;
  }
  GNUNET_asprintf (&plugin,
                   "libgnunet_plugin_ats_%s",
                   plugin_short);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Initializing solver `%s '`%s'\n",
              plugin_short,
              plugin);
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
GAS_plugins_done ()
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
 * @param atsi performance data for the address
 * @param atsi_count size of the @a atsi array
 */
void
GAS_plugin_new_address (struct ATS_Address *new_address,
			enum GNUNET_ATS_Network_Type addr_net,
			const struct GNUNET_ATS_Information *atsi,
			uint32_t atsi_count)
{
  sf->s_add (sf->cls, new_address, addr_net);
  sf->s_bulk_start (sf->cls);
  GAS_normalization_normalize_property (new_address,
					atsi,
					atsi_count);
  sf->s_bulk_stop (sf->cls);
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
  sf->s_del (sf->cls, address, GNUNET_NO);
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
GAS_plugin_preference_feedback (struct GNUNET_SERVER_Client *application,
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
  const struct ATS_Address *aa;

  aa = sf->s_get (sf->cls, pid);
  if (NULL == aa)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Cannot suggest address for peer `%s'\n",
		GNUNET_i2s (pid));
    return;
  }
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
	     "Suggesting address %p for peer `%s'\n",
	     aa,
	     GNUNET_i2s (pid));
  GAS_scheduling_transmit_address_suggestion (pid,
                                              aa->session_id,
                                              GNUNET_BANDWIDTH_value_init (aa->assigned_bw_out),
                                              GNUNET_BANDWIDTH_value_init (aa->assigned_bw_in));
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
  sf->s_get_stop (sf->cls, pid);
}


/* end of gnunet-service-ats_plugins.c */
