/*
 This file is part of GNUnet
 Copyright (C) 2009-2015, 2018 GNUnet e.V.

 GNUnet is free software: you can redistribute it and/or modify it
 under the terms of the GNU Affero General Public License as published
 by the Free Software Foundation, either version 3 of the License,
 or (at your option) any later version.

 GNUnet is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @author Christian Grothoff
 *
 * @file
 * API for the ATS solvers.
 *
 * @defgroup ats-plugin  ATS service plugin API
 * Plugin API for the ATS service.
 *
 * Specifies the struct that is given to the plugin's entry method and the other
 * struct that must be returned.  Note that the destructors of ATS plugins will
 * be given the value returned by the constructor and is expected to return a
 * NULL pointer.
 *
 * @{
 */
#ifndef PLUGIN_ATS_H
#define PLUGIN_ATS_H

#include "gnunet_mq_lib.h"
#include "gnunet_bandwidth_lib.h"
#include "gnunet_ats_application_service.h"
#include "gnunet_ats_transport_service.h"
#include "gnunet_statistics_service.h"


/**
 * Preference being expressed by an application client.
 */
struct GNUNET_ATS_Preference {

  /**
   * Peer to get address suggestions for.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * How much bandwidth in bytes/second does the application expect?
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw;

  /**
   * What type of performance preference does the client have?
   */
  enum GNUNET_MQ_PreferenceKind pk;
};


/**
 * Opaque representation of a session the plugin can allocate bandwidth for.
 */
struct GNUNET_ATS_Session;

/**
 * Plugin-relevant information about a session.
 */
struct GNUNET_ATS_SessionData {

  /**
   * Peer the session is with.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * ATS performance characteristics for a session.
   */
  struct GNUNET_ATS_Properties prop;

  /**
   * Handle to the session that has the given properties.
   */
  struct GNUNET_ATS_Session *session;
  
  /**
   * Is the session inbound only?
   */
  int inbound_only;
  
};

/**
 * Internal representation of a preference by the plugin.
 * (If desired, plugin may just use NULL.)
 */
struct GNUNET_ATS_PreferenceHandle;

/**
 * Internal representation of a session by the plugin.
 * (If desired, plugin may just use NULL.)
 */
struct GNUNET_ATS_SessionHandle;


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
   * The plugin should begin to respect a new preference.
   *
   * @param cls the closure
   * @param pref the preference to add
   * @return plugin's internal representation, or NULL
   */
  struct GNUNET_ATS_PreferenceHandle *
  (*preference_add)(void *cls,
		    const struct GNUNET_ATS_Preference *pref);

  /**
   * The plugin should end respecting a preference.
   *
   * @param cls the closure
   * @param ph whatever @e preference_add returned 
   * @param pref the preference to delete
   * @return plugin's internal representation, or NULL
   */
  void
  (*preference_del)(void *cls,		    
		    struct GNUNET_ATS_PreferenceHandle *ph,
		    const struct GNUNET_ATS_Preference *pref);


  struct GNUNET_ATS_SessionHandle *
  (*session_add)(void *cls,
		 const struct GNUNET_ATS_SessionData *data);

  void
  (*session_update)(void *cls,
		    struct GNUNET_ATS_SessionHandle *sh,
		    const struct GNUNET_ATS_SessionData *data);

  void
  (*session_del)(void *cls,
		 struct GNUNET_ATS_SessionHandle *sh,
		 const struct GNUNET_ATS_SessionData *data);
  
};

#endif

/** @} */  /* end of group */
