/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_ats_service.h
 * @brief automatic transport selection and outbound bandwidth determination
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 * TODO:
 * - move GNUNET_TRANSPORT_ATS* in here and rename...
 */
#ifndef GNUNET_ATS_SERVICE_H
#define GNUNET_ATS_SERVICE_H

#include "gnunet_constants.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"


/* ******************************** Scheduling API ***************************** */

/**
 * Handle to the ATS subsystem for bandwidth/transport scheduling information.
 */
struct GNUNET_ATS_SchedulingHandle;


/**
 * Opaque session handle, defined by plugins.  Contents not known to ATS.
 */
struct Session;


/**
 * Signature of a function called by ATS with the current bandwidth
 * and address preferences as determined by ATS.  
 *
 * @param cls closure
 * @param peer identity of the new peer
 * @param plugin_name name of the plugin, NULL if we have no suggestion
 * @param plugin_addr suggested address, NULL if we have no suggestion
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param session session to use
 * @param bandwidth_out assigned outbound bandwidth for the connection
 * @param bandwidth_in assigned inbound bandwidth for the connection
 * @param ats performance data for the address (as far as known)
 * @param ats_count number of performance records in 'ats'
 */
typedef void (*GNUNET_ATS_AddressSuggestionCallback) (void *cls,
                                                      const struct
                                                      GNUNET_PeerIdentity *
                                                      peer,
                                                      const char *plugin_name,
                                                      const void *plugin_addr,
                                                      size_t plugin_addr_len,
                                                      struct Session * session,
                                                      struct
                                                      GNUNET_BANDWIDTH_Value32NBO
                                                      bandwidth_out,
                                                      struct
                                                      GNUNET_BANDWIDTH_Value32NBO
                                                      bandwidth_in,
						      const struct
						      GNUNET_TRANSPORT_ATS_Information
						      * ats,
						      uint32_t ats_count);


/**
 * Initialize the ATS subsystem.
 *
 * @param cfg configuration to use
 * @param suggest_cb notification to call whenever the suggestation changed
 * @param suggest_cb_cls closure for 'suggest_cb'
 * @return ats context
 */
struct GNUNET_ATS_SchedulingHandle *
GNUNET_ATS_scheduling_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
			    GNUNET_ATS_AddressSuggestionCallback suggest_cb,
			    void *suggest_cb_cls);


/**
 * Client is done with ATS scheduling, release resources.
 *
 * @param sh handle to release
 */
void
GNUNET_ATS_scheduling_done (struct GNUNET_ATS_SchedulingHandle *sh);


/**
 * We would like to establish a new connection with a peer.  ATS
 * should suggest a good address to begin with.
 *
 * @param sh handle
 * @param peer identity of the peer we need an address for
 */
void
GNUNET_ATS_suggest_address (struct GNUNET_ATS_SchedulingHandle *sh,
                            const struct GNUNET_PeerIdentity *peer);


/**
 * We have updated performance statistics for a given address.  Note
 * that this function can be called for addresses that are currently
 * in use as well as addresses that are valid but not actively in use.
 * Furthermore, the peer may not even be connected to us right now (in
 * which case the call may be ignored or the information may be stored
 * for later use).  Update bandwidth assignments.
 *
 * @param sh handle
 * @param peer identity of the new peer
 * @param plugin_name name of the transport plugin
 * @param plugin_addr address  (if available)
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param session session handle (if available)
 * @param ats performance data for the address
 * @param ats_count number of performance records in 'ats'
 */
void
GNUNET_ATS_address_update (struct GNUNET_ATS_SchedulingHandle *sh,
                           const struct GNUNET_PeerIdentity *peer,
                           const char *plugin_name,
                           const void *plugin_addr, size_t plugin_addr_len,
			   struct Session *session,
                           const struct GNUNET_TRANSPORT_ATS_Information *ats,
                           uint32_t ats_count);


/**
 * A session got destroyed, stop including it as a valid address.
 *
 * @param sh handle
 * @param peer identity of the peer
 * @param plugin_name name of the transport plugin
 * @param plugin_addr address  (if available)
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param session session handle that is no longer valid (if available)
 */
void
GNUNET_ATS_address_destroyed (struct GNUNET_ATS_SchedulingHandle *sh,
                              const struct GNUNET_PeerIdentity *peer,
			      const char *plugin_name,
			      const void *plugin_addr, 
			      size_t plugin_addr_len,
			      struct Session *session);


/* ******************************** Performance API ***************************** */

/**
 * ATS Handle to obtain and/or modify performance information.
 */
struct GNUNET_ATS_PerformanceHandle;


/**
 * Signature of a function that is called with QoS information about a peer.
 *
 * @param cls closure
 * @param peer identity of the new peer
 * @param plugin_name name of the plugin, NULL if we have no suggestion
 * @param plugin_addr suggested address, NULL if we have no suggestion
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param bandwidth_out assigned outbound bandwidth for the connection
 * @param bandwidth_in assigned inbound bandwidth for the connection
 * @param ats performance data for the address (as far as known)
 * @param ats_count number of performance records in 'ats'
 */
typedef void (*GNUNET_ATS_PeerInformationCallback) (void *cls,
						    const struct
						    GNUNET_PeerIdentity *
						    peer,
						    const char *plugin_name,
						    const void *plugin_addr,
						    size_t plugin_addr_len,
						    struct
						    GNUNET_BANDWIDTH_Value32NBO
						    bandwidth_out,
						    struct
						    GNUNET_BANDWIDTH_Value32NBO
						    bandwidth_in,
						    const struct
						    GNUNET_TRANSPORT_ATS_Information
						    * ats,
						    uint32_t ats_count);


/**
 * Get handle to access performance API of the ATS subsystem.
 *
 * @param cfg configuration to use
 * @param infocb function to call on performance changes, can be NULL
 * @param infocb_cls closure for infocb
 * @return ats performance context
 */
struct GNUNET_ATS_PerformanceHandle *
GNUNET_ATS_performance_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
			     GNUNET_ATS_PeerInformationCallback infocb,
			     void *infocb_cls);


/**
 * Client is done using the ATS performance subsystem, release resources.
 *
 * @param ph handle
 */
void
GNUNET_ATS_performance_done (struct GNUNET_ATS_SchedulingHandle *ph);


/**
 * Function called with reservation result.
 *
 * @param cls closure
 * @param peer identifies the peer
 * @param amount set to the amount that was actually reserved or unreserved;
 *               either the full requested amount or zero (no partial reservations)
 * @param res_delay if the reservation could not be satisfied (amount was 0), how
 *        long should the client wait until re-trying?
 */
typedef void (*GNUNET_ATS_ReservationCallback) (void *cls,
						const struct
						GNUNET_PeerIdentity *
						peer,
						int32_t amount,
						struct
						GNUNET_TIME_Relative
						res_delay);



/**
 * Context that can be used to cancel a peer information request.
 */
struct GNUNET_ATS_ReservationContext;


/**
 * Reserve inbound bandwidth from the given peer.  ATS will look at
 * the current amount of traffic we receive from the peer and ensure
 * that the peer could add 'amount' of data to its stream.
 *
 * @param ph performance handle
 * @param peer identifies the peer
 * @param amount reserve N bytes for receiving, negative
 *                amounts can be used to undo a (recent) reservation;
 * @param info function to call with the resulting reservation information
 * @param info_cls closure for info
 * @return NULL on error
 * @deprecated will be replaced soon
 */
struct GNUNET_ATS_ReservationContext *
GNUNET_ATS_reserve_bandwidth (struct GNUNET_ATS_PerformanceHandle *ph,
			      const struct GNUNET_PeerIdentity *peer,
			      int32_t amount, 
			      GNUNET_ATS_ReservationCallback info, 
			      void *info_cls);


/**
 * Cancel request for reserving bandwidth.
 *
 * @param rc context returned by the original GNUNET_ATS_reserve_bandwidth call
 */
void
GNUNET_ATS_reserve_bandwidth_cancel (struct
				     GNUNET_ATS_ReservationContext *rc);



/**
 * Enum defining all known preference categories.
 */
enum GNUNET_ATS_PreferenceKind
{

  /**
   * End of preference list.
   */
  GNUNET_ATS_PREFERENCE_END = 0,

  /**
   * Change the peer's bandwidth value (value per byte of bandwidth in
   * the goal function) to the given amount.  The argument is followed
   * by a double value giving the desired value (can be negative).
   * Preference changes are forgotten if peers disconnect. 
   */
  GNUNET_ATS_PREFERENCE_BANDWIDTH,

  /**
   * Change the peer's latency value to the given amount.  The
   * argument is followed by a double value giving the desired value
   * (can be negative).  The absolute score in the goal function is
   * the inverse of the latency in ms (minimum: 1 ms) multiplied by
   * the latency preferences.
   */
  GNUNET_ATS_PREFERENCE_LATENCY

};

  
/**
 * Change preferences for the given peer. Preference changes are forgotten if peers
 * disconnect.
 * 
 * @param ph performance handle
 * @param peer identifies the peer
 * @param ... 0-terminated specification of the desired changes
 */
void
GNUNET_ATS_change_preference (struct GNUNET_ATS_PerformanceHandle *ph,
			      const struct GNUNET_PeerIdentity *peer,
			      ...);



#endif
/* end of file gnunet-service-transport_ats.h */
