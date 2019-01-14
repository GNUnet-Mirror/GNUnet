/*
 This file is part of GNUnet.
 Copyright (C) 2010-2015, 2018 GNUnet e.V.

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

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file
 * Bandwidth allocation API for the transport service
 *
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 * @defgroup ats  ATS service
 * Bandwidth allocation for transport service
 *
 * @see [Documentation](https://gnunet.org/ats-subsystem)
 *
 * @{
 */
#ifndef GNUNET_ATS_TRANSPORT_SERVICE_H
#define GNUNET_ATS_TRANSPORT_SERVICE_H

#include "gnunet_constants.h"
#include "gnunet_util_lib.h"
#include "gnunet_nt_lib.h"
#include "gnunet_transport_communication_service.h"


/**
 * ATS performance characteristics for a session.
 */
struct GNUNET_ATS_Properties
{

  /**
   * Delay.  Time between when the time packet is sent and the packet
   * arrives.  FOREVER if we did not (successfully) measure yet.
   */
  struct GNUNET_TIME_Relative delay;

  /**
   * Confirmed successful payload on this connection from this peer to
   * the other peer.
   *
   * Unit: [bytes/second]
   */
  uint32_t goodput_out;

  /**
   * Confirmed useful payload on this connection to this peer from
   * the other peer.
   *
   * Unit: [bytes/second]
   */
  uint32_t goodput_in;

  /**
   * Actual traffic on this connection from this peer to the other peer.
   * Includes transport overhead.
   *
   * Unit: [bytes/second]
   */
  uint32_t utilization_out;

  /**
   * Actual traffic on this connection from the other peer to this peer.
   * Includes transport overhead.
   *
   * Unit: [bytes/second]
   */
  uint32_t utilization_in;

  /**
   * Distance on network layer (required for distance-vector routing)
   * in hops.  Zero for direct connections (i.e. plain TCP/UDP).
   */
  uint32_t distance;

  /**
   * MTU of the network layer, UINT32_MAX for no MTU (stream).
   *
   * Unit: [bytes]
   */
  uint32_t mtu;

  /**
   * Which network scope does the respective address belong to?
   */
  enum GNUNET_NetworkType nt;

  /**
   * What characteristics does this communicator have?
   */
  enum GNUNET_TRANSPORT_CommunicatorCharacteristics cc;

};


/* ******************************** Transport API ***************************** */

/**
 * Handle to the ATS subsystem for bandwidth/transport transport information.
 */
struct GNUNET_ATS_TransportHandle;

/**
 * Opaque session handle, to be defined by transport.  Contents not known to ATS.
 */
struct GNUNET_ATS_Session;


/**
 * Signature of a function called by ATS with the current bandwidth
 * allocation to be used as determined by ATS.
 *
 * @param cls closure
 * @param session session this is about
 * @param bandwidth_out assigned outbound bandwidth for the connection,
 *        0 to signal disconnect
 * @param bandwidth_in assigned inbound bandwidth for the connection,
 *        0 to signal disconnect
 */
typedef void
(*GNUNET_ATS_AllocationCallback) (void *cls,
                                  struct GNUNET_ATS_Session *session,
                                  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                                  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in);


/**
 * Signature of a function called by ATS suggesting transport to
 * try connecting with a particular address.
 *
 * @param cls closure
 * @param pid target peer
 * @param address the address to try
 */
typedef void
(*GNUNET_ATS_SuggestionCallback) (void *cls,
                                  const struct GNUNET_PeerIdentity *pid,
                                  const char *address);


/**
 * Initialize the ATS transport subsystem.
 *
 * @param cfg configuration to use
 * @param alloc_cb notification to call whenever the allocation changed
 * @param alloc_cb_cls closure for @a alloc_cb
 * @param suggest_cb notification to call whenever the suggestation is made
 * @param suggest_cb_cls closure for @a suggest_cb
 * @return ats context
 */
struct GNUNET_ATS_TransportHandle *
GNUNET_ATS_transport_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           GNUNET_ATS_AllocationCallback alloc_cb,
                           void *alloc_cb_cls,
                           GNUNET_ATS_SuggestionCallback suggest_cb,
                           void *suggest_cb_cls);


/**
 * Client is done with ATS transport, release resources.
 *
 * @param ath handle to release
 */
void
GNUNET_ATS_transport_done (struct GNUNET_ATS_TransportHandle *ath);


/**
 * Handle used within ATS to track an session.
 */
struct GNUNET_ATS_SessionRecord;


/**
 * We have a new session ATS should know. Sessiones have to be added with this
 * function before they can be: updated, set in use and destroyed
 *
 * @param ath handle
 * @param pid peer we connected to
 * @param address the address (human readable version),
 * @param session transport-internal handle for the session/queue, NULL if
 *        the session is inbound-only
 * @param prop performance data for the session
 * @return handle to the session representation inside ATS, NULL
 *         on error (i.e. ATS knows this exact session already, or
 *         session is invalid)
 */
struct GNUNET_ATS_SessionRecord *
GNUNET_ATS_session_add (struct GNUNET_ATS_TransportHandle *ath,
                        const struct GNUNET_PeerIdentity *pid,
                        const char *address,
                        struct GNUNET_ATS_Session *session,
                        const struct GNUNET_ATS_Properties *prop);


/**
 * We have updated performance statistics for a given session.  Based
 * on the information provided, ATS may update bandwidth assignments.
 *
 * @param ar session record to update information for
 * @param prop performance data for the session
 */
void
GNUNET_ATS_session_update (struct GNUNET_ATS_SessionRecord *ar,
                           const struct GNUNET_ATS_Properties *prop);


/**
 * A session was destroyed, ATS should now schedule and
 * allocate under the assumption that this @a ar is no
 * longer in use.
 *
 * @param ar session record to drop
 */
void
GNUNET_ATS_session_del (struct GNUNET_ATS_SessionRecord *ar);


#endif

/** @} */  /* end of group */

/* end of file gnunet-service-transport_ats.h */
