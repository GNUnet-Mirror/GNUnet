/*
     This file is part of GNUnet.
     Copyright (C) 2015 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport_ats.h
 * @brief interfacing between transport and ATS service
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_ATS_H
#define GNUNET_SERVICE_TRANSPORT_ATS_H

#include "gnunet_ats_service.h"

/**
 * Initialize ATS subsystem.
 */
void
GST_ats_init (void);


/**
 * Shutdown ATS subsystem.
 */
void
GST_ats_done (void);


/**
 * Test if ATS knows about this address.
 *
 * @param address the address
 * @param session the session
 * @return #GNUNET_YES if address is known, #GNUNET_NO if not.
 */
int
GST_ats_is_known (const struct GNUNET_HELLO_Address *address,
                  struct Session *session);


/**
 * Temporarily block a valid address for use by ATS for address
 * suggestions.  This function should be called if an address was
 * suggested by ATS but failed to perform (i.e. failure to establish a
 * session or to exchange the PING/PONG).
 *
 * @param address the address to block
 * @param session the session (can be NULL)
 */
void
GST_ats_block_address (const struct GNUNET_HELLO_Address *address,
                       struct Session *session);


/**
 * Reset address blocking time.  Resets the exponential
 * back-off timer for this address to zero.  Done when
 * an address was used to create a successful connection.
 *
 * @param address the address to reset the blocking timer
 * @param session the session (can be NULL)
 */
void
GST_ats_block_reset (const struct GNUNET_HELLO_Address *address,
                     struct Session *session);


/**
 * Notify ATS about the a new inbound address.  We may already
 * know the address (as this is called each time we receive
 * a message from an inbound connection).  If the address is
 * indeed new, make it available to ATS.
 *
 * @param address the address
 * @param session the session
 * @param prop performance information
 */
void
GST_ats_add_inbound_address (const struct GNUNET_HELLO_Address *address,
                             struct Session *session,
                             const struct GNUNET_ATS_Properties *prop);


/**
 * Notify ATS about the new address including the network this address is
 * located in.  The address must NOT be inbound and must be new to ATS.
 *
 * @param address the address
 * @param prop performance information
 */
void
GST_ats_add_address (const struct GNUNET_HELLO_Address *address,
                     const struct GNUNET_ATS_Properties *prop);


/**
 * Notify ATS about a new session now existing for the given
 * address.
 *
 * @param address the address
 * @param session the session
 */
void
GST_ats_new_session (const struct GNUNET_HELLO_Address *address,
                     struct Session *session);


/**
 * Notify ATS about property changes to an address's properties.
 * FIXME: we probably want to split this one up for the different
 * updatable properties.
 *
 * @param address the address
 * @param session the session
 * @param prop updated performance information
 */
void
GST_ats_update_metrics (const struct GNUNET_HELLO_Address *address,
			struct Session *session,
			const struct GNUNET_ATS_Properties *prop);


/**
 * Notify ATS about utilization changes to an address.
 *
 * @param address our information about the address
 * @param bps_in new utilization inbound
 * @param bps_out new utilization outbound
 */
void
GST_ats_update_utilization (const struct GNUNET_HELLO_Address *address,
                            uint32_t bps_in,
                            uint32_t bps_out);


/**
 * Notify ATS about property changes to an address's properties.
 *
 * @param address the address
 * @param session the session
 * @param delay new delay value
 */
void
GST_ats_update_delay (const struct GNUNET_HELLO_Address *address,
                      struct GNUNET_TIME_Relative delay);


/**
 * Notify ATS about property changes to an address's properties.
 *
 * @param address the address
 * @param distance new distance value
 */
void
GST_ats_update_distance (const struct GNUNET_HELLO_Address *address,
                         uint32_t distance);


/**
 * Notify ATS that the session (but not the address) of
 * a given address is no longer relevant.
 *
 * @param address the address
 * @param session the session
 */
void
GST_ats_del_session (const struct GNUNET_HELLO_Address *address,
                     struct Session *session);


/**
 * Notify ATS that the address has expired and thus cannot
 * be used any longer.  This function must only be called
 * if the corresponding session is already gone.
 *
 * @param address the address
 */
void
GST_ats_expire_address (const struct GNUNET_HELLO_Address *address);


#endif
