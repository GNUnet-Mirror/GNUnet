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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
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
 * Test if ATS knows about this @a address and @a session.
 * Note that even if the address is expired, we return
 * #GNUNET_YES if the respective session matches.
 *
 * @param address the address
 * @param session the session
 * @return #GNUNET_YES if @a address is known, #GNUNET_NO if not.
 */
int
GST_ats_is_known (const struct GNUNET_HELLO_Address *address,
                  struct Session *session);


/**
 * Test if ATS knows about this @a address.  Note that
 * expired addresses do not count.
 *
 * @param address the address
 * @return #GNUNET_YES if @a address is known, #GNUNET_NO if not.
 */
int
GST_ats_is_known_no_session (const struct GNUNET_HELLO_Address *address);


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
 * back-off timer for this address to zero.  Called when
 * an address was used to create a successful connection.
 *
 * @param address the address to reset the blocking timer
 * @param session the session (can be NULL)
 */
void
GST_ats_block_reset (const struct GNUNET_HELLO_Address *address,
                     struct Session *session);


/**
 * Notify ATS about a new inbound @a address. The @a address in
 * combination with the @a session must be new, but this function will
 * perform a santiy check.  If the @a address is indeed new, make it
 * available to ATS.
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
 * Notify ATS about a new address including the network this address is
 * located in.  The address must NOT be inbound and must be new to ATS.
 *
 * @param address the address
 * @param prop performance information
 */
void
GST_ats_add_address (const struct GNUNET_HELLO_Address *address,
                     const struct GNUNET_ATS_Properties *prop);


/**
 * Notify ATS about a new @a session now existing for the given
 * @a address.  Essentially, an outbound @a address was used
 * to establish a @a session.  It is safe to call this function
 * repeatedly for the same @a address and @a session pair.
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
 * Notify ATS about utilization changes to an @a address.
 * Does nothing if the @a address is not known to us.
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
 * Notify ATS about @a delay changes to properties of an @a address.
 * Does nothing if the @a address is not known to us.
 *
 * @param address the address
 * @param session the session
 * @param delay new delay value
 */
void
GST_ats_update_delay (const struct GNUNET_HELLO_Address *address,
                      struct GNUNET_TIME_Relative delay);


/**
 * Notify ATS about DV @a distance change to an @a address.
 * Does nothing if the @a address is not known to us.
 *
 * @param address the address
 * @param distance new distance value
 */
void
GST_ats_update_distance (const struct GNUNET_HELLO_Address *address,
                         uint32_t distance);


/**
 * Notify ATS that the @a session (but not the @a address) of
 * a given @a address is no longer relevant. (The @a session
 * went down.) This function may be called even if for the
 * respective outbound address #GST_ats_new_session() was
 * never called and thus the pair is unknown to ATS. In this
 * case, the call is simply ignored.
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
