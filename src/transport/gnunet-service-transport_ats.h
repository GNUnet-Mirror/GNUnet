/*
     This file is part of GNUnet.
     (C) 2015 Christian Grothoff (and other contributing authors)

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
 *
 * FIXME:
 * - add API to give ATS feedback about an address that was
 *   suggested but did not work out (without fully 'deleting'
 *   it forever)
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
 * Notify ATS about the new address including the network this address is
 * located in.
 *
 * @param address the address
 * @param session the session
 * @param ats ats information
 * @param ats_count number of @a ats information
 */
void
GST_ats_add_address (const struct GNUNET_HELLO_Address *address,
                     struct Session *session,
                     const struct GNUNET_ATS_Information *ats,
                     uint32_t ats_count);


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
 * Notify ATS about a new session now being in use (or not).
 *
 * @param address the address
 * @param session the session
 * @param in_use #GNUNET_YES or #GNUNET_NO
 */
void
GST_ats_set_in_use (const struct GNUNET_HELLO_Address *address,
                    struct Session *session,
                    int in_use);


/**
 * Notify ATS about property changes to an address
 *
 * @param address the address
 * @param session the session
 * @param ats performance information
 * @param ats_count number of elements in @a ats
 */
void
GST_ats_update_metrics (const struct GNUNET_HELLO_Address *address,
			struct Session *session,
			const struct GNUNET_ATS_Information *ats,
			uint32_t ats_count);


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
