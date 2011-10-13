/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_addresses.c
 * @brief ats service address management
 * @author Matthias Wachs
 */
#ifndef GNUNET_SERVICE_ATS_ADDRESSES_H
#define GNUNET_SERVICE_ATS_ADDRESSES_H

#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h" // FIXME...

/**
 */
void
GAS_addresses_init (void);


/**
 */
void
GAS_addresses_done (void);


void
GAS_address_update (struct GNUNET_SERVER_Client *client,
		    const struct GNUNET_PeerIdentity *peer,
		    const char *plugin_name,
		    const void *plugin_addr, size_t plugin_addr_len,
		    uint32_t session_id,
		    const struct GNUNET_TRANSPORT_ATS_Information *atsi,
		    uint32_t atsi_count);

#endif
