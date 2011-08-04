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
 * @file transport/gnunet-service-transport_blacklist.h
 * @brief blacklisting API
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_BLACKLIST_H
#define GNUNET_SERVICE_TRANSPORT_BLACKLIST_H

#include "gnunet_statistics_service.h"
#include "gnunet_transport_blacklist.h"
#include "gnunet_util_lib.h"

/**
 *
 */
void
GST_blacklist_start (void);


/**
 *
 */
void
GST_blacklist_stop (void);


/**
 *
 */
void
GST_blacklist_handle_init (void *cls,
			   const struct GNUNET_SERVER_Client *client,
			   const struct GNUNET_MessageHeader *message);

/**
 *
 */
void
GST_blacklist_handle_reply (void *cls,
			    const struct GNUNET_SERVER_Client *client,
			    const struct GNUNET_MessageHeader *message);

/**
 *
 */
void
GST_blacklist_add_peer (const struct GNUNET_PeerIdentity *peer,
			const char *transport_name);
							

/**
 *
 */
int
GST_blacklist_test (const struct GNUNET_PeerIdentity *peer,
		    const char *transport_name);
		    				 


#endif
/* end of file gnunet-service-transport_blacklist.h */
