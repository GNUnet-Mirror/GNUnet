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
 * @file transport/gnunet-service-transport_hello.h
 * @brief hello API
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_HELLO_H
#define GNUNET_SERVICE_TRANSPORT_HELLO_H

#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_util_lib.h"


/**
 *
 */
void 
GST_hello_start (void);

/**
 *
 */
void
GST_hello_stop (void);

/**
 *
 */
const struct GNUNET_MessageHeader *
GST_hello_get (void);

/**
 *
 */
void
GST_hello_modify_addresses (int addremove,
			    const char *plugin_name,
			    const void *plugin_address,
			    size_t plugin_address_len);

/**
 *
 */
int
GST_hello_test_address (const char *plugin_name,
			const void *plugin_address,
			size_t plugin_address_len);


#endif
/* end of file gnunet-service-transport_hello.h */
