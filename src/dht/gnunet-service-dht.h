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
 * @file dht/gnunet-service-dht.h
 * @brief GNUnet DHT globals
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_DHT_H
#define GNUNET_SERVICE_DHT_H

#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"

#define DEBUG_DHT GNUNET_EXTRA_LOGGING

/**
 * Configuration we use.
 */
extern const struct GNUNET_CONFIGURATION_Handle *GDS_cfg;

/**
 * Our handle to the BLOCK library.
 */
extern struct GNUNET_BLOCK_Context *GDS_block_context;

/**
 * Handle for the statistics service.
 */
extern struct GNUNET_STATISTICS_Handle *GDS_stats;

/**
 * Our HELLO
 */
extern struct GNUNET_MessageHeader *GDS_my_hello;

/**
 * Handle to the transport service, for getting our hello
 */
extern struct GNUNET_TRANSPORT_Handle *GDS_transport_handle;

#endif
