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
 * @file transport/gnunet-service-transport_plugins.h
 * @brief plugin management API
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_PLUGINS_H
#define GNUNET_SERVICE_TRANSPORT_PLUGINS_H

#include "gnunet_statistics_service.h"
#include "gnunet_transport_plugins.h"
#include "gnunet_util_lib.h"


/**
 *
 */
int 
GST_plugins_load (GNUNET_TRANSPORT_PluginReceiveCallback recv_cb,
		  GNUNET_TRANSPORT_AddressNotification address_cb,
		  GNUNET_TRANSPORT_TrafficReport traffic_cb,
		  GNUNET_TRANSPORT_SessionEnd session_end_cb,
		  GNUNET_TRANSPORT_CostReport cost_cb);


/**
 *
 */
int 
GST_plugins_unload (void);


/**
 *
 */
struct GNUNET_TRANSPORT_PluginFunctions *
GST_plugins_find (const char *name);



#endif
/* end of file gnunet-service-transport_plugins.h */
