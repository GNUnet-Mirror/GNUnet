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
 * @file dht/gnunet-service-dht_nse.h
 * @brief GNUnet DHT integration with NSE
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_DHT_NSE_H
#define GNUNET_SERVICE_DHT_NSE_H


/**
 * Return the log of the current network size estimate.
 *
 * @return log of NSE
 */
double
GDS_NSE_get (void);


/**
 * Initialize NSE subsystem.
 */
void
GDS_NSE_init (void);


/**
 * Shutdown NSE subsystem.
 */
void
GDS_NSE_done (void);

#endif
