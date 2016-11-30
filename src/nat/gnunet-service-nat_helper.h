/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2016 GNUnet e.V.

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
 * @file nat/gnunet-service-nat_helper.h
 * @brief runs the gnunet-helper-nat-server
 * @author Milan Bouchet-Valat
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"


/**
 * Information we keep per NAT helper process.
 */
struct HelperContext;


/**
 * Function called whenever we get a connection reversal
 * request from another peer.
 *
 * @param cls closure
 * @param ra IP address of the peer who wants us to connect to it 
 */
typedef void
(*GN_ReversalCallback) (void *cls,
			const struct sockaddr_in *ra);


/**
 * Start the gnunet-helper-nat-server and process incoming
 * requests.
 *
 * @param internal_address
 * @param cb function to call if we receive a request
 * @param cb_cls closure for @a cb
 * @return NULL on error
 */
struct HelperContext *
GN_start_gnunet_nat_server_ (const char *internal_address,
			     GN_ReversalCallback cb,
			     void *cb_cls);

			
/**
 * Start the gnunet-helper-nat-server and process incoming
 * requests.
 *
 * @param h helper context to stop
 */
void
GN_stop_gnunet_nat_server_ (struct HelperContext *h);


/* end of gnunet-service-nat_helper.h */
