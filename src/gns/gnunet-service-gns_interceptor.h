/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2012 Christian Grothoff (and other contributing authors)

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
 * @file gns/gnunet-service-gns_interceptor.h
 * @brief GNUnet GNS service
 * @author Martin Schanzenbach
 */
#ifndef GNUNET_GNS_INTERCEPTOR_H
#define GNUNET_GNS_INTERCEPTOR_H

#include "gnunet_util_lib.h"


/**
 * Initialize DNS interceptor
 *
 * @param gnu_zone the zone we start lookups in
 * @param c the configuration
 * @return GNUNET_YES on success GNUNET_SYSERR on error
 */
int
GNS_interceptor_init (const struct GNUNET_CRYPTO_EcdsaPublicKey *gnu_zone,
		      const struct GNUNET_CONFIGURATION_Handle *c);

/**
 * Stops the interceptor
 */
void
GNS_interceptor_done (void);

#endif
