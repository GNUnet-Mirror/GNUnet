/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 Christian Grothoff (and other contributing authors)

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
 * @file gns/gnunet-service-gns_shorten.h
 * @brief GNUnet GNS shortening API
 * @author Martin Schanzenbach
 */
#ifndef GNS_SHORTEN_H
#define GNS_SHORTEN_H
#include "gns.h"
#include "gnunet_dht_service.h"
#include "gnunet_namecache_service.h"
#include "gnunet_namestore_service.h"


/**
 * Initialize the shorten subsystem.
 * MUST be called before #GNS_shorten_start.
 *
 * @param nh handle to the namestore
 * @param nc the namecache handle
 * @param dht handle to the dht
 */
void
GNS_shorten_init (struct GNUNET_NAMESTORE_Handle *nh,
                  struct GNUNET_NAMECACHE_Handle *nc,
		  struct GNUNET_DHT_Handle *dht);


/**
 * Cleanup shorten: Terminate pending lookups
 */
void
GNS_shorten_done (void);


/**
 * Start shortening algorithm, try to allocate a nice short
 * canonical name for @a pub in @a shorten_zone, using
 * @a original_label as one possible suggestion.
 *
 * @param original_label original label for the zone
 * @param pub public key of the zone to shorten
 * @param shorten_zone private key of the target zone for the new record
 */
void
GNS_shorten_start (const char *original_label,
                   const char *suggested_label,
                   const struct GNUNET_CRYPTO_EcdsaPublicKey *pub,
                   const struct GNUNET_CRYPTO_EcdsaPrivateKey *shorten_zone);


#endif
