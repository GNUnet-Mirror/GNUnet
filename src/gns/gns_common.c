/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 *
 * @file gns/gns_common.c
 * @brief helper functions shared between GNS service and block plugin
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gns_common.h"


/**
 * Compute the DHT key for a name in a zone.
 * DHT key is H(name) xor H(pubkey).
 *
 * @param name name of the record
 * @param zone GADS zone
 * @param key where to store the DHT key for records under this name in the given zone
 */
void 
GNUNET_GNS_get_key_for_record (const char *name,
			       const struct GNUNET_CRYPTO_ShortHashCode *zone,
			       struct GNUNET_HashCode *key)
{
  struct GNUNET_CRYPTO_ShortHashCode name_hash;
  struct GNUNET_HashCode name_hash_double;
  struct GNUNET_HashCode zone_hash_double;

  /* TODO 3) AB: New publishing
   * Create new key V = H(H(i,Q) * Q)
   */

  GNUNET_CRYPTO_short_hash (name,
			    strlen (name),
			    &name_hash);
  GNUNET_CRYPTO_short_hash_double (&name_hash, &name_hash_double);
  GNUNET_CRYPTO_short_hash_double (zone, &zone_hash_double);
  GNUNET_CRYPTO_hash_xor(&name_hash_double, &zone_hash_double, key);
}


/**
 * Compute the zone identifier from a given DHT key and record name.
 *
 * @param name name of the record
 * @param key DHT key of the record
 * @param zone set to the corresponding zone hash
 */
void 
GNUNET_GNS_get_zone_from_key (const char *name,
			      const struct GNUNET_HashCode *key,			       
			      struct GNUNET_CRYPTO_ShortHashCode *zone)
{
  struct GNUNET_CRYPTO_ShortHashCode name_hash;
  struct GNUNET_HashCode name_hash_double;
  struct GNUNET_HashCode zone_hash_double;

  GNUNET_CRYPTO_short_hash(name, strlen(name), &name_hash);
  GNUNET_CRYPTO_short_hash_double(&name_hash, &name_hash_double);
  GNUNET_CRYPTO_hash_xor(key, &name_hash_double, &zone_hash_double);
  GNUNET_CRYPTO_short_hash_from_truncation (&zone_hash_double, zone);
}			       


/* end of gns_common.c */
