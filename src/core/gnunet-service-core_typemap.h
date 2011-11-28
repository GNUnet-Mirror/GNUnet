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
 * @file core/gnunet-service-core_typemap.h
 * @brief management of map that specifies which message types this peer supports
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CORE_TYPEMAP_H
#define GNUNET_SERVICE_CORE_TYPEMAP_H

#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"

/**
 * Map specifying which message types a peer supports.
 */
struct GSC_TypeMap;


/**
 * Add a set of types to our type map.
 */
void
GSC_TYPEMAP_add (const uint16_t * types, unsigned int tlen);


/**
 * Remove a set of types from our type map.
 */
void
GSC_TYPEMAP_remove (const uint16_t * types, unsigned int tlen);


/**
 * Compute a type map message for this peer.
 *
 * @return this peers current type map message.
 */
struct GNUNET_MessageHeader *
GSC_TYPEMAP_compute_type_map_message (void);


/**
 * Extract a type map from a TYPE_MAP message.
 *
 * @param msg a type map message
 * @return NULL on error
 */
struct GSC_TypeMap *
GSC_TYPEMAP_get_from_message (const struct GNUNET_MessageHeader *msg);


/**
 * Test if any of the types from the types array is in the
 * given type map.
 *
 * @param tmap map to test
 * @param types array of types
 * @param tcnt number of entries in types
 * @return GNUNET_YES if a type is in the map, GNUNET_NO if not
 */
int
GSC_TYPEMAP_test_match (const struct GSC_TypeMap *tmap, const uint16_t * types,
                        unsigned int tcnt);


/**
 * Add additional types to a given typemap.
 *
 * @param tmap map to extend (not changed)
 * @param types array of types to add
 * @param tcnt number of entries in types
 * @return updated type map (fresh copy)
 */
struct GSC_TypeMap *
GSC_TYPEMAP_extend (const struct GSC_TypeMap *tmap, const uint16_t * types,
                    unsigned int tcnt);

/**
 * Create an empty type map.
 *
 * @return an empty type map
 */
struct GSC_TypeMap *
GSC_TYPEMAP_create (void);


/**
 * Free the given type map.
 *
 * @param tmap a type map
 */
void
GSC_TYPEMAP_destroy (struct GSC_TypeMap *tmap);


/**
 * Initialize typemap subsystem.
 */
void
GSC_TYPEMAP_init (void);


/**
 * Shutdown typemap subsystem.
 */
void
GSC_TYPEMAP_done (void);

#endif
/* end of gnunet-service-core_typemap.h */
