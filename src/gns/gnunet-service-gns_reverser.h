/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 GNUnet e.V.

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
 * @file gns/gnunet-service-gns_reverser.h
 * @brief GNUnet GNS service
 * @author Martin Schanzenbach
 */
#ifndef GNS_REVERSER_H
#define GNS_REVERSER_H
#include "gns.h"
#include "gnunet_gns_service.h"

/**
 * Handle for an active request.
 */
struct GNS_ReverserHandle;


/**
 * Function called with results for a GNS resolution.
 *
 * @param cls closure
 * @param rd_count number of records in @a rd
 * @param rd records returned for the lookup
 */
typedef void (*GNS_ReverseResultProcessor)(void *cls,
                                           const char *name);


/**
 * Reverse lookup of a specific zone
 * calls RecordLookupProcessor on result or timeout
 *
 * @param target the zone to perform the lookup in
 * @param authority the authority
 * @param proc the processor to call
 * @param proc_cls the closure to pass to @a proc
 * @return handle to cancel operation
 */
struct GNS_ReverserHandle *
GNS_reverse_lookup (const struct GNUNET_CRYPTO_EcdsaPublicKey *target,
                    const struct GNUNET_CRYPTO_EcdsaPublicKey *authority,
                    GNS_ReverseResultProcessor proc,
                    void *proc_cls);


/**
 * Cancel active resolution (i.e. client disconnected).
 *
 * @param rh resolution to abort
 */
void
GNS_reverse_lookup_cancel (struct GNS_ReverserHandle *rh);

#endif
