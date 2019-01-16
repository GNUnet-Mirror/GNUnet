/*
     This file is part of GNUnet.
     Copyright (C) 2018 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/
/**
 * @file gns/gnunet-service-gns.h
 * @brief GNU Name System (main service)
 * @author Martin Schanzenbach
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_GNS_H
#define GNUNET_SERVICE_GNS_H


/**
 * Find GNS zone belonging to TLD @a tld.
 *
 * @param tld_str top-level domain to look up
 * @param[out] pkey public key to set
 * @return #GNUNET_YES if @a tld was found #GNUNET_NO if not
 */
int
GNS_find_tld (const char *tld_str,
              struct GNUNET_CRYPTO_EcdsaPublicKey *pkey);


/**
 * Obtain the TLD of the given @a name.
 *
 * @param name a name
 * @return the part of @a name after the last ".",
 *         or @a name if @a name does not contain a "."
 */
const char *
GNS_get_tld (const char *name);


#endif
