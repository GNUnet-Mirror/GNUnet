/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013 GNUnet e.V.

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
 * @author Jeffrey Burdges
 *
 * @file
 * SOCKS proxy for connections
 *
 * @defgroup socks  SOCKS proxy
 * SOCKS proxy for connections.
 * @{
 */

#ifndef GNUNET_SOCKS_H
#define GNUNET_SOCKS_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"


/**
 * Check if a SOCKS proxy is required by a service.  Do not use local service
 * if a SOCKS proxy port is configured as this could deanonymize a user.
 *
 * @param service_name name of service to connect to
 * @param cfg configuration to use
 * @return GNUNET_YES if so, GNUNET_NO if not
 */
int
GNUNET_SOCKS_check_service (const char *service_name,
                            const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Try to connect to a service configured to use a SOCKS5 proxy.
 *
 * @param service_name name of service to connect to
 * @param cfg configuration to use
 * @return Connection handle that becomes usable when the handshake completes.
 *         NULL if SOCKS not configured or not configured properly
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_SOCKS_do_connect (const char *service_name,
                          const struct GNUNET_CONFIGURATION_Handle *cfg);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SOCKS_H */
#endif

/** @} */  /* end of group */

/* end of gnunet_socks.h */
