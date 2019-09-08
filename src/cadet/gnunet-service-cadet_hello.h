/*
     This file is part of GNUnet.
     Copyright (C) 2014, 2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet_hello.h
 * @brief cadet service; dealing with hello messages
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 *
 * All functions in this file should use the prefix GCH (Gnunet Cadet Hello)
 */

#ifndef GNUNET_SERVICE_CADET_HELLO_H
#define GNUNET_SERVICE_CADET_HELLO_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"


/**
 * Initialize the hello subsystem.
 *
 * @param c Configuration.
 */
void
GCH_init(const struct GNUNET_CONFIGURATION_Handle *c);


/**
 * Shut down the hello subsystem.
 */
void
GCH_shutdown(void);


/**
 * Get own hello message.
 *
 * @return Own hello message.
 */
const struct GNUNET_HELLO_Message *
GCH_get_mine(void);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CADET_SERVICE_HELLO_H */
#endif
/* end of gnunet-cadet-service_hello.h */
