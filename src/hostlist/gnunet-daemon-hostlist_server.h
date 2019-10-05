/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
 * @file hostlist/gnunet-daemon-hostlist_server.h
 * @brief hostlist support.  Downloads HELLOs via HTTP.
 * @author Christian Grothoff
 */

#ifndef GNUNET_DAEMON_HOSTLIST_SERVER_H
#define GNUNET_DAEMON_HOSTLIST_SERVER_H

#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_util_lib.h"


/**
 * Start server offering our hostlist.
 *
 * @param c configuration to use
 * @param st statistics handle to use
 * @param co core handle to use
 * @param[out] server_ch set to handler for CORE connect events
 * @param advertise #GNUNET_YES if we should advertise our hostlist
 * @return #GNUNET_OK on success
 */
int
GNUNET_HOSTLIST_server_start (const struct GNUNET_CONFIGURATION_Handle *c,
                              struct GNUNET_STATISTICS_Handle *st,
                              struct GNUNET_CORE_Handle *core,
                              GNUNET_CORE_ConnectEventHandler *server_ch,
                              int advertise);


/**
 * Stop server offering our hostlist.
 */
void
GNUNET_HOSTLIST_server_stop (void);


#endif
/* end of gnunet-daemon-hostlist_server.h */
