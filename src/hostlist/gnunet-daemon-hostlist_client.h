/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
 * @file hostlist/gnunet-daemon-hostlist_client.h
 * @brief hostlist support.  Downloads HELLOs via HTTP.
 * @author Christian Grothoff
 */
#ifndef GNUNET_DAEMON_HOSTLIST_CLIENT_H
#define GNUNET_DAEMON_HOSTLIST_CLIENT_H

#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_util_lib.h"


/**
 * Function that handles an advertised URI.
 *
 * @param uri 0-termianted URI of a hostlist
 */
typedef void
(*GNUNET_HOSTLIST_UriHandler)(const char *uri);


/**
 * Start downloading hostlists from hostlist servers as necessary.
 *
 * @param c configuration to use
 * @param st statistics handle to use
 * @param[out] ch set to handler for CORE connect events
 * @param[out] dh set to handler for CORE disconnect events
 * @param[out] msgh set to handler for CORE advertisement messages
 * @param learn should we learn hostlist URLs from CORE
 * @return #GNUNET_OK on success
 */
int
GNUNET_HOSTLIST_client_start (const struct GNUNET_CONFIGURATION_Handle *c,
                              struct GNUNET_STATISTICS_Handle *st,
                              GNUNET_CORE_ConnecTEventHandler *ch,
                              GNUNET_CORE_DisconnecTEventHandler *dh,
                              GNUNET_HOSTLIST_UriHandler *msgh,
                              int learn);


/**
 * Stop downloading hostlists from hostlist servers as necessary.
 */
void
GNUNET_HOSTLIST_client_stop (void);


#endif
/* end of gnunet-daemon-hostlist_client.h */
