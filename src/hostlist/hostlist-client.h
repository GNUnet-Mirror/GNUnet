/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file hostlist/hostlist-client.h
 * @brief hostlist support.  Downloads HELLOs via HTTP.
 * @author Christian Grothoff
 */

#ifndef HOSTLIST_CLIENT_H
#define HOSTLIST_CLIENT_H

#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_util_lib.h"
#include "gnunet_time_lib.h"

/**
 * Maximum number of hostlist that are saved
 */
#define MAX_NUMBER_HOSTLISTS 30

/**
 * Time intervall hostlists are saved to disk
 */
#define SAVING_INTERVALL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 30)

/**
 * Time interval between two hostlist tests
 */
#define TESTING_INTERVALL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)

/**
 * Time interval for download dispatcher before a download is re-scheduled
 */
#define WAITING_INTERVALL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * Defines concerning the hostlist quality metric
 */

/**
 * Initial quality of a new created hostlist
 */
#define HOSTLIST_INITIAL 10000

/**
 * Value subtracted each time a hostlist download fails
 */
#define HOSTLIST_FAILED_DOWNLOAD 100

/**
 * Value added each time a hostlist download is successful
 */
#define HOSTLIST_SUCCESSFUL_DOWNLOAD 100

/**
 * Value added for each valid HELLO recived during a hostlist download
 */
#define HOSTLIST_SUCCESSFUL_HELLO 1



/**
 * Start downloading hostlists from hostlist servers as necessary.
 *
 * @param c the configuration to use
 * @param st hande for publishing statistics
 * @param ch set to handler for connect notifications
 * @param dh set to handler for disconnect notifications
 * @param msgh set to handler for message handler notifications
 * @param learn set if client is learning new hostlists
 * @return GNUNET_OK on success
 */
int
GNUNET_HOSTLIST_client_start (const struct GNUNET_CONFIGURATION_Handle *c,
                              struct GNUNET_STATISTICS_Handle *st,
                              GNUNET_CORE_ConnectEventHandler *ch,
                              GNUNET_CORE_DisconnectEventHandler *dh,
                              GNUNET_CORE_MessageCallback *msgh, int learn);


/**
 * Stop downloading hostlists from hostlist servers as necessary.
 */
void
GNUNET_HOSTLIST_client_stop (void);


#endif
/* end of hostlist-client.h */
