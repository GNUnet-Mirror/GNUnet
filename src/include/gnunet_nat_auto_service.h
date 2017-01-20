/*
     This file is part of GNUnet.
     Copyright (C) 2007-2017 GNUnet e.V.

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
 * @author Christian Grothoff
 * @author Milan Bouchet-Valat
 *
 * @file
 * Service for testing and autoconfiguration of
 * NAT traversal functionality
 *
 * @defgroup nat  NAT testing library
 *
 * @{
 */

#ifndef GNUNET_NAT_AUTO_SERVICE_H
#define GNUNET_NAT_AUTO_SERVICE_H

#include "gnunet_util_lib.h"
#include "gnunet_nat_service.h"


/**
 * Handle to a NAT test.
 */
struct GNUNET_NAT_AUTO_Test;


/**
 * Start testing if NAT traversal works using the given configuration.
 *  The transport adapters should be down while using this function.
 *
 * @param cfg configuration for the NAT traversal
 * @param proto protocol to test, i.e. IPPROTO_TCP or IPPROTO_UDP
 * @param section_name configuration section to use for configuration
 * @param report function to call with the result of the test
 * @param report_cls closure for @a report
 * @return handle to cancel NAT test
 */
struct GNUNET_NAT_AUTO_Test *
GNUNET_NAT_AUTO_test_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
			    uint8_t proto,
			    const char *section_name,
			    GNUNET_NAT_TestCallback report,
			    void *report_cls);


/**
 * Stop an active NAT test.
 *
 * @param tst test to stop.
 */
void
GNUNET_NAT_AUTO_test_stop (struct GNUNET_NAT_AUTO_Test *tst);


/**
 * Handle to auto-configuration in progress.
 */
struct GNUNET_NAT_AUTO_AutoHandle;


/**
 * Converts `enum GNUNET_NAT_StatusCode` to string
 *
 * @param err error code to resolve to a string
 * @return point to a static string containing the error code
 */
const char *
GNUNET_NAT_AUTO_status2string (enum GNUNET_NAT_StatusCode err);


/**
 * Function called with the result from the autoconfiguration.
 *
 * @param cls closure
 * @param diff minimal suggested changes to the original configuration
 *             to make it work (as best as we can)
 * @param result #GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 * @param type what the situation of the NAT
 */
typedef void
(*GNUNET_NAT_AUTO_AutoResultCallback)(void *cls,
				      const struct GNUNET_CONFIGURATION_Handle *diff,
				      enum GNUNET_NAT_StatusCode result,
				      enum GNUNET_NAT_Type type);


/**
 * Start auto-configuration routine.  The transport adapters should
 * be stopped while this function is called.
 *
 * @param cfg initial configuration
 * @param cb function to call with autoconfiguration result
 * @param cb_cls closure for @a cb
 * @return handle to cancel operation
 */
struct GNUNET_NAT_AUTO_AutoHandle *
GNUNET_NAT_AUTO_autoconfig_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
				  GNUNET_NAT_AUTO_AutoResultCallback cb,
				  void *cb_cls);


/**
 * Abort autoconfiguration.
 *
 * @param ah handle for operation to abort
 */
void
GNUNET_NAT_AUTO_autoconfig_cancel (struct GNUNET_NAT_AUTO_AutoHandle *ah);


#endif

/** @} */  /* end of group */

/* end of gnunet_nat_auto_service.h */
