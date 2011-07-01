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
 * @file nat/nat_test.c
 * @brief functions to test if the NAT configuration is successful at achieving NAT traversal (with the help of a gnunet-nat-server)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_nat_lib.h"
#include "nat.h"


/**
 * Handle to a NAT test.
 */
struct GNUNET_NAT_Test
{
  GNUNET_NAT_TestCallback report;
  
  void *report_cls;
};


/**
 * Start testing if NAT traversal works using the
 * given configuration (IPv4-only).
 *
 * @param cfg configuration for the NAT traversal
 * @param is_tcp GNUNET_YES to test TCP, GNUNET_NO to test UDP
 * @param bnd_port port to bind to
 * @param adv_port externally advertised port to use
 * @param report function to call with the result of the test
 * @param report_cls closure for report
 * @return handle to cancel NAT test
 */
struct GNUNET_NAT_Test *
GNUNET_NAT_test_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
		       int is_tcp,
		       uint16_t bnd_port,
		       uint16_t adv_port,
		       GNUNET_NAT_TestCallback report,
		       void *report_cls)
{
  return NULL;
}


/**
 * Stop an active NAT test.
 *
 * @param tst test to stop.
 */
void
GNUNET_NAT_test_stop (struct GNUNET_NAT_Test *tst)
{
  GNUNET_free (tst);
}

/* end of nat_test.c */
