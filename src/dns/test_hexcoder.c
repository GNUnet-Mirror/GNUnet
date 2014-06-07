/*
     This file is part of GNUnet.
     (C) 2014 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 * @file dns/test_hexcoder.c
 * @brief test for #GNUNET_DNSPARSER_hex_to_bin() and
 *                 #GNUNET_DNSPARSER_bin_to_hex()
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dnsparser_lib.h"

#define TESTSTRING "Hello World!"


int
main (int argc,
      char *argv[])
{
  char buf[strlen (TESTSTRING)  + 1];
  char *ret;

  GNUNET_log_setup ("test-hexcoder", "WARNING", NULL);
  ret = GNUNET_DNSPARSER_bin_to_hex (TESTSTRING,
                                     strlen (TESTSTRING) + 1);
  GNUNET_assert (NULL != ret);
  GNUNET_assert (sizeof (buf) ==
                 GNUNET_DNSPARSER_hex_to_bin (ret,
                                              buf));
  GNUNET_assert (0 == memcmp (TESTSTRING,
                              buf,
                              sizeof (buf)));
  GNUNET_free (ret);
  return 0;
}


/* end of test_hexcoder.c */
