/*
     This file is part of GNUnet
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file regex/test_regex_iptoregex.c
 * @brief simple test for regex.c iptoregex functions
 * @author Maximilian Szengel
 */
#include "platform.h"
#include "gnunet_regex_lib.h"


static int
test_iptoregex (const char *ipv4, const char *netmask, const char *expectedv4,
                const char *ipv6, unsigned int prefixlen,
                const char *expectedv6)
{
  int error = 0;

  struct in_addr a;
  struct in6_addr b;
  char rxv4[GNUNET_REGEX_IPV4_REGEXLEN];
  char rxv6[GNUNET_REGEX_IPV6_REGEXLEN];

  GNUNET_assert (1 == inet_pton (AF_INET, ipv4, &a));
  GNUNET_REGEX_ipv4toregex (&a, netmask, rxv4);


  if (0 != strcmp (rxv4, expectedv4))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Expected: %s but got: %s\n",
                expectedv4, rxv4);
    error++;
  }

  GNUNET_assert (1 == inet_pton (AF_INET6, ipv6, &b));
  GNUNET_REGEX_ipv6toregex (&b, prefixlen, rxv6);

  if (0 != strcmp (rxv6, expectedv6))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Expected: %s but got: %s\n",
                expectedv6, rxv6);
    error++;
  }

  return error;
}

int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test-regex",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  int error;

  error = 0;

  error +=
      test_iptoregex ("192.0.0.0", "255.255.255.0",
                      "110000000000000000000000(0|1)+", "FFFF::0", 16,
                      "1111111111111111(0|1)+");

  error +=
      test_iptoregex ("255.255.255.255", "255.255.255.255",
                      "11111111111111111111111111111111",
                      "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", 128,
                      "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");

  error +=
      test_iptoregex ("0.0.0.0", "255.255.255.255",
                      "00000000000000000000000000000000", "0::0", 128,
                      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");


  return error;
}
