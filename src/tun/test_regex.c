/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file tun/test_regex.c
 * @brief simple test for regex.c iptoregex functions
 * @author Maximilian Szengel
 */
#include "platform.h"
#include "gnunet_tun_lib.h"

/**
 * 'wildcard', matches all possible values (for HEX encoding).
 */
#define DOT "(0|1|2|3|4|5|6|7|8|9|A|B|C|D|E|F)"


static int
test_iptoregex (const char *ipv4,
                uint16_t port,
                const char *expectedv4,
                const char *ipv6,
                uint16_t port6,
                const char *expectedv6)
{
  int error = 0;

  struct in_addr a;
  struct in6_addr b;
  char rxv4[GNUNET_TUN_IPV4_REGEXLEN];
  char rxv6[GNUNET_TUN_IPV6_REGEXLEN];

  GNUNET_assert (1 == inet_pton (AF_INET, ipv4, &a));
  GNUNET_TUN_ipv4toregexsearch (&a, port, rxv4);

  if (0 != strcmp (rxv4, expectedv4))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected: %s but got: %s\n",
                expectedv4,
                rxv4);
    error++;
  }

  GNUNET_assert (1 == inet_pton (AF_INET6, ipv6, &b));
  GNUNET_TUN_ipv6toregexsearch (&b, port6, rxv6);
  if (0 != strcmp (rxv6, expectedv6))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected: %s but got: %s\n",
                expectedv6, rxv6);
    error++;
  }
  return error;
}


static int
test_policy4toregex (const char *policy,
                     const char *regex)
{
  char *r;
  int ret;

  ret = 0;
  r = GNUNET_TUN_ipv4policy2regex (policy);
  if (NULL == r)
  {
    GNUNET_break (0);
    return 1;
  }
  if (0 != strcmp (regex, r))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected: `%s' but got: `%s'\n",
                regex, r);
    ret = 2;
  }
  GNUNET_free (r);
  return ret;
}


static int
test_policy6toregex (const char *policy,
                     const char *regex)
{
  char *r;
  int ret;

  ret = 0;
  r = GNUNET_TUN_ipv6policy2regex (policy);
  if (NULL == r)
  {
    GNUNET_break (0);
    return 1;
  }
  if (0 != strcmp (regex, r))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected: `%s' but got: `%s'\n",
                regex, r);
    ret = 2;
  }
  GNUNET_free (r);
  return ret;
}


int
main (int argc, char *argv[])
{
  int error;
  char *r;

  GNUNET_log_setup ("test-regex", "WARNING", NULL);
  error = 0;

  /* this is just a performance test ... */
  r = GNUNET_TUN_ipv4policy2regex ("1.2.3.4/16:!25;");
  GNUNET_break (NULL != r);
  GNUNET_free (r);

  error +=
    test_iptoregex ("192.1.2.3", 2086,
                    "4-0826-C0010203",
                    "FFFF::1", 8080,
                    "6-1F90-FFFF0000000000000000000000000001");
  error +=
    test_iptoregex ("187.238.255.0", 80,
                    "4-0050-BBEEFF00",
                    "E1E1:73F9:51BE::0", 49,
                    "6-0031-E1E173F951BE00000000000000000000");
  error +=
    test_policy4toregex ("192.1.2.0/24:80;",
                         "4-0050-C00102" DOT DOT);
  error +=
    test_policy4toregex ("192.1.0.0/16;",
                         "4-" DOT DOT DOT DOT "-C001" DOT DOT DOT DOT);
  error +=
    test_policy4toregex ("192.1.0.0/16:80-81;",
                         "4-(0050|0051)-C001" DOT DOT DOT DOT);
  error +=
    test_policy4toregex ("192.1.0.0/8:!3-65535;",
                         "4-000(0|1|2)-C0" DOT DOT DOT DOT DOT DOT);
  error +=
    test_policy4toregex ("192.1.0.0/8:!25-56;",
                         "4-(0(0(0"DOT"|1(0|1|2|3|4|5|6|7|8)|3(9|A|B|C|D|E|F)|(4|5|6|7|8|9|A|B|C|D|E|F)"DOT")|(1|2|3|4|5|6|7|8|9|A|B|C|D|E|F)"DOT DOT")|(1|2|3|4|5|6|7|8|9|A|B|C|D|E|F)"DOT DOT DOT")-C0"DOT DOT DOT DOT DOT DOT);
  error +=
    test_policy6toregex ("E1E1::1;",
                         "6-"DOT DOT DOT DOT"-E1E10000000000000000000000000001");
  error +=
    test_policy6toregex ("E1E1:ABCD::1/120;",
                         "6-"DOT DOT DOT DOT"-E1E1ABCD0000000000000000000000" DOT DOT);
  error +=
    test_policy6toregex ("E1E1:ABCD::ABCD/126;",
                         "6-"DOT DOT DOT DOT"-E1E1ABCD00000000000000000000ABC(C|D|E|F)");
  error +=
    test_policy6toregex ("E1E1:ABCD::ABCD/127;",
                         "6-"DOT DOT DOT DOT"-E1E1ABCD00000000000000000000ABC(C|D)");
  error +=
    test_policy6toregex ("E1E1:ABCD::ABCD/128:80;",
                         "6-0050-E1E1ABCD00000000000000000000ABCD");
  return error;
}
