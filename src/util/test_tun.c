/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2011, 2012 Christian Grothoff

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
 * @file tun/test_tun.c
 * @brief test for tun.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"

static int ret;

static void
test_udp(size_t pll,
         int pl_fill,
         uint16_t crc)
{
  struct GNUNET_TUN_IPv4Header ip;
  struct GNUNET_TUN_UdpHeader udp;
  char payload[pll];
  struct in_addr src;
  struct in_addr dst;

  GNUNET_assert(1 == inet_pton(AF_INET, "1.2.3.4", &src));
  GNUNET_assert(1 == inet_pton(AF_INET, "122.2.3.5", &dst));
  memset(payload, pl_fill, sizeof(payload));
  GNUNET_TUN_initialize_ipv4_header(&ip,
                                    IPPROTO_UDP,
                                    pll + sizeof(udp),
                                    &src,
                                    &dst);
  udp.source_port = htons(4242);
  udp.destination_port = htons(4242);
  udp.len = htons(pll);
  GNUNET_TUN_calculate_udp4_checksum(&ip,
                                     &udp,
                                     payload,
                                     pll);
  if (crc != ntohs(udp.crc))
    {
      fprintf(stderr, "Got CRC: %u, wanted: %u\n",
              ntohs(udp.crc),
              crc);
      ret = 1;
    }
}

int main(int argc,
         char **argv)
{
  test_udp(4, 3, 22439);
  test_udp(4, 1, 23467);
  test_udp(7, 17, 6516);
  test_udp(12451, 251, 42771);
  return ret;
}
