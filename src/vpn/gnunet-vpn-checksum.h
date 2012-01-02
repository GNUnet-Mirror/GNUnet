/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff

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
#ifndef GNUNET_VPN_CHECKSUM_H
#define GNUNET_VPN_CHECKSUM_H

#include <platform.h>

uint32_t
calculate_checksum_update (uint32_t sum, uint16_t * hdr, short len);

uint16_t
calculate_checksum_end (uint32_t sum);

/**
 * Calculate the checksum of an IPv4-Header
 */
uint16_t
calculate_ip_checksum (uint16_t * hdr, short len);

#endif /* end of include guard: GNUNET-VPN-CHECKSUM_H */
