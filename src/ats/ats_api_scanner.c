/*
     This file is part of GNUnet.
     Copyright (C) 2010-2015 GNUnet e.V.

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
 * @file ats/ats_api_scanner.c
 * @brief LAN interface scanning to determine IPs in LAN
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_service.h"

/**
 * Convert ATS properties from host to network byte order.
 *
 * @param nbo[OUT] value written
 * @param hbo value read
 */
void
GNUNET_ATS_properties_hton (struct GNUNET_ATS_PropertiesNBO *nbo,
                            const struct GNUNET_ATS_Properties *hbo)
{
  nbo->utilization_out = htonl (hbo->utilization_out);
  nbo->utilization_in = htonl (hbo->utilization_in);
  nbo->scope = htonl ((uint32_t) hbo->scope);
  nbo->distance = htonl (hbo->distance);
  nbo->delay = GNUNET_TIME_relative_hton (hbo->delay);
}


/**
 * Convert ATS properties from network to host byte order.
 *
 * @param hbo[OUT] value written
 * @param nbo value read
 */
void
GNUNET_ATS_properties_ntoh (struct GNUNET_ATS_Properties *hbo,
                            const struct GNUNET_ATS_PropertiesNBO *nbo)
{
  hbo->utilization_out = ntohl (nbo->utilization_out);
  hbo->utilization_in = ntohl (nbo->utilization_in);
  hbo->scope = ntohl ((uint32_t) nbo->scope);
  hbo->distance = ntohl (nbo->distance);
  hbo->delay = GNUNET_TIME_relative_ntoh (nbo->delay);
}


/* end of ats_api_scanner.c */
