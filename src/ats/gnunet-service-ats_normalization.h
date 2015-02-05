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
 * @file ats/gnunet-service-ats_normalization.h
 * @brief ats service address: management of ATS properties and preferences normalization
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_ATS_NORMALIZATION_H
#define GNUNET_SERVICE_ATS_NORMALIZATION_H
#include "gnunet_ats_service.h"

#define DEFAULT_REL_QUALITY 1.0


/**
 * Get the normalized properties values for a specific peer or
 * the default values if no normalized values are available.
 *
 * @param cls ignored
 * @param address the address
 * @return pointer to the values, can be indexed with GNUNET_ATS_PreferenceKind,
 * default preferences if peer does not exist
 */
const double *
GAS_normalization_get_properties (void *cls,
				  const struct ATS_Address *address);


/**
 * Update and normalize a atsi performance information
 *
 * @param address the address to update
 * @param atsi the array of performance information
 * @param atsi_count the number of atsi information in the array
 */
void
GAS_normalization_normalize_property (struct ATS_Address *address,
				      const struct GNUNET_ATS_Information *atsi,
				      uint32_t atsi_count);


/**
 * Start the normalization component
 */
void
GAS_normalization_start (void);


/**
 * Stop the normalization component and free all items
 */
void
GAS_normalization_stop (void);

#endif
/* end of gnunet-service-ats_normalization.h */
