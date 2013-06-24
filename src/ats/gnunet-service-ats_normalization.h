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
#include "platform.h"
#include "gnunet_ats_service.h"

#define PREF_AGING_INTERVAL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
#define PREF_AGING_FACTOR 0.95

#define DEFAULT_REL_PREFERENCE 1.0
#define DEFAULT_ABS_PREFERENCE 0.0

#define DEFAULT_REL_QUALITY 1.0

typedef void
(*GAS_Normalization_preference_changed_cb) (void *cls,
																						const struct GNUNET_PeerIdentity *peer,
																						enum GNUNET_ATS_PreferenceKind kind,
																						double pref_rel);

typedef void
(*GAS_Normalization_property_changed_cb) (void *cls,
																				 const struct ATS_Address *peer,
																				 uint32_t type,
																				 double prop_rel);

/**
 * Get the normalized preference values for a specific peer
 *
 * @param id the peer
 * @return pointer to the values, can be indexed with GNUNET_ATS_PreferenceKind, NULL if peer does not exist
 */
const double *
GAS_normalization_get_preferences (const struct GNUNET_PeerIdentity *id);


/**
 * Normalize an updated preference value
 *
 * @param src the client with this preference
 * @param peer the peer to change the preference for
 * @param kind the kind to change the preference
 * @param score_abs the normalized score
 */
void
GAS_normalization_normalize_preference (void *src,
                                   	 const struct GNUNET_PeerIdentity *peer,
                                   	 enum GNUNET_ATS_PreferenceKind kind,
                                   	 float score_abs);

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
 *
 * @param pref_ch_cb callback to call on relative preference changing
 * @param pref_ch_cb_cls cls for the callback
 */
void
GAS_normalization_start (GAS_Normalization_preference_changed_cb pref_ch_cb,
												 void *pref_ch_cb_cls,
												 GAS_Normalization_property_changed_cb property_ch_ch_cls,
												 void *property_ch_cb_cls);


/**
 * Stop the normalization component and free all items
 */
void
GAS_normalization_stop ();


/* end of gnunet-service-ats_normalization.h */
