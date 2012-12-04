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
 * @file ats/gnunet-service-ats_addresses_simplistic.h
 * @brief ats simplistic ressource assignment
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet_statistics_service.h"


/**
 * A handle for the simplistic solver
 */
struct GAS_SIMPLISTIC_Handle
{

};


/**
 * Init the simplistic problem solving component
 *
 * @param cfg configuration handle
 * @param stats the GNUNET_STATISTICS handle
 * @return handle for the solver on success, NULL on fail
 */
void *
GAS_simplistic_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     const struct GNUNET_STATISTICS_Handle *stats)
{
  struct GAS_SIMPLISTIC_Handle *solver = GNUNET_malloc (sizeof (struct GAS_SIMPLISTIC_Handle));
  return solver;
}


/**
 * Shutdown the simplistic problem solving component
 *
 * @param solver the respective handle to shutdown
 */
void
GAS_simplistic_done (void *solver)
{
  GNUNET_assert (solver != NULL);
  GNUNET_free (solver);
}

/**
 * Updates a single address in the solve
 *
 * @param solver the solver Handle
 * @param addresses the address hashmap containing all addresses
 * @param address the update address
 */
void
GAS_simplistic_address_update (void *solver, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address)
{

}


/**
 * Remove an address from the solver
 *
 * @param solver the solver handle
 * @param addresses the address hashmap containing all addresses
 * @param address the address to remove
 */
void
GAS_simplistic_address_delete (void *solver, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address)
{

}


/**
 * Get the prefered address for a specific peer
 *
 * @param solver the solver handle
 * @param addresses the address hashmap containing all addresses
 * @param peer the identity of the peer
 */
struct ATS_PreferedAddress *
GAS_simplistic_get_preferred_address (void *solver,
                               struct GNUNET_CONTAINER_MultiHashMap * addresses,
                               const struct GNUNET_PeerIdentity *peer)
{
  return NULL;
}


/**
 * Changes the preferences for a peer in the problem
 *
 * @param solver the solver handle
 * @param peer the peer to change the preference for
 * @param kind the kind to change the preference
 * @param score the score
 */
void
GAS_simplistic_address_change_preference (void *solver,
                                   const struct GNUNET_PeerIdentity *peer,
                                   enum GNUNET_ATS_PreferenceKind kind,
                                   float score)
{

}

/* end of gnunet-service-ats_addresses_simplistic.c */
