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
 * @file ats/gnunet-service-ats_addresses_simplistic.c
 * @brief ats mlp problem solver
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet_statistics_service.h"
#include "glpk.h"

struct GAS_SIMPLISTIC_Handle
{

};

/**
 * Init the simplistic problem solving component
 *
 * @param cfg configuration handle
 * @param stats the GNUNET_STATISTICS handle
 * @param max_duration maximum numbers of iterations for the LP/MLP Solver
 * @param max_iterations maximum time limit for the LP/MLP Solver
 * @return struct GAS_MLP_Handle * on success, NULL on fail
 */
struct GAS_SIMPLISTIC_Handle *
GAS_simplistic_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     const struct GNUNET_STATISTICS_Handle *stats)
{
  struct GAS_SIMPLISTIC_Handle *solver = GNUNET_malloc (sizeof (struct GAS_SIMPLISTIC_Handle));
  return solver;
}

/**
 * Shutdown the simplistic problem solving component
 */
void
GAS_simplistic_done (struct GAS_SIMPLISTIC_Handle *solver)
{
  GNUNET_free (solver);
}

/* end of gnunet-service-ats_addresses_simplistic.c */
