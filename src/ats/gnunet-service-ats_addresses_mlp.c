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
 * @file ats/gnunet-service-ats_addresses_mlp.c
 * @brief ats mlp problem solver
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-ats_addresses_mlp.h"
#if HAVE_LIBGLPK
#include "glpk.h"
#endif

struct GAS_MLP_Handle *GAS_mlp;

/**
 * Init the MLP problem solving component
 */
void
GAS_mlp_init ()
{
  GAS_mlp = GNUNET_malloc (sizeof (struct GAS_MLP_Handle));
  GAS_mlp->prob = NULL;
}

/**
 * Shutdown the MLP problem solving component
 */
void
GAS_mlp_done ()
{
  GNUNET_free (GAS_mlp);
}


/* end of gnunet-service-ats_addresses_mlp.c */
