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
 * @file ats/gnunet-service-ats_addresses_mlp.h
 * @brief ats mlp problem solver
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#if HAVE_LIBGLPK
#include "glpk.h"
#endif

#ifndef GNUNET_SERVICE_ATS_ADDRESSES_MLP_H
#define GNUNET_SERVICE_ATS_ADDRESSES_MLP_H

struct GAS_MLP_Handle
{
  /**
   * GLPK (MLP) problem object
   */
#if HAVE_LIBGLPK
  glp_prob *prob;
#else
  void *prob;
#endif

};

/**
 * Init the MLP problem solving component
 */
void
GAS_mlp_init ();

/**
 * Shutdown the MLP problem solving component
 */
void
GAS_mlp_done ();

#endif
/* end of gnunet-service-ats_addresses_mlp.h */
