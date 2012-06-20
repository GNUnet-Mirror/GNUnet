/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file include/block_mesh.h
 * @brief fs block formats (shared between fs and block)
 * @author Bartlomiej Polot
 */
#ifndef BLOCK_MESH_H
#define BLOCK_MESH_H

#include "gnunet_util_lib.h"
#include "gnunet_mesh_service.h"
#include <stdint.h>

/**
 * @brief peer block (announce peer + type)
 */
struct PBlock
{
    /**
     * Identity of the peer
     */
  struct GNUNET_PeerIdentity id;

    /**
     * Type of service offered
     */
  GNUNET_MESH_ApplicationType type;
};

#endif