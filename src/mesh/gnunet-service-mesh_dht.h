/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file mesh/gnunet-service-mesh_dht.h
 * @brief mesh service; dealing with DHT requests and results
 * @author Bartlomiej Polot
 *
 * All functions in this file should use the prefix GMD (Gnunet Mesh Dht)
 */

#ifndef GNUNET_SERVICE_MESH_DHT_H
#define GNUNET_SERVICE_MESH_DHT_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "gnunet_util_lib.h"


/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Initialize the DHT subsystem.
 *
 * @param c Configuration.
 * @param peer_id Local peer ID (must remain valid during all execution time).
 */
void
GMD_init (const struct GNUNET_CONFIGURATION_Handle *c,
          struct GNUNET_PeerIdentity *peer_id);

/**
 * Shut down the DHT subsystem.
 */
void
GMD_shutdown (void);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_MESH_SERVICE_LOCAL_H */
#endif
/* end of gnunet-mesh-service_LOCAL.h */