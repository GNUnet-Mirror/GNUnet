/*
     This file is part of GNUnet.
     Copyright (C) 2017 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file cadet/gnunet-service-cadet_core.h
 * @brief cadet service; interaction with CORE service
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 *
 * All functions in this file should use the prefix GCO (Gnunet Cadet cOre (bottom))
 */

#ifndef GNUNET_SERVICE_CADET_CORE_H
#define GNUNET_SERVICE_CADET_CORE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"


/**
 * Initialize the CORE subsystem.
 *
 * @param c Configuration.
 */
void
GCO_init (const struct GNUNET_CONFIGURATION_Handle *c);


/**
 * Shut down the CORE subsystem.
 */
void
GCO_shutdown (void);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CADET_SERVICE_CORE_H */
#endif
/* end of gnunet-cadet-service_core.h */
