/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public Liceidentity as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public Liceidentity for more details.

     You should have received a copy of the GNU General Public Liceidentity
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @author Christian Grothoff
 * @file identity/identity.h
 *
 * @brief Common type definitions for the identity
 *        service and API.
 */
#ifndef IDENTITY_H
#define IDENTITY_H

#include "gnunet_common.h"

/**
 * Generate debug-level log messages?
 */
#define DEBUG_IDENTITY GNUNET_EXTRA_LOGGING

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Network size estimate sent from the service
 * to clients.  Contains the current size estimate
 * (or 0 if none has been calculated) and the
 * standard deviation of known estimates.
 *
 */
struct GNUNET_IDENTITY_XXXMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_IDENTITY_XXX
   */
  struct GNUNET_MessageHeader header;

};
GNUNET_NETWORK_STRUCT_END

#endif
