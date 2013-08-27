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
 * @file psycstore/psycstore.h
 * @brief Common type definitions for the PSYCstore service and API.
 * @author Gabor X Toth
 */

#ifndef PSYCSTORE_H
#define PSYCSTORE_H

#include "gnunet_common.h"


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Answer from service to client about last operation.
 */
struct GNUNET_PSYCSTORE_ResultCodeMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_CODE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Status code for the last operation, in NBO.
   * (currently not used).
   */
  uint32_t result_code GNUNET_PACKED;

  /* followed by 0-terminated error message (on error) */

};

GNUNET_NETWORK_STRUCT_END

#endif
