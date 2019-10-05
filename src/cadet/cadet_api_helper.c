/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2017 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file cadet/cadet_api_helper.c
 * @brief cadet api: client implementation of cadet service
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_cadet_service.h"
#include "cadet.h"
#include "cadet_protocol.h"


/**
 * Transitional function to convert an unsigned int port to a hash value.
 * WARNING: local static value returned, NOT reentrant!
 * WARNING: do not use this function for new code!
 *
 * @param port Numerical port (unsigned int format).
 *
 * @return A GNUNET_HashCode usable for the new CADET API.
 */
const struct GNUNET_HashCode *
GC_u2h (uint32_t port)
{
  static struct GNUNET_HashCode hash;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "This is a transitional function, use proper crypto hashes as CADET ports\n");
  GNUNET_CRYPTO_hash (&port,
                      sizeof(port),
                      &hash);
  return &hash;
}
