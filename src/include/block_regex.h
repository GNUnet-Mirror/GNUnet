/*
     This file is part of GNUnet.
     Copyright (C) 2012,2013 GNUnet e.V.

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
 * @file
 * regex block formats
 *
 * @author Bartlomiej Polot
 */
#ifndef BLOCK_REGEX_H
#define BLOCK_REGEX_H

#ifdef __cplusplus
extern "C"
{
#if 0
/* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include <stdint.h>


GNUNET_NETWORK_STRUCT_BEGIN


/**
 * @brief Block to announce a peer accepting a state.
 */
struct RegexAcceptBlock
{
  /**
   * Accept blocks must be signed.  Signature
   * goes over expiration time and key.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * When does the signature expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * The key of the state.
   */
  struct GNUNET_HashCode key;

  /**
   * Public key of the peer signing.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * The signature.
   */
  struct GNUNET_CRYPTO_EddsaSignature signature;
};


GNUNET_NETWORK_STRUCT_END


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
