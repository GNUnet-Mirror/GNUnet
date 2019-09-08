/*
     This file is part of GNUnet.
     Copyright (C) 2010 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * FS block formats (shared between FS and Block)
 *
 * @defgroup block-fs  FS block formats
 * Shared between the [FS service](@ref fs) and the [Block library](@ref block).
 * @{
 */
#ifndef BLOCK_FS_H
#define BLOCK_FS_H

#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"


/**
 * Maximum legal size for a ublock.
 */
#define MAX_UBLOCK_SIZE (60 * 1024)



GNUNET_NETWORK_STRUCT_BEGIN

/**
 * @brief universal block for keyword and namespace search results
 */
struct UBlock {
  /**
   * Signature using pseudonym and search keyword / identifier.
   */
  struct GNUNET_CRYPTO_EcdsaSignature signature;

  /**
   * What is being signed and why?
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Public key used to sign this block.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey verification_key;

  /* rest of the data is encrypted */

  /* 0-terminated update-identifier here (ignored for keyword results) */

  /* 0-terminated URI here */

  /* variable-size Meta-Data follows here */
};


/**
 * @brief index block (indexing a DBlock that
 *        can be obtained directly from reading
 *        the plaintext file)
 */
struct OnDemandBlock {
  /**
   * Hash code of the entire content of the
   * file that was indexed (used to uniquely
   * identify the plaintext file).
   */
  struct GNUNET_HashCode file_id;

  /**
   * At which offset should we be able to find
   * this on-demand encoded block? (in NBO)
   */
  uint64_t offset GNUNET_PACKED;
};
GNUNET_NETWORK_STRUCT_END

#endif

/** @} */  /* end of group */
