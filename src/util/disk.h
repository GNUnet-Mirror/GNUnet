/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
 * @file util/disk.h
 * @brief Internal DISK related helper functions
 * @author Nils Durner
 */
#ifndef GNUNET_DISK_H_
#define GNUNET_DISK_H_

#include "gnunet_crypto_lib.h"
#include "gnunet_disk_lib.h"

/**
 * Retrieve OS file handle
 *
 * @internal
 * @param fh GNUnet file descriptor
 * @param dst destination buffer
 * @param dst_len length of @a dst
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_DISK_internal_file_handle_ (const struct GNUNET_DISK_FileHandle *fh,
                                   void *dst, size_t dst_len);

#endif /* GNUNET_DISK_H_ */
