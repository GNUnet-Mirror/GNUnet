/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file util/disk.h
 * @brief Internal DISK related helper functions
 * @author Nils Durner
 */
#ifndef GNUNET_DISK_H_
#define GNUNET_DISK_H_

#include "gnunet_disk_lib.h"

/**
 * Retrieve OS file handle
 *
 * @internal
 * @param fh GNUnet file descriptor
 * @param dst destination buffer
 * @param dst_len length of dst
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_DISK_internal_file_handle_ (const struct GNUNET_DISK_FileHandle *fh,
                                   void *dst, size_t dst_len);

#endif /* GNUNET_DISK_H_ */
