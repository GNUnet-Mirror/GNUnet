/*
     This file is part of GNUnet.
     Copyright (C) 2011 GNUnet e.V.

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
 * @file fs/gnunet-service-fs_put.h
 * @brief support for putting content into the DHT
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_FS_PUT_H
#define GNUNET_SERVICE_FS_PUT_H

#include "gnunet-service-fs.h"


/**
 * Setup the module.
 */
void
GSF_put_init_ (void);


/**
 * Shutdown the module.
 */
void
GSF_put_done_ (void);


#endif
