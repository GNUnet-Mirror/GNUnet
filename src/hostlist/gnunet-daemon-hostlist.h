/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
 * @file hostlist/gnunet-daemon-hostlist.h
 * @brief common internal definitions for hostlist daemon
 * @author Matthias Wachs
 */
#include <stdlib.h>
#include "platform.h"
#include "gnunet_core_service.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet_util_lib.h"

/**
 * How long can hostlist URLs be?
 */
#define MAX_URL_LEN 1000

/**
 * How many bytes do we download at most from a hostlist server?
 */
#define MAX_BYTES_PER_HOSTLISTS 500000

/* end of gnunet-daemon-hostlist.h */
