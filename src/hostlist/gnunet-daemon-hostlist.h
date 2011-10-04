/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file hostlist/gnunet-daemon-hostlist.h
 * @brief common internal definitions for hostlist daemon
 * @author Matthias Wachs
 */
#include <stdlib.h>
#include "platform.h"
#include "hostlist-client.h"
#include "hostlist-server.h"
#include "gnunet_core_service.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_program_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_strings_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"

/**
 * General hostlist daemon debugging.
 */
#define DEBUG_HOSTLIST GNUNET_EXTRA_LOGGING

#define MAX_URL_LEN 1000
#define MAX_BYTES_PER_HOSTLISTS 500000

/* end of gnunet-daemon-hostlist.h */
