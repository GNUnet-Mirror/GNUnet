/*
      This file is part of GNUnet
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
 * @author Christian Grothoff
 *
 * @file
 * Convenience header including all headers of subsystems in the gnunet_util library
 *
 * @see [Documentation](https://gnunet.org/libgnuneutil)
 */

#ifndef GNUNET_UTIL_LIB_H
#define GNUNET_UTIL_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Largest supported message (to be precise, one byte more
 * than the largest possible message, so tests involving
 * this value should check for messages being smaller than
 * this value).
 */
#define GNUNET_MAX_MESSAGE_SIZE 65536

/**
 * Smallest supported message.
 */
#define GNUNET_MIN_MESSAGE_SIZE sizeof (struct GNUNET_MessageHeader)

/**
 * NOTE: You MUST adjust this URL to point to the location of a
 * publicly accessible repository (or TGZ) containing the sources of
 * THIS release. Otherwise, you are violating the Affero GPL if you make
 * this service available to anyone but yourself.
 */
#define GNUNET_AGPL_URL "https://gnunet.org/git/gnunet.git#" PACKAGE_VERSION


#include "gnunet_crypto_lib.h"
#include "gnunet_bandwidth_lib.h"
#include "gnunet_bio_lib.h"
#include "gnunet_client_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_helper_lib.h"
#include "gnunet_mst_lib.h"
#include "gnunet_mq_lib.h"
#include "gnunet_nc_lib.h"
#include "gnunet_op_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_peer_lib.h"
#include "gnunet_plugin_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_signal_lib.h"
#include "gnunet_strings_lib.h"
#include "gnunet_tun_lib.h"
#include "gnunet_dnsstub_lib.h"
#include "gnunet_dnsparser_lib.h"

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
