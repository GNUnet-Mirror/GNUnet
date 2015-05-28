/*
      This file is part of GNUnet
      Copyright (C) 2009, 2015 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_util_taler_wallet_lib.h
 * @brief convenience header including all headers of subsystems in
 *        gnunet_util_taler_wallet library.  Note that (due to the
 *        structure of the original headers), not all symbols declared
 *        by the included headers are actually included in the
 *        gnunet_util_taler_wallet library!  The library excludes anything
 *        relating to the GNUnet installation location, scheduler, networking
 *        or OS-specific logic that would not apply to Apps/Browser extensions.
 * @author Christian Grothoff
 */

#ifndef GNUNET_UTIL_TALER_WALLET_LIB_H
#define GNUNET_UTIL_TALER_WALLET_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_crypto_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_disk_lib.h"
#include "gnunet_strings_lib.h"

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
