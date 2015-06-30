/*
     This file is part of GNUnet.
     Copyright (C) 2014 Christian Grothoff (and other contributing authors)

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
 * @author LRN
 * @file src/util/gnunet-helper-w32-console.h
 */
#ifndef GNUNET_HELPER_W32_CONSOLE_H
#define GNUNET_HELPER_W32_CONSOLE_H

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_common.h"

/**
 * Input event from the console
 */
#define GNUNET_MESSAGE_TYPE_W32_CONSOLE_HELPER_INPUT 60000

/**
 * Chars from the console
 */
#define GNUNET_MESSAGE_TYPE_W32_CONSOLE_HELPER_CHARS 60001

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * This is just a dump of the INPUT_RECORD structure.
 */
struct GNUNET_W32_CONSOLE_input
{
  /**
   * Type:  GNUNET_MESSAGE_TYPE_W32_CONSOLE_HELPER_INPUT
   */
  struct GNUNET_MessageHeader header;

  INPUT_RECORD input_record GNUNET_PACKED;
};

/**
 * A header, followed by UTF8-encoded, 0-terminated string
 */
struct GNUNET_W32_CONSOLE_chars
{
  /**
   * Type:  GNUNET_MESSAGE_TYPE_W32_CONSOLE_HELPER_CHARS
   */
  struct GNUNET_MessageHeader header;

  /* followed by a string */
};

GNUNET_NETWORK_STRUCT_END

#endif
