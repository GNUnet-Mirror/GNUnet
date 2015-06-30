/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file regex/regex_ipc.h
 * @brief regex IPC messages (not called 'regex.h' due to conflict with
 *        system headers)
 * @author Christian Grothoff
 */
#ifndef REGEX_IPC_H
#define REGEX_IPC_H

#include "gnunet_util_lib.h"

/**
 * Request for regex service to announce capability.
 */
struct AnnounceMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_REGEX_ANNOUNCE
   */
  struct GNUNET_MessageHeader header;

  /**
   * How many characters can we squeeze per edge?
   */
  uint16_t compression;

  /**
   * Always zero.
   */
  uint16_t reserved;

  /**
   * Delay between repeated announcements.
   */
  struct GNUNET_TIME_RelativeNBO refresh_delay;

  /* followed by 0-terminated regex as string */
};


/**
 * Message to initiate regex search.
 */
struct RegexSearchMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_REGEX_SEARCH
   */
  struct GNUNET_MessageHeader header;

  /* followed by 0-terminated search string */

};


/**
 * Result from regex search.
 */
struct ResultMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_REGEX_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of entries in the GET path.
   */
  uint16_t get_path_length;

  /**
   * Number of entries in the PUT path.
   */
  uint16_t put_path_length;

  /**
   * Identity of the peer that was found.
   */
  struct GNUNET_PeerIdentity id;

  /* followed by GET path and PUT path arrays */

};


/* end of regex_ipc.h */
#endif
