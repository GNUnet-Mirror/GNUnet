/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2009 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 * @file statistics/statistics.h
 */
#ifndef STATISTICS_H
#define STATISTICS_H

#include "gnunet_common.h"

#define DEBUG_STATISTICS GNUNET_EXTRA_LOGGING

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Statistics message. Contains how long the system is up
 * and one value.
 *
 * The struct is be followed by the service name and
 * name of the statistic, both 0-terminated.
 */
struct GNUNET_STATISTICS_ReplyMessage
{
  /**
   * Type:  GNUNET_MESSAGE_TYPE_STATISTICS_VALUE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique numerical identifier for the value (will
   * not change during the same client-session).  Highest
   * bit will be set for persistent values.
   */
  uint32_t uid GNUNET_PACKED;

  /**
   * The value.
   */
  uint64_t value GNUNET_PACKED;

};

#define GNUNET_STATISTICS_PERSIST_BIT (1<<31)

#define GNUNET_STATISTICS_SETFLAG_ABSOLUTE 0

#define GNUNET_STATISTICS_SETFLAG_RELATIVE 1

#define GNUNET_STATISTICS_SETFLAG_PERSISTENT 2

/**
 * Message to set a statistic.  Followed
 * by the subsystem name and the name of
 * the statistic (each 0-terminated).
 */
struct GNUNET_STATISTICS_SetMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_STATISTICS_SET
   */
  struct GNUNET_MessageHeader header;

  /**
   * 0 for absolute value, 1 for relative value; 2 to make persistent
   * (see GNUNET_STATISTICS_SETFLAG_*).
   */
  uint32_t flags GNUNET_PACKED;

  /**
   * Value. Note that if this is a relative value, it will
   * be signed even though the type given here is unsigned.
   */
  uint64_t value GNUNET_PACKED;

};


/**
 * Message transmitted if a watched value changes.
 */
struct GNUNET_STATISTICS_WatchValueMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_STATISTICS_WATCH_VALUE
   */
  struct GNUNET_MessageHeader header;

  /**
   * 0 for absolute value, 1 for relative value; 2 to make persistent
   * (see GNUNET_STATISTICS_SETFLAG_*).
   */
  uint32_t flags GNUNET_PACKED;

  /**
   * Unique watch identification number (watch
   * requests are enumerated in the order they
   * are received, the first request having
   * a wid of zero).
   */
  uint32_t wid GNUNET_PACKED;

  /**
   * Reserved (always 0).
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Value. Note that if this is a relative value, it will
   * be signed even though the type given here is unsigned.
   */
  uint64_t value GNUNET_PACKED;

};
GNUNET_NETWORK_STRUCT_END

#endif
