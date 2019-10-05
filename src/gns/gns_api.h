/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016, 2018 GNUnet e.V.

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
 * @file gns/gns_api.h
 * @brief shared data structures of libgnunetgns
 * @author Martin Schanzenbach
 * @author Christian Grothoff
 */
#ifndef GNS_API_H
#define GNS_API_H

#include "gnunet_gns_service.h"


/**
 * Connection to the GNS service.
 */
struct GNUNET_GNS_Handle
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Connection to service (if available).
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Head of linked list of active lookup requests.
   */
  struct GNUNET_GNS_LookupRequest *lookup_head;

  /**
   * Tail of linked list of active lookup requests.
   */
  struct GNUNET_GNS_LookupRequest *lookup_tail;

  /**
   * Reconnect task
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * How long do we wait until we try to reconnect?
   */
  struct GNUNET_TIME_Relative reconnect_backoff;

  /**
   * Request Id generator.  Incremented by one for each request.
   */
  uint32_t r_id_gen;
};


#endif
