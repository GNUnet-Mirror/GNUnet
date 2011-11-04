/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file core/gnunet-service-core.h
 * @brief Globals for gnunet-service-core
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CORE_H
#define GNUNET_SERVICE_CORE_H

#include "gnunet_statistics_service.h"
#include "core.h"

/**
 * Opaque handle to a client.
 */
struct GSC_Client;


/**
 * Record kept for each request for transmission issued by a
 * client that is still pending. (This struct is used by
 * both the 'CLIENTS' and 'SESSIONS' subsystems.)
 */
struct GSC_ClientActiveRequest
{

  /**
   * Active requests are kept in a doubly-linked list of
   * the respective target peer.
   */
  struct GSC_ClientActiveRequest *next;

  /**
   * Active requests are kept in a doubly-linked list of
   * the respective target peer.
   */
  struct GSC_ClientActiveRequest *prev;

  /**
   * Which peer is the message going to be for?
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Handle to the client.
   */
  struct GSC_Client *client_handle;

  /**
   * By what time would the client want to see this message out?
   */
  struct GNUNET_TIME_Absolute deadline;

  /**
   * How important is this request.
   */
  uint32_t priority;

  /**
   * Has this request been solicited yet?
   */
  int was_solicited;

  /**
   * How many bytes does the client intend to send?
   */
  uint16_t msize;

  /**
   * Unique request ID (in big endian).
   */
  uint16_t smr_id;

};


/**
 * Our configuration.
 */
extern const struct GNUNET_CONFIGURATION_Handle *GSC_cfg;

/**
 * For creating statistics.
 */
extern struct GNUNET_STATISTICS_Handle *GSC_stats;

/**
 * Our identity.
 */
extern struct GNUNET_PeerIdentity GSC_my_identity;


#endif
