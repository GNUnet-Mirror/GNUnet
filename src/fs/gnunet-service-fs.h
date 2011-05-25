/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-service-fs.h
 * @brief shared data structures of gnunet-service-fs.c
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_FS_H
#define GNUNET_SERVICE_FS_H

#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_core_service.h"
#include "gnunet_block_lib.h"
#include "fs.h"

#define DEBUG_FS GNUNET_YES

#define DEBUG_FS_CLIENT GNUNET_NO


/**
 * Should we introduce random latency in processing?  Required for proper
 * implementation of GAP, but can be disabled for performance evaluation of
 * the basic routing algorithm.
 *
 * Note that with delays enabled, performance can be significantly lower
 * (several orders of magnitude in 2-peer test runs); if you want to
 * measure throughput of other components, set this to NO.  Also, you
 * might want to consider changing 'RETRY_PROBABILITY_INV' to 1 for
 * a rather wasteful mode of operation (that might still get the highest
 * throughput overall).
 *
 * Performance measurements (for 50 MB file, 2 peers):
 *
 * - Without delays: 3300 kb/s
 * - With    delays:  101 kb/s
 */
#define SUPPORT_DELAYS GNUNET_NO


/**
 * At what frequency should our datastore load decrease
 * automatically (since if we don't use it, clearly the
 * load must be going down).
 */
#define DATASTORE_LOAD_AUTODECLINE GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 250)



/**
 * A connected peer.
 */
struct GSF_ConnectedPeer;

/**
 * An active request.
 */
struct GSF_PendingRequest;

/**
 * A local client.
 */
struct GSF_LocalClient;

/**
 * Information kept per plan per request ('pe' module).
 */
struct GSF_RequestPlan;

/**
 * Our connection to the datastore.
 */
extern struct GNUNET_DATASTORE_Handle *GSF_dsh;

/**
 * Our configuration.
 */
extern const struct GNUNET_CONFIGURATION_Handle *GSF_cfg;

/**
 * Handle for reporting statistics.
 */
extern struct GNUNET_STATISTICS_Handle *GSF_stats;

/**
 * Pointer to handle to the core service (points to NULL until we've
 * connected to it).
 */
extern struct GNUNET_CORE_Handle *GSF_core;

/**
 * Handle for DHT operations.
 */
extern struct GNUNET_DHT_Handle *GSF_dht;

/**
 * How long do requests typically stay in the routing table?
 */
extern struct GNUNET_LOAD_Value *GSF_rt_entry_lifetime;

/**
 * Typical priorities we're seeing from other peers right now.  Since
 * most priorities will be zero, this value is the weighted average of
 * non-zero priorities seen "recently".  In order to ensure that new
 * values do not dramatically change the ratio, values are first
 * "capped" to a reasonable range (+N of the current value) and then
 * averaged into the existing value by a ratio of 1:N.  Hence
 * receiving the largest possible priority can still only raise our
 * "current_priorities" by at most 1.
 */
extern double GSF_current_priorities;

/**
 * How many query messages have we received 'recently' that 
 * have not yet been claimed as cover traffic?
 */
extern unsigned int GSF_cover_query_count;

/**
 * How many content messages have we received 'recently' that 
 * have not yet been claimed as cover traffic?
 */
extern unsigned int GSF_cover_content_count;

/**
 * Our block context.
 */
extern struct GNUNET_BLOCK_Context *GSF_block_ctx;


/**
 * Test if the DATABASE (GET) load on this peer is too high
 * to even consider processing the query at
 * all.  
 * 
 * @return GNUNET_YES if the load is too high to do anything (load high)
 *         GNUNET_NO to process normally (load normal)
 *         GNUNET_SYSERR to process for free (load low)
 */
int
GSF_test_get_load_too_high_ (uint32_t priority);


/**
 * We've just now completed a datastore request.  Update our
 * datastore load calculations.
 *
 * @param start time when the datastore request was issued
 */
void
GSF_update_datastore_delay_ (struct GNUNET_TIME_Absolute start);



#endif
/* end of gnunet-service-fs.h */
