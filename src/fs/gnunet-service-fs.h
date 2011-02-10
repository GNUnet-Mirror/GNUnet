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
static struct GNUNET_DHT_Handle *GSF_dht;



#endif
/* end of gnunet-service-fs.h */
