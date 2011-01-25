/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-service-fs_pe.h
 * @brief API to manage query plan
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_FS_PE_H
#define GNUNET_SERVICE_FS_PE_H

#include "gnunet-service-fs.h"


/**
 * Create a new query plan entry.
 *
 * @param cp peer with the entry
 * @param pr request with the entry
 * @param position position of the entry in the cp queue
 * @return handle for the new plan entry
 */
struct GSF_PlanEntry *
GSF_plan_entry_create_ (struct GSF_ConnectedPeer *cp,
			struct GSF_PendingRequest *pr,
			unsigned int position);


/**
 * Get the first plan entry for the given connected peer.
 * FIXME...
 *
 * @param cp connected peer 
 * @return NULL if there is no request planned for this peer
 */
struct GSF_PendingRequest *
GSF_plan_get_ (struct GSF_ConnectedPeer *cp);



#endif
/* end of gnunet-service-fs_pe.h */
