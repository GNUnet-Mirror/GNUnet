/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs.c
 * @brief main FS functions
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_fs_service.h"
#include "fs.h"


/**
 * Setup a connection to the file-sharing service.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param client_name unique identifier for this client 
 * @param upcb function to call to notify about FS actions
 * @param upcb_cls closure for upcb
 */
struct GNUNET_FS_Handle *
GNUNET_FS_start (struct GNUNET_SCHEDULER_Handle *sched,
		 const struct GNUNET_CONFIGURATION_Handle *cfg,
		 const char *client_name,
		 GNUNET_FS_ProgressCallback upcb,
		 void *upcb_cls)
{
  struct GNUNET_FS_Handle *ret;
  struct GNUNET_CLIENT_Connection *client;
  
  client = GNUNET_CLIENT_connect (sched,
				  "fs",
				  cfg);
  if (NULL == client)
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_Handle));
  ret->sched = sched;
  ret->cfg = cfg;
  ret->client_name = GNUNET_strdup (client_name);
  ret->upcb = upcb;
  ret->upcb_cls = upcb_cls;
  ret->client = client;
  // FIXME: setup receive-loop with client

  // FIXME: deserialize state; use client-name to find master-directory!
  // Deserialize-Upload:
  // * read FNs for upload FIs, deserialize each
  // Deserialize Search:
  // * read search queries
  // * for each query, read file with search results
  // * for each search result with active download, deserialize download
  // * for each directory search result, check for active downloads of contents
  // Deserialize Download:
  // * always part of search???
  // Deserialize Unindex:
  // * read FNs for unindex with progress offset
  return ret;
}


/**
 * Close our connection with the file-sharing service.
 * The callback given to GNUNET_FS_start will no longer be
 * called after this function returns.
 *
 * @param h handle that was returned from GNUNET_FS_start
 */                    
void 
GNUNET_FS_stop (struct GNUNET_FS_Handle *h)
{
  // FIXME: serialize state!? (or is it always serialized???)
  // FIXME: terminate receive-loop with client  
  GNUNET_CLIENT_disconnect (h->client);
  GNUNET_free (h->client_name);
  GNUNET_free (h);
}


/* end of fs.c */
