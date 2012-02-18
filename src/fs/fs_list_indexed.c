/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_list_indexed.c
 * @author Christian Grothoff
 * @brief provide a list of all indexed files
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_fs_service.h"
#include "gnunet_protocols.h"
#include "fs_api.h"


/**
 * Context for "GNUNET_FS_get_indexed_files".
 */
struct GNUNET_FS_GetIndexedContext
{
  /**
   * Handle to global FS context.
   */
  struct GNUNET_FS_Handle *h;

  /**
   * Connection to the FS service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Function to call for each indexed file.
   */
  GNUNET_FS_IndexedFileProcessor iterator;

  /**
   * Closure for iterator.
   */
  void *iterator_cls;

  /**
   * Continuation to trigger at the end.
   */
  GNUNET_SCHEDULER_Task cont;

  /**
   * Closure for cont.
   */
  void *cont_cls;
};


/**
 * Function called on each response from the FS
 * service with information about indexed files.
 *
 * @param cls closure (of type "struct GNUNET_FS_GetIndexedContext*")
 * @param msg message with indexing information
 */
static void
handle_index_info (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_FS_GetIndexedContext *gic = cls;
  const struct IndexInfoMessage *iim;
  uint16_t msize;
  const char *filename;

  if (NULL == msg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Failed to receive response for `%s' request from `%s' service.\n"),
                "GET_INDEXED", "fs");
    (void) gic->iterator (gic->iterator_cls, NULL, NULL);
    GNUNET_FS_get_indexed_files_cancel (gic);
    return;
  }
  if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_END)
  {
    /* normal end-of-list */
    (void) gic->iterator (gic->iterator_cls, NULL, NULL);
    GNUNET_FS_get_indexed_files_cancel (gic);
    return;
  }
  msize = ntohs (msg->size);
  iim = (const struct IndexInfoMessage *) msg;
  filename = (const char *) &iim[1];
  if ((ntohs (msg->type) != GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_ENTRY) ||
      (msize <= sizeof (struct IndexInfoMessage)) ||
      (filename[msize - sizeof (struct IndexInfoMessage) - 1] != '\0'))
  {
    /* bogus reply */
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Failed to receive valid response for `%s' request from `%s' service.\n"),
                "GET_INDEXED", "fs");
    (void) gic->iterator (gic->iterator_cls, NULL, NULL);
    GNUNET_FS_get_indexed_files_cancel (gic);
    return;
  }
  if (GNUNET_OK != gic->iterator (gic->iterator_cls, filename, &iim->file_id))
  {
    GNUNET_FS_get_indexed_files_cancel (gic);
    return;
  }
  /* get more */
  GNUNET_CLIENT_receive (gic->client, &handle_index_info, gic,
                         GNUNET_CONSTANTS_SERVICE_TIMEOUT);
}


/**
 * Iterate over all indexed files.
 *
 * @param h handle to the file sharing subsystem
 * @param iterator function to call on each indexed file
 * @param iterator_cls closure for iterator
 * @return NULL on error ('iter' is not called)
 */
struct GNUNET_FS_GetIndexedContext *
GNUNET_FS_get_indexed_files (struct GNUNET_FS_Handle *h,
                             GNUNET_FS_IndexedFileProcessor iterator,
                             void *iterator_cls)
{
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_FS_GetIndexedContext *gic;
  struct GNUNET_MessageHeader msg;

  client = GNUNET_CLIENT_connect ("fs", h->cfg);
  if (NULL == client)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to not connect to `%s' service.\n"), "fs");
    return NULL;
  }
  gic = GNUNET_malloc (sizeof (struct GNUNET_FS_GetIndexedContext));
  gic->h = h;
  gic->client = client;
  gic->iterator = iterator;
  gic->iterator_cls = iterator_cls;
  msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  msg.type = htons (GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_GET);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CLIENT_transmit_and_get_response (client, &msg,
                                                          GNUNET_CONSTANTS_SERVICE_TIMEOUT,
                                                          GNUNET_YES,
                                                          &handle_index_info,
                                                          gic));
  return gic;
}


/**
 * Cancel iteration over all indexed files.
 *
 * @param gic operation to cancel
 */
void
GNUNET_FS_get_indexed_files_cancel (struct GNUNET_FS_GetIndexedContext *gic)
{
  GNUNET_CLIENT_disconnect (gic->client, GNUNET_NO);
  GNUNET_free (gic);
}


/* end of fs_list_indexed.c */
