/*
     This file is part of GNUnet.
     Copyright (C) 2003, 2004, 2006, 2009 GNUnet e.V.

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
 * Context for #GNUNET_FS_get_indexed_files().
 */
struct GNUNET_FS_GetIndexedContext
{

  /**
   * Connection to the FS service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Function to call for each indexed file.
   */
  GNUNET_FS_IndexedFileProcessor iterator;

  /**
   * Closure for @e iterator.
   */
  void *iterator_cls;

  /**
   * Continuation to trigger at the end.
   */
  GNUNET_SCHEDULER_TaskCallback cont;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;
};


/**
 * Function called on each response from the FS
 * service with information about indexed files.
 *
 * @param cls closure (of type `struct GNUNET_FS_GetIndexedContext *`)
 * @param msg message with indexing information
 */
static void
handle_index_info_end (void *cls,
                       const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_FS_GetIndexedContext *gic = cls;

  (void) gic->iterator (gic->iterator_cls,
                        NULL,
                        NULL);
  GNUNET_FS_get_indexed_files_cancel (gic);
}


/**
 * Check validity of response from the FS
 * service with information about indexed files.
 *
 * @param cls closure (of type `struct GNUNET_FS_GetIndexedContext *`)
 * @param iim message with indexing information
 */
static int
check_index_info (void *cls,
                  const struct IndexInfoMessage *iim)
{
  uint16_t msize = ntohs (iim->header.size) - sizeof (*iim);
  const char *filename;

  filename = (const char *) &iim[1];
  if (filename[msize - 1] != '\0')
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function called on each response from the FS
 * service with information about indexed files.
 *
 * @param cls closure (of type `struct GNUNET_FS_GetIndexedContext *`)
 * @param iim message with indexing information
 */
static void
handle_index_info (void *cls,
                   const struct IndexInfoMessage *iim)
{
  struct GNUNET_FS_GetIndexedContext *gic = cls;
  const char *filename;

  filename = (const char *) &iim[1];
  if (GNUNET_OK !=
      gic->iterator (gic->iterator_cls,
                     filename,
                     &iim->file_id))
  {
    GNUNET_FS_get_indexed_files_cancel (gic);
    return;
  }
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_FS_GetIndexedContent *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_FS_GetIndexedContext *gic = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              _("Failed to receive response from `%s' service.\n"),
              "fs");
  (void) gic->iterator (gic->iterator_cls, NULL, NULL);
  GNUNET_FS_get_indexed_files_cancel (gic);
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
  GNUNET_MQ_hd_fixed_size (index_info_end,
                           GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_END,
                           struct GNUNET_MessageHeader);
  GNUNET_MQ_hd_var_size (index_info,
                         GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_ENTRY,
                         struct IndexInfoMessage);
  struct GNUNET_FS_GetIndexedContext *gic
    = GNUNET_new (struct GNUNET_FS_GetIndexedContext);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    make_index_info_end_handler (gic),
    make_index_info_handler (gic),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;

  gic->mq = GNUNET_CLIENT_connecT (h->cfg,
                                   "fs",
                                   handlers,
                                   &mq_error_handler,
                                   h);
  if (NULL == gic->mq)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to not connect to `%s' service.\n"),
                "fs");
    GNUNET_free (gic);
    return NULL;
  }
  gic->iterator = iterator;
  gic->iterator_cls = iterator_cls;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_GET);
  GNUNET_MQ_send (gic->mq,
                  env);
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
  GNUNET_MQ_destroy (gic->mq);
  GNUNET_free (gic);
}


/* end of fs_list_indexed.c */
