/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016 GNUnet e.V.

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
 * @file transport/transport_api.c
 * @brief library to obtain our HELLO from our transport service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"
#include "transport.h"


/**
 * Linked list of functions to call whenever our HELLO is updated.
 */
struct GNUNET_TRANSPORT_GetHelloHandle
{

  /**
   * This is a doubly linked list.
   */
  struct GNUNET_TRANSPORT_GetHelloHandle *next;

  /**
   * This is a doubly linked list.
   */
  struct GNUNET_TRANSPORT_GetHelloHandle *prev;

  /**
   * Transport handle.
   */
  struct GNUNET_TRANSPORT_Handle *handle;

  /**
   * Callback to call once we got our HELLO.
   */
  GNUNET_TRANSPORT_HelloUpdateCallback rec;

  /**
   * Task for calling the HelloUpdateCallback when we already have a HELLO
   */
  struct GNUNET_SCHEDULER_Task *notify_task;

  /**
   * Closure for @e rec.
   */
  void *rec_cls;

};



/**
 * Task to call the HelloUpdateCallback of the GetHelloHandle
 *
 * @param cls the `struct GNUNET_TRANSPORT_GetHelloHandle`
 */
static void
call_hello_update_cb_async (void *cls)
{
  struct GNUNET_TRANSPORT_GetHelloHandle *ghh = cls;

  GNUNET_assert (NULL != ghh->handle->my_hello);
  GNUNET_assert (NULL != ghh->notify_task);
  ghh->notify_task = NULL;
  ghh->rec (ghh->rec_cls,
            ghh->handle->my_hello);
}


/**
 * Obtain the HELLO message for this peer.  The callback given in this function
 * is never called synchronously.
 *
 * @param handle connection to transport service
 * @param rec function to call with the HELLO, sender will be our peer
 *            identity; message and sender will be NULL on timeout
 *            (handshake with transport service pending/failed).
 *             cost estimate will be 0.
 * @param rec_cls closure for @a rec
 * @return handle to cancel the operation
 */
struct GNUNET_TRANSPORT_GetHelloHandle *
GNUNET_TRANSPORT_get_hello (struct GNUNET_TRANSPORT_Handle *handle,
                            GNUNET_TRANSPORT_HelloUpdateCallback rec,
                            void *rec_cls)
{
  struct GNUNET_TRANSPORT_GetHelloHandle *hwl;

  hwl = GNUNET_new (struct GNUNET_TRANSPORT_GetHelloHandle);
  hwl->rec = rec;
  hwl->rec_cls = rec_cls;
  hwl->handle = handle;
  GNUNET_CONTAINER_DLL_insert (handle->hwl_head,
                               handle->hwl_tail,
                               hwl);
  if (NULL != handle->my_hello)
    hwl->notify_task = GNUNET_SCHEDULER_add_now (&call_hello_update_cb_async,
                                                 hwl);
  return hwl;
}


/**
 * Stop receiving updates about changes to our HELLO message.
 *
 * @param ghh handle to cancel
 */
void
GNUNET_TRANSPORT_get_hello_cancel (struct GNUNET_TRANSPORT_GetHelloHandle *ghh)
{
  struct GNUNET_TRANSPORT_Handle *handle = ghh->handle;

  if (NULL != ghh->notify_task)
    GNUNET_SCHEDULER_cancel (ghh->notify_task);
  GNUNET_CONTAINER_DLL_remove (handle->hwl_head,
                               handle->hwl_tail,
                               ghh);
  GNUNET_free (ghh);
}


/* end of transport_api_hello.c */
