/*
      This file is part of GNUnet
      (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_dv_service.h
 * @brief API to deal with dv service
 *
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#ifndef GNUNET_DV_SERVICE_H
#define GNUNET_DV_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_transport_plugin.h"

/**
 * Version of the dv API.
 */
#define GNUNET_DV_VERSION 0x00000000

/**
 * Opaque handle for the dv service.
 */
struct GNUNET_DV_Handle;

/**
 * Send a message from the plugin to the DV service indicating that
 * a message should be sent via DV to some peer.
 *
 * @param dv_handle the handle to the DV api
 * @param target the final target of the message
 * @param msgbuf the msg(s) to send
 * @param msgbuf_size the size of msgbuf
 * @param priority priority to pass on to core when sending the message
 * @param timeout how long can this message be delayed (pass through to core)
 * @param addr the address of this peer (internally known to DV)
 * @param addrlen the length of the peer address
 * @param cont continuation to call once the message has been sent (or failed)
 * @param cont_cls closure for continuation
 *
 */
int
GNUNET_DV_send (struct GNUNET_DV_Handle *dv_handle,
                const struct GNUNET_PeerIdentity *target, const char *msgbuf,
                size_t msgbuf_size, unsigned int priority,
                struct GNUNET_TIME_Relative timeout, const void *addr,
                size_t addrlen, GNUNET_TRANSPORT_TransmitContinuation cont,
                void *cont_cls);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
