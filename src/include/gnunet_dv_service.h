/*
      This file is part of GNUnet
      (C) 2009 Christian Grothoff (and other contributing authors)

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

/**
 * Version of the dv API.
 */
#define GNUNET_DV_VERSION 0x00000000

/**
 * Opaque handle for the dv service.
 */
struct GNUNET_DV_Handle;


int GNUNET_DV_send (struct GNUNET_DV_Handle *dv_handle,
                    const struct GNUNET_PeerIdentity *target,
                    const char *msgbuf,
                    size_t msgbuf_size,
                    unsigned int priority,
                    struct GNUNET_TIME_Relative timeout,
                    const void *addr,
                    size_t addrlen);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
