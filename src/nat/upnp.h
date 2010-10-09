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
 * @file nat/upnp.h
 * @brief UPnP support for the NAT library
 *
 * @author Milan Bouchet-Valat
 */

#ifndef UPNP_H
#define UPNP_H 1

#include "platform.h"

struct GNUNET_NAT_UPNP_Handle;

typedef void (*GNUNET_NAT_UPNP_pulse_cb) (int status,
                                          struct sockaddr * ext_addr,
                                          void *cls);

struct GNUNET_NAT_UPNP_Handle *GNUNET_NAT_UPNP_init (struct
                                                     GNUNET_SCHEDULER_Handle
                                                     *sched,
                                                     const struct sockaddr
                                                     *addr, socklen_t addrlen,
                                                     unsigned short port,
                                                     GNUNET_NAT_UPNP_pulse_cb
                                                     pulse_cb,
                                                     void *pulse_cls);

void GNUNET_NAT_UPNP_close (struct GNUNET_NAT_UPNP_Handle *h);

void GNUNET_NAT_UPNP_pulse (struct GNUNET_NAT_UPNP_Handle *h,
                            int is_enabled, int do_port_check);

#endif
/* UPNP_H */
