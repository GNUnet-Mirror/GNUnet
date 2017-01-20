/*
  This file is part of GNUnet.
  Copyright (C) 2016, 2017 GNUnet e.V.

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
 * @file nat/gnunet-service-nat.h
 * @brief network address translation traversal service
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_NAT_H
#define GNUNET_SERVICE_NAT_H

/**
 * Is UPnP enabled? #GNUNET_YES if enabled, #GNUNET_NO if disabled,
 * #GNUNET_SYSERR if configuration enabled but binary is unavailable.
 */
extern int enable_upnp;

#endif
