/*
   This file is part of GNUnet.
   Copyright (C) 2010-2015, 2018 GNUnet e.V.

   GNUnet is free software: you can redistribute it and/or modify it
   under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License,
   or (at your option) any later version.

   GNUnet is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file network type characterization
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 * @defgroup nt  network type characterization
 *
 * @{
 */
#ifndef GNUNET_NT_LIB_H
#define GNUNET_NT_LIB_H

/**
 * Types of networks (with separate quotas) we support.
 */
enum GNUNET_NetworkType
{
  /**
   * Category of last resort.
   */
  GNUNET_NT_UNSPECIFIED = 0,

  /**
   * Loopback (same host).
   */
  GNUNET_NT_LOOPBACK = 1,

  /**
   * Local area network.
   */
  GNUNET_NT_LAN = 2,

  /**
   * Wide area network (i.e. Internet)
   */
  GNUNET_NT_WAN = 3,

  /**
   * Wireless LAN (i.e. 802.11abgn)
   */
  GNUNET_NT_WLAN = 4,

  /**
   * Bluetooth LAN
   */
  GNUNET_NT_BT = 5

/**
 * Number of network types supported by ATS
 */
#define GNUNET_NT_COUNT 6
};


/**
 * Convert a `enum GNUNET_NetworkType` to a string
 *
 * @param net the network type
 * @return a string or NULL if invalid
 */
const char *
GNUNET_NT_to_string (enum GNUNET_NetworkType net);


/**
 * Handle for the LAN Characterization library.
 */
struct GNUNET_NT_InterfaceScanner;


/**
 * Returns where the address is located: loopback, LAN or WAN.
 *
 * @param is handle from #GNUNET_ATS_interface_scanner_init()
 * @param addr address
 * @param addrlen address length
 * @return type of the network the address belongs to
 */
enum GNUNET_NetworkType
GNUNET_NT_scanner_get_type (struct GNUNET_NT_InterfaceScanner *is,
                            const struct sockaddr *addr,
                            socklen_t addrlen);


/**
 * Initialize the address characterization client handle.
 *
 * @return scanner handle, NULL on error
 */
struct GNUNET_NT_InterfaceScanner *
GNUNET_NT_scanner_init (void);


/**
 * Terminate interface scanner.
 *
 * @param is scanner we are done with
 */
void
GNUNET_NT_scanner_done (struct GNUNET_NT_InterfaceScanner *is);


#endif

/** @} */  /* end of group */
