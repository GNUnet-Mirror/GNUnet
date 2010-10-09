/*
     This file is part of GNUnet.
     (C) 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file nat/nat.h
 * @brief Library handling UPnP and NAT-PMP port forwarding and
 *     external IP address retrieval
 * @author Milan Bouchet-Valat
 */

#ifndef NAT_H
#define NAT_H

#define DEBUG GNUNET_YES

/**
 * Used to communicate with the UPnP and NAT-PMP plugins 
 */
enum GNUNET_NAT_PortState
{
  GNUNET_NAT_PORT_ERROR,

    /**
     * the port isn't forwarded 
     */
  GNUNET_NAT_PORT_UNMAPPED,

    /**
     * we're cancelling the port forwarding 
     */
  GNUNET_NAT_PORT_UNMAPPING,

    /**
     * we're in the process of trying to set up port forwarding 
     */
  GNUNET_NAT_PORT_MAPPING,

    /**
     * we've successfully forwarded the port 
     */
  GNUNET_NAT_PORT_MAPPED
};


/**
 * Compare the sin(6)_addr fields of AF_INET or AF_INET(6) sockaddr.
 * 
 * @param a first sockaddr
 * @param b second sockaddr
 * @return 0 if addresses are equal, non-null value otherwise 
 */
int GNUNET_NAT_cmp_addr (const struct sockaddr *a, const struct sockaddr *b);


#endif
