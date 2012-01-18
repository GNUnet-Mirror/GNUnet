/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_applications.h
 * @brief constants for network applications operating on top of the MESH service
 * @author Christian Grothoff
 */

#ifndef GNUNET_APPLICATIONS_H
#define GNUNET_APPLICATIONS_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * End of list marker.
 */
#define GNUNET_APPLICATION_TYPE_END 0

/**
 * Test.
 */
#define GNUNET_APPLICATION_TYPE_TEST 1

/**
 * Internet DNS resolution (external DNS gateway).
 */
#define GNUNET_APPLICATION_TYPE_INTERNET_RESOLVER 2


/**
 * Internet IPv4 gateway (any TCP/UDP/ICMP).
 */
#define GNUNET_APPLICATION_TYPE_IPV4_GATEWAY 16

/**
 * Internet IPv6 gateway (any TCP/UDP/ICMP).
 */
#define GNUNET_APPLICATION_TYPE_IPV6_GATEWAY 17


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_APPLICATIONS_H */
#endif
/* end of gnunet_applications.h */
