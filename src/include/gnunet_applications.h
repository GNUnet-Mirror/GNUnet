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
 * Test.
 */
#define GNUNET_APPLICATION_TYPE_TEST 1

/**
 * Internet DNS resolution (external DNS gateway).
 */
#define GNUNET_APPLICATION_TYPE_INTERNET_RESOLVER 2

/**
 * Internet HTTP gateway (port 80).
 */
#define GNUNET_APPLICATION_TYPE_INTERNET_HTTP_GATEWAY 3

/**
 * Internet HTTPS gateway (port 443).
 */
#define GNUNET_APPLICATION_TYPE_INTERNET_HTTPS_GATEWAY 4

/**
 * Internet TCP gateway (any port).
 */
#define GNUNET_APPLICATION_TYPE_INTERNET_TCP_GATEWAY 5

/**
 * Internet UDP gateway (any port).
 */
#define GNUNET_APPLICATION_TYPE_INTERNET_UDP_GATEWAY 6

/**
 * GNUnet VPN Search Engine (searches HTTP sites hosted within GNUnet) [example]
 */
#define GNUNET_APPLICATION_TYPE_GNUNET_SEARCH 7


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_APPLICATIONS_H */
#endif
/* end of gnunet_applications.h */
