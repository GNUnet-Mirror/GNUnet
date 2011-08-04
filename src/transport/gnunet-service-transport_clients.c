/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport_clients.c
 * @brief plugin management API
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-transport_clients.h"


/**
 * Start handling requests from clients.
 *
 * @param server server used to accept clients from.
 */
void 
GST_clients_start (struct GNUNET_SERVER_Handle *server)
{
}


/**
 * Stop processing clients.
 */
void
GST_clients_stop ()
{
}


/**
 * Broadcast the given message to all of our clients.
 *
 * @param msg message to broadcast
 */
void
GST_clients_broadcast (const struct GNUNET_MessageHeader *msg)
{
  
}


/* end of file gnunet-service-transport_clients.c */
