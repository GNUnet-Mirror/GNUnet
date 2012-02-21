/*
     This file is part of GNUnet.
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
 * @file namestore/namestore.h
 * @brief common internal definitions for namestore service
 * @author Matthias Wachs
 */
#ifndef NAMESTORE_H
#define NAMESTORE_H

GNUNET_NETWORK_STRUCT_BEGIN
/**
 * Change in blacklisting (either request or notification,
 * depending on which direction it is going).
 */
struct StartMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_START
   */
  struct GNUNET_MessageHeader header;

};
GNUNET_NETWORK_STRUCT_END

/* end of namestore.h */
#endif
