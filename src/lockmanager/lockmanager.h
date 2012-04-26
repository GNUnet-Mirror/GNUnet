/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file lockmanager/lockmanager.h
 * @brief client-server protocol messages for LOCKMANAGER service
 * @author Sree Harsha Totakura
 */

#ifndef LOCKMANAGER_H
#define LOCKMANAGER_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"

/**
 * Structure of Lockmanager message
 */
struct GNUNET_LOCKMANAGER_Message
{
  /**
   * The generic message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * The lock
   */
  uint32_t lock;

  /**
   * The locking domain name(NULL terminated string of characters) should
   * follow here. The size of the header should include the size of this string
   * with its trailing NULL
   */
};

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef LOCKMANAGER_H */
#endif
/* end of lockmanager.h */
