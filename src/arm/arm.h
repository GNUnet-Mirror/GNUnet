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
 * @author Christian Grothoff
 * @file arm/arm.h
 */
#ifndef ARM_H
#define ARM_H

#include "gnunet_common.h"

/**
 * This option will turn on the DEBUG loglevel for
 * all processes controlled by this ARM!
 */
#define DEBUG_ARM GNUNET_EXTRA_LOGGING

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Reply from ARM to client.
 */
struct GNUNET_ARM_ResultMessage
{

  /**
   * Reply to client, of type is GNUNET_MESSAGE_TYPE_ARM_RESULT. 
   */
  struct GNUNET_MessageHeader header;
  
  /**
   * Status from the 'enum GNUNET_ARM_ProcessStatus'
   */
  uint32_t status;
};

/**
 * Reply from ARM to client for the 
 * GNUNET_MESSAGE_TYPE_ARM_LIST request followed by count 
 * '\0' terminated strings. header->size contains the
 * total size (including all strings).
 */
struct GNUNET_ARM_ListResultMessage
{
  /**
   * Reply to client is of type GNUNET_MESSAGE_TYPE_ARM_LIST_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of '\0' terminated strings that follow
   * this message.
   */
  uint16_t count;
};

GNUNET_NETWORK_STRUCT_END

#endif
