/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_sat_send.h
 * @brief header for transport plugin for satellite for send operations
 * @author Christian Rupp
 */

#ifndef PLUGIN_TRANSPORT_SAT_SEND
#define PLUGIN_TRANSPORT_SAT_SEND

#include <stdint.h>
#include "gnunet_common.h"

typedef struct MacAdress
{
  uint8_t mac[6];
} MacAdress;

//praeamble
static const struct char praeambel[56] =
    { {1, 0, 1, 0, 10, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
       0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
       0, 1, 0, 1, 0, 1, 0}
};

//start of frame
static const struct char sof[8] = { {1, 0, 1, 0, 1, 0, 1, 1} }

// broadcast mac
static const struct MacAddress bc_all_mac =
    { {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} };

//crc polynom
static const struct char ploynom[32] =
    { {1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1,
       0, 0, 1, 0, 0, 0, 0, 1}
};
#endif
