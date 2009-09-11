/*
     This file is part of GNUnet.
     (C) 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file upnp/upnp_ip.c
 * @brief code to determine the IP of the local machine
 *
 * @author Christian Grothoff
 */

#include <stdlib.h>
#include "platform.h"
#include "gnunet_util.h"
#include "ip.h"

/**
 * Get the IP address for the local machine.
 * @return NULL on error
 */
char *
GNUNET_upnp_get_internal_ip (struct GNUNET_GC_Configuration *cfg,
                             struct GNUNET_GE_Context *ectx)
{
  struct in_addr address;

  return GNUNET_get_local_ip (cfg, ectx, &address);
}


/* end of ip.c */
