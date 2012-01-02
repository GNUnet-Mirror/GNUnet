/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff

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
 * @file vpn/gnunet-helper-vpn-api.c
 * @brief exposes the API (the convenience-functions) of dealing with the
 *        helper-vpn
 * @author Philipp Toelke
 */

#include <platform.h>
#include <gnunet_common.h>
#include <gnunet_server_lib.h>
#include <gnunet_os_lib.h>

#include "gnunet-helper-vpn-api.h"


void
cleanup_helper (struct GNUNET_VPN_HELPER_Handle *handle)
{
  stop_helper (handle);
  GNUNET_free (handle);
}

struct GNUNET_VPN_HELPER_Handle *
start_helper (const char *ifname, const char *ipv6addr, const char *ipv6prefix,
              const char *ipv4addr, const char *ipv4mask,
              const char *process_name, GNUNET_SCHEDULER_Task restart_task,
              GNUNET_SERVER_MessageTokenizerCallback cb, void *cb_cls)
{

