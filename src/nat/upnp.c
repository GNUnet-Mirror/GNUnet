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

/*
 * This file has been adapted from the Transmission project:
 * Originally licensed by the GPL version 2.
 * Copyright (C) 2007-2009 Charles Kerr <charles@transmissionbt.com>
 */

/**
 * @file nat/upnp.c
 * @brief UPnP support for the NAT library
 *
 * @author Milan Bouchet-Valat
 */
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include <miniupnp/miniupnpc.h>
#include <miniupnp/upnpcommands.h>

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_nat_lib.h"
#include "upnp.h"

/* Component name for logging */
#define COMP_NAT_UPNP _("NAT (UPnP)")

enum UPNP_State
{
  UPNP_IDLE,
  UPNP_ERR,
  UPNP_DISCOVER,
  UPNP_MAP,
  UPNP_UNMAP
};

struct GNUNET_NAT_UPNP_Handle
{
  int hasDiscovered;
  struct UPNPUrls urls;
  struct IGDdatas data;
  int port;
  const struct sockaddr *addr;
  socklen_t addrlen;
  unsigned int is_mapped;
  enum UPNP_State state;
  struct sockaddr *ext_addr;
  const char *iface;
};

static int
process_if (void *cls,
            const char *name,
            int isDefault,
            const struct sockaddr *addr,
            socklen_t addrlen)
{
  struct GNUNET_NAT_UPNP_Handle *upnp = cls;

  if (addr && GNUNET_NAT_cmp_addr (upnp->addr, addr) == 0)
    {
      upnp->iface = name; // BADNESS!
      return GNUNET_SYSERR;
    }

  return GNUNET_OK;
}


GNUNET_NAT_UPNP_Handle *
GNUNET_NAT_UPNP_init (const struct sockaddr *addr, 
		      socklen_t addrlen,
                      u_short port)
{
  GNUNET_NAT_UPNP_Handle *upnp;

  upnp = GNUNET_malloc (sizeof (GNUNET_NAT_UPNP_Handle));
  upnp->state = UPNP_DISCOVER;
  upnp->addr = addr;
  upnp->addrlen = addrlen;
  upnp->port = port;
  /* Find the interface corresponding to the address,
   * on which we should broadcast call for routers */
  GNUNET_OS_network_interfaces_list (&process_if, upnp);
  if (!upnp->iface)
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, 
		       COMP_NAT_UPNP, 
		       "Could not find an interface matching the wanted address.\n");
  return upnp;
}


void
GNUNET_NAT_UPNP_close (GNUNET_NAT_UPNP_Handle * handle)
{
  GNUNET_assert (!handle->is_mapped);
  GNUNET_assert ((handle->state == UPNP_IDLE)
          || (handle->state == UPNP_ERR) || (handle->state == UPNP_DISCOVER));

  if (handle->hasDiscovered)
    FreeUPNPUrls (&handle->urls);
  GNUNET_free (handle);
}

/**
 * Check state of UPnP NAT: port redirection, external IP address.
 * 
 * 
 * @param handle the handle for UPnP object
 * @param is_enabled whether enable port redirection
 * @param doPortCheck FIXME
 * @param ext_addr pointer for returning external IP address.
 *     Will be set to NULL if address could not be found. Don't free the sockaddr.
 */
int
GNUNET_NAT_UPNP_pulse (GNUNET_NAT_UPNP_Handle * handle, int is_enabled,
                       int doPortCheck, struct sockaddr **ext_addr)
{
  int ret;

  if (is_enabled && (handle->state == UPNP_DISCOVER))
    {
      struct UPNPDev *devlist;
      errno = 0;
      devlist = upnpDiscover (2000, handle->iface, handle->addr, NULL, 0);
      if (devlist == NULL)
        {
#ifdef DEBUG
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, COMP_NAT_UPNP,
                      "upnpDiscover failed (errno %d - %s)\n", errno,
                      strerror (errno));
#endif
        }
      errno = 0;
      if (UPNP_GetValidIGD (devlist, &handle->urls, &handle->data,
                            NULL, 0))
        {
          GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT_UPNP,
                      _("Found Internet Gateway Device \"%s\"\n"),
                      handle->urls.controlURL);
          handle->state = UPNP_IDLE;
          handle->hasDiscovered = 1;
        }
      else
        {
          handle->state = UPNP_ERR;
#ifdef DEBUG
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, COMP_NAT_UPNP,
                      "UPNP_GetValidIGD failed (errno %d - %s)\n",
                      errno, strerror (errno));
#endif
        }
      freeUPNPDevlist (devlist);
    }

  if (handle->state == UPNP_IDLE)
    {
      if (handle->is_mapped && !is_enabled)
        handle->state = UPNP_UNMAP;
    }

  if (is_enabled && handle->is_mapped && doPortCheck)
    {
      char portStr[8];
      char intPort[8];
      char intClient[128];
      int i;

      GNUNET_snprintf (portStr, sizeof (portStr), "%d", handle->port);
      i = UPNP_GetSpecificPortMappingEntry (handle->urls.controlURL,
                                            handle->data.servicetype, portStr,
                                            "TCP", intClient, intPort);
      if (i != UPNPCOMMAND_SUCCESS)
        {
          GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT_UPNP,
                      _("Port %d isn't forwarded\n"), handle->port);
          handle->is_mapped = GNUNET_NO;
        }
    }

  if (handle->state == UPNP_UNMAP)
    {
      char portStr[16];
      GNUNET_snprintf (portStr, sizeof (portStr), "%d", handle->port);
      UPNP_DeletePortMapping (handle->urls.controlURL,
                              handle->data.servicetype, portStr, "TCP", NULL);
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT_UPNP,
                  _
                  ("Stopping port forwarding through \"%s\", service \"%s\"\n"),
                  handle->urls.controlURL, handle->data.servicetype);
      handle->is_mapped = 0;
      handle->state = UPNP_IDLE;
      handle->port = -1;
    }

  if (handle->state == UPNP_IDLE)
    {
      if (is_enabled && !handle->is_mapped)
        handle->state = UPNP_MAP;
    }

  if (handle->state == UPNP_MAP)
    {
      int err = -1;
      errno = 0;

      if (!handle->urls.controlURL)
        handle->is_mapped = 0;
      else
        {
          char portStr[16];
          char desc[64];
          GNUNET_snprintf (portStr, sizeof (portStr), "%d", handle->port);
          GNUNET_snprintf (desc, sizeof (desc), "GNUnet at %d", handle->port);
          err = UPNP_AddPortMapping (handle->urls.controlURL,
                                     handle->data.servicetype,
                                     portStr, portStr, GNUNET_a2s (handle->addr, handle->addrlen),              
                                     desc, "TCP", NULL);
          handle->is_mapped = !err;
        }
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT_UPNP,
                  _
                  ("Port forwarding through \"%s\", service \"%s\"\n"),
                  handle->urls.controlURL, handle->data.servicetype);
      if (handle->is_mapped)
        {
          GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT_UPNP,
                      _("Port %d forwarded successfully\n"), handle->port);
          handle->state = UPNP_IDLE;
        }
      else
        {
          GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT_UPNP,
                      "Port forwarding failed with error %d (errno %d - %s)\n",
                      err, errno, strerror (errno));
          handle->state = UPNP_ERR;
        }
    }

  if (ext_addr && handle->state != UPNP_DISCOVER)
    {
      int err;
      char addr_str[128];
      struct in_addr addr;
      struct in6_addr addr6;

      /* Keep to NULL if address could not be found */
      *ext_addr = NULL;
      err = UPNP_GetExternalIPAddress (handle->urls.controlURL,
                                       handle->data.servicetype, addr_str);
      if (err == 0)
        {
          if (handle->ext_addr)
            {
              GNUNET_free (handle->ext_addr);
              handle->ext_addr = NULL;
            }

          /* Try IPv4 and IPv6 as we don't know what's the format */
          if (inet_aton (addr_str, &addr) != 0)
            {
              handle->ext_addr = GNUNET_malloc (sizeof (struct sockaddr_in));
              handle->ext_addr->sa_family = AF_INET;
              ((struct sockaddr_in *) handle->ext_addr)->sin_addr = addr;
              *ext_addr = handle->ext_addr;
            }
          else if (inet_pton (AF_INET6, addr_str, &addr6) != 1)
            {
              handle->ext_addr = GNUNET_malloc (sizeof (struct sockaddr_in6));
              handle->ext_addr->sa_family = AF_INET6;
              ((struct sockaddr_in6 *) handle->ext_addr)->sin6_addr = addr6;
              *ext_addr = handle->ext_addr;
            }
          else
            GNUNET_assert (GNUNET_YES);
#ifdef DEBUG
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, COMP_NAT_UPNP,
                      _("Found public IP address %s\n"),
                      addr_str);
#endif
        }
      else
        {
          *ext_addr = NULL;
          if (handle->ext_addr)
            {
              GNUNET_free (handle->ext_addr);
              handle->ext_addr = NULL;
            }
#ifdef DEBUG
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, COMP_NAT_UPNP,
                      "UPNP_GetExternalIPAddress failed (error %d)\n", err);
#endif
        }
    }

  switch (handle->state)
    {
    case UPNP_DISCOVER:
      ret = GNUNET_NAT_PORT_UNMAPPED;
      break;

    case UPNP_MAP:
      ret = GNUNET_NAT_PORT_MAPPING;
      break;

    case UPNP_UNMAP:
      ret = GNUNET_NAT_PORT_UNMAPPING;
      break;

    case UPNP_IDLE:
      ret =
        handle->is_mapped ? GNUNET_NAT_PORT_MAPPED : GNUNET_NAT_PORT_UNMAPPED;
      break;

    default:
      ret = GNUNET_NAT_PORT_ERROR;
      break;
    }

  return ret;
}
