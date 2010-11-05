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

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_nat_lib.h"
#include "nat.h"
#include "upnp-discover.h"
#include "upnp-commands.h"
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
  char *control_url;
  char *service_type;
  int port;
  const struct sockaddr *addr;
  socklen_t addrlen;
  unsigned int is_mapped;
  enum UPNP_State state;
  struct sockaddr *ext_addr;
  const char *iface;
  int processing;
  GNUNET_NAT_UPNP_pulse_cb pulse_cb;
  void *pulse_cls;
};

static int
process_if (void *cls,
            const char *name,
            int isDefault, const struct sockaddr *addr, socklen_t addrlen)
{
  struct GNUNET_NAT_UPNP_Handle *upnp = cls;

  if (addr && GNUNET_NAT_cmp_addr (upnp->addr, addr) == 0)
    {
      upnp->iface = name;       // BADNESS!
      return GNUNET_SYSERR;
    }

  return GNUNET_OK;
}


struct GNUNET_NAT_UPNP_Handle *
GNUNET_NAT_UPNP_init (const struct sockaddr *addr,
                      socklen_t addrlen,
                      u_short port,
                      GNUNET_NAT_UPNP_pulse_cb pulse_cb, void *pulse_cls)
{
  struct GNUNET_NAT_UPNP_Handle *handle;

  handle = GNUNET_malloc (sizeof (struct GNUNET_NAT_UPNP_Handle));
  handle->processing = GNUNET_NO;
  handle->state = UPNP_DISCOVER;
  handle->addr = addr;
  handle->addrlen = addrlen;
  handle->port = port;
  handle->pulse_cb = pulse_cb;
  handle->pulse_cls = pulse_cls;
  handle->control_url = NULL;
  handle->service_type = NULL;

  /* Find the interface corresponding to the address,
   * on which we should broadcast call for routers */
  GNUNET_OS_network_interfaces_list (&process_if, handle);
  if (!handle->iface)
    GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
                     COMP_NAT_UPNP,
                     "Could not find an interface matching the wanted address.\n");
  return handle;
}


void
GNUNET_NAT_UPNP_close (struct GNUNET_NAT_UPNP_Handle *handle)
{
  GNUNET_assert (!handle->is_mapped);
  GNUNET_assert ((handle->state == UPNP_IDLE)
                 || (handle->state == UPNP_ERR)
                 || (handle->state == UPNP_DISCOVER));

  GNUNET_free_non_null (handle->control_url);
  GNUNET_free_non_null (handle->service_type);
  GNUNET_free (handle);
}

static void
pulse_finish (struct GNUNET_NAT_UPNP_Handle *handle)
{
  enum GNUNET_NAT_PortState status;
  handle->processing = GNUNET_NO;

  switch (handle->state)
    {
    case UPNP_DISCOVER:
      status = GNUNET_NAT_PORT_UNMAPPED;
      break;

    case UPNP_MAP:
      status = GNUNET_NAT_PORT_MAPPING;
      break;

    case UPNP_UNMAP:
      status = GNUNET_NAT_PORT_UNMAPPING;
      break;

    case UPNP_IDLE:
      status =
        handle->is_mapped ? GNUNET_NAT_PORT_MAPPED : GNUNET_NAT_PORT_UNMAPPED;
      break;

    default:
      status = GNUNET_NAT_PORT_ERROR;
      break;
    }

  handle->pulse_cb (status, handle->ext_addr, handle->pulse_cls);
}

static void
discover_cb (const char *control_url, const char *service_type, void *cls)
{
  struct GNUNET_NAT_UPNP_Handle *handle = cls;

  if (control_url)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT_UPNP,
                       _("Found Internet Gateway Device \"%s\"\n"),
                       control_url);

      GNUNET_free_non_null (handle->control_url);
      GNUNET_free_non_null (handle->service_type);

      handle->control_url = GNUNET_strdup (control_url);
      handle->service_type = GNUNET_strdup (service_type);
      handle->state = UPNP_IDLE;
      handle->hasDiscovered = 1;
    }
  else
    {
      handle->control_url = NULL;
      handle->service_type = NULL;
      handle->state = UPNP_ERR;
#ifdef DEBUG_UPNP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, COMP_NAT_UPNP,
                       "UPNP device discovery failed\n");
#endif
    }

  pulse_finish (handle);
}

static void
check_port_mapping_cb (int error, const char *control_url,
                       const char *service_type, const char *extPort,
                       const char *inPort, const char *proto,
                       const char *remoteHost, void *cls)
{
  struct GNUNET_NAT_UPNP_Handle *handle = cls;

  if (error)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT_UPNP,
                       _("Port %d isn't forwarded\n"), handle->port);
      handle->is_mapped = GNUNET_NO;
    }

  pulse_finish (handle);
}

static void
delete_port_mapping_cb (int error, const char *control_url,
                        const char *service_type, const char *extPort,
                        const char *inPort, const char *proto,
                        const char *remoteHost, void *cls)
{
  struct GNUNET_NAT_UPNP_Handle *handle = cls;

  if (error)
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT_UPNP,
                     _
                     ("Could not stop port forwarding through \"%s\", service \"%s\": error %d\n"),
                     handle->control_url, handle->service_type, error);
  else
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT_UPNP,
                       _
                       ("Stopped port forwarding through \"%s\", service \"%s\"\n"),
                       handle->control_url, handle->service_type);
      handle->is_mapped = !error;
      handle->state = UPNP_IDLE;
      handle->port = -1;
    }

  pulse_finish (handle);
}

static void
add_port_mapping_cb (int error, const char *control_url,
                     const char *service_type, const char *extPort,
                     const char *inPort, const char *proto,
                     const char *remoteHost, void *cls)
{
  struct GNUNET_NAT_UPNP_Handle *handle = cls;

  if (error)
    {
      handle->is_mapped = GNUNET_NO;
      handle->state = UPNP_ERR;
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT_UPNP,
                       _
                       ("Port forwarding through \"%s\", service \"%s\" failed with error %d\n"),
                       handle->control_url, handle->service_type, error);
      return;
    }
  else
    {
      handle->is_mapped = GNUNET_NO;
      handle->state = UPNP_IDLE;
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT_UPNP,
                       _("Port %d forwarded successfully\n"), handle->port);
    }

  pulse_finish (handle);
}

static void
get_ip_address_cb (int error, char *ext_addr, void *cls)
{
  struct GNUNET_NAT_UPNP_Handle *handle = cls;

  if (error)
    {
      if (handle->ext_addr)
        {
          GNUNET_free (handle->ext_addr);
          handle->ext_addr = NULL;
        }
#ifdef DEBUG_UPNP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, COMP_NAT_UPNP,
                       "UPNP_get_external_ip_address_ failed (error %d)\n",
                       error);
#endif
    }
  else
    {
      struct in_addr addr;
      struct in6_addr addr6;

      if (handle->ext_addr)
        {
          GNUNET_free (handle->ext_addr);
          handle->ext_addr = NULL;
        }

      /* Try IPv4 and IPv6 as we don't know what's the format */
      if (inet_aton (ext_addr, &addr) != 0)
        {
          handle->ext_addr = GNUNET_malloc (sizeof (struct sockaddr_in));
          handle->ext_addr->sa_family = AF_INET;
          ((struct sockaddr_in *) handle->ext_addr)->sin_addr = addr;
        }
      else if (inet_pton (AF_INET6, ext_addr, &addr6) != 1)
        {
          handle->ext_addr = GNUNET_malloc (sizeof (struct sockaddr_in6));
          handle->ext_addr->sa_family = AF_INET6;
          ((struct sockaddr_in6 *) handle->ext_addr)->sin6_addr = addr6;
        }
      else
        GNUNET_assert (GNUNET_YES);

#ifdef DEBUG_UPNP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, COMP_NAT_UPNP,
                       _("Found public IP address %s\n"), ext_addr);
#endif
    }

  pulse_finish (handle);
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
void
GNUNET_NAT_UPNP_pulse (struct GNUNET_NAT_UPNP_Handle *handle,
                       int is_enabled, int doPortCheck)
{
  /* Stop if we're already waiting for an action to complete */
  if (handle->processing == GNUNET_YES)
    return;

  if (is_enabled && (handle->state == UPNP_DISCOVER))
    {
      handle->processing = GNUNET_YES;
      UPNP_discover_ (handle->iface, handle->addr, discover_cb,
                      handle);
    }

  if (handle->state == UPNP_IDLE)
    {
      if (handle->is_mapped && !is_enabled)
        handle->state = UPNP_UNMAP;
    }

  if (is_enabled && handle->is_mapped && doPortCheck)
    {
      char portStr[8];

      GNUNET_snprintf (portStr, sizeof (portStr), "%d", handle->port);

      handle->processing = GNUNET_YES;
      UPNP_get_specific_port_mapping_entry_ (handle->control_url,
                                             handle->service_type, portStr,
                                             "TCP", check_port_mapping_cb,
                                             handle);
    }

  if (handle->state == UPNP_UNMAP)
    {
      char portStr[16];
      GNUNET_snprintf (portStr, sizeof (portStr), "%d", handle->port);

      handle->processing = GNUNET_YES;
      UPNP_delete_port_mapping_ (handle->control_url,
                                 handle->service_type, portStr, "TCP", NULL,
                                 delete_port_mapping_cb, handle);
    }

  if (handle->state == UPNP_IDLE)
    {
      if (is_enabled && !handle->is_mapped)
        handle->state = UPNP_MAP;
    }

  if (handle->state == UPNP_MAP)
    {
      if (!handle->control_url)
        handle->is_mapped = 0;
      else
        {
          char portStr[16];
          char desc[64];
          GNUNET_snprintf (portStr, sizeof (portStr), "%d", handle->port);
          GNUNET_snprintf (desc, sizeof (desc), "GNUnet at %d", handle->port);

          handle->processing = GNUNET_YES;
          UPNP_add_port_mapping_ (handle->control_url,
                                  handle->service_type,
                                  portStr, portStr, GNUNET_a2s (handle->addr,
                                                                handle->addrlen),
                                  desc, "TCP", NULL, add_port_mapping_cb,
                                  handle);
        }
    }

  if (handle->state != UPNP_DISCOVER)
    {
      handle->processing = GNUNET_YES;
      UPNP_get_external_ip_address_ (handle->control_url,
                                     handle->service_type,
                                     get_ip_address_cb, handle);
    }
}
