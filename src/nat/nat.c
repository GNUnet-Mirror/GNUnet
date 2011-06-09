/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * Parts of this file have been adapted from the Transmission project:
 * Originally licensed by the GPL version 2.
 * Copyright (C) 2007-2009 Charles Kerr <charles@transmissionbt.com>
 */

/**
 * @file nat/nat.c
 * @brief Library handling UPnP and NAT-PMP port forwarding and
 *     external IP address retrieval
 *
 * @author Milan Bouchet-Valat
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_nat_lib.h"
#include "nat.h"
#include "natpmp.h"
#include "upnp.h"

/**
 * Handle for active NAT registrations.
 */
struct GNUNET_NAT_Handle
{
  /**
   * Handle for UPnP operations.
   */
  struct GNUNET_NAT_UPNP_Handle *upnp;

  /**
   * Handle for NAT PMP operations.
   */
  struct GNUNET_NAT_NATPMP_Handle *natpmp;

  /**
   * LAN address as passed by the caller 
   */
  struct sockaddr *local_addr;

  /**
   * External address as reported by found NAT box 
   */
  struct sockaddr *ext_addr;

  /**
   * External address as reported by each type of NAT box 
   */
  struct sockaddr *ext_addr_upnp;
  struct sockaddr *ext_addr_natpmp;

  /**
   * External address and port where packets are redirected
   */
  struct sockaddr *contact_addr;

  GNUNET_NAT_AddressCallback callback;

  /**
   * Closure for 'callback'.
   */
  void *callback_cls;

  GNUNET_SCHEDULER_TaskIdentifier pulse_timer;

  enum GNUNET_NAT_PortState natpmp_status;

  enum GNUNET_NAT_PortState upnp_status;

  int is_enabled;

  int should_change;

  int port_mapped;

  int old_status;

  int new_status;

  int did_warn;

  int processing;

  uint16_t public_port;

};

#ifdef DEBUG
static const char *
get_nat_state_str (enum GNUNET_NAT_PortState state)
{
  switch (state)
    {
    case GNUNET_NAT_PORT_MAPPING:
      return "Starting";
    case GNUNET_NAT_PORT_MAPPED:
      return "Forwarded";
    case GNUNET_NAT_PORT_UNMAPPING:
      return "Stopping";
    case GNUNET_NAT_PORT_UNMAPPED:
      return "Not forwarded";
    case GNUNET_NAT_PORT_ERROR:
      return "Redirection failed";
    default:
      return "not found";
    }
}
#endif


static int
get_traversal_status (const struct GNUNET_NAT_Handle *h)
{
  return GNUNET_MAX (h->natpmp_status, h->upnp_status);
}


/**
 * Compare the sin(6)_addr fields of AF_INET or AF_INET(6) sockaddr.
 * @param a first sockaddr
 * @param b second sockaddr
 * @return 0 if addresses are equal, non-null value otherwise */
int
GNUNET_NAT_cmp_addr (const struct sockaddr *a, const struct sockaddr *b)
{
  if (!(a && b))
    return -1;
  if ((a->sa_family == AF_INET) && (b->sa_family == AF_INET))
    return memcmp (&(((struct sockaddr_in *) a)->sin_addr),
                   &(((struct sockaddr_in *) b)->sin_addr),
                   sizeof (struct in_addr));
  if ((a->sa_family == AF_INET6) && (b->sa_family == AF_INET6))
    return memcmp (&(((struct sockaddr_in6 *) a)->sin6_addr),
                   &(((struct sockaddr_in6 *) b)->sin6_addr),
                   sizeof (struct in6_addr));
  return -1;
}


/**
 * Deal with a new IP address or port redirection:
 * Send signals with the appropriate sockaddr (IP and port), free and changes
 * or nullify the previous sockaddr. Change the port if needed.
 */
static void
notify_change (struct GNUNET_NAT_Handle *h,
               struct sockaddr *addr, size_t addrlen, int new_port_mapped)
{
  if (new_port_mapped == h->port_mapped)
    return;
  h->port_mapped = new_port_mapped;

  if ((NULL != h->contact_addr) && (NULL != h->callback))
    h->callback (h->callback_cls,
                 GNUNET_NO, h->contact_addr, sizeof (h->contact_addr));
  GNUNET_free_non_null (h->contact_addr);
  h->contact_addr = NULL;
  GNUNET_free_non_null (h->ext_addr);
  h->ext_addr = NULL;
  if (NULL == addr)
    return;
  h->ext_addr = GNUNET_malloc (addrlen);
  memcpy (h->ext_addr, addr, addrlen);

  /* Recreate the ext_addr:public_port bogus address to pass to the callback */
  if (h->ext_addr->sa_family == AF_INET)
    {
      struct sockaddr_in *tmp_addr;

      tmp_addr = GNUNET_malloc (sizeof (struct sockaddr_in));
      tmp_addr->sin_family = AF_INET;
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
      tmp_addr->sin_len = sizeof (struct sockaddr_in);
#endif
      tmp_addr->sin_port = h->port_mapped ? htons (h->public_port) : 0;
      tmp_addr->sin_addr = ((struct sockaddr_in *) h->ext_addr)->sin_addr;
      h->contact_addr = (struct sockaddr *) tmp_addr;

      if (NULL != h->callback)
        h->callback (h->callback_cls,
                     GNUNET_YES,
                     h->contact_addr, sizeof (struct sockaddr_in));
    }
  else if (h->ext_addr->sa_family == AF_INET6)
    {
      struct sockaddr_in6 *tmp_addr;

      tmp_addr = GNUNET_malloc (sizeof (struct sockaddr_in6));
      tmp_addr->sin6_family = AF_INET6;
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
      tmp_addr->sin6_len = sizeof (struct sockaddr_in6);
#endif
      tmp_addr->sin6_port = h->port_mapped ? htons (h->public_port) : 0;
      tmp_addr->sin6_addr = ((struct sockaddr_in6 *) h->ext_addr)->sin6_addr;
      h->contact_addr = (struct sockaddr *) tmp_addr;

      if (NULL != h->callback)
        h->callback (h->callback_cls,
                     GNUNET_YES,
                     h->contact_addr, sizeof (struct sockaddr_in6));
    }
  else
    {
      GNUNET_break (0);
    }
}

static void nat_pulse (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext *tc);

static void
pulse_cb (struct GNUNET_NAT_Handle *h)
{
  socklen_t addrlen;
  int port_mapped;

  /* One of the protocols is still working, wait for it to complete */
  if (h->processing)
    return;

  h->new_status = get_traversal_status (h);
  if ((h->old_status != h->new_status) &&
      ((h->new_status == GNUNET_NAT_PORT_UNMAPPED) ||
       (h->new_status == GNUNET_NAT_PORT_ERROR)))
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                     "NAT",
                     _
                     ("Port redirection failed: no UPnP or NAT-PMP routers supporting this feature found\n"));
#ifdef DEBUG
  if (h->new_status != h->old_status)
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "NAT",
                     _("State changed from `%s' to `%s'\n"),
                     get_nat_state_str (h->old_status),
                     get_nat_state_str (h->new_status));
#endif

  port_mapped = (h->new_status == GNUNET_NAT_PORT_MAPPED);
  if (!(h->ext_addr_upnp || h->ext_addr_natpmp))
    {
      /* Address has just changed and we could not get it, or it's the first try,
       * and we're not waiting for a reply from UPnP or NAT-PMP */
      if (((NULL != h->ext_addr) ||
           (GNUNET_NO == h->did_warn)) && h->processing != 0)
        {
          GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                           "NAT",
                           _("Could not determine external IP address\n"));
          h->did_warn = GNUNET_YES;
        }
      notify_change (h, NULL, 0, port_mapped);
    }
  else if (h->ext_addr_upnp
           && GNUNET_NAT_cmp_addr (h->ext_addr, h->ext_addr_upnp) != 0)
    {
      addrlen = h->ext_addr_upnp->sa_family == AF_INET ?
        sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                       "NAT",
                       _("External IP address changed to %s\n"),
                       GNUNET_a2s (h->ext_addr_upnp, addrlen));
      notify_change (h, h->ext_addr_upnp, addrlen, port_mapped);
    }
  else if (h->ext_addr_natpmp
           && GNUNET_NAT_cmp_addr (h->ext_addr, h->ext_addr_natpmp) != 0)
    {
      addrlen = h->ext_addr_natpmp->sa_family == AF_INET ?
        sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "NAT",
                       _("External IP address changed to `%s'\n"),
                       GNUNET_a2s (h->ext_addr_natpmp, addrlen));
      notify_change (h, h->ext_addr_natpmp, addrlen, port_mapped);
    }

  h->pulse_timer = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                                 &nat_pulse, h);
}

static void
upnp_pulse_cb (int status, struct sockaddr *ext_addr, void *cls)
{
  struct GNUNET_NAT_Handle *h = cls;

  h->upnp_status = status;
  h->ext_addr_upnp = ext_addr;

  h->processing--;
  pulse_cb (h);
}

#if 0
static void
natpmp_pulse_cb (int status, struct sockaddr *ext_addr, void *cls)
{
  struct GNUNET_NAT_Handle *h = cls;

  h->natpmp_status = status;
  h->ext_addr_natpmp = ext_addr;

  h->processing--;
  pulse_cb (h);
}
#endif

static void
nat_pulse (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_Handle *h = cls;

  /* Stop if we're already waiting for an action to complete */
  h->pulse_timer = GNUNET_SCHEDULER_NO_TASK;
  if (h->processing)
    return;
  h->old_status = get_traversal_status (h);

  /* Only update the protocol that has been successful until now */
  if (h->upnp_status >= GNUNET_NAT_PORT_UNMAPPED)
    {
      h->processing = 1;
      GNUNET_NAT_UPNP_pulse (h->upnp, h->is_enabled, GNUNET_YES);

      /* Wait for the callback to call pulse_cb() to handle changes */
      return;
    }
  else if (h->natpmp_status >= GNUNET_NAT_PORT_UNMAPPED)
    {
      h->processing = 1;
#if 0
      GNUNET_NAT_NATPMP_pulse (h->natpmp, h->is_enabled);
#endif
    }
  else                          /* try both */
    {
      h->processing = 2;

      GNUNET_NAT_UPNP_pulse (h->upnp, h->is_enabled, GNUNET_YES);
#if 0
      GNUNET_NAT_NATPMP_pulse (h->natpmp, h->is_enabled, &natpmp_pulse_cb, h);
#endif
    }
}


/**
 * Attempt to enable port redirection and detect public IP address contacting
 * UPnP or NAT-PMP routers on the local network. Use addr to specify to which
 * of the local host's addresses should the external port be mapped. The port
 * is taken from the corresponding sockaddr_in[6] field.
 *
 * @param cfg configuration to use
 * @param addr the local address packets should be redirected to
 * @param addrlen actual lenght of the address
 * @param callback function to call everytime the public IP address changes
 * @param callback_cls closure for callback
 * @return NULL on error, otherwise handle that can be used to unregister 
 */
struct GNUNET_NAT_Handle *
GNUNET_NAT_register (const struct GNUNET_CONFIGURATION_Handle *cfg,
		     const struct sockaddr *addr,
                     socklen_t addrlen,
                     GNUNET_NAT_AddressCallback callback, void *callback_cls)
{
  struct GNUNET_NAT_Handle *h;

  h = GNUNET_malloc (sizeof (struct GNUNET_NAT_Handle));

  if (addr)
    {
      GNUNET_assert ((addr->sa_family == AF_INET) ||
                     (addr->sa_family == AF_INET6));
      h->local_addr = GNUNET_malloc (addrlen);
      memcpy (h->local_addr, addr, addrlen);
      if (addr->sa_family == AF_INET)
        {
          h->public_port = ntohs (((struct sockaddr_in *) addr)->sin_port);
          ((struct sockaddr_in *) h->local_addr)->sin_port = 0;
        }
      else if (addr->sa_family == AF_INET6)
        {
          h->public_port = ntohs (((struct sockaddr_in6 *) addr)->sin6_port);
          ((struct sockaddr_in6 *) h->local_addr)->sin6_port = 0;
        }
    }
  h->should_change = GNUNET_YES;
  h->is_enabled = GNUNET_YES;
  h->upnp_status = GNUNET_NAT_PORT_UNMAPPED;
  h->natpmp_status = GNUNET_NAT_PORT_UNMAPPED;
  h->callback = callback;
  h->callback_cls = callback_cls;
  h->upnp =
    GNUNET_NAT_UPNP_init (h->local_addr, addrlen, h->public_port,
                          &upnp_pulse_cb, h);
#if 0
  h->natpmp =
    GNUNET_NAT_NATPMP_init (h->local_addr, addrlen, h->public_port,
                            &natpmp_pulse_cb, h);
#endif
  h->pulse_timer = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                                 &nat_pulse, h);
  return h;
}


/**
 * Stop port redirection and public IP address detection for the given handle.
 * This frees the handle, after having sent the needed commands to close open ports.
 *
 * @param h the handle to stop
 */
void
GNUNET_NAT_unregister (struct GNUNET_NAT_Handle *h)
{
  GNUNET_NAT_UPNP_pulse (h->upnp, GNUNET_NO, GNUNET_NO);
  GNUNET_NAT_UPNP_close (h->upnp);

#if 0
  GNUNET_NAT_NATPMP_pulse (h->natpmp, GNUNET_NO);
  GNUNET_NAT_NATPMP_close (h->natpmp);
#endif

  if (GNUNET_SCHEDULER_NO_TASK != h->pulse_timer)
    GNUNET_SCHEDULER_cancel (h->pulse_timer);

  GNUNET_free_non_null (h->local_addr);
  GNUNET_free_non_null (h->ext_addr);
  GNUNET_free_non_null (h->ext_addr_upnp);
  GNUNET_free_non_null (h->ext_addr_natpmp);
  GNUNET_free (h);
}

/* end of nat.c */
