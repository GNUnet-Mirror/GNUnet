/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_nat_lib.h"
#include "natpmp.h"
#include "upnp.h"

/* Component name for logging */
#define COMP_NAT _("NAT")
#define DEBUG

struct GNUNET_NAT_Handle
{
  int is_enabled;

  enum GNUNET_NAT_port_forwarding natpmp_status;
  enum GNUNET_NAT_port_forwarding upnp_status;

  int should_change;
  u_short public_port;

  GNUNET_NAT_UPNP_Handle *upnp;
  GNUNET_NAT_NATPMP_Handle *natpmp;

  struct GNUNET_SCHEDULER_Handle *sched;
  GNUNET_SCHEDULER_TaskIdentifier pulse_timer;

  struct sockaddr *local_addr; /* LAN address as passed by the caller */
  struct sockaddr *ext_addr; /* External address as reported by NAT box */
  struct sockaddr *contact_addr; /* External address and port where paquets are redirected*/
  GNUNET_NAT_AddressCallback callback;
  void *callback_cls;
};

#ifdef DEBUG
static const char *
get_nat_state_str (int state)
{
  switch (state)
    {
      /* we're in the process of trying to set up port forwarding */
    case GNUNET_NAT_PORT_MAPPING:
      return "Starting";

      /* we've successfully forwarded the port */
    case GNUNET_NAT_PORT_MAPPED:
      return "Forwarded";

      /* we're cancelling the port forwarding */
    case GNUNET_NAT_PORT_UNMAPPING:
      return "Stopping";

      /* the port isn't forwarded */
    case GNUNET_NAT_PORT_UNMAPPED:
      return "Not forwarded";

    case GNUNET_NAT_PORT_ERROR:
      return "Redirection failed";
    }

  return "notfound";
}
#endif

static int
get_traversal_status (const struct GNUNET_NAT_Handle * s)
{
  return MAX (s->natpmp_status, s->upnp_status);
}

/**
 * Compare the sin(6)_addr fields of AF_INET or AF_INET(6) sockaddr.
 * @param a first sockaddr
 * @param b second sockaddr
 * @returns 0 if addresses are equal, non-null value otherwise */
int
GNUNET_NAT_cmp_addr (const struct sockaddr *a, const struct sockaddr *b)
{
  if (!(a && b))
    return -1;

  if (a->sa_family == AF_INET && b->sa_family == AF_INET)
    return memcmp (&(((struct sockaddr_in *) a)->sin_addr),
                   &(((struct sockaddr_in *) b)->sin_addr),
                   sizeof (struct in_addr));
  else if (a->sa_family == AF_INET6 && b->sa_family == AF_INET6)
    return memcmp (&(((struct sockaddr_in6 *) a)->sin6_addr),
                   &(((struct sockaddr_in6 *) b)->sin6_addr),
                   sizeof (struct in6_addr));
  else
    return -1;
}

/* Deal with a new IP address or port redirection:
 * Send signals with the appropriate sockaddr (IP and port), free and changes
 * or nullify the previous sockaddr. Change the port if needed.
 */
static void
notify_change (struct GNUNET_NAT_Handle *nat, struct sockaddr *addr, int new_port_mapped)
{
  static int port_mapped = GNUNET_NO;

  /* Nothing to do. We already check in nat_pulse() that addr has changed */
  if (new_port_mapped == port_mapped)
    return;

  port_mapped = new_port_mapped;

  if (nat->contact_addr && nat->callback)
    (*nat->callback) (nat->callback_cls, GNUNET_NO, (struct sockaddr *) &nat->contact_addr,
                      sizeof (nat->contact_addr));

  /* At this point, we're sure contact_addr has changed */
  if (nat->contact_addr)
    {
      GNUNET_free (nat->contact_addr);
      nat->contact_addr = NULL;
    }

  /* No address, don't signal a new one */
  if (!addr)
    {
      if (nat->ext_addr)
        GNUNET_free (nat->ext_addr);
      nat->ext_addr = NULL;
      return;
    }
  /* Copy the new address and use it */
  else if (addr != nat->ext_addr)
    {
      if (nat->ext_addr)
        GNUNET_free (nat->ext_addr);
      nat->ext_addr = GNUNET_malloc (sizeof (*addr));
      memcpy (nat->ext_addr, addr, sizeof (*addr));
    }

  /* Recreate the ext_addr:public_port bogus address to pass to the callback */
  if (nat->ext_addr->sa_family == AF_INET)
    {
      struct sockaddr_in *tmp_addr;
      tmp_addr = GNUNET_malloc (sizeof (struct sockaddr_in));
      tmp_addr->sin_family = AF_INET;
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
      tmp_addr->sin_len = sizeof (struct sockaddr_in);
#endif
      tmp_addr->sin_port = port_mapped ? htons (nat->public_port) : 0;
      tmp_addr->sin_addr = ((struct sockaddr_in *) nat->ext_addr)->sin_addr;
      nat->contact_addr = (struct sockaddr *) tmp_addr;
      if (nat->callback)
        (*nat->callback) (nat->callback_cls, GNUNET_YES, nat->contact_addr,
                          sizeof (struct sockaddr_in));
    }
  else if (nat->ext_addr->sa_family == AF_INET6)
    {
      struct sockaddr_in6 *tmp_addr;
      tmp_addr = GNUNET_malloc (sizeof (struct sockaddr_in6));
      tmp_addr->sin6_family = AF_INET6;
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
      tmp_addr->sin6_len = sizeof (struct sockaddr_in6);
#endif
      tmp_addr->sin6_port = port_mapped ? htons (nat->public_port) : 0;
      tmp_addr->sin6_addr = ((struct sockaddr_in6 *) nat->ext_addr)->sin6_addr;
      nat->contact_addr = (struct sockaddr *) tmp_addr;
      if (nat->callback)
        (*nat->callback) (nat->callback_cls, GNUNET_YES, nat->contact_addr,
                          sizeof (struct sockaddr_in6));
    }
}

static void
nat_pulse (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_Handle *nat = cls;
  static int first_warning = GNUNET_YES;
  int old_status;
  int new_status;
  int port_mapped;
  struct sockaddr *ext_addr_upnp = NULL;
  struct sockaddr *ext_addr_natpmp = NULL;

  old_status = get_traversal_status (nat);

  /* Only update the protocol that has been successful until now */
  if (nat->upnp_status >= GNUNET_NAT_PORT_UNMAPPED)
    nat->upnp_status =
      GNUNET_NAT_UPNP_pulse (nat->upnp, nat->is_enabled, GNUNET_YES,
                             &ext_addr_upnp);
  else if (nat->natpmp_status >= GNUNET_NAT_PORT_UNMAPPED)
    nat->natpmp_status =
      GNUNET_NAT_NATPMP_pulse (nat->natpmp, nat->is_enabled,
                               &ext_addr_natpmp);
  else
    {
      nat->upnp_status =
        GNUNET_NAT_UPNP_pulse (nat->upnp, nat->is_enabled, GNUNET_YES,
                               &ext_addr_upnp);
      nat->natpmp_status =
        GNUNET_NAT_NATPMP_pulse (nat->natpmp, nat->is_enabled,
                                 &ext_addr_natpmp);
    }

  new_status = get_traversal_status (nat);

  if (old_status != new_status &&
     (new_status == GNUNET_NAT_PORT_UNMAPPED || new_status == GNUNET_NAT_PORT_ERROR))
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT,
                     _("Port redirection failed: no UPnP or NAT-PMP routers supporting this feature found\n"));

#ifdef DEBUG
  if (new_status != old_status)
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, COMP_NAT,
                     _("State changed from \"%s\" to \"%s\"\n"),
                     get_nat_state_str (old_status),
                     get_nat_state_str (new_status));
#endif

  port_mapped = (new_status == GNUNET_NAT_PORT_MAPPED);
  if (!(ext_addr_upnp || ext_addr_natpmp))
    {
      /* Address has just changed and we could not get it, or it's the first try */
      if (nat->ext_addr || first_warning)
        {
          GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT,
                      _("Could not determine external IP address\n"));
          first_warning = GNUNET_NO;
        }

      notify_change (nat, NULL, port_mapped);
    }
  else if (ext_addr_upnp && GNUNET_NAT_cmp_addr (nat->ext_addr, ext_addr_upnp) != 0)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT,
                  _("External IP address changed from %s to %s\n"),
                  GNUNET_a2s (nat->ext_addr, sizeof (nat->ext_addr)),
                  GNUNET_a2s (ext_addr_upnp, sizeof (ext_addr_upnp)));

      notify_change (nat, ext_addr_upnp, port_mapped);
    }
  else if (ext_addr_natpmp && GNUNET_NAT_cmp_addr (nat->ext_addr, ext_addr_natpmp) != 0)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT,
                  _("External IP address changed from %s to %s\n"),
                  GNUNET_a2s (nat->ext_addr, sizeof (nat->ext_addr)),
                  GNUNET_a2s (ext_addr_natpmp, sizeof (ext_addr_natpmp)));

      notify_change (nat, ext_addr_natpmp, port_mapped);
    }

  nat->pulse_timer = GNUNET_SCHEDULER_add_delayed (nat->sched, 
                                                   GNUNET_TIME_UNIT_SECONDS,
                                                   &nat_pulse, nat);
}

struct GNUNET_NAT_Handle *
GNUNET_NAT_register (struct GNUNET_SCHEDULER_Handle *sched,
                     const struct sockaddr *addr, socklen_t addrlen,
                     GNUNET_NAT_AddressCallback callback, void *callback_cls)
{
  struct GNUNET_NAT_Handle *nat = GNUNET_malloc (sizeof (struct GNUNET_NAT_Handle));

  if (addr)
    {
      GNUNET_assert (addr->sa_family == AF_INET
                     || addr->sa_family == AF_INET6);
      nat->local_addr = GNUNET_malloc (addrlen);
      memcpy (nat->local_addr, addr, addrlen);

      if (addr->sa_family == AF_INET)
        {
          nat->public_port = ntohs (((struct sockaddr_in *) addr)->sin_port);
          ((struct sockaddr_in *) nat->local_addr)->sin_port = 0;
        }
      else if (addr->sa_family == AF_INET6)
        {
          nat->public_port = ntohs (((struct sockaddr_in6 *) addr)->sin6_port);
          ((struct sockaddr_in6 *) nat->local_addr)->sin6_port = 0;
        }
    }
  else
    {
      nat->local_addr = NULL;
      nat->public_port = 0;
    }

  nat->should_change = GNUNET_YES;
  nat->sched = sched;
  nat->is_enabled = GNUNET_YES;
  nat->upnp_status = GNUNET_NAT_PORT_UNMAPPED;
  nat->natpmp_status = GNUNET_NAT_PORT_UNMAPPED;
  nat->callback = callback;
  nat->callback_cls = callback_cls;
  nat->ext_addr = NULL;
  nat->contact_addr = NULL;
  nat->natpmp = GNUNET_NAT_NATPMP_init (nat->local_addr, addrlen, nat->public_port);
  nat->upnp = GNUNET_NAT_UPNP_init (nat->local_addr, addrlen, nat->public_port);

  nat->pulse_timer = GNUNET_SCHEDULER_add_delayed (sched, 
                                                   GNUNET_TIME_UNIT_SECONDS,
                                                   &nat_pulse, nat);

  return nat;
}

void
GNUNET_NAT_unregister (struct GNUNET_NAT_Handle *nat)
{
  struct sockaddr *addr;
  GNUNET_SCHEDULER_cancel (nat->sched, nat->pulse_timer);

  nat->upnp_status =
    GNUNET_NAT_UPNP_pulse (nat->upnp, GNUNET_NO, GNUNET_NO,
                           &addr);
  nat->natpmp_status =
    GNUNET_NAT_NATPMP_pulse (nat->natpmp, GNUNET_NO,
                             &addr);

  GNUNET_NAT_NATPMP_close (nat->natpmp);
  GNUNET_NAT_UPNP_close (nat->upnp);

  if (nat->local_addr)
    GNUNET_free (nat->local_addr);
  if (nat->ext_addr)
    GNUNET_free (nat->ext_addr);
  GNUNET_free (nat);
}
