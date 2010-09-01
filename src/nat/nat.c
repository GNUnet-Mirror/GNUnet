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
  GNUNET_NAT_UPNP_Handle *upnp;

  /**
   * Handle for NAT PMP operations.
   */
  GNUNET_NAT_NATPMP_Handle *natpmp;

  /**
   * Scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * LAN address as passed by the caller 
   */
  struct sockaddr *local_addr; 

  /**
   * External address as reported by NAT box 
   */
  struct sockaddr *ext_addr; 

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

  int did_warn;

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
get_traversal_status (const struct GNUNET_NAT_Handle * s)
{
  return MAX (s->natpmp_status, s->upnp_status);
}


/**
 * Compare the sin(6)_addr fields of AF_INET or AF_INET(6) sockaddr.
 * @param a first sockaddr
 * @param b second sockaddr
 * @return 0 if addresses are equal, non-null value otherwise */
int
GNUNET_NAT_cmp_addr (const struct sockaddr *a, 
		     const struct sockaddr *b)
{
  if (!(a && b))
    return -1;
  if ( (a->sa_family == AF_INET) && (b->sa_family == AF_INET) )
    return memcmp (&(((struct sockaddr_in *) a)->sin_addr),
                   &(((struct sockaddr_in *) b)->sin_addr),
                   sizeof (struct in_addr));
  if ( (a->sa_family == AF_INET6) && (b->sa_family == AF_INET6) )
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
notify_change (struct GNUNET_NAT_Handle *nat,
	       struct sockaddr *addr, 
	       size_t addrlen,
	       int new_port_mapped)
{
  if (new_port_mapped == nat->port_mapped)
    return;
  nat->port_mapped = new_port_mapped;

  if ( (NULL != nat->contact_addr) &&
       (NULL != nat->callback) )
    nat->callback (nat->callback_cls, 
		   GNUNET_NO, 
		   nat->contact_addr,
		   sizeof (nat->contact_addr));
  GNUNET_free_non_null (nat->contact_addr);
  nat->contact_addr = NULL;
  GNUNET_free_non_null (nat->ext_addr);
  nat->ext_addr = NULL;
  if (NULL == addr)
    return;    
  nat->ext_addr = GNUNET_malloc (addrlen);
  memcpy (nat->ext_addr, addr, addrlen);

  /* Recreate the ext_addr:public_port bogus address to pass to the callback */
  if (nat->ext_addr->sa_family == AF_INET)
    {
      struct sockaddr_in tmp_addr;

      tmp_addr = GNUNET_malloc (sizeof (struct sockaddr_in));
      tmp_addr->sin_family = AF_INET;
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
      tmp_addr->sin_len = sizeof (struct sockaddr_in);
#endif
      tmp_addr->sin_port = port_mapped ? htons (nat->public_port) : 0;
      tmp_addr->sin_addr = ((struct sockaddr_in *) nat->ext_addr)->sin_addr;
      nat->contact_addr = (struct sockaddr *) tmp_addr;
      if (NULL != nat->callback)
        nat->callback (nat->callback_cls, 
		       GNUNET_YES, 
		       nat->contact_addr,
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
      if (NULL != nat->callback)
        nat->callback (nat->callback_cls,
		       GNUNET_YES, 
		       nat->contact_addr,
		       sizeof (struct sockaddr_in6));
    }
  else
    {
      GNUNET_break (0);
    }
}


static void
nat_pulse (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_Handle *nat = cls;
  int old_status;
  int new_status;
  int port_mapped;
  struct sockaddr *ext_addr_upnp = NULL;
  struct sockaddr *ext_addr_natpmp = NULL;

  nat->pulse_timer = GNUNET_SCHEDULER_NO_TASK;
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
      /* try both */
      nat->upnp_status =
        GNUNET_NAT_UPNP_pulse (nat->upnp, nat->is_enabled, GNUNET_YES,
                               &ext_addr_upnp);
      nat->natpmp_status =
        GNUNET_NAT_NATPMP_pulse (nat->natpmp, nat->is_enabled,
                                 &ext_addr_natpmp);
    }
  new_status = get_traversal_status (nat);
  if ( (old_status != new_status) &&
       ( (new_status == GNUNET_NAT_PORT_UNMAPPED) || 
	 (new_status == GNUNET_NAT_PORT_ERROR) ) )
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
		     "NAT",
                     _("Port redirection failed: no UPnP or NAT-PMP routers supporting this feature found\n"));
#ifdef DEBUG
  if (new_status != old_status)
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "NAT",
                     _("State changed from `%s' to `%s'\n"),
                     get_nat_state_str (old_status),
                     get_nat_state_str (new_status));
#endif

  port_mapped = (new_status == GNUNET_NAT_PORT_MAPPED);
  if (!(ext_addr_upnp || ext_addr_natpmp))
    {
      /* Address has just changed and we could not get it, or it's the first try */
      if ( (NULL != nat->ext_addr) || 
	   (GNUNET_NO == nat->did_warn) )
        {
          GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, 
			   "NAT",
			   _("Could not determine external IP address\n"));
          nat->did_warn = GNUNET_YES;
        }
      notify_change (nat, NULL, port_mapped);
    }
  else if (ext_addr_upnp && GNUNET_NAT_cmp_addr (nat->ext_addr, ext_addr_upnp) != 0)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
		       "NAT",
		       _("External IP address changed to %s\n"),
		       GNUNET_a2s (ext_addr_upnp, sizeof (ext_addr_upnp)));
      notify_change (nat, ext_addr_upnp, port_mapped);
    }
  else if (ext_addr_natpmp && GNUNET_NAT_cmp_addr (nat->ext_addr, ext_addr_natpmp) != 0)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "NAT",
		       _("External IP address changed to `%s'\n"),
		       GNUNET_a2s (ext_addr_natpmp, sizeof (ext_addr_natpmp)));      
      notify_change (nat, ext_addr_natpmp, port_mapped);
    }
  nat->pulse_timer = GNUNET_SCHEDULER_add_delayed (nat->sched, 
                                                   GNUNET_TIME_UNIT_SECONDS,
                                                   &nat_pulse, nat);
}


/**
 * Attempt to enable port redirection and detect public IP address contacting
 * UPnP or NAT-PMP routers on the local network. Use addr to specify to which
 * of the local host's addresses should the external port be mapped. The port
 * is taken from the corresponding sockaddr_in[6] field.
 *
 * @param sched the sheduler used in the program
 * @param addr the local address packets should be redirected to
 * @param addrlen actual lenght of the address
 * @param callback function to call everytime the public IP address changes
 * @param callback_cls closure for callback
 * @return NULL on error, otherwise handle that can be used to unregister 
 */
struct GNUNET_NAT_Handle *
GNUNET_NAT_register (struct GNUNET_SCHEDULER_Handle *sched,
                     const struct sockaddr *addr, socklen_t addrlen,
                     GNUNET_NAT_AddressCallback callback, void *callback_cls)
{
  struct GNUNET_NAT_Handle *nat;

  nat = GNUNET_malloc (sizeof (struct GNUNET_NAT_Handle));
  if (addr)
    {
      GNUNET_assert ( (addr->sa_family == AF_INET) ||
		      (addr->sa_family == AF_INET6) );
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
  nat->should_change = GNUNET_YES;
  nat->sched = sched;
  nat->is_enabled = GNUNET_YES;
  nat->upnp_status = GNUNET_NAT_PORT_UNMAPPED;
  nat->natpmp_status = GNUNET_NAT_PORT_UNMAPPED;
  nat->callback = callback;
  nat->callback_cls = callback_cls;
  nat->natpmp = GNUNET_NAT_NATPMP_init (nat->local_addr, addrlen, nat->public_port);
  nat->upnp = GNUNET_NAT_UPNP_init (nat->local_addr, addrlen, nat->public_port);
  nat->pulse_timer = GNUNET_SCHEDULER_add_delayed (sched, 
                                                   GNUNET_TIME_UNIT_SECONDS,
                                                   &nat_pulse, nat);
  return nat;
}


/**
 * Stop port redirection and public IP address detection for the given handle.
 * This frees the handle, after having sent the needed commands to close open ports.
 *
 * @param h the handle to stop
 */
void
GNUNET_NAT_unregister (struct GNUNET_NAT_Handle *nat)
{
  struct sockaddr *addr;

  GNUNET_SCHEDULER_cancel (nat->sched, 
			   nat->pulse_timer);
  nat->upnp_status =
    GNUNET_NAT_UPNP_pulse (nat->upnp, 
			   GNUNET_NO, GNUNET_NO,
                           &addr);
  nat->natpmp_status =
    GNUNET_NAT_NATPMP_pulse (nat->natpmp, GNUNET_NO,
                             &addr);
  GNUNET_NAT_NATPMP_close (nat->natpmp);
  GNUNET_NAT_UPNP_close (nat->upnp);
  GNUNET_free_non_null (nat->local_addr);
  GNUNET_free_non_null (nat->ext_addr);
  GNUNET_free (nat);
}

/* end of nat.c */

