/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2015, 2016, 2017 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * Code to figure out what our external IPv4 address(es) might
 * be (external IPv4s are what is seen on the rest of the Internet).
 *
 * This can be implemented using different methods, and we allow
 * the main service to be notified about changes to what we believe
 * is our external IPv4 address.
 *
 * Note that this is explicitly only about NATed systems; if one
 * of our network interfaces has a global IP address this does
 * not count as "external".
 *
 * @file nat/gnunet-service-nat_externalip.c
 * @brief Functions for monitoring external IPv4 addresses
 * @author Christian Grothoff
 */
#include "platform.h"
#include <math.h>
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_resolver_service.h"
#include "gnunet_nat_service.h"
#include "gnunet-service-nat.h"
#include "gnunet-service-nat_externalip.h"
#include "gnunet-service-nat_stun.h"
#include "gnunet-service-nat_mini.h"
#include "gnunet-service-nat_helper.h"
#include "nat.h"
#include <gcrypt.h>


/**
 * How long do we wait until we re-try running `external-ip` if the
 * command failed to terminate nicely?
 */
#define EXTERN_IP_RETRY_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 15)

/**
 * How long do we wait until we re-try running `external-ip` if the
 * command failed (but terminated)?
 */
#define EXTERN_IP_RETRY_FAILURE GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 30)

/**
 * How long do we wait until we re-try running `external-ip` if the
 * command succeeded?
 */
#define EXTERN_IP_RETRY_SUCCESS GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)


/**
 * Handle to monitor for external IP changes.
 */
struct GN_ExternalIPMonitor
{
  /**
   * Kept in DLL.
   */
  struct GN_ExternalIPMonitor *next;

  /**
   * Kept in DLL.
   */
  struct GN_ExternalIPMonitor *prev;

  /**
   * Function to call when we believe our external IPv4 address changed.
   */
  GN_NotifyExternalIPv4Change cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

};


/**
 * List of monitors, kept in DLL.
 */
static struct GN_ExternalIPMonitor *mon_head;

/**
 * List of monitors, kept in DLL.
 */
static struct GN_ExternalIPMonitor *mon_tail;

/**
 * Task run to obtain our external IP (if #enable_upnp is set
 * and if we find we have a NATed IP address).
 */
static struct GNUNET_SCHEDULER_Task *probe_external_ip_task;

/**
 * Handle to our operation to run `external-ip`.
 */
static struct GNUNET_NAT_ExternalHandle *probe_external_ip_op;

/**
 * What is our external IP address as claimed by `external-ip`?
 * 0 for unknown.
 */
static struct in_addr mini_external_ipv4;


/**
 * Tell relevant clients about a change in our external
 * IPv4 address.
 *
 * @param add #GNUNET_YES to add, #GNUNET_NO to remove
 * @param v4 the external address that changed
 */
static void
notify_monitors_external_ipv4_change (int add,
				      const struct in_addr *v4)
{
  for (struct GN_ExternalIPMonitor *mon = mon_head;
       NULL != mon;
       mon = mon->next)
    mon->cb (mon->cb_cls,
	     v4,
	     add);
}


/**
 * Task used to run `external-ip` to get our external IPv4
 * address and pass it to NATed clients if possible.
 *
 * @param cls NULL
 */
static void
run_external_ip (void *cls);


/**
 * We learn our current external IP address.  If it changed,
 * notify all of our applicable clients. Also re-schedule
 * #run_external_ip with an appropriate timeout.
 *
 * @param cls NULL
 * @param addr the address, NULL on errors
 * @param result #GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 */
static void
handle_external_ip (void *cls,
		    const struct in_addr *addr,
		    enum GNUNET_NAT_StatusCode result)
{
  char buf[INET_ADDRSTRLEN];

  probe_external_ip_op = NULL;
  GNUNET_SCHEDULER_cancel (probe_external_ip_task);
  probe_external_ip_task
    = GNUNET_SCHEDULER_add_delayed ((NULL == addr)
				    ? EXTERN_IP_RETRY_FAILURE
				    : EXTERN_IP_RETRY_SUCCESS,
				    &run_external_ip,
				    NULL);
  switch (result)
  {
  case GNUNET_NAT_ERROR_SUCCESS:
    GNUNET_assert (NULL != addr);
    if (addr->s_addr == mini_external_ipv4.s_addr)
      return; /* not change */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Our external IP is now %s\n",
		inet_ntop (AF_INET,
			   addr,
			   buf,
			   sizeof (buf)));
    if (0 != mini_external_ipv4.s_addr)
      notify_monitors_external_ipv4_change (GNUNET_NO,
					    &mini_external_ipv4);
    mini_external_ipv4 = *addr;
    notify_monitors_external_ipv4_change (GNUNET_YES,
					  &mini_external_ipv4);
    break;
  default:
    if (0 != mini_external_ipv4.s_addr)
      notify_monitors_external_ipv4_change (GNUNET_NO,
					    &mini_external_ipv4);
    mini_external_ipv4.s_addr = 0;
    break;
  }
}


/**
 * Task used to run `external-ip` to get our external IPv4
 * address and pass it to NATed clients if possible.
 *
 * @param cls NULL
 */
static void
run_external_ip (void *cls)
{
  probe_external_ip_task
    = GNUNET_SCHEDULER_add_delayed (EXTERN_IP_RETRY_TIMEOUT,
				    &run_external_ip,
				    NULL);
  if (NULL != probe_external_ip_op)
  {
    GNUNET_NAT_mini_get_external_ipv4_cancel_ (probe_external_ip_op);
    probe_external_ip_op = NULL;
  }
  probe_external_ip_op
    = GNUNET_NAT_mini_get_external_ipv4_ (&handle_external_ip,
					  NULL);
}


/**
 * We have changed our opinion about being NATed in the first
 * place. Adapt our probing.
 *
 * @param have_nat #GNUNET_YES if we believe we are behind NAT
 */
void
GN_nat_status_changed (int have_nat)
{
  if (GNUNET_YES != enable_upnp)
    return;
  if ( (GNUNET_YES == have_nat) &&
       (NULL == probe_external_ip_task) &&
       (NULL == probe_external_ip_op) )
  {
    probe_external_ip_task
      = GNUNET_SCHEDULER_add_now (&run_external_ip,
				  NULL);
    return;
  }
  if (GNUNET_NO == have_nat)
  {
    if (NULL != probe_external_ip_task)
    {
      GNUNET_SCHEDULER_cancel (probe_external_ip_task);
      probe_external_ip_task = NULL;
    }
    if (NULL != probe_external_ip_op)
    {
      GNUNET_NAT_mini_get_external_ipv4_cancel_ (probe_external_ip_op);
      probe_external_ip_op = NULL;
    }
  }
}


/**
 * Start monitoring external IPv4 addresses.
 *
 * @param cb function to call on changes
 * @param cb_cls closure for @a cb
 * @return handle to cancel
 */
struct GN_ExternalIPMonitor *
GN_external_ipv4_monitor_start (GN_NotifyExternalIPv4Change cb,
				void *cb_cls)
{
  struct GN_ExternalIPMonitor *mon;

  mon = GNUNET_new (struct GN_ExternalIPMonitor);
  mon->cb = cb;
  mon->cb_cls = cb_cls;
  GNUNET_CONTAINER_DLL_insert (mon_head,
			       mon_tail,
			       mon);
  if (0 != mini_external_ipv4.s_addr)
    cb (cb_cls,
	&mini_external_ipv4,
	GNUNET_YES);
  return mon;
}


/**
 * Stop calling monitor.
 *
 * @param mon monitor to call
 */
void
GN_external_ipv4_monitor_stop (struct GN_ExternalIPMonitor *mon)
{
  GNUNET_CONTAINER_DLL_remove (mon_head,
			       mon_tail,
			       mon);
  GNUNET_free (mon);
}

/* end of gnunet-service-nat_externalip.c */
