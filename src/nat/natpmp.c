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
 * @file nat/natpmp.c
 * @brief NAT-PMP support for the NAT library
 *
 * @author Milan Bouchet-Valat
 */
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>

#define ENABLE_STRNATPMPERR
#include <libnatpmp/natpmp.h>

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_nat_lib.h"
#include "nat.h"
#include "natpmp.h"

#define LIFETIME_SECS 3600
#define COMMAND_WAIT_SECS 8
/* Component name for logging */
#define COMP_NAT_NATPMP _("NAT (NAT-PMP))")

enum NATPMP_state
{
  NATPMP_IDLE,
  NATPMP_ERR,
  NATPMP_DISCOVER,
  NATPMP_RECV_PUB,
  NATPMP_SEND_MAP,
  NATPMP_RECV_MAP,
  NATPMP_SEND_UNMAP,
  NATPMP_RECV_UNMAP
}
 ;

struct GNUNET_NAT_NATPMP_Handle
{
  const struct sockaddr *addr;
  socklen_t addrlen;
  struct sockaddr *ext_addr;
  int is_mapped;
  int has_discovered;
  int port;
  time_t renew_time;
  time_t command_time;
  enum NATPMP_state state;
  struct natpmp_t natpmp;
};


static void
log_val (const char *func, int ret)
{
#ifdef DEBUG
  if (ret == NATPMP_TRYAGAIN)
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                     COMP_NAT_NATPMP, _("%s retry (%d)\n"), func, ret);
  if (ret >= 0)
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                     COMP_NAT_NATPMP, _("%s succeeded (%d)\n"), func, ret);
  else
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                     COMP_NAT_NATPMP,
                     "%s failed.  natpmp returned %d (%s); errno is %d (%s)\n",
                     func, ret, strnatpmperr (ret), errno, strerror (errno));
#endif
}

struct GNUNET_NAT_NATPMP_Handle *
GNUNET_NAT_NATPMP_init (const struct sockaddr *addr, socklen_t addrlen,
                        u_short port)
{
  struct GNUNET_NAT_NATPMP_Handle *nat;

  nat = GNUNET_malloc (sizeof (struct GNUNET_NAT_NATPMP_Handle));
  nat->state = NATPMP_DISCOVER;
  nat->port = port;
  nat->addr = addr;
  nat->addrlen = addrlen;
  return nat;
}

void
GNUNET_NAT_NATPMP_close (struct GNUNET_NAT_NATPMP_Handle *nat)
{
  if (nat)
    {
      closenatpmp (&nat->natpmp);
      GNUNET_free (nat);
    }
}

static int
can_send_command (const struct GNUNET_NAT_NATPMP_Handle *nat)
{
  return time (NULL) >= nat->command_time;
}

static void
set_command_time (struct GNUNET_NAT_NATPMP_Handle *nat)
{
  nat->command_time = time (NULL) + COMMAND_WAIT_SECS;
}

int
GNUNET_NAT_NATPMP_pulse (struct GNUNET_NAT_NATPMP_Handle *nat, int is_enabled,
                         struct sockaddr **ext_addr)
{
#if DEBUG
  char buf[INET6_ADDRSTRLEN];
#endif
  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;
  int ret;

  /* Keep to NULL if address could not be found */
  *ext_addr = NULL;

  if (is_enabled && (nat->state == NATPMP_DISCOVER))
    {
      int val = initnatpmp (&nat->natpmp);
      log_val ("initnatpmp", val);
      val = sendpublicaddressrequest (&nat->natpmp);
      log_val ("sendpublicaddressrequest", val);
      nat->state = val < 0 ? NATPMP_ERR : NATPMP_RECV_PUB;
      nat->has_discovered = 1;
      set_command_time (nat);
    }

  if ((nat->state == NATPMP_RECV_PUB) && can_send_command (nat))
    {
      struct natpmpresp_t response;
      const int val = readnatpmpresponseorretry (&nat->natpmp,
                                                 &response);
      log_val ("readnatpmpresponseorretry", val);
      if (val >= 0)
        {
          if (NULL != nat->ext_addr)
            {
              GNUNET_free (nat->ext_addr);
              nat->ext_addr = NULL;
            }

          if (response.pnu.publicaddress.family == AF_INET)
            {
              v4 = GNUNET_malloc (sizeof (struct sockaddr_in));
              nat->ext_addr = (struct sockaddr *) v4;
              v4->sin_family = AF_INET;
              v4->sin_port = response.pnu.newportmapping.mappedpublicport;
              memcpy (&v4->sin_addr, &response.pnu.publicaddress.addr,
                      sizeof (struct in_addr));
#ifdef DEBUG
              GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, COMP_NAT_NATPMP,
                               _("Found public IP address %s\n"),
                               inet_ntop (AF_INET,
                                          &response.pnu.publicaddress.addr,
                                          buf, sizeof (buf)));
#endif
            }
          else
            {
              v6 = GNUNET_malloc (sizeof (struct sockaddr_in6));
              nat->ext_addr = (struct sockaddr *) v6;
              v6->sin6_family = AF_INET6;
              v6->sin6_port = response.pnu.newportmapping.mappedpublicport;
              memcpy (&v6->sin6_addr,
                      &response.pnu.publicaddress.addr6,
                      (sizeof (struct in6_addr)));
#ifdef DEBUG
              GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, COMP_NAT_NATPMP,
                               _("Found public IP address %s\n"),
                               inet_ntop (AF_INET6,
                                          &response.pnu.publicaddress.addr6,
                                          buf, sizeof (buf)));
#endif
            }
          *ext_addr = nat->ext_addr;
          nat->state = NATPMP_IDLE;
        }
      else if (val != NATPMP_TRYAGAIN)
        {
          nat->state = NATPMP_ERR;
        }
    }

  if ((nat->state == NATPMP_IDLE) || (nat->state == NATPMP_ERR))
    {
      if (nat->is_mapped && !is_enabled)
        nat->state = NATPMP_SEND_UNMAP;
    }

  if ((nat->state == NATPMP_SEND_UNMAP) && can_send_command (nat))
    {
      const int val =
        sendnewportmappingrequest (&nat->natpmp, NATPMP_PROTOCOL_TCP,
                                   nat->port, nat->port,
                                   0);
      log_val ("sendnewportmappingrequest", val);
      nat->state = val < 0 ? NATPMP_ERR : NATPMP_RECV_UNMAP;
      set_command_time (nat);
    }

  if (nat->state == NATPMP_RECV_UNMAP)
    {
      struct natpmpresp_t resp;
      const int val = readnatpmpresponseorretry (&nat->natpmp, &resp);
      log_val ("readnatpmpresponseorretry", val);
      if (val >= 0)
        {
          const int p = resp.pnu.newportmapping.privateport;
          GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT_NATPMP,
                           _("No longer forwarding port %d\n"), p);
          if (nat->port == p)
            {
              nat->port = -1;
              nat->state = NATPMP_IDLE;
              nat->is_mapped = 0;
            }
        }
      else if (val != NATPMP_TRYAGAIN)
        {
          nat->state = NATPMP_ERR;
        }
    }

  if (nat->state == NATPMP_IDLE)
    {
      if (is_enabled && !nat->is_mapped && nat->has_discovered)
        nat->state = NATPMP_SEND_MAP;

      else if (nat->is_mapped && time (NULL) >= nat->renew_time)
        nat->state = NATPMP_SEND_MAP;
    }

  if ((nat->state == NATPMP_SEND_MAP) && can_send_command (nat))
    {
      const int val =
        sendnewportmappingrequest (&nat->natpmp, NATPMP_PROTOCOL_TCP,
                                   nat->port,
                                   nat->port,
                                   LIFETIME_SECS);
      log_val ("sendnewportmappingrequest", val);
      nat->state = val < 0 ? NATPMP_ERR : NATPMP_RECV_MAP;
      set_command_time (nat);
    }

  if (nat->state == NATPMP_RECV_MAP)
    {
      struct natpmpresp_t resp;
      const int val = readnatpmpresponseorretry (&nat->natpmp, &resp);
      log_val ("readnatpmpresponseorretry", val);
      if (val >= 0)
        {
          nat->state = NATPMP_IDLE;
          nat->is_mapped = 1;
          nat->renew_time = time (NULL) + LIFETIME_SECS;
          nat->port = resp.pnu.newportmapping.privateport;
          GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, COMP_NAT_NATPMP,
                           _("Port %d forwarded successfully\n"), nat->port);
        }
      else if (val != NATPMP_TRYAGAIN)
        {
          nat->state = NATPMP_ERR;
        }
    }

  switch (nat->state)
    {
    case NATPMP_IDLE:
      ret =
        nat->is_mapped ? GNUNET_NAT_PORT_MAPPED : GNUNET_NAT_PORT_UNMAPPED;
      break;

    case NATPMP_DISCOVER:
      ret = GNUNET_NAT_PORT_UNMAPPED;
      break;

    case NATPMP_RECV_PUB:
    case NATPMP_SEND_MAP:
    case NATPMP_RECV_MAP:
      ret = GNUNET_NAT_PORT_MAPPING;
      break;

    case NATPMP_SEND_UNMAP:
    case NATPMP_RECV_UNMAP:
      ret = GNUNET_NAT_PORT_UNMAPPING;
      break;

    default:
      ret = GNUNET_NAT_PORT_ERROR;
      break;
    }
  return ret;
}

/* end of natpmp.c */
