/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file nat/nat.c
 * @brief Library handling UPnP and NAT-PMP port forwarding and
 *     external IP address retrieval
 * @author Milan Bouchet-Valat
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
#include "gnunet_nat_lib.h"
#include "nat.h"

#define LOG(kind,...) GNUNET_log_from (kind, "nat", __VA_ARGS__)

/**
 * How often do we scan for changes in our IP address from our local
 * interfaces?
 */
#define IFC_SCAN_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 15)

/**
 * How often do we scan for changes in how our hostname resolves?
 */
#define HOSTNAME_DNS_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 20)


/**
 * How often do we scan for changes in how our external (dyndns) hostname resolves?
 */
#define DYNDNS_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 7)

/**
 * How long until we give up trying to resolve our own hostname?
 */
#define HOSTNAME_RESOLVE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)


/**
 * Where did the given local address originate from?
 * To be used for debugging as well as in the future
 * to remove all addresses from a certain source when
 * we reevaluate the source.
 */
enum LocalAddressSource
{
    /**
     * Address was obtained by DNS resolution of the external hostname
     * given in the configuration (i.e. hole-punched DynDNS setup).
     */
  LAL_EXTERNAL_IP,

    /**
     * Address was obtained by looking up our own hostname in DNS.
     */
  LAL_HOSTNAME_DNS,

    /**
     * Address was obtained by scanning our hosts's network interfaces
     * and taking their address (no DNS involved).
     */
  LAL_INTERFACE_ADDRESS,

    /**
     * Addresses we were explicitly bound to.
     */
  LAL_BINDTO_ADDRESS,

    /**
     * Addresses from UPnP or PMP
     */
  LAL_UPNP,

    /**
     * End of the list.
     */
  LAL_END
};


/**
 * List of local addresses that we currently deem valid.  Actual
 * struct is followed by the 'struct sockaddr'.  Note that the code
 * intentionally makes no attempt to ensure that a particular address
 * is only listed once (especially since it may come from different
 * sources, and the source is an "internal" construct).
 */
struct LocalAddressList
{
  /**
   * This is a linked list.
   */
  struct LocalAddressList *next;

  /**
   * Previous entry.
   */
  struct LocalAddressList *prev;

  /**
   * Number of bytes of address that follow.
   */
  socklen_t addrlen;

  /**
   * Origin of the local address.
   */
  enum LocalAddressSource source;
};


/**
 * Handle for miniupnp-based NAT traversal actions.
 */
struct MiniList
{

  /**
   * Doubly-linked list.
   */
  struct MiniList *next;

  /**
   * Doubly-linked list.
   */
  struct MiniList *prev;

  /**
   * Handle to mini-action.
   */
  struct GNUNET_NAT_MiniHandle *mini;

  /**
   * Local port number that was mapped.
   */
  uint16_t port;

};


/**
 * Handle for active NAT registrations.
 */
struct GNUNET_NAT_Handle
{

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Function to call when we learn about a new address.
   */
  GNUNET_NAT_AddressCallback address_callback;

  /**
   * Function to call when we notice another peer asking for
   * connection reversal.
   */
  GNUNET_NAT_ReversalCallback reversal_callback;

  /**
   * Closure for 'callback'.
   */
  void *callback_cls;

  /**
   * Handle for (DYN)DNS lookup of our external IP.
   */
  struct GNUNET_RESOLVER_RequestHandle *ext_dns;

  /**
   * Handle for request of hostname resolution, non-NULL if pending.
   */
  struct GNUNET_RESOLVER_RequestHandle *hostname_dns;

  /**
   * stdout pipe handle for the gnunet-helper-nat-server process
   */
  struct GNUNET_DISK_PipeHandle *server_stdout;

  /**
   * stdout file handle (for reading) for the gnunet-helper-nat-server process
   */
  const struct GNUNET_DISK_FileHandle *server_stdout_handle;

  /**
   * Linked list of currently valid addresses (head).
   */
  struct LocalAddressList *lal_head;

  /**
   * Linked list of currently valid addresses (tail).
   */
  struct LocalAddressList *lal_tail;

  /**
   * How long do we wait for restarting a crashed gnunet-helper-nat-server?
   */
  struct GNUNET_TIME_Relative server_retry_delay;

  /**
   * ID of select gnunet-helper-nat-server stdout read task
   */
  GNUNET_SCHEDULER_TaskIdentifier server_read_task;

  /**
   * ID of interface IP-scan task
   */
  GNUNET_SCHEDULER_TaskIdentifier ifc_task;

  /**
   * ID of hostname DNS lookup task
   */
  GNUNET_SCHEDULER_TaskIdentifier hostname_task;

  /**
   * ID of DynDNS lookup task
   */
  GNUNET_SCHEDULER_TaskIdentifier dns_task;

  /**
   * ID of task to add addresses from bind.
   */
  GNUNET_SCHEDULER_TaskIdentifier bind_task;

  /**
   * How often do we scan for changes in our IP address from our local
   * interfaces?
   */
  struct GNUNET_TIME_Relative ifc_scan_frequency;

  /**
   * How often do we scan for changes in how our hostname resolves?
   */
  struct GNUNET_TIME_Relative hostname_dns_frequency;

  /**
   * How often do we scan for changes in how our external (dyndns) hostname resolves?
   */
  struct GNUNET_TIME_Relative dyndns_frequency;

  /**
   * The process id of the server process (if behind NAT)
   */
  struct GNUNET_OS_Process *server_proc;

  /**
   * LAN address as passed by the caller (array).
   */
  struct sockaddr **local_addrs;

  /**
   * Length of the 'local_addrs'.
   */
  socklen_t *local_addrlens;

  /**
   * List of handles for UPnP-traversal, one per local port (if
   * not IPv6-only).
   */
  struct MiniList *mini_head;

  /**
   * List of handles for UPnP-traversal, one per local port (if
   * not IPv6-only).
   */
  struct MiniList *mini_tail;

  /**
   * Number of entries in 'local_addrs' array.
   */
  unsigned int num_local_addrs;

  /**
   * Our external address (according to config, UPnP may disagree...),
   * in dotted decimal notation, IPv4-only. Or NULL if not known.
   */
  char *external_address;

  /**
   * Presumably our internal address (according to config)
   */
  char *internal_address;

  /**
   * Is this transport configured to be behind a NAT?
   */
  int behind_nat;

  /**
   * Has the NAT been punched? (according to config)
   */
  int nat_punched;

  /**
   * Is this transport configured to allow connections to NAT'd peers?
   */
  int enable_nat_client;

  /**
   * Should we run the gnunet-helper-nat-server?
   */
  int enable_nat_server;

  /**
   * Are we allowed to try UPnP/PMP for NAT traversal?
   */
  int enable_upnp;

  /**
   * Should we use local addresses (loopback)? (according to config)
   */
  int use_localaddresses;

  /**
   * Should we return local addresses to clients
   */
  int return_localaddress;

  /**
   * Should we do a DNS lookup of our hostname to find out our own IP?
   */
  int use_hostname;

  /**
   * Is using IPv6 disabled?
   */
  int disable_ipv6;

  /**
   * Is this TCP or UDP?
   */
  int is_tcp;

  /**
   * Port we advertise to the outside.
   */
  uint16_t adv_port;

};


/**
 * Try to start the gnunet-helper-nat-server (if it is not
 * already running).
 *
 * @param h handle to NAT
 */
static void
start_gnunet_nat_server (struct GNUNET_NAT_Handle *h);


/**
 * Remove all addresses from the list of 'local' addresses
 * that originated from the given source.
 *
 * @param h handle to NAT
 * @param src source that identifies addresses to remove
 */
static void
remove_from_address_list_by_source (struct GNUNET_NAT_Handle *h,
                                    enum LocalAddressSource src)
{
  struct LocalAddressList *pos;
  struct LocalAddressList *next;

  next = h->lal_head;
  while (NULL != (pos = next))
  {
    next = pos->next;
    if (pos->source != src)
      continue;
    GNUNET_CONTAINER_DLL_remove (h->lal_head, h->lal_tail, pos);
    if (NULL != h->address_callback)
      h->address_callback (h->callback_cls, GNUNET_NO,
                           (const struct sockaddr *) &pos[1], pos->addrlen);
    GNUNET_free (pos);
  }
}


/**
 * Add the given address to the list of 'local' addresses, thereby
 * making it a 'legal' address for this peer to have.
 *
 * @param h handle to NAT
 * @param src where did the local address originate from?
 * @param arg the address, some 'struct sockaddr'
 * @param arg_size number of bytes in arg
 */
static void
add_to_address_list_as_is (struct GNUNET_NAT_Handle *h,
                           enum LocalAddressSource src,
                           const struct sockaddr *arg, socklen_t arg_size)
{
  struct LocalAddressList *lal;

  lal = GNUNET_malloc (sizeof (struct LocalAddressList) + arg_size);
  memcpy (&lal[1], arg, arg_size);
  lal->addrlen = arg_size;
  lal->source = src;
  GNUNET_CONTAINER_DLL_insert (h->lal_head, h->lal_tail, lal);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Adding address `%s' from source %d\n",
       GNUNET_a2s (arg, arg_size), src);
  if (NULL != h->address_callback)
    h->address_callback (h->callback_cls, GNUNET_YES, arg, arg_size);
}


/**
 * Add the given address to the list of 'local' addresses, thereby
 * making it a 'legal' address for this peer to have.   Set the
 * port number in the process to the advertised port and possibly
 * also to zero (if we have the gnunet-helper-nat-server).
 *
 * @param h handle to NAT
 * @param src where did the local address originate from?
 * @param arg the address, some 'struct sockaddr'
 * @param arg_size number of bytes in arg
 */
static void
add_to_address_list (struct GNUNET_NAT_Handle *h, enum LocalAddressSource src,
                     const struct sockaddr *arg, socklen_t arg_size)
{
  struct sockaddr_in s4;
  const struct sockaddr_in *in4;
  struct sockaddr_in6 s6;
  const struct sockaddr_in6 *in6;

  if (arg_size == sizeof (struct sockaddr_in))
  {
    in4 = (const struct sockaddr_in *) arg;
    s4 = *in4;
    s4.sin_port = htons (h->adv_port);
    add_to_address_list_as_is (h, src, (const struct sockaddr *) &s4,
                               sizeof (struct sockaddr_in));
    if (GNUNET_YES == h->enable_nat_server)
    {
      /* also add with PORT = 0 to indicate NAT server is enabled */
      s4.sin_port = htons (0);
      add_to_address_list_as_is (h, src, (const struct sockaddr *) &s4,
                                 sizeof (struct sockaddr_in));
    }
  }
  else if (arg_size == sizeof (struct sockaddr_in6))
  {
    if (GNUNET_YES != h->disable_ipv6)
    {
      in6 = (const struct sockaddr_in6 *) arg;
      s6 = *in6;
      s6.sin6_port = htons (h->adv_port);
      add_to_address_list_as_is (h, src, (const struct sockaddr *) &s6,
                                 sizeof (struct sockaddr_in6));
    }
  }
  else
  {
    GNUNET_assert (0);
  }
}


/**
 * Add the given IP address to the list of 'local' addresses, thereby
 * making it a 'legal' address for this peer to have.
 *
 * @param h handle to NAT
 * @param src where did the local address originate from?
 * @param addr the address, some 'struct in_addr' or 'struct in6_addr'
 * @param addrlen number of bytes in addr
 */
static void
add_ip_to_address_list (struct GNUNET_NAT_Handle *h,
                        enum LocalAddressSource src, const void *addr,
                        socklen_t addrlen)
{
  struct sockaddr_in s4;
  const struct in_addr *in4;
  struct sockaddr_in6 s6;
  const struct in6_addr *in6;

  if (addrlen == sizeof (struct in_addr))
  {
    in4 = (const struct in_addr *) addr;
    memset (&s4, 0, sizeof (s4));
    s4.sin_family = AF_INET;
    s4.sin_port = 0;
#if HAVE_SOCKADDR_IN_SIN_LEN
    s4.sin_len = (u_char) sizeof (struct sockaddr_in);
#endif
    s4.sin_addr = *in4;
    add_to_address_list (h, src, (const struct sockaddr *) &s4,
                         sizeof (struct sockaddr_in));
    if (GNUNET_YES == h->enable_nat_server)
    {
      /* also add with PORT = 0 to indicate NAT server is enabled */
      s4.sin_port = htons (0);
      add_to_address_list (h, src, (const struct sockaddr *) &s4,
                           sizeof (struct sockaddr_in));

    }
  }
  else if (addrlen == sizeof (struct in6_addr))
  {
    if (GNUNET_YES != h->disable_ipv6)
    {
      in6 = (const struct in6_addr *) addr;
      memset (&s6, 0, sizeof (s6));
      s6.sin6_family = AF_INET6;
      s6.sin6_port = htons (h->adv_port);
#if HAVE_SOCKADDR_IN_SIN_LEN
      s6.sin6_len = (u_char) sizeof (struct sockaddr_in6);
#endif
      s6.sin6_addr = *in6;
      add_to_address_list (h, src, (const struct sockaddr *) &s6,
                           sizeof (struct sockaddr_in6));
    }
  }
  else
  {
    GNUNET_assert (0);
  }
}


/**
 * Task to do DNS lookup on our external hostname to
 * get DynDNS-IP addresses.
 *
 * @param cls the NAT handle
 * @param tc scheduler context
 */
static void
resolve_dns (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Our (external) hostname was resolved and the configuration says that
 * the NAT was hole-punched.
 *
 * @param cls the 'struct Plugin'
 * @param addr NULL on error, otherwise result of DNS lookup
 * @param addrlen number of bytes in addr
 */
static void
process_external_ip (void *cls, const struct sockaddr *addr, socklen_t addrlen)
{
  struct GNUNET_NAT_Handle *h = cls;
  struct in_addr dummy;

  if (addr == NULL)
  {
    h->ext_dns = NULL;
    if (1 == inet_pton (AF_INET, h->external_address, &dummy))
      return;                   /* repated lookup pointless: was numeric! */
    h->dns_task =
        GNUNET_SCHEDULER_add_delayed (h->dyndns_frequency, &resolve_dns, h);
    return;
  }
  add_to_address_list (h, LAL_EXTERNAL_IP, addr, addrlen);
}


/**
 * Task to do a lookup on our hostname for IP addresses.
 *
 * @param cls the NAT handle
 * @param tc scheduler context
 */
static void
resolve_hostname (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function called by the resolver for each address obtained from DNS
 * for our own hostname.  Add the addresses to the list of our IP
 * addresses.
 *
 * @param cls closure
 * @param addr one of the addresses of the host, NULL for the last address
 * @param addrlen length of the address
 */
static void
process_hostname_ip (void *cls, const struct sockaddr *addr, socklen_t addrlen)
{
  struct GNUNET_NAT_Handle *h = cls;

  if (addr == NULL)
  {
    h->hostname_dns = NULL;
    h->hostname_task =
        GNUNET_SCHEDULER_add_delayed (h->hostname_dns_frequency,
                                      &resolve_hostname, h);
    return;
  }
  add_to_address_list (h, LAL_HOSTNAME_DNS, addr, addrlen);
}


/**
 * Add the IP of our network interface to the list of
 * our IP addresses.
 *
 * @param cls the 'struct GNUNET_NAT_Handle'
 * @param name name of the interface
 * @param isDefault do we think this may be our default interface
 * @param addr address of the interface
 * @param broadcast_addr the broadcast address (can be NULL for unknown or unassigned)
 * @param netmask the network mask (can be NULL for unknown or unassigned))
 * @param addrlen number of bytes in addr
 * @return GNUNET_OK to continue iterating
 */
static int
process_interfaces (void *cls, const char *name, int isDefault,
                    const struct sockaddr *addr,
                    const struct sockaddr *broadcast_addr,
                    const struct sockaddr *netmask, socklen_t addrlen)
{
  struct GNUNET_NAT_Handle *h = cls;
  const struct sockaddr_in *s4;
  const struct sockaddr_in6 *s6;
  const void *ip;
  char buf[INET6_ADDRSTRLEN];

  switch (addr->sa_family)
  {
  case AF_INET:
    s4 = (struct sockaddr_in *) addr;
    ip = &s4->sin_addr;

    /* Check if address is in 127.0.0.0/8 */
    uint32_t address = ntohl ((uint32_t) (s4->sin_addr.s_addr));
    uint32_t value = (address & 0xFF000000) ^ 0x7F000000;

    if ((h->return_localaddress == GNUNET_NO) && (value == 0))
    {
      return GNUNET_OK;
    }
    if (GNUNET_YES == h->use_localaddresses)
    {
      add_ip_to_address_list (h, LAL_INTERFACE_ADDRESS, &s4->sin_addr,
                              sizeof (struct in_addr));
    }
    break;
  case AF_INET6:
    s6 = (struct sockaddr_in6 *) addr;
    if (IN6_IS_ADDR_LINKLOCAL (&((struct sockaddr_in6 *) addr)->sin6_addr))
    {
      /* skip link local addresses */
      return GNUNET_OK;
    }
    if ((h->return_localaddress == GNUNET_NO) &&
        (IN6_IS_ADDR_LOOPBACK (&((struct sockaddr_in6 *) addr)->sin6_addr)))
    {
      return GNUNET_OK;
    }
    ip = &s6->sin6_addr;
    if (GNUNET_YES == h->use_localaddresses)
    {
      add_ip_to_address_list (h, LAL_INTERFACE_ADDRESS, &s6->sin6_addr,
                              sizeof (struct in6_addr));
    }
    break;
  default:
    GNUNET_break (0);
    return GNUNET_OK;
  }
  if ((h->internal_address == NULL) && (h->server_proc == NULL) &&
      (h->server_read_task == GNUNET_SCHEDULER_NO_TASK) &&
      (GNUNET_YES == isDefault) && ((addr->sa_family == AF_INET) ||
                                    (addr->sa_family == AF_INET6)))
  {
    /* no internal address configured, but we found a "default"
     * interface, try using that as our 'internal' address */
    h->internal_address =
        GNUNET_strdup (inet_ntop (addr->sa_family, ip, buf, sizeof (buf)));
    start_gnunet_nat_server (h);
  }
  return GNUNET_OK;
}


/**
 * Task that restarts the gnunet-helper-nat-server process after a crash
 * after a certain delay.
 *
 * @param cls the 'struct GNUNET_NAT_Handle'
 * @param tc scheduler context
 */
static void
restart_nat_server (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_Handle *h = cls;

  h->server_read_task = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  start_gnunet_nat_server (h);
}


/**
 * We have been notified that gnunet-helper-nat-server has written something to stdout.
 * Handle the output, then reschedule this function to be called again once
 * more is available.
 *
 * @param cls the NAT handle
 * @param tc the scheduling context
 */
static void
nat_server_read (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_Handle *h = cls;
  char mybuf[40];
  ssize_t bytes;
  size_t i;
  int port;
  const char *port_start;
  struct sockaddr_in sin_addr;

  h->server_read_task = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  memset (mybuf, 0, sizeof (mybuf));
  bytes =
      GNUNET_DISK_file_read (h->server_stdout_handle, mybuf, sizeof (mybuf));
  if (bytes < 1)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Finished reading from server stdout with code: %d\n", bytes);
    if (0 != GNUNET_OS_process_kill (h->server_proc, SIGTERM))
      GNUNET_log_from_strerror (GNUNET_ERROR_TYPE_WARNING, "nat", "kill");
    GNUNET_OS_process_wait (h->server_proc);
    GNUNET_OS_process_destroy (h->server_proc);
    h->server_proc = NULL;
    GNUNET_DISK_pipe_close (h->server_stdout);
    h->server_stdout = NULL;
    h->server_stdout_handle = NULL;
    /* now try to restart it */
    h->server_retry_delay =
        GNUNET_TIME_relative_multiply (h->server_retry_delay, 2);
    h->server_retry_delay =
        GNUNET_TIME_relative_max (GNUNET_TIME_UNIT_HOURS,
                                  h->server_retry_delay);
    h->server_read_task =
        GNUNET_SCHEDULER_add_delayed (h->server_retry_delay,
                                      &restart_nat_server, h);
    return;
  }

  port_start = NULL;
  for (i = 0; i < sizeof (mybuf); i++)
  {
    if (mybuf[i] == '\n')
    {
      mybuf[i] = '\0';
      break;
    }
    if ((mybuf[i] == ':') && (i + 1 < sizeof (mybuf)))
    {
      mybuf[i] = '\0';
      port_start = &mybuf[i + 1];
    }
  }

  /* construct socket address of sender */
  memset (&sin_addr, 0, sizeof (sin_addr));
  sin_addr.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  sin_addr.sin_len = sizeof (sin_addr);
#endif
  if ((NULL == port_start) || (1 != SSCANF (port_start, "%d", &port)) ||
      (-1 == inet_pton (AF_INET, mybuf, &sin_addr.sin_addr)))
  {
    /* should we restart gnunet-helper-nat-server? */
    LOG (GNUNET_ERROR_TYPE_WARNING, "nat",
         _("gnunet-helper-nat-server generated malformed address `%s'\n"),
         mybuf);
    h->server_read_task =
        GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                        h->server_stdout_handle,
                                        &nat_server_read, h);
    return;
  }
  sin_addr.sin_port = htons ((uint16_t) port);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "gnunet-helper-nat-server read: %s:%d\n", mybuf,
       port);
  h->reversal_callback (h->callback_cls, (const struct sockaddr *) &sin_addr,
                        sizeof (sin_addr));
  h->server_read_task =
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                      h->server_stdout_handle, &nat_server_read,
                                      h);
}


/**
 * Try to start the gnunet-helper-nat-server (if it is not
 * already running).
 *
 * @param h handle to NAT
 */
static void
start_gnunet_nat_server (struct GNUNET_NAT_Handle *h)
{
  if ((h->behind_nat == GNUNET_YES) && (h->enable_nat_server == GNUNET_YES) &&
      (h->internal_address != NULL) &&
      (NULL !=
       (h->server_stdout =
        GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_NO, GNUNET_YES))))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Starting `%s' at `%s'\n",
         "gnunet-helper-nat-server", h->internal_address);
    /* Start the server process */
    h->server_proc =
        GNUNET_OS_start_process (GNUNET_NO, NULL, h->server_stdout,
                                 "gnunet-helper-nat-server",
                                 "gnunet-helper-nat-server",
                                 h->internal_address, NULL);
    if (h->server_proc == NULL)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "nat", _("Failed to start %s\n"),
           "gnunet-helper-nat-server");
      GNUNET_DISK_pipe_close (h->server_stdout);
      h->server_stdout = NULL;
    }
    else
    {
      /* Close the write end of the read pipe */
      GNUNET_DISK_pipe_close_end (h->server_stdout, GNUNET_DISK_PIPE_END_WRITE);
      h->server_stdout_handle =
          GNUNET_DISK_pipe_handle (h->server_stdout, GNUNET_DISK_PIPE_END_READ);
      h->server_read_task =
          GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                          h->server_stdout_handle,
                                          &nat_server_read, h);
    }
  }
}


/**
 * Task to scan the local network interfaces for IP addresses.
 *
 * @param cls the NAT handle
 * @param tc scheduler context
 */
static void
list_interfaces (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_Handle *h = cls;

  h->ifc_task = GNUNET_SCHEDULER_NO_TASK;
  remove_from_address_list_by_source (h, LAL_INTERFACE_ADDRESS);
  GNUNET_OS_network_interfaces_list (&process_interfaces, h);
  h->ifc_task =
      GNUNET_SCHEDULER_add_delayed (h->ifc_scan_frequency, &list_interfaces, h);
}


/**
 * Task to do a lookup on our hostname for IP addresses.
 *
 * @param cls the NAT handle
 * @param tc scheduler context
 */
static void
resolve_hostname (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_Handle *h = cls;

  h->hostname_task = GNUNET_SCHEDULER_NO_TASK;
  remove_from_address_list_by_source (h, LAL_HOSTNAME_DNS);
  h->hostname_dns =
      GNUNET_RESOLVER_hostname_resolve (AF_UNSPEC, HOSTNAME_RESOLVE_TIMEOUT,
                                        &process_hostname_ip, h);
}


/**
 * Task to do DNS lookup on our external hostname to
 * get DynDNS-IP addresses.
 *
 * @param cls the NAT handle
 * @param tc scheduler context
 */
static void
resolve_dns (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_Handle *h = cls;

  h->dns_task = GNUNET_SCHEDULER_NO_TASK;
  remove_from_address_list_by_source (h, LAL_EXTERNAL_IP);
  h->ext_dns =
      GNUNET_RESOLVER_ip_get (h->external_address, AF_INET,
                              GNUNET_TIME_UNIT_MINUTES, &process_external_ip,
                              h);
}


/**
 * Add or remove UPnP-mapped addresses.
 *
 * @param cls the GNUNET_NAT_Handle
 * @param add_remove GNUNET_YES to mean the new public IP address, GNUNET_NO to mean
 *     the previous (now invalid) one
 * @param addr either the previous or the new public IP address
 * @param addrlen actual lenght of the address
 */
static void
upnp_add (void *cls, int add_remove, const struct sockaddr *addr,
          socklen_t addrlen)
{
  struct GNUNET_NAT_Handle *h = cls;
  struct LocalAddressList *pos;
  struct LocalAddressList *next;

  if (GNUNET_YES == add_remove)
  {
    add_to_address_list (h, LAL_UPNP, addr, addrlen);
    return;
  }
  /* remove address */
  next = h->lal_head;
  while (NULL != (pos = next))
  {
    next = pos->next;
    if ((pos->source != LAL_UPNP) || (pos->addrlen != addrlen) ||
        (0 != memcmp (&pos[1], addr, addrlen)))
      continue;
    GNUNET_CONTAINER_DLL_remove (h->lal_head, h->lal_tail, pos);
    if (NULL != h->address_callback)
      h->address_callback (h->callback_cls, GNUNET_NO,
                           (const struct sockaddr *) &pos[1], pos->addrlen);
    GNUNET_free (pos);
    return;                     /* only remove once */
  }
  /* asked to remove address that does not exist */
  GNUNET_break (0);
}


/**
 * Try to add a port mapping using UPnP.
 *
 * @param h overall NAT handle
 * @param port port to map with UPnP
 */
static void
add_minis (struct GNUNET_NAT_Handle *h, uint16_t port)
{
  struct MiniList *ml;

  ml = h->mini_head;
  while (NULL != ml)
  {
    if (port == ml->port)
      return;                   /* already got this port */
    ml = ml->next;
  }
  ml = GNUNET_malloc (sizeof (struct MiniList));
  ml->port = port;
  ml->mini = GNUNET_NAT_mini_map_start (port, h->is_tcp, &upnp_add, h);
  GNUNET_CONTAINER_DLL_insert (h->mini_head, h->mini_tail, ml);
}


/**
 * Task to add addresses from original bind to set of valid addrs.
 *
 * @param cls the NAT handle
 * @param tc scheduler context
 */
static void
add_from_bind (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static struct in6_addr any = IN6ADDR_ANY_INIT;
  struct GNUNET_NAT_Handle *h = cls;
  unsigned int i;
  struct sockaddr *sa;
  const struct sockaddr_in *v4;

  h->bind_task = GNUNET_SCHEDULER_NO_TASK;
  for (i = 0; i < h->num_local_addrs; i++)
  {
    sa = h->local_addrs[i];
    switch (sa->sa_family)
    {
    case AF_INET:
      if (sizeof (struct sockaddr_in) != h->local_addrlens[i])
      {
        GNUNET_break (0);
        break;
      }
      v4 = (const struct sockaddr_in *) sa;
      if (0 != v4->sin_addr.s_addr)
        add_to_address_list (h, LAL_BINDTO_ADDRESS, sa,
                             sizeof (struct sockaddr_in));
      if (h->enable_upnp)
        add_minis (h, ntohs (v4->sin_port));
      break;
    case AF_INET6:
      if (sizeof (struct sockaddr_in6) != h->local_addrlens[i])
      {
        GNUNET_break (0);
        break;
      }
      if (0 !=
          memcmp (&((const struct sockaddr_in6 *) sa)->sin6_addr, &any,
                  sizeof (struct in6_addr)))
        add_to_address_list (h, LAL_BINDTO_ADDRESS, sa,
                             sizeof (struct sockaddr_in6));
      break;
    default:
      break;
    }
  }
}



/**
 * Attempt to enable port redirection and detect public IP address contacting
 * UPnP or NAT-PMP routers on the local network. Use addr to specify to which
 * of the local host's addresses should the external port be mapped. The port
 * is taken from the corresponding sockaddr_in[6] field.
 *
 * @param cfg configuration to use
 * @param is_tcp GNUNET_YES for TCP, GNUNET_NO for UDP
 * @param adv_port advertised port (port we are either bound to or that our OS
 *                 locally performs redirection from to our bound port).
 * @param num_addrs number of addresses in 'addrs'
 * @param addrs the local addresses packets should be redirected to
 * @param addrlens actual lengths of the addresses
 * @param address_callback function to call everytime the public IP address changes
 * @param reversal_callback function to call if someone wants connection reversal from us
 * @param callback_cls closure for callbacks
 * @return NULL on error, otherwise handle that can be used to unregister
 */
struct GNUNET_NAT_Handle *
GNUNET_NAT_register (const struct GNUNET_CONFIGURATION_Handle *cfg, int is_tcp,
                     uint16_t adv_port, unsigned int num_addrs,
                     const struct sockaddr **addrs, const socklen_t * addrlens,
                     GNUNET_NAT_AddressCallback address_callback,
                     GNUNET_NAT_ReversalCallback reversal_callback,
                     void *callback_cls)
{
  struct GNUNET_NAT_Handle *h;
  struct in_addr in_addr;
  unsigned int i;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Registered with NAT service at port %u with %u IP bound local addresses\n",
       (unsigned int) adv_port, num_addrs);
  h = GNUNET_malloc (sizeof (struct GNUNET_NAT_Handle));
  h->server_retry_delay = GNUNET_TIME_UNIT_SECONDS;
  h->cfg = cfg;
  h->is_tcp = is_tcp;
  h->address_callback = address_callback;
  h->reversal_callback = reversal_callback;
  h->callback_cls = callback_cls;
  h->num_local_addrs = num_addrs;
  h->adv_port = adv_port;
  if (num_addrs != 0)
  {
    h->local_addrs = GNUNET_malloc (num_addrs * sizeof (struct sockaddr *));
    h->local_addrlens = GNUNET_malloc (num_addrs * sizeof (socklen_t));
    for (i = 0; i < num_addrs; i++)
    {
      GNUNET_assert (addrlens[i] > 0);
      GNUNET_assert (addrs[i] != NULL);
      h->local_addrlens[i] = addrlens[i];
      h->local_addrs[i] = GNUNET_malloc (addrlens[i]);
      memcpy (h->local_addrs[i], addrs[i], addrlens[i]);
    }
  }
  h->bind_task = GNUNET_SCHEDULER_add_now (&add_from_bind, h);
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_have_value (cfg, "nat", "INTERNAL_ADDRESS"))
  {
    (void) GNUNET_CONFIGURATION_get_value_string (cfg, "nat",
                                                  "INTERNAL_ADDRESS",
                                                  &h->internal_address);
  }
  if ((h->internal_address != NULL) &&
      (inet_pton (AF_INET, h->internal_address, &in_addr) != 1))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "nat",
         _("Malformed %s `%s' given in configuration!\n"), "INTERNAL_ADDRESS",
         h->internal_address);
    GNUNET_free (h->internal_address);
    h->internal_address = NULL;
  }

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_have_value (cfg, "nat", "EXTERNAL_ADDRESS"))
  {
    (void) GNUNET_CONFIGURATION_get_value_string (cfg, "nat",
                                                  "EXTERNAL_ADDRESS",
                                                  &h->external_address);
  }
  h->behind_nat =
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "nat", "BEHIND_NAT");
  h->nat_punched =
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "nat", "PUNCHED_NAT");
  h->enable_nat_client =
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "nat", "ENABLE_ICMP_CLIENT");
  h->enable_nat_server =
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "nat", "ENABLE_ICMP_SERVER");
  h->enable_upnp =
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "nat", "ENABLE_UPNP");
  h->use_localaddresses =
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "nat", "USE_LOCALADDR");
  h->return_localaddress =
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "nat",
                                            "RETURN_LOCAL_ADDRESSES");

  h->use_hostname =
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "nat", "USE_HOSTNAME");
  h->disable_ipv6 =
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "nat", "DISABLEV6");
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg, "nat", "DYNDNS_FREQUENCY",
                                           &h->dyndns_frequency))
    h->dyndns_frequency = DYNDNS_FREQUENCY;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg, "nat", "IFC_SCAN_FREQUENCY",
                                           &h->ifc_scan_frequency))
    h->ifc_scan_frequency = IFC_SCAN_FREQUENCY;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg, "nat", "HOSTNAME_DNS_FREQUENCY",
                                           &h->hostname_dns_frequency))
    h->hostname_dns_frequency = HOSTNAME_DNS_FREQUENCY;

  if (NULL == reversal_callback)
    h->enable_nat_server = GNUNET_NO;

  /* Check if NAT was hole-punched */
  if ((NULL != h->address_callback) && (h->external_address != NULL) &&
      (h->nat_punched == GNUNET_YES))
  {
    h->dns_task = GNUNET_SCHEDULER_add_now (&resolve_dns, h);
    h->enable_nat_server = GNUNET_NO;
    h->enable_upnp = GNUNET_NO;
  }

  /* Test for SUID binaries */
  if ((h->behind_nat == GNUNET_YES) && (GNUNET_YES == h->enable_nat_server) &&
      (GNUNET_YES !=
       GNUNET_OS_check_helper_binary ("gnunet-helper-nat-server")))
  {
    h->enable_nat_server = GNUNET_NO;
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _
         ("Configuration requires `%s', but binary is not installed properly (SUID bit not set).  Option disabled.\n"),
         "gnunet-helper-nat-server");
  }
  if ((GNUNET_YES == h->enable_nat_client) &&
      (GNUNET_YES !=
       GNUNET_OS_check_helper_binary ("gnunet-helper-nat-client")))
  {
    h->enable_nat_client = GNUNET_NO;
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _
         ("Configuration requires `%s', but binary is not installed properly (SUID bit not set).  Option disabled.\n"),
         "gnunet-helper-nat-client");
  }

  start_gnunet_nat_server (h);

  /* FIXME: add support for UPnP, etc */

  if (NULL != h->address_callback)
  {
    h->ifc_task = GNUNET_SCHEDULER_add_now (&list_interfaces, h);
    if (GNUNET_YES == h->use_hostname)
      h->hostname_task = GNUNET_SCHEDULER_add_now (&resolve_hostname, h);
  }

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
  unsigned int i;
  struct LocalAddressList *lal;
  struct MiniList *ml;

  while (NULL != (ml = h->mini_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->mini_head, h->mini_tail, ml);
    if (NULL != ml->mini)
      GNUNET_NAT_mini_map_stop (ml->mini);
    GNUNET_free (ml);
  }
  if (h->ext_dns != NULL)
  {
    GNUNET_RESOLVER_request_cancel (h->ext_dns);
    h->ext_dns = NULL;
  }
  if (NULL != h->hostname_dns)
  {
    GNUNET_RESOLVER_request_cancel (h->hostname_dns);
    h->hostname_dns = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != h->server_read_task)
  {
    GNUNET_SCHEDULER_cancel (h->server_read_task);
    h->server_read_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != h->bind_task)
  {
    GNUNET_SCHEDULER_cancel (h->bind_task);
    h->bind_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != h->ifc_task)
  {
    GNUNET_SCHEDULER_cancel (h->ifc_task);
    h->ifc_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != h->hostname_task)
  {
    GNUNET_SCHEDULER_cancel (h->hostname_task);
    h->hostname_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != h->dns_task)
  {
    GNUNET_SCHEDULER_cancel (h->dns_task);
    h->dns_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != h->server_proc)
  {
    if (0 != GNUNET_OS_process_kill (h->server_proc, SIGTERM))
      GNUNET_log_from_strerror (GNUNET_ERROR_TYPE_WARNING, "nat", "kill");
    GNUNET_OS_process_wait (h->server_proc);
    GNUNET_OS_process_destroy (h->server_proc);
    h->server_proc = NULL;
    GNUNET_DISK_pipe_close (h->server_stdout);
    h->server_stdout = NULL;
    h->server_stdout_handle = NULL;
  }
  if (NULL != h->server_stdout)
  {
    GNUNET_DISK_pipe_close (h->server_stdout);
    h->server_stdout = NULL;
    h->server_stdout_handle = NULL;
  }
  while (NULL != (lal = h->lal_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->lal_head, h->lal_tail, lal);
    if (NULL != h->address_callback)
      h->address_callback (h->callback_cls, GNUNET_NO,
                           (const struct sockaddr *) &lal[1], lal->addrlen);
    GNUNET_free (lal);
  }
  for (i = 0; i < h->num_local_addrs; i++)
    GNUNET_free (h->local_addrs[i]);
  GNUNET_free_non_null (h->local_addrs);
  GNUNET_free_non_null (h->local_addrlens);
  GNUNET_free_non_null (h->external_address);
  GNUNET_free_non_null (h->internal_address);
  GNUNET_free (h);
}


/**
 * We learned about a peer (possibly behind NAT) so run the
 * gnunet-helper-nat-client to send dummy ICMP responses to cause
 * that peer to connect to us (connection reversal).
 *
 * @return GNUNET_SYSERR on error, GNUNET_NO if nat client is disabled,
 *         GNUNET_OK otherwise
 */
int
GNUNET_NAT_run_client (struct GNUNET_NAT_Handle *h,
                       const struct sockaddr_in *sa)


{
  char inet4[INET_ADDRSTRLEN];
  char port_as_string[6];
  struct GNUNET_OS_Process *proc;

  if (GNUNET_YES != h->enable_nat_client)
    return GNUNET_NO;                     /* not permitted / possible */

  if (h->internal_address == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "nat",
         _
         ("Internal IP address not known, cannot use ICMP NAT traversal method\n"));
    return GNUNET_SYSERR;
  }
  GNUNET_assert (sa->sin_family == AF_INET);
  if (NULL == inet_ntop (AF_INET, &sa->sin_addr, inet4, INET_ADDRSTRLEN))
  {
    GNUNET_log_from_strerror (GNUNET_ERROR_TYPE_WARNING, "nat", "inet_ntop");
    return GNUNET_SYSERR;
  }
  GNUNET_snprintf (port_as_string, sizeof (port_as_string), "%d", h->adv_port);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       _("Running gnunet-helper-nat-client %s %s %u\n"), h->internal_address,
       inet4, (unsigned int) h->adv_port);
  proc =
      GNUNET_OS_start_process (GNUNET_NO,
			       NULL, NULL, "gnunet-helper-nat-client",
                               "gnunet-helper-nat-client", h->internal_address,
                               inet4, port_as_string, NULL);
  if (NULL == proc)
    return GNUNET_SYSERR;
  /* we know that the gnunet-helper-nat-client will terminate virtually
   * instantly */
  GNUNET_OS_process_wait (proc);
  GNUNET_OS_process_destroy (proc);
  return GNUNET_OK;
}


/**
 * Test if the given address is (currently) a plausible IP address for this peer.
 *
 * @param h the handle returned by register
 * @param addr IP address to test (IPv4 or IPv6)
 * @param addrlen number of bytes in addr
 * @return GNUNET_YES if the address is plausible,
 *         GNUNET_NO if the address is not plausible,
 *         GNUNET_SYSERR if the address is malformed
 */
int
GNUNET_NAT_test_address (struct GNUNET_NAT_Handle *h, const void *addr,
                         socklen_t addrlen)
{
  struct LocalAddressList *pos;
  const struct sockaddr_in *in4;
  const struct sockaddr_in6 *in6;

  if ((addrlen != sizeof (struct in_addr)) &&
      (addrlen != sizeof (struct in6_addr)))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  pos = h->lal_head;
  while (NULL != pos)
  {
    if (pos->addrlen == sizeof (struct sockaddr_in))
    {
      in4 = (struct sockaddr_in *) &pos[1];
      if ((addrlen == sizeof (struct in_addr)) &&
          (0 == memcmp (&in4->sin_addr, addr, sizeof (struct in_addr))))
        return GNUNET_YES;
    }
    else if (pos->addrlen == sizeof (struct sockaddr_in6))
    {
      in6 = (struct sockaddr_in6 *) &pos[1];
      if ((addrlen == sizeof (struct in6_addr)) &&
          (0 == memcmp (&in6->sin6_addr, addr, sizeof (struct in6_addr))))
        return GNUNET_YES;
    }
    else
    {
      GNUNET_assert (0);
    }
    pos = pos->next;
  }
  LOG (GNUNET_ERROR_TYPE_WARNING,
       "Asked to validate one of my addresses and validation failed!\n");
  return GNUNET_NO;
}


/* end of nat.c */
