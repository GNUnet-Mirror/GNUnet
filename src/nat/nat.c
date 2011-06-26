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
 *
 * TODO:
 * - implement UPnP/PMP support
 * - repeatedly perform certain checks again to notice changes
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
#include "gnunet_nat_lib.h"


/**
 * How long until we give up on transmitting the welcome message?
 */
#define HOSTNAME_RESOLVE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)


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
     * FIXME: repeatedly do the lookup to notice changes!
     */
    LAL_EXTERNAL_IP,

    /**
     * Address was obtained by looking up our own hostname in DNS.
     * FIXME: repeatedly do the lookup to notice changes!
     */
    LAL_HOSTNAME_DNS,

    /**
     * Address was obtained by scanning our hosts's network interfaces
     * and taking their address (no DNS involved).
     * FIXME: repeatedly do the lookup to notice changes!
     */
    LAL_INTERFACE_ADDRESS,

    /* TODO: add UPnP, etc. */

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
   * stdout pipe handle for the gnunet-nat-server process
   */
  struct GNUNET_DISK_PipeHandle *server_stdout;

  /**
   * stdout file handle (for reading) for the gnunet-nat-server process
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
   * How long do we wait for restarting a crashed gnunet-nat-server?
   */
  struct GNUNET_TIME_Relative server_retry_delay;

  /**
   * ID of select gnunet-nat-server stdout read task
   */
  GNUNET_SCHEDULER_TaskIdentifier server_read_task;

  /**
   * ID of interface IP-scan task
   */
  GNUNET_SCHEDULER_TaskIdentifier ifc_task;

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
   * Number of entries in 'local_addrs' array.
   */
  unsigned int num_local_addrs;

  /**
   * The our external address (according to config, UPnP may disagree...)
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
   * Should we run the gnunet-nat-server?
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
 * Try to start the gnunet-nat-server (if it is not
 * already running).
 *
 * @param h handle to NAT
 */
static void
start_gnunet_nat_server (struct GNUNET_NAT_Handle *h);


/**
 * Add the given address to the list of 'local' addresses, thereby
 * making it a 'legal' address for this peer to have.  
 * 
 * @param plugin the plugin
 * @param src where did the local address originate from?
 * @param arg the address, some 'struct sockaddr'
 * @param arg_size number of bytes in arg
 */
static void
add_to_address_list_as_is (struct GNUNET_NAT_Handle *h,
			   enum LocalAddressSource src,
			   const struct sockaddr *arg,
			   socklen_t arg_size)
{
  struct LocalAddressList *lal;

  lal = GNUNET_malloc (sizeof (struct LocalAddressList) + arg_size);
  memcpy (&lal[1], arg, arg_size);
  lal->addrlen = arg_size;
  lal->source = src;
  GNUNET_CONTAINER_DLL_insert (h->lal_head,
			       h->lal_tail,
			       lal);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "nat",
		   "Adding address `%s' from source %d\n",
		   GNUNET_a2s (arg, arg_size),
		   src);
  h->address_callback (h->callback_cls,
		       GNUNET_YES,
		       arg,
		       arg_size);
}


/**
 * Add the given address to the list of 'local' addresses, thereby
 * making it a 'legal' address for this peer to have.   Set the
 * port number in the process to the advertised port and possibly
 * also to zero (if we have the gnunet-nat-server).
 * 
 * @param plugin the plugin
 * @param src where did the local address originate from?
 * @param arg the address, some 'struct sockaddr'
 * @param arg_size number of bytes in arg
 */
static void
add_to_address_list (struct GNUNET_NAT_Handle *h,
		     enum LocalAddressSource src,
		     const struct sockaddr *arg,
		     socklen_t arg_size)
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
      add_to_address_list_as_is (h, 
				 src,
				 (const struct sockaddr*) &s4,
				 sizeof (struct sockaddr_in));
      if (GNUNET_YES == h->enable_nat_server)
	{
	  /* also add with PORT = 0 to indicate NAT server is enabled */
	  s4.sin_port = htons(0);
	  add_to_address_list_as_is (h, 
				     src,
				     (const struct sockaddr*) &s4,
				     sizeof (struct sockaddr_in));	  
	}
    }
  else if (arg_size == sizeof (struct sockaddr_in6))
    {
      if (GNUNET_YES != h->disable_ipv6)
	{
	  in6 = (const struct sockaddr_in6 *) arg;
	  s6 = *in6;
	  s6.sin6_port = htons(h->adv_port);
	  add_to_address_list_as_is (h, 
				     src,
				     (const struct sockaddr*) &s6,
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
 * @param plugin the plugin
 * @param src where did the local address originate from?
 * @param arg the address, some 'struct in_addr' or 'struct in6_addr'
 * @param arg_size number of bytes in arg
 */
static void
add_ip_to_address_list (struct GNUNET_NAT_Handle *h,
			enum LocalAddressSource src,
			const void *addr,
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
      add_to_address_list (h, 
			   src,
			   (const struct sockaddr*) &s4,
			   sizeof (struct sockaddr_in));
      if (GNUNET_YES == h->enable_nat_server)
	{
	  /* also add with PORT = 0 to indicate NAT server is enabled */
	  s4.sin_port = htons(0);
	  add_to_address_list (h, 
			       src,
			       (const struct sockaddr*) &s4,
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
	  s6.sin6_port = htons(h->adv_port);
#if HAVE_SOCKADDR_IN_SIN_LEN
	  s6.sin6_len = (u_char) sizeof (struct sockaddr_in6);
#endif
	  s6.sin6_addr = *in6;
	  add_to_address_list (h, 
			       src,
			       (const struct sockaddr*) &s6,
			       sizeof (struct sockaddr_in6));
	}
    }
  else
    {
      GNUNET_assert (0);
    }
}


/**
 * Our (external) hostname was resolved and the configuration says that
 * the NAT was hole-punched.
 *
 * @param cls the 'struct Plugin'
 * @param addr NULL on error, otherwise result of DNS lookup
 * @param addrlen number of bytes in addr
 */
static void
process_external_ip (void *cls,
		     const struct sockaddr *addr,
		     socklen_t addrlen)
{
  struct GNUNET_NAT_Handle *h = cls;

  if (addr == NULL)
    {    
      h->ext_dns = NULL;
      /* FIXME: schedule task to resolve IP again in the
	 future, and if the result changes, update the
	 local address list accordingly */
      return;
    }
  add_to_address_list (h, LAL_EXTERNAL_IP, addr, addrlen);
}


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
process_hostname_ip (void *cls,
                      const struct sockaddr *addr, socklen_t addrlen)
{
  struct GNUNET_NAT_Handle *h = cls;
 
  if (addr == NULL)
    {
      h->hostname_dns = NULL;
      /* FIXME: schedule task to resolve IP again in the
	 future, and if the result changes, update the
	 address list accordingly */
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
 * @param addrlen number of bytes in addr
 * @return GNUNET_OK to continue iterating
 */
static int
process_interfaces (void *cls,
                    const char *name,
                    int isDefault,
                    const struct sockaddr *addr, socklen_t addrlen)
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
      if (GNUNET_YES == h->use_localaddresses)
	add_ip_to_address_list (h, 
				LAL_INTERFACE_ADDRESS,
				&s4->sin_addr,
				sizeof (struct in_addr));
      break;
    case AF_INET6:
      s6 = (struct sockaddr_in6 *) addr;
      if (IN6_IS_ADDR_LINKLOCAL (&((struct sockaddr_in6 *) addr)->sin6_addr))
	{
	  /* skip link local addresses */
	  return GNUNET_OK;
	}
      ip = &s6->sin6_addr;
      if (GNUNET_YES == h->use_localaddresses)
	add_ip_to_address_list (h, 
				LAL_INTERFACE_ADDRESS,
				&s6->sin6_addr,
				sizeof (struct in6_addr));
      break;
    default:
      GNUNET_break (0);
      break;
    }
  if ( (h->internal_address == NULL) &&
       (h->server_proc == NULL) &&
       (h->server_read_task == GNUNET_SCHEDULER_NO_TASK) &&
       (GNUNET_YES == isDefault) &&
       ( (addr->sa_family == AF_INET) || (addr->sa_family == AF_INET6) ) )
    {
      /* no internal address configured, but we found a "default"
	 interface, try using that as our 'internal' address */
      h->internal_address = GNUNET_strdup (inet_ntop (addr->sa_family,
						      ip,
						      buf,
						      sizeof (buf)));
      start_gnunet_nat_server (h);
    }
  return GNUNET_OK;
}


/**
 * Return the actual path to a file found in the current
 * PATH environment variable.
 *
 * @param binary the name of the file to find
 * @return path to binary, NULL if not found
 */
static char *
get_path_from_PATH (const char *binary)
{
  char *path;
  char *pos;
  char *end;
  char *buf;
  const char *p;

  p = getenv ("PATH");
  if (p == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
		       "tcp",
		       _("PATH environment variable is unset.\n"));
      return NULL;
    }
  path = GNUNET_strdup (p);     /* because we write on it */
  buf = GNUNET_malloc (strlen (path) + 20);
  pos = path;

  while (NULL != (end = strchr (pos, PATH_SEPARATOR)))
    {
      *end = '\0';
      sprintf (buf, "%s/%s", pos, binary);
      if (GNUNET_DISK_file_test (buf) == GNUNET_YES)
        {
          GNUNET_free (path);
          return buf;
        }
      pos = end + 1;
    }
  sprintf (buf, "%s/%s", pos, binary);
  if (GNUNET_DISK_file_test (buf) == GNUNET_YES)
    {
      GNUNET_free (path);
      return buf;
    }
  GNUNET_free (buf);
  GNUNET_free (path);
  return NULL;
}


/**
 * Check whether the suid bit is set on a file.
 * Attempts to find the file using the current
 * PATH environment variable as a search path.
 *
 * @param binary the name of the file to check
 * @return GNUNET_YES if the file is SUID, 
 *         GNUNET_NO if not, 
 *         GNUNET_SYSERR on error
 */
static int
check_gnunet_nat_binary (const char *binary)
{
  struct stat statbuf;
  char *p;
#ifdef MINGW
  SOCKET rawsock;
  char *binaryexe;

  GNUNET_asprintf (&binaryexe, "%s.exe", binary);
  p = get_path_from_PATH (binaryexe);
  free (binaryexe);
#else
  p = get_path_from_PATH (binary);
#endif
  if (p == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
		       "tcp",
		       _("Could not find binary `%s' in PATH!\n"),
		       binary);
      return GNUNET_NO;
    }
  if (0 != STAT (p, &statbuf))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, 
		  _("stat (%s) failed: %s\n"), 
		  p,
		  STRERROR (errno));
      GNUNET_free (p);
      return GNUNET_SYSERR;
    }
  GNUNET_free (p);
#ifndef MINGW
  if ( (0 != (statbuf.st_mode & S_ISUID)) &&
       (statbuf.st_uid == 0) )
    return GNUNET_YES;
  return GNUNET_NO;
#else
  rawsock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (INVALID_SOCKET == rawsock)
    {
      DWORD err = GetLastError ();
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, 
		       "tcp",
		       "socket (AF_INET, SOCK_RAW, IPPROTO_ICMP) failed! GLE = %d\n", err);
      return GNUNET_NO; /* not running as administrator */
    }
  closesocket (rawsock);
  return GNUNET_YES;
#endif
}


/**
 * Task that restarts the gnunet-nat-server process after a crash
 * after a certain delay.
 *
 * @param cls the 'struct GNUNET_NAT_Handle'
 * @param tc scheduler context
 */ 
static void
restart_nat_server (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_Handle *h = cls;

  h->server_read_task = GNUNET_SCHEDULER_NO_TASK;
  if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;  
  start_gnunet_nat_server (h);
}


/**
 * We have been notified that gnunet-nat-server has written something to stdout.
 * Handle the output, then reschedule this function to be called again once
 * more is available.
 *
 * @param cls the NAT handle
 * @param tc the scheduling context
 */
static void
nat_server_read (void *cls, 
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_Handle *h = cls;
  char mybuf[40];
  ssize_t bytes;
  size_t i;
  int port;
  const char *port_start;
  struct sockaddr_in sin_addr;

  h->server_read_task = GNUNET_SCHEDULER_NO_TASK;
  if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  memset (mybuf, 0, sizeof(mybuf));
  bytes = GNUNET_DISK_file_read(h->server_stdout_handle, 
				mybuf,
				sizeof(mybuf));
  if (bytes < 1)
    {
#if DEBUG_TCP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "nat",
		       "Finished reading from server stdout with code: %d\n", 
		       bytes);
#endif
      if (0 != GNUNET_OS_process_kill (h->server_proc, SIGTERM))
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
      GNUNET_OS_process_wait (h->server_proc);
      GNUNET_OS_process_close (h->server_proc);
      h->server_proc = NULL;
      GNUNET_DISK_pipe_close (h->server_stdout);
      h->server_stdout = NULL;
      h->server_stdout_handle = NULL;
      /* now try to restart it */
      h->server_retry_delay = GNUNET_TIME_relative_multiply (h->server_retry_delay, 2);
      h->server_retry_delay = GNUNET_TIME_relative_max (GNUNET_TIME_UNIT_HOURS, 
							h->server_retry_delay);
      h->server_read_task = GNUNET_SCHEDULER_add_delayed (h->server_retry_delay,
							  &restart_nat_server,
							  h);
      return;
    }

  port_start = NULL;
  for (i = 0; i < sizeof(mybuf); i++)
    {
      if (mybuf[i] == '\n')
	{
	  mybuf[i] = '\0';
	  break;
	}
      if ( (mybuf[i] == ':') && (i + 1 < sizeof(mybuf)) )
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
  if ( (NULL == port_start) ||
       (1 != sscanf (port_start, "%d", &port)) ||
       (-1 == inet_pton(AF_INET, mybuf, &sin_addr.sin_addr)) )
    {
      /* should we restart gnunet-nat-server? */
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
		       "nat",
		       _("gnunet-nat-server generated malformed address `%s'\n"),
		       mybuf);
      h->server_read_task 
	= GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
					  h->server_stdout_handle,
					  &nat_server_read, 
					  h);
      return;
    }
  sin_addr.sin_port = htons((uint16_t) port);
#if DEBUG_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "nat",
		   "gnunet-nat-server read: %s:%d\n", 
		   mybuf, port);
#endif
  h->reversal_callback (h->callback_cls,
			(const struct sockaddr*) &sin_addr,
			sizeof (sin_addr));
  h->server_read_task =
    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
				    h->server_stdout_handle, 
				    &nat_server_read, 
				    h);
}


/**
 * Try to start the gnunet-nat-server (if it is not
 * already running).
 *
 * @param h handle to NAT
 */
static void
start_gnunet_nat_server (struct GNUNET_NAT_Handle *h)
{
  if ( (h->behind_nat == GNUNET_YES) &&
       (h->enable_nat_server == GNUNET_YES) &&
       (h->internal_address != NULL) &&
       (NULL != (h->server_stdout = GNUNET_DISK_pipe (GNUNET_YES,
						      GNUNET_NO,
						      GNUNET_YES))) )
    {
#if DEBUG_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "nat"
		       "Starting %s at `%s'\n",
		       "gnunet-nat-server", 
		       h->internal_address);
#endif
      /* Start the server process */
      h->server_proc = GNUNET_OS_start_process (NULL,
						h->server_stdout,
						"gnunet-nat-server", 
						"gnunet-nat-server", 
						h->internal_address, 
						NULL);
      if (h->server_proc == NULL)
	{
	  GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
			   "nat",
			   _("Failed to start %s\n"),
			   "gnunet-nat-server");
	  GNUNET_DISK_pipe_close (h->server_stdout);
	  h->server_stdout = NULL;
	}
      else
	{
	  /* Close the write end of the read pipe */
	  GNUNET_DISK_pipe_close_end(h->server_stdout, 
				     GNUNET_DISK_PIPE_END_WRITE);
	  h->server_stdout_handle 
	    = GNUNET_DISK_pipe_handle (h->server_stdout, 
				       GNUNET_DISK_PIPE_END_READ);
	  h->server_read_task 
	    = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
					      h->server_stdout_handle,
					      &nat_server_read, 
					      h);
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
list_interfaces (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_Handle *h = cls;

  h->ifc_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_OS_network_interfaces_list (&process_interfaces, h); 
#if 0
  h->ifc_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FIXME,
					      &list_interfaces, h);
#endif
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
 * @param addr the local address packets should be redirected to
 * @param addrlen actual lenght of the address
 * @param address_callback function to call everytime the public IP address changes
 * @param reversal_callback function to call if someone wants connection reversal from us
 * @param callback_cls closure for callbacks
 * @return NULL on error, otherwise handle that can be used to unregister 
 */
struct GNUNET_NAT_Handle *
GNUNET_NAT_register (const struct GNUNET_CONFIGURATION_Handle *cfg,
		     int is_tcp,
		     uint16_t adv_port,
		     unsigned int num_addrs,
		     const struct sockaddr **addrs,
                     const socklen_t *addrlens,
                     GNUNET_NAT_AddressCallback address_callback, 
		     GNUNET_NAT_ReversalCallback reversal_callback,
		     void *callback_cls)
{
  struct GNUNET_NAT_Handle *h;
  struct in_addr in_addr;
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
	      "Registered with NAT service at port %u with %u IP bound local addresses\n",
	      (unsigned int) adv_port,
	      num_addrs);
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
      h->local_addrs = GNUNET_malloc (num_addrs * sizeof (struct sockaddr*));
      h->local_addrlens = GNUNET_malloc (num_addrs * sizeof (socklen_t));
      for (i=0;i<num_addrs;i++)
	{
	  h->local_addrlens[i] = addrlens[i];
	  h->local_addrs[i] = GNUNET_malloc (addrlens[i]);
	  memcpy (h->local_addrs[i], addrs[i], addrlens[i]);
	}
    }

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_have_value (cfg,
				       "nat",
				       "INTERNAL_ADDRESS"))
    {
      (void) GNUNET_CONFIGURATION_get_value_string (cfg,
						    "nat",
						    "INTERNAL_ADDRESS",
						    &h->internal_address);
    }
  if ( (h->internal_address != NULL) && 
       (inet_pton(AF_INET, h->internal_address, &in_addr) != 1) )
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
		       "nat",
		       _("Malformed %s `%s' given in configuration!\n"), 
		       "INTERNAL_ADDRESS",
		       h->internal_address);      
      GNUNET_free (h->internal_address);
      h->internal_address = NULL;
    }

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_have_value (cfg,
				       "nat",
				       "EXTERNAL_ADDRESS"))
    {
      (void) GNUNET_CONFIGURATION_get_value_string (cfg,
						    "nat",
						    "EXTERNAL_ADDRESS",
						    &h->external_address);
    }
  if ( (h->external_address != NULL) && 
       (inet_pton(AF_INET, h->external_address, &in_addr) != 1) ) 
    {      
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
		       "nat",
		       _("Malformed %s `%s' given in configuration!\n"), 
		       "EXTERNAL_ADDRESS",
		       h->external_address);
      GNUNET_free (h->external_address);
      h->external_address = NULL;
    }
  h->behind_nat = GNUNET_CONFIGURATION_get_value_yesno (cfg,
							"nat",
							"BEHIND_NAT");
  h->nat_punched = GNUNET_CONFIGURATION_get_value_yesno (cfg,
							 "nat",
							 "NAT_PUNCHED");
  h->enable_nat_client = GNUNET_CONFIGURATION_get_value_yesno (cfg,
							       "nat",
							       "ENABLE_NAT_CLIENT");
  h->enable_nat_server = GNUNET_CONFIGURATION_get_value_yesno (cfg,
							       "nat",
							       "ENABLE_NAT_SERVER");
  h->enable_upnp = GNUNET_CONFIGURATION_get_value_yesno (cfg,
							 "nat",
							 "ENABLE_UPNP");
  h->use_localaddresses = GNUNET_CONFIGURATION_get_value_yesno (cfg,
								"nat",
								"USE_LOCALADDR");
  h->disable_ipv6 = GNUNET_CONFIGURATION_get_value_yesno(cfg,
							 "nat", 
							 "DISABLEV6");
  if (NULL == reversal_callback)
    h->enable_nat_server = GNUNET_NO;

  /* Check if NAT was hole-punched */
  if ( (NULL != h->address_callback) &&
       (h->external_address != NULL) &&
       (h->nat_punched == GNUNET_YES) )
    {
      h->ext_dns = GNUNET_RESOLVER_ip_get (h->external_address,
					   AF_INET,
					   GNUNET_TIME_UNIT_MINUTES,
					   &process_external_ip,
					   h);
      h->enable_nat_server = GNUNET_NO;
      h->enable_upnp = GNUNET_NO;
    }

  /* Test for SUID binaries */
  if ( (h->behind_nat == GNUNET_YES) &&
       (GNUNET_YES == h->enable_nat_server) &&
       (GNUNET_YES != check_gnunet_nat_binary("gnunet-nat-server")) )
    {
      h->enable_nat_server = GNUNET_NO;
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Configuration requires `%s', but binary is not installed properly (SUID bit not set).  Option disabled.\n"),
		  "gnunet-nat-server");        
    }
  if ( (GNUNET_YES == h->enable_nat_client) &&
       (GNUNET_YES != check_gnunet_nat_binary("gnunet-nat-client")) )
    {
      h->enable_nat_client = GNUNET_NO;
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Configuration requires `%s', but binary is not installed properly (SUID bit not set).  Option disabled.\n"),
		  "gnunet-nat-client");	
    }

  start_gnunet_nat_server (h);

  /* FIXME: add support for UPnP, etc */

  if (NULL != h->address_callback)
    {
      h->ifc_task = GNUNET_SCHEDULER_add_now (&list_interfaces, h);
      h->hostname_dns = GNUNET_RESOLVER_hostname_resolve (AF_UNSPEC,
							  HOSTNAME_RESOLVE_TIMEOUT,
							  &process_hostname_ip,
							  h);
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
  if (GNUNET_SCHEDULER_NO_TASK != h->ifc_task)
    {
      GNUNET_SCHEDULER_cancel (h->ifc_task);
      h->ifc_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (NULL != h->server_proc)
    {
      if (0 != GNUNET_OS_process_kill (h->server_proc, SIGTERM))
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
      GNUNET_OS_process_wait (h->server_proc);
      GNUNET_OS_process_close (h->server_proc);
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
      GNUNET_CONTAINER_DLL_remove (h->lal_head,
				   h->lal_tail,
				   lal);
      h->address_callback (h->callback_cls,
			   GNUNET_NO,
			   (const struct sockaddr*) &lal[1],
			   lal->addrlen);
      GNUNET_free (lal);
    }
  for (i=0;i<h->num_local_addrs;i++)   
    GNUNET_free (h->local_addrs[i]);
  GNUNET_free_non_null (h->local_addrs);
  GNUNET_free_non_null (h->local_addrlens);
  GNUNET_free_non_null (h->external_address);
  GNUNET_free_non_null (h->internal_address);  
  GNUNET_free (h);
}


/**
 * We learned about a peer (possibly behind NAT) so run the
 * gnunet-nat-client to send dummy ICMP responses to cause
 * that peer to connect to us (connection reversal).
 *
 * @param h NAT handle for us (largely used for configuration)
 * @param sa the address of the peer (IPv4-only)
 */
void
GNUNET_NAT_run_client (struct GNUNET_NAT_Handle *h,
		       const struct sockaddr_in *sa)
{
  char inet4[INET_ADDRSTRLEN];
  char port_as_string[6];
  struct GNUNET_OS_Process *proc;

  if (GNUNET_YES != h->enable_nat_client) 
    return; /* not permitted / possible */

  if (h->internal_address == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
		       "nat",
		       _("Internal IP address not known, cannot use ICMP NAT traversal method\n"));
      return;
    }
  GNUNET_assert (sa->sin_family == AF_INET);
  if (NULL == inet_ntop (AF_INET,
			 &sa->sin_addr,
			 inet4, INET_ADDRSTRLEN))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "inet_ntop");
      return;
    }
  GNUNET_snprintf(port_as_string, 
		  sizeof (port_as_string),
		  "%d", 
		  h->adv_port);
#if DEBUG_TCP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "nat",
		   _("Running gnunet-nat-client %s %s %u\n"), 
		   h->internal_address,
		   inet4,
		   (unsigned int) h->adv_port);
#endif
  proc = GNUNET_OS_start_process (NULL, 
				  NULL, 
				  "gnunet-nat-client",
				  "gnunet-nat-client",
				  h->internal_address, 
				  inet4,
				  port_as_string, 
				  NULL);
  if (NULL == proc)
    return;
  /* we know that the gnunet-nat-client will terminate virtually
     instantly */
  GNUNET_OS_process_wait (proc);
  GNUNET_OS_process_close (proc);
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
GNUNET_NAT_test_address (struct GNUNET_NAT_Handle *h,
			 const void *addr,
			 socklen_t addrlen)
{
  struct LocalAddressList *pos;
  const struct sockaddr_in *in4;
  const struct sockaddr_in6 *in6;
  
  if ( (addrlen != sizeof (struct in_addr)) &&
       (addrlen != sizeof (struct in6_addr)) )
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  pos = h->lal_head;
  while (NULL != pos)
    {
      if (pos->addrlen == sizeof (struct sockaddr_in))
	{
	  in4 = (struct sockaddr_in* ) &pos[1];
	  if ( (addrlen == sizeof (struct in_addr)) &&
	       (0 == memcmp (&in4->sin_addr, addr, sizeof (struct in_addr))) )
	    return GNUNET_YES;
	}
      else if (pos->addrlen == sizeof (struct sockaddr_in6))
	{
	  in6 = (struct sockaddr_in6* ) &pos[1];
	  if ( (addrlen == sizeof (struct in6_addr)) &&
	       (0 == memcmp (&in6->sin6_addr, addr, sizeof (struct in6_addr))) )
	    return GNUNET_YES;
	}
      else
	{
	  GNUNET_assert (0);	  
	}
      pos = pos->next;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
	      "Asked to validate one of my addresses and validation failed!\n");
  return GNUNET_NO;
}


/* end of nat.c */
