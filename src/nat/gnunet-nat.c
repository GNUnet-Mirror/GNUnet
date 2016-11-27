/*
     This file is part of GNUnet.
     Copyright (C) 2015, 2016 GNUnet e.V.

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
 * @file src/nat/gnunet-nat.c
 * @brief Daemon to auto configure nat
 * @author Christian Grothoff
 * @author Bruno Cabral
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_nat_service.h"

/**
 * Value to return from #main().
 */
static int global_ret;

/**
 * Handle to ongoing autoconfiguration.
 */
static struct GNUNET_NAT_AutoHandle *ah;

/**
 * Port we advertise.
 */ 
static unsigned int adv_port;

/**
 * Flag set to 1 if we use IPPROTO_UDP.
 */
static int use_udp;

/**
 * Flag set to 1 if we are to listen for connection reversal requests.
 */
static int listen_reversal;

/**
 * Flag set to 1 if we use IPPROTO_TCP.
 */
static int use_tcp;

/**
 * Protocol to use.
 */
static uint8_t proto;

/**
 * Address we are bound to (in test), or should bind to
 * (if #do_stun is set).
 */
static char *bind_addr;

/**
 * External IP address and port to use for the test.
 * If not set, use #bind_addr.
 */
static char *extern_addr;

/**
 * Local address to use for connection reversal request.
 */
static char *local_addr;

/**
 * Remote address to use for connection reversal request.
 */
static char *remote_addr;

/**
 * Should we actually bind to #bind_addr and receive and process STUN requests?
 */
static unsigned int do_stun;

/**
 * Should we run autoconfiguration?
 */
static unsigned int do_auto;

/**
 * Handle to a NAT test operation.
 */
static struct GNUNET_NAT_Test *nt;

/**
 * Handle to NAT operation.
 */
static struct GNUNET_NAT_Handle *nh;


/**
 * Test if all activities have finished, and if so,
 * terminate.
 */
static void
test_finished ()
{
  if (NULL != ah)
    return;
  if (NULL != nt)
    return;
  if (NULL != nh)
    return;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Function to iterate over sugested changes options
 *
 * @param cls closure
 * @param section name of the section
 * @param option name of the option
 * @param value value of the option
 */
static void
auto_conf_iter (void *cls,
                const char *section,
                const char *option,
                const char *value)
{
  PRINTF ("%s: %s\n",
	  option,
	  value);
}


/**
 * Function called with the result from the autoconfiguration.
 *
 * @param cls closure
 * @param diff minimal suggested changes to the original configuration
 *             to make it work (as best as we can)
 * @param result #GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 * @param type what the situation of the NAT
 */
static void
auto_config_cb (void *cls,
		const struct GNUNET_CONFIGURATION_Handle *diff,
		enum GNUNET_NAT_StatusCode result,
		enum GNUNET_NAT_Type type)
{
  const char *nat_type;
  char unknown_type[64];

  ah = NULL;
  switch (type)
  {
    case GNUNET_NAT_TYPE_NO_NAT:
      nat_type = "NO NAT";
      break;
    case GNUNET_NAT_TYPE_UNREACHABLE_NAT:
      nat_type = "NAT but we can traverse";
      break;
    case GNUNET_NAT_TYPE_STUN_PUNCHED_NAT:
      nat_type = "NAT but STUN is able to identify the correct information";
      break;
    case GNUNET_NAT_TYPE_UPNP_NAT:
      nat_type = "NAT but UPNP opened the ports";
      break;
    default:
      SPRINTF (unknown_type,
	       "NAT unknown, type %u",
	       type);
      nat_type = unknown_type;
  }

  PRINTF ("NAT status: %s/%s\n",
	  GNUNET_NAT_status2string (result),
	  nat_type);
  
  PRINTF ("SUGGESTED CHANGES:\n");
  GNUNET_CONFIGURATION_iterate_section_values (diff,
                                               "nat",
                                               &auto_conf_iter,
                                               NULL);
  // Have option to save config
  test_finished ();
}


/**
 * Function called to report success or failure for
 * NAT configuration test.
 *
 * @param cls closure
 * @param result #GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 */
static void
test_report_cb (void *cls,
		enum GNUNET_NAT_StatusCode result)
{
  nt = NULL;
  PRINTF ("NAT test result: %s\n",
	  GNUNET_NAT_status2string (result));
  test_finished ();
}


/**
 * Signature of the callback passed to #GNUNET_NAT_register() for
 * a function to call whenever our set of 'valid' addresses changes.
 *
 * @param cls closure
 * @param add_remove #GNUNET_YES to add a new public IP address, 
 *                   #GNUNET_NO to remove a previous (now invalid) one
 * @param ac address class the address belongs to
 * @param addr either the previous or the new public IP address
 * @param addrlen actual length of the @a addr
 */
static void
address_cb (void *cls,
	    int add_remove,
	    enum GNUNET_NAT_AddressClass ac,
	    const struct sockaddr *addr,
	    socklen_t addrlen)
{
  // FIXME: print!
}


/**
 * Signature of the callback passed to #GNUNET_NAT_register().
 * for a function to call whenever someone asks us to do connection
 * reversal.
 *
 * @param cls closure
 * @param local_addr address where we received the request
 * @param local_addrlen actual length of the @a local_addr
 * @param remote_addr public IP address of the other peer
 * @param remote_addrlen actual length of the @a remote_addr
 */
static void
reversal_cb (void *cls,
	     const struct sockaddr *local_addr,
	     socklen_t local_addrlen,
	     const struct sockaddr *remote_addr,
	     socklen_t remote_addrlen)
{
  // FIXME: print!
}


/**
 * Task run on shutdown.
 *
 * @param cls NULL
 */
static void
do_shutdown (void *cls)
{
  if (NULL != ah)
  {
    GNUNET_NAT_autoconfig_cancel (ah);
    ah = NULL;
  }
  if (NULL != nt)
  {
    GNUNET_NAT_test_stop (nt);
    nt = NULL;
  }
  if (NULL != nh)
  {
    GNUNET_NAT_unregister (nh);
    nh = NULL;
  }
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  uint8_t af;
  struct sockaddr_in bind_sa;
  struct sockaddr_in extern_sa;
  struct sockaddr *local_sa;
  struct sockaddr *remote_sa;
  size_t local_len;
  size_t remote_len;
  
  if (use_tcp && use_udp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		"Cannot use TCP and UDP\n");
    global_ret = 1;
    return;
  }
  proto = 0;
  if (use_tcp)
    proto = IPPROTO_TCP;
  if (use_udp)
    proto = IPPROTO_UDP;
  if (0 == proto)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		"Must specify either TCP or UDP\n");
    global_ret = 1;
    return;
  }
  if (NULL != bind_addr)
  {
    if (GNUNET_OK !=
	GNUNET_STRINGS_to_address_ipv4 (bind_addr,
					strlen (bind_addr),
					&bind_sa))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		  "Invalid socket address `%s'\n",
		  bind_addr);
      global_ret = 1;
      return;
    }
  }
  if (NULL != extern_addr)
  {
    if (GNUNET_OK !=
	GNUNET_STRINGS_to_address_ipv4 (extern_addr,
					strlen (extern_addr),
					&extern_sa))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		  "Invalid socket address `%s'\n",
		  extern_addr);
      global_ret = 1;
      return;
    }
  }
  if (NULL != local_addr)
  {
    local_len = GNUNET_STRINGS_parse_socket_addr (local_addr,
						  &af,
						  &local_sa);
    if (0 == local_len)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		  "Invalid socket address `%s'\n",
		  local_addr);
      global_ret = 1;
      return;
    }
  }
  if (NULL != remote_addr)
  {
    remote_len = GNUNET_STRINGS_parse_socket_addr (remote_addr,
						   &af,
						   &remote_sa);
    if (0 == remote_len)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		  "Invalid socket address `%s'\n",
		  remote_addr);
      global_ret = 1;
      return;
    }
  }

  if (NULL != bind_addr)
  {
    if (NULL == extern_addr)
      extern_sa = bind_sa;
    nt = GNUNET_NAT_test_start (c,
				proto,
				bind_sa.sin_addr,
				ntohs (bind_sa.sin_port),
				extern_sa.sin_addr,
				ntohs (extern_sa.sin_port),
				&test_report_cb,
				NULL);
  }

  if (NULL != local_addr)
  {
    nh = GNUNET_NAT_register (c,
			      proto,
			      (uint16_t) adv_port,
			      1,
			      (const struct sockaddr **) &local_sa,
			      &local_len,
			      &address_cb,
			      (listen_reversal) ? &reversal_cb : NULL,
			      NULL);
  }

  if (NULL != remote_addr)
  {
    int ret;
    
    if ( (NULL == nh) ||
	 (sizeof (struct sockaddr_in) != local_len) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		  "Require IPv4 local address to initiate connection reversal\n");
      global_ret = 1;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    if (sizeof (struct sockaddr_in) != remote_len)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		  "Require IPv4 reversal target address\n");
      global_ret = 1;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    ret = GNUNET_NAT_request_reversal (nh,
				       (const struct sockaddr_in *) &local_sa,
				       (const struct sockaddr_in *) &remote_sa);
    switch (ret)
    {
    case GNUNET_SYSERR:
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		  "Connection reversal internal error\n");
      break;
    case GNUNET_NO:
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		  "Connection reversal unavailable\n");
      break;
    case GNUNET_OK:
      /* operation in progress */
      break;
    }
  }
  
  if (do_auto)
  {
    ah = GNUNET_NAT_autoconfig_start (c,
				      &auto_config_cb,
				      NULL);
  }
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
				 NULL);
  test_finished ();
}


/**
 * Main function of gnunet-nat
 *
 * @param argc number of command-line arguments
 * @param argv command line
 * @return 0 on success, -1 on error
 */
int
main (int argc,
      char *const argv[])
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'a', "auto", NULL,
     gettext_noop ("run autoconfiguration"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &do_auto },
    {'b', "bind", "ADDRESS",
     gettext_noop ("which IP and port are we bound to"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &bind_addr },
    {'e', "external", "ADDRESS",
     gettext_noop ("which external IP and port should be used to test"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &extern_addr },
    {'l', "local", "ADDRESS",
     gettext_noop ("which IP and port are we locally using to listen to for connection reversals"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &local_addr },
    {'r', "remote", "ADDRESS",
     gettext_noop ("which remote IP and port should be asked for connection reversal"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &remote_addr },
    {'L', "listen", NULL,
     gettext_noop ("listen for connection reversal requests"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &listen_reversal },
    {'p', "port", NULL,
     gettext_noop ("port to use to advertise"),
     GNUNET_YES, &GNUNET_GETOPT_set_uint, &adv_port },
    {'s', "stun", NULL,
     gettext_noop ("enable STUN processing"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &do_stun },
    {'t', "tcp", NULL,
     gettext_noop ("use TCP"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &use_tcp },
    {'u', "udp", NULL,
     gettext_noop ("use UDP"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &use_udp },
   GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
				    &argc, &argv))
    return 2;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv,
			  "gnunet-nat [options]",
                          _("GNUnet NAT traversal autoconfigure daemon"),
			  options,
                          &run,
			  NULL))
  {
    global_ret = 1;
  }
  GNUNET_free ((void*) argv);
  return global_ret;
}


/* end of gnunet-nat.c */
