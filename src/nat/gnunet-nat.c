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
 * @brief Command-line tool to interact with the NAT service
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
 * Name of section in configuration file to use for
 * additional options.
 */
static char *section_name;

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
static int do_stun;

/**
 * Handle to NAT operation.
 */
static struct GNUNET_NAT_Handle *nh;

/**
 * Listen socket for STUN processing.
 */
static struct GNUNET_NETWORK_Handle *ls;

/**
 * Task for reading STUN packets.
 */
static struct GNUNET_SCHEDULER_Task *rtask;


/**
 * Test if all activities have finished, and if so,
 * terminate.
 */
static void
test_finished ()
{
  if (NULL != nh)
    return;
  if (NULL != rtask)
    return;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Signature of the callback passed to #GNUNET_NAT_register() for
 * a function to call whenever our set of 'valid' addresses changes.
 *
 * @param cls closure, NULL
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
  fprintf (stdout,
           "%s %s (%d)\n",
           add_remove ? "+" : "-",
           GNUNET_a2s (addr,
                       addrlen),
           (int) ac);
}


/**
 * Signature of the callback passed to #GNUNET_NAT_register().
 * for a function to call whenever someone asks us to do connection
 * reversal.
 *
 * @param cls closure, NULL
 * @param remote_addr public IP address of the other peer
 * @param remote_addrlen actual length of the @a remote_addr
 */
static void
reversal_cb (void *cls,
	     const struct sockaddr *remote_addr,
	     socklen_t remote_addrlen)
{
  GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
	      "Connection reversal requested by %s\n",
	      GNUNET_a2s (remote_addr,
			  remote_addrlen));
}


/**
 * Task run on shutdown.
 *
 * @param cls NULL
 */
static void
do_shutdown (void *cls)
{
  if (NULL != nh)
  {
    GNUNET_NAT_unregister (nh);
    nh = NULL;
  }
  if (NULL != ls)
  {
    GNUNET_NETWORK_socket_close (ls);
    ls = NULL;
  }
  if (NULL != rtask)
  {
    GNUNET_SCHEDULER_cancel (rtask);
    rtask = NULL;
  }
}


/**
 * Task to receive incoming packets for STUN processing.
 */
static void
stun_read_task (void *cls)
{
  ssize_t size;

  rtask = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
					 ls,
					 &stun_read_task,
					 NULL);
  size = GNUNET_NETWORK_socket_recvfrom_amount (ls);
  if (size > 0)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    global_ret = 1;
    return;
  }
  {
    char buf[size + 1];
    struct sockaddr_storage sa;
    socklen_t salen = sizeof (sa);
    ssize_t ret;

    ret = GNUNET_NETWORK_socket_recvfrom (ls,
					  buf,
					  size + 1,
					  (struct sockaddr *) &sa,
					  &salen);
    if (ret != size)
    {
      GNUNET_break (0);
      GNUNET_SCHEDULER_shutdown ();
      global_ret = 1;
      return;
    }
    (void) GNUNET_NAT_stun_handle_packet (nh,
					  (const struct sockaddr *) &sa,
					  salen,
					  buf,
					  ret);
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
  struct sockaddr *local_sa;
  struct sockaddr *remote_sa;
  socklen_t local_len;
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

  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
				 NULL);

  if (0 == proto)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		"Must specify either TCP or UDP\n");
    global_ret = 1;
    return;
  }
  local_len = 0;
  local_sa = NULL;
  remote_len = 0;
  remote_sa = NULL;
  if (NULL != local_addr)
  {
    local_len = (socklen_t) GNUNET_STRINGS_parse_socket_addr (local_addr,
							      &af,
							      &local_sa);
    if (0 == local_len)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		  "Invalid socket address `%s'\n",
		  local_addr);
      goto fail_and_shutdown;
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
      goto fail_and_shutdown;
    }
  }

  if (NULL != local_addr)
  {
    if (NULL == section_name)
      section_name = GNUNET_strdup ("undefined");
    nh = GNUNET_NAT_register (c,
			      section_name,
			      proto,
			      1,
			      (const struct sockaddr **) &local_sa,
			      &local_len,
			      &address_cb,
			      (listen_reversal) ? &reversal_cb : NULL,
			      NULL);
  }
  else if (listen_reversal)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		"Use of `-W` only effective in combination with `-i`\n");
    goto fail_and_shutdown;
  }

  if (NULL != remote_addr)
  {
    int ret;

    if ( (NULL == nh) ||
	 (sizeof (struct sockaddr_in) != local_len) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		  "Require IPv4 local address to initiate connection reversal\n");
      goto fail_and_shutdown;
    }
    if (sizeof (struct sockaddr_in) != remote_len)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		  "Require IPv4 reversal target address\n");
      goto fail_and_shutdown;
    }
    GNUNET_assert (AF_INET == local_sa->sa_family);
    GNUNET_assert (AF_INET == remote_sa->sa_family);
    ret = GNUNET_NAT_request_reversal (nh,
				       (const struct sockaddr_in *) local_sa,
				       (const struct sockaddr_in *) remote_sa);
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

  if (do_stun)
  {
    if (NULL == local_addr)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		  "Require local address to support STUN requests\n");
      goto fail_and_shutdown;
    }
    if (IPPROTO_UDP != proto)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		  "STUN only supported over UDP\n");
      goto fail_and_shutdown;
    }
    ls = GNUNET_NETWORK_socket_create (af,
				       SOCK_DGRAM,
				       IPPROTO_UDP);
    if (GNUNET_OK !=
	GNUNET_NETWORK_socket_bind (ls,
				    local_sa,
				    local_len))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Failed to bind to %s: %s\n",
		  GNUNET_a2s (local_sa,
			      local_len),
		  STRERROR (errno));
      goto fail_and_shutdown;
    }
    rtask = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
					   ls,
					   &stun_read_task,
					   NULL);
  }
  GNUNET_free_non_null (remote_sa);
  GNUNET_free_non_null (local_sa);
  test_finished ();
  return;
 fail_and_shutdown:
  global_ret = 1;
  GNUNET_SCHEDULER_shutdown ();
  GNUNET_free_non_null (remote_sa);
  GNUNET_free_non_null (local_sa);
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
  struct GNUNET_GETOPT_CommandLineOption options[] = {

    GNUNET_GETOPT_option_string ('i',
                                 "in",
                                 "ADDRESS",
                                 gettext_noop ("which IP and port are we locally using to bind/listen to"),
                                 &local_addr),

    GNUNET_GETOPT_option_string ('r',
                                 "remote",
                                 "ADDRESS",
                                 gettext_noop ("which remote IP and port should be asked for connection reversal"),
                                 &remote_addr),

    GNUNET_GETOPT_option_string ('S',
                                 "section",
                                 NULL,
                                 gettext_noop ("name of configuration section to find additional options, such as manual host punching data"),
                                 &section_name),

    GNUNET_GETOPT_option_flag ('s',
                                  "stun",
                                  gettext_noop ("enable STUN processing"),
                                  &do_stun),

    GNUNET_GETOPT_option_flag ('t',
                                  "tcp",
                                  gettext_noop ("use TCP"),
                                  &use_tcp),

    GNUNET_GETOPT_option_flag ('u',
                                  "udp",
                                  gettext_noop ("use UDP"),
                                  &use_udp),

    GNUNET_GETOPT_option_flag ('W',
                                  "watch",
                                  gettext_noop ("watch for connection reversal requests"),
                                  &listen_reversal),
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
