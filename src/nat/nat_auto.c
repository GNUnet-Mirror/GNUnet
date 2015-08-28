/*
     This file is part of GNUnet.
     Copyright (C) 2015 Christian Grothoff (and other contributing authors)

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
 * @file nat/nat_auto.c
 * @brief functions for auto-configuration of the network
 * @author Christian Grothoff
 * @author Bruno Cabral
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
#include "gnunet_nat_lib.h"
#include "nat.h"

#define LOG(kind,...) GNUNET_log_from (kind, "nat", __VA_ARGS__)


/**
 * How long do we wait for the NAT test to report success?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

#define NAT_SERVER_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

/**
 * Phases of the auto configuration.
 */
enum AutoPhase
{
  /**
   * Initial start value.
   */
  AUTO_INIT = 0,

  /**
   * Test our external IP.
   */
  AUTO_EXTERNAL_IP,

  /**
   * Test our external IP.
   */
   AUTO_STUN,

  /**
   * Test our internal IP.
   */
  AUTO_LOCAL_IP,

  /**
   * Test if NAT was punched.
   */
  AUTO_NAT_PUNCHED,

  /**
   * Test if UPnP is working.
   */
  AUTO_UPNPC,

  /**
   * Test if ICMP server works.
   */
  AUTO_ICMP_SERVER,

  /**
   * Test if ICMP client works.
   */
  AUTO_ICMP_CLIENT,

  /**
   * Last phase, we're done.
   */
  AUTO_DONE

};


/**
 * Handle to auto-configuration in progress.
 */
struct GNUNET_NAT_AutoHandle
{

  /**
   * Handle to the active NAT test.
   */
  struct GNUNET_NAT_Test *tst;

  /**
   * Function to call when done.
   */
  GNUNET_NAT_AutoResultCallback fin_cb;

  /**
   * Closure for @e fin_cb.
   */
  void *fin_cb_cls;

  /**
   * Handle for active 'GNUNET_NAT_mini_get_external_ipv4'-operation.
   */
  struct GNUNET_NAT_ExternalHandle *eh;

  /**
   * Current configuration (with updates from previous phases)
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Original configuration (used to calculate differences)
   */
  struct GNUNET_CONFIGURATION_Handle *initial_cfg;

  /**
   * Task identifier for the timeout.
   */
  struct GNUNET_SCHEDULER_Task * task;

  /**
   * Where are we in the test?
   */
  enum AutoPhase phase;


  /**
   * Situation of the NAT
   */
  enum GNUNET_NAT_Type type;

  /**
   * Do we have IPv6?
   */
  int have_v6;

  /**
   * UPnP already set the external ip address ?
   */
  int upnp_set_external_address;

  /**
   * Did the external server connected back ?
   */
  int connected_back;

  /**
    * Address detected by STUN
   */
  char* stun_ip;
  int stun_port;

  /**
   * Internal IP is the same as the public one ?
   */
  int internal_ip_is_public;

  /**
   * Error code for better debugging and user feedback
   */
  enum GNUNET_NAT_StatusCode ret;
};






/**
 * The listen socket of the service for IPv4
 */
static struct GNUNET_NETWORK_Handle *lsock4;


/**
 * The listen task ID for IPv4
 */
static struct GNUNET_SCHEDULER_Task * ltask4;




/**
 * The port the test service is running on (default 7895)
 */
static unsigned long long port = 7895;

static char *stun_server = "stun.ekiga.net";
static int stun_port = 3478;



/**
 * Run the next phase of the auto test.
 *
 * @param ah auto test handle
 */
static void
        next_phase (struct GNUNET_NAT_AutoHandle *ah);




static void
process_stun_reply(struct sockaddr_in* answer, struct GNUNET_NAT_AutoHandle *ah)
{

  ah->stun_ip = inet_ntoa(answer->sin_addr);
  ah->stun_port = ntohs(answer->sin_port);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "External IP is: %s , with port %d\n", ah->stun_ip, ah->stun_port);


  next_phase (ah);

}

/**
 * Function that terminates the test.
 */
static void
stop_stun ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Stopping NAT and quitting...\n");

  //Clean task
  if(NULL != ltask4)
    GNUNET_SCHEDULER_cancel (ltask4);

  //Clean socket
  if(NULL != lsock4)
    GNUNET_NETWORK_socket_close (lsock4);

}

/**
 * Activity on our incoming socket.  Read data from the
 * incoming connection.
 *
 * @param cls
 * @param tc scheduler context
 */
static void
do_udp_read (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_AutoHandle *ah = cls;
  unsigned char reply_buf[1024];
  ssize_t rlen;
  struct sockaddr_in answer;


  if ((0 != (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY)) &&
      (GNUNET_NETWORK_fdset_isset (tc->read_ready,
                                   lsock4)))
  {
    rlen = GNUNET_NETWORK_socket_recv (lsock4, reply_buf, sizeof (reply_buf));


    //Lets handle the packet
    memset(&answer, 0, sizeof(struct sockaddr_in));





    if(ah->phase == AUTO_NAT_PUNCHED)
    {
      //Destroy the connection
      GNUNET_NETWORK_socket_close (lsock4);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "The external server was able to connect back");
      ah->connected_back = GNUNET_YES;
      next_phase (ah);
    }
    else
    {
      if(GNUNET_OK == GNUNET_NAT_stun_handle_packet(reply_buf,rlen, &answer))
      {
        //Process the answer
        process_stun_reply(&answer, ah);

      }
      else
      {
        next_phase (ah);
      }
    }


  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "TIMEOUT while aiting for an answer");
    if(ah->phase == AUTO_NAT_PUNCHED)
    {
      stop_stun();
    }

    next_phase(ah);
  }



}


/**
 * Create an IPv4 listen socket bound to our port.
 *
 * @return NULL on error
 */
static struct GNUNET_NETWORK_Handle *
bind_v4 ()
{
  struct GNUNET_NETWORK_Handle *ls;
  struct sockaddr_in sa4;
  int eno;

  memset (&sa4, 0, sizeof (sa4));
  sa4.sin_family = AF_INET;
  sa4.sin_port = htons (port);
#if HAVE_SOCKADDR_IN_SIN_LEN
    sa4.sin_len = sizeof (sa4);
#endif
  ls = GNUNET_NETWORK_socket_create (AF_INET,
                                     SOCK_DGRAM,
                                     0);
  if (NULL == ls)
    return NULL;
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_bind (ls, (const struct sockaddr *) &sa4,
                                  sizeof (sa4)))
  {
    eno = errno;
    GNUNET_NETWORK_socket_close (ls);
    errno = eno;
    return NULL;
  }
  return ls;
}




static void request_callback(void *cls,
                             enum GNUNET_NAT_StatusCode result)
{
  struct GNUNET_NAT_AutoHandle *ah = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Stopping NAT and quitting...\n");
  stop_stun();

  next_phase(ah);
};





/**
 * Function called by NAT to report the outcome of the nat-test.
 * Clean up and update GUI.
 *
 * @param cls the auto handle
 * @param success currently always #GNUNET_OK
 * @param emsg NULL on success, otherwise an error message
 */
static void
result_callback (void *cls,
                 enum GNUNET_NAT_StatusCode ret)
{
  struct GNUNET_NAT_AutoHandle *ah = cls;

  if (GNUNET_NAT_ERROR_SUCCESS == ret)
    GNUNET_NAT_test_stop (ah->tst);
  ah->tst = NULL;
  ah->ret = ret;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              GNUNET_NAT_ERROR_SUCCESS == ret
	      ? _("NAT traversal with ICMP Server succeeded.\n")
	      : _("NAT traversal with ICMP Server failed.\n"));
  GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat", "ENABLE_ICMP_SERVER",
					 GNUNET_NAT_ERROR_SUCCESS == ret ? "NO" : "YES");
  next_phase (ah);
}


/**
 * Main function for the connection reversal test.
 *
 * @param cls the `struct GNUNET_NAT_AutoHandle`
 * @param tc scheduler context
 */
static void
reversal_test (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_AutoHandle *ah = cls;

  ah->task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Testing connection reversal with ICMP server.\n"));
  GNUNET_RESOLVER_connect (ah->cfg);
  ah->tst = GNUNET_NAT_test_start (ah->cfg, GNUNET_YES, 0, 0, TIMEOUT,
				   &result_callback, ah);
}


/**
 * Set our external IPv4 address based on the UPnP.
 *
 *
 * @param cls closure with our setup context
 * @param addr the address, NULL on errors
 * @param emsg NULL on success, otherwise an error message
 */
static void
set_external_ipv4 (void *cls,
                   const struct in_addr *addr,
                   enum GNUNET_NAT_StatusCode ret)
{
  struct GNUNET_NAT_AutoHandle *ah = cls;
  char buf[INET_ADDRSTRLEN];

  ah->eh = NULL;
  ah->ret = ret;
  if (GNUNET_NAT_ERROR_SUCCESS != ret)
  {
    next_phase (ah);
    return;
  }
  /* enable 'behind nat' */
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Detected external IP `%s'\n"),
	      inet_ntop (AF_INET,
			 addr,
			 buf,
			 sizeof (buf)));
  GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat", "BEHIND_NAT", "YES");

  /* set external IP address */
  if (NULL == inet_ntop (AF_INET, addr, buf, sizeof (buf)))
  {
    GNUNET_break (0);
    /* actually, this should never happen, as the caller already executed just
     * this check, but for consistency (eg: future changes in the caller) 
     * we still need to report this error...
     */
    ah->ret = GNUNET_NAT_ERROR_EXTERNAL_IP_ADDRESS_INVALID;
    next_phase (ah);
    return;
  }
  GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat", "EXTERNAL_ADDRESS",
					 buf);
  ah->upnp_set_external_address = GNUNET_YES;
  next_phase (ah);
}


/**
 * Determine our external IPv4 address.
 *
 * @param ah auto setup context
 */
static void
test_external_ip (struct GNUNET_NAT_AutoHandle *ah)
{
  if (GNUNET_NAT_ERROR_SUCCESS != ah->ret)
    next_phase (ah);
  
  // FIXME: CPS?
  /* try to detect external IP */
  ah->eh = GNUNET_NAT_mini_get_external_ipv4 (TIMEOUT,
					      &set_external_ipv4, ah);
}


/**
 * Determine our external IPv4 address and port using an external STUN server
 *
 * @param ah auto setup context
 */
static void
test_stun (struct GNUNET_NAT_AutoHandle *ah)
{

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,"Running STUN test");

  /* Get port from the configuration */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (ah->cfg,
                                             "transport-udp",
                                             "PORT",
                                             &port))
  {
    port = 2086;
  }

  //Lets create the socket
  lsock4 = bind_v4 ();
  if (NULL == lsock4)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
    next_phase(ah);
    return;
  }
  else
  {
    //Lets call our function now when it accepts
    ltask4 = GNUNET_SCHEDULER_add_read_net (NAT_SERVER_TIMEOUT,
                                            lsock4, &do_udp_read, ah);

  }


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "STUN service listens on port %u\n",
              port);
  if( GNUNET_NO == GNUNET_NAT_stun_make_request(stun_server, stun_port, lsock4, &request_callback, NULL))
  {
    /*An error happened*/
    stop_stun();
    next_phase(ah);
  }


}



/**
 * Process list of local IP addresses.  Find and set the
 * one of the default interface.
 *
 * @param cls our `struct GNUNET_NAT_AutoHandle`
 * @param name name of the interface (can be NULL for unknown)
 * @param isDefault is this presumably the default interface
 * @param addr address of this interface (can be NULL for unknown or unassigned)
 * @param broadcast_addr the broadcast address (can be NULL for unknown or unassigned)
 * @param netmask the network mask (can be NULL for unknown or unassigned))
 * @param addrlen length of the @a addr and @a broadcast_addr
 * @return GNUNET_OK to continue iteration, #GNUNET_SYSERR to abort
 */
static int
process_if (void *cls,
      const char *name,
      int isDefault,
      const struct sockaddr *addr,
      const struct sockaddr *broadcast_addr,
      const struct sockaddr *netmask,
      socklen_t addrlen)
{
  struct GNUNET_NAT_AutoHandle *ah = cls;
  const struct sockaddr_in *in;
  char buf[INET_ADDRSTRLEN];


  if ( (sizeof (struct sockaddr_in6) == addrlen) &&
       (0 != memcmp (&in6addr_loopback, &((const struct sockaddr_in6 *) addr)->sin6_addr,
		     sizeof (struct in6_addr))) &&
       (! IN6_IS_ADDR_LINKLOCAL(&((const struct sockaddr_in6 *) addr)->sin6_addr)) )
  {
    ah->have_v6 = GNUNET_YES;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("This system has a global IPv6 address, setting IPv6 to supported.\n"));

    return GNUNET_OK;
  }
  if (addrlen != sizeof (struct sockaddr_in))
    return GNUNET_OK;
  in = (const struct sockaddr_in *) addr;


  /* set internal IP address */
  if (NULL == inet_ntop (AF_INET, &in->sin_addr, buf, sizeof (buf)))
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat", "INTERNAL_ADDRESS",
					 buf);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Detected internal network address `%s'.\n"),
	      buf);


  ah->ret = GNUNET_NAT_ERROR_SUCCESS;

  /* Check if our internal IP is the same as the External detect by STUN*/
  if(ah->stun_ip && (strcmp(buf, ah->stun_ip) == 0) )
  {
    ah->internal_ip_is_public = GNUNET_YES;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,"A internal IP is the sameas the external");
    /* No need to continue*/
    return GNUNET_SYSERR;
  }

  /* no need to continue iteration if we found the default */
  if (!isDefault)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
}


/**
 * Determine our local IP addresses; detect internal IP & IPv6-support
 *
 * @param ah auto setup context
 */
static void
test_local_ip (struct GNUNET_NAT_AutoHandle *ah)
{
  ah->have_v6 = GNUNET_NO;
  ah->ret = GNUNET_NAT_ERROR_NO_VALID_IF_IP_COMBO; // reset to success if any of the IFs in below iterator has a valid IP
  GNUNET_OS_network_interfaces_list (&process_if, ah);
  
  GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat", "DISABLEV6",
					 (GNUNET_YES == ah->have_v6) ? "NO" : "YES");
  next_phase (ah);
}


/**
 * Test if NAT has been punched
 *
 * @param ah auto setup context
 */
static void
test_nat_punched (struct GNUNET_NAT_AutoHandle *ah)
{

  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_NAT_TestMessage msg;


  if(ah->stun_ip)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Asking gnunet-nat-server to connect to `%s'\n",
         ah->stun_ip);


    msg.header.size = htons (sizeof (struct GNUNET_NAT_TestMessage));
    msg.header.type = htons (GNUNET_MESSAGE_TYPE_NAT_TEST);
    msg.dst_ipv4 = inet_addr(ah->stun_ip);
    msg.dport = htons(ah->stun_port);
    msg.data = port;
    msg.is_tcp = htonl ((uint32_t) GNUNET_NO);

    client = GNUNET_CLIENT_connect ("gnunet-nat-server", ah->cfg);
    if (NULL == client)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to connect to `gnunet-nat-server'\n"));
      return;
    }

    GNUNET_break (GNUNET_OK ==
                  GNUNET_CLIENT_transmit_and_get_response (client, &msg.header,
                                                           NAT_SERVER_TIMEOUT,
                                                           GNUNET_YES, NULL,
                                                           NULL));
    ltask4 = GNUNET_SCHEDULER_add_read_net (NAT_SERVER_TIMEOUT,
                                            lsock4, &do_udp_read, ah);

  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "We don't have a STUN IP");
    next_phase(ah);
  }


}




/**
 * Test if UPnPC works.
 *
 * @param ah auto setup context
 */
static void
test_upnpc (struct GNUNET_NAT_AutoHandle *ah)
{

  int have_upnpc;

  if (GNUNET_NAT_ERROR_SUCCESS != ah->ret)
    next_phase (ah);
  
  // test if upnpc is available
  have_upnpc = (GNUNET_SYSERR !=
		GNUNET_OS_check_helper_binary ("upnpc", GNUNET_NO, NULL));
  //FIXME: test if upnpc is actually working, that is, if transports start to work once we use UPnP
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      (have_upnpc)
	      ? _("upnpc found, enabling its use\n")
	      : _("upnpc not found\n"));
  GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat", "ENABLE_UPNP",
					 (GNUNET_YES == have_upnpc) ? "YES" : "NO");
  next_phase (ah);

}


/**
 * Test if ICMP server is working
 *
 * @param ah auto setup context
 */
static void
test_icmp_server (struct GNUNET_NAT_AutoHandle *ah)
{

  int ext_ip;
  int nated;
  int binary;
  char *tmp;
  char *helper;
  ext_ip = GNUNET_NO;
  nated = GNUNET_NO;
  binary = GNUNET_NO;
  
  tmp = NULL;
  helper = GNUNET_OS_get_libexec_binary_path ("gnunet-helper-nat-server");
  if ((GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_string (ah->cfg, "nat", "EXTERNAL_ADDRESS",
                                               &tmp)) && (0 < strlen (tmp))){
    ext_ip = GNUNET_OK;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("test_icmp_server not possible, as we have no public IPv4 address\n"));
  }
  else
    goto err;
    
  if (GNUNET_YES ==
        GNUNET_CONFIGURATION_get_value_yesno (ah->cfg, "nat", "BEHIND_NAT")){
    nated = GNUNET_YES;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("test_icmp_server not possible, as we are not behind NAT\n"));
  }
  else
    goto err;
  
  if (GNUNET_YES ==
        GNUNET_OS_check_helper_binary (helper, GNUNET_YES, "-d 127.0.0.1" )){
    binary = GNUNET_OK; // use localhost as source for that one udp-port, ok for testing
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("No working gnunet-helper-nat-server found\n"));
  }
err:
  GNUNET_free_non_null (tmp);
  GNUNET_free (helper);

  if (GNUNET_OK == ext_ip && GNUNET_YES == nated && GNUNET_OK == binary)
    ah->task = GNUNET_SCHEDULER_add_now (&reversal_test, ah);
  else
    next_phase (ah);

}


/**
 * Test if ICMP client is working
 *
 * @param ah auto setup context
 */
static void
test_icmp_client (struct GNUNET_NAT_AutoHandle *ah)
{


  char *tmp;
  char *helper;

  tmp = NULL;
  helper = GNUNET_OS_get_libexec_binary_path ("gnunet-helper-nat-client");
  if ((GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_string (ah->cfg, "nat", "INTERNAL_ADDRESS",
                                               &tmp)) && (0 < strlen (tmp)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("test_icmp_client not possible, as we have no internal IPv4 address\n"));
  }
  else
    goto err;
  
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_yesno (ah->cfg, "nat", "BEHIND_NAT")){
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("test_icmp_server not possible, as we are not behind NAT\n"));
  }
  else
    goto err;
  
  if (GNUNET_YES ==
      GNUNET_OS_check_helper_binary (helper, GNUNET_YES, "-d 127.0.0.1 127.0.0.2 42")){
          // none of these parameters are actually used in privilege testing mode
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("No working gnunet-helper-nat-server found\n"));
  }
err:
  GNUNET_free_non_null (tmp);
  GNUNET_free (helper);

  next_phase (ah);

}


/**
 * Run the next phase of the auto test.
 */
static void
next_phase (struct GNUNET_NAT_AutoHandle *ah)
{
  struct GNUNET_CONFIGURATION_Handle *diff;

  ah->phase++;
  switch (ah->phase)
  {
  case AUTO_INIT:
    GNUNET_assert (0);
    break;
  case AUTO_EXTERNAL_IP:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Will run AUTO_EXTERNAL_IP\n");
    test_external_ip (ah);
    break;
  case AUTO_STUN:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Will run AUTO_STUN\n");
    test_stun (ah);
    break;
  case AUTO_LOCAL_IP:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Will run AUTO_LOCAL_IP\n");
    test_local_ip (ah);
    break;
  case AUTO_NAT_PUNCHED:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Will run GNUNET_ERROR_TYPE_DEBUG\n");
    test_nat_punched (ah);
    break;
  case AUTO_UPNPC:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Will run AUTO_UPNPC\n");
    test_upnpc (ah);
    break;
  case AUTO_ICMP_SERVER:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Will run AUTO_ICMP_SERVER\n");
    test_icmp_server (ah);
    break;
  case AUTO_ICMP_CLIENT:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Will run AUTO_ICMP_CLIENT\n");
    test_icmp_client (ah);
    break;
  case AUTO_DONE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Done with tests\n");
    if(!ah->internal_ip_is_public)
    {
      GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat", "BEHIND_NAT", "YES");

      if(ah->connected_back)
      {
        GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat", "PUNCHED_NAT", "YES");
      }
      else
      {
        GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat", "PUNCHED_NAT", "NO");
      }

      if (ah->stun_ip)
      {
        GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat", "EXTERNAL_ADDRESS",
                                               ah->stun_ip);
        if(ah->connected_back)
        {
          ah->type = GNUNET_NAT_TYPE_STUN_PUNCHED_NAT;
          GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat", "USE_STUN", "YES");
        }
        else
        {
          ah->type = GNUNET_NAT_TYPE_UNREACHABLE_NAT;
          GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat", "USE_STUN", "NO");
        }

      }
      if(ah->stun_port)
      {
        GNUNET_CONFIGURATION_set_value_number (ah->cfg, "transport-udp",
                                               "ADVERTISED_PORT",
                                               ah->stun_port);
      }

    }
    else
    {
      //The internal IP is the same as public, but we didn't got a incoming connection
      if(ah->connected_back)
      {
        ah->type = GNUNET_NAT_TYPE_NO_NAT;
        GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat", "BEHIND_NAT", "NO");
      }
      else
      {
        GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat", "BEHIND_NAT", "YES");
        ah->type = GNUNET_NAT_TYPE_UNREACHABLE_NAT;
        if (ah->stun_ip)
        {
          GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat", "EXTERNAL_ADDRESS",
                                                 ah->stun_ip);
        }
        if(ah->stun_port)
        {
          GNUNET_CONFIGURATION_set_value_number (ah->cfg, "transport-udp",
                                                 "ADVERTISED_PORT",
                                                 ah->stun_port);

        }
      }
    }

    diff = GNUNET_CONFIGURATION_get_diff (ah->initial_cfg,
                                          ah->cfg);


    ah->fin_cb (ah->fin_cb_cls,
                diff,
                ah->ret,
                ah->type);
    GNUNET_CONFIGURATION_destroy (diff);
    GNUNET_NAT_autoconfig_cancel (ah);
    return;

  }



}


/**
 * Start auto-configuration routine.  The resolver service should
 * be available when this function is called.
 *
 * @param cfg initial configuration
 * @param cb function to call with autoconfiguration result
 * @param cb_cls closure for @a cb
 * @return handle to cancel operation
 */
struct GNUNET_NAT_AutoHandle *
GNUNET_NAT_autoconfig_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
			     GNUNET_NAT_AutoResultCallback cb,
			     void *cb_cls)
{
  struct GNUNET_NAT_AutoHandle *ah;

  ah = GNUNET_new (struct GNUNET_NAT_AutoHandle);
  ah->fin_cb = cb;
  ah->fin_cb_cls = cb_cls;
  ah->ret = GNUNET_NAT_ERROR_SUCCESS;
  ah->cfg = GNUNET_CONFIGURATION_dup (cfg);
  ah->initial_cfg = GNUNET_CONFIGURATION_dup (cfg);

  /* never use loopback addresses if user wanted autoconfiguration */
  GNUNET_CONFIGURATION_set_value_string (ah->cfg, "nat",
					 "USE_LOCALADDR",
					 "NO");

  next_phase (ah);
  return ah;
}


/**
 * Abort autoconfiguration.
 *
 * @param ah handle for operation to abort
 */
void
GNUNET_NAT_autoconfig_cancel (struct GNUNET_NAT_AutoHandle *ah)
{
  if (NULL != ah->tst)
  {
    GNUNET_NAT_test_stop (ah->tst);
    ah->tst = NULL;
  }
  if (NULL != ah->eh)
  {
    GNUNET_NAT_mini_get_external_ipv4_cancel (ah->eh);
    ah->eh = NULL;
  }
  if (NULL != ah->task)
  {
    GNUNET_SCHEDULER_cancel (ah->task);
    ah->task = NULL;
  }
  GNUNET_CONFIGURATION_destroy (ah->cfg);
  GNUNET_CONFIGURATION_destroy (ah->initial_cfg);
  GNUNET_free (ah);
}


/* end of nat_auto.c */
