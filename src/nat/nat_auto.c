/*
     This file is part of GNUnet.
     Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file nat/nat_auto.c
 * @brief functions for auto-configuration of the network
 * @author Christian Grothoff
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
   * Test if we are online.
   */
  AUTO_ONLINE,

  /**
   * Test our external IP.
   */
  AUTO_EXTERNAL_IP,

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
   * Do we have IPv6?
   */
  int have_v6;

  /**
   * Error code for better debugging and user feedback
   */
  enum GNUNET_NAT_StatusCode ret;
};


/**
 * Run the next phase of the auto test.
 *
 * @param ah auto test handle
 */
static void
next_phase (struct GNUNET_NAT_AutoHandle *ah);


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
 * Test if we are online at all.
 *
 * @param ah auto setup context
 */
static void
test_online (struct GNUNET_NAT_AutoHandle *ah)
{
  // FIXME: not implemented
  /*
   * if (failure)
   *  ah->ret = GNUNET_NAT_ERROR_NOT_ONLINE;
   */
  next_phase (ah);
}


/**
 * Set our external IPv4 address.
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

  if (!isDefault)
    return GNUNET_OK;
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
  /* no need to continue iteration */
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
  if (GNUNET_NAT_ERROR_SUCCESS != ah->ret)
    next_phase (ah);
  
  // FIXME: not implemented
  
  next_phase (ah);
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
  
  /* test if upnpc is available */
  have_upnpc = (GNUNET_SYSERR !=
		GNUNET_OS_check_helper_binary ("upnpc", GNUNET_NO, NULL));
  /* FIXME: test if upnpc is actually working, that is, if transports
     start to work once we use UPnP */
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
  case AUTO_ONLINE:
    test_online (ah);
    break;
  case AUTO_EXTERNAL_IP:
    test_external_ip (ah);
    break;
  case AUTO_LOCAL_IP:
    test_local_ip (ah);
    break;
  case AUTO_NAT_PUNCHED:
    test_nat_punched (ah);
    break;
  case AUTO_UPNPC:
    test_upnpc (ah);
    break;
  case AUTO_ICMP_SERVER:
    test_icmp_server (ah);
    break;
  case AUTO_ICMP_CLIENT:
    test_icmp_client (ah);
    break;
  case AUTO_DONE:
    diff = GNUNET_CONFIGURATION_get_diff (ah->initial_cfg,
					  ah->cfg);
    ah->fin_cb (ah->fin_cb_cls,
		diff,
                ah->ret);
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
