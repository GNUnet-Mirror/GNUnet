/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
  AUTO_ONLINE = 1,

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
   * Closure for 'fin_cb'.
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
  GNUNET_SCHEDULER_TaskIdentifier tsk;

  /**
   * Where are we in the test?
   */
  enum AutoPhase phase;

};


/**
 * Run the next phase of the auto test.
 *
 * @param ac auto test handle
 */
static void
next_phase (struct GNUNET_NAT_AutoHandle *ac);



    GNUNET_break (0);
    return;
  }
  gtk_toggle_button_set_active (button, on ? TRUE : FALSE);
}



/**
 * Function called if NAT failed to confirm success.
 * Clean up and update GUI (with failure).
 *
 * @param cls closure with setup context
 * @param tc scheduler callback
 */
static void
fail_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_AutoHandle *ac = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("NAT traversal with ICMP Server timed out.\n"));
  GNUNET_assert (NULL != ac->tst);
  ac->tsk = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_NAT_test_stop (ac->tst);
  ac->tst = NULL;
  update_icmp_server_enable_button (GNUNET_NO);
  if (NULL != cfg)
    GNUNET_CONFIGURATION_set_value_string (cfg, "nat", "ENABLE_ICMP_SERVER", "NO");
  next_phase (ac);
}


/**
 * Main function for the connection reversal test.
 *
 * @param cls the 'int*' for the result
 * @param tc scheduler context
 */
static void
reversal_test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_AutoHandle *ac = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Testing connection reversal with ICMP server.\n"));
  GNUNET_assert (NULL != cfg);
  GNUNET_RESOLVER_connect (cfg);
  ac->tst = GNUNET_NAT_test_start (cfg, GNUNET_YES, 0, 0, &result_callback, ac);
  if (NULL == ac->tst)
  {
    next_phase (ac);
    return;
  }
  ac->tsk = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &fail_timeout, ac);
}


/**
 * Test if we are online at all.
 *
 * @param ac auto setup context
 */
static void
test_online (struct GNUNET_NAT_AutoHandle *ac)
{
  // FIXME: not implemented
  next_phase (ac);
}


/**
 * Set our external IPv4 address.
 *
 * @param cls closure with our setup context
 * @param addr the address, NULL on errors
 */
static void
set_external_ipv4 (void *cls, const struct in_addr *addr)
{
  struct GNUNET_NAT_AutoHandle *ac = cls;
  char buf[INET_ADDRSTRLEN];
  GObject *o;

  ac->eh = NULL;
  if (NULL == addr)
  {
    next_phase (ac);
    return;
  }
  /* enable 'behind nat' */
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Detected external IP `%s'\n"),
	      inet_ntop (AF_INET,
			 addr,
			 buf,
			 sizeof (buf)));
  if (NULL != cfg)
    GNUNET_CONFIGURATION_set_value_string (cfg, "nat", "BEHIND_NAT", "YES");
  o = GNUNET_SETUP_get_object ("GNUNET_setup_transport_nat_checkbutton");
  gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (o), TRUE);

  /* set external IP address */
  if (NULL == inet_ntop (AF_INET, addr, buf, sizeof (buf)))
  {
    GNUNET_break (0);
    next_phase (ac);
    return;
  }
  if (NULL != cfg)
    GNUNET_CONFIGURATION_set_value_string (cfg, "nat", "EXTERNAL_ADDRESS",
					   buf);
  o = GNUNET_SETUP_get_object ("GNUNET_setup_transport_external_ip_address_entry");
  gtk_entry_set_text (GTK_ENTRY (o), buf);
  next_phase (ac);
}


/**
 * Determine our external IPv4 address.
 *
 * @param ac auto setup context
 */
static void
test_external_ip (struct GNUNET_NAT_AutoHandle *ac)
{
  // FIXME: CPS?
  /* try to detect external IP */
  ac->eh = GNUNET_NAT_mini_get_external_ipv4 (TIMEOUT,
					      &set_external_ipv4, ac);
}


/**
 * Process list of local IP addresses.  Find and set the
 * one of the default interface.
 *
 * @param cls pointer to int to store if we have a non-local IPv6 address
 * @param name name of the interface (can be NULL for unknown)
 * @param isDefault is this presumably the default interface
 * @param addr address of this interface (can be NULL for unknown or unassigned)
 * @param broadcast_addr the broadcast address (can be NULL for unknown or unassigned)
 * @param netmask the network mask (can be NULL for unknown or unassigned))
 * @param addrlen length of the address
 * @return GNUNET_OK to continue iteration, GNUNET_SYSERR to abort
 */
static int
nipo (void *cls, const char *name, int isDefault, const struct sockaddr *addr,
      const struct sockaddr *broadcast_addr, const struct sockaddr *netmask,
      socklen_t addrlen)
{
  int *have_v6 = cls;
  const struct sockaddr_in *in;
  char buf[INET_ADDRSTRLEN];
  GtkEntry *entry;

  if (!isDefault)
    return GNUNET_OK;
  if ( (sizeof (struct sockaddr_in6) == addrlen) &&
       (0 != memcmp (&in6addr_loopback, addr,
		     addrlen)) &&
       (! IN6_IS_ADDR_LINKLOCAL(addr)) )
  {
    *have_v6 = GNUNET_YES;
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
  GNUNET_CONFIGURATION_set_value_string (cfg, "nat", "INTERNAL_ADDRESS", buf);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Detected internal network address `%s'.\n"),
	      buf);
  entry =
      GTK_ENTRY (GNUNET_SETUP_get_object
                 ("GNUNET_setup_transport_internal_ip_entry"));
  gtk_entry_set_text (entry, buf);
  /* no need to continue iteration */
  return GNUNET_SYSERR;
}


/**
 * Determine our local IP addresses; detect internal IP & IPv6-support 
 *
 * @param ac auto setup context
 */
static void
test_local_ip (struct GNUNET_NAT_AutoHandle *ac)
{
  GtkToggleButton *button;
  int have_v6;

  have_v6 = GNUNET_NO;
  GNUNET_OS_network_interfaces_list (&nipo, &have_v6);
  button = GTK_TOGGLE_BUTTON (GNUNET_SETUP_get_object ("GNUNET_setup_transport_disable_ipv6_checkbutton"));
  gtk_toggle_button_set_active (button,
				(GNUNET_YES == have_v6) ? FALSE : TRUE);
  if (NULL != cfg)
    GNUNET_CONFIGURATION_set_value_string (cfg, "nat", "DISABLEV6", 
					   (GNUNET_YES == have_v6) ? "NO" : "YES");
  next_phase (ac);
}


/**
 * Test if NAT has been punched
 *
 * @param ac auto setup context
 */
static void
test_nat_punched (struct GNUNET_NAT_AutoHandle *ac)
{
  // FIXME: not implemented
  next_phase (ac);
}


/**
 * Test if UPnPC works.
 *
 * @param ac auto setup context
 */
static void
test_upnpc (struct GNUNET_NAT_AutoHandle *ac)
{
  int have_upnpc;
  GtkToggleButton *button;

  /* test if upnpc is available */
  button = GTK_TOGGLE_BUTTON (GNUNET_SETUP_get_object ("GNUNET_setup_transport_upnp_enable_checkbutton"));
  have_upnpc = (GNUNET_SYSERR !=
		GNUNET_OS_check_helper_binary ("upnpc"));
  /* FIXME: test if upnpc is actually working, that is, if transports
     start to work once we use UPnP */
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      (have_upnpc) 
	      ? _("upnpc found, enabling its use\n")
	      : _("upnpc not found\n"));
  gtk_toggle_button_set_active (button,
				have_upnpc
				? TRUE
				: FALSE);
  if (NULL != cfg)
    GNUNET_CONFIGURATION_set_value_string (cfg, "nat", "ENABLE_UPNP", 
					   (GNUNET_YES == have_upnpc) ? "YES" : "NO");
  next_phase (ac);
}


/**
 * Test if ICMP server is working
 *
 * @param ac auto setup context
 */
static void
test_icmp_server (struct GNUNET_NAT_AutoHandle *ac)
{
  int hns;
  char *tmp;
  char *binary;

  tmp = NULL;
  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-helper-nat-server");
  hns =
      ((GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_string (cfg, "nat", "EXTERNAL_ADDRESS",
                                               &tmp)) && (0 < strlen (tmp)) &&
       (GNUNET_YES ==
        GNUNET_CONFIGURATION_get_value_yesno (cfg, "nat", "BEHIND_NAT")) &&
       (GNUNET_YES ==
        GNUNET_OS_check_helper_binary (binary)));
  GNUNET_free_non_null (tmp);
  GNUNET_free (binary);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      (hns) 
	      ? _("gnunet-helper-nat-server found, testing it\n")
	      : _("No working gnunet-helper-nat-server found\n"));
  if (hns)
     GNUNET_SCHEDULER_add_now (&reversal_test, ac);
  else
    next_phase (ac);
}


/**
 * Test if ICMP client is working
 *
 * @param ac auto setup context
 */
static void
test_icmp_client (struct GNUNET_NAT_AutoHandle *ac)
{
  GtkToggleButton *button;
  int hnc;
  char *tmp;
  char *binary;

  tmp = NULL;
  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-helper-nat-client");
  hnc =
      ((GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_string (cfg, "nat", "INTERNAL_ADDRESS",
                                               &tmp)) && (0 < strlen (tmp)) &&
       (GNUNET_YES !=
        GNUNET_CONFIGURATION_get_value_yesno (cfg, "nat", "BEHIND_NAT")) &&
       (GNUNET_YES ==
        GNUNET_OS_check_helper_binary (binary)));
  GNUNET_free_non_null (tmp);
  GNUNET_free (binary);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      (hnc) 
	      ? _("gnunet-helper-nat-client found, enabling it\n")
	      : _("gnunet-helper-nat-client not found or behind NAT, disabling it\n"));
  button =
      GTK_TOGGLE_BUTTON (GNUNET_SETUP_get_object
                         ("GNUNET_setup_transport_icmp_client_enable_checkbutton"));
  gtk_toggle_button_set_active (button, hnc ? TRUE : FALSE);
  next_phase (ac);
}


/**
 * Run the next phase of the auto test.
 */
static void
next_phase (struct GNUNET_NAT_AutoHandle *ac)
{
  ac->phase++;
  switch (ac->phase)
  {
  case AUTO_INIT:
    GNUNET_assert (0);
    break;
  case AUTO_ONLINE:
    test_online (ac);
    break;
  case AUTO_EXTERNAL_IP:
    test_external_ip (ac);
    break;
  case AUTO_LOCAL_IP:
    test_local_ip (ac);
    break;
  case AUTO_NAT_PUNCHED:
    test_nat_punched (ac);
    break;
  case AUTO_UPNPC:
    test_upnpc (ac);
    break;
  case AUTO_ICMP_SERVER:
    test_icmp_server (ac);
    break;
  case AUTO_ICMP_CLIENT:
    test_icmp_client (ac);
    break;
  case AUTO_DONE:
    ac->fin_cb (ac->fin_cb_cls);
    GNUNET_free (ac);
    return;
  }
}



/**
 * Start auto-configuration routine.  The resolver service should
 * be available when this function is called.
 *
 * @param cfg initial configuration
 * @param cb function to call with autoconfiguration result
 * @param cb_cls closure for cb
 * @return handle to cancel operation
 */
struct GNUNET_NAT_AutoHandle *
GNUNET_NAT_autoconfig_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
			     GNUNET_NAT_AutoResultCallback cb,
			     void *cb_cls)
{
  struct GNUNET_NAT_AutoHandle *ac;

  ac = GNUNET_malloc (sizeof (struct GNUNET_NAT_AutoHandle));
  ac->fin_cb = cb;
  ac->fin_cb_cls = cb_cls;
  ac->cfg = GNUNET_CONFIGURATION_dup (cfg);
  ac->init_cfg = GNUNET_CONFIGURATION_dup (cfg);

  /* never use loopback addresses if user wanted autoconfiguration */
  GNUNET_CONFIGURATION_set_value_string (ac->cfg, "nat", 
					 "USE_LOCALADDR", 
					 "NO");
  next_phase (ac);
  return ac;
}

			     

/**
 * Abort autoconfiguration.
 *
 * @param ah handle for operation to abort
 */
void
GNUNET_NAT_autoconfig_cancel (struct GNUNET_NAT_AutoHandle *ah)
{
}



/* end of nat_auto.c */
