/*
     This file is part of GNUnet.
     Copyright (C) 2007-2017 GNUnet e.V.

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
 * @author Christian Grothoff
 * @author Milan Bouchet-Valat
 *
 * @file nat-auto/nat_auto_api.c
 * Routines for NAT auto configuration.
 */
#include "platform.h"
#include "gnunet_nat_service.h"
#include "gnunet_nat_auto_service.h"
#include "nat-auto.h"



/**
 * Handle to auto-configuration in progress.
 */
struct GNUNET_NAT_AUTO_AutoHandle
{

  /**
   * Configuration we use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  
  /**
   * Message queue for communicating with the NAT service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Function called with the result from the autoconfiguration.
   */
  GNUNET_NAT_AUTO_AutoResultCallback arc;

  /**
   * Closure for @e arc.
   */
  void *arc_cls;

};


/**
 * Converts `enum GNUNET_NAT_StatusCode` to string
 *
 * @param err error code to resolve to a string
 * @return point to a static string containing the error code
 */
const char *
GNUNET_NAT_AUTO_status2string (enum GNUNET_NAT_StatusCode err)
{
  switch (err)
  {
  case GNUNET_NAT_ERROR_SUCCESS:
    return _ ("Operation Successful");
  case GNUNET_NAT_ERROR_IPC_FAILURE:
    return _ ("IPC failure");
  case GNUNET_NAT_ERROR_INTERNAL_NETWORK_ERROR:
    return _ ("Failure in network subsystem, check permissions.");
  case GNUNET_NAT_ERROR_TIMEOUT:
    return _ ("Encountered timeout while performing operation");
  case GNUNET_NAT_ERROR_NOT_ONLINE:
    return _ ("detected that we are offline");
  case GNUNET_NAT_ERROR_UPNPC_NOT_FOUND:
    return _ ("`upnpc` command not found");
  case GNUNET_NAT_ERROR_UPNPC_FAILED:
    return _ ("Failed to run `upnpc` command");
  case GNUNET_NAT_ERROR_UPNPC_TIMEOUT:
    return _ ("`upnpc' command took too long, process killed");
  case GNUNET_NAT_ERROR_UPNPC_PORTMAP_FAILED:
    return _ ("`upnpc' command failed to establish port mapping");
  case GNUNET_NAT_ERROR_EXTERNAL_IP_UTILITY_NOT_FOUND:
    return _ ("`external-ip' command not found");
  case GNUNET_NAT_ERROR_EXTERNAL_IP_UTILITY_FAILED:
    return _ ("Failed to run `external-ip` command");
  case GNUNET_NAT_ERROR_EXTERNAL_IP_UTILITY_OUTPUT_INVALID:
    return _ ("`external-ip' command output invalid");
  case GNUNET_NAT_ERROR_EXTERNAL_IP_ADDRESS_INVALID:
    return _ ("no valid address was returned by `external-ip'");
  case GNUNET_NAT_ERROR_NO_VALID_IF_IP_COMBO:
    return _ ("Could not determine interface with internal/local network address");
  case GNUNET_NAT_ERROR_HELPER_NAT_SERVER_NOT_FOUND:
    return _ ("No functioning gnunet-helper-nat-server installation found");
  case GNUNET_NAT_ERROR_NAT_TEST_START_FAILED:
    return _ ("NAT test could not be initialized");
  case GNUNET_NAT_ERROR_NAT_TEST_TIMEOUT:
    return _ ("NAT test timeout reached");
  case GNUNET_NAT_ERROR_NAT_REGISTER_FAILED:
    return _ ("could not register NAT");
  case GNUNET_NAT_ERROR_HELPER_NAT_CLIENT_NOT_FOUND:
    return _ ("No working gnunet-helper-nat-client installation found");
  default:
    return "unknown status code";
  }
}


/**
 * Check result from autoconfiguration attempt.
 *
 * @param cls the `struct GNUNET_NAT_AUTO_AutoHandle`
 * @param res the result
 * @return #GNUNET_OK if @a res is well-formed (always for now)
 */
static int
check_auto_result (void *cls,
		   const struct GNUNET_NAT_AUTO_AutoconfigResultMessage *res)
{
  return GNUNET_OK;
}


/**
 * Handle result from autoconfiguration attempt.
 *
 * @param cls the `struct GNUNET_NAT_AUTO_AutoHandle`
 * @param res the result
 */
static void
handle_auto_result (void *cls,
		    const struct GNUNET_NAT_AUTO_AutoconfigResultMessage *res)
{
  struct GNUNET_NAT_AUTO_AutoHandle *ah = cls;
  size_t left;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  enum GNUNET_NAT_Type type
    = (enum GNUNET_NAT_Type) ntohl (res->type);
  enum GNUNET_NAT_StatusCode status
    = (enum GNUNET_NAT_StatusCode) ntohl (res->status_code);

  left = ntohs (res->header.size) - sizeof (*res);
  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_deserialize (cfg,
					(const char *) &res[1],
					left,
					GNUNET_NO))
  {
    GNUNET_break (0);
    ah->arc (ah->arc_cls,
	     NULL,
	     GNUNET_NAT_ERROR_IPC_FAILURE,
	     type);
  }
  else
  {
    ah->arc (ah->arc_cls,
	     cfg,
	     status,
	     type);
  }
  GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_NAT_AUTO_autoconfig_cancel (ah);
}


/**
 * Handle queue errors by reporting autoconfiguration failure.
 *
 * @param cls the `struct GNUNET_NAT_AUTO_AutoHandle *`
 * @param error details about the error
 */
static void
ah_error_handler (void *cls,
		  enum GNUNET_MQ_Error error)
{
  struct GNUNET_NAT_AUTO_AutoHandle *ah = cls;

  ah->arc (ah->arc_cls,
	   NULL,
	   GNUNET_NAT_ERROR_IPC_FAILURE,
	   GNUNET_NAT_TYPE_UNKNOWN);
  GNUNET_NAT_AUTO_autoconfig_cancel (ah);
}


/**
 * Start auto-configuration routine.  The transport adapters should
 * be stopped while this function is called.
 *
 * @param cfg initial configuration
 * @param cb function to call with autoconfiguration result
 * @param cb_cls closure for @a cb
 * @return handle to cancel operation
 */
struct GNUNET_NAT_AUTO_AutoHandle *
GNUNET_NAT_AUTO_autoconfig_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
			     GNUNET_NAT_AUTO_AutoResultCallback cb,
			     void *cb_cls)
{
  struct GNUNET_NAT_AUTO_AutoHandle *ah = GNUNET_new (struct GNUNET_NAT_AUTO_AutoHandle);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (auto_result,
			   GNUNET_MESSAGE_TYPE_NAT_AUTO_CFG_RESULT,
			   struct GNUNET_NAT_AUTO_AutoconfigResultMessage,
			   ah),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_NAT_AUTO_AutoconfigRequestMessage *req;
  char *buf;
  size_t size;

  buf = GNUNET_CONFIGURATION_serialize (cfg,
					&size);
  if (size > GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (*req))
  {
    GNUNET_break (0);
    GNUNET_free (buf);
    GNUNET_free (ah);
    return NULL;
  }
  ah->arc = cb;
  ah->arc_cls = cb_cls;
  ah->mq = GNUNET_CLIENT_connecT (cfg,
				  "nat",
				  handlers,
				  &ah_error_handler,
				  ah);
  if (NULL == ah->mq)
  {
    GNUNET_break (0);
    GNUNET_free (buf);
    GNUNET_free (ah);
    return NULL;
  }
  env = GNUNET_MQ_msg_extra (req,
			     size,
			     GNUNET_MESSAGE_TYPE_NAT_AUTO_REQUEST_CFG);
  GNUNET_memcpy (&req[1],
		 buf,
		 size);
  GNUNET_free (buf);
  GNUNET_MQ_send (ah->mq,
		  env);
  return ah;
}


/**
 * Abort autoconfiguration.
 *
 * @param ah handle for operation to abort
 */
void
GNUNET_NAT_AUTO_autoconfig_cancel (struct GNUNET_NAT_AUTO_AutoHandle *ah)
{
  GNUNET_MQ_destroy (ah->mq);
  GNUNET_free (ah);
}

/* end of nat_api_auto.c */
