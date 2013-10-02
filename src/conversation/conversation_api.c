/*
     This file is part of GNUnet.
     (C  2013 Christian Grothoff (and other contributing authors)

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
 * @file conversation/conversation_api.c
 * @brief API for conversation
 * @author Simon Dieterle
 * @author Andreas Fuchs
 * STRUCTURE:
 * - DATA STRUCTURES
 * - DECLARATIONS
 * - AUXILIARY FUNCTIONS
 * - RECEIVE HANDLERS
 * - SEND FUNCTIONS
 * - API CALL DEFINITIONS
 *
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_gns_service.h"
#include "gnunet_protocols.h"
#include "conversation.h"
#include "gnunet_conversation_service.h"

#define MAX_TRANSMIT_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

enum GNUNET_CONVERSATION_CallType
{
  CALLER = 0,
  CALLEE
};

/**
* Information about a call
*/
struct GNUNET_CONVERSATION_CallInformation
{

	/**
	* Peer interacting with
	*/
  struct GNUNET_PeerIdentity peer;

	/**
	* Type of call (incoming or outgoing)
	*/
  int type;

	/**
	* Shows if the call ist fully established
	*/
  int established;
};

/**
 * Opaque handle to the service.
 */
struct GNUNET_CONVERSATION_Handle
{

	/**
 	* Our configuration.
 	*/
  const struct GNUNET_CONFIGURATION_Handle *cfg;

    /**
     * Handle to the server connection, to send messages later
     */
  struct GNUNET_CLIENT_Connection *client;

   /**
	* GNS handle
	*/
  struct GNUNET_GNS_Handle *gns;

	/**
	* Namestore handle
	*/
  struct GNUNET_NAMESTORE_Handle *namestore;

	/**
	* TXT record for gns
	*/
  int txt_record_set;

	/**
     * Callback for incoming calls
     */
  GNUNET_CONVERSATION_CallHandler *call_handler;

	/**
     * Callback for rejected calls
     */
  GNUNET_CONVERSATION_RejectHandler *reject_handler;

	/**
     * Callback for notifications
     */
  GNUNET_CONVERSATION_NotificationHandler *notification_handler;

	/**
     * Callback for missed calls
     */
  GNUNET_CONVERSATION_MissedCallHandler *missed_call_handler;

	/**
	* The pointer to the call
	*/
  struct GNUNET_CONVERSATION_CallInformation *call;
};

/******************************************************************************/
/***********************     AUXILIARY FUNCTIONS      *************************/
/******************************************************************************/

/**
* Initialize the conversation txt record in GNS
*/
static void
setup_gns_txt (struct GNUNET_CONVERSATION_Handle *handle)
{
  struct GNUNET_CRYPTO_EccPublicSignKey zone_pkey;
  struct GNUNET_CRYPTO_EccPrivateKey *zone_key;
  struct GNUNET_CRYPTO_EccPrivateKey *peer_key;
  struct GNUNET_NAMESTORE_RecordData rd;
  struct GNUNET_PeerIdentity peer;

  char *zone_keyfile;
  char *peer_keyfile;

  rd.expiration_time = UINT64_MAX;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (handle->cfg, "gns", "ZONEKEY",
					       &zone_keyfile))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
      return;
    }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (handle->cfg, "PEER",
					       "PRIVATE_KEY", &peer_keyfile))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
      return;
    }

  zone_key = GNUNET_CRYPTO_ecc_key_create_from_file (zone_keyfile);
  GNUNET_CRYPTO_ecc_key_get_public_for_signature (zone_key, &zone_pkey);
  peer_key = GNUNET_CRYPTO_ecc_key_create_from_file (peer_keyfile);
  GNUNET_CRYPTO_ecc_key_get_public_for_signature (peer_key,
						  &peer.public_key);
  const char *h = GNUNET_i2s_full (&peer);

  rd.data_size = strlen (h) + 1;
  rd.data = h;
  rd.record_type = GNUNET_DNSPARSER_TYPE_TXT;
  rd.flags = GNUNET_NAMESTORE_RF_NONE;

  /* FIXME: continuation? return value? */
  GNUNET_NAMESTORE_records_store (handle->namestore, 
				  zone_key,
				  "conversation", 
				  1, &rd,
				  NULL, NULL);
}

/**
* Callback for checking the conversation txt gns record
*
* @param cls closure
* @param rd_count
* @param rd
*/
static void
check_gns_cb (void *cls, uint32_t rd_count,
	      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GNUNET_CONVERSATION_Handle *h = (struct GNUNET_CONVERSATION_Handle *) cls;

  if (0 == rd_count)
    {
      setup_gns_txt (h);
    }
  else
    {
      h->txt_record_set = GNUNET_YES;
    }

  return;
}

/**
* Check if the gns txt record for conversation exits
*/
static void
check_gns (struct GNUNET_CONVERSATION_Handle *h)
{
  GNUNET_GNS_lookup (h->gns, "conversation.gads", 
		     NULL /* FIXME_ZONE */,
		     GNUNET_DNSPARSER_TYPE_TXT,
		     GNUNET_NO, 
		     NULL, 
		     &check_gns_cb, h);

  return;
}

/******************************************************************************/
/***********************      RECEIVE HANDLERS     ****************************/
/******************************************************************************/

/**
 * Function to process all messages received from the service
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
receive_message_cb (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CONVERSATION_Handle *h = cls;
  struct ServerClientSessionInitiateMessage *imsg;
  struct ServerClientSessionRejectMessage *rmsg;
  struct GNUNET_CONVERSATION_MissedCallNotification *missed_calls;

  if (NULL != msg)
    {
      switch (ntohs (msg->type))
	{
	case GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_ACCEPT:
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("%s has accepted your call.\n"),
		      GNUNET_i2s_full (&(h->call->peer)));

	  h->notification_handler (NULL, h, NotificationType_CALL_ACCEPTED,
				   &(h->call->peer));
	  h->call->type = CALLEE;

	  break;

	case GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_REJECT:
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("%s has rejected your call.\n"),
		      GNUNET_i2s_full (&(h->call->peer)));

	  rmsg = (struct ServerClientSessionRejectMessage *) msg;
	  h->reject_handler (NULL, h, ntohs (rmsg->reason), &(h->call->peer));
	  GNUNET_free (h->call);
	  h->call = NULL;

	  break;

	case GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_TERMINATE:
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("%s has terminated the call.\n"),
		      GNUNET_i2s_full (&(h->call->peer)));

	  h->notification_handler (NULL, h, NotificationType_CALL_TERMINATED,
				   &(h->call->peer));
	  GNUNET_free (h->call);
	  h->call = NULL;

	  break;

	case GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_INITIATE:
	  imsg = (struct ServerClientSessionInitiateMessage *) msg;

	  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("%s wants to call you.\n"),
		      GNUNET_i2s_full (&(imsg->peer)));

	  h->call =
	    (struct GNUNET_CONVERSATION_CallInformation *)
	    GNUNET_malloc (sizeof (struct GNUNET_CONVERSATION_CallInformation));
	  memcpy (&(h->call->peer), &(imsg->peer),
		  sizeof (struct GNUNET_PeerIdentity));
	  h->call_handler (NULL, h, &(h->call->peer));
	  h->call->type = CALLEE;

	  break;

	case GNUNET_MESSAGE_TYPE_CONVERSATION_SC_MISSED_CALL:
	  missed_calls =
	    (struct GNUNET_CONVERSATION_MissedCallNotification *) (msg +
							   (sizeof
							    (struct
							     GNUNET_MessageHeader)));
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("You &d have missed a calls.\n"),
		      missed_calls->number);
	  h->missed_call_handler (NULL, h, missed_calls);
	  break;

	case GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SERVICE_BLOCKED:
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("The service is blocked.\n"));
	  h->notification_handler (NULL, h, NotificationType_SERVICE_BLOCKED,
				   NULL);
	  break;

	case GNUNET_MESSAGE_TYPE_CONVERSATION_SC_PEER_NOT_CONNECTED:
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("The peer you are calling is not connected.\n"));
	  h->notification_handler (NULL, h, NotificationType_NO_PEER, NULL);
	  break;

	case GNUNET_MESSAGE_TYPE_CONVERSATION_SC_NO_ANSWER:
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("The peer you are calling does not answer.\n"));
	  h->notification_handler (NULL, h, NotificationType_NO_ANSWER,
				   &(h->call->peer));
	  break;

	case GNUNET_MESSAGE_TYPE_CONVERSATION_SC_ERROR:
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Generic error occured.\n"));
	  break;

	default:
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("Got unknown message type.\n"));
	  break;
	}

    }

  GNUNET_CLIENT_receive (h->client, &receive_message_cb, h,
			 GNUNET_TIME_UNIT_FOREVER_REL);
}

/******************************************************************************/
/************************       SEND FUNCTIONS     ****************************/
/******************************************************************************/

/**
 * Function called to send a session initiate message to the service.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the initiate message
 * @return number of bytes written to buf
 */
static size_t
transmit_session_initiate_message (void *cls, size_t size, void *buf)
{
  size_t msg_size;
  struct ClientServerSessionInitiateMessage *msg;
  struct GNUNET_CONVERSATION_Handle *h = (struct GNUNET_CONVERSATION_Handle *) cls;

  msg_size = sizeof (struct ClientServerSessionInitiateMessage);

  GNUNET_assert (size >= msg_size);
  msg = buf;
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_INITIATE);
  memcpy (&msg->peer, &(h->call->peer), sizeof (struct GNUNET_PeerIdentity));

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _
	      ("Sending ClientServerSessionInitiateMessage to the service for peer: %s\n"),
	      GNUNET_i2s_full (&(h->call->peer)));

  h->call->type = CALLER;

  return msg_size;
}

/**
 * Function called to send a session accept message to the service.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the accept message
 * @return number of bytes written to buf
 */
static size_t
transmit_session_accept_message (void *cls, size_t size, void *buf)
{
  size_t msg_size;
  struct ClientServerSessionAcceptMessage *msg;
  struct GNUNET_CONVERSATION_Handle *h = (struct GNUNET_CONVERSATION_Handle *) cls;

  msg_size = sizeof (struct ClientServerSessionAcceptMessage);

  GNUNET_assert (size >= msg_size);
  msg = buf;
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_ACCEPT);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _
	      ("Sending ClienServerSessionAcceptMessage to the service for peer: %s\n"),
	      GNUNET_i2s_full (&(h->call->peer)));

  h->call->established = GNUNET_YES;

  return msg_size;
}

/**
 * Function called to send a session reject message to the service.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the reject message
 * @return number of bytes written to buf
 */
static size_t
transmit_session_reject_message (void *cls, size_t size, void *buf)
{
  size_t msg_size;
  struct ClientServerSessionRejectMessage *msg;
  struct GNUNET_CONVERSATION_Handle *h = (struct GNUNET_CONVERSATION_Handle *) cls;

  msg_size = sizeof (struct ClientServerSessionRejectMessage);

  GNUNET_assert (size >= msg_size);
  msg = buf;
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_REJECT);
  msg->reason = htons (REJECT_REASON_NOT_WANTED);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _
	      ("Sending ClientServerSessionRejectMessage to the service for peer: %s\n"),
	      GNUNET_i2s_full (&(h->call->peer)));

  GNUNET_free (h->call);
  h->call = NULL;

  return msg_size;
}

/**
 * Function called to send a session terminate message to the service.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the terminate message
 * @return number of bytes written to buf
 */
static size_t
transmit_session_terminate_message (void *cls, size_t size, void *buf)
{
  size_t msg_size;
  struct ClientServerSessionTerminateMessage *msg;
  struct GNUNET_CONVERSATION_Handle *h = (struct GNUNET_CONVERSATION_Handle *) cls;

  msg_size = sizeof (struct ClientServerSessionTerminateMessage);

  GNUNET_assert (size >= msg_size);
  msg = buf;
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_TERMINATE);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _
	      ("Sending ClientServerSessionTerminateMessage to the service for peer: %s\n"),
	      GNUNET_i2s_full (&(h->call->peer)));

  GNUNET_free (h->call);
  h->call = NULL;

  return msg_size;
}

/**
 * Auxiliary function to call a peer.
 * 
 * @param h conversation handle
 * @return 
 */
static void
initiate_call (struct GNUNET_CONVERSATION_Handle *h, struct GNUNET_PeerIdentity peer)
{
  h->call =
    (struct GNUNET_CONVERSATION_CallInformation *)
    GNUNET_malloc (sizeof (struct GNUNET_CONVERSATION_CallInformation));
  memcpy (&(h->call->peer), &peer, sizeof (struct GNUNET_PeerIdentity));

  GNUNET_CLIENT_notify_transmit_ready (h->client,
				       sizeof (struct
					       ClientServerSessionInitiateMessage),
				       MAX_TRANSMIT_DELAY, GNUNET_YES,
				       &transmit_session_initiate_message, h);

  return;
}

/**
 * Auxiliary function to accept a call.
 * 
 * @param h conversation handle
 */
static void
accept_call (struct GNUNET_CONVERSATION_Handle *h)
{
  GNUNET_CLIENT_notify_transmit_ready (h->client,
				       sizeof (struct
					       ClientServerSessionAcceptMessage),
				       MAX_TRANSMIT_DELAY, GNUNET_YES,
				       &transmit_session_accept_message, h);
}

/**
 * Auxiliary function to reject a call.
 * 
 * @param h conversation handle
 */
static void
reject_call (struct GNUNET_CONVERSATION_Handle *h)
{
  GNUNET_CLIENT_notify_transmit_ready (h->client,
				       sizeof (struct
					       ClientServerSessionRejectMessage),
				       MAX_TRANSMIT_DELAY, GNUNET_YES,
				       &transmit_session_reject_message, h);
}

/**
 * Auxiliary function to terminate a call.
 * 
 * @param h conversation handle
 */
static void
terminate_call (struct GNUNET_CONVERSATION_Handle *h)
{
  GNUNET_CLIENT_notify_transmit_ready (h->client,
				       sizeof (struct
					       ClientServerSessionTerminateMessage),
				       MAX_TRANSMIT_DELAY, GNUNET_YES,
				       &transmit_session_terminate_message,
				       h);
}

/**
*
*/
static void
gns_call_cb (void *cls, uint32_t rd_count,
	     const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GNUNET_CONVERSATION_Handle *handle = cls;
  struct GNUNET_PeerIdentity peer;
  unsigned int i;

  for (i=0;i<rd_count;i++)
  {
    switch (rd[i].record_type)
    {
    case GNUNET_DNSPARSER_TYPE_TXT: /* FIXME:  use fresh record type for voide... */
      if (GNUNET_OK !=
	  GNUNET_CRYPTO_ecc_public_sign_key_from_string (rd[i].data,
							 rd[i].data_size,
							 &peer.public_key))
      {
	GNUNET_break_op (0);
	continue;
      }      
      initiate_call (handle, peer);
      return;
    default:
      break;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      "Lookup failed\n");
  handle->notification_handler (NULL, handle, 
				NotificationType_NO_PEER,
				NULL);
}


/**
* GNS lookup
*/
static void
gns_lookup_and_call (struct GNUNET_CONVERSATION_Handle *h, const char *callee)
{
  char domain[GNUNET_DNSPARSER_MAX_NAME_LENGTH];
  char *pos;

  pos = domain;
  strcpy (pos, "conversation");
  pos += strlen ("conversation");
  strcpy (pos, ".");
  pos++;
  strcpy (pos, callee);
  pos += strlen (callee);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Lookup for %s\n", domain);

  GNUNET_GNS_lookup (h->gns,
		     domain,
		     NULL /* FIXME: ZONE! */,
		     GNUNET_DNSPARSER_TYPE_TXT,
		     GNUNET_NO, 
		     NULL,
		     &gns_call_cb, h);
}


/******************************************************************************/
/**********************      API CALL DEFINITIONS     *************************/
/******************************************************************************/

struct GNUNET_CONVERSATION_Handle *
GNUNET_CONVERSATION_connect (const struct GNUNET_CONFIGURATION_Handle *cfg, void *cls,
		     GNUNET_CONVERSATION_CallHandler * call_handler,
		     GNUNET_CONVERSATION_RejectHandler * reject_handler,
		     GNUNET_CONVERSATION_NotificationHandler * notification_handler,
		     GNUNET_CONVERSATION_MissedCallHandler * missed_call_handler)
{
  struct GNUNET_CONVERSATION_Handle *h;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "GNUNET_CONVERSATION_connect()\n");
  h = GNUNET_malloc (sizeof (struct GNUNET_CONVERSATION_Handle));

  h->cfg = cfg;
  h->call_handler = call_handler;
  h->reject_handler = reject_handler;
  h->notification_handler = notification_handler;
  h->missed_call_handler = missed_call_handler;

  if (NULL == (h->client = GNUNET_CLIENT_connect ("conversation", cfg)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not access CONVERSATION service\n");
      GNUNET_break (0);
      GNUNET_free (h);

      return NULL;
    }

  if (NULL == (h->gns = GNUNET_GNS_connect (cfg)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not access GNS service\n");
      GNUNET_break (0);
      GNUNET_CLIENT_disconnect (h->client);
      GNUNET_free (h);

      return NULL;
    }

  if (NULL == (h->namestore = GNUNET_NAMESTORE_connect (cfg)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Could not access NAMESTORE service\n");
      GNUNET_break (0);
      GNUNET_CLIENT_disconnect (h->client);
      GNUNET_GNS_disconnect (h->gns);
      GNUNET_free (h);

      return NULL;
    }

  check_gns (h);
  GNUNET_CLIENT_receive (h->client, &receive_message_cb, h,
			 GNUNET_TIME_UNIT_FOREVER_REL);

  return h;
}

void
GNUNET_CONVERSATION_disconnect (struct GNUNET_CONVERSATION_Handle *handle)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "CONVERSATION DISCONNECT\n");

  GNUNET_CLIENT_disconnect (handle->client);
  GNUNET_GNS_disconnect (handle->gns);

  GNUNET_free (handle);
  handle = NULL;
}


void
GNUNET_CONVERSATION_call (struct GNUNET_CONVERSATION_Handle *h, 
			  const char *callee,
			  int doGnsLookup)
{
  struct GNUNET_PeerIdentity peer;

  if (NULL == h || NULL == h->client)
    return;

  if (GNUNET_YES == doGnsLookup)
  {
    gns_lookup_and_call (h, callee);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecc_public_sign_key_from_string (callee, 
						     strlen (callee),
						     &peer.public_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("`%s'  is not a valid public key\n"),
		callee);
    h->notification_handler (NULL, h, NotificationType_NO_PEER, NULL);
    return;
  }  
  initiate_call (h, peer);
}

void
GNUNET_CONVERSATION_hangup (struct GNUNET_CONVERSATION_Handle *h)
{
  if (NULL == h || NULL == h->client)
    return;

  terminate_call (h);
}

void
GNUNET_CONVERSATION_accept (struct GNUNET_CONVERSATION_Handle *h)
{
  if (NULL == h || NULL == h->client)
    return;

  accept_call (h);
}

void
GNUNET_CONVERSATION_reject (struct GNUNET_CONVERSATION_Handle *h)
{
  if (NULL == h || NULL == h->client)
    return;

  reject_call (h);
}

/* end of conversation_api.c */
