/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file conversation/conversation.h
 * @brief constants for network protocols
 * @author Siomon Dieterle
 * @author Andreas Fuchs
 */
#ifndef CONVERSATION_H
#define CONVERSATION_H

#ifdef __cplusplus
extern "C"
{
#if 0				/* keep Emacsens' auto-indent happy */
}
#endif
#endif


#define MAX_TRANSMIT_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)


/************************************************************************************************************************
* Messages for the Client <-> Server communication
*/


/**
 * VoipClient.
 */
struct VoipClient
{
  /**
   * Handle for a conversation client.
   */
  struct GNUNET_SERVER_Client *client;
};

/**
* The connection status of the service
*/
struct ConnectionStatus
{
	/**
	* The client which is in interaction
	*/
  struct GNUNET_SERVER_Client *client;

	/**
	* The PeerIdentity of the peer
	*/
  struct GNUNET_PeerIdentity peer;

	/**
	* The status (see enum)
	*/
  int status;
};

/**
* Information about a missed call
*/
struct MissedCall
{
	/**
	* The PeerIdentity of the peer
	*/
  struct GNUNET_PeerIdentity peer;

	/**
	* The time the call was
	*/
  struct GNUNET_TIME_Absolute time;

};




/**
 * Client <-> Server message to initiate a new call
 */
struct ClientServerSessionInitiateMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_INITIATE 
   */
  struct GNUNET_MessageHeader header;
  struct GNUNET_PeerIdentity peer;
};


/**
 * Client <-> Server meessage to accept an incoming call
 */
struct ClientServerSessionAcceptMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_ACCEPT 
   */
  struct GNUNET_MessageHeader header;
};


/**
 * Client <-> Server message to reject an incoming call
 */
struct ClientServerSessionRejectMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_REJECT
   */
  struct GNUNET_MessageHeader header;
  int reason;
};


/**
 * Client <-> Server message to terminat a call
 */
struct ClientServerSessionTerminateMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_TERMINATE 
   */
  struct GNUNET_MessageHeader header;
};


/**
 * Client <-> Server message to initiate a new call
 */
struct ClientServerTestMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_TEST 
   */
  struct GNUNET_MessageHeader header;
  struct GNUNET_PeerIdentity peer;
};

/************************************************************************************************************************
* Messages for the Server <-> Client communication
*/

/**
 * Server <-> Client message to initiate a new call
 */
struct ServerClientSessionInitiateMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_INITIATE
   */
  struct GNUNET_MessageHeader header;
  struct GNUNET_PeerIdentity peer;
};


/**
 * Server <-> Client meessage to accept an incoming call
 */
struct ServerClientSessionAcceptMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_ACCEPT 
   */
  struct GNUNET_MessageHeader header;
};


/**
 * Server <-> Client message to reject an incoming call
 */
struct ServerClientSessionRejectMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_REJECT 
   */
  struct GNUNET_MessageHeader header;
  int reason;
  int notify;
};


/**
 * Server <-> Client message to terminat a call
 */
struct ServerClientSessionTerminateMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_TERMINATE 
   */
  struct GNUNET_MessageHeader header;
};


/**
 * Server <-> Client message to signalize the client that the service is already in use
 */
struct ServerClientServiceBlockedMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SERVICE_BLOCKED
   */
  struct GNUNET_MessageHeader header;
};

/**
 * Server <-> Client message to signalize the client that the called peer is not connected
 */
struct ServerClientPeerNotConnectedMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_SC_PEER_NOT_CONNECTED 
   */
  struct GNUNET_MessageHeader header;
};


/**
 * Server <-> Client message to signalize the client that called peer does not answer
 */
struct ServerClientNoAnswerMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_SC_NO_ANSWER
   */
  struct GNUNET_MessageHeader header;
};

/**
 * Server <-> Client message to notify client of missed call
 */
struct ServerClientMissedCallMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_SC_MISSED_CALL 
   */
  struct GNUNET_MessageHeader header;
  int number;
  struct MissedCall *missed_call;
};


/**
 * Server <-> Client message to signalize the client that there occured an error
 */
struct ServerClientErrorMessage
{
  /**
   * Type is: #define GNUNET_MESSAGE_TYPE_CONVERSATION_SC_ERROR 
   */
  struct GNUNET_MessageHeader header;
};


/**
 * Server <-> Client message to notify client of peer being available
 */
struct ServerClientPeerAvailableMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_SC_PEER_AVAILABLE
   */
  struct GNUNET_MessageHeader header;
  struct GNUNET_PeerIdentity peer;
  struct GNUNET_TIME_Absolute time;
};

/************************************************************************************************************************
* Messages for the Mesh communication
*/

struct VoIPMeshMessageHeader
{
  /**
   * Type is: 
   */
  struct GNUNET_MessageHeader header;
  int SequenceNumber;
  struct GNUNET_TIME_Absolute time;
};


/**
 * Mesh message to sinal the remote peer the wish to initiate a new call
 */
struct MeshSessionInitiateMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_INITIATE
   */
  struct GNUNET_MessageHeader header;
  int SequenceNumber;
  struct GNUNET_TIME_Absolute time;
  struct GNUNET_PeerIdentity peer;
};

/**
 * Mesh message to signal the remote peer the acceptance of an initiated call
 */
struct MeshSessionAcceptMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_ACCEPT
   */
  struct GNUNET_MessageHeader header;
  int SequenceNumber;
  struct GNUNET_TIME_Absolute time;
};


/**
 * Mesh message to reject an a wish to initiate a new call
 */
struct MeshSessionRejectMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_REJECT 
   */
  struct GNUNET_MessageHeader header;
  int SequenceNumber;
  struct GNUNET_TIME_Absolute time;
  int reason;
  int notify;
};


/**
 * Mesh message to signal a remote peer the terminatation of a call
 */
struct MeshSessionTerminateMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_TERMINATE 
   */
  struct GNUNET_MessageHeader header;
  int SequenceNumber;
  struct GNUNET_TIME_Absolute time;
};


/**
 * Server <-> Client message to notify client of peer being available
 */
struct MeshPeerAvailableMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_PEER_AVAILABLE 
   */
  struct GNUNET_MessageHeader header;
  int SequenceNumber;
  struct GNUNET_TIME_Absolute time;
  struct GNUNET_PeerIdentity peer;
  struct GNUNET_TIME_Absolute call;
};


/**
 * Messages for the audio communication
 */
struct TestMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_TEST 
   */
  struct GNUNET_MessageHeader header;
};

////////////////////////////////////////////////////////////

/**
 * Message to transmit the audio (between client and helpers).
 */
struct AudioMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO
   */
  struct GNUNET_MessageHeader header;

  /* followed by audio data */

};


/**
 * Client -> Service message to register a phone.
 */
struct ClientPhoneRegisterMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_REGISTER
   */
  struct GNUNET_MessageHeader header;

  /**
   * Phone line to register.
   */
  uint32_t line GNUNET_PACKED;
};


/**
 * Service -> Client message for phone is ringing.
 */
struct ClientPhoneRingMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RING
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Who is calling us?
   */
  struct GNUNET_CRYPTO_EccPublicSignKey caller_id;

};


/**
 * Service -> Client message for phone is busy.
 */
struct ClientPhoneBusyMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_BUSY
   */
  struct GNUNET_MessageHeader header;

};


/**
 * Client -> Service pick up phone that is ringing.
 */
struct ClientPhonePickupMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_PICK_UP
   */
  struct GNUNET_MessageHeader header;
  
  /* followed by variable length 0-terminated string with meta data */

};


/**
 * Client <-> Service hang up phone that may or may not be ringing.
 * Also sent in response to a (failed) `struct ClientCallMessage`.
 */
struct ClientPhoneHangupMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_HANG_UP
   */
  struct GNUNET_MessageHeader header;
  
  /* followed by variable length 0-terminated string with meta data */

};


/**
 * Message Client <->Service to transmit the audio.
 */
struct ClientAudioMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_AUDIO
   */
  struct GNUNET_MessageHeader header;

  /* followed by audio data */

};


/**
 * Client -> Service message to call a phone.
 */
struct ClientCallMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_CALL
   */
  struct GNUNET_MessageHeader header;

  /**
   * Which phone line to call at the peer?
   */
  uint32_t line GNUNET_PACKED;

  /**
   * Which peer is hosting the line?
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Identity of the caller.
   */
  struct GNUNET_CRYPTO_EccPrivateKey caller_id;
};


/**
 * Service -> Client: other peer has picked up the phone, we are
 * now talking.
 */
struct ClientPhonePickedupMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_PICKED_UP
   */
  struct GNUNET_MessageHeader header;
  
  /* followed by variable length 0-terminated string with meta data */

};


/**
 * Mesh message for phone is ringing.
 */
struct MeshPhoneRingMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_PHONE_RING
   */
  struct GNUNET_MessageHeader header;

  /**
   * Desired target line.
   */
  uint32_t line GNUNET_PACKED;

  /**
   * Purpose for the signature.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Who is calling us? (also who is signing).
   */
  struct GNUNET_CRYPTO_EccPublicSignKey caller_id;

  /**
   * Who are we calling?
   */
  struct GNUNET_PeerIdentity target;

  /**
   * From where are we calling?
   */
  struct GNUNET_PeerIdentity source;

  /**
   * When does the signature expire?
   */ 
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * Signature on the above.
   */
  struct GNUNET_CRYPTO_EccSignature signature;

};


/**
 * Mesh message for hanging up.
 */
struct MeshPhoneHangupMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_PHONE_HANG_UP
   */
  struct GNUNET_MessageHeader header;

  /* followed by variable-size 0-terminated reason string */
};


/**
 * Mesh message for picking up.
 */
struct MeshPhonePickupMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_PHONE_PICK_UP
   */
  struct GNUNET_MessageHeader header;

  /* followed by variable-size 0-terminated metadata string */
};


/**
 * Mesh message for phone busy.
 */
struct MeshPhoneBusyMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_PHONE_BUSY
   */
  struct GNUNET_MessageHeader header;

  /* followed by variable-size 0-terminated metadata string??? */
};


/**
 * Mesh message to transmit the audio.
 */
struct MeshAudioMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_AUDIO
   */
  struct GNUNET_MessageHeader header;

  /* followed by audio data */

};



#if 0				/* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PROTOCOLS_CONVERSATION_H */
#endif
/* end of gnunet_protocols_conversation.h */
