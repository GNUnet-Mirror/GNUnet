/*
     This file is part of GNUnet.
     (C) 

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file include/gnunet_protocols_conversation.h
 * @brief constants for network protocols
 * @author Siomon Dieterle
 * @author Andreas Fuchs
 */

#ifndef GNUNET_PROTOCOLS_CONVERSATION_H
#define GNUNET_PROTOCOLS_CONVERSATION_H

#ifdef __cplusplus
extern "C"
{
#if 0				/* keep Emacsens' auto-indent happy */
}
#endif
#endif


/************************************************************************************************************************
* Messages for the Client <-> Server communication
*/

/**
* Client <-> Server message to initiate a new call
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_INITIATE 30002
struct ClientServerSessionInitiateMessage
{
  struct GNUNET_MessageHeader header;
  struct GNUNET_PeerIdentity peer;
};

/**
* Client <-> Server meessage to accept an incoming call
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_ACCEPT 30003
struct ClientServerSessionAcceptMessage
{
  struct GNUNET_MessageHeader header;
};

/**
* Client <-> Server message to reject an incoming call
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_REJECT 30004
struct ClientServerSessionRejectMessage
{
  struct GNUNET_MessageHeader header;
  int reason;
};

/**
* Client <-> Server message to terminat a call
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_TERMINATE 30005
struct ClientServerSessionTerminateMessage
{
  struct GNUNET_MessageHeader header;
};

/**
* Client <-> Server message to initiate a new call
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CS_TEST 30099
struct ClientServerTestMessage
{
  struct GNUNET_MessageHeader header;
  struct GNUNET_PeerIdentity peer;
};

/************************************************************************************************************************
* Messages for the Server <-> Client communication
*/

/**
* Server <-> Client message to initiate a new call
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_INITIATE 30006
struct ServerClientSessionInitiateMessage
{
  struct GNUNET_MessageHeader header;
  struct GNUNET_PeerIdentity peer;
};

/**
* Server <-> Client meessage to accept an incoming call
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_ACCEPT 30007
struct ServerClientSessionAcceptMessage
{
  struct GNUNET_MessageHeader header;
};

/**
* Server <-> Client message to reject an incoming call
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_REJECT 30008
struct ServerClientSessionRejectMessage
{
  struct GNUNET_MessageHeader header;
  int reason;
  int notify;
};

/**
* Server <-> Client message to terminat a call
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_TERMINATE 30009
struct ServerClientSessionTerminateMessage
{
  struct GNUNET_MessageHeader header;
};

/**
* Server <-> Client message to signalize the client that the service is already in use
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SERVICE_BLOCKED 30010
struct ServerClientServiceBlockedMessage
{
  struct GNUNET_MessageHeader header;
};

/**
* Server <-> Client message to signalize the client that the called peer is not connected
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_SC_PEER_NOT_CONNECTED 30011
struct ServerClientPeerNotConnectedMessage
{
  struct GNUNET_MessageHeader header;
};

/**
* Server <-> Client message to signalize the client that called peer does not answer
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_SC_NO_ANSWER 30012
struct ServerClientNoAnswerMessage
{
  struct GNUNET_MessageHeader header;
};

/**
* Server <-> Client message to notify client of missed call
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_SC_MISSED_CALL 30013
struct ServerClientMissedCallMessage
{
  struct GNUNET_MessageHeader header;
  int number;
  struct MissedCall *missed_call;
};

/**
* Server <-> Client message to signalize the client that there occured an error
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_SC_ERROR 30014
struct ServerClientErrorMessage
{
  struct GNUNET_MessageHeader header;
};

/**
* Server <-> Client message to notify client of peer being available
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_SC_PEER_AVAILABLE 30015
struct ServerClientPeerAvailableMessage
{
  struct GNUNET_MessageHeader header;
  struct GNUNET_PeerIdentity peer;
  struct GNUNET_TIME_Absolute time;
};

/************************************************************************************************************************
* Messages for the Mesh communication
*/

struct VoIPMeshMessageHeader
{
  struct GNUNET_MessageHeader header;
  int SequenceNumber;
  struct GNUNET_TIME_Absolute time;
};

/**
* Mesh message to sinal the remote peer the wish to initiate a new call
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_INITIATE 40000
struct MeshSessionInitiateMessage
{
  struct GNUNET_MessageHeader header;
  int SequenceNumber;
  struct GNUNET_TIME_Absolute time;
  struct GNUNET_PeerIdentity peer;
};

/**
* Mesh message to signal the remote peer the acceptance of an initiated call
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_ACCEPT 40001
struct MeshSessionAcceptMessage
{
  struct GNUNET_MessageHeader header;
  int SequenceNumber;
  struct GNUNET_TIME_Absolute time;
};

/**
* Mesh message to reject an a wish to initiate a new call
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_REJECT 40002
struct MeshSessionRejectMessage
{
  struct GNUNET_MessageHeader header;
  int SequenceNumber;
  struct GNUNET_TIME_Absolute time;
  int reason;
  int notify;
};

/**
* Mesh message to signal a remote peer the terminatation of a call
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_TERMINATE 40003
struct MeshSessionTerminateMessage
{
  struct GNUNET_MessageHeader header;
  int SequenceNumber;
  struct GNUNET_TIME_Absolute time;
};

/**
* Server <-> Client message to notify client of peer being available
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_PEER_AVAILABLE 40004
struct MeshPeerAvailableMessage
{
  struct GNUNET_MessageHeader header;
  int SequenceNumber;
  struct GNUNET_TIME_Absolute time;
  struct GNUNET_PeerIdentity peer;
  struct GNUNET_TIME_Absolute call;
};

/************************************************************************************************************************
* Messages for the audio communication
*/


#define GNUNET_MESSAGE_TYPE_CONVERSATION_TEST 50001
struct TestMessage
{
  struct GNUNET_MessageHeader header;
};

/**
* Message to transmit the audio
*/
#define GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO 50000
struct AudioMessage
{
  struct GNUNET_MessageHeader header;
  int SequenceNumber;
  struct GNUNET_TIME_Absolute time;
  int length;
  int encrypted;
  uint8_t audio[200];

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
