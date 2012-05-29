/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_http.h
 * @brief http transport service plugin
 * @author Matthias Wachs
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_connection_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_resolver_service.h"
#include "gnunet_server_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_transport_plugin.h"
#include "gnunet_os_lib.h"
#include "gnunet_nat_lib.h"
#include "microhttpd.h"
#include <curl/curl.h>


#define DEBUG_HTTP GNUNET_EXTRA_LOGGING
#define VERBOSE_SERVER GNUNET_EXTRA_LOGGING
#define VERBOSE_CLIENT GNUNET_EXTRA_LOGGING
#define VERBOSE_CURL GNUNET_NO

#if BUILD_HTTPS
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_https_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_https_done
#else
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_http_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_http_done
#endif

#define INBOUND  GNUNET_YES
#define OUTBOUND GNUNET_NO


#define HTTP_NOT_VALIDATED_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin
{
  /**
   * General handles
   * ---------------
   */

  /**
   * Our environment.
   */
  struct GNUNET_TRANSPORT_PluginEnvironment *env;

  /**
   * Linked list of open sessions.
   */

  struct Session *head;

  struct Session *tail;

  /**
   * NAT handle & address management
   */
  struct GNUNET_NAT_Handle *nat;

  /**
   * List of own addresses
   */

  /**
   * IPv4 addresses DLL head
   */
  struct IPv4HttpAddressWrapper *ipv4_addr_head;

  /**
   * IPv4 addresses DLL tail
   */
  struct IPv4HttpAddressWrapper *ipv4_addr_tail;

  /**
   * IPv6 addresses DLL head
   */
  struct IPv6HttpAddressWrapper *ipv6_addr_head;

  /**
   * IPv6 addresses DLL tail
   */
  struct IPv6HttpAddressWrapper *ipv6_addr_tail;

  /**
   * Plugin configuration
   * --------------------
   */

  /**
   * Plugin name
   * Equals configuration section: transport-http, transport-https
   */
  char *name;

  /**
   * Plugin protocol
   * http, https
   */
  char *protocol;

  /**
   * Use IPv4?
   * GNUNET_YES or GNUNET_NO
   */
  int ipv4;

  /**
   * Use IPv6?
   * GNUNET_YES or GNUNET_NO
   */
  int ipv6;

  /**
   * Does plugin just use outbound connections and not accept inbound?
   */

  int client_only;

  /**
   * Port used
   */
  uint16_t port;

  /**
   * Maximum number of sockets the plugin can use
   * Each http inbound /outbound connections are two connections
   */
  int max_connections;

  /**
   * Number of outbound sessions
   */
  unsigned int outbound_sessions;

  /**
   * Number of inbound sessions
   */
  unsigned int inbound_sessions;

  /**
   * Plugin HTTPS SSL/TLS options
   * ----------------------------
   */

  /**
   * libCurl TLS crypto init string, can be set to enhance performance
   *
   * Example:
   *
   * Use RC4-128 instead of AES:
   * NONE:+VERS-TLS1.0:+ARCFOUR-128:+SHA1:+RSA:+COMP-NULL
   *
   */
  char *crypto_init;

  /**
   * TLS key
   */
  char *key;

  /**
   * TLS certificate
   */
  char *cert;

  /**
   * Plugin values
   * -------------
   */

  /**
   * Current number of establishes connections
   */
  int cur_connections;

  /**
   * Last used unique HTTP connection tag
   */
  uint32_t last_tag;

  /**
   * Server handles
   * --------------
   */

  /**
   * MHD IPv4 daemon
   */
  struct MHD_Daemon *server_v4;

  /**
   * MHD IPv4 task
   */
  GNUNET_SCHEDULER_TaskIdentifier server_v4_task;

  /**
   * The IPv4 server is scheduled to run asap
   */
  int server_v4_immediately;

  /**
   * MHD IPv6 daemon
   */
  struct MHD_Daemon *server_v6;

  /**
   * MHD IPv4 task
   */
  GNUNET_SCHEDULER_TaskIdentifier server_v6_task;

  /**
   * The IPv6 server is scheduled to run asap
   */

  int server_v6_immediately;

  /**
   * IPv4 server socket to bind to
   */
  struct sockaddr_in *server_addr_v4;

  /**
   * IPv6 server socket to bind to
   */
  struct sockaddr_in6 *server_addr_v6;

  /**
   * Server semi connections
   * A full session consists of 2 semi-connections: send and receive
   * If not both directions are established the server keeps this sessions here
   */
  struct Session *server_semi_head;

  struct Session *server_semi_tail;

  /*
   * Client handles
   */

  /**
   * cURL Multihandle
   */
  CURLM *client_mh;

  /**
   * curl perform task
   */
  GNUNET_SCHEDULER_TaskIdentifier client_perform_task;

};

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * IPv4 addresses
 */
struct IPv4HttpAddress
{
  /**
   * IPv4 address, in network byte order.
   */
  uint32_t ipv4_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t u4_port GNUNET_PACKED;
};

/**
 * IPv4 addresses
 */
struct IPv6HttpAddress
{
  /**
   * IPv6 address.
   */
  struct in6_addr ipv6_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t u6_port GNUNET_PACKED;
};
GNUNET_NETWORK_STRUCT_END


struct ServerConnection
{
  /* _RECV or _SEND */
  int direction;

  /* Should this connection get disconnected? GNUNET_YES/NO  */
  int disconnect;

  /* The session this server connection belongs to */
  struct Session *session;

  /* The MHD connection */
  struct MHD_Connection *mhd_conn;
};



/**
 * Session handle for connections.
 */
struct Session
{

  /**
   * Stored in a linked list.
   */
  struct Session *next;

  /**
   * Stored in a linked list.
   */
  struct Session *prev;

  /**
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;

  /**
   * Address
   */
  void *addr;

  /**
   * Address length
   */
  size_t addrlen;

  /**
   * ATS network type in NBO
   */
  uint32_t ats_address_network_type;

  /**
   * To whom are we talking to
   */
  struct GNUNET_PeerIdentity target;

  /**
   * next pointer for double linked list
   */
  struct HTTP_Message *msg_head;

  /**
   * previous pointer for double linked list
   */
  struct HTTP_Message *msg_tail;


  /**
   * Message stream tokenizer for incoming data
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *msg_tk;

  /**
   * Absolute time when to receive data again
   * Used for receive throttling
   */
  struct GNUNET_TIME_Absolute next_receive;

  /**
   * Inbound or outbound connection
   * Outbound: GNUNET_NO (client is used to send and receive)
   * Inbound : GNUNET_YES (server is used to send and receive)
   */
  int inbound;

  /**
   * Unique HTTP/S connection tag for this connection
   */
  uint32_t tag;

  /**
   * Client handles
   */

  /**
   * Client send handle
   */
  void *client_put;

  /**
   * Client receive handle
   */
  void *client_get;

  /**
   * Task to wake up client receive handle when receiving is allowed again
   */
  GNUNET_SCHEDULER_TaskIdentifier recv_wakeup_task;

  /**
   * Session timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Is client send handle paused since there are no data to send?
   * GNUNET_YES/NO
   */
  int client_put_paused;

  /**
   * Server handles
   */

  /**
   * Client send handle
   */
  struct ServerConnection *server_recv;

  /**
   * Client send handle
   */
  struct ServerConnection *server_send;
};

/**
 *  Message to send using http
 */
struct HTTP_Message
{
  /**
   * next pointer for double linked list
   */
  struct HTTP_Message *next;

  /**
   * previous pointer for double linked list
   */
  struct HTTP_Message *prev;

  /**
   * buffer containing data to send
   */
  char *buf;

  /**
   * amount of data already sent
   */
  size_t pos;

  /**
   * buffer length
   */
  size_t size;

  /**
   * Continuation function to call once the transmission buffer
   * has again space available.  NULL if there is no
   * continuation to call.
   */
  GNUNET_TRANSPORT_TransmitContinuation transmit_cont;

  /**
   * Closure for transmit_cont.
   */
  void *transmit_cont_cls;
};

struct Session *
create_session (struct Plugin *plugin, const struct GNUNET_PeerIdentity *target,
                const void *addr, size_t addrlen);

int
exist_session (struct Plugin *plugin, struct Session *s);

void
delete_session (struct Session *s);

int
exist_session (struct Plugin *plugin, struct Session *s);

struct GNUNET_TIME_Relative
http_plugin_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_MessageHeader *message,
                     struct Session *session, const char *sender_address,
                     uint16_t sender_address_len);

const char *
http_plugin_address_to_string (void *cls, const void *addr, size_t addrlen);

int
client_disconnect (struct Session *s);

int
client_connect (struct Session *s);

int
client_send (struct Session *s, struct HTTP_Message *msg);

int
client_start (struct Plugin *plugin);

void
client_stop (struct Plugin *plugin);

int
server_disconnect (struct Session *s);

int
server_send (struct Session *s, struct HTTP_Message *msg);

int
server_start (struct Plugin *plugin);

void
server_stop (struct Plugin *plugin);

void
notify_session_end (void *cls, const struct GNUNET_PeerIdentity *peer,
                    struct Session *s);

/* end of plugin_transport_http.h */
