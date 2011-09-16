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


#define DEBUG_HTTP GNUNET_YES
#define VERBOSE_SERVER GNUNET_YES
#define VERBOSE_CLIENT GNUNET_YES
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


#define HTTP_NOT_VALIDATED_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)

/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin
{
  /**
   * Our environment.
   */
  struct GNUNET_TRANSPORT_PluginEnvironment *env;

  /**
   * List of open sessions.
   */
  struct Session *head;

  struct Session *tail;

  /**
   * NAT handle & address management
   */
  struct GNUNET_NAT_Handle *nat;


  /**
   * ipv4 DLL head
   */
  struct IPv4HttpAddressWrapper *ipv4_addr_head;

  /**
   * ipv4 DLL tail
   */
  struct IPv4HttpAddressWrapper *ipv4_addr_tail;

  /**
   * ipv6 DLL head
   */
  struct IPv6HttpAddressWrapper *ipv6_addr_head;

  /**
   * ipv6 DLL tail
   */
  struct IPv6HttpAddressWrapper *ipv6_addr_tail;


  /* Plugin configuration */

  char *name;

  char *protocol;

  int ipv4;

  int ipv6;

  uint16_t port;

  int max_connections;



  /* Plugin values */


  int cur_connections;
  uint32_t last_tag;
  /*
   * Server handles
   */

  struct MHD_Daemon *server_v4;
  GNUNET_SCHEDULER_TaskIdentifier server_v4_task;

  struct MHD_Daemon *server_v6;
  GNUNET_SCHEDULER_TaskIdentifier server_v6_task;

  char *crypto_init;
  char *key;
  char *cert;

  struct Session *server_semi_head;

  struct Session *server_semi_tail;



  /*
   * Client handles
   */

  /**
   * cURL Multihandle
   */
  CURLM *client_mh;

  GNUNET_SCHEDULER_TaskIdentifier client_perform_task;

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
   * next pointer for double linked list
   */
  struct HTTP_Message *msg_head;

  /**
   * previous pointer for double linked list
   */
  struct HTTP_Message *msg_tail;


  /**
   * message stream tokenizer for incoming data
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *msg_tk;

  /**
   * Continuation function to call once the transmission buffer
   * has again space available.  NULL if there is no
   * continuation to call.
   */
  GNUNET_TRANSPORT_TransmitContinuation transmit_cont;


  void *addr;

  size_t addrlen;

  /**
   * Closure for transmit_cont.
   */
  void *transmit_cont_cls;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity target;

  /**
   * At what time did we reset last_received last?
   */
  //struct GNUNET_TIME_Absolute last_quota_update;

  /**
   * How many bytes have we received since the "last_quota_update"
   * timestamp?
   */
  //uint64_t last_received;

  /**
   * Number of bytes per ms that this peer is allowed
   * to send to us.
   */
  //uint32_t quota;


  int inbound;

  void *client_put;
  void *client_get;
  int put_paused;

  void *server_recv;
  void *server_send;
  struct GNUNET_TIME_Absolute delay;
  GNUNET_SCHEDULER_TaskIdentifier reset_task;
  uint32_t tag;

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

void
delete_session (struct Session *s);

struct Session *
create_session (struct Plugin *plugin, const struct GNUNET_PeerIdentity *target,
                const void *addr, size_t addrlen,
                GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls);

struct GNUNET_TIME_Relative
http_plugin_receive (void *cls, const struct GNUNET_PeerIdentity * peer,
    const struct  GNUNET_MessageHeader * message,
    struct Session * session,
    const char *sender_address,
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
server_send (struct Session *s, struct HTTP_Message * msg);

int
server_start (struct Plugin *plugin);

void
server_stop (struct Plugin *plugin);

void
notify_session_end (void *cls,
                    const struct GNUNET_PeerIdentity *
                    peer, struct Session * s);

/* end of plugin_transport_http.h */
