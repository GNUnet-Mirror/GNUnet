/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file dht/gnunet_dht_service.c
 * @brief main DHT service shell, building block for DHT implementations
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_signal_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_datastore_service.h"
#include "dht.h"

/**
 * Handle to the datastore service (for inserting/retrieving data)
 */
static struct GNUNET_DATASTORE_Handle *datastore;

/**
 * The main scheduler to use for the DHT service
 */
static struct GNUNET_SCHEDULER_Handle *sched;

/**
 * The configuration the DHT service is running with
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Timeout for transmissions to clients
 */
static struct GNUNET_TIME_Relative client_transmit_timeout;

/**
 * Handle to the core service
 */
static struct GNUNET_CORE_Handle *coreAPI;

/**
 * The identity of our peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Task to run when we shut down, cleaning up all our trash
 */
static GNUNET_SCHEDULER_TaskIdentifier cleanup_task;

struct ClientList
{
  /**
   * This is a linked list
   */
  struct ClientList *next;

  /**
   * The client in question
   */
  struct GNUNET_SERVER_Client *client;
};

/**
 * Server handler for handling locally received dht requests
 */
static void
handle_dht_start_message(void *cls, struct GNUNET_SERVER_Client * client,
                         const struct GNUNET_MessageHeader *message);

static void
handle_dht_stop_message(void *cls, struct GNUNET_SERVER_Client * client,
                         const struct GNUNET_MessageHeader *message);

static struct GNUNET_SERVER_MessageHandler plugin_handlers[] = {
  {&handle_dht_start_message, NULL, GNUNET_MESSAGE_TYPE_DHT, 0},
  {&handle_dht_stop_message, NULL, GNUNET_MESSAGE_TYPE_DHT_STOP, 0},
/*  {&handle_dht_get_stop, NULL, GNUNET_MESSAGE_TYPE_DHT_GET_STOP, 0},
  {&handle_dht_put, NULL, GNUNET_MESSAGE_TYPE_DHT_PUT, 0},
  {&handle_dht_find_peer, NULL, GNUNET_MESSAGE_TYPE_DHT_FIND_PEER, 0},
  {&handle_dht_find_peer_stop, NULL, GNUNET_MESSAGE_TYPE_DHT_FIND_PEER_STOP, 0},*/
  {NULL, NULL, 0, 0}
};


/**
 * Core handler for p2p dht get requests.
 */
static int handle_dht_p2p_get (void *cls,
                             const struct GNUNET_PeerIdentity * peer,
                             const struct GNUNET_MessageHeader * message,
                             struct GNUNET_TIME_Relative latency,
                             uint32_t distance);

/**
 * Core handler for p2p dht put requests.
 */
static int handle_dht_p2p_put (void *cls,
                             const struct GNUNET_PeerIdentity * peer,
                             const struct GNUNET_MessageHeader * message,
                             struct GNUNET_TIME_Relative latency,
                             uint32_t distance);

/**
 * Core handler for p2p dht find peer requests.
 */
static int handle_dht_p2p_find_peer (void *cls,
                             const struct GNUNET_PeerIdentity * peer,
                             const struct GNUNET_MessageHeader * message,
                             struct GNUNET_TIME_Relative latency,
                             uint32_t distance);

static struct GNUNET_CORE_MessageHandler core_handlers[] = {
  {&handle_dht_p2p_get, GNUNET_MESSAGE_TYPE_DHT_GET, 0},
  {&handle_dht_p2p_put, GNUNET_MESSAGE_TYPE_DHT_PUT, 0},
  {&handle_dht_p2p_find_peer, GNUNET_MESSAGE_TYPE_DHT_PUT, 0},
  {NULL, 0, 0}
};



/**
 * Server handler for initiating local dht get requests
 */
static void handle_dht_get (void *cls, struct GNUNET_DHT_GetMessage *get_msg, GNUNET_HashCode *key)
{
  GNUNET_HashCode get_key;
  size_t get_type;

  GNUNET_assert(ntohs(get_msg->header.size) >= sizeof(struct GNUNET_DHT_GetMessage));
  get_type = ntohs(get_msg->type);

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from client, message type %d, key %s\n", "DHT", "GET", get_type, GNUNET_h2s(&get_key));
#endif

  /* FIXME: Implement get functionality here */
}


/**
 * Server handler for initiating local dht find peer requests
 */
static void handle_dht_find_peer (void *cls, struct GNUNET_DHT_FindPeerMessage *find_msg, GNUNET_HashCode *key)
{

  GNUNET_assert(ntohs(find_msg->header.size) == sizeof(struct GNUNET_DHT_FindPeerMessage));

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from client, key %s\n", "DHT", "FIND PEER", GNUNET_h2s(key));
#endif

  /* FIXME: Implement find peer functionality here */
}


/**
 * Server handler for initiating local dht put requests
 */
static void handle_dht_put (void *cls, struct GNUNET_DHT_PutMessage *put_msg, GNUNET_HashCode *key)
{
  size_t put_type;
  size_t data_size;
  char *data;

  GNUNET_assert(ntohs(put_msg->header.size) >= sizeof(struct GNUNET_DHT_PutMessage));

  put_type = ntohs(put_msg->type);
  data_size = ntohs(put_msg->data_size);
  GNUNET_assert(ntohs(put_msg->header.size) == sizeof(struct GNUNET_DHT_PutMessage) + data_size);
  data = GNUNET_malloc(data_size);
  memcpy(data, &put_msg[1], data_size);

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from client, message type %d, key %s\n", "DHT", "PUT", put_type, GNUNET_h2s(key));
#endif

  /**
   * FIXME: Implement dht put request functionality here!
   */

  GNUNET_free(data);
}

/**
 * Context for sending receipt confirmations. Not used yet.
 */
struct SendConfirmationContext
{
  /**
   * The message to send.
   */
  struct GNUNET_DHT_StopMessage *message;

  /**
   * Transmit handle.
   */
  struct GNUNET_CONNECTION_TransmitHandle * transmit_handle;
};

size_t send_confirmation (void *cls,
                          size_t size, void *buf)
{
  struct GNUNET_DHT_StopMessage *confirmation_message = cls;

  if (buf == NULL) /* Message timed out, that's crappy... */
  {
    GNUNET_free(confirmation_message);
    return 0;
  }

  if (size >= ntohs(confirmation_message->header.size))
  {
    memcpy(buf, confirmation_message, ntohs(confirmation_message->header.size));
    return ntohs(confirmation_message->header.size);
  }
  else
    return 0;
}

static void
send_client_receipt_confirmation(struct GNUNET_SERVER_Client *client, uint64_t uid)
{
  struct GNUNET_DHT_StopMessage *confirm_message;

  confirm_message = GNUNET_malloc(sizeof(struct GNUNET_DHT_StopMessage));
  confirm_message->header.type = htons(GNUNET_MESSAGE_TYPE_DHT_STOP);
  confirm_message->header.size = htons(sizeof(struct GNUNET_DHT_StopMessage));
  confirm_message->unique_id = GNUNET_htonll(uid);

  GNUNET_SERVER_notify_transmit_ready (client,
                                       sizeof(struct GNUNET_DHT_StopMessage),
                                       GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5),
                                       &send_confirmation, confirm_message);

}

static void
handle_dht_start_message(void *cls, struct GNUNET_SERVER_Client * client,
                         const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_DHT_Message *dht_msg = (struct GNUNET_DHT_Message *)message;
  struct GNUNET_MessageHeader *enc_msg;
  size_t enc_type;

  enc_msg = (struct GNUNET_MessageHeader *)&dht_msg[1];
  enc_type = ntohs(enc_msg->type);


#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from client, message type %d, key %s, uid %llu\n", "DHT", "GENERIC", enc_type, GNUNET_h2s(&dht_msg->key), GNUNET_ntohll(dht_msg->unique_id));
#endif

  /* FIXME: Implement demultiplexing functionality here */
  switch (enc_type)
    {
    case GNUNET_MESSAGE_TYPE_DHT_GET:
      handle_dht_get(cls, (struct GNUNET_DHT_GetMessage *)enc_msg, &dht_msg->key);
      break;
    case GNUNET_MESSAGE_TYPE_DHT_PUT:
      handle_dht_put(cls, (struct GNUNET_DHT_PutMessage *)enc_msg, &dht_msg->key);
      break;
    case GNUNET_MESSAGE_TYPE_DHT_FIND_PEER:
      handle_dht_find_peer(cls, (struct GNUNET_DHT_FindPeerMessage *)enc_msg, &dht_msg->key);
      break;
    default:
#if DEBUG_DHT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "`%s': Message type (%d) not handled\n", "DHT", enc_type);
#endif
    }

  GNUNET_SERVER_receive_done(client, GNUNET_OK);

}


static void
handle_dht_stop_message(void *cls, struct GNUNET_SERVER_Client * client,
                        const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_DHT_StopMessage * dht_stop_msg = (struct GNUNET_DHT_StopMessage *)message;

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from client, uid %llu\n", "DHT", "GENERIC STOP", GNUNET_ntohll(dht_stop_msg->unique_id));
#endif
  send_client_receipt_confirmation(client, GNUNET_ntohll(dht_stop_msg->unique_id));
  GNUNET_SERVER_receive_done(client, GNUNET_OK);
}


/**
 * Core handler for p2p dht get requests.
 */
static int handle_dht_p2p_get (void *cls,
                               const struct GNUNET_PeerIdentity * peer,
                               const struct GNUNET_MessageHeader * message,
                               struct GNUNET_TIME_Relative latency,
                               uint32_t distance)
{
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from another peer\n", "DHT", "GET");
#endif

  return GNUNET_YES;
}

/**
 * Core handler for p2p dht put requests.
 */
static int handle_dht_p2p_put (void *cls,
                             const struct GNUNET_PeerIdentity * peer,
                             const struct GNUNET_MessageHeader * message,
                             struct GNUNET_TIME_Relative latency,
                             uint32_t distance)
{
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from another peer\n", "DHT", "PUT");
#endif

  return GNUNET_YES;
}

/**
 * Core handler for p2p dht find peer requests.
 */
static int handle_dht_p2p_find_peer (void *cls,
                             const struct GNUNET_PeerIdentity * peer,
                             const struct GNUNET_MessageHeader * message,
                             struct GNUNET_TIME_Relative latency,
                             uint32_t distance)
{
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from another peer\n", "DHT", "FIND PEER");
#endif

  return GNUNET_YES;
}

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_CORE_disconnect (coreAPI);
}

/**
 * To be called on core init/fail.
 */
void core_init (void *cls,
                struct GNUNET_CORE_Handle * server,
                const struct GNUNET_PeerIdentity *identity,
                const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded * publicKey)
{

  if (server == NULL)
    {
      GNUNET_SCHEDULER_cancel(sched, cleanup_task);
      GNUNET_SCHEDULER_add_now(sched, &shutdown_task, NULL);
      return;
    }
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Core connection initialized, I am peer: %s\n", "dht", GNUNET_i2s(identity));
#endif
  memcpy(&my_identity, identity, sizeof(struct GNUNET_PeerIdentity));
  coreAPI = server;
}

/**
 * Process dht requests.
 *
 * @param cls closure
 * @param scheduler scheduler to use
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *scheduler,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  sched = scheduler;
  cfg = c;

  datastore = GNUNET_DATASTORE_connect(c, scheduler);

  client_transmit_timeout = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5);
  GNUNET_SERVER_add_handlers (server, plugin_handlers);

  coreAPI =
  GNUNET_CORE_connect (sched, /* Main scheduler */
                       cfg,   /* Main configuration */
                       client_transmit_timeout, /* Delay for connecting */
                       NULL, /* FIXME: anything we want to pass around? */
                       &core_init, /* Call core_init once connected */
                       NULL, /* Don't care about pre-connects */
                       NULL, /* Don't care about connects */
                       NULL, /* Don't care about disconnects */
                       NULL, /* Don't want notified about all incoming messages */
                       GNUNET_NO, /* For header only inbound notification */
                       NULL, /* Don't want notified about all outbound messages */
                       GNUNET_NO, /* For header only outbound notification */
                       core_handlers); /* Register these handlers */

  if (coreAPI == NULL)
    return;

  /* Scheduled the task to clean up when shutdown is called */
  cleanup_task = GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task,
                                NULL);
}


/**
 * The main function for the dv service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                              argv,
                              "dht",
                              GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}
