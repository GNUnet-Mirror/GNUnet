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
 * @file transport/plugin_transport_wlan.c
 * @brief template for a new transport service
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "plugin_transport.h"

#define PROTOCOL_PREFIX "wlan"

#define DEBUG_wlan GNUNET_NO

/**
 * After how long do we expire an address that we
 * learned from another peer if it is not reconfirmed
 * by anyone?
 */
#define LEARNED_ADDRESS_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 6)


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin;


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
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;

  /**
   * The client (used to identify this connection)
   */
  /* void *client; */

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

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * At what time did we reset last_received last?
   */
  struct GNUNET_TIME_Absolute last_quota_update;

  /**
   * How many bytes have we received since the "last_quota_update"
   * timestamp?
   */
  uint64_t last_received;

  /**
   * Number of bytes per ms that this peer is allowed
   * to send to us.
   */
  uint32_t quota;

};

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
   * TODO?
   */
  struct Session *sessions;

  /**
   * encapsulation to the local wlan server prog
   */

  struct GNUNET_SERVER_MessageStreamTokenizer * consoltoken;

  /**
   * encapsulation of the data
   */

  struct GNUNET_SERVER_MessageStreamTokenizer * datatoken;

  /**
   * stdout pipe handle for the gnunet-wlan-helper process
   */
  struct GNUNET_DISK_PipeHandle *server_stdout;

  /**
   * stdout file handle for the gnunet-wlan-helper process
   */
  const struct GNUNET_DISK_FileHandle *server_stdout_handle;

  /**
   * stdin pipe handle for the gnunet-wlan-helper process
   */
  struct GNUNET_DISK_PipeHandle *server_stdin;

  /**
   * stdin file handle for the gnunet-wlan-helper process
   */
  const struct GNUNET_DISK_FileHandle *server_stdin_handle;

  /**
   * ID of select gnunet-nat-server std read task
   */
  GNUNET_SCHEDULER_TaskIdentifier server_read_task;

  /**
   * The process id of the server process (if behind NAT)
   */
  pid_t server_pid;

  /**
   * The interface of the wlan card given to us by the user.
   */
  char *interface;

  /**
   * The mac_address of the wlan card given to us by the helper.
   */
  char *mac_address;

};

struct Plugin* plugin;

/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.
 *
 * @param cls closure
 * @param target who should receive this message
 * @param priority how important is the message
 * @param msgbuf the message to transmit
 * @param msgbuf_size number of bytes in 'msgbuf'
 * @param timeout when should we time out 
 * @param session which session must be used (or NULL for "any")
 * @param addr the address to use (can be NULL if the plugin
 *                is "on its own" (i.e. re-use existing TCP connection))
 * @param addrlen length of the address in bytes
 * @param force_address GNUNET_YES if the plugin MUST use the given address,
 *                otherwise the plugin may use other addresses or
 *                existing connections (if available)
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
static ssize_t
wlan_plugin_send (void *cls,
                      const struct GNUNET_PeerIdentity *
                      target,
                      const char *msgbuf,
                      size_t msgbuf_size,
                      unsigned int priority,
                      struct GNUNET_TIME_Relative timeout,
		      struct Session *session,
                      const void *addr,
                      size_t addrlen,
                      int force_address,
                      GNUNET_TRANSPORT_TransmitContinuation
                      cont, void *cont_cls)
{
  int bytes_sent = 0;
  /*  struct Plugin *plugin = cls; */
  return bytes_sent;
}



/**
 * Function that can be used to force the plugin to disconnect
 * from the given peer and cancel all previous transmissions
 * (and their continuationc).
 *
 * @param cls closure
 * @param target peer from which to disconnect
 */
static void
wlan_plugin_disconnect (void *cls,
                            const struct GNUNET_PeerIdentity *target)
{
  // struct Plugin *plugin = cls;
  // FIXME
}


/**
 * Convert the transports address to a nice, human-readable
 * format.
 *
 * @param cls closure
 * @param type name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 * @param numeric should (IP) addresses be displayed in numeric form?
 * @param timeout after how long should we give up?
 * @param asc function to call on each string
 * @param asc_cls closure for asc
 */
static void
wlan_plugin_address_pretty_printer (void *cls,
				    const char *type,
				    const void *addr,
				    size_t addrlen,
				    int numeric,
				    struct GNUNET_TIME_Relative timeout,
				    GNUNET_TRANSPORT_AddressStringCallback
				    asc, void *asc_cls)
{
  char ret[92];
  const unsigned char * input;
  
  GNUNET_assert(cls !=NULL);
  if (addrlen != 6)
    {
      /* invalid address (MAC addresses have 6 bytes) */
      GNUNET_break (0);
      asc (asc_cls, NULL);
      return;
    }
  input = (const unsigned char*) addr;
  GNUNET_snprintf (ret, 
		   sizeof (ret),
		   "%s Mac-Adress %X:%X:%X:%X:%X:%X",
		   PROTOCOL_PREFIX, 
		   input[0], input[1], input[2], input[3], input[4], input[5]);  
  asc (asc_cls, ret);
}



/**
 * Another peer has suggested an address for this
 * peer and transport plugin.  Check that this could be a valid
 * address.  If so, consider adding it to the list
 * of addresses.
 *
 * @param cls closure
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport
 */
static int
wlan_plugin_address_suggested (void *cls,
				   const void *addr,
				   size_t addrlen)
{
  /* struct Plugin *plugin = cls; */

  /* check if the address is plausible; if so,
     add it to our list! */

  GNUNET_assert(cls !=NULL);

  //Mac Adress has 6 bytes
  if (addrlen == 6){
    /* TODO check for bad addresses like milticast, broadcast, etc */
    return GNUNET_OK;
  } else {
    return GNUNET_SYSERR;
  }

}


/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the 
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param cls closure
 * @param addr binary address
 * @param addrlen length of the address
 * @return string representing the same address 
 */
static const char* 
wlan_plugin_address_to_string (void *cls,
			       const void *addr,
			       size_t addrlen)
{
  char ret[92];
  const unsigned char * input;
  
  GNUNET_assert(cls !=NULL);
  if (addrlen != 6)
    {
      /* invalid address (MAC addresses have 6 bytes) */
      GNUNET_break (0);
      return NULL;
    }
  input = (const unsigned char*) addr;
  GNUNET_snprintf (ret, 
		   sizeof (ret),
		   "%s Mac-Adress %X:%X:%X:%X:%X:%X",
		   PROTOCOL_PREFIX, 
		   input[0], input[1], input[2], input[3], input[4], input[5]);  
  return GNUNET_strdup (ret);
}


#if 0
/**
 * Function for used to process the data from the suid process
 */
static void
wlan_process_helper (void *cls,
                      void *client_identity,
                      struct GNUNET_MessageHeader *hdr)
{
  if (hdr->type == GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA){
    //TODO DATA
  } else if (hdr->type == GNUNET_MESSAGE_TYPE_WLAN_HELPER_ADVERTISEMENT){
    //TODO ADV
  } else if (hdr->type == GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL){
    //TODO Control
    if (hdr->size == 6){
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Notifying transport of address %s\n", wlan_plugin_address_to_string(cls, plugin->mac_address, hdr->size));
      plugin->env->notify_address (plugin->env->cls,
                                      "wlan",
                                      &plugin->mac_address, sizeof(plugin->mac_address), GNUNET_TIME_UNIT_FOREVER_REL);
    } else {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Wrong wlan mac address %s\n", plugin->mac_address);
    }


  } else {
    // TODO Wrong data?
  }
}


static void
wlan_plugin_helper_read (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  char mybuf[3000]; //max size of packet from helper
  ssize_t bytes;
  //memset(&mybuf, 0, sizeof(mybuf)); //?

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  bytes = GNUNET_DISK_file_read(plugin->server_stdout_handle, &mybuf, sizeof(mybuf));

  if (bytes < 1)
    {
#if DEBUG_TCP_NAT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Finished reading from wlan-helper stdout with code: %d\n"), bytes);
#endif
      return;
    }

  plugin->server_read_task =
  GNUNET_SCHEDULER_add_read_file (plugin->env->sched,
                                  GNUNET_TIME_UNIT_FOREVER_REL,
                                  plugin->server_stdout_handle, &wlan_plugin_helper_read, plugin);

}


/**
 * Start the gnunet-wlan-helper process for users behind NAT.
 *
 * @param plugin the transport plugin
 *
 * @return GNUNET_YES if process was started, GNUNET_SYSERR on error
 */
static int
wlan_transport_start_wlan_helper(struct Plugin *plugin)
{

  plugin->server_stdout = (GNUNET_YES, GNUNET_NO, GNUNET_YES);
  if (plugin->server_stdout == NULL)
    return GNUNET_SYSERR;

  plugin->server_stdin = GNUNET_DISK_pipe(GNUNET_YES, GNUNET_YES, GNUNET_NO);
    if (plugin->server_stdin == NULL)
      return GNUNET_SYSERR;

#if DEBUG_TCP_NAT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                   "Starting gnunet-wlan-helper process cmd: %s %s\n", "gnunet-wlan-helper", plugin->interface);
#endif
  /* Start the server process */
  plugin->server_pid = GNUNET_OS_start_process(plugin->server_stdin, plugin->server_stdout, "gnunet-transport-wlan-helper", "gnunet-transport-wlan-helper", plugin->interface, NULL);
  if (plugin->server_pid == GNUNET_SYSERR)
    {
#if DEBUG_TCP_NAT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                     "Failed to start gnunet-wlan-helper process\n");
#endif
      return GNUNET_SYSERR;
    }
  /* Close the write end of the read pipe */
  GNUNET_DISK_pipe_close_end(plugin->server_stdout, GNUNET_DISK_PIPE_END_WRITE);

  /* Close the read end of the write pipe */
  GNUNET_DISK_pipe_close_end(plugin->server_stdout, GNUNET_DISK_PIPE_END_READ);

  plugin->server_stdout_handle = GNUNET_DISK_pipe_handle(plugin->server_stdout, GNUNET_DISK_PIPE_END_READ);
  plugin->server_stdin_handle = GNUNET_DISK_pipe_handle(plugin->server_stdin, GNUNET_DISK_PIPE_END_WRITE);

  plugin->server_read_task =
  GNUNET_SCHEDULER_add_read_file (plugin->env->sched,
                                  GNUNET_TIME_UNIT_FOREVER_REL,
                                  plugin->server_stdout_handle, &wlan_plugin_helper_read, plugin);
  return GNUNET_YES;
}



#endif


/**
 * Entry point for the plugin.
 */
void *
gnunet_plugin_transport_wlan_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;

  GNUNET_assert(cls !=NULL);

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;


  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &wlan_plugin_send;
  api->disconnect = &wlan_plugin_disconnect;
  api->address_pretty_printer = &wlan_plugin_address_pretty_printer;
  api->check_address = &wlan_plugin_address_suggested;
  api->address_to_string = &wlan_plugin_address_to_string;

  return api;
}


/**
 * Exit point from the plugin.
 */
void *
gnunet_plugin_transport_wlan_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  GNUNET_assert(cls !=NULL);

  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_wlan.c */
