/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2018 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/
/**
 * @file ats/gnunet-service-ats-new.c
 * @brief ats service
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_ats_plugin_new.h"
#include "ats2.h"


/**
 * What type of client is this client?
 */
enum ClientType {
  /**
   * We don't know yet.
   */
  CT_NONE = 0,

  /**
   * Transport service.
   */
  CT_TRANSPORT,

  /**
   * Application.
   */
  CT_APPLICATION
};


/**
 * Information we track per client.
 */
struct Client;

/**
 * Preferences expressed by a client are kept in a DLL per client.
 */
struct ClientPreference
{
  /**
   * DLL pointer.
   */
  struct ClientPreference *next;

  /**
   * DLL pointer.
   */
  struct ClientPreference *prev;

  /**
   * Which client expressed the preference?
   */
  struct Client *client;

  /**
   * Plugin's representation of the preference.
   */
  struct GNUNET_ATS_PreferenceHandle *ph;

  /**
   * Details about the preference.
   */
  struct GNUNET_ATS_Preference pref;
};


/**
 * Information about ongoing sessions of the transport client.
 */
struct GNUNET_ATS_Session
{

  /**
   * Session data exposed to the plugin.
   */
  struct GNUNET_ATS_SessionData data;

  /**
   * The transport client that provided the session.
   */
  struct Client *client;

  /**
   * Session state in the plugin.
   */
  struct GNUNET_ATS_SessionHandle *sh;

  /**
   * Unique ID for the session when talking with the client.
   */
  uint32_t session_id;

};


/**
 * Information we track per client.
 */
struct Client
{
  /**
   * Type of the client, initially #CT_NONE.
   */
  enum ClientType type;

  /**
   * Service handle of the client.
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Message queue to talk to the client.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Details depending on @e type.
   */
  union {

    struct {

      /**
       * Head of DLL of preferences expressed by this client.
       */
      struct ClientPreference *cp_head;

      /**
       * Tail of DLL of preferences expressed by this client.
       */
      struct ClientPreference *cp_tail;

    } application;

    struct {

      /**
       * Map from session IDs to `struct GNUNET_ATS_Session` objects.
       */
      struct GNUNET_CONTAINER_MultiHashMap32 *sessions;

    } transport;

  } details;

};


/**
 * Handle for statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Our solver.
 */
static struct GNUNET_ATS_SolverFunctions *plugin;

/**
 * Solver plugin name as string
 */
static char *plugin_name;

/**
 * The transport client (there can only be one at a time).
 */
static struct Client *transport_client;


/**
 * Function called by the solver to prompt the transport to
 * try out a new address.
 *
 * @param cls closure, NULL
 * @param pid peer this is about
 * @param address address the transport should try
 */
static void
suggest_cb (void *cls,
	    const struct GNUNET_PeerIdentity *pid,
	    const char *address)
{
  struct GNUNET_MQ_Envelope *env;
  size_t slen = strlen (address) + 1;
  struct AddressSuggestionMessage *as;

  if (NULL == transport_client)
  {
    // FIXME: stats!
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Suggesting address `%s' of peer `%s'\n",
              address,
              GNUNET_i2s (pid));
  env = GNUNET_MQ_msg_extra (as,
			     slen,
			     GNUNET_MESSAGE_TYPE_ATS_ADDRESS_SUGGESTION);
  as->peer = *pid;
  memcpy (&as[1],
	  address,
	  slen);
  GNUNET_MQ_send (transport_client->mq,
		  env);
}


/**
 * Function called by the solver to tell the transpor to
 * allocate bandwidth for the specified session.
 *
 * @param cls closure, NULL
 * @param session session this is about
 * @param peer peer this is about
 * @param bw_in suggested bandwidth for receiving
 * @param bw_out suggested bandwidth for transmission
 */
static void
allocate_cb (void *cls,
	     struct GNUNET_ATS_Session *session,
	     const struct GNUNET_PeerIdentity *peer,
	     struct GNUNET_BANDWIDTH_Value32NBO bw_in,
	     struct GNUNET_BANDWIDTH_Value32NBO bw_out)
{
  struct GNUNET_MQ_Envelope *env;
  struct SessionAllocationMessage *sam;

  (void) cls;
  if ( (NULL == transport_client) ||
       (session->client != transport_client) )
  {
    /* transport must have just died and solver is addressing the
       losses of sessions (possibly of previous transport), ignore! */
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Allocating %u/%u bytes for %p of peer `%s'\n",
              ntohl (bw_in.value__),
              ntohl (bw_out.value__),
              session,
              GNUNET_i2s (peer));
  env = GNUNET_MQ_msg (sam,
		       GNUNET_MESSAGE_TYPE_ATS_SESSION_ALLOCATION);
  sam->session_id = session->session_id;
  sam->peer = *peer;
  sam->bandwidth_in = bw_in;
  sam->bandwidth_out = bw_out;
  GNUNET_MQ_send (transport_client->mq,
		  env);
}


/**
 * Convert @a properties to @a prop
 *
 * @param properties in NBO
 * @param prop[out] in HBO
 */
static void
prop_ntoh (const struct PropertiesNBO *properties,
	   struct GNUNET_ATS_Properties *prop)
{
  prop->delay = GNUNET_TIME_relative_ntoh (properties->delay);
  prop->goodput_out = ntohl (properties->goodput_out);
  prop->goodput_in = ntohl (properties->goodput_in);
  prop->utilization_out = ntohl (properties->utilization_out);
  prop->utilization_in = ntohl (properties->utilization_in);
  prop->distance = ntohl (properties->distance);
  prop->mtu = ntohl (properties->mtu);
  prop->nt = (enum GNUNET_NetworkType) ntohl (properties->nt);
  prop->cc = (enum GNUNET_TRANSPORT_CommunicatorCharacteristics) ntohl (properties->cc);
}


/**
 * We have received a `struct ExpressPreferenceMessage` from an application client.
 *
 * @param cls handle to the client
 * @param msg the start message
 */
static void
handle_suggest (void *cls,
                const struct ExpressPreferenceMessage *msg)
{
  struct Client *c = cls;
  struct ClientPreference *cp;

  if (CT_NONE == c->type)
    c->type = CT_APPLICATION;
  if (CT_APPLICATION != c->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client suggested we talk to %s with preference %d at rate %u\n",
              GNUNET_i2s (&msg->peer),
              (int) ntohl (msg->pk),
              (int) ntohl (msg->bw.value__));
  cp = GNUNET_new (struct ClientPreference);
  cp->client = c;
  cp->pref.peer = msg->peer;
  cp->pref.bw = msg->bw;
  cp->pref.pk = (enum GNUNET_MQ_PreferenceKind) ntohl (msg->pk);
  cp->ph = plugin->preference_add (plugin->cls,
				   &cp->pref);
  GNUNET_CONTAINER_DLL_insert (c->details.application.cp_head,
			       c->details.application.cp_tail,
			       cp);
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * We have received a `struct ExpressPreferenceMessage` from an application client.
 *
 * @param cls handle to the client
 * @param msg the start message
 */
static void
handle_suggest_cancel (void *cls,
                       const struct ExpressPreferenceMessage *msg)
{
  struct Client *c = cls;
  struct ClientPreference *cp;

  if (CT_NONE == c->type)
    c->type = CT_APPLICATION;
  if (CT_APPLICATION != c->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  for (cp = c->details.application.cp_head;
       NULL != cp;
       cp = cp->next)
    if ( (cp->pref.pk == (enum GNUNET_MQ_PreferenceKind) ntohl (msg->pk)) &&
	 (cp->pref.bw.value__ == msg->bw.value__) &&
	 (0 == memcmp (&cp->pref.peer,
		       &msg->peer,
		       sizeof (struct GNUNET_PeerIdentity))) )
      break;
  if (NULL == cp)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  plugin->preference_del (plugin->cls,
			  cp->ph,
			  &cp->pref);
  GNUNET_CONTAINER_DLL_remove (c->details.application.cp_head,
			       c->details.application.cp_tail,
			       cp);
  GNUNET_free (cp);
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * Handle 'start' messages from transport clients.
 *
 * @param cls client that sent the request
 * @param message the request message
 */
static void
handle_start (void *cls,
	      const struct GNUNET_MessageHeader *hdr)
{
  struct Client *c = cls;

  if (CT_NONE != c->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  c->type = CT_TRANSPORT;
  c->details.transport.sessions
    = GNUNET_CONTAINER_multihashmap32_create (128);
  if (NULL != transport_client)
  {
    GNUNET_SERVICE_client_drop (transport_client->client);
    transport_client = NULL;
  }
  transport_client = c;
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * Check 'session_add' message is well-formed and comes from a
 * transport client.
 *
 * @param cls client that sent the request
 * @param message the request message
 * @return #GNUNET_OK if @a message is well-formed
 */
static int
check_session_add (void *cls,
		   const struct SessionAddMessage *message)
{
  struct Client *c = cls;

  GNUNET_MQ_check_zero_termination (message);
  if (CT_TRANSPORT != c->type)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle 'session add' messages from transport clients.
 *
 * @param cls client that sent the request
 * @param message the request message
 */
static void
handle_session_add (void *cls,
		    const struct SessionAddMessage *message)
{
  struct Client *c = cls;
  const char *address = (const char *) &message[1];
  struct GNUNET_ATS_Session *session;
  int inbound_only = (GNUNET_MESSAGE_TYPE_ATS_SESSION_ADD_INBOUND_ONLY ==
		      ntohs (message->header.type));

  session = GNUNET_CONTAINER_multihashmap32_get (c->details.transport.sessions,
						 message->session_id);
  if (NULL != session)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  session = GNUNET_new (struct GNUNET_ATS_Session);
  session->data.session = session;
  session->client = c;
  session->session_id = message->session_id;
  session->data.peer = message->peer;
  prop_ntoh (&message->properties,
	     &session->data.prop);
  session->data.inbound_only = inbound_only;
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap32_put (c->details.transport.sessions,
						      message->session_id,
						      session,
						      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  session->sh = plugin->session_add (plugin->cls,
				     &session->data,
				     address);
  GNUNET_assert (NULL != session->sh);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transport has new session %p to %s\n",
              session,
              GNUNET_i2s (&message->peer));
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * Handle 'session update' messages from transport clients.
 *
 * @param cls client that sent the request
 * @param msg the request message
 */
static void
handle_session_update (void *cls,
		       const struct SessionUpdateMessage *msg)
{
  struct Client *c = cls;
  struct GNUNET_ATS_Session *session;

  if (CT_TRANSPORT != c->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  session = GNUNET_CONTAINER_multihashmap32_get (c->details.transport.sessions,
						 msg->session_id);
  if (NULL == session)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  prop_ntoh (&msg->properties,
	     &session->data.prop);
  plugin->session_update (plugin->cls,
			  session->sh,
			  &session->data);
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * Handle 'session delete' messages from transport clients.
 *
 * @param cls client that sent the request
 * @param message the request message
 */
static void
handle_session_del (void *cls,
		    const struct SessionDelMessage *message)
{
  struct Client *c = cls;
  struct GNUNET_ATS_Session *session;

  if (CT_TRANSPORT != c->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  session = GNUNET_CONTAINER_multihashmap32_get (c->details.transport.sessions,
						 message->session_id);
  if (NULL == session)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  GNUNET_assert (NULL != session->sh);
  plugin->session_del (plugin->cls,
		       session->sh,
		       &session->data);
  session->sh = NULL;
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap32_remove (c->details.transport.sessions,
							 session->session_id,
							 session));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transport lost session %p to %s\n",
              session,
              GNUNET_i2s (&session->data.peer));
  GNUNET_free (session);
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * A client connected to us. Setup the local client
 * record.
 *
 * @param cls unused
 * @param client handle of the client
 * @param mq message queue to talk to @a client
 * @return @a client
 */
static void *
client_connect_cb (void *cls,
		   struct GNUNET_SERVICE_Client *client,
		   struct GNUNET_MQ_Handle *mq)
{
  struct Client *c = GNUNET_new (struct Client);

  c->client = client;
  c->mq = mq;
  return c;
}


/**
 * Function called on each session to release associated state
 * on transport disconnect.
 *
 * @param cls the `struct Client`
 * @param key unused (session_id)
 * @param value a `struct GNUNET_ATS_Session`
 */
static int
free_session (void *cls,
	      uint32_t key,
	      void *value)
{
  struct Client *c = cls;
  struct GNUNET_ATS_Session *session = value;

  (void) key;
  GNUNET_assert (c == session->client);
  GNUNET_assert (NULL != session->sh);
  plugin->session_del (plugin->cls,
		       session->sh,
		       &session->data);
  session->sh = NULL;
  GNUNET_free (session);
  return GNUNET_OK;
}


/**
 * A client disconnected from us.  Tear down the local client
 * record.
 *
 * @param cls unused
 * @param client handle of the client
 * @param app_ctx our `struct Client`
 */
static void
client_disconnect_cb (void *cls,
		      struct GNUNET_SERVICE_Client *client,
		      void *app_ctx)
{
  struct Client *c = app_ctx;

  (void) cls;
  GNUNET_assert (c->client == client);
  switch (c->type)
  {
  case CT_NONE:
    break;
  case CT_APPLICATION:
    for (struct ClientPreference *cp = c->details.application.cp_head;
	 NULL != cp;
	 cp = c->details.application.cp_head)
    {
      plugin->preference_del (plugin->cls,
			      cp->ph,
			      &cp->pref);
      GNUNET_CONTAINER_DLL_remove (c->details.application.cp_head,
				   c->details.application.cp_tail,
				   cp);
      GNUNET_free (cp);
    }
    break;
  case CT_TRANSPORT:
    if (transport_client == c)
      transport_client = NULL;
    GNUNET_CONTAINER_multihashmap32_iterate (c->details.transport.sessions,
					     &free_session,
					     c);
    GNUNET_CONTAINER_multihashmap32_destroy (c->details.transport.sessions);
    break;
  }
  GNUNET_free (c);
}


/**
 * Task run at the end during shutdown.
 *
 * @param cls unused
 */
static void
final_cleanup (void *cls)
{
  (void) cls;
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats,
			       GNUNET_NO);
    stats = NULL;
  }
  if (NULL != plugin)
  {
    GNUNET_PLUGIN_unload (plugin_name,
			  plugin);
    plugin = NULL;
  }
  if (NULL != plugin_name)
  {
    GNUNET_free (plugin_name);
    plugin_name = NULL;
  }
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
cleanup_task (void *cls)
{
  (void) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "ATS shutdown initiated\n");
  GNUNET_SCHEDULER_add_now (&final_cleanup,
                            NULL);
}


/**
 * Process template requests.
 *
 * @param cls closure
 * @param cfg configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_SERVICE_Handle *service)
{
  static struct GNUNET_ATS_PluginEnvironment env;
  char *solver;

  stats = GNUNET_STATISTICS_create ("ats",
				    cfg);
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "ats",
                                             "SOLVER",
                                             &solver))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "No ATS solver configured, using 'simple' approach\n");
    solver = GNUNET_strdup ("simple");
  }
  GNUNET_SCHEDULER_add_shutdown (&cleanup_task,
				 NULL);
  env.cls = NULL;
  env.cfg = cfg;
  env.stats = stats;
  env.suggest_cb = &suggest_cb;
  env.allocate_cb = &allocate_cb;
  GNUNET_asprintf (&plugin_name,
                   "libgnunet_plugin_ats2_%s",
                   solver);
  GNUNET_free (solver);
  if (NULL == (plugin = GNUNET_PLUGIN_load (plugin_name,
					    &env)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to initialize solver `%s'!\n"),
                plugin_name);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("ats",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_fixed_size (suggest,
                          GNUNET_MESSAGE_TYPE_ATS_SUGGEST,
                          struct ExpressPreferenceMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (suggest_cancel,
                          GNUNET_MESSAGE_TYPE_ATS_SUGGEST_CANCEL,
                          struct ExpressPreferenceMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (start,
			  GNUNET_MESSAGE_TYPE_ATS_START,
			  struct GNUNET_MessageHeader,
			  NULL),
 GNUNET_MQ_hd_var_size (session_add,
			GNUNET_MESSAGE_TYPE_ATS_SESSION_ADD,
			struct SessionAddMessage,
			NULL),
 GNUNET_MQ_hd_var_size (session_add,
			GNUNET_MESSAGE_TYPE_ATS_SESSION_ADD_INBOUND_ONLY,
			struct SessionAddMessage,
			NULL),
 GNUNET_MQ_hd_fixed_size (session_update,
			  GNUNET_MESSAGE_TYPE_ATS_SESSION_UPDATE,
			  struct SessionUpdateMessage,
			  NULL),
 GNUNET_MQ_hd_fixed_size (session_del,
			  GNUNET_MESSAGE_TYPE_ATS_SESSION_DEL,
			  struct SessionDelMessage,
			  NULL),
 GNUNET_MQ_handler_end ());


/* end of gnunet-service-ats.c */
