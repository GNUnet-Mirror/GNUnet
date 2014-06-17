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
 * @file conversation/gnunet-conversation.c
 * @brief conversation implementation
 * @author Simon Dieterle
 * @author Andreas Fuchs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_conversation_service.h"
#include "gnunet_namestore_service.h"
#ifdef WINDOWS
#include "../util/gnunet-helper-w32-console.h"
#endif

/**
 * Maximum length allowed for the command line input.
 */
#define MAX_MESSAGE_LENGTH 1024

#define XSTRINGIFY(x) STRINGIFY(x)

#define STRINGIFY(x) (#x)

#ifdef WINDOWS
/**
 * Helper that reads the console for us.
 */
struct GNUNET_HELPER_Handle *stdin_hlp;
#endif

/**
 * Possible states of the phone.
 */
enum PhoneState
{
  /**
   * We're waiting for our own idenitty.
   */
  PS_LOOKUP_EGO,

  /**
   * We're listening for calls
   */
  PS_LISTEN,

  /**
   * We accepted an incoming phone call.
   */
  PS_ACCEPTED,

  /**
   * Internal error
   */
  PS_ERROR
};


/**
 * States for current outgoing call.
 */
enum CallState
{
  /**
   * We are looking up some other participant.
   */
  CS_RESOLVING,

  /**
   * We are now ringing the other participant.
   */
  CS_RINGING,

  /**
   * The other party accepted our call and we are now connected.
   */
  CS_CONNECTED,

  /**
   * The call is currently suspended (by us).
   */
  CS_SUSPENDED

};



/**
 * List of incoming calls
 */
struct CallList
{

  /**
   * A DLL.
   */
  struct CallList *prev;

  /**
   * A DLL.
   */
  struct CallList *next;

  /**
   * Handle to hang up or activate.
   */
  struct GNUNET_CONVERSATION_Caller *caller;

  /**
   * Public key identifying the caller.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey caller_id;

  /**
   * Unique number of the call.
   */
  unsigned int caller_num;

};



/**
 * Phone handle
 */
static struct GNUNET_CONVERSATION_Phone *phone;

/**
 * Call handle (for active outgoing call).
 */
static struct GNUNET_CONVERSATION_Call *call;

/**
 * Caller handle (for active incoming call).
 */
static struct CallList *cl_active;

/**
 * Head of calls waiting to be accepted.
 */
static struct CallList *cl_head;

/**
 * Tail of calls waiting to be accepted.
 */
static struct CallList *cl_tail;

/**
 * Desired phone line.
 */
static unsigned int line;

/**
 * Task which handles the commands
 */
static GNUNET_SCHEDULER_TaskIdentifier handle_cmd_task;

/**
 * Our speaker.
 */
static struct GNUNET_SPEAKER_Handle *speaker;

/**
 * Our microphone.
 */
static struct GNUNET_MICROPHONE_Handle *mic;

/**
 * Our configuration.
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Our ego.
 */
static struct GNUNET_IDENTITY_Ego *my_caller_id;

/**
 * Handle to identity service.
 */
static struct GNUNET_IDENTITY_Handle *id;

/**
 * Name of our ego.
 */
static char *ego_name;

/**
 * Public key of active conversation partner (if any).
 */
static struct GNUNET_CRYPTO_EcdsaPublicKey peer_key;

/**
 * Name of active conversation partner (if any).
 */
static char *peer_name;

/**
 * File handle for stdin.
 */
static struct GNUNET_DISK_FileHandle *stdin_fh;

/**
 * Our phone's current state.
 */
static enum PhoneState phone_state;

/**
 * Our call's current state.
 */
static enum CallState call_state;

/**
 * Counts the number of incoming calls we have had so far.
 */
static unsigned int caller_num_gen;

/**
 * GNS address for this phone.
 */
static char *address;

/**
 * Be verbose.
 */
static int verbose;


/**
 * Function called with an event emitted by a phone.
 *
 * @param cls closure
 * @param code type of the event
 * @param caller handle for the caller
 * @param caller_id public key of the caller (in GNS)
 */
static void
phone_event_handler (void *cls,
                     enum GNUNET_CONVERSATION_PhoneEventCode code,
                     struct GNUNET_CONVERSATION_Caller *caller,
                     const struct GNUNET_CRYPTO_EcdsaPublicKey *caller_id)
{
  struct CallList *cl;

  switch (code)
  {
  case GNUNET_CONVERSATION_EC_PHONE_RING:
    FPRINTF (stdout,
             _("Incoming call from `%s'. Please /accept #%u or /cancel %u the call.\n"),
             GNUNET_GNSRECORD_pkey_to_zkey (caller_id),
             caller_num_gen,
             caller_num_gen);
    cl = GNUNET_new (struct CallList);
    cl->caller = caller;
    cl->caller_id = *caller_id;
    cl->caller_num = caller_num_gen++;
    GNUNET_CONTAINER_DLL_insert (cl_head,
                                 cl_tail,
                                 cl);
    break;
  case GNUNET_CONVERSATION_EC_PHONE_HUNG_UP:
    for (cl = cl_head; NULL != cl; cl = cl->next)
      if (caller == cl->caller)
        break;
    if (NULL == cl)
    {
      GNUNET_break (0);
      return;
    }
    FPRINTF (stdout,
             _("Call from `%s' terminated\n"),
             GNUNET_GNSRECORD_pkey_to_zkey (&cl->caller_id));
    GNUNET_CONTAINER_DLL_remove (cl_head,
                                 cl_tail,
                                 cl);
    if (cl == cl_active)
    {
      cl_active = NULL;
      phone_state = PS_LISTEN;
    }
    GNUNET_free (cl);
    break;
  }
}


/**
 * Function called with an event emitted by a caller.
 *
 * @param cls closure with the `struct CallList` of the caller
 * @param code type of the event issued by the caller
 */
static void
caller_event_handler (void *cls,
                      enum GNUNET_CONVERSATION_CallerEventCode code)
{
  struct CallList *cl = cls;

  switch (code)
  {
  case GNUNET_CONVERSATION_EC_CALLER_SUSPEND:
    FPRINTF (stdout,
             _("Call from `%s' suspended by other user\n"),
             GNUNET_GNSRECORD_pkey_to_zkey (&cl->caller_id));
    break;
  case GNUNET_CONVERSATION_EC_CALLER_RESUME:
    FPRINTF (stdout,
             _("Call from `%s' resumed by other user\n"),
             GNUNET_GNSRECORD_pkey_to_zkey (&cl->caller_id));
    break;
  }
}


/**
 * Start our phone.
 */
static void
start_phone ()
{
  struct GNUNET_GNSRECORD_Data rd;

  if (NULL == my_caller_id)
  {
    FPRINTF (stderr,
             _("Ego `%s' no longer available, phone is now down.\n"),
             ego_name);
    phone_state = PS_LOOKUP_EGO;
    return;
  }
  GNUNET_assert (NULL == phone);
  phone = GNUNET_CONVERSATION_phone_create (cfg,
                                            my_caller_id,
                                            &phone_event_handler, NULL);
  /* FIXME: get record and print full GNS record info later here... */
  if (NULL == phone)
  {
    FPRINTF (stderr,
             "%s",
             _("Failed to setup phone (internal error)\n"));
    phone_state = PS_ERROR;
  }
  else
  {
    GNUNET_CONVERSATION_phone_get_record (phone,
                                          &rd);
    GNUNET_free_non_null (address);
    address = GNUNET_GNSRECORD_value_to_string (rd.record_type,
                                                rd.data,
                                                rd.data_size);
    FPRINTF (stdout,
             _("Phone active on line %u.  Type `/help' for a list of available commands\n"),
             (unsigned int) line);
    phone_state = PS_LISTEN;
  }
}


/**
 * Function called with an event emitted by a call.
 *
 * @param cls closure, NULL
 * @param code type of the event on the call
 */
static void
call_event_handler (void *cls,
                    enum GNUNET_CONVERSATION_CallEventCode code)
{
  switch (code)
  {
  case GNUNET_CONVERSATION_EC_CALL_RINGING:
    GNUNET_break (CS_RESOLVING == call_state);
    FPRINTF (stdout,
             _("Resolved address of `%s'. Now ringing other party.\n"),
             peer_name);
    call_state = CS_RINGING;
    break;
  case GNUNET_CONVERSATION_EC_CALL_PICKED_UP:
    GNUNET_break (CS_RINGING == call_state);
    FPRINTF (stdout,
             _("Connection established to `%s'\n"),
             peer_name);
    call_state = CS_CONNECTED;
    break;
  case GNUNET_CONVERSATION_EC_CALL_GNS_FAIL:
    GNUNET_break (CS_RESOLVING == call_state);
    FPRINTF (stdout,
             _("Failed to resolve `%s'\n"),
             peer_name);
    GNUNET_free (peer_name);
    peer_name = NULL;
    call = NULL;
    break;
  case GNUNET_CONVERSATION_EC_CALL_HUNG_UP:
    FPRINTF (stdout,
             _("Call to `%s' terminated\n"),
             peer_name);
    GNUNET_free (peer_name);
    peer_name = NULL;
    call = NULL;
    break;
  case GNUNET_CONVERSATION_EC_CALL_SUSPENDED:
    GNUNET_break (CS_CONNECTED == call_state);
    FPRINTF (stdout,
             _("Connection to `%s' suspended (by other user)\n"),
             peer_name);
    break;
  case GNUNET_CONVERSATION_EC_CALL_RESUMED:
    GNUNET_break (CS_CONNECTED == call_state);
    FPRINTF (stdout,
             _("Connection to `%s' resumed (by other user)\n"),
             peer_name);
    break;
  case GNUNET_CONVERSATION_EC_CALL_ERROR:
    FPRINTF (stdout,
             _("Error with the call, restarting it\n"));
    call_state = CS_RESOLVING;
    // FIXME: is this correct?
    break;
  }
}


/**
 * Function declareation for executing a action
 *
 * @param arguments arguments given to the function
 */
typedef void (*ActionFunction) (const char *arguments);


/**
 * Structure which defines a command
 */
struct VoipCommand
{
  /**
   * Command the user needs to enter.
   */
  const char *command;

  /**
   * Function to call on command.
   */
  ActionFunction Action;

  /**
   * Help text for the command.
   */
  const char *helptext;
};


/**
 * Action function to print help for the command shell.
 *
 * @param args arguments given to the command
 */
static void
do_help (const char *args);


/**
 * Terminate the client
 *
 * @param args arguments given to the command
 */
static void
do_quit (const char *args)
{
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Handler for unknown command.
 *
 * @param msg arguments given to the command
 */
static void
do_unknown (const char *msg)
{
  FPRINTF (stderr,
	   _("Unknown command `%s'\n"),
	   msg);
}


/**
 * Initiating a new call
 *
 * @param arg arguments given to the command
 */
static void
do_call (const char *arg)
{
  if (NULL == my_caller_id)
  {
    FPRINTF (stderr,
             _("Ego `%s' not available\n"),
             ego_name);
    return;
  }
  if (NULL != call)
  {
    FPRINTF (stderr,
             _("You are calling someone else already, hang up first!\n"));
    return;
  }
  switch (phone_state)
  {
  case PS_LOOKUP_EGO:
    FPRINTF (stderr,
             _("Ego `%s' not available\n"),
             ego_name);
    return;
  case PS_LISTEN:
    /* ok to call! */
    break;
  case PS_ACCEPTED:
    FPRINTF (stderr,
             _("You are answering call from `%s', hang up or suspend that call first!\n"),
             GNUNET_GNSRECORD_pkey_to_zkey (&peer_key));
    return;
  case PS_ERROR:
    /* ok to call */
    break;
  }
  if (NULL == arg)
  {
    FPRINTF (stderr,
             _("Call recipient missing.\n"));
    do_help ("/call");
    return;
  }
  peer_name = GNUNET_strdup (arg);
  call_state = CS_RESOLVING;
  GNUNET_assert (NULL == call);
  call = GNUNET_CONVERSATION_call_start (cfg,
                                         my_caller_id,
                                         my_caller_id,
                                         arg,
                                         speaker,
                                         mic,
                                         &call_event_handler, NULL);
}


/**
 * Accepting an incoming call
 *
 * @param args arguments given to the command
 */
static void
do_accept (const char *args)
{
  struct CallList *cl;
  char buf[32];

  if ( (NULL != call) &&
       (CS_SUSPENDED != call_state) )
  {
    FPRINTF (stderr,
             _("You are calling someone else already, hang up first!\n"));
    return;
  }
  switch (phone_state)
  {
  case PS_LOOKUP_EGO:
    GNUNET_break (0);
    break;
  case PS_LISTEN:
    /* this is the expected state */
    break;
  case PS_ACCEPTED:
    FPRINTF (stderr,
             _("You are answering call from `%s', hang up or suspend that call first!\n"),
             GNUNET_GNSRECORD_pkey_to_zkey (&peer_key));
    return;
  case PS_ERROR:
    GNUNET_break (0);
    break;
  }
  cl = cl_head;
  if (NULL == cl)
  {
    FPRINTF (stderr,
             _("There is no incoming call to accept here!\n"));
    return;
  }
  if ( (NULL != cl->next) || (NULL != args) )
  {
    for (cl = cl_head; NULL != cl; cl = cl->next)
    {
      GNUNET_snprintf (buf, sizeof (buf),
                       "%u",
                       cl->caller_num);
      if (0 == strcmp (buf, args))
        break;
    }
  }
  if (NULL == cl)
  {
    FPRINTF (stderr,
             _("There is no incoming call `%s' to accept right now!\n"),
             args);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (cl_head,
                               cl_tail,
                               cl);
  cl_active = cl;
  peer_key = cl->caller_id;
  phone_state = PS_ACCEPTED;
  GNUNET_CONVERSATION_caller_pick_up (cl->caller,
                                      &caller_event_handler,
                                      cl,
                                      speaker,
                                      mic);
}


/**
 * Print address information for this phone.
 *
 * @param args arguments given to the command
 */
static void
do_address (const char *args)
{
  if (NULL == address)
  {
    FPRINTF (stdout,
             "%s",
             _("We currently do not have an address.\n"));
    return;
  }
  FPRINTF (stdout,
           "%s\n",
           address);
}


/**
 * Accepting an incoming call
 *
 * @param args arguments given to the command
 */
static void
do_status (const char *args)
{
  struct CallList *cl;

  switch (phone_state)
  {
  case PS_LOOKUP_EGO:
    FPRINTF (stdout,
             _("We are currently trying to locate the private key for the ego `%s'.\n"),
             ego_name);
    break;
  case PS_LISTEN:
    FPRINTF (stdout,
             _("We are listening for incoming calls for ego `%s' on line %u.\n"),
             ego_name,
             line);
    break;
  case PS_ACCEPTED:
    FPRINTF (stdout,
             _("You are having a conversation with `%s'.\n"),
             GNUNET_GNSRECORD_pkey_to_zkey (&peer_key));;
    break;
  case PS_ERROR:
    FPRINTF (stdout,
             _("We had an internal error setting up our phone line. You can still make calls.\n"));
    break;
  }
  if (NULL != call)
  {
    switch (call_state)
    {
    case CS_RESOLVING:
      FPRINTF (stdout,
               _("We are trying to find the network address to call `%s'.\n"),
               peer_name);
      break;
    case CS_RINGING:
      FPRINTF (stdout,
               _("We are calling `%s', his phone should be ringing.\n"),
               peer_name);
      break;
    case CS_CONNECTED:
      FPRINTF (stdout,
               _("You are having a conversation with `%s'.\n"),
               peer_name);
      break;
    case CS_SUSPENDED:
      /* ok to accept incoming call right now */
      break;
    }
  }
  if ( (NULL != cl_head) &&
       ( (cl_head != cl_active) ||
         (cl_head != cl_tail) ) )
  {
    FPRINTF (stdout,
             "%s",
             _("Calls waiting:\n"));
    for (cl = cl_head; NULL != cl; cl = cl->next)
    {
      if (cl == cl_active)
        continue;
      FPRINTF (stdout,
               _("#%u: `%s'\n"),
               cl->caller_num,
               GNUNET_GNSRECORD_pkey_to_zkey (&cl->caller_id));
    }
    FPRINTF (stdout,
             "%s",
             "\n");
  }
}


/**
 * Suspending a call
 *
 * @param args arguments given to the command
 */
static void
do_suspend (const char *args)
{
  if (NULL != call)
  {
    switch (call_state)
    {
    case CS_RESOLVING:
    case CS_RINGING:
    case CS_SUSPENDED:
      FPRINTF (stderr,
               "%s",
               _("There is no call that could be suspended right now.\n"));
      return;
    case CS_CONNECTED:
      call_state = CS_SUSPENDED;
      GNUNET_CONVERSATION_call_suspend (call);
      return;
    }
  }
  switch (phone_state)
  {
  case PS_LOOKUP_EGO:
  case PS_LISTEN:
  case PS_ERROR:
    FPRINTF (stderr,
             "%s",
             _("There is no call that could be suspended right now.\n"));
    return;
  case PS_ACCEPTED:
    /* expected state, do rejection logic */
    break;
  }
  GNUNET_assert (NULL != cl_active);
  GNUNET_CONVERSATION_caller_suspend (cl_active->caller);
  cl_active = NULL;
  phone_state = PS_LISTEN;
}


/**
 * Resuming a call
 *
 * @param args arguments given to the command
 */
static void
do_resume (const char *args)
{
  struct CallList *cl;
  char buf[32];

  if (NULL != call)
  {
    switch (call_state)
    {
    case CS_RESOLVING:
    case CS_RINGING:
    case CS_CONNECTED:
      FPRINTF (stderr,
               "%s",
               _("There is no call that could be resumed right now.\n"));
      return;
    case CS_SUSPENDED:
      call_state = CS_CONNECTED;
      GNUNET_CONVERSATION_call_resume (call,
                                       speaker,
                                       mic);
      return;
    }
  }
  switch (phone_state)
  {
  case PS_LOOKUP_EGO:
  case PS_ERROR:
    FPRINTF (stderr,
             "%s",
             _("There is no call that could be resumed right now.\n"));
    return;
  case PS_LISTEN:
    /* expected state, do resume logic */
    break;
  case PS_ACCEPTED:
    FPRINTF (stderr,
             _("Already talking with `%s', cannot resume a call right now.\n"),
             GNUNET_GNSRECORD_pkey_to_zkey (&peer_key));
    return;
  }
  GNUNET_assert (NULL == cl_active);
  cl = cl_head;
  if (NULL == cl)
  {
    FPRINTF (stderr,
             _("There is no incoming call to resume here!\n"));
    return;
  }
  if ( (NULL != cl->next) || (NULL != args) )
  {
    for (cl = cl_head; NULL != cl; cl = cl->next)
    {
      GNUNET_snprintf (buf, sizeof (buf),
                       "%u",
                       cl->caller_num);
      if (0 == strcmp (buf, args))
        break;
    }
  }
  if (NULL == cl)
  {
    FPRINTF (stderr,
             _("There is no incoming call `%s' to resume right now!\n"),
             args);
    return;
  }
  cl_active = cl;
  GNUNET_CONVERSATION_caller_resume (cl_active->caller,
                                     speaker,
                                     mic);
  phone_state = PS_ACCEPTED;
}


/**
 * Rejecting a call
 *
 * @param args arguments given to the command
 */
static void
do_reject (const char *args)
{
  struct CallList *cl;
  char buf[32];

  if (NULL != call)
  {
    GNUNET_CONVERSATION_call_stop (call);
    call = NULL;
    return;
  }
  switch (phone_state)
  {
  case PS_LOOKUP_EGO:
  case PS_ERROR:
    FPRINTF (stderr,
             "%s",
             _("There is no call that could be cancelled right now.\n"));
    return;
  case PS_LISTEN:
    /* look for active incoming calls to refuse */
    cl = cl_head;
    if (NULL == cl)
    {
      FPRINTF (stderr,
               _("There is no incoming call to refuse here!\n"));
      return;
    }
    if ( (NULL != cl->next) || (NULL != args) )
    {
      for (cl = cl_head; NULL != cl; cl = cl->next)
      {
        GNUNET_snprintf (buf, sizeof (buf),
                         "%u",
                         cl->caller_num);
        if (0 == strcmp (buf, args))
          break;
      }
    }
    if (NULL == cl)
    {
      FPRINTF (stderr,
               _("There is no incoming call `%s' to refuse right now!\n"),
               args);
      return;
    }
    GNUNET_CONVERSATION_caller_hang_up (cl->caller);
    GNUNET_CONTAINER_DLL_remove (cl_head,
                                 cl_tail,
                                 cl);
    GNUNET_free (cl);
    break;
  case PS_ACCEPTED:
    /* expected state, do rejection logic */
    GNUNET_assert (NULL != cl_active);
    GNUNET_CONVERSATION_caller_hang_up (cl_active->caller);
    cl_active = NULL;
    phone_state = PS_LISTEN;
    break;
  }
}


/**
 * List of supported commands.
 */
static struct VoipCommand commands[] = {
  {"/address", &do_address,
   gettext_noop ("Use `/address' to find out which address this phone should have in GNS")},
  {"/call", &do_call,
   gettext_noop ("Use `/call USER.gnu' to call USER")},
  {"/accept", &do_accept,
   gettext_noop ("Use `/accept #NUM' to accept incoming call #NUM")},
  {"/suspend", &do_suspend,
   gettext_noop ("Use `/suspend' to suspend the active call")},
  {"/resume", &do_resume,
   gettext_noop ("Use `/resume [#NUM]' to resume a call, #NUM is needed to resume incoming calls, no argument is needed to resume the current outgoing call.")},
  {"/cancel", &do_reject,
   gettext_noop ("Use `/cancel' to reject or terminate a call")},
  {"/status", &do_status,
   gettext_noop ("Use `/status' to print status information")},
  {"/quit", &do_quit,
   gettext_noop ("Use `/quit' to terminate gnunet-conversation")},
  {"/help", &do_help,
   gettext_noop ("Use `/help command' to get help for a specific command")},
  {"", &do_unknown,
   NULL},
  {NULL, NULL, NULL},
};


/**
 * Action function to print help for the command shell.
 *
 * @param args arguments given to the command
 */
static void
do_help (const char *args)
{
  unsigned int i;

  i = 0;
  while ( (NULL != args) &&
          (0 != strlen (args)) &&
          (commands[i].Action != &do_help))
  {
    if (0 ==
	strncasecmp (&args[1], &commands[i].command[1], strlen (args) - 1))
    {
      FPRINTF (stdout,
	       "%s\n",
	       gettext (commands[i].helptext));
      return;
    }
    i++;
  }
  i = 0;
  FPRINTF (stdout,
	   "%s",
	   "Available commands:\n");
  while (commands[i].Action != &do_help)
  {
    FPRINTF (stdout,
	     "%s\n",
	     gettext (commands[i].command));
    i++;
  }
  FPRINTF (stdout,
	   "%s",
	   "\n");
  FPRINTF (stdout,
	   "%s\n",
	   gettext (commands[i].helptext));
}


/**
 * Task run during shutdown.
 *
 * @param cls NULL
 * @param tc unused
 */
static void
do_stop_task (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#ifdef WINDOWS
  if (NULL != stdin_hlp)
  {
    GNUNET_HELPER_stop (stdin_hlp, GNUNET_NO);
    stdin_hlp = NULL;
  }
#endif
  if (NULL != call)
  {
    GNUNET_CONVERSATION_call_stop (call);
    call = NULL;
  }
  if (NULL != phone)
  {
    GNUNET_CONVERSATION_phone_destroy (phone);
    phone = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != handle_cmd_task)
  {
    GNUNET_SCHEDULER_cancel (handle_cmd_task);
    handle_cmd_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != id)
  {
    GNUNET_IDENTITY_disconnect (id);
    id = NULL;
  }
  GNUNET_SPEAKER_destroy (speaker);
  speaker = NULL;
  GNUNET_MICROPHONE_destroy (mic);
  mic = NULL;
  GNUNET_free (ego_name);
  ego_name = NULL;
  GNUNET_free_non_null (peer_name);
  peer_name = NULL;
  phone_state = PS_ERROR;
}


/**
 * Handle user command.
 *
 * @param message command the user typed in
 * @param str_len number of bytes to process in @a message
 */
static void
handle_command_string (char *message,
                       size_t str_len)
{
  size_t i;
  const char *ptr;

  if (0 == str_len)
    return;
  if (message[str_len - 1] == '\n')
    message[str_len - 1] = '\0';
  if (message[str_len - 2] == '\r')
    message[str_len - 2] = '\0';
  if (0 == strlen (message))
    return;
  i = 0;
  while ((NULL != commands[i].command) &&
	 (0 != strncasecmp (commands[i].command, message,
                            strlen (commands[i].command))))
    i++;
  ptr = &message[strlen (commands[i].command)];
  while (isspace ((int) *ptr))
    ptr++;
  if ('\0' == *ptr)
    ptr = NULL;
  commands[i].Action (ptr);
}


#ifdef WINDOWS
static int
console_reader_chars (void *cls,
                      void *client,
                      const struct GNUNET_MessageHeader *message)
{
  char *chars;
  size_t str_size;
  switch (ntohs (message->type))
  {
  case GNUNET_MESSAGE_TYPE_W32_CONSOLE_HELPER_CHARS:
    chars = (char *) &message[1];
    str_size = ntohs (message->size) - sizeof (struct GNUNET_MessageHeader);
    if (chars[str_size - 1] != '\0')
      return GNUNET_SYSERR;
    /* FIXME: is it ok that we pass part of a const struct to
     * this function that may mangle the contents?
     */
    handle_command_string (chars, str_size - 1);
    break;
  default:
    GNUNET_break (0);
    break;
  }
  return GNUNET_OK;
}
#endif

/**
 * Task to handle commands from the terminal.
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
handle_command (void *cls,
		const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char message[MAX_MESSAGE_LENGTH + 1];

  handle_cmd_task =
    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                    stdin_fh,
                                    &handle_command, NULL);
  /* read message from command line and handle it */
  memset (message, 0, MAX_MESSAGE_LENGTH + 1);
  if (NULL == fgets (message, MAX_MESSAGE_LENGTH, stdin))
    return;
  handle_command_string (message, strlen (message));
}


/**
 * Function called by identity service with information about egos.
 *
 * @param cls NULL
 * @param ego ego handle
 * @param ctx unused
 * @param name name of the ego
 */
static void
identity_cb (void *cls,
             struct GNUNET_IDENTITY_Ego *ego,
             void **ctx,
             const char *name)
{
  if (NULL == name)
    return;
  if (ego == my_caller_id)
  {
    if (verbose)
      FPRINTF (stdout,
               _("Name of our ego changed to `%s'\n"),
               name);
    GNUNET_free (ego_name);
    ego_name = GNUNET_strdup (name);
    return;
  }
  if (0 != strcmp (name,
                   ego_name))
    return;
  if (NULL == ego)
  {
    if (verbose)
      FPRINTF (stdout,
               _("Our ego `%s' was deleted!\n"),
               ego_name);
    my_caller_id = NULL;
    return;
  }
  my_caller_id = ego;
  GNUNET_CONFIGURATION_set_value_number (cfg,
                                         "CONVERSATION",
                                         "LINE",
                                         line);
  start_phone ();
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = GNUNET_CONFIGURATION_dup (c);
  speaker = GNUNET_SPEAKER_create_from_hardware (cfg);
  mic = GNUNET_MICROPHONE_create_from_hardware (cfg);
  if (NULL == ego_name)
  {
    FPRINTF (stderr,
             "%s",
             _("You must specify the NAME of an ego to use\n"));
    return;
  }
  id = GNUNET_IDENTITY_connect (cfg,
                                &identity_cb,
                                NULL);
#ifdef WINDOWS
  if (stdin_fh == NULL)
  {
    static char cpid[64];
    static char *args[] = {"gnunet-helper-w32-console.exe", "chars",
        XSTRINGIFY (MAX_MESSAGE_LENGTH), cpid, NULL};
    snprintf (cpid, 64, "%d", GetCurrentProcessId ());
    stdin_hlp = GNUNET_HELPER_start (
        GNUNET_NO,
	"gnunet-helper-w32-console",
	args,
	console_reader_chars,
	NULL,
	NULL);
    if (NULL == stdin_hlp)
    {
      FPRINTF (stderr,
               "%s",
               _("Failed to start gnunet-helper-w32-console\n"));
      return;
    }
  }
  else
#endif
  handle_cmd_task =
    GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_UI,
					&handle_command, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &do_stop_task,
				NULL);
}


/**
 * The main function to conversation.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'e', "ego", "NAME",
     gettext_noop ("sets the NAME of the ego to use for the phone (and name resolution)"),
     1, &GNUNET_GETOPT_set_string, &ego_name},
    {'p', "phone", "LINE",
      gettext_noop ("sets the LINE to use for the phone"),
     1, &GNUNET_GETOPT_set_uint, &line},
    GNUNET_GETOPT_OPTION_END
  };
  int ret;
#ifndef WINDOWS
  int flags;
  flags = fcntl (0, F_GETFL, 0);
  flags |= O_NONBLOCK;
  if (0 != fcntl (0, F_SETFL, flags))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "fcntl");
  stdin_fh = GNUNET_DISK_get_handle_from_int_fd (0);
#else
  if (FILE_TYPE_CHAR == GetFileType ((HANDLE) _get_osfhandle (0)))
  {
    stdin_fh = NULL;
  }
  else
    stdin_fh = GNUNET_DISK_get_handle_from_int_fd (0);
#endif

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  ret = GNUNET_PROGRAM_run (argc, argv,
                            "gnunet-conversation",
			    gettext_noop ("Enables having a conversation with other GNUnet users."),
			    options, &run, NULL);
  GNUNET_free ((void *) argv);
  if (NULL != cfg)
  {
    GNUNET_CONFIGURATION_destroy (cfg);
    cfg = NULL;
  }
  return (GNUNET_OK == ret) ? 0 : 1;
}

/* end of gnunet-conversation.c */
