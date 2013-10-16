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


/**
 * Maximum length allowed for the command line input.
 */
#define MAX_MESSAGE_LENGTH 1024


/**
 * Possible states of the program.
 */
enum ConversationState
{
  /**
   * We're waiting for our own idenitty.
   */
  CS_LOOKUP_EGO,

  /**
   * We're listening for calls
   */
  CS_LISTEN,

  /**
   * Our phone is ringing.
   */
  CS_RING,

  /**
   * We accepted an incoming phone call.
   */
  CS_ACCEPTED,

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
   * Internal error
   */
  CS_ERROR

};


/**
 * Phone handle
 */
static struct GNUNET_CONVERSATION_Phone *phone;

/**
 * Call handle
 */
static struct GNUNET_CONVERSATION_Call *call;

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
static struct GNUNET_IDENTITY_Ego *caller_id;

/**
 * Handle to identity service.
 */
static struct GNUNET_IDENTITY_Handle *id;

/**
 * Name of our ego.
 */
static char *ego_name;

/**
 * Name of conversation partner (if any).
 */
static char *peer_name;

/**
 * File handle for stdin.
 */
static struct GNUNET_DISK_FileHandle *stdin_fh;

/**
 * Our current state.
 */
static enum ConversationState state;

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
 * @param code type of the event on the phone
 * @param ... additional information, depends on @a code
 */
static void
phone_event_handler (void *cls,
                     enum GNUNET_CONVERSATION_EventCode code,
                     ...)
{
  va_list va;

  va_start (va, code);
  switch (code)
  {
  case GNUNET_CONVERSATION_EC_RING:
    GNUNET_break (CS_LISTEN == state);
    GNUNET_free_non_null (peer_name);
    peer_name = GNUNET_strdup (va_arg (va, const char *));
    FPRINTF (stdout,
             _("Incoming call from `%s'.\nPlease /accept or /cancel the call.\n"),
             peer_name);
    state = CS_RING;
    break;
  case GNUNET_CONVERSATION_EC_RINGING:
    GNUNET_break (0);
    break;
  case GNUNET_CONVERSATION_EC_READY:
    GNUNET_break (0);
    break;
  case GNUNET_CONVERSATION_EC_GNS_FAIL:
    GNUNET_break (0);
    break;
  case GNUNET_CONVERSATION_EC_BUSY:
    GNUNET_break (0);
    break;
  case GNUNET_CONVERSATION_EC_TERMINATED:
    GNUNET_break ( (CS_RING == state) ||
                   (CS_ACCEPTED == state) );
    FPRINTF (stdout,
             _("Call terminated: %s\n"),
             va_arg (va, const char *));
    state = CS_LISTEN;
    break;
  }
  va_end (va);
}


/**
 * Start our phone.
 */
static void
start_phone ()
{
  struct GNUNET_GNSRECORD_Data rd;

  if (NULL == caller_id)
  {
    FPRINTF (stderr,
             _("Ego `%s' no longer available, phone is now down.\n"),
             ego_name);
    state = CS_LOOKUP_EGO;
    return;
  }
  phone = GNUNET_CONVERSATION_phone_create (cfg,
                                            caller_id,
                                            &phone_event_handler, NULL);
  /* FIXME: get record and print full GNS record info later here... */
  if (NULL == phone)
  {
    FPRINTF (stderr,
             "%s",
             _("Failed to setup phone (internal error)\n"));
    state = CS_ERROR;
  }
  else
  {
    GNUNET_CONVERSATION_phone_get_record (phone,
                                          &rd);
    GNUNET_free_non_null (address);
    address = GNUNET_GNSRECORD_value_to_string (rd.record_type,
                                                rd.data,
                                                rd.data_size);
    if (verbose)
      FPRINTF (stdout,
               _("Phone active on line %u\n"),
               (unsigned int) line);
    state = CS_LISTEN;
  }
}


/**
 * Function called with an event emitted by a phone.
 *
 * @param cls closure
 * @param code type of the event on the phone
 * @param ... additional information, depends on @a code
 */
static void
call_event_handler (void *cls,
                    enum GNUNET_CONVERSATION_EventCode code,
                    ...)
{
  va_list va;

  va_start (va, code);
  switch (code)
  {
  case GNUNET_CONVERSATION_EC_RING:
    GNUNET_break (0);
    break;
  case GNUNET_CONVERSATION_EC_RINGING:
    GNUNET_break (CS_RESOLVING == state);
    if (verbose)
      FPRINTF (stdout,
               "%s",
               _("Resolved address. Now ringing other party.\n"));
    state = CS_RINGING;
    break;
  case GNUNET_CONVERSATION_EC_READY:
    GNUNET_break (CS_RINGING == state);
    FPRINTF (stdout,
             _("Connection established to `%s': %s\n"),
             peer_name,
             va_arg (va, const char *));
    state = CS_CONNECTED;
    break;
  case GNUNET_CONVERSATION_EC_GNS_FAIL:
    GNUNET_break (CS_RESOLVING == state);
    FPRINTF (stdout,
             _("Failed to resolve `%s'\n"),
             ego_name);
    call = NULL;
    start_phone ();
    break;
  case GNUNET_CONVERSATION_EC_BUSY:
    GNUNET_break (CS_RINGING == state);
    FPRINTF (stdout,
             "%s",
             _("Line busy\n"));
    call = NULL;
    start_phone ();
    break;
  case GNUNET_CONVERSATION_EC_TERMINATED:
    GNUNET_break ( (CS_RINGING == state) ||
                   (CS_CONNECTED == state) );
    FPRINTF (stdout,
             _("Call terminated: %s\n"),
             va_arg (va, const char *));
    call = NULL;
    start_phone ();
    break;
  }
  va_end (va);
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
  if (NULL == caller_id)
  {
    FPRINTF (stderr,
             _("Ego `%s' not available\n"),
             ego_name);
    return;
  }
  switch (state)
  {
  case CS_LOOKUP_EGO:
    FPRINTF (stderr,
             _("Ego `%s' not available\n"),
             ego_name);
    return;
  case CS_LISTEN:
    /* ok to call! */
    break;
  case CS_RING:
    FPRINTF (stdout,
             _("Hanging up on incoming phone call from `%s' to call `%s'.\n"),
             peer_name,
             arg);
    GNUNET_CONVERSATION_phone_hang_up (phone, NULL);
    break;
  case CS_ACCEPTED:
    FPRINTF (stderr,
             _("You are already in a conversation with `%s', refusing to call `%s'.\n"),
             peer_name,
             arg);
    return;
  case CS_RESOLVING:
  case CS_RINGING:
    FPRINTF (stderr,
             _("Aborting call to `%s'\n"),
             peer_name);
    GNUNET_CONVERSATION_call_stop (call, NULL);
    call = NULL;
    break;
  case CS_CONNECTED:
    FPRINTF (stderr,
             _("You are already in a conversation with `%s', refusing to call `%s'.\n"),
             peer_name,
             arg);
    return;
  case CS_ERROR:
    /* ok to call */
    break;
  }
  GNUNET_assert (NULL == call);
  if (NULL != phone)
  {
    GNUNET_CONVERSATION_phone_destroy (phone);
    phone = NULL;
  }
  GNUNET_free_non_null (peer_name);
  peer_name = GNUNET_strdup (arg);
  call = GNUNET_CONVERSATION_call_start (cfg,
                                         caller_id,
                                         arg,
                                         speaker,
                                         mic,
                                         &call_event_handler, NULL);
  state = CS_RESOLVING;
}


/**
 * Accepting an incoming call
 *
 * @param args arguments given to the command
 */
static void
do_accept (const char *args)
{
  switch (state)
  {
  case CS_LOOKUP_EGO:
  case CS_LISTEN:
  case CS_ERROR:
    FPRINTF (stderr,
             _("There is no incoming call to be accepted!\n"));
    return;
  case CS_RING:
    /* this is the expected state */
    break;
  case CS_ACCEPTED:
    FPRINTF (stderr,
             _("You are already in a conversation with `%s'.\n"),
             peer_name);
    return;
  case CS_RESOLVING:
  case CS_RINGING:
    FPRINTF (stderr,
             _("You are trying to call `%s', cannot accept incoming calls right now.\n"),
             peer_name);
    return;
  case CS_CONNECTED:
    FPRINTF (stderr,
             _("You are already in a conversation with `%s'.\n"),
             peer_name);
    return;
  }
  GNUNET_assert (NULL != phone);
  GNUNET_CONVERSATION_phone_pick_up (phone,
                                     args,
                                     speaker,
                                     mic);
  state = CS_ACCEPTED;
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
  switch (state)
  {
  case CS_LOOKUP_EGO:
    FPRINTF (stdout,
             _("We are currently trying to locate the private key for the ego `%s'.\n"),
             ego_name);
    break;
  case CS_LISTEN:
    FPRINTF (stdout,
             _("We are listening for incoming calls for ego `%s' on line %u.\n"),
             ego_name,
             line);
    break;
  case CS_RING:
    FPRINTF (stdout,
             _("The phone is rining. `%s' is trying to call us.\n"),
             peer_name);
    break;
  case CS_ACCEPTED:
  case CS_CONNECTED:
    FPRINTF (stdout,
             _("You are having a conversation with `%s'.\n"),
             peer_name);
    break;
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
  case CS_ERROR:
    FPRINTF (stdout,
             _("We had an internal error setting up our phone line. You can still make calls.\n"));
    break;
  }
}


/**
 * Rejecting a call
 *
 * @param args arguments given to the command
 */
static void
do_reject (const char *args)
{
  switch (state)
  {
  case CS_LOOKUP_EGO:
  case CS_LISTEN:
  case CS_ERROR:
    FPRINTF (stderr,
             "%s",
             _("There is no call that could be cancelled right now.\n"));
    return;
  case CS_RING:
  case CS_ACCEPTED:
  case CS_RESOLVING:
  case CS_RINGING:
  case CS_CONNECTED:
    /* expected state, do rejection logic */
    break;
  }
  if (NULL == call)
  {
    GNUNET_assert (NULL != phone);
    GNUNET_CONVERSATION_phone_hang_up (phone,
                                       args);
    state = CS_LISTEN;
  }
  else
  {
    GNUNET_CONVERSATION_call_stop (call, args);
    call = NULL;
    start_phone ();
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
   gettext_noop ("Use `/accept MESSAGE' to accept an incoming call")},
  {"/cancel", &do_reject,
   gettext_noop ("Use `/cancel MESSAGE' to reject or terminate a call")},
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
 * @param arguments arguments given to the command
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
  if (NULL != call)
  {
    GNUNET_CONVERSATION_call_stop (call, NULL);
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
  GNUNET_CONFIGURATION_destroy (cfg);
  cfg = NULL;
  GNUNET_free_non_null (peer_name);
  state = CS_ERROR;
}


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
  const char *ptr;
  size_t i;

  handle_cmd_task =
    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                    stdin_fh,
                                    &handle_command, NULL);
  /* read message from command line and handle it */
  memset (message, 0, MAX_MESSAGE_LENGTH + 1);
  if (NULL == fgets (message, MAX_MESSAGE_LENGTH, stdin))
    return;
  if (0 == strlen (message))
    return;
  if (message[strlen (message) - 1] == '\n')
    message[strlen (message) - 1] = '\0';
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
  commands[i].Action (ptr);
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
  if (ego == caller_id)
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
    caller_id = NULL;
    return;
  }
  caller_id = ego;
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
  int flags;
  int ret;

  flags = fcntl (0, F_GETFL, 0);
  flags |= O_NONBLOCK;
  fcntl (0, F_SETFL, flags);
  stdin_fh = GNUNET_DISK_get_handle_from_int_fd (0);
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  ret = GNUNET_PROGRAM_run (argc, argv,
                            "gnunet-conversation",
			    gettext_noop ("Enables having a conversation with other GNUnet users."),
			    options, &run, NULL);
  GNUNET_free ((void *) argv);
  return (GNUNET_OK == ret) ? 0 : 1;
}

/* end of gnunet-conversation.c */
