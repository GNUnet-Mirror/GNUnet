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
#include "gnunet_conversation_service.h"
#include <fcntl.h>

#define MAX_MESSAGE_LENGTH   (32 * 1024)

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
 * File handle for stdin.
 */
static struct GNUNET_DISK_FileHandle *stdin_fh;


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
    FPRINTF (stdout,
             _("Incoming call from `%s'.  Enter /accept to take it.\n"),
             va_arg (va, const char *));
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
    FPRINTF (stdout,
             _("Call terminated: %s\n"),
             va_arg (va, const char *));
    break;
  }
  va_end (va);
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
    FPRINTF (stdout,
             "%s",
             _("Ringing other party\n"));
    break;
  case GNUNET_CONVERSATION_EC_READY:
    FPRINTF (stdout,
             _("Connection established: %s\n"),
             va_arg (va, const char *));
    break;
  case GNUNET_CONVERSATION_EC_GNS_FAIL:
    FPRINTF (stdout,
             "%s",
             _("Failed to resolve name\n"));
    break;
  case GNUNET_CONVERSATION_EC_BUSY:
    FPRINTF (stdout,
             "%s",
             _("Line busy\n"));
    break;
  case GNUNET_CONVERSATION_EC_TERMINATED:
    FPRINTF (stdout,
             _("Call terminated: %s\n"),
             va_arg (va, const char *));
    GNUNET_CONVERSATION_call_stop (call, NULL);
    call = NULL;
    if (NULL == caller_id)
    {
      FPRINTF (stderr,
               _("Ego `%s' no longer available, phone is now down.\n"),
               ego_name);
      return;
    }
    phone = GNUNET_CONVERSATION_phone_create (cfg,
                                              caller_id,
                                              &phone_event_handler, NULL);
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
 * @param arguments arguments given to the command
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
 * @param args arguments given to the command
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
 * @param args arguments given to the command
 */
static void
do_call (const char *arg)
{
  if (NULL != call)
    return;
  if (NULL == caller_id)
  {
    FPRINTF (stderr,
             _("Ego `%s' not available\n"),
             ego_name);
    return;
  }
  /* FIXME: also check that we do NOT have a running conversation or ring */
  if (NULL != phone)
  {
    GNUNET_CONVERSATION_phone_destroy (phone);
    phone = NULL;
  }
  call = GNUNET_CONVERSATION_call_start (cfg,
                                         caller_id,
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
  if (NULL == phone)
    return;
  /* FIXME: also check that we don't have a running conversation */
  GNUNET_CONVERSATION_phone_pick_up (phone, 
                                     args,
                                     speaker,
                                     mic);
}


/**
 * Rejecting a call
 *
 * @param args arguments given to the command
 */
static void
do_reject (const char *args)
{
  /* FIXME: also check that we do have a running conversation or ring */
  if (NULL == call)
  {
    GNUNET_CONVERSATION_phone_hang_up (phone, 
                                       args);
  }
  else
  {
    GNUNET_CONVERSATION_call_stop (call, args);
    call = NULL;
    phone = GNUNET_CONVERSATION_phone_create (cfg,
                                              caller_id,
                                              &phone_event_handler, NULL);
  }
}


/**
 * List of supported commands.
 */
static struct VoipCommand commands[] = {
  {"/call", &do_call, 
   gettext_noop ("Use `/call USER.gnu'")},
  {"/accept", &do_accept,
   gettext_noop ("Use `/accept MESSAGE' to accept an incoming call")},
  {"/cancel", &do_reject,
   gettext_noop ("Use `/cancel MESSAGE' to reject or terminate a call")},
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
  int i;

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
    caller_id = NULL;
    return;
  }
  caller_id = ego;
  GNUNET_CONFIGURATION_set_value_number (cfg,
                                         "CONVERSATION",
                                         "LINE",
                                         line);
  phone = GNUNET_CONVERSATION_phone_create (cfg,
                                            caller_id,
                                            &phone_event_handler, NULL);
  /* FIXME: get record and print full GNS record info later here... */
  if (NULL == phone)
  {
    fprintf (stderr,
             _("Failed to setup phone (internal error)\n"));
  }
  else
    fprintf (stdout,
             _("Phone active on line %u\n"),
             (unsigned int) line);
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
    {'p', "phone", "LINE",
      gettext_noop ("sets the LINE to use for the phone"),
     1, &GNUNET_GETOPT_set_uint, &line},
    {'e', "ego", "NAME",
     gettext_noop ("sets the NAME of the ego to use for the phone (and name resolution)"),
     1, &GNUNET_GETOPT_set_string, &ego_name},
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
