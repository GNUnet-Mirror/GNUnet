/*
		 This file is part of GNUnet.
		 (C)

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
		 Free Software Foundation, InGNUNET_SERVERc., 59 Temple Place - Suite 330,
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
* CONVERSATION handle
*/
struct GNUNET_CONVERSATION_Handle *conversation = NULL;

/**
* Task which handles the commands
*/
static GNUNET_SCHEDULER_TaskIdentifier handle_cmd_task;

/**
* Function declareation for executing a action
*/
typedef int (*ActionFunction) (const char *argumetns, const void *xtra);

/**
* Structure which defines a command
*/
struct VoipCommand
{
  const char *command;
  ActionFunction Action;
  const char *helptext;
};

/******************************************************************************/
/***********************         DECLARATIONS         *************************/
/******************************************************************************/

static int do_help (const char *args, const void *xtra);

/******************************************************************************/
/***********************         Functions            *************************/
/******************************************************************************/


/**
 * Method called whenever a call is incoming
 *
 * @param cls closure
 * @param handle to the conversation session
 * @param caller peer that calls you
 */
static void
call_handler (void *cls,
	      struct GNUNET_CONVERSATION_Handle *handle,
	      const struct GNUNET_PeerIdentity *caller)
{
  FPRINTF (stdout, 
	   _("Incoming call from peer: %s\n"),
	   GNUNET_i2s_full (caller));
}


/**
 * Method called whenever a call is rejected
 *
 * @param cls closure
 * @param handle to the conversation session
 * @param reason given reason why the call was rejected
 * @param peer peer that rejected your call
 */
static void
reject_handler (void *cls, 
		struct GNUNET_CONVERSATION_Handle *handle, 
		enum GNUNET_CONVERSATION_RejectReason reason,
		const struct GNUNET_PeerIdentity *peer)
{
  FPRINTF (stdout, 
	   _("Peer %s rejected your call. Reason: %d\n"),
	   GNUNET_i2s_full (peer), reason);
}


/**
 * Method called whenever a notification is there
 *
 * @param cls closure
 * @param handle to the conversation session
 * @param type the type of the notification
 * @param peer peer that the notification is about
 */
static void
notification_handler (void *cls, 
		      struct GNUNET_CONVERSATION_Handle *handle, 
		      enum GNUNET_CONVERSATION_NotificationType type,
		      const struct GNUNET_PeerIdentity *peer)
{
  switch (type)
  {
  case GNUNET_CONVERSATION_NT_SERVICE_BLOCKED:
    FPRINTF (stdout,
	     _("The service is already in use. Try again later."));    
    break;    
  case GNUNET_CONVERSATION_NT_NO_PEER:
    FPRINTF (stdout, 
	     _("The Peer you were calling is no correct peer.\n"));    
    break;    
  case GNUNET_CONVERSATION_NT_NO_ANSWER:
    FPRINTF (stdout, 
	     _("Peer %s did not answer your call.\n"),
	     GNUNET_i2s_full (peer));    
    break;    
  case GNUNET_CONVERSATION_NT_AVAILABLE_AGAIN:
    FPRINTF (stdout,
	     _("Peer %s is now available.\n"),
	     GNUNET_i2s_full (peer));    
    break;    
  case GNUNET_CONVERSATION_NT_CALL_ACCEPTED:
    FPRINTF (stdout, 
	     _("Peer %s has accepted your call.\n"),
	     GNUNET_i2s_full (peer));    
    break;    
  case GNUNET_CONVERSATION_NT_CALL_TERMINATED:
    FPRINTF (stdout,
	     _("Peer %s has terminated the call.\n"),
	     GNUNET_i2s_full (peer));
    break;
  default:
    GNUNET_break (0);
  }  
}


/**
 * Method called whenever a notification for missed calls is there
 *
 * @param cls closure
 * @param handle to the conversation session
 * @param missed_calls a list of missed calls
 */
static void
missed_call_handler (void *cls,
		     struct GNUNET_CONVERSATION_Handle *handle,
		     struct GNUNET_CONVERSATION_MissedCallNotification *missed_calls)
{
  FPRINTF (stdout, _("You have missed calls.\n"));
}


/**
 * Terminating the client
 */
static int
do_quit (const char *args, 
	 const void *xtra)
{
  return GNUNET_SYSERR;
}


/**
 *
 */
static int
do_unknown (const char *msg, 
	    const void *xtra)
{
  FPRINTF (stderr, _("Unknown command `%s'\n"), msg);
  return GNUNET_OK;
}


/**
 * Initiating a new call
 */
static int
do_call (const char *arg, 
	 const void *xtra)
{
  char *callee = GNUNET_strdup (arg);

  FPRINTF (stdout, 
	   _("Initiating call to: %s\n"), 
	   callee);
  GNUNET_CONVERSATION_call (conversation, 
			    callee, 
			    GNUNET_YES);
  return GNUNET_OK;
}


/**
 * Initiating a new call
 */
static int
do_call_peer (const char *arg, 
	      const void *xtra)
{
  char *callee = GNUNET_strdup (arg);

  FPRINTF (stdout, 
	   _("Initiating call to: %s\n"), 
	   callee);
  GNUNET_CONVERSATION_call (conversation, callee, GNUNET_NO);
  
  return GNUNET_OK;
}


/**
 * Accepting an incoming call
 */
static int
do_accept (const char *args, 
	   const void *xtra)
{
  FPRINTF (stdout,
	   _("Accepting the call\n"));
  GNUNET_CONVERSATION_accept (conversation);

  return GNUNET_OK;
}


/**
 * Rejecting a call
 */
static int
do_reject (const char *args, 
	   const void *xtra)
{
  FPRINTF (stdout,
	   _("Rejecting the call\n"));
  GNUNET_CONVERSATION_reject (conversation);
  return GNUNET_OK;
}


/**
 * Terminating a call
 */
static int
do_hang_up (const char *args, 
	    const void *xtra)
{
  FPRINTF (stdout, 
	   _("Terminating the call\n"));
  GNUNET_CONVERSATION_hangup (conversation);  
  return GNUNET_OK;
}


/**
 * List of supported commands.
 */
static struct VoipCommand commands[] = {
  {"/call ", &do_call, gettext_noop ("Use `/call gads_record'")},
  {"/callpeer ", &do_call_peer,
   gettext_noop ("Use `/call private_key' to call a person")},
  {"/accept", &do_accept,
   gettext_noop ("Use `/accept' to accept an incoming call")},
  {"/terminate", &do_hang_up,
   gettext_noop ("Use `/terminate' to end a call")},
  {"/reject", &do_reject,
   gettext_noop ("Use `/rejet' to reject an incoming call")},
  {"/quit", &do_quit, gettext_noop ("Use `/quit' to terminate gnunet-conversation")},
  {"/help", &do_help,
   gettext_noop ("Use `/help command' to get help for a specific command")},
  {"/", &do_unknown, NULL},
  {"", &do_unknown, NULL},
  {NULL, NULL, NULL},
};


/**
 *
 */
static int
do_help (const char *args, 
	 const void *xtra)
{
  int i;

  i = 0;
  while ((NULL != args) && (0 != strlen (args)) &&
	 (commands[i].Action != &do_help))
  {
    if (0 ==
	strncasecmp (&args[1], &commands[i].command[1], strlen (args) - 1))
    {
      FPRINTF (stdout, 
	       "%s\n",
	       gettext (commands[i].helptext));
      return GNUNET_OK;
    }
    i++;
  }
  i = 0;
  FPRINTF (stdout, 
	   "%s", 
	   "Available commands:");
  while (commands[i].Action != &do_help)
  {
    FPRINTF (stdout, 
	     " %s", 
	     gettext (commands[i].command));
    i++;
  }
  FPRINTF (stdout,
	   "%s",
	   "\n");
  FPRINTF (stdout,
	   "%s\n",
	   gettext (commands[i].helptext));
  return GNUNET_OK;
}


/**
 *
 */
static void
do_stop_task (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      "Running shutdown task\n");
  GNUNET_CONVERSATION_disconnect (conversation);
  
  if (handle_cmd_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (handle_cmd_task);
    handle_cmd_task = GNUNET_SCHEDULER_NO_TASK;
  } 
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      "Running shutdown task finished\n");
}


/**
 *
 */
static void
handle_command (void *cls,
		const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char message[MAX_MESSAGE_LENGTH + 1];
  int i;

  /* read message from command line and handle it */
  memset (message, 0, MAX_MESSAGE_LENGTH + 1);
  if (NULL == fgets (message, MAX_MESSAGE_LENGTH, stdin))
    goto next;
  if (strlen (message) == 0)
    goto next;
  if (message[strlen (message) - 1] == '\n')
    message[strlen (message) - 1] = '\0';
  if (strlen (message) == 0)
    goto next;
  i = 0;
  while ((NULL != commands[i].command) &&
	 (0 !=
	  strncasecmp (commands[i].command, message,
		       strlen (commands[i].command))))
    i++;
  if (GNUNET_OK !=
      commands[i].Action (&message[strlen (commands[i].command)], NULL))
    goto out;

next:
  handle_cmd_task =
    GNUNET_SCHEDULER_add_delayed_with_priority (GNUNET_TIME_relative_multiply
						(GNUNET_TIME_UNIT_MILLISECONDS,
						 100),
						GNUNET_SCHEDULER_PRIORITY_UI,
						&handle_command, NULL);
  return;

out:
  handle_cmd_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_SCHEDULER_shutdown ();
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
  if (NULL ==
      (conversation =
       GNUNET_CONVERSATION_connect (c, NULL, 
				    &call_handler,
				    &reject_handler,
				    &notification_handler,
				    &missed_call_handler)))
  {
    FPRINTF (stderr,
	     "%s",
	     _("Could not access CONVERSATION service.  Exiting.\n"));
    return;
  }

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
    GNUNET_GETOPT_OPTION_END
  };

  int flags;
  int ret;

  flags = fcntl (0, F_GETFL, 0);
  flags |= O_NONBLOCK;
  fcntl (0, F_SETFL, flags);

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = GNUNET_PROGRAM_run (argc, argv, "gnunet-conversation",
			    gettext_noop ("Print information about conversation."),
			    options, &run, NULL);
  GNUNET_free ((void *) argv);

  return ret;
}

/* end of gnunet-conversation.c */
