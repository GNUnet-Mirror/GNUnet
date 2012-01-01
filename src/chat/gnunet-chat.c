/*
     This file is part of GNUnet.
     (C) 2007, 2008, 2011 Christian Grothoff (and other contributing authors)

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
 * @file chat/gnunet-chat.c
 * @brief Minimal chat command line tool
 * @author Christian Grothoff
 * @author Nathan Evans
 * @author Vitaly Minko
 */

#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_chat_service.h"
#include <fcntl.h>

static int ret;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static char *nickname;

static char *room_name;

static struct GNUNET_CONTAINER_MetaData *meta;

static struct GNUNET_CHAT_Room *room;

static GNUNET_SCHEDULER_TaskIdentifier handle_cmd_task =
    GNUNET_SCHEDULER_NO_TASK;

struct ChatCommand
{
  const char *command;
  int (*Action) (const char *arguments, const void *xtra);
  const char *helptext;
};

struct UserList
{
  struct UserList *next;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  int ignored;
};

static struct UserList *users;

static void
free_user_list ()
{
  struct UserList *next;

  while (NULL != users)
  {
    next = users->next;
    GNUNET_free (users);
    users = next;
  }
}

static int
do_help (const char *args, const void *xtra);


/**
 * Callback used for notification that we have joined the room.
 *
 * @param cls closure
 * @return GNUNET_OK
 */
static int
join_cb (void *cls)
{
  FPRINTF (stdout, "%s",  _("Joined\n"));
  return GNUNET_OK;
}


/**
 * Callback used for notification about incoming messages.
 *
 * @param cls closure, NULL
 * @param room in which room was the message received?
 * @param sender what is the ID of the sender? (maybe NULL)
 * @param member_info information about the joining member
 * @param message the message text
 * @param timestamp time when the member joined
 * @param options options for the message
 * @return GNUNET_OK to accept the message now, GNUNET_NO to
 *         accept (but user is away), GNUNET_SYSERR to signal denied delivery
 */
static int
receive_cb (void *cls, struct GNUNET_CHAT_Room *room,
            const GNUNET_HashCode * sender,
            const struct GNUNET_CONTAINER_MetaData *member_info,
            const char *message, struct GNUNET_TIME_Absolute timestamp,
            enum GNUNET_CHAT_MsgOptions options)
{
  char *nick;
  char *time;
  const char *fmt;

  if (NULL != sender)
    nick = GNUNET_PSEUDONYM_id_to_name (cfg, sender);
  else
    nick = GNUNET_strdup (_("anonymous"));
  fmt = NULL;
  switch ((int) options)
  {
  case GNUNET_CHAT_MSG_OPTION_NONE:
  case GNUNET_CHAT_MSG_ANONYMOUS:
    fmt = _("(%s) `%s' said: %s\n");
    break;
  case GNUNET_CHAT_MSG_PRIVATE:
    fmt = _("(%s) `%s' said to you: %s\n");
    break;
  case GNUNET_CHAT_MSG_PRIVATE | GNUNET_CHAT_MSG_ANONYMOUS:
    fmt = _("(%s) `%s' said to you: %s\n");
    break;
  case GNUNET_CHAT_MSG_AUTHENTICATED:
    fmt = _("(%s) `%s' said for sure: %s\n");
    break;
  case GNUNET_CHAT_MSG_PRIVATE | GNUNET_CHAT_MSG_AUTHENTICATED:
    fmt = _("(%s) `%s' said to you for sure: %s\n");
    break;
  case GNUNET_CHAT_MSG_ACKNOWLEDGED:
    fmt = _("(%s) `%s' was confirmed that you received: %s\n");
    break;
  case GNUNET_CHAT_MSG_PRIVATE | GNUNET_CHAT_MSG_ACKNOWLEDGED:
    fmt = _("(%s) `%s' was confirmed that you and only you received: %s\n");
    break;
  case GNUNET_CHAT_MSG_AUTHENTICATED | GNUNET_CHAT_MSG_ACKNOWLEDGED:
    fmt = _("(%s) `%s' was confirmed that you received from him or her: %s\n");
    break;
  case GNUNET_CHAT_MSG_AUTHENTICATED | GNUNET_CHAT_MSG_PRIVATE | GNUNET_CHAT_MSG_ACKNOWLEDGED:
    fmt =
        _
        ("(%s) `%s' was confirmed that you and only you received from him or her: %s\n");
    break;
  case GNUNET_CHAT_MSG_OFF_THE_RECORD:
    fmt = _("(%s) `%s' said off the record: %s\n");
    break;
  default:
    fmt = _("(%s) <%s> said using an unknown message type: %s\n");
    break;
  }
  time = GNUNET_STRINGS_absolute_time_to_string (timestamp);
  FPRINTF (stdout, fmt, time, nick, message);
  GNUNET_free (nick);
  GNUNET_free (time);
  return GNUNET_OK;
}


/**
 * Callback used for message delivery confirmations.
 *
 * @param cls closure, NULL
 * @param room in which room was the message received?
 * @param orig_seq_number sequence number of the original message
 * @param timestamp when was the message received?
 * @param receiver who is confirming the receipt?
 * @return GNUNET_OK to continue, GNUNET_SYSERR to refuse processing further
 *         confirmations from anyone for this message
 */
static int
confirmation_cb (void *cls, struct GNUNET_CHAT_Room *room,
                 uint32_t orig_seq_number,
                 struct GNUNET_TIME_Absolute timestamp,
                 const GNUNET_HashCode * receiver)
{
  char *nick;

  nick = GNUNET_PSEUDONYM_id_to_name (cfg, receiver);
  FPRINTF (stdout, _("'%s' acknowledged message #%d\n"), nick, orig_seq_number);
  return GNUNET_OK;
}


/**
 * Callback used for notification that another room member has joined or left.
 *
 * @param cls closure (not used)
 * @param member_info will be non-null if the member is joining, NULL if he is
 *        leaving
 * @param member_id hash of public key of the user (for unique identification)
 * @param options what types of messages is this member willing to receive?
 * @return GNUNET_OK
 */
static int
member_list_cb (void *cls, const struct GNUNET_CONTAINER_MetaData *member_info,
                const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *member_id,
                enum GNUNET_CHAT_MsgOptions options)
{
  char *nick;
  GNUNET_HashCode id;
  struct UserList *pos;
  struct UserList *prev;

  GNUNET_CRYPTO_hash (member_id,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &id);
  nick = GNUNET_PSEUDONYM_id_to_name (cfg, &id);
  FPRINTF (stdout,
           member_info !=
           NULL ? _("`%s' entered the room\n") : _("`%s' left the room\n"),
           nick);
  GNUNET_free (nick);
  if (NULL != member_info)
  {
    /* user joining */
    pos = GNUNET_malloc (sizeof (struct UserList));
    pos->next = users;
    pos->pkey = *member_id;
    pos->ignored = GNUNET_NO;
    users = pos;
  }
  else
  {
    /* user leaving */
    prev = NULL;
    pos = users;
    while ((NULL != pos) &&
           (0 !=
            memcmp (&pos->pkey, member_id,
                    sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded))))
    {
      prev = pos;
      pos = pos->next;
    }
    if (NULL == pos)
    {
      GNUNET_break (0);
    }
    else
    {
      if (NULL == prev)
        users = pos->next;
      else
        prev->next = pos->next;
      GNUNET_free (pos);
    }
  }
  return GNUNET_OK;
}


static int
do_join (const char *arg, const void *xtra)
{
  char *my_name;
  GNUNET_HashCode me;

  if (arg[0] == '#')
    arg++;                      /* ignore first hash */
  GNUNET_CHAT_leave_room (room);
  free_user_list ();
  GNUNET_free (room_name);
  room_name = GNUNET_strdup (arg);
  room =
      GNUNET_CHAT_join_room (cfg, nickname, meta, room_name, -1, &join_cb, NULL,
                             &receive_cb, NULL, &member_list_cb, NULL,
                             &confirmation_cb, NULL, &me);
  if (NULL == room)
  {
    FPRINTF (stdout, "%s",  _("Could not change username\n"));
    return GNUNET_SYSERR;
  }
  my_name = GNUNET_PSEUDONYM_id_to_name (cfg, &me);
  FPRINTF (stdout, _("Joining room `%s' as user `%s'...\n"), room_name,
           my_name);
  GNUNET_free (my_name);
  return GNUNET_OK;
}


static int
do_nick (const char *msg, const void *xtra)
{
  char *my_name;
  GNUNET_HashCode me;

  GNUNET_CHAT_leave_room (room);
  free_user_list ();
  GNUNET_free (nickname);
  GNUNET_CONTAINER_meta_data_destroy (meta);
  nickname = GNUNET_strdup (msg);
  meta = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_CONTAINER_meta_data_insert (meta, "<gnunet>", EXTRACTOR_METATYPE_TITLE,
                                     EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                     nickname, strlen (nickname) + 1);
  room =
      GNUNET_CHAT_join_room (cfg, nickname, meta, room_name, -1, &join_cb, NULL,
                             &receive_cb, NULL, &member_list_cb, NULL,
                             &confirmation_cb, NULL, &me);
  if (NULL == room)
  {
    FPRINTF (stdout, "%s",  _("Could not change username\n"));
    return GNUNET_SYSERR;
  }
  my_name = GNUNET_PSEUDONYM_id_to_name (cfg, &me);
  FPRINTF (stdout, _("Changed username to `%s'\n"), my_name);
  GNUNET_free (my_name);
  return GNUNET_OK;
}


static int
do_names (const char *msg, const void *xtra)
{
  char *name;
  struct UserList *pos;
  GNUNET_HashCode pid;

  FPRINTF (stdout, _("Users in room `%s': "), room_name);
  pos = users;
  while (NULL != pos)
  {
    GNUNET_CRYPTO_hash (&pos->pkey,
                        sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                        &pid);
    name = GNUNET_PSEUDONYM_id_to_name (cfg, &pid);
    FPRINTF (stdout, "`%s' ", name);
    GNUNET_free (name);
    pos = pos->next;
  }
  FPRINTF (stdout, "%s",  "\n");
  return GNUNET_OK;
}


static int
do_send (const char *msg, const void *xtra)
{
  uint32_t seq;

  GNUNET_CHAT_send_message (room, msg, GNUNET_CHAT_MSG_OPTION_NONE, NULL, &seq);
  return GNUNET_OK;
}


static int
do_send_pm (const char *msg, const void *xtra)
{
  char *user;
  GNUNET_HashCode uid;
  GNUNET_HashCode pid;
  uint32_t seq;
  struct UserList *pos;

  if (NULL == strstr (msg, " "))
  {
    FPRINTF (stderr, "%s",  _("Syntax: /msg USERNAME MESSAGE"));
    return GNUNET_OK;
  }
  user = GNUNET_strdup (msg);
  strstr (user, " ")[0] = '\0';
  msg += strlen (user) + 1;
  if (GNUNET_OK != GNUNET_PSEUDONYM_name_to_id (cfg, user, &uid))
  {
    FPRINTF (stderr, _("Unknown user `%s'\n"), user);
    GNUNET_free (user);
    return GNUNET_OK;
  }
  pos = users;
  while (NULL != pos)
  {
    GNUNET_CRYPTO_hash (&pos->pkey,
                        sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                        &pid);
    if (0 == memcmp (&pid, &uid, sizeof (GNUNET_HashCode)))
      break;
    pos = pos->next;
  }
  if (NULL == pos)
  {
    FPRINTF (stderr, _("User `%s' is currently not in the room!\n"), user);
    GNUNET_free (user);
    return GNUNET_OK;
  }
  GNUNET_CHAT_send_message (room, msg, GNUNET_CHAT_MSG_PRIVATE, &pos->pkey,
                            &seq);
  GNUNET_free (user);
  return GNUNET_OK;
}


static int
do_send_sig (const char *msg, const void *xtra)
{
  uint32_t seq;

  GNUNET_CHAT_send_message (room, msg, GNUNET_CHAT_MSG_AUTHENTICATED, NULL,
                            &seq);
  return GNUNET_OK;
}


static int
do_send_ack (const char *msg, const void *xtra)
{
  uint32_t seq;

  GNUNET_CHAT_send_message (room, msg, GNUNET_CHAT_MSG_ACKNOWLEDGED, NULL,
                            &seq);
  return GNUNET_OK;
}


static int
do_send_anonymous (const char *msg, const void *xtra)
{
  uint32_t seq;

  GNUNET_CHAT_send_message (room, msg, GNUNET_CHAT_MSG_ANONYMOUS, NULL, &seq);
  return GNUNET_OK;
}


static int
do_quit (const char *args, const void *xtra)
{
  return GNUNET_SYSERR;
}


static int
do_unknown (const char *msg, const void *xtra)
{
  FPRINTF (stderr, _("Unknown command `%s'\n"), msg);
  return GNUNET_OK;
}


/**
 * List of supported IRC commands. The order matters!
 */
static struct ChatCommand commands[] = {
  {"/join ", &do_join,
   gettext_noop
   ("Use `/join #roomname' to join a chat room. Joining a room will cause you"
    " to leave the current room")},
  {"/nick ", &do_nick,
   gettext_noop
   ("Use `/nick nickname' to change your nickname.  This will cause you to"
    " leave the current room and immediately rejoin it with the new name.")},
  {"/msg ", &do_send_pm,
   gettext_noop
   ("Use `/msg nickname message' to send a private message to the specified"
    " user")},
  {"/notice ", &do_send_pm,
   gettext_noop ("The `/notice' command is an alias for `/msg'")},
  {"/query ", &do_send_pm,
   gettext_noop ("The `/query' command is an alias for `/msg'")},
  {"/sig ", &do_send_sig,
   gettext_noop ("Use `/sig message' to send a signed public message")},
  {"/ack ", &do_send_ack,
   gettext_noop
   ("Use `/ack message' to require signed acknowledgment of the message")},
  {"/anonymous ", &do_send_anonymous,
   gettext_noop
   ("Use `/anonymous message' to send a public anonymous message")},
  {"/anon ", &do_send_anonymous,
   gettext_noop ("The `/anon' command is an alias for `/anonymous'")},
  {"/quit", &do_quit,
   gettext_noop ("Use `/quit' to terminate gnunet-chat")},
  {"/leave", &do_quit,
   gettext_noop ("The `/leave' command is an alias for `/quit'")},
  {"/names", &do_names,
   gettext_noop
   ("Use `/names' to list all of the current members in the chat room")},
  {"/help", &do_help,
   gettext_noop ("Use `/help command' to get help for a specific command")},
  /* Add standard commands:
   * /whois (print metadata),
   * /ignore (set flag, check on receive!) */
  /* the following three commands must be last! */
  {"/", &do_unknown, NULL},
  {"", &do_send, NULL},
  {NULL, NULL, NULL},
};


static int
do_help (const char *args, const void *xtra)
{
  int i;

  i = 0;
  while ((NULL != args) && (0 != strlen (args)) &&
         (commands[i].Action != &do_help))
  {
    if (0 == strncasecmp (&args[1], &commands[i].command[1], strlen (args) - 1))
    {
      FPRINTF (stdout, "%s\n", gettext (commands[i].helptext));
      return GNUNET_OK;
    }
    i++;
  }
  i = 0;
  FPRINTF (stdout, "%s",  "Available commands:");
  while (commands[i].Action != &do_help)
  {
    FPRINTF (stdout, " %s", gettext (commands[i].command));
    i++;
  }
  FPRINTF (stdout, "%s",  "\n");
  FPRINTF (stdout, "%s\n", gettext (commands[i].helptext));
  return GNUNET_OK;
}


static void
do_stop_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_CHAT_leave_room (room);
  if (handle_cmd_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (handle_cmd_task);
    handle_cmd_task = GNUNET_SCHEDULER_NO_TASK;
  }
  free_user_list ();
  GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_free (room_name);
  GNUNET_free (nickname);
}


void
handle_command (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
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
						(GNUNET_TIME_UNIT_MILLISECONDS, 100),
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
 * @param cls closure, NULL
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  GNUNET_HashCode me;
  char *my_name;

  cfg = c;
  /* check arguments */
  if (NULL == nickname)
  {
    FPRINTF (stderr, "%s",  _("You must specify a nickname\n"));
    ret = -1;
    return;
  }
  if (NULL == room_name)
    room_name = GNUNET_strdup ("gnunet");
  meta = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_CONTAINER_meta_data_insert (meta, "<gnunet>", EXTRACTOR_METATYPE_TITLE,
                                     EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                     nickname, strlen (nickname) + 1);
  room =
      GNUNET_CHAT_join_room (cfg, nickname, meta, room_name, -1, &join_cb, NULL,
                             &receive_cb, NULL, &member_list_cb, NULL,
                             &confirmation_cb, NULL, &me);
  if (NULL == room)
  {
    FPRINTF (stderr, _("Failed to join room `%s'\n"), room_name);
    GNUNET_free (room_name);
    GNUNET_free (nickname);
    GNUNET_CONTAINER_meta_data_destroy (meta);
    ret = -1;
    return;
  }
  my_name = GNUNET_PSEUDONYM_id_to_name (cfg, &me);
  FPRINTF (stdout, _("Joining room `%s' as user `%s'...\n"), room_name,
           my_name);
  GNUNET_free (my_name);
  handle_cmd_task =
      GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_UI,
                                          &handle_command, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &do_stop_task,
                                NULL);
}


/**
 * The main function to chat via GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int flags;

  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'n', "nick", "NAME",
     gettext_noop ("set the nickname to use (required)"),
     1, &GNUNET_GETOPT_set_string, &nickname},
    {'r', "room", "NAME",
     gettext_noop ("set the chat room to join"),
     1, &GNUNET_GETOPT_set_string, &room_name},
    GNUNET_GETOPT_OPTION_END
  };

#ifndef WINDOWS
  flags = fcntl (0, F_GETFL, 0);
  flags |= O_NONBLOCK;
  fcntl (0, F_SETFL, flags);
#endif
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-chat",
                              gettext_noop ("Join a chat on GNUnet."), options,
                              &run, NULL)) ? ret : 1;
}

/* end of gnunet-chat.c */
