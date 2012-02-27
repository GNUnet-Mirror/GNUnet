/*
     This file is part of GNUnet.
     (C) 2005, 2006, 2007, 2008, 2011 Christian Grothoff (and other contributing authors)

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
 * @file chat/test_chat.c
 * @brief base test case for the chat library
 * @author Christian Grothoff
 * @author Nathan Evans
 * @author Vitaly Minko
 *
 * This test case serves as a base for simple chatting, anonymous chatting,
 * authenticated chatting and acknowledgements test cases.  Based on the
 * executable being run the correct test case will be performed.  Private
 * chatting is covered by a separate test case since it requires 3 users.
 */

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_chat_service.h"

#define VERBOSE GNUNET_NO

#define START_ARM GNUNET_YES

/**
 * How long until we give up on passing the test?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
#if START_ARM
  struct GNUNET_OS_Process *arm_proc;
#endif
};

struct Wanted
{
  struct GNUNET_CONTAINER_MetaData *meta;

  GNUNET_HashCode *sender;

  char *msg;

  const char *me;

  enum GNUNET_CHAT_MsgOptions opt;

  uint32_t sequence_number;

  struct GNUNET_TIME_Absolute timestamp;

  GNUNET_SCHEDULER_Task next_task;

  void *next_task_cls;

};

static struct PeerContext p1;

static struct PeerContext p2;

static GNUNET_HashCode alice;

static GNUNET_HashCode bob;

static struct GNUNET_CHAT_Room *alice_room;

static struct GNUNET_CHAT_Room *bob_room;

static struct GNUNET_CONTAINER_MetaData *alice_meta;

static struct GNUNET_CONTAINER_MetaData *bob_meta;

static struct Wanted alice_wanted;

static struct Wanted bob_wanted;

static GNUNET_SCHEDULER_TaskIdentifier kill_task;

static GNUNET_SCHEDULER_TaskIdentifier wait_task;

static int err;

static int is_ready;

static int is_p2p;

static int is_ackn;

static int is_anon;

static int is_auth;


static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_proc =
      GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm",
#if VERBOSE
                               "-L", "DEBUG",
#endif
                               "-c", cfgname, NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
}


static void
stop_arm (struct PeerContext *p)
{
#if START_ARM
  if (0 != GNUNET_OS_process_kill (p->arm_proc, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  if (GNUNET_OS_process_wait (p->arm_proc) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ARM process %u stopped\n",
              GNUNET_OS_process_get_pid (p->arm_proc));
  GNUNET_OS_process_close (p->arm_proc);
  p->arm_proc = NULL;
#endif
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


static void
abort_test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (alice_room != NULL)
  {
    GNUNET_CHAT_leave_room (alice_room);
    alice_room = NULL;
  }
  if (bob_room != NULL)
  {
    GNUNET_CHAT_leave_room (bob_room);
    bob_room = NULL;
  }
  err = 1;
}


static void
timeout_kill (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#if VERBOSE
  printf ("Timed out, stopping the test.\n");
#endif
  kill_task = GNUNET_SCHEDULER_NO_TASK;
  if (wait_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (wait_task);
    wait_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_SCHEDULER_add_continuation (&abort_test, NULL,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static int
join_cb (void *cls)
{
  struct Wanted *want = cls;

#if VERBOSE
  printf ("%s has joined\n", want->me);
#endif
  if (NULL != want->next_task)
    GNUNET_SCHEDULER_add_now (want->next_task, want->next_task_cls);
  return GNUNET_OK;
}


static int
member_list_cb (void *cls, const struct GNUNET_CONTAINER_MetaData *member_info,
                const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *member_id,
                enum GNUNET_CHAT_MsgOptions options)
{
  struct Wanted *want = cls;
  GNUNET_HashCode sender;

#if VERBOSE
  printf ("%s - told that %s has %s\n", want->me,
          member_info ==
          NULL ? NULL : GNUNET_CONTAINER_meta_data_get_by_type (member_info,
                                                                EXTRACTOR_METATYPE_TITLE),
          member_info == NULL ? "left" : "joined");
#endif
  GNUNET_CRYPTO_hash (member_id,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &sender);
  if ((0 == memcmp (&sender, want->sender, sizeof (GNUNET_HashCode))) &&
      (((member_info == NULL) && (want->meta == NULL)) ||
       ((member_info != NULL) && (want->meta != NULL) &&
        (GNUNET_CONTAINER_meta_data_test_equal (member_info, want->meta)))) &&
      (options == want->opt))
  {
    if (NULL != want->next_task)
      GNUNET_SCHEDULER_add_now (want->next_task, want->next_task_cls);
  }
  else
  {
    GNUNET_SCHEDULER_cancel (kill_task);
    kill_task = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_SCHEDULER_add_now (&abort_test, NULL);
  }
  return GNUNET_OK;
}


static int
receive_cb (void *cls, struct GNUNET_CHAT_Room *room,
            const GNUNET_HashCode * sender,
            const struct GNUNET_CONTAINER_MetaData *meta, const char *message,
            struct GNUNET_TIME_Absolute timestamp,
            enum GNUNET_CHAT_MsgOptions options)
{
  struct Wanted *want = cls;

#if VERBOSE
  printf ("%s - told that %s said %s\n", want->me,
          meta == NULL ? NULL : GNUNET_CONTAINER_meta_data_get_by_type (meta,
                                                                        EXTRACTOR_METATYPE_TITLE),
          message);
#endif
  if ((0 == strcmp (message, want->msg)) &&
      (((sender == NULL) && (want->sender == NULL)) ||
       ((sender != NULL) && (want->sender != NULL) &&
        (0 == memcmp (sender, want->sender, sizeof (GNUNET_HashCode))))) &&
      (GNUNET_CONTAINER_meta_data_test_equal (meta, want->meta)) &&
      (options == want->opt) &&
      /* Not == since the library sets the actual timestamp, so it may be
       * slightly greater
       */
      (timestamp.abs_value >= want->timestamp.abs_value))
  {
    if (NULL != want->next_task)
      GNUNET_SCHEDULER_add_now (want->next_task, want->next_task_cls);
  }
  else
  {
    GNUNET_SCHEDULER_cancel (kill_task);
    kill_task = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_SCHEDULER_add_now (&abort_test, NULL);
  }
  return GNUNET_OK;
}


static int
confirmation_cb (void *cls, struct GNUNET_CHAT_Room *room,
                 uint32_t orig_seq_number,
                 struct GNUNET_TIME_Absolute timestamp,
                 const GNUNET_HashCode * receiver)
{
  struct Wanted *want = cls;

#if VERBOSE
  printf ("%s - told that %s acknowledged message #%d\n", want->me,
          GNUNET_CONTAINER_meta_data_get_by_type (want->meta,
                                                  EXTRACTOR_METATYPE_TITLE),
          orig_seq_number);
#endif
  if ((0 == memcmp (receiver, want->sender, sizeof (GNUNET_HashCode))) &&
      (orig_seq_number == want->sequence_number) &&
      (timestamp.abs_value >= want->timestamp.abs_value))
  {
    if (NULL != want->next_task)
      GNUNET_SCHEDULER_add_now (want->next_task, want->next_task_cls);
  }
  else
  {
    GNUNET_SCHEDULER_cancel (kill_task);
    kill_task = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_SCHEDULER_add_now (&abort_test, NULL);
  }
  return GNUNET_OK;
}


static void
wait_until_ready (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_SCHEDULER_Task task = cls;

#if VERBOSE
  printf ("Waiting...\n");
#endif
  if (is_ready)
  {
    wait_task = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_SCHEDULER_add_now (task, NULL);
  }
  else
    wait_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_MILLISECONDS, 50),
                                      &wait_until_ready, task);
}


static void
disconnect_alice (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#if VERBOSE
  printf ("Alice is leaving.\n");
#endif
  if (is_p2p)
    stop_arm (&p2);
  GNUNET_CHAT_leave_room (alice_room);
  alice_room = NULL;
  GNUNET_SCHEDULER_cancel (kill_task);
  kill_task = GNUNET_SCHEDULER_NO_TASK;
}


static void
disconnect_bob (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#if VERBOSE
  printf ("Bod is leaving.\n");
#endif
  alice_wanted.meta = NULL;
  alice_wanted.sender = &bob;
  alice_wanted.msg = NULL;
  alice_wanted.opt = 0;
  alice_wanted.next_task = &disconnect_alice;
  alice_wanted.next_task_cls = NULL;
  GNUNET_CHAT_leave_room (bob_room);
  bob_room = NULL;
}


static void
set_ready (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  is_ready = GNUNET_YES;
}


static void
send_to_alice (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#if VERBOSE
  printf ("Bob says 'Hi!'\n");
#endif

  alice_wanted.meta = bob_meta;
  alice_wanted.sender = &bob;
  alice_wanted.msg = "Hi Alice!";
  alice_wanted.opt = GNUNET_CHAT_MSG_OPTION_NONE;
  alice_wanted.timestamp = GNUNET_TIME_absolute_get ();
  alice_wanted.next_task = &disconnect_bob;
  alice_wanted.next_task_cls = NULL;
  GNUNET_CHAT_send_message (bob_room, "Hi Alice!", GNUNET_CHAT_MSG_OPTION_NONE,
                            NULL, NULL);
}


static void
send_to_bob (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  enum GNUNET_CHAT_MsgOptions options;
  uint32_t *seq = NULL;

#if VERBOSE
  printf ("Alice says 'Hi!'\n");
#endif
  if (is_ackn)
  {
    options = GNUNET_CHAT_MSG_ACKNOWLEDGED;
    alice_wanted.meta = bob_meta;
    alice_wanted.sender = &bob;
    alice_wanted.timestamp = GNUNET_TIME_absolute_get ();
    alice_wanted.next_task = &disconnect_bob;
    alice_wanted.next_task_cls = NULL;
    bob_wanted.meta = alice_meta;
    bob_wanted.sender = &alice;
    bob_wanted.next_task = NULL;
    seq = &(alice_wanted.sequence_number);
  }
  else if (is_anon)
  {
    options = GNUNET_CHAT_MSG_ANONYMOUS;
    bob_wanted.meta = NULL;
    bob_wanted.sender = NULL;
    bob_wanted.next_task = &disconnect_bob;
  }
  else if (is_auth)
  {
    options = GNUNET_CHAT_MSG_AUTHENTICATED;
    bob_wanted.meta = alice_meta;
    bob_wanted.sender = &alice;
    bob_wanted.next_task = &disconnect_bob;
  }
  else
  {
    options = GNUNET_CHAT_MSG_OPTION_NONE;
    bob_wanted.meta = alice_meta;
    bob_wanted.sender = &alice;
    bob_wanted.next_task = &send_to_alice;
  }
  bob_wanted.msg = "Hi Bob!";
  bob_wanted.opt = options;
  bob_wanted.timestamp = GNUNET_TIME_absolute_get ();
  bob_wanted.next_task_cls = NULL;
  GNUNET_CHAT_send_message (alice_room, "Hi Bob!", options, NULL, seq);
}


static void
prepare_for_alice_task (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  bob_wanted.meta = alice_meta;
  bob_wanted.sender = &alice;
  bob_wanted.msg = NULL;
  bob_wanted.opt = -1;
  bob_wanted.next_task = &set_ready;
  bob_wanted.next_task_cls = NULL;
}


static void
join_bob_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#if VERBOSE
  printf ("Bob joining\n");
#endif
  alice_wanted.meta = bob_meta;
  alice_wanted.sender = &bob;
  alice_wanted.msg = NULL;
  alice_wanted.opt = -1;
  alice_wanted.next_task = &wait_until_ready;
  alice_wanted.next_task_cls = &send_to_bob;
  bob_wanted.next_task = &prepare_for_alice_task;
  bob_wanted.next_task_cls = NULL;
  is_ready = GNUNET_NO;
  bob_room =
      GNUNET_CHAT_join_room (is_p2p ? p2.cfg : p1.cfg, "bob", bob_meta, "test",
                             -1, &join_cb, &bob_wanted, &receive_cb,
                             &bob_wanted, &member_list_cb, &bob_wanted,
                             &confirmation_cb, &bob_wanted, &bob);
  if (NULL == bob_room)
  {
    GNUNET_SCHEDULER_cancel (kill_task);
    kill_task = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_CHAT_leave_room (alice_room);
    alice_room = NULL;
    err = 1;
  }
}


static void
join_alice_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#if VERBOSE
  printf ("Alice joining\n");
#endif
  alice_wanted.next_task = &join_bob_task;
  alice_wanted.next_task_cls = NULL;
  alice_room =
      GNUNET_CHAT_join_room (p1.cfg, "alice", alice_meta, "test", -1, &join_cb,
                             &alice_wanted, &receive_cb, &alice_wanted,
                             &member_list_cb, &alice_wanted, &confirmation_cb,
                             &alice_wanted, &alice);
  if (NULL == alice_room)
  {
    GNUNET_SCHEDULER_cancel (kill_task);
    kill_task = GNUNET_SCHEDULER_NO_TASK;
    err = 1;
  }
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  if (is_p2p)
  {
    setup_peer (&p1, "test_chat_peer1.conf");
    setup_peer (&p2, "test_chat_peer2.conf");
  }
  else
    setup_peer (&p1, "test_chat_data.conf");

  memset (&alice_wanted, 0, sizeof (struct Wanted));
  memset (&bob_wanted, 0, sizeof (struct Wanted));
  alice_wanted.me = "Alice";
  bob_wanted.me = "Bob";
  alice_meta = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_CONTAINER_meta_data_insert (alice_meta, "<gnunet>",
                                     EXTRACTOR_METATYPE_TITLE,
                                     EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                     "Alice", strlen ("Alice") + 1);
  bob_meta = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_CONTAINER_meta_data_insert (bob_meta, "<gnunet>",
                                     EXTRACTOR_METATYPE_TITLE,
                                     EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                     "Bob", strlen ("Bob") + 1);
  kill_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &timeout_kill, NULL);
  GNUNET_SCHEDULER_add_now (&join_alice_task, NULL);
}


int
main (int argc, char *argv[])
{
  char *const argvx[] = {
    "test-chat",
    "-c",
    "test_chat_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_log_setup ("test_chat",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  if (strstr (argv[0], "p2p") != NULL)
  {
    is_p2p = GNUNET_YES;
  }
  if (strstr (argv[0], "acknowledgment") != NULL)
  {
    is_ackn = GNUNET_YES;
  }
  else if (strstr (argv[0], "anonymous") != NULL)
  {
    is_anon = GNUNET_YES;
  }
  else if (strstr (argv[0], "authentication") != NULL)
  {
    is_auth = GNUNET_YES;
  }
  GNUNET_PROGRAM_run ((sizeof (argvx) / sizeof (char *)) - 1, argvx,
                      "test-chat", "nohelp", options, &run, NULL);
  stop_arm (&p1);
  GNUNET_CONTAINER_meta_data_destroy (alice_meta);
  GNUNET_CONTAINER_meta_data_destroy (bob_meta);
  if (is_p2p)
  {
    GNUNET_DISK_directory_remove ("/tmp/gnunet-test-chat-peer-1/");
    GNUNET_DISK_directory_remove ("/tmp/gnunet-test-chat-peer-2/");
  }
  else
    GNUNET_DISK_directory_remove ("/tmp/gnunet-test-chat/");
  return err;
}

/* end of test_chat.c */
