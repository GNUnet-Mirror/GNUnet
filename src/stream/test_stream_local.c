/*
     This file is part of GNUnet.
     (C) 2011, 2012 Christian Grothoff (and other contributing authors)

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
 * @file stream/test_stream_local.c
 * @brief Stream API testing between local peers
 * @author Sree Harsha Totakura
 */

#include <string.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_mesh_service.h"
#include "gnunet_stream_lib.h"

#define VERBOSE 1

/**
 * Structure for holding peer's sockets and IO Handles
 */
struct PeerData
{
  /**
   * Peer's stream socket
   */
  struct GNUNET_STREAM_Socket *socket;

  /**
   * Peer's io handle
   */
  struct GNUNET_STREAM_IOHandle *io_handle;

  /**
   * Bytes the peer has written
   */
  unsigned int bytes_wrote;

  /**
   * Byte the peer has read
   */
  unsigned int bytes_read;
};

static struct GNUNET_OS_Process *arm_pid;
static struct PeerData peer1;
static struct PeerData peer2;
static struct GNUNET_STREAM_ListenSocket *peer2_listen_socket;

static GNUNET_SCHEDULER_TaskIdentifier abort_task;
static GNUNET_SCHEDULER_TaskIdentifier test_task;
static GNUNET_SCHEDULER_TaskIdentifier read_task;

static char *data = "ABCD";
static int result;

/**
 * Shutdown nicely
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_STREAM_close (peer1.socket);
  GNUNET_STREAM_close (peer2.socket);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: shutdown\n");
  if (0 != abort_task)
  {
    GNUNET_SCHEDULER_cancel (abort_task);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: arm\n");
  if (0 != GNUNET_OS_process_kill (arm_pid, SIGTERM))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Wait\n");
  GNUNET_assert (GNUNET_OK == GNUNET_OS_process_wait (arm_pid));
  GNUNET_OS_process_close (arm_pid);
}


/**
 * Something went wrong and timed out. Kill everything and set error flag
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: ABORT\n");
  if (0 != test_task)
  {
    GNUNET_SCHEDULER_cancel (test_task);
  }
  if (0 != read_task)
    {
      GNUNET_SCHEDULER_cancel (read_task);
    }
  result = GNUNET_SYSERR;
  abort_task = 0;
  do_shutdown (cls, tc);
}


/**
 * The write completion function; called upon writing some data to stream or
 * upon error
 *
 * @param cls the closure from GNUNET_STREAM_write/read
 * @param status the status of the stream at the time this function is called
 * @param size the number of bytes read or written
 */
static void 
write_completion (void *cls,
                  enum GNUNET_STREAM_Status status,
                  size_t size)
{
  struct PeerData *peer;

  peer = (struct PeerData *) cls;
  GNUNET_assert (GNUNET_STREAM_OK == status);
  GNUNET_assert (size < strlen (data));
  peer->bytes_wrote += size;

  if (peer->bytes_wrote < strlen(data)) /* Have more data to send */
    {
      peer->io_handle = GNUNET_STREAM_write (peer->socket,
                                             (void *) data,
                                             strlen(data) - peer->bytes_wrote,
                                             GNUNET_TIME_relative_multiply
                                             (GNUNET_TIME_UNIT_SECONDS, 5),
                                             &write_completion,
                                             cls);
      GNUNET_assert (NULL != peer->io_handle);
    }
  else
    {
      if (&peer1 == peer)   /* Peer1 has finished writing; should read now */
        {
          peer->io_handle = GNUNET_STREAM_read ((struct GNUNET_STREAM_Socket *)
                                                peer->socket,
                                                GNUNET_TIME_relative_multiply
                                                (GNUNET_TIME_UNIT_SECONDS, 5),
                                                &input_processor,
                                                cls);
          GNUNET_assert (NULL!=peer->io_handle);
        }
    }
}


/**
 * Function executed after stream has been established
 *
 * @param cls the closure from GNUNET_STREAM_open
 * @param socket socket to use to communicate with the other side (read/write)
 */
static void 
stream_open_cb (void *cls,
                struct GNUNET_STREAM_Socket *socket)
{
  struct PeerData *peer;

  peer = (struct PeerData *) cls;
  peer->bytes_wrote = 0;
  GNUNET_assert (socket == peer1.socket);
  GNUNET_assert (socket == peer->socket);
  peer->io_handle = GNUNET_STREAM_write (peer->socket, /* socket */
                                         (void *) data, /* data */
                                         strlen(data),
                                         GNUNET_TIME_relative_multiply
                                         (GNUNET_TIME_UNIT_SECONDS, 5),
                                         &write_completion,
                                         cls);
  GNUNET_assert (NULL != peer->io_handle);
}


/**
 * Input processor
 *
 * @param cls the closure from GNUNET_STREAM_write/read
 * @param status the status of the stream at the time this function is called
 * @param data traffic from the other side
 * @param size the number of bytes available in data read 
 * @return number of bytes of processed from 'data' (any data remaining should be
 *         given to the next time the read processor is called).
 */
static size_t
input_processor (void *cls,
                 enum GNUNET_STREAM_Status status,
                 const void *input_data,
                 size_t size)
{
  struct PeerData *peer;

  peer = (struct PeerData *) cls;

  GNUNET_assert (GNUNET_STERAM_OK == status);
  GNUNET_assert (size < strlen (data));
  GNUNET_assert (strncmp ((const char *) data + peer->bytes_read, 
                          (const char *) input_data,
                          size));
  peer->bytes_read += size;
  
  if (peer->bytes_read < strlen (data))
    {
      peer->io_handle = GNUNET_STREAM_read ((struct GNUNET_STREAM_Socket *)
                                            peer->socket,
                                            GNUNET_TIME_relative_multiply
                                            (GNUNET_TIME_UNIT_SECONDS, 5),
                                            &input_processor,
                                            cls);
      GNUNET_assert (NULL != peer->io_handle);
    }
  else 
    {
      if (&peer2 == peer)    /* Peer2 has completed reading; should write */
        {
          peer->bytes_wrote = 0;
          peer->io_handle = GNUNET_STREAM_write ((struct GNUNET_STREAM_Socket *)
                                                 peer->socket,
                                                 (void *) data,
                                                 strlen(data),
                                                 GNUNET_TIME_relative_multiply
                                                 (GNUNET_TIME_UNIT_SECONDS, 5),
                                                 &write_completion,
                                                 cls);
        }
      else                      /* Peer1 has completed reading. End of tests */
        {
          GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
        }
    } 
  return size;
}

  
/**
 * Scheduler call back; to be executed when a new stream is connected
 * Called from listen connect for peer2
 */
static void
stream_read (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  read_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (NULL != cls);
  peer2.bytes_read = 0;
  GNUNET_STREAM_listen_close (peer2_listen_socket); /* Close listen socket */
  peer2.io_handle = GNUNET_STREAM_read ((struct GNUNET_STREAM_Socket *) cls,
                                        GNUNET_TIME_relative_multiply
                                        (GNUNET_TIME_UNIT_SECONDS, 5),
                                        &input_processor,
                                        (void *) &peer2);
  GNUNET_assert (NULL != peer2.io_handle);
}


/**
 * Functions of this type are called upon new stream connection from other peers
 *
 * @param cls the closure from GNUNET_STREAM_listen
 * @param socket the socket representing the stream
 * @param initiator the identity of the peer who wants to establish a stream
 *            with us
 * @return GNUNET_OK to keep the socket open, GNUNET_SYSERR to close the
 *             stream (the socket will be invalid after the call)
 */
static int
stream_listen_cb (void *cls,
           struct GNUNET_STREAM_Socket *socket,
           const struct GNUNET_PeerIdentity *initiator)
{
  GNUNET_assert (NULL != socket);
  GNUNET_assert (NULL == initiator);   /* Local peer=NULL? */
  GNUNET_assert (socket != peer1.socket);

  peer2.socket = socket;
  read_task = GNUNET_SCHEDULER_add_now (&stream_read, (void *) socket);
  return GNUNET_OK;
}


/**
 * Testing function
 */
static void
test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  test_task = GNUNET_SCHEDULER_NO_TASK;

  /* Connect to stream library */
  peer1.socket = GNUNET_STREAM_open (NULL,         /* Null for local peer? */
                                     10,           /* App port */
                                     &stream_open_cb,
                                     (void *) &peer1);
  GNUNET_assert (NULL != peer1.socket);
  peer2_listen_socket = GNUNET_STREAM_listen (10 /* App port */
                                              &stream_listen_cb,
                                              NULL);
  GNUNET_assert (NULL != peer2_listen_socket);
                  
}

/**
 * Initialize framework and start test
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
   GNUNET_log_setup ("test_stream_local",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
   arm_pid =
     GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                              "gnunet-service-arm",
#if VERBOSE_ARM
                              "-L", "DEBUG",
#endif
                              "-c", "test_stream_local.conf", NULL);

   abort_task =
     GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                   (GNUNET_TIME_UNIT_SECONDS, 20), &do_abort,
                                    NULL);

   test_task = GNUNET_SCHEDULER_add_now (&test, (void *) cfg);

}

/**
 * Main function
 */
int main (int argc, char **argv)
{
  int ret;

  char *const argv2[] = { "test-stream-local",
                          "-c", "test_stream.conf",
#if VERBOSE
                          "-L", "DEBUG",
#endif
                          NULL
  };
  
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  
  ret =
      GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                          "test-stream-local", "nohelp", options, &run, NULL);

  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "run failed with error code %d\n",
                ret);
    return 1;
  }
  if (GNUNET_SYSERR == result)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "test failed\n");
    return 1;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test ok\n");
  return 0;
}
