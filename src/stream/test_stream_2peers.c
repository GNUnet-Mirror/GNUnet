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
 * @file stream/test_stream_2peers.c
 * @brief Stream API testing between 2 peers using testing API
 * @author Sree Harsha Totakura
 */

#include <string.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_mesh_service.h"
#include "gnunet_stream_lib.h"
#include "gnunet_testing_lib.h"

#define VERBOSE 1

/**
 * Number of peers
 */
#define NUM_PEERS 2

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
   * Peer's io write handle
   */
  struct GNUNET_STREAM_IOWriteHandle *io_write_handle;

  /**
   * Peer's io read handle
   */
  struct GNUNET_STREAM_IOReadHandle *io_read_handle;

  /**
   * Peer's shutdown handle
   */
  struct GNUNET_STREAM_ShutdownHandle *shutdown_handle;

  /**
   * Our Peer id
   */
  struct GNUNET_PeerIdentity our_id;

  /**
   * Bytes the peer has written
   */
  unsigned int bytes_wrote;

  /**
   * Byte the peer has read
   */
  unsigned int bytes_read;
};

/**
 * The current peer group
 */
static struct GNUNET_TESTING_PeerGroup *pg;

/**
 * Peer 1 daemon
 */
static struct GNUNET_TESTING_Daemon *d1;

/**
 * Peer 2 daemon
 */
static struct GNUNET_TESTING_Daemon *d2;

static struct PeerData peer1;
static struct PeerData peer2;
static struct GNUNET_STREAM_ListenSocket *peer2_listen_socket;
static struct GNUNET_CONFIGURATION_Handle *config;

static GNUNET_SCHEDULER_TaskIdentifier abort_task;

static char *data = "ABCD";
static int result;

static int writing_success;
static int reading_success;


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
                 size_t size);

/**
 * Task for calling STREAM_read
 *
 * @param cls the peer data entity
 * @param tc the task context
 */
static void
stream_read_task (void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerData *peer = cls;
  
  peer->io_read_handle = GNUNET_STREAM_read (peer->socket,
                                             GNUNET_TIME_relative_multiply
                                             (GNUNET_TIME_UNIT_SECONDS, 5),
                                             &input_processor,
                                             peer);
  GNUNET_assert (NULL != peer->io_read_handle);
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
                  size_t size);


/**
 * Task for calling STREAM_write
 *
 * @param cls the peer data entity
 * @param tc the task context
 */
static void
stream_write_task (void *cls,
                   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerData *peer = cls;
  
  peer->io_write_handle = 
    GNUNET_STREAM_write (peer->socket,
                         (void *) data,
                         strlen(data) - peer->bytes_wrote,
                         GNUNET_TIME_relative_multiply
                         (GNUNET_TIME_UNIT_SECONDS, 5),
                         &write_completion,
                         peer);
 
  GNUNET_assert (NULL != peer->io_write_handle);
 }


/**
 * Check whether peers successfully shut down.
 */
static void
peergroup_shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Shutdown of peers failed!\n");
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "All peers successfully shut down!\n");
  }
  GNUNET_CONFIGURATION_destroy (config);
}


/**
 * Close sockets and stop testing deamons nicely
 */
static void
do_close (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != peer1.socket)
    GNUNET_STREAM_close (peer1.socket);
  if (NULL != peer2.socket)
    GNUNET_STREAM_close (peer2.socket);
  if (NULL != peer2_listen_socket)
    GNUNET_STREAM_listen_close (peer2_listen_socket);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: shutdown\n");
  if (0 != abort_task)
  {
    GNUNET_SCHEDULER_cancel (abort_task);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Wait\n");

  GNUNET_TESTING_daemons_stop (pg,
                               GNUNET_TIME_relative_multiply
                               (GNUNET_TIME_UNIT_SECONDS, 5),
                               &peergroup_shutdown_callback,
                               NULL);
}


/**
 * Completion callback for shutdown
 *
 * @param cls the closure from GNUNET_STREAM_shutdown call
 * @param operation the operation that was shutdown (SHUT_RD, SHUT_WR,
 *          SHUT_RDWR) 
 */
static void 
shutdown_completion (void *cls,
                     int operation)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "STREAM shutdown successful\n");
  GNUNET_SCHEDULER_add_now (&do_close,
                            cls);
}



/**
 * Shutdown sockets gracefully
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  peer1.shutdown_handle = GNUNET_STREAM_shutdown (peer1.socket, 
                                                  SHUT_RDWR,
                                                  &shutdown_completion,
                                                  cls);
}


/**
 * Something went wrong and timed out. Kill everything and set error flag
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: ABORT\n");
  result = GNUNET_SYSERR;
  abort_task = 0;
  do_close (cls, tc);  
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
  struct PeerData *peer=cls;

  GNUNET_assert (GNUNET_STREAM_OK == status);
  GNUNET_assert (size <= strlen (data));
  peer->bytes_wrote += size;

  if (peer->bytes_wrote < strlen(data)) /* Have more data to send */
    {
      GNUNET_SCHEDULER_add_now (&stream_write_task, peer);
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Writing completed\n");

      if (&peer1 == peer)   /* Peer1 has finished writing; should read now */
        {
          peer->bytes_read = 0;
          GNUNET_SCHEDULER_add_now (&stream_read_task, peer);
        }
      else
        {
          writing_success = GNUNET_YES;
          if (GNUNET_YES == reading_success)
            GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
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
  struct PeerData *peer=cls;
  
  GNUNET_assert (&peer1 == peer);
  GNUNET_assert (socket == peer1.socket);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Stream established from peer1\n",
              GNUNET_i2s (&peer1.our_id));
  peer->bytes_wrote = 0;
  GNUNET_SCHEDULER_add_now (&stream_write_task, peer);
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

  if (GNUNET_STREAM_TIMEOUT == status)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Read operation timedout - reading again!\n");
      GNUNET_assert (0 == size);
      GNUNET_SCHEDULER_add_now (&stream_read_task, peer);
      return 0;
    }

  GNUNET_assert (GNUNET_STREAM_OK == status);
  GNUNET_assert (size <= strlen (data));
  GNUNET_assert (0 == strncmp ((const char *) data + peer->bytes_read, 
                               (const char *) input_data,
                               size));
  peer->bytes_read += size;
  
  if (peer->bytes_read < strlen (data))
    {
      GNUNET_SCHEDULER_add_now (&stream_read_task, peer);
    }
  else 
    {
      if (&peer2 == peer)    /* Peer2 has completed reading; should write */
        {
          peer->bytes_wrote = 0;
          GNUNET_SCHEDULER_add_now (&stream_write_task, peer);
        }
      else                      /* Peer1 has completed reading. End of tests */
        {
          reading_success = GNUNET_YES;
          if (GNUNET_YES == writing_success)
            GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
        }
    }
  return size;
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
  GNUNET_assert (NULL != initiator);
  GNUNET_assert (socket != peer1.socket);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Peer connected: %s\n",
              GNUNET_i2s (&peer2.our_id),
              GNUNET_i2s(initiator));

  peer2.socket = socket;
  peer2.bytes_read = 0;
  GNUNET_SCHEDULER_add_now (&stream_read_task, &peer2);
  return GNUNET_OK;
}


/**
 * Callback to be called when testing peer group is ready
 *
 * @param cls NULL
 * @param emsg NULL on success
 */
void
peergroup_ready (void *cls, const char *emsg)
{
  if (NULL != emsg)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Starting peer group failed: %s\n", emsg);
      return;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer group is now ready\n");
  
  GNUNET_assert (2 == GNUNET_TESTING_daemons_running (pg));
  
  d1 = GNUNET_TESTING_daemon_get (pg, 0);
  GNUNET_assert (NULL != d1);
  
  d2 = GNUNET_TESTING_daemon_get (pg, 1);
  GNUNET_assert (NULL != d2);

  GNUNET_TESTING_get_peer_identity (d1->cfg,
                                    &peer1.our_id);
  GNUNET_TESTING_get_peer_identity (d2->cfg,
                                    &peer2.our_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s : %s\n",
              GNUNET_i2s (&peer1.our_id),
              GNUNET_i2s (&d1->id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s : %s\n",
              GNUNET_i2s (&peer2.our_id),
              GNUNET_i2s (&d2->id));

  peer2_listen_socket = GNUNET_STREAM_listen (d2->cfg,
                                              10, /* App port */
                                              &stream_listen_cb,
                                              NULL);
  GNUNET_assert (NULL != peer2_listen_socket);

  /* Connect to stream library */
  peer1.socket = GNUNET_STREAM_open (d1->cfg,
                                     &d2->id,         /* Null for local peer? */
                                     10,           /* App port */
                                     &stream_open_cb,
                                     &peer1,
				     GNUNET_STREAM_OPTION_END);
  GNUNET_assert (NULL != peer1.socket);
}


/**
 * Initialize framework and start test
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_TESTING_Host *hosts; /* FIXME: free hosts (DLL) */

  GNUNET_log_setup ("test_stream_2peers",
                    "DEBUG",
                    NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting test\n");
  /* Duplicate the configuration */
  config = GNUNET_CONFIGURATION_dup (cfg);

  hosts = GNUNET_TESTING_hosts_load (config);
  
  pg = GNUNET_TESTING_peergroup_start (config,
                                       2,
                                       GNUNET_TIME_relative_multiply
                                       (GNUNET_TIME_UNIT_SECONDS, 3),
                                       NULL,
                                       &peergroup_ready,
                                       NULL,
                                       hosts);
  GNUNET_assert (NULL != pg);
                                       
  abort_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 40), &do_abort,
                                  NULL);
}

/**
 * Main function
 */
int main (int argc, char **argv)
{
  int ret;

  char *argv2[] = { "test-stream-2peers",
                    "-L", "DEBUG",
                    "-c", "test_stream_local.conf",
                    NULL};
  
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  ret =
      GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                          "test-stream-2peers", "nohelp", options, &run, NULL);

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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "test ok\n");
  return 0;
}
