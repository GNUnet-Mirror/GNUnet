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
 * @file stream/test_stream_big.c
 * @brief large data transfer using stream API between local peers
 * @author Sree Harsha Totakura
 */

#include <string.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_stream_lib.h"
#include "gnunet_testing_lib-new.h"

#define LOG(kind, ...)                         \
  GNUNET_log (kind, __VA_ARGS__);

#define TIME_REL_SECS(sec) \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, sec)


/**
 * Structure for holding peer's sockets and IO Handles
 */
struct PeerData
{
  /**
   * Peer's stream socket
   */
  struct GNUNET_STREAM_Socket *socket;

  struct GNUNET_PeerIdentity self;

  /**
   * Peer's io write handle
   */
  struct GNUNET_STREAM_IOWriteHandle *io_write_handle;

  /**
   * Peer's io read handle
   */
  struct GNUNET_STREAM_IOReadHandle *io_read_handle;

  /**
   * Bytes the peer has written
   */
  unsigned int bytes_wrote;

  /**
   * Byte the peer has read
   */
  unsigned int bytes_read;
};

static struct PeerData peer1;
static struct PeerData peer2;
static struct GNUNET_STREAM_ListenSocket *peer2_listen_socket;
static const struct GNUNET_CONFIGURATION_Handle *config;

static GNUNET_SCHEDULER_TaskIdentifier abort_task;
static GNUNET_SCHEDULER_TaskIdentifier test_task;
static GNUNET_SCHEDULER_TaskIdentifier read_task;
static GNUNET_SCHEDULER_TaskIdentifier write_task;

#define DATA_SIZE 65536      /* 64KB */
static uint32_t data[DATA_SIZE / 4];     /* 64KB array */
static int result;

/**
 * Shutdown nicely
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_STREAM_close (peer1.socket);
  if (NULL != peer2.socket)
    GNUNET_STREAM_close (peer2.socket);
  if (NULL != peer2_listen_socket)
    GNUNET_STREAM_listen_close (peer2_listen_socket); /* Close listen socket */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: shutdown\n");
  if (0 != abort_task)
  {
    GNUNET_SCHEDULER_cancel (abort_task);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Wait\n");
  GNUNET_SCHEDULER_shutdown ();
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
  GNUNET_assert (size <= DATA_SIZE);
  peer->bytes_wrote += size;

  if (peer->bytes_wrote < DATA_SIZE) /* Have more data to send */
    {
      peer->io_write_handle =
        GNUNET_STREAM_write (peer->socket,
                             ((void *) data) + peer->bytes_wrote,
			     sizeof (data) - peer->bytes_wrote,
                             GNUNET_TIME_relative_multiply
                             (GNUNET_TIME_UNIT_SECONDS, 5),
                             &write_completion,
                             cls);
      GNUNET_assert (NULL != peer->io_write_handle);
    }
  else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Writing successfully finished\n");
      result = GNUNET_OK;
      GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    }
}


/**
 * Task for calling STREAM_write with a chunk of random data
 *
 * @param cls the peer data entity
 * @param tc the task context
 */
static void
stream_write_task (void *cls,
                   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerData *peer=cls;
  unsigned int count;

  write_task = GNUNET_SCHEDULER_NO_TASK;
  for (count=0; count < DATA_SIZE / 4; count++)
    {
      data[count]=GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                            UINT32_MAX);
    }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Generation of random data complete\n");
  peer->io_write_handle = GNUNET_STREAM_write (peer->socket,
                                               data,
                                               sizeof (data),
                                               GNUNET_TIME_relative_multiply
                                               (GNUNET_TIME_UNIT_SECONDS, 10),
                                               &write_completion,
                                               peer);
  GNUNET_assert (NULL != peer->io_write_handle);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stream established from peer1\n");
  peer = (struct PeerData *) cls;
  peer->bytes_wrote = 0;
  GNUNET_assert (socket == peer1.socket);
  GNUNET_assert (socket == peer->socket);
  write_task = GNUNET_SCHEDULER_add_now (&stream_write_task, peer);
}


/**
 * Scheduler call back; to be executed when a new stream is connected
 * Called from listen connect for peer2
 */
static void
stream_read_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Input processor
 *
 * @param cls peer2
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
  struct PeerData *peer = cls;

  GNUNET_assert (GNUNET_STREAM_OK == status);
  GNUNET_assert (&peer2 == peer);
  GNUNET_assert (size < DATA_SIZE);
  GNUNET_assert (0 == memcmp (((void *)data ) + peer->bytes_read, 
			      input_data, size));
  peer->bytes_read += size;
  
  if (peer->bytes_read < DATA_SIZE)
  {
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == read_task);
    read_task = GNUNET_SCHEDULER_add_now (&stream_read_task, &peer2);
    /* peer->io_read_handle = GNUNET_STREAM_read ((struct GNUNET_STREAM_Socket *) */
    /*                                            peer->socket, */
    /*                                            GNUNET_TIME_relative_multiply */
    /*                                            (GNUNET_TIME_UNIT_SECONDS, 5), */
    /*                                            &input_processor, */
    /*                                            cls); */
    /* GNUNET_assert (NULL != peer->io_read_handle); */
  }
  else 
  {
    /* Peer2 has completed reading*/
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Reading finished successfully\n");
  } 
  return size;
}

  
/**
 * Scheduler call back; to be executed when a new stream is connected
 * Called from listen connect for peer2
 */
static void
stream_read_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerData *peer = cls;

  read_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (&peer2 == peer);  
  peer->io_read_handle =
    GNUNET_STREAM_read (peer->socket,
                        GNUNET_TIME_relative_multiply
                        (GNUNET_TIME_UNIT_SECONDS, 10),
                        &input_processor,
                        peer);
  GNUNET_assert (NULL != peer->io_read_handle);
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
  GNUNET_assert (socket != peer1.socket);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer connected: %s\n", GNUNET_i2s(initiator));

  peer2.socket = socket;
  peer2.bytes_read = 0;
  read_task = GNUNET_SCHEDULER_add_now (&stream_read_task, &peer2);
  return GNUNET_OK;
}


/**
 * Listen success callback; connects a peer to stream as client
 */
static void
stream_connect (void)
{
  struct PeerData *peer = &peer1;

  /* Connect to stream */
  peer->socket = GNUNET_STREAM_open (config,
                                     &peer2.self,         /* Null for local peer? */
                                     10,           /* App port */
                                     &stream_open_cb, &peer1,
				     GNUNET_STREAM_OPTION_MAX_PAYLOAD_SIZE, 500,
				     GNUNET_STREAM_OPTION_END);
  GNUNET_assert (NULL != peer->socket);
}


/**
 * Initialize framework and start test
 *
 * @param cls closure
 * @param cfg configuration of the peer that was started
 * @param peer identity of the peer that was created
 */
static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_PeerIdentity self;
  
  GNUNET_TESTING_peer_get_identity (peer, &self);
  config = cfg;  
  peer2_listen_socket = 
    GNUNET_STREAM_listen (config,
                          10, /* App port */
                          &stream_listen_cb,
                          NULL,
                          GNUNET_STREAM_OPTION_SIGNAL_LISTEN_SUCCESS,
                          &stream_connect,
                          GNUNET_STREAM_OPTION_END);
  GNUNET_assert (NULL != peer2_listen_socket);
  peer1.self = self;
  peer2.self = self;
  abort_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 60), &do_abort,
                                  NULL);
}

/**
 * Main function
 */
int main (int argc, char **argv)
{
  if (0 != GNUNET_TESTING_peer_run ("test_stream_big",
				    "test_stream_local.conf",
				    &run, NULL))
    return 1;
  return (GNUNET_SYSERR == result) ? 1 : 0;
}

/* end of test_stream_big.c */
