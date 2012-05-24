/*
 This file is part of GNUnet.
 (C) 2010, 2012 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-helper-transport-wlan-dummy.c
 * @brief helper for the testcases for plugin_transport_wlan.c
 * @author David Brodski
 */
#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"
#include "plugin_transport_wlan.h"

/**
 * Name of the fifo to use for IPC with the other dummy process.
 */
#define FIFO_FILE1 "/tmp/test-transport/api-wlan-p1/WLAN_FIFO_in"

/**
 * Name of the fifo to use for IPC with the other dummy process.
 */
#define FIFO_FILE2 "/tmp/test-transport/api-wlan-p1/WLAN_FIFO_out"

/**
 * Maximum size of a message allowed in either direction
 * (used for our receive and sent buffers).
 */
#define MAXLINE 4096


/**
 * IO buffer used for buffering data in transit.
 */
struct SendBuffer
{

  /**
   * How many bytes that were stored in 'buf' did we already write to the
   * destination?  Always smaller than 'size'.
   */
  size_t pos;

  /**
   * How many bytes of data are stored in 'buf' for transmission right now?
   * Data always starts at offset 0 and extends to 'size'.
   */
  size_t size;

  /**
   * Buffered data; twice the maximum allowed message size as we add some
   * headers.
   */
  char buf[MAXLINE * 2];
};


/**
 * Flag set to 1 if we are to terminate, otherwise 0.
 */
static int closeprog;


/**
 * We're being killed, clean up.
 *
 * @param sig killing signal
 */
static void
sigfunc (int sig)
{
  closeprog = 1;
  (void) unlink (FIFO_FILE1);
  (void) unlink (FIFO_FILE2);
}


/**
 * Create control message for plugin
 *
 * @param buffer pointer to buffer for the message
 * @param mac pointer to the mac address
 * @return number of bytes written
 */
static int
send_mac_to_plugin (char *buffer, struct GNUNET_TRANSPORT_WLAN_MacAddress *mac)
{

  struct GNUNET_TRANSPORT_WLAN_HelperControlMessage macmsg;

  memcpy (&macmsg.mac, (char *) mac, sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress));
  macmsg.hdr.size = htons (sizeof (struct GNUNET_TRANSPORT_WLAN_HelperControlMessage));
  macmsg.hdr.type = htons (GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL);
  memcpy (buffer, &macmsg, sizeof (struct GNUNET_TRANSPORT_WLAN_HelperControlMessage));
  return sizeof (struct GNUNET_TRANSPORT_WLAN_HelperControlMessage);
}


/**
 * We got a message from the FIFO, check it, convert the message
 * type to the output forward and copy it to the buffer for stdout.
 *
 * @param cls the 'struct SendBuffer' to copy the converted message to
 * @param client unused
 * @param hdr inbound message from the FIFO
 */
static int
stdin_send (void *cls, void *client, const struct GNUNET_MessageHeader *hdr)
{
  struct SendBuffer *write_pout = cls;
  const struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *in;
  size_t payload_size;
  struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage newheader;
  uint16_t sendsize;

  sendsize = ntohs (hdr->size);
  in = (const struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *) hdr;
  if ( (GNUNET_MESSAGE_TYPE_WLAN_DATA_TO_HELPER != ntohs (hdr->type)) ||
       (sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage) > sendsize) )
  {
    FPRINTF (stderr, "%s", "Received malformed message\n");
    exit (1);
  }
  payload_size = sendsize - sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage);
  if ((payload_size + sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage) + write_pout->size) > MAXLINE * 2)
  {
    FPRINTF (stderr, "%s",  "Packet too big for buffer\n");
    exit (1);
  }
  memset (&newheader, 0, sizeof (newheader));
  newheader.header.size = htons (payload_size + sizeof (newheader));
  newheader.header.type = htons (GNUNET_MESSAGE_TYPE_WLAN_DATA_FROM_HELPER);
  newheader.frame = in->frame;
  memcpy (write_pout->buf + write_pout->size,
	  &newheader,
	  sizeof (newheader));
  write_pout->size += sizeof (newheader);
  memcpy (write_pout->buf + write_pout->size,
	  &in[1],
	  payload_size);
  write_pout->size += payload_size;
  return GNUNET_OK;
}


/**
 * We read a full message from stdin.  Copy it to our send buffer.
 *
 * @param cls the 'struct SendBuffer' to copy to
 * @param client unused
 * @param hdr the message we received to copy to the buffer
 */
static int
file_in_send (void *cls, void *client, const struct GNUNET_MessageHeader *hdr)
{
  struct SendBuffer *write_std = cls;
  uint16_t sendsize;

  sendsize = ntohs (hdr->size);
  if ((sendsize + write_std->size) > MAXLINE * 2)
  {
    FPRINTF (stderr, "%s", "Packet too big for buffer\n");
    exit (1);
  }
  memcpy (write_std->buf + write_std->size, hdr, sendsize);
  write_std->size += sendsize;
  return GNUNET_OK;
}


/**
 * Main function of a program that pretends to be a WLAN card.
 *
 * @param argc should be 2
 * @param argv either '1' or '2', depending on which of the two cards this dummy is to emulate
 * @return 1 on error, 0 if terminated normally via signal
 */
int
main (int argc, char *argv[])
{
  struct stat st;
  int erg;
  FILE *fpin = NULL;
  FILE *fpout = NULL;
  int fdpin;
  int fdpout;
  char readbuf[MAXLINE];
  int readsize;
  struct SendBuffer write_std;
  struct SendBuffer write_pout;
  int ret;
  int maxfd;
  fd_set rfds;
  fd_set wfds;
  struct timeval tv;
  int retval;
  struct GNUNET_SERVER_MessageStreamTokenizer *stdin_mst = NULL;
  struct GNUNET_SERVER_MessageStreamTokenizer *file_in_mst = NULL;
  struct GNUNET_TRANSPORT_WLAN_MacAddress macaddr;
  int first;

  if ( (2 != argc) ||
       ((0 != strcmp (argv[1], "1")) && (0 != strcmp (argv[1], "2"))) )
  {
    FPRINTF (stderr,
             "%s",
	     "This program must be started with the operating mode (1 or 2) as the only argument.\n");
    return 1;
  }

  /* make the fifos if needed */
  umask (0);
  if ( (GNUNET_OK != GNUNET_DISK_directory_create_for_file (FIFO_FILE1)) ||
       (GNUNET_OK != GNUNET_DISK_directory_create_for_file (FIFO_FILE2)) )
  {
    FPRINTF (stderr, "Failed to create directory for file `%s'\n", FIFO_FILE1);
    return 1;
  }
  if (0 == strcmp (argv[1], "1") )
  {
    if (0 != stat (FIFO_FILE1, &st))
    {
      erg = mkfifo (FIFO_FILE1, 0666);
      if ( (0 != erg) && (EEXIST != errno) )
	FPRINTF (stderr, "Error in mkfifo(%s): %s\n", FIFO_FILE1,
		 strerror (errno));    
    }
  }
  else
  {
    if (0 != stat (FIFO_FILE2, &st))
    {
      erg = mkfifo (FIFO_FILE2, 0666);
      if ( (0 != erg) && (EEXIST != errno) )
	FPRINTF (stderr, "Error in mkfifo(%s): %s\n", FIFO_FILE2,
		 strerror (errno));
    }
  }

  if (0 == strcmp (argv[1], "1"))
  {
    first = 1;
    fpin = fopen (FIFO_FILE1, "r");
    if (NULL == fpin)
    {
      FPRINTF (stderr, "fopen of read FIFO_FILE1 failed: %s\n", STRERROR (errno));
      goto end;
    }
    if (NULL == (fpout = fopen (FIFO_FILE2, "w")))
    {
      erg = mkfifo (FIFO_FILE2, 0666);
      fpout = fopen (FIFO_FILE2, "w");
    }
    if (NULL == fpout)
    {
      FPRINTF (stderr, "fopen of write FIFO_FILE2 failed: %s\n", STRERROR (errno));
      goto end;
    }
  }
  else
  {
    first = 0;
    if (NULL == (fpout = fopen (FIFO_FILE1, "w")))
    {
      erg = mkfifo (FIFO_FILE1, 0666);
      fpout = fopen (FIFO_FILE1, "w");
    }
    if (NULL == fpout)
    {
      FPRINTF (stderr, "fopen of write FIFO_FILE1 failed: %s\n", STRERROR (errno));
      goto end;
    }
    fpin = fopen (FIFO_FILE2, "r");
    if (NULL == fpin)
    {
      FPRINTF (stderr, "fopen of read FIFO_FILE2 failed: %s\n", STRERROR (errno));
      goto end;
    }
  }

  fdpin = fileno (fpin);
  GNUNET_assert (fpin >= 0);
  if (fdpin >= FD_SETSIZE)
  {
    FPRINTF (stderr, "File fdpin number too large (%d > %u)\n", fdpin,
             (unsigned int) FD_SETSIZE);
    goto end;
  }

  fdpout = fileno (fpout);
  GNUNET_assert (fdpout >= 0);

  if (fdpout >= FD_SETSIZE)
  {
    FPRINTF (stderr, "File fdpout number too large (%d > %u)\n", fdpout,
             (unsigned int) FD_SETSIZE);
    goto end;
  }

  signal (SIGINT, &sigfunc);
  signal (SIGTERM, &sigfunc);

  write_std.size = 0;
  write_std.pos = 0;
  write_pout.size = 0;
  write_pout.pos = 0;
  stdin_mst = GNUNET_SERVER_mst_create (&stdin_send, &write_pout);
  file_in_mst = GNUNET_SERVER_mst_create (&file_in_send, &write_std);

  /* Send 'random' mac address */
  macaddr.mac[0] = 0x13;
  macaddr.mac[1] = 0x22;
  macaddr.mac[2] = 0x33;
  macaddr.mac[3] = 0x44;
  macaddr.mac[4] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, 256);
  macaddr.mac[5] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, 256);
  write_std.size = send_mac_to_plugin (write_std.buf, &macaddr);

  while (0 == closeprog)
  {
    maxfd = -1;
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    FD_ZERO (&rfds);
    FD_ZERO (&wfds);
    /* if output queue is empty, read */
    if (0 == write_pout.size)
    {
      FD_SET (STDIN_FILENO, &rfds);
      maxfd = MAX (STDIN_FILENO, maxfd);
    }
    if (0 == write_std.size)
    {
      FD_SET (fdpin, &rfds);
      maxfd = MAX (fdpin, maxfd);
    }

    /* if there is something to write, try to write */
    if (0 < write_std.size)
    {
      FD_SET (STDOUT_FILENO, &wfds);
      maxfd = MAX (maxfd, STDOUT_FILENO);
    }
    if (0 < write_pout.size)
    {
      FD_SET (fdpout, &wfds);
      maxfd = MAX (maxfd, fdpout);
    }

    retval = select (maxfd + 1, &rfds, &wfds, NULL, &tv);
    if ((-1 == retval) && (EINTR == errno))
      continue;
    if (0 > retval)
    {
      FPRINTF (stderr, "select failed: %s\n", STRERROR (errno));
      closeprog = 1;
      break;
    }

    if (FD_ISSET (STDOUT_FILENO, &wfds))
    {
      ret =
          write (STDOUT_FILENO, write_std.buf + write_std.pos,
                 write_std.size - write_std.pos);
      if (0 > ret)
      {
        closeprog = 1;
        FPRINTF (stderr, "Write ERROR to STDOUT_FILENO: %s\n",
                 STRERROR (errno));
        break;
      }
      else
      {
        write_std.pos += ret;
        /* check if finished writing */
        if (write_std.pos == write_std.size)
        {
          write_std.pos = 0;
          write_std.size = 0;
        }
      }
    }

    if (FD_ISSET (fdpout, &wfds))
    {
      ret =
          write (fdpout, write_pout.buf + write_pout.pos,
                 write_pout.size - write_pout.pos);

      if (0 > ret)
      {
        closeprog = 1;
        FPRINTF (stderr, "Write ERROR to fdpout failed: %s\n", STRERROR (errno));
      }
      else
      {
        write_pout.pos += ret;
        /* check if finished writing */
        if (write_pout.pos == write_pout.size)
        {
          write_pout.pos = 0;
          write_pout.size = 0;
        }
      }
    }

    if (FD_ISSET (STDIN_FILENO, &rfds))
    {
      readsize = read (STDIN_FILENO, readbuf, sizeof (readbuf));

      if (0 > readsize)
      {
        closeprog = 1;
        FPRINTF (stderr, "Error reading from STDIN_FILENO: %s\n",
                 STRERROR (errno));
      }
      else if (0 < readsize)
      {
        GNUNET_SERVER_mst_receive (stdin_mst, NULL, readbuf, readsize,
                                   GNUNET_NO, GNUNET_NO);

      }
      else
      {
        /* eof */
        closeprog = 1;
      }
    }

    if (FD_ISSET (fdpin, &rfds))
    {
      readsize = read (fdpin, readbuf, sizeof (readbuf));
      if (0 > readsize)
      {
        closeprog = 1;
        FPRINTF (stderr, "Error reading from fdpin: %s\n", STRERROR (errno));
        break;
      }
      else if (0 < readsize)
      {
        GNUNET_SERVER_mst_receive (file_in_mst, NULL, readbuf, readsize,
                                   GNUNET_NO, GNUNET_NO);
      }
      else
      {
        /* eof */
        closeprog = 1;
      }
    }
  }

end:
  /* clean up */
  if (NULL != stdin_mst)
    GNUNET_SERVER_mst_destroy (stdin_mst);
  if (NULL != file_in_mst)
    GNUNET_SERVER_mst_destroy (file_in_mst);

  if (NULL != fpout)
    fclose (fpout);
  if (NULL != fpin)
    fclose (fpin);
  if (1 == first)
  {
    (void) unlink (FIFO_FILE1);
    (void) unlink (FIFO_FILE2);
  }
  return 0;
}
