/*
 This file is part of GNUnet.
 (C) 2010 Christian Grothoff (and other contributing authors)

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

#define FIFO_FILE1       "/tmp/test-transport/api-wlan-p1/WLAN_FIFO_in"
#define FIFO_FILE2       "/tmp/test-transport/api-wlan-p1/WLAN_FIFO_out"

#define MAXLINE 4096

struct sendbuf
{
  unsigned int pos;
  unsigned int size;
  char buf[MAXLINE * 2];
};

static int first;

static int closeprog;

static void
sigfunc (int sig)
{
  closeprog = 1;
  (void) unlink (FIFO_FILE1);
  (void) unlink (FIFO_FILE2);
}


/**
 * function to create GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL message for plugin
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

static void
stdin_send (void *cls, void *client, const struct GNUNET_MessageHeader *hdr)
{
  struct sendbuf *write_pout = cls;
  int sendsize;
  struct GNUNET_MessageHeader newheader;
  char *to_data;
  char *to_radiotap;
  char *to_start;

  sendsize =
      ntohs (hdr->size) - sizeof (struct Radiotap_Send) +
      sizeof (struct Radiotap_rx);

  if (GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA != ntohs (hdr->type))
  {
    fprintf (stderr, "Function stdin_send: wrong packet type\n");
    exit (1);
  }
  if ((sendsize + write_pout->size) > MAXLINE * 2)
  {
    fprintf (stderr, "Function stdin_send: Packet too big for buffer\n");
    exit (1);
  }

  newheader.size = htons (sendsize);
  newheader.type = htons (GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA);

  to_start = write_pout->buf + write_pout->size;
  memcpy (to_start, &newheader, sizeof (struct GNUNET_MessageHeader));
  write_pout->size += sizeof (struct GNUNET_MessageHeader);

  to_radiotap = to_start + sizeof (struct GNUNET_MessageHeader);
  memset (to_radiotap, 0, sizeof (struct Radiotap_rx));
  write_pout->size += sizeof (struct Radiotap_rx);

  to_data = to_radiotap + sizeof (struct Radiotap_rx);
  memcpy (to_data,
          ((char *) hdr) + sizeof (struct Radiotap_Send) +
          sizeof (struct GNUNET_MessageHeader),
          ntohs (hdr->size) - sizeof (struct Radiotap_Send) -
          sizeof (struct GNUNET_MessageHeader));
  write_pout->size +=
      ntohs (hdr->size) - sizeof (struct Radiotap_Send) -
      sizeof (struct GNUNET_MessageHeader);
}


static void
file_in_send (void *cls, void *client, const struct GNUNET_MessageHeader *hdr)
{
  struct sendbuf *write_std = cls;
  uint16_t sendsize;

  sendsize = ntohs (hdr->size);

  if (GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA != ntohs (hdr->type))
  {
    fprintf (stderr, "Function file_in_send: wrong packet type\n");
    exit (1);
  }
  if ((sendsize + write_std->size) > MAXLINE * 2)
  {
    fprintf (stderr, "Function file_in_send: Packet too big for buffer\n");
    exit (1);
  }

  memcpy (write_std->buf + write_std->size, hdr, sendsize);
  write_std->size += sendsize;
}


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
  int readsize = 0;
  struct sendbuf write_std;
  struct sendbuf write_pout;
  int ret = 0;
  int maxfd = 0;
  fd_set rfds;
  fd_set wfds;
  struct timeval tv;
  int retval;
  struct GNUNET_SERVER_MessageStreamTokenizer *stdin_mst;
  struct GNUNET_SERVER_MessageStreamTokenizer *file_in_mst;
  struct GNUNET_TRANSPORT_WLAN_MacAddress macaddr;

  if (2 != argc)
  {
    fprintf (stderr,
             "This program must be started with the operating mode (1 or 2) as the only argument.\n");
    return 1;
  }
  if ((0 != strstr (argv[1], "1")) && (0 != strstr (argv[1], "2")))
    return 1;

  //make the fifos if needed
  if (0 != stat (FIFO_FILE1, &st))
  {
    if (0 == stat (FIFO_FILE2, &st))
    {
      fprintf (stderr, "FIFO_FILE2 exists, but FIFO_FILE1 not\n");
      exit (1);
    }
    umask (0);
    erg = mkfifo (FIFO_FILE1, 0666);
    if (0 != erg)
    {
      fprintf (stderr, "Error in mkfifo(%s): %s\n", FIFO_FILE1,
               strerror (errno));
      //exit(1);
    }
    erg = mkfifo (FIFO_FILE2, 0666);
    if (0 != erg)
    {
      fprintf (stderr, "Error in mkfifo(%s): %s\n", FIFO_FILE2,
               strerror (errno));
      //exit(1);
    }

  }
  else
  {
    if (0 != stat (FIFO_FILE2, &st))
    {
      fprintf (stderr, "FIFO_FILE1 exists, but FIFO_FILE2 not\n");
      exit (1);
    }
  }

  if (strstr (argv[1], "1"))
  {
    //fprintf(stderr, "First\n");
    first = 1;
    fpin = fopen (FIFO_FILE1, "r");
    if (NULL == fpin)
    {
      fprintf (stderr, "fopen of read FIFO_FILE1\n");
      goto end;
    }
    fpout = fopen (FIFO_FILE2, "w");
    if (NULL == fpout)
    {
      fprintf (stderr, "fopen of write FIFO_FILE2\n");
      goto end;
    }

  }
  else
  {
    first = 0;
    //fprintf(stderr, "Second\n");
    fpout = fopen (FIFO_FILE1, "w");
    if (NULL == fpout)
    {
      fprintf (stderr, "fopen of write FIFO_FILE1\n");
      goto end;
    }
    fpin = fopen (FIFO_FILE2, "r");
    if (NULL == fpin)
    {
      fprintf (stderr, "fopen of read FIFO_FILE2\n");
      goto end;
    }

  }

  fdpin = fileno (fpin);
  GNUNET_assert (fpin >= 0);

  if (fdpin >= FD_SETSIZE)
  {
    fprintf (stderr, "File fdpin number too large (%d > %u)\n", fdpin,
             (unsigned int) FD_SETSIZE);
    goto end;
  }

  fdpout = fileno (fpout);
  GNUNET_assert (fdpout >= 0);

  if (fdpout >= FD_SETSIZE)
  {
    fprintf (stderr, "File fdpout number too large (%d > %u)\n", fdpout,
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

  //Send random mac address
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
    //set timeout
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    FD_ZERO (&rfds);
    // if output queue is empty
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
    FD_ZERO (&wfds);
    // if there is something to write
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
      fprintf (stderr, "select failed: %s\n", strerror (errno));
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
        fprintf (stderr, "Write ERROR to STDOUT_FILENO: %s\n",
                 strerror (errno));
        break;
      }
      else
      {
        write_std.pos += ret;
        // check if finished
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
        fprintf (stderr, "Write ERROR to fdpout: %s\n", strerror (errno));
      }
      else
      {
        write_pout.pos += ret;
        // check if finished
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
        fprintf (stderr, "Error reading from STDIN_FILENO: %s\n",
                 strerror (errno));
      }
      else if (0 < readsize)
      {
        GNUNET_SERVER_mst_receive (stdin_mst, NULL, readbuf, readsize,
                                   GNUNET_NO, GNUNET_NO);

      }
      else
      {
        //eof
        closeprog = 1;
      }
    }

    if (FD_ISSET (fdpin, &rfds))
    {
      readsize = read (fdpin, readbuf, sizeof (readbuf));
      if (0 > readsize)
      {
        closeprog = 1;
        fprintf (stderr, "Error reading from fdpin: %s\n", strerror (errno));
        break;
      }
      else if (0 < readsize)
      {
        GNUNET_SERVER_mst_receive (file_in_mst, NULL, readbuf, readsize,
                                   GNUNET_NO, GNUNET_NO);
      }
      else
      {
        //eof
        closeprog = 1;
      }
    }
  }

  //clean up
  GNUNET_SERVER_mst_destroy (stdin_mst);
  GNUNET_SERVER_mst_destroy (file_in_mst);

end:
  if (fpout != NULL)
    fclose (fpout);
  if (fpin != NULL)
    fclose (fpin);
  if (1 == first)
  {
    (void) unlink (FIFO_FILE1);
    (void) unlink (FIFO_FILE2);
  }
  return 0;
}
