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
 * @file transport/test_transport_wlan_dummy.c
 * @brief helper for the testcases for plugin_transport_wlan.c
 * @author David Brodski
 */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_os_lib.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"
#include "gnunet_util_lib.h"
#include "plugin_transport_wlan.h"
#include "gnunet_common.h"
//#include "gnunet-transport-wlan-helper.h"
#include "gnunet_crypto_lib.h"
#include "wlan/loopback_helper.h"
#include "wlan/helper_common.h"

static int first;

static void
sigfunc (int sig)
{
  closeprog = 1;
  unlink (FIFO_FILE1);
  unlink (FIFO_FILE2);
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

int closeprog;


int
testmode (int argc, char *argv[])
{
  struct stat st;
  int erg;

  FILE *fpin = NULL;
  FILE *fpout = NULL;

  int fdpin;
  int fdpout;

  //make the fifos if needed
  if (0 != stat (FIFO_FILE1, &st))
  {
    if (0 == stat (FIFO_FILE2, &st))
    {
      fprintf (stderr, "FIFO_FILE2 exists, but FIFO_FILE1 not\n");
      exit (1);
    }

    umask (0);
    //unlink(FIFO_FILE1);
    //unlink(FIFO_FILE2);
    // FIXME: use mkfifo!
    erg = mkfifo (FIFO_FILE1, 0666);
    if (0 != erg)
    {
      fprintf (stderr, "Error at mkfifo1: %s\n", strerror (errno));
      //exit(1);
    }
    erg = mkfifo (FIFO_FILE2, 0666);
    if (0 != erg)
    {
      fprintf (stderr, "Error at mkfifo2: %s\n", strerror (errno));
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

  char readbuf[MAXLINE];
  int readsize = 0;
  struct sendbuf write_std;

  write_std.size = 0;
  write_std.pos = 0;

  struct sendbuf write_pout;

  write_pout.size = 0;
  write_pout.pos = 0;

  int ret = 0;
  int maxfd = 0;

  fd_set rfds;
  fd_set wfds;
  struct timeval tv;
  int retval;

  struct GNUNET_SERVER_MessageStreamTokenizer *stdin_mst;
  struct GNUNET_SERVER_MessageStreamTokenizer *file_in_mst;

  stdin_mst = GNUNET_SERVER_mst_create (&stdin_send, &write_pout);
  file_in_mst = GNUNET_SERVER_mst_create (&file_in_send, &write_std);

  //send mac first

  struct MacAddress macaddr;

  //Send random mac address
  macaddr.mac[0] = 0x13;
  macaddr.mac[1] = 0x22;
  macaddr.mac[2] = 0x33;
  macaddr.mac[3] = 0x44;
  macaddr.mac[4] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, 256);
  macaddr.mac[5] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, 256);

  write_std.size = send_mac_to_plugin (write_std.buf, macaddr.mac);

  while (0 == closeprog)
  {

    maxfd = 0;

    //set timeout
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    FD_ZERO (&rfds);
    // if output queue is empty
    if (0 == write_pout.size)
    {
      FD_SET (STDIN_FILENO, &rfds);

    }
    if (0 == write_std.size)
    {
      FD_SET (fdpin, &rfds);
      maxfd = fdpin;
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

    if (-1 == retval && EINTR == errno)
    {
      continue;
    }
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
        fprintf (stderr, "Write ERROR to STDOUT\n");
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
        fprintf (stderr, "Write ERROR to fdpout\n");
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
        fprintf (stderr, "Read ERROR to STDIN_FILENO\n");
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
        fprintf (stderr, "Read ERROR to fdpin: %s\n", strerror (errno));
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

end:if (fpout != NULL)
    fclose (fpout);
  if (fpin != NULL)
    fclose (fpin);

  if (1 == first)
  {
    unlink (FIFO_FILE1);
    unlink (FIFO_FILE2);
  }

  return (0);
}

int
main (int argc, char *argv[])
{
  if (2 != argc)
  {
    fprintf (stderr,
             "This program must be started with the operating mode as argument.\n");
    fprintf (stderr,
             "Usage: options\n" "options:\n" "1 = first loopback file\n"
             "2 = second loopback file\n" "\n");
    return 1;
  }
  if (strstr (argv[1], "1") || strstr (argv[1], "2"))
    return testmode (argc, argv);
  return 1;
}
