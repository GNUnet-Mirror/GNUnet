

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
#include "gnunet-transport-wlan-helper.h"
#include "gnunet_crypto_lib.h"
#include "loopback_helper.h"
#include "helper_common.h"

extern int first;

static void
sigfunc(int sig)
{
  closeprog = 1;
  unlink(FIFO_FILE1);
  unlink(FIFO_FILE2);
}

static void
stdin_send(void *cls, void *client, const struct GNUNET_MessageHeader *hdr)
{
  struct sendbuf *write_pout = cls;
  int sendsize;
  struct GNUNET_MessageHeader newheader;
  unsigned char * from;
  unsigned char * to;

  sendsize = ntohs(hdr->size) - sizeof(struct Radiotap_Send);

  if (GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA != ntohs(hdr->type))
    {
      fprintf(stderr, "Function stdin_send: wrong packet type\n");
      exit(1);
    }
  if ((sendsize + write_pout->size) > MAXLINE * 2)
    {
      fprintf(stderr, "Function stdin_send: Packet too big for buffer\n");
      exit(1);
    }

  newheader.size = htons(sendsize);
  newheader.type = htons(GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA);

  to = write_pout->buf + write_pout->size;
  memcpy(to, &newheader, sizeof(struct GNUNET_MessageHeader));
  write_pout->size += sizeof(struct GNUNET_MessageHeader);

  from = ((unsigned char *) hdr) + sizeof(struct Radiotap_Send)
      + sizeof(struct GNUNET_MessageHeader);
  to = write_pout->buf + write_pout->size;
  memcpy(to, from, sendsize - sizeof(struct GNUNET_MessageHeader));
  write_pout->size += sendsize - sizeof(struct GNUNET_MessageHeader);
}

static void
file_in_send(void *cls, void *client, const struct GNUNET_MessageHeader *hdr)
{
  struct sendbuf * write_std = cls;
  uint16_t sendsize;

  sendsize = ntohs(hdr->size);

  if (GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA != ntohs(hdr->type))
    {
      fprintf(stderr, "Function file_in_send: wrong packet type\n");
      exit(1);
    }
  if ((sendsize + write_std->size) > MAXLINE * 2)
    {
      fprintf(stderr, "Function file_in_send: Packet too big for buffer\n");
      exit(1);
    }

  memcpy(write_std->buf + write_std->size, hdr, sendsize);
  write_std->size += sendsize;
}

int
testmode(int argc, char *argv[])
{
  struct stat st;
  int erg;

  FILE *fpin;
  FILE *fpout;

  int fdpin;
  int fdpout;

  //make the fifos if needed
  if (0 != stat(FIFO_FILE1, &st))
    {
      if (0 == stat(FIFO_FILE2, &st))
        {
          fprintf(stderr, "FIFO_FILE2 exists, but FIFO_FILE1 not\n");
          exit(1);
        }

      umask(0);
      erg = mknod(FIFO_FILE1, S_IFIFO | 0666, 0);
      erg = mknod(FIFO_FILE2, S_IFIFO | 0666, 0);

    }
  else
    {

      if (0 != stat(FIFO_FILE2, &st))
        {
          fprintf(stderr, "FIFO_FILE1 exists, but FIFO_FILE2 not\n");
          exit(1);
        }

    }

  if (strstr(argv[2], "1"))
    {
      //fprintf(stderr, "First\n");
      first = 1;
      fpin = fopen(FIFO_FILE1, "r");
      if (NULL == fpin)
        {
          fprintf(stderr, "fopen of read FIFO_FILE1\n");
          exit(1);
        }
      if (NULL == (fpout = fopen(FIFO_FILE2, "w")))
        {
          fprintf(stderr, "fopen of write FIFO_FILE2\n");
          exit(1);
        }

    }
  else
    {
      first = 0;
      //fprintf(stderr, "Second\n");
      if (NULL == (fpout = fopen(FIFO_FILE1, "w")))
        {
          fprintf(stderr, "fopen of write FIFO_FILE1\n");
          exit(1);
        }
      if (NULL == (fpin = fopen(FIFO_FILE2, "r")))
        {
          fprintf(stderr, "fopen of read FIFO_FILE2\n");
          exit(1);
        }

    }

  fdpin = fileno(fpin);
  if (fdpin >= FD_SETSIZE)
    {
      fprintf(stderr, "File fdpin number too large (%d > %u)\n", fdpin,
          (unsigned int) FD_SETSIZE);
      close(fdpin);
      return -1;
    }

  fdpout = fileno(fpout);
  if (fdpout >= FD_SETSIZE)
    {
      fprintf(stderr, "File fdpout number too large (%d > %u)\n", fdpout,
          (unsigned int) FD_SETSIZE);
      close(fdpout);
      return -1;

    }

  signal(SIGINT, &sigfunc);
  signal(SIGTERM, &sigfunc);

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

  struct GNUNET_SERVER_MessageStreamTokenizer * stdin_mst;
  struct GNUNET_SERVER_MessageStreamTokenizer * file_in_mst;

  stdin_mst = GNUNET_SERVER_mst_create(&stdin_send, &write_pout);
  file_in_mst = GNUNET_SERVER_mst_create(&file_in_send, &write_std);

  //send mac first

  struct MacAddress macaddr;

  //Send random mac address
  macaddr.mac[0] = 0x13;
  macaddr.mac[1] = 0x22;
  macaddr.mac[2] = 0x33;
  macaddr.mac[3] = 0x44;
  macaddr.mac[4] = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_STRONG, 256);
  macaddr.mac[5] = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_NONCE, 256);

  write_std.size = send_mac_to_plugin((char *) write_std.buf, macaddr.mac);

  /*
   //wait
   tv.tv_sec = 2;
   tv.tv_usec = 0;
   retval = select(0, NULL, NULL, NULL, &tv);


   tv.tv_sec = 3;
   tv.tv_usec = 0;
   // if there is something to write
   FD_ZERO(&wfds);
   FD_SET(STDOUT_FILENO, &wfds);

   retval = select(STDOUT_FILENO + 1, NULL, &wfds, NULL, &tv);

   if (FD_ISSET(STDOUT_FILENO, &wfds))
   {
   ret = write(STDOUT_FILENO, write_std.buf + write_std.pos, write_std.size
   - write_std.pos);

   if (0 > ret)
   {
   closeprog = 1;
   fprintf(stderr, "Write ERROR to STDOUT");
   exit(1);
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

   memcpy(&write_std.buf, &macmsg, sizeof(struct Wlan_Helper_Control_Message));
   write_std.size = sizeof(struct Wlan_Helper_Control_Message);
   */

  //wait
  tv.tv_sec = 2;
  tv.tv_usec = 0;
  retval = select(0, NULL, NULL, NULL, &tv);

  while (0 == closeprog)
    {

      maxfd = 0;

      //set timeout
      tv.tv_sec = 5;
      tv.tv_usec = 0;

      FD_ZERO(&rfds);
      // if output queue is empty
      if (0 == write_pout.size)
        {
          FD_SET(STDIN_FILENO, &rfds);

        }
      if (0 == write_std.size)
        {
          FD_SET(fdpin, &rfds);
          maxfd = fdpin;
        }
      FD_ZERO(&wfds);
      // if there is something to write
      if (0 < write_std.size)
        {
          FD_SET(STDOUT_FILENO, &wfds);
          maxfd = MAX(maxfd, STDOUT_FILENO);
        }

      if (0 < write_pout.size)
        {
          FD_SET(fdpout, &wfds);
          maxfd = MAX(maxfd, fdpout);
        }

      retval = select(maxfd + 1, &rfds, &wfds, NULL, &tv);

      if (-1 == retval && EINTR == errno)
        {
          continue;
        }
      if (0 > retval)
        {
          fprintf(stderr, "select failed: %s\n", strerror(errno));
          exit(1);
        }

      if (FD_ISSET(STDOUT_FILENO, &wfds))
        {
          ret = write(STDOUT_FILENO, write_std.buf + write_std.pos,
              write_std.size - write_std.pos);

          if (0 > ret)
            {
              closeprog = 1;
              fprintf(stderr, "Write ERROR to STDOUT\n");
              exit(1);
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

      if (FD_ISSET(fdpout, &wfds))
        {
          ret = write(fdpout, write_pout.buf + write_pout.pos, write_pout.size
              - write_pout.pos);

          if (0 > ret)
            {
              closeprog = 1;
              fprintf(stderr, "Write ERROR to fdpout\n");
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

      if (FD_ISSET(STDIN_FILENO, &rfds))
        {
          readsize = read(STDIN_FILENO, readbuf, sizeof(readbuf));

          if (0 > readsize)
            {
              closeprog = 1;
              fprintf(stderr, "Read ERROR to STDIN_FILENO\n");
            }
          else if (0 < readsize)
            {
              GNUNET_SERVER_mst_receive(stdin_mst, NULL, readbuf, readsize,
                  GNUNET_NO, GNUNET_NO);

            }
          else
            {
              //eof
              closeprog = 1;
            }
        }

      if (FD_ISSET(fdpin, &rfds))
        {
          readsize = read(fdpin, readbuf, sizeof(readbuf));

          if (0 > readsize)
            {
              closeprog = 1;
              fprintf(stderr, "Read ERROR to fdpin: %s\n", strerror(errno));
              closeprog = 1;
            }
          else if (0 < readsize)
            {
              GNUNET_SERVER_mst_receive(file_in_mst, NULL, readbuf, readsize,
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
  fclose(fpout);
  fclose(fpin);

  if (1 == first)
    {
      unlink(FIFO_FILE1);
      unlink(FIFO_FILE2);
    }

  return (0);
}
