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
 * @brief helper for the testcase for plugin_transport_wlan.c
 * @author David Brodski
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_os_lib.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"
#include "plugin_transport_wlan.h"
#include "gnunet_common.h"
#include "gnunet-transport-wlan-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#define FIFO_FILE1       "MYFIFOin"
#define FIFO_FILE2       "MYFIFOout"
#define MAXLINE         5000

int closeprog = 0;

void sigfunc(int sig)
{

 if(sig != SIGINT || sig != SIGTERM || sig != SIGKILL)
   return;
 else
  {
   closeprog = 1;
   exit(0);
   }
}




int
main(int argc, char *argv[])
{
  struct stat st;
  struct stat st2;
  int erg;
  int first;
  FILE *fpin;
  FILE *fpout;
  pid_t pid;

  perror("Test");


  //make the fifos if needed
  if (stat(FIFO_FILE1, &st) != 0)
    {
      if (stat(FIFO_FILE2, &st2) == 0)
        {
          perror("FIFO 2 exists, but FIFO 1 not, blub");
          exit(1);
        }
      first = 1;
      perror("First");
      umask(0);
      erg = mknod(FIFO_FILE1, S_IFIFO | 0666, 0);
      erg = mknod(FIFO_FILE2, S_IFIFO | 0666, 0);

      if ((fpin = fopen(FIFO_FILE1, "r")) == NULL)
        {
          perror("fopen");
          exit(1);
        }
      if ((fpout = fopen(FIFO_FILE2, "w")) == NULL)
        {
          perror("fopen");
          exit(1);
        }
    }
  else
    {
      first = 0;
      perror("Second");
      if (stat(FIFO_FILE2, &st2) != 0)
        {
          perror("FIFO 1 exists, but FIFO 2 not, mäh");
          exit(1);
        }
      if ((fpout = fopen(FIFO_FILE1, "w")) == NULL)
        {
          perror("fopen");
          exit(1);
        }
      if ((fpin = fopen(FIFO_FILE2, "r")) == NULL)
        {
          perror("fopen");
          exit(1);
        }

    }

  // fork

  if ((pid = fork()) < 0)
    {
      perror("FORK ERROR");

      //clean up
      if (first == 1)
              {
                unlink(FIFO_FILE1);
                unlink(FIFO_FILE2);
              }
      fclose(fpin);
      fclose(fpout);
      return -3;
    }
  else if (pid == 0) // CHILD PROCESS
    {
    perror("Child");
      signal(SIGINT, sigfunc);
      signal(SIGTERM, sigfunc);
      signal(SIGKILL, sigfunc);
      int rv = 0;
      int readc = 0;
      int pos = 0;
      char line[MAXLINE];

      fd_set rfds;
      fd_set wfds;
      struct timeval tv;
      int retval;


      tv.tv_sec = 5;
      tv.tv_usec = 0;


      FD_ZERO(&rfds);
      FD_SET(STDIN_FILENO, &rfds);

      FD_ZERO(&wfds);
      FD_SET(STDOUT_FILENO, &wfds);

      struct GNUNET_SERVER_MessageStreamTokenizer * stdin_mst;
      struct GNUNET_SERVER_MessageStreamTokenizer * file_in_mst;

      stdin_mst = GNUNET_SERVER_mst_create(&stdin_send, NULL);
      file_in_mst = GNUNET_SERVER_mst_create(&file_in_send, NULL);

      while (closeprog == 0)
        {
          readc = 0;


          while (readc < sizeof( struct RadiotapHeader) + sizeof(struct GNUNET_MessageHeader)){
            if ((rv = read(STDIN_FILENO, line, MAXLINE)) < 0)
              {
                perror("READ ERROR FROM STDIN");
              }
            readc += rv;
          }

          pos = 0;

          //fwrite(&line[pos], 1, sizeof(struct GNUNET_MessageHeader), fpout);

          //pos += sizeof(struct GNUNET_MessageHeader);

          //do not send radiotap header
          pos += sizeof( struct RadiotapHeader);

          while (pos < readc)
            {
              pos += fwrite(&line[pos], 1, readc - pos, fpout);
            }
        }


      //clean up
      fclose(fpout);
    }
  else // PARENT PROCESS
    {
    perror("Parent");
      signal(SIGINT, sigfunc);
      signal(SIGTERM, sigfunc);
      signal(SIGKILL, sigfunc);
      int rv = 0;
      ssize_t pos = 0;
      char line[MAXLINE];
      struct Wlan_Helper_Control_Message macmsg;


      //Send random mac address
      macmsg.mac.mac[0] = 0x13;
      macmsg.mac.mac[1] = 0x22;
      macmsg.mac.mac[2] = 0x33;
      macmsg.mac.mac[3] = 0x44;
      macmsg.mac.mac[4] = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, 255);
      macmsg.mac.mac[5] = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, 255);
      macmsg.hdr.size = sizeof(struct Wlan_Helper_Control_Message);

      pos = 0;
      /*
      while (pos < sizeof(struct Wlan_Helper_Control_Message))
        {
          pos += write(STDOUT_FILENO, &macmsg + pos, sizeof(struct Wlan_Helper_Control_Message) - pos);
        }
      */
      while (closeprog == 0)
        {
          if ((rv = fread(line, 1, MAXLINE, fpin)) < 0)
            {
              perror("READ ERROR FROM fpin");
            }

          pos = 0;
          while (pos < rv)
            {
              pos += write(STDOUT_FILENO, &line[pos], rv - pos);
            }
        }


      //clean up
      fclose(fpin);

      if (first == 1)
        {
          unlink(FIFO_FILE1);
          unlink(FIFO_FILE2);
        }
    }

  // Write the input to the output

  return (0);
}

