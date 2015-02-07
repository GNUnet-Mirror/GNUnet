/*
 This file is part of GNUnet
 Copyright (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-transport-wlan-sender.c
 * @brief program to send via WLAN as much as possible (to test physical/theoretical throughput)
 * @author David Brodski
 */
#include "platform.h"
#include "plugin_transport_wlan.h"
#include "gnunet_protocols.h"

#define WLAN_MTU 1500

/**
 * LLC fields for better compatibility
 */
#define WLAN_LLC_DSAP_FIELD 0x1f
#define WLAN_LLC_SSAP_FIELD 0x1f

#define IEEE80211_ADDR_LEN      6       /* size of 802.11 address */

#define IEEE80211_FC0_VERSION_MASK              0x03
#define IEEE80211_FC0_VERSION_SHIFT             0
#define IEEE80211_FC0_VERSION_0                 0x00
#define IEEE80211_FC0_TYPE_MASK                 0x0c
#define IEEE80211_FC0_TYPE_SHIFT                2
#define IEEE80211_FC0_TYPE_MGT                  0x00
#define IEEE80211_FC0_TYPE_CTL                  0x04
#define IEEE80211_FC0_TYPE_DATA                 0x08


/**
 * function to fill the radiotap header
 * @param header pointer to the radiotap header
 * @param size total message size
 * @return GNUNET_YES at success
 */
static int
getRadiotapHeader (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *header,
		   uint16_t size)
{
  header->header.size = htons (size);
  header->header.type = htons (GNUNET_MESSAGE_TYPE_WLAN_DATA_TO_HELPER);
  header->rate = 255;
  header->tx_power = 0;
  header->antenna = 0;
  return GNUNET_YES;
}

/**
 * function to generate the wlan hardware header for one packet
 * @param Header address to write the header to
 * @param to_mac_addr pointer to the address of the recipient
 * @param mac pointer to the mac address to send from (normally overwritten over by helper)
 * @param size size of the whole packet, needed to calculate the time to send the packet
 * @return GNUNET_YES if there was no error
 */
static int
getWlanHeader (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame *Header,
	       const struct GNUNET_TRANSPORT_WLAN_MacAddress *to_mac_addr,
               const struct GNUNET_TRANSPORT_WLAN_MacAddress *mac, unsigned int size)
{
  const int rate = 11000000;

  Header->frame_control = htons (IEEE80211_FC0_TYPE_DATA);
  Header->addr3 = mac_bssid_gnunet;
  Header->addr2 = *mac;
  Header->addr1 = *to_mac_addr;
  Header->duration = GNUNET_htole16 ((size * 1000000) / rate + 290);
  Header->llc[0] = WLAN_LLC_DSAP_FIELD;
  Header->llc[1] = WLAN_LLC_SSAP_FIELD;
  Header->llc[2] = 0; // FIXME
  Header->llc[3] = 0; // FIXME
  return GNUNET_YES;
}


int
main (int argc, char *argv[])
{
  char msg_buf[WLAN_MTU];
  struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *radiotap;
  unsigned int temp[6];
  struct GNUNET_TRANSPORT_WLAN_MacAddress inmac;
  struct GNUNET_TRANSPORT_WLAN_MacAddress outmac;
  struct GNUNET_TRANSPORT_WLAN_HelperControlMessage hcm;
  unsigned long long count;
  double bytes_per_s;
  time_t start;
  time_t akt;
  int i;
  ssize_t ret;
  pid_t pid;
  int commpipe[2];              /* This holds the fd for the input & output of the pipe */
  int macpipe[2];              /* This holds the fd for the input & output of the pipe */

  if (4 != argc)
  {
    fprintf (stderr,
             "This program must be started with the interface and the targets and source mac as argument.\n");
    fprintf (stderr,
             "Usage: interface-name mac-DST mac-SRC\n"
             "e.g. mon0 11-22-33-44-55-66 12-34-56-78-90-ab\n");
    return 1;
  }
  if (6 !=
      SSCANF (argv[2], "%x-%x-%x-%x-%x-%x", &temp[0], &temp[1], &temp[2],
              &temp[3], &temp[4], &temp[5]))
  {
    fprintf (stderr,
             "Usage: interface-name mac-DST mac-SRC\n"
             "e.g. mon0 11-22-33-44-55-66 12-34-56-78-90-ab\n");
    return 1;
  }
  for (i = 0; i < 6; i++)
    outmac.mac[i] = temp[i];
  if (6 !=
      SSCANF (argv[3], "%x-%x-%x-%x-%x-%x", &temp[0], &temp[1], &temp[2],
              &temp[3], &temp[4], &temp[5]))
  {
    fprintf (stderr,
             "Usage: interface-name mac-DST mac-SRC\n"
             "e.g. mon0 11-22-33-44-55-66 12-34-56-78-90-ab\n");
    return 1;
  }
  for (i = 0; i < 6; i++)
    inmac.mac[i] = temp[i];


  /* Setup communication pipeline first */
  if (pipe (commpipe))
  {
    fprintf (stderr,
	     "Failed to create pipe: %s\n",
	     STRERROR (errno));
    exit (1);
  }
  if (pipe (macpipe))
  {
    fprintf (stderr,
	     "Failed to create pipe: %s\n",
	     STRERROR (errno));
    exit (1);
  }

  /* Attempt to fork and check for errors */
  if ((pid = fork ()) == -1)
  {
    fprintf (stderr, "Failed to fork: %s\n",
	     STRERROR (errno));
    exit (1);
  }
  memset (msg_buf, 0x42, sizeof (msg_buf));
  if (pid)
  {
    /* A positive (non-negative) PID indicates the parent process */
    if (0 != close (commpipe[0]))        /* Close unused side of pipe (in side) */
      fprintf (stderr,
	       "Failed to close fd: %s\n",
	       strerror (errno));
    setvbuf (stdout, (char *) NULL, _IONBF, 0); /* Set non-buffered output on stdout */

    if (0 != close (macpipe[1]))
      fprintf (stderr,
	       "Failed to close fd: %s\n",
	       strerror (errno));
    if (sizeof (hcm) != read (macpipe[0], &hcm, sizeof (hcm)))
      fprintf (stderr,
	       "Failed to read hcm...\n");
    fprintf (stderr,
	     "Got MAC %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
	     hcm.mac.mac[0], hcm.mac.mac[1],
	     hcm.mac.mac[2], hcm.mac.mac[3], hcm.mac.mac[4], hcm.mac.mac[5]);				
    radiotap = (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *) msg_buf;
    getRadiotapHeader (radiotap, WLAN_MTU);
    getWlanHeader (&radiotap->frame, &outmac, &inmac,
                   WLAN_MTU);
    start = time (NULL);
    count = 0;
    while (1)
    {
      ret = write (commpipe[1], msg_buf, WLAN_MTU);
      if (0 > ret)
      {
	fprintf (stderr, "write failed: %s\n", strerror (errno));
	break;
      }
      count += ret;
      akt =  time (NULL);
      if (akt - start > 30)
      {
	bytes_per_s = count / (akt - start);
	bytes_per_s /= 1024;
	printf ("send %f kbytes/s\n", bytes_per_s);
	start = akt;
	count = 0;
      }
    }
  }
  else
  {
    /* A zero PID indicates that this is the child process */
    (void) close (0);
    (void) close (1);
    if (-1 == dup2 (commpipe[0], 0))    /* Replace stdin with the in side of the pipe */
      fprintf (stderr, "dup2 failed: %s\n", strerror (errno));
    if (-1 == dup2 (macpipe[1], 1))    /* Replace stdout with the out side of the pipe */
      fprintf (stderr, "dup2 failed: %s\n", strerror (errno));
    (void) close (commpipe[1]); /* Close unused side of pipe (out side) */
    (void) close (macpipe[0]); /* Close unused side of pipe (in side) */
    /* Replace the child fork with a new process */
    if (execlp
        ("gnunet-helper-transport-wlan", "gnunet-helper-transport-wlan",
         argv[1], NULL) == -1)
    {
      fprintf (stderr, "Could not start gnunet-helper-transport-wlan!");
      _exit (1);
    }
  }
  return 0;
}
