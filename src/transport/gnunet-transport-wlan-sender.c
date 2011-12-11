/*
 This file is part of GNUnet
 (C) 2011 Christian Grothoff (and other contributing authors)

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
#include "gnunet_protocols.h"
#include "plugin_transport_wlan.h"

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


/*
 * generic definitions for IEEE 802.11 frames
 */
struct ieee80211_frame
{
  u_int8_t i_fc[2];
  u_int8_t i_dur[2];
  u_int8_t i_addr1[IEEE80211_ADDR_LEN];
  u_int8_t i_addr2[IEEE80211_ADDR_LEN];
  u_int8_t i_addr3[IEEE80211_ADDR_LEN];
  u_int8_t i_seq[2];
  u_int8_t llc[4];
} GNUNET_PACKED;


/**
 * function to fill the radiotap header
 * @param header pointer to the radiotap header
 * @return GNUNET_YES at success
 */
static int
getRadiotapHeader (struct Radiotap_Send *header)
{
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
getWlanHeader (struct ieee80211_frame *Header, const char *to_mac_addr,
               const char *mac, unsigned int size)
{
  uint16_t *tmp16;
  const int rate = 11000000;

  Header->i_fc[0] = IEEE80211_FC0_TYPE_DATA;
  Header->i_fc[1] = 0x00;
  memcpy (&Header->i_addr3, &mac_bssid_gnunet, sizeof (mac_bssid_gnunet));
  memcpy (&Header->i_addr2, mac, sizeof (mac_bssid_gnunet));
  memcpy (&Header->i_addr1, to_mac_addr, sizeof (mac_bssid_gnunet));

  tmp16 = (uint16_t *) Header->i_dur;
  *tmp16 = (uint16_t) GNUNET_htole16 ((size * 1000000) / rate + 290);
  Header->llc[0] = WLAN_LLC_DSAP_FIELD;
  Header->llc[1] = WLAN_LLC_SSAP_FIELD;

  return GNUNET_YES;
}


int
main (int argc, char *argv[])
{
  char msg_buf[WLAN_MTU];
  struct GNUNET_MessageHeader *msg;
  struct ieee80211_frame *wlan_header;
  struct Radiotap_Send *radiotap;

  unsigned int temp[6];
  char inmac[6];
  char outmac[6];
  int pos;
  long long count;
  double bytes_per_s;
  time_t start;
  time_t akt;
  int i;

  if (4 != argc)
  {
    fprintf (stderr,
             "This program must be started with the interface and the targets and source mac as argument.\n");
    fprintf (stderr,
             "Usage: interface-name mac-target mac-source\n"
             "e.g. mon0 11-22-33-44-55-66 12-34-56-78-90-ab\n");
    return 1;
  }
  if (6 !=
      sscanf (argv[3], "%x-%x-%x-%x-%x-%x", &temp[0], &temp[1], &temp[2],
              &temp[3], &temp[4], &temp[5]))
  {
    fprintf (stderr,
             "Usage: interface-name mac-target mac-source\n"
             "e.g. mon0 11-22-33-44-55-66 12-34-56-78-90-ab\n");
    return 1;
  }
  if (6 !=
      sscanf (argv[2], "%x-%x-%x-%x-%x-%x", &temp[0], &temp[1], &temp[2],
              &temp[3], &temp[4], &temp[5]))
  {
    fprintf (stderr,
             "Usage: interface-name mac-target mac-source\n"
             "e.g. mon0 11-22-33-44-55-66 12-34-56-78-90-ab\n");
    return 1;
  }
  for (i = 0; i < 6; i++)
    inmac[i] = temp[i];
  for (i = 0; i < 6; i++)
    outmac[i] = temp[i];

  pid_t pid;
  int commpipe[2];              /* This holds the fd for the input & output of the pipe */

  /* Setup communication pipeline first */
  if (pipe (commpipe))
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

  if (pid)
  {
    /* A positive (non-negative) PID indicates the parent process */
    close (commpipe[0]);        /* Close unused side of pipe (in side) */
    setvbuf (stdout, (char *) NULL, _IONBF, 0); /* Set non-buffered output on stdout */


    msg = (struct GNUNET_MessageHeader *) msg_buf;
    msg->type = htons (GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA);
    msg->size = htons (WLAN_MTU);
    radiotap = (struct Radiotap_Send *) &msg[1];
    wlan_header = (struct ieee80211_frame *) &radiotap[1];
    pos = 0;

    getRadiotapHeader (radiotap);
    getWlanHeader (wlan_header, outmac, inmac,
                   WLAN_MTU - sizeof (struct GNUNET_MessageHeader));

    start = time (NULL);
    count = 0;
    while (1)
    {
      pos += write (commpipe[1], msg, WLAN_MTU - pos);
      if (pos % WLAN_MTU == 0)
      {
        pos = 0;
        count++;

        if (count % 1000 == 0)
        {
          akt = time (NULL);
          bytes_per_s = count * WLAN_MTU / (akt - start);
          bytes_per_s /= 1024;
          printf ("send %f kbytes/s\n", bytes_per_s);
        }
      }

    }
  }
  else
  {
    /* A zero PID indicates that this is the child process */
    (void) close (0);
    if (-1 == dup2 (commpipe[0], 0))    /* Replace stdin with the in side of the pipe */
      fprintf (stderr, "dup2 failed: %s\n", strerror (errno));
    (void) close (commpipe[1]); /* Close unused side of pipe (out side) */
    /* Replace the child fork with a new process */
    if (execl
        ("gnunet-helper-transport-wlan", "gnunet-helper-transport-wlan",
         argv[1], NULL) == -1)
    {
      fprintf (stderr, "Could not start gnunet-helper-transport-wlan!");
      _exit (1);
    }
  }
  return 0;
}
