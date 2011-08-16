/*
 This file is part of GNUnet.
 (C) 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file src/transport/gnunet-transport-wlan-helper.c
 * @brief wlan layer two server; must run as root (SUID will do)
 *        This code will work under GNU/Linux only.
 * @author David Brodski
 *
 * This program serves as the mediator between the wlan interface and
 * gnunet
 */

#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <netinet/in.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
//#include <sys/utsname.h>
#include <sys/param.h>

/*
 //#include <resolv.h>
 #include <string.h>
 #include <utime.h>
 #include <getopt.h>
 */
//#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_os_lib.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"
#include "gnunet_util_lib.h"
#include "plugin_transport_wlan.h"
#include "gnunet_common.h"
#include "gnunet-transport-wlan-helper.h"
#include "gnunet_crypto_lib.h"

#include "wlan/radiotap-parser.h"
/* radiotap-parser defines types like u8 that
 * ieee80211_radiotap.h needs
 *
 * we use our local copy of ieee80211_radiotap.h
 *
 * - since we can't support extensions we don't understand
 * - since linux does not include it in userspace headers
 */
#include "wlan/ieee80211_radiotap.h"
#include "wlan/crctable_osdep.h"
#include "wlan/loopback_helper.h"
#include "wlan/ieee80211.h"

#define ARPHRD_IEEE80211        801
#define ARPHRD_IEEE80211_PRISM  802
#define ARPHRD_IEEE80211_FULL   803

#include "wlan/loopback_helper.h"

#define DEBUG 1

#define MAC_ADDR_SIZE 6

struct Hardware_Infos
{

  struct sendbuf write_pout;
  int fd_raw;
  int arptype_in;

  /**
   * Name of the interface, not necessarily 0-terminated (!).
   */
  char iface[IFNAMSIZ];
  unsigned char pl_mac[MAC_ADDR_SIZE];
};

// FIXME: inline?
int
getChannelFromFrequency (int frequency);

// FIXME: make nice...
static unsigned long
calc_crc_osdep (unsigned char *buf, int len)
{
  unsigned long crc = 0xFFFFFFFF;

  for (; len > 0; len--, buf++)
    crc = crc_tbl_osdep[(crc ^ *buf) & 0xFF] ^ (crc >> 8);

  return (~crc);
}

/* CRC checksum verification routine */

// FIXME: make nice...
static int
check_crc_buf_osdep (unsigned char *buf, int len)
{
  unsigned long crc;

  if (0 > len)
    return 0;

  crc = calc_crc_osdep (buf, len);
  buf += len;
  return (((crc) & 0xFF) == buf[0] && ((crc >> 8) & 0xFF) == buf[1] &&
          ((crc >> 16) & 0xFF) == buf[2] && ((crc >> 24) & 0xFF) == buf[3]);
}


// FIXME: make nice...
static int
linux_get_channel (struct Hardware_Infos *dev)
{
  struct iwreq wrq;
  int fd, frequency;
  int chan = 0;

  memset (&wrq, 0, sizeof (struct iwreq));

  strncpy (wrq.ifr_name, dev->iface, IFNAMSIZ);

  fd = dev->fd_raw;
  if (0 > ioctl (fd, SIOCGIWFREQ, &wrq))
    return (-1);

  frequency = wrq.u.freq.m;
  if (100000000 < frequency)
    frequency /= 100000;
  else if (1000000 < frequency)
    frequency /= 1000;

  if (1000 < frequency)
    chan = getChannelFromFrequency (frequency);
  else
    chan = frequency;

  return chan;
}


// FIXME: make nice...
static ssize_t
linux_read (struct Hardware_Infos *dev, unsigned char *buf,     /* FIXME: void*? */
            size_t buf_size, struct Radiotap_rx *ri)
{
  unsigned char tmpbuf[buf_size];
  ssize_t caplen;
  int n, got_signal, got_noise, got_channel, fcs_removed;

  n = got_signal = got_noise = got_channel = fcs_removed = 0;

  caplen = read (dev->fd_raw, tmpbuf, buf_size);
  if (0 > caplen)
  {
    if (EAGAIN == errno)
      return 0;
    fprintf (stderr, "Failed to read from RAW socket: %s\n", strerror (errno));
    return -1;
  }

  memset (buf, 0, buf_size);
  memset (ri, 0, sizeof (*ri));

  switch (dev->arptype_in)
  {
  case ARPHRD_IEEE80211_PRISM:
  {
    /* skip the prism header */
    if (tmpbuf[7] == 0x40)
    {
      /* prism54 uses a different format */
      ri->ri_power = tmpbuf[0x33];
      ri->ri_noise = *(unsigned int *) (tmpbuf + 0x33 + 12);
      ri->ri_rate = (*(unsigned int *) (tmpbuf + 0x33 + 24)) * 500000;
      got_signal = 1;
      got_noise = 1;
      n = 0x40;
    }
    else
    {
      ri->ri_mactime = *(u_int64_t *) (tmpbuf + 0x5C - 48);
      ri->ri_channel = *(unsigned int *) (tmpbuf + 0x5C - 36);
      ri->ri_power = *(unsigned int *) (tmpbuf + 0x5C);
      ri->ri_noise = *(unsigned int *) (tmpbuf + 0x5C + 12);
      ri->ri_rate = (*(unsigned int *) (tmpbuf + 0x5C + 24)) * 500000;
      got_channel = 1;
      got_signal = 1;
      got_noise = 1;
      n = *(int *) (tmpbuf + 4);
    }

    if (n < 8 || n >= caplen)
      return (0);
  }
    break;

  case ARPHRD_IEEE80211_FULL:
  {
    struct ieee80211_radiotap_iterator iterator;
    struct ieee80211_radiotap_header *rthdr;

    rthdr = (struct ieee80211_radiotap_header *) tmpbuf;

    if (ieee80211_radiotap_iterator_init (&iterator, rthdr, caplen) < 0)
      return (0);

    /* go through the radiotap arguments we have been given
     * by the driver
     */

    while (ieee80211_radiotap_iterator_next (&iterator) >= 0)
    {

      switch (iterator.this_arg_index)
      {

      case IEEE80211_RADIOTAP_TSFT:
        ri->ri_mactime = le64_to_cpu (*((uint64_t *) iterator.this_arg));
        break;

      case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
        if (!got_signal)
        {
          if (*iterator.this_arg < 127)
            ri->ri_power = *iterator.this_arg;
          else
            ri->ri_power = *iterator.this_arg - 255;

          got_signal = 1;
        }
        break;

      case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
        if (!got_signal)
        {
          if (*iterator.this_arg < 127)
            ri->ri_power = *iterator.this_arg;
          else
            ri->ri_power = *iterator.this_arg - 255;

          got_signal = 1;
        }
        break;

      case IEEE80211_RADIOTAP_DBM_ANTNOISE:
        if (!got_noise)
        {
          if (*iterator.this_arg < 127)
            ri->ri_noise = *iterator.this_arg;
          else
            ri->ri_noise = *iterator.this_arg - 255;

          got_noise = 1;
        }
        break;

      case IEEE80211_RADIOTAP_DB_ANTNOISE:
        if (!got_noise)
        {
          if (*iterator.this_arg < 127)
            ri->ri_noise = *iterator.this_arg;
          else
            ri->ri_noise = *iterator.this_arg - 255;

          got_noise = 1;
        }
        break;

      case IEEE80211_RADIOTAP_ANTENNA:
        ri->ri_antenna = *iterator.this_arg;
        break;

      case IEEE80211_RADIOTAP_CHANNEL:
        ri->ri_channel = *iterator.this_arg;
        got_channel = 1;
        break;

      case IEEE80211_RADIOTAP_RATE:
        ri->ri_rate = (*iterator.this_arg) * 500000;
        break;

      case IEEE80211_RADIOTAP_FLAGS:
        /* is the CRC visible at the end?
         * remove
         */
        if (*iterator.this_arg & IEEE80211_RADIOTAP_F_FCS)
        {
          fcs_removed = 1;
          caplen -= 4;
        }

        if (*iterator.this_arg & IEEE80211_RADIOTAP_F_RX_BADFCS)
          return (0);

        break;
      }
    }
    n = le16_to_cpu (rthdr->it_len);
    if (n <= 0 || n >= caplen)
      return 0;
  }
    break;
  case ARPHRD_IEEE80211:
    /* do nothing? */
    break;
  default:
    errno = ENOTSUP;
    return -1;
  }

  caplen -= n;

  //detect fcs at the end, even if the flag wasn't set and remove it
  if ((0 == fcs_removed) && (1 == check_crc_buf_osdep (tmpbuf + n, caplen - 4)))
  {
    caplen -= 4;
  }
  memcpy (buf, tmpbuf + n, caplen);
  if (!got_channel)
    ri->ri_channel = linux_get_channel (dev);

  return caplen;
}


/**
 * @return 0 on success
 */
static int
openraw (struct Hardware_Infos *dev)
{
  struct ifreq ifr;
  struct iwreq wrq;
  struct packet_mreq mr;
  struct sockaddr_ll sll;

  /* find the interface index */
  memset (&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, dev->iface, IFNAMSIZ);
  if (-1 == ioctl (dev->fd_raw, SIOCGIFINDEX, &ifr))
  {
    fprintf (stderr,
             "Line: 381 ioctl(SIOCGIFINDEX) on interface `%.*s' failed: %s\n",
             IFNAMSIZ, dev->iface, strerror (errno));
    return 1;
  }

  /* lookup the hardware type */
  memset (&sll, 0, sizeof (sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifr.ifr_ifindex;
  sll.sll_protocol = htons (ETH_P_ALL);
  if (-1 == ioctl (dev->fd_raw, SIOCGIFHWADDR, &ifr))
  {
    fprintf (stderr, "ioctl(SIOCGIFHWADDR) on interface `%.*s' failed: %s\n",
             IFNAMSIZ, dev->iface, strerror (errno));
    return 1;
  }

  /* lookup iw mode */
  memset (&wrq, 0, sizeof (struct iwreq));
  strncpy (wrq.ifr_name, dev->iface, IFNAMSIZ);
  if (-1 == ioctl (dev->fd_raw, SIOCGIWMODE, &wrq))
  {
    /* most probably not supported (ie for rtap ipw interface) *
     * so just assume its correctly set...                     */
    wrq.u.mode = IW_MODE_MONITOR;
  }

  if (((ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211) &&
       (ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_PRISM) &&
       (ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_FULL)) ||
      (wrq.u.mode != IW_MODE_MONITOR))
  {
    fprintf (stderr, "Error: interface `%.*s' is not in monitor mode\n",
             IFNAMSIZ, dev->iface);
    return 1;
  }

  /* Is interface st to up, broadcast & running ? */
  if ((ifr.ifr_flags | IFF_UP | IFF_BROADCAST | IFF_RUNNING) != ifr.ifr_flags)
  {
    /* Bring interface up */
    ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING;

    if (-1 == ioctl (dev->fd_raw, SIOCSIFFLAGS, &ifr))
    {
      fprintf (stderr,
               "Line: 434 ioctl(SIOCSIFFLAGS) on interface `%.*s' failed: %s\n",
               IFNAMSIZ, dev->iface, strerror (errno));
      return 1;
    }
  }

  /* bind the raw socket to the interface */
  if (-1 == bind (dev->fd_raw, (struct sockaddr *) &sll, sizeof (sll)))
  {
    fprintf (stderr, "Failed to bind interface `%.*s': %s\n", IFNAMSIZ,
             dev->iface, strerror (errno));
    return 1;
  }

  /* lookup the hardware type */
  if (-1 == ioctl (dev->fd_raw, SIOCGIFHWADDR, &ifr))
  {
    fprintf (stderr,
             "Line: 457 ioctl(SIOCGIFHWADDR) on interface `%.*s' failed: %s\n",
             IFNAMSIZ, dev->iface, strerror (errno));
    return 1;
  }

  memcpy (dev->pl_mac, ifr.ifr_hwaddr.sa_data, MAC_ADDR_SIZE);
  dev->arptype_in = ifr.ifr_hwaddr.sa_family;
  if ((ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211) &&
      (ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_PRISM) &&
      (ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_FULL))
  {
    fprintf (stderr, "Unsupported hardware link type %d on interface `%.*s'\n",
             ifr.ifr_hwaddr.sa_family, IFNAMSIZ, dev->iface);
    return 1;
  }

  /* enable promiscuous mode */
  memset (&mr, 0, sizeof (mr));
  mr.mr_ifindex = sll.sll_ifindex;
  mr.mr_type = PACKET_MR_PROMISC;
  if (0 !=
      setsockopt (dev->fd_raw, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
                  sizeof (mr)))
  {
    fprintf (stderr, "Failed to enable promiscuous mode on interface `%.*s'\n",
             IFNAMSIZ, dev->iface);
    return 1;
  }

  return 0;
}

/**
 * @return 0 on success
 */
static int
wlaninit (struct Hardware_Infos *dev, const char *iface)
{
  char strbuf[512];
  struct stat sbuf;
  int ret;

  dev->fd_raw = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (0 > dev->fd_raw)
  {
    fprintf (stderr, "Failed to create raw socket: %s\n", strerror (errno));
    return 1;
  }
  if (dev->fd_raw >= FD_SETSIZE)
  {
    fprintf (stderr, "File descriptor too large for select (%d > %d)\n",
             dev->fd_raw, FD_SETSIZE);
    close (dev->fd_raw);
    return 1;
  }

  /* mac80211 stack detection */
  ret =
      snprintf (strbuf, sizeof (strbuf), "/sys/class/net/%s/phy80211/subsystem",
                iface);
  if ((ret < 0) || (ret >= sizeof (strbuf)) || (0 != stat (strbuf, &sbuf)))
  {
    fprintf (stderr, "Did not find 802.11 interface `%s'. Exiting.\n", iface);
    close (dev->fd_raw);
    return 1;
  }
  strncpy (dev->iface, iface, IFNAMSIZ);
  if (0 != openraw (dev))
  {
    close (dev->fd_raw);
    return 1;
  }
  return 0;
}


/**
 * Function to test incoming packets mac for being our own.
 *
 * @param u8aIeeeHeader buffer of the packet
 * @param dev the Hardware_Infos struct
 * @return 0 if mac belongs to us, 1 if mac is for another target
 */
static int
mac_test (const struct ieee80211_frame *u8aIeeeHeader,
          const struct Hardware_Infos *dev)
{
  if (0 != memcmp (u8aIeeeHeader->i_addr3, &mac_bssid, MAC_ADDR_SIZE))
    return 1;
  if (0 == memcmp (u8aIeeeHeader->i_addr1, dev->pl_mac, MAC_ADDR_SIZE))
    return 0;
  if (0 == memcmp (u8aIeeeHeader->i_addr1, &bc_all_mac, MAC_ADDR_SIZE))
    return 0;
  return 1;
}


/**
 * function to set the wlan header to make attacks more difficult
 * @param buf buffer of the packet
 * @param dev pointer to the Hardware_Infos struct
 */
static void
mac_set (struct ieee80211_frame *u8aIeeeHeader,
         const struct Hardware_Infos *dev)
{
  u8aIeeeHeader->i_fc[0] = 0x08;
  u8aIeeeHeader->i_fc[1] = 0x00;
  memcpy (u8aIeeeHeader->i_addr2, dev->pl_mac, MAC_ADDR_SIZE);
  memcpy (u8aIeeeHeader->i_addr3, &mac_bssid, MAC_ADDR_SIZE);

}

struct RadioTapheader
{
  struct ieee80211_radiotap_header header;
  u8 rate;
  u8 pad1;
  u16 txflags;
};

static void
stdin_send_hw (void *cls, void *client, const struct GNUNET_MessageHeader *hdr)
{
  struct Hardware_Infos *dev = cls;
  struct sendbuf *write_pout = &dev->write_pout;
  struct Radiotap_Send *header = (struct Radiotap_Send *) &hdr[1];
  struct ieee80211_frame *wlanheader;
  size_t sendsize;

  // struct? // FIXME: make nice...
  struct RadioTapheader rtheader;

  rtheader.header.it_version = 0;
  rtheader.header.it_len = htole16 (0x0c);
  rtheader.header.it_present = htole32 (0x00008004);
  rtheader.rate = 0x00;
  rtheader.txflags =
      htole16 (IEEE80211_RADIOTAP_F_TX_NOACK | IEEE80211_RADIOTAP_F_TX_NOSEQ);

  /*  { 0x00, 0x00, <-- radiotap version
   * 0x0c, 0x00, <- radiotap header length
   * 0x04, 0x80, 0x00, 0x00,  <-- bitmap
   * 0x00,  <-- rate
   * 0x00,  <-- padding for natural alignment
   * 0x18, 0x00,  <-- TX flags
   * }; */

  sendsize = ntohs (hdr->size);
  if (sendsize <
      sizeof (struct Radiotap_Send) + sizeof (struct GNUNET_MessageHeader))
  {
    fprintf (stderr, "Function stdin_send_hw: mailformed packet (too small)\n");
    exit (1);
  }
  sendsize -=
      sizeof (struct Radiotap_Send) + sizeof (struct GNUNET_MessageHeader);

  if (MAXLINE < sendsize)
  {
    fprintf (stderr, "Function stdin_send_hw: Packet too big for buffer\n");
    exit (1);
  }
  if (GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA != ntohs (hdr->type))
  {
    fprintf (stderr, "Function stdin_send: wrong packet type\n");
    exit (1);
  }

  rtheader.header.it_len = htole16 (sizeof (rtheader));
  rtheader.rate = header->rate;
  memcpy (write_pout->buf, &rtheader, sizeof (rtheader));
  memcpy (write_pout->buf + sizeof (rtheader), &header[1], sendsize);
  /* payload contains MAC address, but we don't trust it, so we'll 
   * overwrite it with OUR MAC address again to prevent mischief */
  wlanheader = (struct ieee80211_frame *) (write_pout->buf + sizeof (rtheader));
  mac_set (wlanheader, dev);
  write_pout->size = sendsize + sizeof (rtheader);
}

#if 0
static int
maketest (unsigned char *buf, struct Hardware_Infos *dev)
{
  uint16_t *tmp16;
  static uint16_t seqenz = 0;
  static int first = 0;

  const int rate = 11000000;
  static const char txt[] =
      "Hallo1Hallo2 Hallo3 Hallo4...998877665544332211Hallo1Hallo2 Hallo3 Hallo4...998877665544332211";

  unsigned char u8aRadiotap[] = { 0x00, 0x00,   // <-- radiotap version
    0x00, 0x00,                 // <- radiotap header length
    0x04, 0x80, 0x02, 0x00,     // <-- bitmap
    0x00,                       // <-- rate
    0x00,                       // <-- padding for natural alignment
    0x10, 0x00,                 // <-- TX flags
    0x04                        //retries
  };

  /*uint8_t u8aRadiotap[] =
   * {
   * 0x00, 0x00, // <-- radiotap version
   * 0x19, 0x00, // <- radiotap header length
   * 0x6f, 0x08, 0x00, 0x00, // <-- bitmap
   * 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
   * 0x00, // <-- flags (Offset +0x10)
   * 0x6c, // <-- rate (0ffset +0x11)
   * 0x71, 0x09, 0xc0, 0x00, // <-- channel
   * 0xde, // <-- antsignal
   * 0x00, // <-- antnoise
   * 0x01, // <-- antenna
   * }; */

  u8aRadiotap[8] = (rate / 500000);
  u8aRadiotap[2] = htole16 (sizeof (u8aRadiotap));

  static struct ieee80211_frame u8aIeeeHeader;

  uint8_t u8aIeeeHeader_def[] = { 0x08, 0x00,   // Frame Control 0x08= 00001000 -> | b1,2 = 0 -> Version 0;
    //      b3,4 = 10 -> Data; b5-8 = 0 -> Normal Data
    //      0x01 = 00000001 -> | b1 = 1 to DS; b2 = 0 not from DS;
    0x00, 0x00,                 // Duration/ID

    //0x00, 0x1f, 0x3f, 0xd1, 0x8e, 0xe6, // mac1 - in this case receiver
    0x00, 0x1d, 0xe0, 0xb0, 0x17, 0xdf, // mac1 - in this case receiver
    0xC0, 0x3F, 0x0E, 0x44, 0x2D, 0x51, // mac2 - in this case sender
    //0x02, 0x1d, 0xe0, 0x00, 0x01, 0xc4,
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac3 - in this case bssid
    0x10, 0x86,                 //Sequence Control
  };
  if (0 == first)
  {
    memcpy (&u8aIeeeHeader, u8aIeeeHeader_def, sizeof (struct ieee80211_frame));
    memcpy (u8aIeeeHeader.i_addr2, dev->pl_mac, MAC_ADDR_SIZE);
    first = 1;
  }

  tmp16 = (uint16_t *) u8aIeeeHeader.i_dur;
  *tmp16 =
      (uint16_t)
      htole16 ((sizeof (txt) +
                sizeof (struct ieee80211_frame) * 1000000) / rate + 290);
  tmp16 = (uint16_t *) u8aIeeeHeader.i_seq;
  *tmp16 =
      (*tmp16 & IEEE80211_SEQ_FRAG_MASK) | (htole16 (seqenz) <<
                                            IEEE80211_SEQ_SEQ_SHIFT);
  seqenz++;

  memcpy (buf, u8aRadiotap, sizeof (u8aRadiotap));
  memcpy (buf + sizeof (u8aRadiotap), &u8aIeeeHeader, sizeof (u8aIeeeHeader));
  memcpy (buf + sizeof (u8aRadiotap) + sizeof (u8aIeeeHeader), txt,
          sizeof (txt));
  return sizeof (u8aRadiotap) + sizeof (u8aIeeeHeader) + sizeof (txt);

}
#endif


/**
 * function to create GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL message for plugin
 * @param buffer pointer to buffer for the message
 * @param mac pointer to the mac address
 * @return number of bytes written
 */
// FIXME: use 'struct MacAddress' for 'mac' (everywhere in this file)
static int
send_mac_to_plugin (char *buffer, uint8_t * mac)
{
  struct Wlan_Helper_Control_Message macmsg;

  macmsg.hdr.size = htons (sizeof (struct Wlan_Helper_Control_Message));
  macmsg.hdr.type = htons (GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL);
  memcpy (macmsg.mac.mac, mac, sizeof (struct MacAddress));
  memcpy (buffer, &macmsg, sizeof (struct Wlan_Helper_Control_Message));
  return sizeof (struct Wlan_Helper_Control_Message);
}


static int
hardwaremode (int argc, char *argv[])
{
  uid_t uid;
  struct Hardware_Infos dev;
  char readbuf[MAXLINE];
  struct sendbuf write_std;
  ssize_t ret;
  int maxfd;
  fd_set rfds;
  fd_set wfds;
  int retval;
  int stdin_open;
  struct GNUNET_SERVER_MessageStreamTokenizer *stdin_mst;

  if (0 != wlaninit (&dev, argv[1]))
    return 1;
  uid = getuid ();
  if (0 != setresuid (uid, uid, uid))
  {
    fprintf (stderr, "Failed to setresuid: %s\n", strerror (errno));
    /* not critical, continue anyway */
  }

  dev.write_pout.size = 0;
  dev.write_pout.pos = 0;
  stdin_mst = GNUNET_SERVER_mst_create (&stdin_send_hw, &dev);

  /* send mac to STDOUT first */
  write_std.pos = 0;
  write_std.size = send_mac_to_plugin ((char *) &write_std.buf, dev.pl_mac);
  stdin_open = 1;

  while (1)
  {
    maxfd = -1;
    FD_ZERO (&rfds);
    if ((0 == dev.write_pout.size) && (1 == stdin_open))
    {
      FD_SET (STDIN_FILENO, &rfds);
      maxfd = MAX (maxfd, STDIN_FILENO);
    }
    if (0 == write_std.size)
    {
      FD_SET (dev.fd_raw, &rfds);
      maxfd = MAX (maxfd, dev.fd_raw);
    }
    FD_ZERO (&wfds);
    if (0 < write_std.size)
    {
      FD_SET (STDOUT_FILENO, &wfds);
      maxfd = MAX (maxfd, STDOUT_FILENO);
    }
    if (0 < dev.write_pout.size)
    {
      FD_SET (dev.fd_raw, &wfds);
      maxfd = MAX (maxfd, dev.fd_raw);
    }
    retval = select (maxfd + 1, &rfds, &wfds, NULL, NULL);
    if ((-1 == retval) && (EINTR == errno))
      continue;
    if (0 > retval)
    {
      fprintf (stderr, "select failed: %s\n", strerror (errno));
      break;
    }

    if (FD_ISSET (STDOUT_FILENO, &wfds))
    {
      ret =
          write (STDOUT_FILENO, write_std.buf + write_std.pos,
                 write_std.size - write_std.pos);
      if (0 > ret)
      {
        fprintf (stderr, "Failed to write to STDOUT: %s\n", strerror (errno));
        break;
      }
      write_std.pos += ret;
      if (write_std.pos == write_std.size)
      {
        write_std.pos = 0;
        write_std.size = 0;
      }
    }

    if (FD_ISSET (dev.fd_raw, &wfds))
    {
      ret = write (dev.fd_raw, dev.write_pout.buf, dev.write_pout.size);
      if (0 > ret)
      {
        fprintf (stderr,
                 "Line %u: Failed to write to WLAN device: %s, Message-Size: %u\n",
                 __LINE__, strerror (errno), dev.write_pout.size);
        break;
      }
      dev.write_pout.pos += ret;
      if ((dev.write_pout.pos != dev.write_pout.size) && (ret != 0))
      {
        fprintf (stderr, "Line %u: Write error, partial send: %u/%u\n",
                 __LINE__, dev.write_pout.pos, dev.write_pout.size);
        break;
      }
      if (dev.write_pout.pos == dev.write_pout.size)
      {
        dev.write_pout.pos = 0;
        dev.write_pout.size = 0;
      }
    }

    if (FD_ISSET (STDIN_FILENO, &rfds))
    {
      ret = read (STDIN_FILENO, readbuf, sizeof (readbuf));
      if (0 > ret)
      {
        fprintf (stderr, "Read error from STDIN: %s\n", strerror (errno));
        break;
      }
      if (0 == ret)
      {
        /* stop reading... */
        stdin_open = 0;
      }
      GNUNET_SERVER_mst_receive (stdin_mst, NULL, readbuf, ret, GNUNET_NO,
                                 GNUNET_NO);
    }

    if (FD_ISSET (dev.fd_raw, &rfds))
    {
      struct GNUNET_MessageHeader *header;
      struct Radiotap_rx *rxinfo;
      struct ieee80211_frame *datastart;

      header = (struct GNUNET_MessageHeader *) write_std.buf;
      rxinfo = (struct Radiotap_rx *) &header[1];
      datastart = (struct ieee80211_frame *) &rxinfo[1];
      ret =
          linux_read (&dev, (unsigned char *) datastart,
                      sizeof (write_std.buf) - sizeof (struct Radiotap_rx) -
                      sizeof (struct GNUNET_MessageHeader), rxinfo);
      if (0 > ret)
      {
        fprintf (stderr, "Read error from raw socket: %s\n", strerror (errno));
        break;
      }
      if ((0 < ret) && (0 == mac_test (datastart, &dev)))
      {
        write_std.size =
            ret + sizeof (struct GNUNET_MessageHeader) +
            sizeof (struct Radiotap_rx);
        header->size = htons (write_std.size);
        header->type = htons (GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA);
      }
    }

  }
  /* Error handling, try to clean up a bit at least */
  GNUNET_SERVER_mst_destroy (stdin_mst);
  close (dev.fd_raw);
  return 1;
}

int
main (int argc, char *argv[])
{
  if (2 != argc)
  {
    fprintf (stderr,
             "This program must be started with the interface as argument.\nThis program was compiled at ----- %s ----\n",
             __TIMESTAMP__);
    fprintf (stderr, "Usage: interface-name\n" "\n");
    return 1;
  }
  return hardwaremode (argc, argv);
}
