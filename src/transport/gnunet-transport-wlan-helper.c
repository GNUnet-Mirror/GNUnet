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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
//#include <sys/utsname.h>
#include <sys/param.h>

/*
 //#include <resolv.h>
 #include <string.h>
 #include <utime.h>
 //#include <unistd.h>
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

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

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

int closeprog;

#include "wlan/helper_common.h"
#include "wlan/loopback_helper.h"

#define DEBUG 1

struct Hardware_Infos
{

  struct sendbuf *write_pout;
  int fd_in, arptype_in;
  int fd_out;

  char *iface;
  unsigned char pl_mac[6];
};



static void
sigfunc_hw(int sig)
{
  closeprog = 1;
}

static void
usage()
{
  printf("Usage: interface-name options\n"
    "options: 0 = with hardware\n"
    "1 = first loopback file\n"
    "2 = second loopback file\n"
    "\n");
}

static unsigned long
calc_crc_osdep(unsigned char * buf, int len)
{
  unsigned long crc = 0xFFFFFFFF;

  for (; len > 0; len--, buf++)
    crc = crc_tbl_osdep[(crc ^ *buf) & 0xFF] ^ (crc >> 8);

  return (~crc);
}

/* CRC checksum verification routine */

static int
check_crc_buf_osdep(unsigned char *buf, int len)
{
  unsigned long crc;

  if (0 > len)
    return 0;

  crc = calc_crc_osdep(buf, len);
  buf += len;
  return (((crc) & 0xFF) == buf[0] && ((crc >> 8) & 0xFF) == buf[1] && ((crc
      >> 16) & 0xFF) == buf[2] && ((crc >> 24) & 0xFF) == buf[3]);
}

static int
linux_get_channel(struct Hardware_Infos *dev)
{
  struct iwreq wrq;
  int fd, frequency;
  int chan = 0;

  memset(&wrq, 0, sizeof(struct iwreq));

  strncpy(wrq.ifr_name, dev->iface, IFNAMSIZ );

  fd = dev->fd_in;
  if (0 > ioctl(fd, SIOCGIWFREQ, &wrq))
    return (-1);

  frequency = wrq.u.freq.m;
  if (100000000 < frequency  )
    frequency /= 100000;
  else if (1000000 < frequency )
    frequency /= 1000;

  if (1000 < frequency)
    chan = getChannelFromFrequency(frequency);
  else
    chan = frequency;

  return chan;
}

static int
linux_read(struct Hardware_Infos * dev, unsigned char *buf, int count,
    struct Radiotap_rx * ri)
{
  unsigned char tmpbuf[4096 * 4];

  int caplen, n, got_signal, got_noise, got_channel, fcs_removed;

  caplen = n = got_signal = got_noise = got_channel = fcs_removed = 0;

  if ((unsigned) count > sizeof(tmpbuf))
    return (-1);
  caplen = read(dev->fd_in, tmpbuf, count);
  if (0 > caplen)
    {
      if (EAGAIN == errno)
        return (0);

      perror("read failed");
      return (-1);
    }

  memset(buf, 0, sizeof(buf));

  if (ri)
    memset(ri, 0, sizeof(*ri));

  if (ARPHRD_IEEE80211_PRISM == dev->arptype_in )
    {
      /* skip the prism header */
      if (tmpbuf[7] == 0x40)
        {
          /* prism54 uses a different format */
          if (ri)
            {
              ri->ri_power = tmpbuf[0x33];
              ri->ri_noise = *(unsigned int *) (tmpbuf + 0x33 + 12);
              ri->ri_rate = (*(unsigned int *) (tmpbuf + 0x33 + 24)) * 500000;

              got_signal = 1;
              got_noise = 1;
            }

          n = 0x40;
        }
      else
        {
          if (ri)
            {
              ri->ri_mactime = *(u_int64_t*) (tmpbuf + 0x5C - 48);
              ri->ri_channel = *(unsigned int *) (tmpbuf + 0x5C - 36);
              ri->ri_power = *(unsigned int *) (tmpbuf + 0x5C);
              ri->ri_noise = *(unsigned int *) (tmpbuf + 0x5C + 12);
              ri->ri_rate = (*(unsigned int *) (tmpbuf + 0x5C + 24)) * 500000;

              got_channel = 1;
              got_signal = 1;
              got_noise = 1;
            }

          n = *(int *) (tmpbuf + 4);
        }

      if (n < 8 || n >= caplen)
        return (0);
    }

  if (ARPHRD_IEEE80211_FULL == dev->arptype_in)
    {
      struct ieee80211_radiotap_iterator iterator;
      struct ieee80211_radiotap_header *rthdr;

      rthdr = (struct ieee80211_radiotap_header *) tmpbuf;

      if (ieee80211_radiotap_iterator_init(&iterator, rthdr, caplen) < 0)
        return (0);

      /* go through the radiotap arguments we have been given
       * by the driver
       */

      while (ri && (ieee80211_radiotap_iterator_next(&iterator) >= 0))
        {

          switch (iterator.this_arg_index)
            {

          case IEEE80211_RADIOTAP_TSFT:
            ri->ri_mactime = le64_to_cpu(*((uint64_t*) iterator.this_arg));
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

      n = le16_to_cpu(rthdr->it_len);

      if (n <= 0 || n >= caplen)
        return (0);
    }

  caplen -= n;

  //detect fcs at the end, even if the flag wasn't set and remove it
  if (0 == fcs_removed && 1== check_crc_buf_osdep(tmpbuf + n, caplen - 4))
    {
      caplen -= 4;
    }

  memcpy(buf, tmpbuf + n, caplen);

  if (ri && !got_channel)
    ri->ri_channel = linux_get_channel(dev);

  return (caplen);
}

static int
linux_write(struct Hardware_Infos * dev, unsigned char *buf, unsigned int count)
{
  int ret;
  //int usedrtap;
  //unsigned short int *p_rtlen;

  //unsigned char * u8aRadiotap = buf;

  /* Pointer to the radiotap header length field for later use. */
  //p_rtlen = (unsigned short int*) (u8aRadiotap + 2);
  //usedrtap = 0;
  ret = write(dev->fd_out, buf, count);

  if (0 > ret)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS || errno
          == ENOMEM)
        {
          usleep(10000);
          return (0);
        }

      perror("write failed");
      return (-1);
    }

  /* radiotap header length is stored little endian on all systems */
  /*if (usedrtap)
   ret -= letoh16(*p_rtlen);

   if (0 > ret)
   {
   if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS || errno
   == ENOMEM)
   {
   usleep(10000);
   return (0);
   }

   perror("write failed");
   return (-1);
   }*/

  return (ret);
}

static int
openraw(struct Hardware_Infos * dev, 
	const char * iface, int fd, int * arptype,
    uint8_t *mac)
{
  struct ifreq ifr;
  struct iwreq wrq;
  struct packet_mreq mr;
  struct sockaddr_ll sll;

  /* find the interface index */

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);

  if (0 > ioctl(fd, SIOCGIFINDEX, &ifr))
    {
      printf("Interface %s: \n", iface);
      perror("ioctl(SIOCGIFINDEX) failed");
      return (1);
    }

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifr.ifr_ifindex;

  sll.sll_protocol = htons(ETH_P_ALL);

  /* lookup the hardware type */

  if (0 > ioctl(fd, SIOCGIFHWADDR, &ifr))
    {
      printf("Interface %s: \n", iface);
      perror("ioctl(SIOCGIFHWADDR) failed");
      return (1);
    }

  /* lookup iw mode */
  memset(&wrq, 0, sizeof(struct iwreq));
  strncpy(wrq.ifr_name, iface, IFNAMSIZ);

  if (0 > ioctl(fd, SIOCGIWMODE, &wrq))
    {
      /* most probably not supported (ie for rtap ipw interface) *
       * so just assume its correctly set...                     */
      wrq.u.mode = IW_MODE_MONITOR;
    }

  if ((ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211 && ifr.ifr_hwaddr.sa_family
      != ARPHRD_IEEE80211_PRISM && ifr.ifr_hwaddr.sa_family
      != ARPHRD_IEEE80211_FULL) || (wrq.u.mode != IW_MODE_MONITOR))
    {
      printf("Error: %s not in monitor mode\n", iface);
      return (1);
    }

  /* Is interface st to up, broadcast & running ? */
  if ((ifr.ifr_flags | IFF_UP | IFF_BROADCAST | IFF_RUNNING) != ifr.ifr_flags)
    {
      /* Bring interface up*/
      ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING;

      if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
        {
          perror("ioctl(SIOCSIFFLAGS) failed");
          return (1);
        }
    }
  /* bind the raw socket to the interface */

  if (0 > bind(fd, (struct sockaddr *) &sll, sizeof(sll)))
    {
      printf("Interface %s: \n", iface);
      perror("bind(ETH_P_ALL) failed");
      return (1);
    }

  /* lookup the hardware type */

  if (0 > ioctl(fd, SIOCGIFHWADDR, &ifr))
    {
      printf("Interface %s: \n", iface);
      perror("ioctl(SIOCGIFHWADDR) failed");
      return (1);
    }

  memcpy(mac, (unsigned char*) ifr.ifr_hwaddr.sa_data, 6);

  *arptype = ifr.ifr_hwaddr.sa_family;

  if (ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211 && ifr.ifr_hwaddr.sa_family
      != ARPHRD_IEEE80211_PRISM && ifr.ifr_hwaddr.sa_family
      != ARPHRD_IEEE80211_FULL)
    {
      if (1 == ifr.ifr_hwaddr.sa_family)
        fprintf(stderr, "\nARP linktype is set to 1 (Ethernet) ");
      else
        fprintf(stderr, "\nUnsupported hardware link type %4d ",
            ifr.ifr_hwaddr.sa_family);

      fprintf(stderr, "- expected ARPHRD_IEEE80211,\nARPHRD_IEEE80211_"
        "FULL or ARPHRD_IEEE80211_PRISM instead.  Make\n"
        "sure RFMON is enabled: run 'airmon-ng start %s"
        " <#>'\nSysfs injection support was not found "
        "either.\n\n", iface);
      return (1);
    }

  /* enable promiscuous mode */

  memset(&mr, 0, sizeof(mr));
  mr.mr_ifindex = sll.sll_ifindex;
  mr.mr_type = PACKET_MR_PROMISC;

  if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
    {
      perror("setsockopt(PACKET_MR_PROMISC) failed");
      return (1);
    }

  return (0);
}

static int
wlaninit(struct Hardware_Infos * dev, const char *iface)
{
  char strbuf[512];
  struct stat sbuf;
  int ret;

  dev->fd_out = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (0 > dev->fd_out)
    {
      perror("socket(PF_PACKET) failed at fd_out");
      goto close_in;
    }

  /* figure out device type */

  /* mac80211 radiotap injection
   * detected based on interface called mon...
   * since mac80211 allows multiple virtual interfaces
   *
   * note though that the virtual interfaces are ultimately using a
   * single physical radio: that means for example they must all
   * operate on the same channel
   */

  /* mac80211 stack detection */
  ret = snprintf(strbuf, 
		 sizeof(strbuf),
		 "/sys/class/net/%s/phy80211/subsystem", 
		 iface);
  if ( (ret < 0) ||
       (ret >= sizeof (strbuf)) ||
       (0 != stat(strbuf, &sbuf)) )
    {
      fprintf(stderr, 
	      "Did not find 802.11 interface `%s'. Exiting.\n",
	      iface);
      return 1;
    }

  if (openraw(dev, iface, dev->fd_out, &dev->arptype_in, dev->pl_mac) != 0)
    {
      goto close_out;
    }

  dev->fd_in = dev->fd_out;
  dev->iface = GNUNET_malloc(sizeof(char) *6);
  strncpy(dev->iface, iface, sizeof(char) * 6);


  return 0;
  close_out: close(dev->fd_out);
  close_in: close(dev->fd_in);
  return 1;
}

/**
 * function to test incoming packets mac
 * @param buf buffer of the packet
 * @param dev pointer to the Hardware_Infos struct
 * @return 0 if macs are okay, 1 if macs are wrong
 */

static int
mac_test(unsigned char * buf, struct Hardware_Infos * dev)
{
  struct ieee80211_frame * u8aIeeeHeader;
  u8aIeeeHeader = (struct ieee80211_frame *) buf;
  if (0 == memcmp(u8aIeeeHeader->i_addr3, &mac_bssid, 6))
    {
      if (0 == memcmp(u8aIeeeHeader->i_addr1, dev->pl_mac, 6))
        {
          return 0;
        }

      if (0 == memcmp(u8aIeeeHeader->i_addr1, &bc_all_mac, 6))
        {
          return 0;
        }
    }

  return 1;
}

/**
 * function to set the wlan header to make attacks more difficult
 * @param buf buffer of the packet
 * @param dev pointer to the Hardware_Infos struct
 */

static void
mac_set(unsigned char * buf, struct Hardware_Infos * dev)
{
  struct ieee80211_frame * u8aIeeeHeader;
  u8aIeeeHeader = (struct ieee80211_frame *) buf;

  u8aIeeeHeader->i_fc[0] = 0x08;
  u8aIeeeHeader->i_fc[1] = 0x00;

  memcpy(u8aIeeeHeader->i_addr2, dev->pl_mac, 6);
  memcpy(u8aIeeeHeader->i_addr3, &mac_bssid, 6);

}

static void
stdin_send_hw(void *cls, void *client, const struct GNUNET_MessageHeader *hdr)
{
  struct Hardware_Infos * dev = cls;
  struct sendbuf *write_pout = dev->write_pout;
  struct Radiotap_Send * header = (struct Radiotap_Send *) &hdr[1];
  unsigned char * wlanheader;

  int sendsize;

  unsigned char u8aRadiotap[] =
    { 0x00, 0x00, // <-- radiotap version
        0x0c, 0x00, // <- radiotap header length
        0x04, 0x80, 0x00, 0x00, // <-- bitmap
        0x00, // <-- rate
        0x00, // <-- padding for natural alignment
        0x18, 0x00, // <-- TX flags
      };

  sendsize = ntohs(hdr->size) - sizeof(struct Radiotap_Send)
      - sizeof(struct GNUNET_MessageHeader);

  if (MAXLINE * 2 < sendsize)
    {
      fprintf(stderr, "Function stdin_send: Packet too big for buffer\n");
      exit(1);
    }

  if (GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA != ntohs(hdr->type))
    {
      fprintf(stderr, "Function stdin_send: wrong packet type\n");
      exit(1);
    }

  if ( sizeof(struct ieee80211_frame)
      + sizeof(struct GNUNET_MessageHeader) > sendsize)
    {
      fprintf(stderr, "Function stdin_send: packet too small\n");
      exit(1);
    }

  u8aRadiotap[2] = htole16(sizeof(u8aRadiotap));
  u8aRadiotap[8] = header->rate;

  memcpy(write_pout->buf, u8aRadiotap, sizeof(u8aRadiotap));
  memcpy(write_pout->buf + sizeof(u8aRadiotap), &header[1], sendsize);
  
  wlanheader = write_pout->buf + sizeof(u8aRadiotap);
  mac_set(wlanheader, dev);
  
  sendsize += sizeof(u8aRadiotap);
  write_pout->size = sendsize;
}

static int
maketest(unsigned char * buf, struct Hardware_Infos * dev)
{
  uint16_t * tmp16;
  static uint16_t seqenz = 0;
  static int first = 0;

  const int rate = 11000000;
  static const char
      txt[] =
          "Hallo1Hallo2 Hallo3 Hallo4...998877665544332211Hallo1Hallo2 Hallo3 Hallo4...998877665544332211";

  unsigned char u8aRadiotap[] =
    { 0x00, 0x00, // <-- radiotap version
        0x00, 0x00, // <- radiotap header length
        0x04, 0x80, 0x02, 0x00, // <-- bitmap
        0x00, // <-- rate
        0x00, // <-- padding for natural alignment
        0x10, 0x00, // <-- TX flags
        0x04 //retries
      };

  /*uint8_t u8aRadiotap[] =
   {
   0x00, 0x00, // <-- radiotap version
   0x19, 0x00, // <- radiotap header length
   0x6f, 0x08, 0x00, 0x00, // <-- bitmap
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
   0x00, // <-- flags (Offset +0x10)
   0x6c, // <-- rate (0ffset +0x11)
   0x71, 0x09, 0xc0, 0x00, // <-- channel
   0xde, // <-- antsignal
   0x00, // <-- antnoise
   0x01, // <-- antenna
   };*/

  u8aRadiotap[8] = (rate / 500000);
  u8aRadiotap[2] = htole16(sizeof(u8aRadiotap));

  static struct ieee80211_frame u8aIeeeHeader;

  uint8_t u8aIeeeHeader_def[] =
    { 0x08, 0x00, // Frame Control 0x08= 00001000 -> | b1,2 = 0 -> Version 0;
        //      b3,4 = 10 -> Data; b5-8 = 0 -> Normal Data
        //      0x01 = 00000001 -> | b1 = 1 to DS; b2 = 0 not from DS;
        0x00, 0x00, // Duration/ID

        //0x00, 0x1f, 0x3f, 0xd1, 0x8e, 0xe6, // mac1 - in this case receiver
        0x00, 0x1d, 0xe0, 0xb0, 0x17, 0xdf, // mac1 - in this case receiver
        0xC0, 0x3F, 0x0E, 0x44, 0x2D, 0x51, // mac2 - in this case sender
        //0x02, 0x1d, 0xe0, 0x00, 0x01, 0xc4,
        0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac3 - in this case bssid
        0x10, 0x86, //Sequence Control
      };
  if (0 == first)
    {
      memcpy(&u8aIeeeHeader, u8aIeeeHeader_def, sizeof(struct ieee80211_frame));
      memcpy(u8aIeeeHeader.i_addr2, dev->pl_mac, 6);
      first = 1;
    }

  tmp16 = (uint16_t*) u8aIeeeHeader.i_dur;
  *tmp16
      = (uint16_t) htole16((sizeof(txt) + sizeof(struct ieee80211_frame) * 1000000) / rate + 290);
  tmp16 = (uint16_t*) u8aIeeeHeader.i_seq;
  *tmp16 = (*tmp16 & IEEE80211_SEQ_FRAG_MASK) | (htole16(seqenz)
      << IEEE80211_SEQ_SEQ_SHIFT);
  seqenz++;

  memcpy(buf, u8aRadiotap, sizeof(u8aRadiotap));
  memcpy(buf + sizeof(u8aRadiotap), &u8aIeeeHeader, sizeof(u8aIeeeHeader));
  memcpy(buf + sizeof(u8aRadiotap) + sizeof(u8aIeeeHeader), txt, sizeof(txt));
  return sizeof(u8aRadiotap) + sizeof(u8aIeeeHeader) + sizeof(txt);

}

int
hardwaremode(int argc, char *argv[])
{

  uid_t uid;
  struct Hardware_Infos dev;
  struct Radiotap_rx * rxinfo;
  uint8_t * mac = dev.pl_mac;
  int fdpin, fdpout;

  struct GNUNET_MessageHeader * header;

  signal(SIGINT, &sigfunc_hw);
  signal(SIGTERM, &sigfunc_hw);

  if (wlaninit(&dev, argv[1]))
    {
      return 1;
    }

  uid = getuid();
  //if (0 != setresuid(uid, uid, uid))
  //{
  //  fprintf(stderr, "Failed to setresuid: %s\n", strerror(errno));
  /* not critical, continue anyway */
  //}

  unsigned char * datastart;
  char readbuf[MAXLINE];
  int readsize = 0;
  struct sendbuf write_std;
  write_std.size = 0;
  write_std.pos = 0;

  struct sendbuf write_pout;
  write_pout.size = 0;
  write_pout.pos = 0;

  dev.write_pout = &write_pout;

  int ret = 0;
  int maxfd = 0;

  fd_set rfds;
  fd_set wfds;
  struct timeval tv;
  int retval;

  struct GNUNET_SERVER_MessageStreamTokenizer * stdin_mst;

  fdpin = dev.fd_in;
  fdpout = dev.fd_out;

  stdin_mst = GNUNET_SERVER_mst_create(&stdin_send_hw, &dev);

  //send mac first

  write_std.size = send_mac_to_plugin((char *) &write_std.buf, mac);

  //wait
  tv.tv_sec = 2;
  tv.tv_usec = 0;
  retval = select(0, NULL, NULL, NULL, &tv);

  while (0 == closeprog)
    {

      //write_pout.size = maketest(write_pout.buf, &dev);
      //tv.tv_sec = 2;
      //tv.tv_usec = 0;
      //select(0, NULL, NULL, NULL, &tv);

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
              goto end;
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

          ret = linux_write(&dev, write_pout.buf, write_pout.size);

          if (0 > ret)
            {
              closeprog = 1;
              fprintf(stderr, "Write ERROR to fdpout\n");
            }
          else
            {
              write_pout.pos += ret;
              // check if finished
              if (write_pout.pos != write_pout.size && ret != 0)
                {
                  closeprog = 1;
                  fprintf(stderr,
                      "Write ERROR packet not in one piece send: %u, %u\n",
                      write_pout.pos, write_pout.size);
                }
              else if (write_pout.pos == write_pout.size)
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
          rxinfo = (struct Radiotap_rx *) (write_std.buf
              + sizeof(struct GNUNET_MessageHeader));
          datastart = (unsigned char *) write_std.buf
              + sizeof(struct Radiotap_rx)
              + sizeof(struct GNUNET_MessageHeader);

          readsize = linux_read(&dev, datastart, sizeof(write_std.buf)
              - sizeof(struct Radiotap_rx)
              - sizeof(struct GNUNET_MessageHeader), rxinfo);

          if (0 > readsize)
            {
              closeprog = 1;
              fprintf(stderr, "Read ERROR to fdpin: %s\n", strerror(errno));
              closeprog = 1;
            }
          else if (0 < readsize)
            {
              if (1 == mac_test(datastart, &dev))
                {
                  // mac wrong
                  write_std.pos = 0;
                  write_std.size = 0;
                }
              else
                {
                  header = (struct GNUNET_MessageHeader *) write_std.buf;
                  write_std.size = readsize
                      + sizeof(struct GNUNET_MessageHeader)
                      + sizeof(struct Radiotap_rx);
                  header->size = htons(write_std.size);
                  header->type = htons(GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA);
                  fprintf(stderr, "Got packet with size: %u, size std %u\n",
                      readsize, write_std.size);

                }
            }
        }

    }

  GNUNET_SERVER_mst_destroy(stdin_mst);
  return 0;

  end: GNUNET_SERVER_mst_destroy(stdin_mst);
  return 1;

}

int
main(int argc, char *argv[])
{
  int ret = 0;
  if (3 != argc)
    {
      fprintf(
          stderr,
          "This program must be started with the interface and the operating mode as argument.\n");
      usage();
      return 1;
    }

  if (strstr(argv[2], "1") || strstr(argv[2], "2"))
    {

      ret = testmode(argc, argv);
    }
  else
    {

      ret = hardwaremode(argc, argv);
    }

  return ret;
  maketest(NULL, NULL);
}

