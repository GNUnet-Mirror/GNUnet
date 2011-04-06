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

int first;
int closeprog;

#include "wlan/helper_common.h"
#include "wlan/loopback_helper.h"

#define DEBUG 1

typedef enum
{
  DT_NULL = 0,
  DT_WLANNG,
  DT_HOSTAP,
  DT_MADWIFI,
  DT_MADWIFING,
  DT_BCM43XX,
  DT_ORINOCO,
  DT_ZD1211RW,
  DT_ACX,
  DT_MAC80211_RT,
  DT_AT76USB,
  DT_IPW2200

} DRIVER_TYPE;

static const char * szaDriverTypes[] =
  { [DT_NULL] = "Unknown", [DT_WLANNG] = "Wlan-NG", [DT_HOSTAP] = "HostAP",
      [DT_MADWIFI] = "Madwifi", [DT_MADWIFING] = "Madwifi-NG",
      [DT_BCM43XX] = "BCM43xx", [DT_ORINOCO] = "Orinoco",
      [DT_ZD1211RW] = "ZD1211RW", [DT_ACX] = "ACX",
      [DT_MAC80211_RT] = "Mac80211-Radiotap", [DT_AT76USB] = "Atmel 76_usb",
      [DT_IPW2200] = "ipw2200" };

struct Hardware_Infos
{

  struct sendbuf *write_pout;
  int fd_in, arptype_in;
  int fd_out, arptype_out;
  int fd_main;
  int fd_rtc;

  DRIVER_TYPE drivertype; /* inited to DT_UNKNOWN on allocation by wi_alloc */

  FILE *f_cap_in;

  struct pcap_file_header pfh_in;

  int sysfs_inject;
  int channel;
  int freq;
  int rate;
  int tx_power;
  char *wlanctlng; /* XXX never set */
  char *iwpriv;
  char *iwconfig;
  char *ifconfig;
  char *iface;
  char *main_if;
  unsigned char pl_mac[6];
  int inject_wlanng;
};

//#include "radiotap.h"

// mac of this node
char mac[] =
  { 0x13, 0x22, 0x33, 0x44, 0x55, 0x66 };

/* wifi bitrate to use in 500kHz units */

static const u8 u8aRatesToUse[] =
  {

  54 * 2, 48 * 2, 36 * 2, 24 * 2, 18 * 2, 12 * 2, 9 * 2, 11 * 2, 11, // 5.5
      2 * 2, 1 * 2 };

#define	OFFSET_FLAGS 0x10
#define	OFFSET_RATE 0x11

// this is where we store a summary of the
// information from the radiotap header

typedef struct
{
  int m_nChannel;
  int m_nChannelFlags;
  int m_nRate;
  int m_nAntenna;
  int m_nRadiotapFlags;
}__attribute__((packed)) PENUMBRA_RADIOTAP_DATA;

static void
sigfunc_hw(int sig)
{
  closeprog = 1;
}

void
Dump(u8 * pu8, int nLength)
{
  char sz[256], szBuf[512], szChar[17], *buf, fFirst = 1;
  unsigned char baaLast[2][16];
  uint n, nPos = 0, nStart = 0, nLine = 0, nSameCount = 0;

  buf = szBuf;
  szChar[0] = '\0';

  for (n = 0; n < nLength; n++)
    {
      baaLast[(nLine & 1) ^ 1][n & 0xf] = pu8[n];
      if ((pu8[n] < 32) || (pu8[n] >= 0x7f))
        szChar[n & 0xf] = '.';
      else
        szChar[n & 0xf] = pu8[n];
      szChar[(n & 0xf) + 1] = '\0';
      nPos += sprintf(&sz[nPos], "%02X ", baaLast[(nLine & 1) ^ 1][n & 0xf]);
      if ((n & 15) != 15)
        continue;
      if ((memcmp(baaLast[0], baaLast[1], 16) == 0) && (!fFirst))
        {
          nSameCount++;
        }
      else
        {
          if (nSameCount)
            buf += sprintf(buf, "(repeated %d times)\n", nSameCount);
          buf += sprintf(buf, "%04x: %s %s\n", nStart, sz, szChar);
          nSameCount = 0;
          printf("%s", szBuf);
          buf = szBuf;
        }
      nPos = 0;
      nStart = n + 1;
      nLine++;
      fFirst = 0;
      sz[0] = '\0';
      szChar[0] = '\0';
    }
  if (nSameCount)
    buf += sprintf(buf, "(repeated %d times)\n", nSameCount);

  buf += sprintf(buf, "%04x: %s", nStart, sz);
  if (n & 0xf)
    {
      *buf++ = ' ';
      while (n & 0xf)
        {
          buf += sprintf(buf, "   ");
          n++;
        }
    }
  buf += sprintf(buf, "%s\n", szChar);
  printf("%s", szBuf);
}

void
usage()
{
  printf("Usage: interface-name optins\n"
    "options: 0 = with hardware\n"
    "1 = first loopback file\n"
    "2 = second loopback file\n"
    "\n");
  exit(1);
}

unsigned long
calc_crc_osdep(unsigned char * buf, int len)
{
  unsigned long crc = 0xFFFFFFFF;

  for (; len > 0; len--, buf++)
    crc = crc_tbl_osdep[(crc ^ *buf) & 0xFF] ^ (crc >> 8);

  return (~crc);
}

/* CRC checksum verification routine */

int
check_crc_buf_osdep(unsigned char *buf, int len)
{
  unsigned long crc;

  if (len < 0)
    return 0;

  crc = calc_crc_osdep(buf, len);
  buf += len;
  return (((crc) & 0xFF) == buf[0] && ((crc >> 8) & 0xFF) == buf[1] && ((crc
      >> 16) & 0xFF) == buf[2] && ((crc >> 24) & 0xFF) == buf[3]);
}

/* Search a file recursively */
static char *
searchInside(const char * dir, const char * filename)
{
  char * ret;
  char * curfile;
  struct stat sb;
  int len, lentot;
  DIR *dp;
  struct dirent *ep;

  dp = opendir(dir);
  if (dp == NULL)
    {
      return NULL;
    }

  len = strlen(filename);
  lentot = strlen(dir) + 256 + 2;
  curfile = (char *) calloc(1, lentot);

  while ((ep = readdir(dp)) != NULL)
    {

      memset(curfile, 0, lentot);
      sprintf(curfile, "%s/%s", dir, ep->d_name);

      //Checking if it's the good file
      if ((int) strlen(ep->d_name) == len && !strcmp(ep->d_name, filename))
        {
          (void) closedir(dp);
          return curfile;
        }
      lstat(curfile, &sb);

      //If it's a directory and not a link, try to go inside to search
      if (S_ISDIR(sb.st_mode) && !S_ISLNK(sb.st_mode))
        {
          //Check if the directory isn't "." or ".."
          if (strcmp(".", ep->d_name) && strcmp("..", ep->d_name))
            {
              //Recursive call
              ret = searchInside(curfile, filename);
              if (ret != NULL)
                {
                  (void) closedir(dp);
                  free(curfile);
                  return ret;
                }
            }
        }
    }
  (void) closedir(dp);
  free(curfile);
  return NULL;
}

/* Search a wireless tool and return its path */
static char *
wiToolsPath(const char * tool)
{
  char * path;
  int i, nbelems;
  static const char * paths[] =
    { "/sbin", "/usr/sbin", "/usr/local/sbin", "/bin", "/usr/bin",
        "/usr/local/bin", "/tmp" };

  nbelems = sizeof(paths) / sizeof(char *);

  for (i = 0; i < nbelems; i++)
    {
      path = searchInside(paths[i], tool);
      if (path != NULL)
        return path;
    }

  return NULL;
}

static int
linux_get_channel(struct Hardware_Infos *dev)
{
  struct iwreq wrq;
  int fd, frequency;
  int chan = 0;

  memset(&wrq, 0, sizeof(struct iwreq));

  if (dev->main_if)
    strncpy(wrq.ifr_name, dev->main_if, IFNAMSIZ );
  else
    strncpy(wrq.ifr_name, dev->iface, IFNAMSIZ );

  fd = dev->fd_in;
  if (dev->drivertype == DT_IPW2200)
    fd = dev->fd_main;

  if (ioctl(fd, SIOCGIWFREQ, &wrq) < 0)
    return (-1);

  frequency = wrq.u.freq.m;
  if (frequency > 100000000)
    frequency /= 100000;
  else if (frequency > 1000000)
    frequency /= 1000;

  if (frequency > 1000)
    chan = getChannelFromFrequency(frequency);
  else
    chan = frequency;

  return chan;
}

static int
linux_read(struct Hardware_Infos * dev, unsigned char *buf, int count,
    struct Radiotap_rx * ri)
{
  unsigned char tmpbuf[4096];

  int caplen, n, got_signal, got_noise, got_channel, fcs_removed;

  caplen = n = got_signal = got_noise = got_channel = fcs_removed = 0;

  if ((unsigned) count > sizeof(tmpbuf))
    return (-1);
  caplen = read(dev->fd_in, tmpbuf, count);
  if (0 > caplen)
    {
      if (errno == EAGAIN)
        return (0);

      perror("read failed");
      return (-1);
    }

  memset(buf, 0, sizeof(buf));

  /* XXX */
  if (ri)
    memset(ri, 0, sizeof(*ri));

  if (dev->arptype_in == ARPHRD_IEEE80211_PRISM)
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

  if (dev->arptype_in == ARPHRD_IEEE80211_FULL)
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
  if (fcs_removed == 0 && check_crc_buf_osdep(tmpbuf + n, caplen - 4) == 1)
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
  int ret, usedrtap = 0;
  unsigned short int *p_rtlen;

  unsigned char * u8aRadiotap = buf;

  /* Pointer to the radiotap header length field for later use. */
  p_rtlen = (unsigned short int*) (u8aRadiotap + 2);
  usedrtap = 0;
  ret = write(dev->fd_out, buf, count);

  if (ret < 0)
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
  if (usedrtap)
    ret -= letoh16(*p_rtlen);

  if (ret < 0)
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

  return (ret);
}

static int
openraw(struct Hardware_Infos * dev, char * iface, int fd, int * arptype,
    uint8_t *mac)
{
  struct ifreq ifr;
  struct iwreq wrq;
  struct packet_mreq mr;
  struct sockaddr_ll sll;

  /* find the interface index */

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);

  if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
    {
      printf("Interface %s: \n", iface);
      perror("ioctl(SIOCGIFINDEX) failed");
      return (1);
    }

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifr.ifr_ifindex;

  switch (dev->drivertype)
    {
  default:
    sll.sll_protocol = htons(ETH_P_ALL);
    break;
    }

  /* lookup the hardware type */

  if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
    {
      printf("Interface %s: \n", iface);
      perror("ioctl(SIOCGIFHWADDR) failed");
      return (1);
    }

  /* lookup iw mode */
  memset(&wrq, 0, sizeof(struct iwreq));
  strncpy(wrq.ifr_name, iface, IFNAMSIZ);

  if (ioctl(fd, SIOCGIWMODE, &wrq) < 0)
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

  if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) < 0)
    {
      printf("Interface %s: \n", iface);
      perror("bind(ETH_P_ALL) failed");
      return (1);
    }

  /* lookup the hardware type */

  if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
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
      if (ifr.ifr_hwaddr.sa_family == 1)
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

int
wlaninit(struct Hardware_Infos * dev, char *iface)
{

  char *iwpriv;
  char strbuf[512];
  dev->inject_wlanng = 1;
  dev->rate = 2; /* default to 1Mbps if nothing is set */

  /* open raw socks */
  dev->fd_in = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (0 > dev->fd_in)
    {
      perror("socket(PF_PACKET) failed at fd_in");
      if (getuid() != 0)
        fprintf(stderr, "This program requires root privileges.\n");
      return (1);
    }

  dev->fd_main = socket(PF_PACKET, SOCK_RAW, htons( ETH_P_ALL ) );
  if (0 > dev->fd_main)
    {
      perror("socket(PF_PACKET) failed at fd_main");
      if (getuid() != 0)
        fprintf(stderr, "This program requires root privileges.\n");
      return (1);
    }

  /* Check iwpriv existence */

  iwpriv = wiToolsPath("iwpriv");
  dev->iwpriv = iwpriv;
  dev->iwconfig = wiToolsPath("iwconfig");
  dev->ifconfig = wiToolsPath("ifconfig");

  if (!iwpriv)
    {
      fprintf(stderr, "Can't find wireless tools, exiting.\n");
      goto close_in;
    }

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
  memset(strbuf, 0, sizeof(strbuf));
  snprintf(strbuf, sizeof(strbuf) - 1,
      "ls /sys/class/net/%s/phy80211/subsystem >/dev/null 2>/dev/null", iface);

  if (system(strbuf) == 0)
    dev->drivertype = DT_MAC80211_RT;

  else
    {
      // At the moment only mac80211 tested
      return 1;
    }

#ifdef DEBUG
  fprintf(stderr, "Interface %s -> driver: %s\n", iface,
      szaDriverTypes[dev->drivertype]);
#endif

  if (openraw(dev, iface, dev->fd_out, &dev->arptype_out, dev->pl_mac) != 0)
    {
      goto close_out;
    }

  dev->fd_in = dev->fd_out;

  dev->arptype_in = dev->arptype_out;

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
  if (0 == memcmp(u8aIeeeHeader->i_addr3, mac_bssid, 6))
    {
      if (0 == memcmp(u8aIeeeHeader->i_addr2, dev->pl_mac, 6))
        {
          return 0;
        }

      if (0 == memcmp(u8aIeeeHeader->i_addr2, bc_all_mac, 6))
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

  u8aIeeeHeader->i_fc[0] = 0x80;
  u8aIeeeHeader->i_fc[1] = 0x00;

  memcpy(u8aIeeeHeader->i_addr2, dev->pl_mac, 6);
  memcpy(u8aIeeeHeader->i_addr3, mac_bssid, 6);

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

  if ((sendsize) > MAXLINE * 2)
    {
      fprintf(stderr, "Function stdin_send: Packet too big for buffer\n");
      exit(1);
    }

  if (GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA != ntohs(hdr->type))
    {
      fprintf(stderr, "Function stdin_send: wrong packet type\n");
      exit(1);
    }

  if (sendsize < sizeof(struct ieee80211_frame) + sizeof(struct WlanHeader)
      + sizeof(struct FragmentationHeader)
      + sizeof(struct GNUNET_MessageHeader))
    {
      fprintf(stderr, "Function stdin_send: packet too small\n");
      exit(1);
    }

  u8aRadiotap[2] = htole16(sizeof(u8aRadiotap));
  u8aRadiotap[8] = header->rate;

  switch (dev->drivertype)
    {

  case DT_MAC80211_RT:
    memcpy(write_pout->buf, u8aRadiotap, sizeof(u8aRadiotap));
    memcpy(write_pout->buf + sizeof(u8aRadiotap), write_pout->buf
        + sizeof(struct Radiotap_Send) + sizeof(struct GNUNET_MessageHeader),
        sendsize);

    wlanheader =  write_pout->buf + sizeof(u8aRadiotap);
    mac_set(wlanheader, dev);

    sendsize += sizeof(u8aRadiotap);

    break;
  default:
    break;
    }

  write_pout->size = sendsize;
}

int
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
        0x02, 0x1d, 0xe0, 0x00, 0x01, 0xc4,
        //0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac3 - in this case bssid
        0x10, 0x86, //Sequence Control
      };
  if (first == 0)
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

  struct Hardware_Infos dev;
  struct ifreq ifreq;
  struct Radiotap_rx * rxinfo;
  uint8_t * mac = dev.pl_mac;
  int fdpin, fdpout;

  signal(SIGINT, &sigfunc_hw);
  signal(SIGTERM, &sigfunc_hw);

  if (wlaninit(&dev, argv[1]))
    {
      return 1;
    }

  printf("Device %s -> Ethernet %02x:%02x:%02x:%02x:%02x:%02x\n",
      ifreq.ifr_name, (int) mac[0], (int) mac[1], (int) mac[2], (int) mac[3],
      (int) mac[4], (int) mac[5]);

  //return 0;

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

      write_pout.size = maketest(write_pout.buf, &dev);
      tv.tv_sec = 2;
      tv.tv_usec = 0;
      retval = select(0, NULL, NULL, NULL, &tv);

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
          //FD_SET(fdpin, &rfds);
          //maxfd = fdpin;
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
          rxinfo = (struct Radiotap_rx *) (write_pout.buf
              + sizeof(struct GNUNET_MessageHeader));
          datastart = (unsigned char *) readbuf + sizeof(struct Radiotap_rx)
              + sizeof(struct GNUNET_MessageHeader);

          readsize = linux_read(&dev, datastart, sizeof(readbuf)
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
                  write_pout.pos = 0;
                  write_pout.size = 0;
                }
            }
          else
            {
              //eof
              //closeprog = 1;
            }
        }

    }

  GNUNET_SERVER_mst_destroy(stdin_mst);
  return 0;

}

int
main(int argc, char *argv[])
{
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

      return testmode(argc, argv);
    }
  else
    {
      return hardwaremode(argc, argv);
    }

#if 0
  u8 u8aSendBuffer[500];
  char szErrbuf[PCAP_ERRBUF_SIZE];
  int nCaptureHeaderLength = 0, n80211HeaderLength = 0, nLinkEncap = 0;
  int nOrdinal = 0, r, nDelay = 100000;
  int nRateIndex = 0, retval, bytes;
  pcap_t *ppcap = NULL;
  struct bpf_program bpfprogram;
  char * szProgram = "", fBrokenSocket = 0;
  u16 u16HeaderLen;
  char szHostname[PATH_MAX];

  if (gethostname(szHostname, sizeof (szHostname) - 1))
    {
      perror("unable to get hostname");
    }
  szHostname[sizeof (szHostname) - 1] = '\0';

  printf("Packetspammer (c)2007 Andy Green <andy@warmcat.com>  GPL2\n");

  while (1)
    {
      int nOptionIndex;
      static const struct option optiona[] =
        {
            { "delay", required_argument, NULL, 'd'},
            { "fcs", no_argument, &flagMarkWithFCS, 1},
            { "help", no_argument, &flagHelp, 1},
            { "verbose", no_argument, &flagVerbose, 1},
            { 0, 0, 0, 0}
        };
      int c = getopt_long(argc, argv, "d:hf",
          optiona, &nOptionIndex);

      if (c == -1)
      break;
      switch (c)
        {
          case 0: // long option
          break;

          case 'h': // help
          usage();

          case 'd': // delay
          nDelay = atoi(optarg);
          break;

          case 'f': // mark as FCS attached
          flagMarkWithFCS = 1;
          break;

          case 'v': //Verbose / readable output to cout
          flagVerbose = 1;
          break;

          default:
          printf("unknown switch %c\n", c);
          usage();
          break;
        }
    }

  if (optind >= argc)
  usage();

  // open the interface in pcap

  szErrbuf[0] = '\0';
  ppcap = pcap_open_live(argv[optind], 800, 1, 20, szErrbuf);
  if (ppcap == NULL)
    {
      printf("Unable to open interface %s in pcap: %s\n",
          argv[optind], szErrbuf);
      return (1);
    }

  //get mac from interface

  /*int sock, j, k;
   char mac[32];

   sock=socket(PF_INET, SOCK_STREAM, 0);
   if (-1==sock) {
   perror("can not open socket\n");
   return 1;
   }

   if (-1==ioctl(sock, SIOCGIFHWADDR, &ifr)) {
   perror("ioctl(SIOCGIFHWADDR) ");
   return 1;
   }
   for (j=0, k=0; j<6; j++) {
   k+=snprintf(mac+k, sizeof(mac)-k-1, j ? ":%02X" : "%02X",
   (int)(unsigned int)(unsigned char)ifr.ifr_hwaddr.sa_data[j]);
   }
   mac[sizeof(mac)-1]='\0';
   */

  //get header type
  nLinkEncap = pcap_datalink(ppcap);
  nCaptureHeaderLength = 0;

  switch (nLinkEncap)
    {

      case DLT_PRISM_HEADER:
      printf("DLT_PRISM_HEADER Encap\n");
      nCaptureHeaderLength = 0x40;
      n80211HeaderLength = 0x20; // ieee80211 comes after this
      szProgram = "radio[0x4a:4]==0x13223344";
      break;

      case DLT_IEEE802_11_RADIO:
      printf("DLT_IEEE802_11_RADIO Encap\n");
      nCaptureHeaderLength = 0x40;
      n80211HeaderLength = 0x18; // ieee80211 comes after this
      szProgram = "ether[0x0a:4]==0x13223344";
      break;

      default:
      printf("!!! unknown encapsulation on %s !\n", argv[1]);
      return (1);

    }

  if (pcap_compile(ppcap, &bpfprogram, szProgram, 1, 0) == -1)
    {
      puts(szProgram);
      puts(pcap_geterr(ppcap));
      return (1);
    }
  else
    {
      if (pcap_setfilter(ppcap, &bpfprogram) == -1)
        {
          puts(szProgram);
          puts(pcap_geterr(ppcap));
        }
      else
        {
          printf("RX Filter applied\n");
        }
      pcap_freecode(&bpfprogram);
    }

  pcap_setnonblock(ppcap, 1, szErrbuf);

  printf("   (delay between packets %dus)\n", nDelay);

  memset(u8aSendBuffer, 0, sizeof(u8aSendBuffer));

  while (!fBrokenSocket)
    {
      u8 * pu8 = u8aSendBuffer;
      struct pcap_pkthdr * ppcapPacketHeader = NULL;
      struct ieee80211_radiotap_iterator rti;
      PENUMBRA_RADIOTAP_DATA prd;
      //init of the values
      prd.m_nRate = 255;
      prd.m_nChannel = 255;
      prd.m_nAntenna = 255;
      prd.m_nRadiotapFlags = 255;
      u8 * pu8Payload = u8aSendBuffer;
      int n, nRate;

      // receive

      retval = pcap_next_ex(ppcap, &ppcapPacketHeader,
          (const u_char**) &pu8Payload);

      if (retval < 0)
        {
          fBrokenSocket = 1;
          continue;
        }

      if (retval != 1)
      goto do_tx;

      u16HeaderLen = (pu8Payload[2] + (pu8Payload[3] << 8));

      printf("rtap: ");
      Dump(pu8Payload, u16HeaderLen);

      if (ppcapPacketHeader->len < (u16HeaderLen + n80211HeaderLength))
      continue;

      bytes = ppcapPacketHeader->len - (u16HeaderLen + n80211HeaderLength);
      if (bytes < 0)
      continue;

      if (ieee80211_radiotap_iterator_init(&rti,
              (struct ieee80211_radiotap_header *) pu8Payload, bytes) < 0)
      continue;

      while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0)
        {

          switch (rti.this_arg_index)
            {
              case IEEE80211_RADIOTAP_RATE:
              prd.m_nRate = (*rti.this_arg);
              break;

              case IEEE80211_RADIOTAP_CHANNEL:
              prd.m_nChannel = le16_to_cpu(*((u16 *)rti.this_arg));
              prd.m_nChannelFlags = le16_to_cpu(*((u16 *)(rti.this_arg + 2)));
              break;

              case IEEE80211_RADIOTAP_ANTENNA:
              prd.m_nAntenna = (*rti.this_arg) + 1;
              break;

              case IEEE80211_RADIOTAP_FLAGS:
              prd.m_nRadiotapFlags = *rti.this_arg;
              break;

            }
        }

      pu8Payload += u16HeaderLen + n80211HeaderLength;

      if (prd.m_nRadiotapFlags & IEEE80211_RADIOTAP_F_FCS)
      bytes -= 4;

      printf("RX: Rate: %2d.%dMbps, Freq: %d.%dGHz, "
          "Ant: %d, Flags: 0x%X\n", prd.m_nRate / 2, 5 * (prd.m_nRate & 1),
          prd.m_nChannel / 1000, prd.m_nChannel - ((prd.m_nChannel / 1000)
              * 1000), prd.m_nAntenna, prd.m_nRadiotapFlags);

      Dump(pu8Payload, bytes);

      do_tx:

      // transmit

      memcpy(u8aSendBuffer, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));
      if (flagMarkWithFCS)
      pu8[OFFSET_FLAGS] |= IEEE80211_RADIOTAP_F_FCS;
      nRate = pu8[OFFSET_RATE] = u8aRatesToUse[nRateIndex++];
      if (nRateIndex >= sizeof(u8aRatesToUse))
      nRateIndex = 0;
      pu8 += sizeof(u8aRadiotapHeader);

      memcpy(pu8, u8aIeeeHeader, sizeof(u8aIeeeHeader));
      pu8 += sizeof(u8aIeeeHeader);

      pu8 += sprintf((char *) u8aSendBuffer, "Packetspammer %02d"
          "broadcast packet"
          "#%05d -- :-D --%s ----", nRate / 2, nOrdinal++, szHostname);
      r = pcap_inject(ppcap, u8aSendBuffer, pu8 - u8aSendBuffer);
      if (r != (pu8 - u8aSendBuffer))
        {
          perror("Trouble injecting packet");
          return (1);
        }
      if (nDelay)
      usleep(nDelay);
    }

#endif
  return (0);
}

