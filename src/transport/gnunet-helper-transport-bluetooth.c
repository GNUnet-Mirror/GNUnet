/*
   This file is part of GNUnet.
   Copyright (C) 2010, 2011, 2012 Christian Grothoff (and other contributing authors)
   Copyright (c) 2007, 2008, Andy Green <andy@warmcat.com>
   Copyright Copyright (C) 2009 Thomas d'Otreppe

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
   Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.
*/
#include "gnunet_config.h"

#ifdef MINGW
  #include "platform.h"
  #include "gnunet_util_lib.h"
  #include <bthdef.h>
  #include <ws2bth.h>
#else
  #define SOCKTYPE int
  #include <bluetooth/bluetooth.h>
  #include <bluetooth/hci.h>
  #include <bluetooth/hci_lib.h>
  #include <bluetooth/rfcomm.h>
  #include <bluetooth/sdp.h>
  #include <bluetooth/sdp_lib.h>
  #include <errno.h>
  #include <linux/if.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <sys/ioctl.h>
  #include <sys/param.h>
  #include <sys/socket.h>
  #include <sys/stat.h>
  #include <sys/types.h>
  #include <unistd.h>
#endif

#include "plugin_transport_wlan.h"
#include "gnunet_protocols.h"


/**
 * Maximum number of ports assignable for RFCOMMM protocol.
 */
#define MAX_PORTS 30

/**
 * Maximum size of a message allowed in either direction
 * (used for our receive and sent buffers).
 */
#define MAXLINE 4096


/**
 * Maximum number of loops without inquiring for new devices.
 */
#define MAX_LOOPS 5

#ifdef MINGW
  /* Maximum size of the interface's name */
  #define IFNAMSIZ 16

  #ifndef NS_BTH
    #define NS_BTH 16
  #endif
  /**
   * A copy of the MAC Address.
   */
  struct GNUNET_TRANSPORT_WLAN_MacAddress_Copy
  {
    UINT8 mac[MAC_ADDR_SIZE];
  };

  /**
   * The UUID used for the SDP service.
   * {31191E56-FA7E-4517-870E-71B86BBCC52F}
   */
  #define GNUNET_BLUETOOTH_SDP_UUID \
    { \
      0x31, 0x19, 0x1E, 0x56, \
      0xFA, 0x7E, \
      0x45, 0x17, \
      0x87, 0x0E, \
      0x71, 0xB8, 0x6B, 0xBC, 0xC5, 0x2F \
    }
#endif

/**
 * In bluez library, the maximum name length of a device is 8
 */
#define BLUEZ_DEVNAME_SIZE  8

/**
 * struct for storing the information of the hardware.  There is only
 * one of these.
 */
struct HardwareInfos
{
  /**
   * Name of the interface, not necessarily 0-terminated (!).
   */
  char iface[IFNAMSIZ];

 #ifdef MINGW
  /**
   * socket handle
   */
  struct GNUNET_NETWORK_Handle *handle;

  /**
   * MAC address of our own bluetooth interface.
   */
  struct GNUNET_TRANSPORT_WLAN_MacAddress_Copy pl_mac;
 #else
  /**
   * file descriptor for the rfcomm socket
   */
  int fd_rfcomm;

  /**
   * MAC address of our own bluetooth interface.
   */
  struct GNUNET_TRANSPORT_WLAN_MacAddress pl_mac;

  /**
   * SDP session
   */
   sdp_session_t *session ;
 #endif
};

/**
 * IO buffer used for buffering data in transit (to wireless or to stdout).
 */
struct SendBuffer
{
  /**
   * How many bytes of data are stored in 'buf' for transmission right now?
   * Data always starts at offset 0 and extends to 'size'.
   */
  size_t size;

  /**
   * How many bytes that were stored in 'buf' did we already write to the
   * destination?  Always smaller than 'size'.
   */
  size_t pos;

  /**
   * Buffered data; twice the maximum allowed message size as we add some
   * headers.
   */
  char buf[MAXLINE * 2];
};

#ifdef LINUX
 /**
  * Devices buffer used to keep a list with all the discoverable devices in
  * order to send them HELLO messages one by one when it receive a broadcast message.
  */
 struct BroadcastMessages
 {
   /* List with the discoverable devices' addresses */
   bdaddr_t devices[MAX_PORTS];

   /* List with the open sockets */
   int fds[MAX_PORTS];


   /* The number of the devices */
   int size;

   /* The current position */
   int pos;

   /* The device id */
   int dev_id;
 };

 /**
  * Address used to identify the broadcast messages.
  */
 static struct GNUNET_TRANSPORT_WLAN_MacAddress broadcast_address = {{255, 255, 255, 255, 255, 255}};

 /**
  * Buffer with the discoverable devices.
  */
 static struct BroadcastMessages neighbours;

 static int searching_devices_count = 0;
#endif

/**
 * Buffer for data read from stdin to be transmitted to the bluetooth device
 */
static struct SendBuffer write_pout;

/**
 * Buffer for data read from the bluetooth device to be transmitted to stdout.
 */
static struct SendBuffer write_std;


/* ****** this are the same functions as the ones used in gnunet-helper-transport-wlan.c ****** */

/**
 * To what multiple do we align messages?  8 byte should suffice for everyone
 * for now.
 */
#define ALIGN_FACTOR 8

/**
 * Smallest supported message.
 */
#define MIN_BUFFER_SIZE sizeof (struct GNUNET_MessageHeader)


/**
 * Functions with this signature are called whenever a
 * complete message is received by the tokenizer.
 *
 * @param cls closure
 * @param message the actual message
 */
typedef void (*MessageTokenizerCallback) (void *cls,
            const struct
            GNUNET_MessageHeader *
            message);

/**
 * Handle to a message stream tokenizer.
 */
struct MessageStreamTokenizer
{

  /**
   * Function to call on completed messages.
   */
  MessageTokenizerCallback cb;

  /**
   * Closure for cb.
   */
  void *cb_cls;

  /**
   * Size of the buffer (starting at 'hdr').
   */
  size_t curr_buf;

  /**
   * How many bytes in buffer have we already processed?
   */
  size_t off;

  /**
   * How many bytes in buffer are valid right now?
   */
  size_t pos;

  /**
   * Beginning of the buffer.  Typed like this to force alignment.
   */
  struct GNUNET_MessageHeader *hdr;

};


/**
 * Create a message stream tokenizer.
 *
 * @param cb function to call on completed messages
 * @param cb_cls closure for cb
 * @return handle to tokenizer
 */
static struct MessageStreamTokenizer *
mst_create (MessageTokenizerCallback cb,
      void *cb_cls)
{
  struct MessageStreamTokenizer *ret;

  ret = malloc (sizeof (struct MessageStreamTokenizer));
  if (NULL == ret)
  {
    fprintf (stderr, "Failed to allocate buffer for tokenizer\n");
    exit (1);
  }
  ret->hdr = malloc (MIN_BUFFER_SIZE);
  if (NULL == ret->hdr)
  {
    fprintf (stderr, "Failed to allocate buffer for alignment\n");
    exit (1);
  }
  ret->curr_buf = MIN_BUFFER_SIZE;
  ret->cb = cb;
  ret->cb_cls = cb_cls;
  ret->pos = 0;

  return ret;
}


/**
 * Add incoming data to the receive buffer and call the
 * callback for all complete messages.
 *
 * @param mst tokenizer to use
 * @param buf input data to add
 * @param size number of bytes in buf
 * @return GNUNET_OK if we are done processing (need more data)
 *         GNUNET_SYSERR if the data stream is corrupt
 */
static int
mst_receive (struct MessageStreamTokenizer *mst,
       const char *buf, size_t size)
{
  const struct GNUNET_MessageHeader *hdr;
  size_t delta;
  uint16_t want;
  char *ibuf;
  int need_align;
  unsigned long offset;
  int ret;

  ret = GNUNET_OK;
  ibuf = (char *) mst->hdr;
  while (mst->pos > 0)
  {
do_align:
    if (mst->pos < mst->off)
    {
      //fprintf (stderr, "We processed too many bytes!\n");
      return GNUNET_SYSERR;
    }
    if ((mst->curr_buf - mst->off < sizeof (struct GNUNET_MessageHeader)) ||
        (0 != (mst->off % ALIGN_FACTOR)))
    {
      /* need to align or need more space */
      mst->pos -= mst->off;
      memmove (ibuf, &ibuf[mst->off], mst->pos);
      mst->off = 0;
    }
    if (mst->pos - mst->off < sizeof (struct GNUNET_MessageHeader))
    {
      delta =
          GNUNET_MIN (sizeof (struct GNUNET_MessageHeader) -
                      (mst->pos - mst->off), size);
      memcpy (&ibuf[mst->pos], buf, delta);
      mst->pos += delta;
      buf += delta;
      size -= delta;
    }
    if (mst->pos - mst->off < sizeof (struct GNUNET_MessageHeader))
    {
      //FIXME should I reset ??
      // mst->off = 0;
      // mst->pos = 0;
      return GNUNET_OK;
    }
    hdr = (const struct GNUNET_MessageHeader *) &ibuf[mst->off];
    want = ntohs (hdr->size);
    if (want < sizeof (struct GNUNET_MessageHeader))
    {
      fprintf (stderr,
         "Received invalid message from stdin\n");
      return GNUNET_SYSERR;
    }
    if ((mst->curr_buf - mst->off < want) &&
       (mst->off > 0))
    {
      /* need more space */
      mst->pos -= mst->off;
      memmove (ibuf, &ibuf[mst->off], mst->pos);
      mst->off = 0;
    }
    if (want > mst->curr_buf)
    {
      if (mst->off != 0)
      {
        fprintf (stderr, "Error! We should proceeded 0 bytes\n");
        return GNUNET_SYSERR;
      }
      mst->hdr = realloc (mst->hdr, want);
      if (NULL == mst->hdr)
      {
  fprintf (stderr, "Failed to allocate buffer for alignment\n");
  exit (1);
      }
      ibuf = (char *) mst->hdr;
      mst->curr_buf = want;
    }
    hdr = (const struct GNUNET_MessageHeader *) &ibuf[mst->off];
    if (mst->pos - mst->off < want)
    {
      delta = GNUNET_MIN (want - (mst->pos - mst->off), size);
      if (mst->pos + delta > mst->curr_buf)
      {
        fprintf (stderr, "The size of the buffer will be exceeded!\n");
        return GNUNET_SYSERR;
      }
      memcpy (&ibuf[mst->pos], buf, delta);
      mst->pos += delta;
      buf += delta;
      size -= delta;
    }
    if (mst->pos - mst->off < want)
    {
      //FIXME should I use this?
      // mst->off = 0;
      // mst->pos = 0;
      return GNUNET_OK;
    }
    mst->cb (mst->cb_cls, hdr);
    mst->off += want;
    if (mst->off == mst->pos)
    {
      /* reset to beginning of buffer, it's free right now! */
      mst->off = 0;
      mst->pos = 0;
    }
  }
  if (0 != mst->pos)
  {
    fprintf (stderr, "There should some valid bytes in the buffer on this stage\n");
    return GNUNET_SYSERR;
  }
  while (size > 0)
  {
    if (size < sizeof (struct GNUNET_MessageHeader))
      break;
    offset = (unsigned long) buf;
    need_align = (0 != offset % ALIGN_FACTOR) ? GNUNET_YES : GNUNET_NO;
    if (GNUNET_NO == need_align)
    {
      /* can try to do zero-copy and process directly from original buffer */
      hdr = (const struct GNUNET_MessageHeader *) buf;
      want = ntohs (hdr->size);
      if (want < sizeof (struct GNUNET_MessageHeader))
      {
  fprintf (stderr,
     "Received invalid message from stdin\n");
  //exit (1);
        mst->off = 0;
        return GNUNET_SYSERR;
      }
      if (size < want)
        break;                  /* or not, buffer incomplete, so copy to private buffer... */
      mst->cb (mst->cb_cls, hdr);
      buf += want;
      size -= want;
    }
    else
    {
      /* need to copy to private buffer to align;
       * yes, we go a bit more spagetti than usual here */
      goto do_align;
    }
  }
  if (size > 0)
  {
    if (size + mst->pos > mst->curr_buf)
    {
      mst->hdr = realloc (mst->hdr, size + mst->pos);
      if (NULL == mst->hdr)
      {
  fprintf (stderr, "Failed to allocate buffer for alignment\n");
  exit (1);
      }
      ibuf = (char *) mst->hdr;
      mst->curr_buf = size + mst->pos;
    }
    if (mst->pos + size > mst->curr_buf)
    {
      fprintf (stderr,
         "Assertion failed\n");
      exit (1);
    }
    memcpy (&ibuf[mst->pos], buf, size);
    mst->pos += size;
  }
  return ret;
}

/**
 * Destroys a tokenizer.
 *
 * @param mst tokenizer to destroy
 */
static void
mst_destroy (struct MessageStreamTokenizer *mst)
{
  free (mst->hdr);
  free (mst);
}

/**
 * Calculate crc32, the start of the calculation
 *
 * @param buf buffer to calc the crc
 * @param len len of the buffer
 * @return crc sum
 */
static unsigned long
calc_crc_osdep (const unsigned char *buf, size_t len)
{
  static const unsigned long int crc_tbl_osdep[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
    0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD,
    0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB,
    0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
    0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447,
    0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75,
    0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
    0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11,
    0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F,
    0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
    0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B,
    0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49,
    0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
    0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5,
    0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3,
    0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
    0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF,
    0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D,
    0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
    0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9,
    0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767,
    0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
    0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703,
    0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31,
    0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
    0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D,
    0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B,
    0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
    0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7,
    0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5,
    0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
    0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1,
    0x5A05DF1B, 0x2D02EF8D
  };

  unsigned long crc = 0xFFFFFFFF;

  for (; len > 0; len--, buf++)
    crc = crc_tbl_osdep[(crc ^ *buf) & 0xFF] ^ (crc >> 8);
  return (~crc);
}


/**
 * Calculate and check crc of the bluetooth packet
 *
 * @param buf buffer of the packet, with len + 4 bytes of data,
 *            the last 4 bytes being the checksum
 * @param len length of the payload in data
 * @return 0 on success (checksum matches), 1 on error
 */
static int
check_crc_buf_osdep (const unsigned char *buf, size_t len)
{
  unsigned long crc;

  crc = calc_crc_osdep (buf, len);
  buf += len;
  if (((crc) & 0xFF) == buf[0] && ((crc >> 8) & 0xFF) == buf[1] &&
      ((crc >> 16) & 0xFF) == buf[2] && ((crc >> 24) & 0xFF) == buf[3])
    return 0;
  return 1;
}



/* ************** end of clone  ***************** */

#ifdef MINGW
  /**
   * Function used to get the code of last error and to print the type of error.
   */
  static void
  print_last_error()
  {
    LPVOID lpMsgBuf = NULL;

    if (FormatMessage (FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL, GetLastError(), 0, (LPTSTR) &lpMsgBuf, 0, NULL))
      fprintf (stderr, "%s\n", (char *)lpMsgBuf);
    else
      fprintf (stderr, "Failed to format the message for the last error! Error number : %d\n", GetLastError());
  }

  /**
   * Function used to initialize the Windows Sockets
   */
  static void
  initialize_windows_sockets()
  {
    WSADATA wsaData ;
    WORD wVersionRequested = MAKEWORD (2, 0);
    if (WSAStartup (wVersionRequested, &wsaData) != NO_ERROR)
    {
      fprintf (stderr , "Error initializing window sockets!\n");
      print_last_error();
      ExitProcess (2) ;
    }
  }

  /**
   * Function used to convert the GUID.
   * @param bytes the GUID represented as a char array
   * @param uuid pointer to the GUID
   */
  static void
  convert_guid(char *bytes, GUID * uuid)
  {
    int i;
    uuid->Data1 = ((bytes[0] << 24) & 0xff000000) | ((bytes[1] << 16) & 0x00ff0000) | ((bytes[2] << 8) & 0x0000ff00) | (bytes[3] & 0x000000ff);
    uuid->Data2 = ((bytes[4] << 8) & 0xff00) | (bytes[5] & 0x00ff);
    uuid->Data3 = ((bytes[6] << 8) & 0xff00) | (bytes[7] & 0x00ff);

    for (i = 0; i < 8; i++)
    {
      uuid->Data4[i] = bytes[i + 8];
    }
  }
#endif

#ifdef LINUX
  /**
   * Function for assigning a port number
   *
   * @param socket the socket used to bind
   * @param addr pointer to the rfcomm address
   * @return 0 on success
   */
  static int
  bind_socket (int socket, struct sockaddr_rc *addr)
  {
    int port, status;

    /* Bind every possible port (from 0 to 30) and stop when binding doesn't fail */
    //FIXME : it should start from port 1, but on my computer it doesn't work :)
    for (port = 3; port <= 30; port++)
    {
      addr->rc_channel = port;
      status = bind (socket, (struct sockaddr *) addr, sizeof (struct sockaddr_rc));
      if (status == 0)
        return 0;
    }

    return -1;
  }
#endif

#ifdef MINGW
  /**
   * Function used for creating the service record and registering it.
   *
   * @param dev pointer to the device struct
   * @return 0 on success
   */
  static int
  register_service (struct HardwareInfos *dev)
  {
    /* advertise the service */
    CSADDR_INFO addr_info;
    WSAQUERYSET wqs;
    GUID guid;
    unsigned char uuid[] = GNUNET_BLUETOOTH_SDP_UUID;
    SOCKADDR_BTH addr;
    int addr_len = sizeof (SOCKADDR_BTH);
    int fd;
    /* get the port on which we are listening on */
    memset (& addr, 0, sizeof (SOCKADDR_BTH));
    fd = GNUNET_NETWORK_get_fd (dev->handle);
    if (fd <= 0)
    {
      fprintf (stderr, "Failed to get the file descriptor\n");
      return -1;
    }
    if (SOCKET_ERROR == getsockname (fd, (SOCKADDR*)&addr, &addr_len))
    {
      fprintf (stderr, "Failed to get the port on which we are listening on: \n");
      print_last_error();
      return -1;
    }

    /* save the device address */
    memcpy (&dev->pl_mac, &addr.btAddr, sizeof (BTH_ADDR));

    /* set the address information */
    memset (&addr_info, 0, sizeof (CSADDR_INFO));
    addr_info.iProtocol = BTHPROTO_RFCOMM;
    addr_info.iSocketType = SOCK_STREAM;
    addr_info.LocalAddr.lpSockaddr = (LPSOCKADDR)&addr;
    addr_info.LocalAddr.iSockaddrLength = sizeof (addr);
    addr_info.RemoteAddr.lpSockaddr = (LPSOCKADDR)&addr;
    addr_info.RemoteAddr.iSockaddrLength = sizeof (addr);

    convert_guid((char *) uuid, &guid);

    /* register the service */
    memset (&wqs, 0, sizeof (WSAQUERYSET));
    wqs.dwSize = sizeof (WSAQUERYSET);
    wqs.dwNameSpace = NS_BTH;
    wqs.lpszServiceInstanceName = "GNUnet Bluetooth Service";
    wqs.lpszComment = "This is the service used by the GNUnnet plugin transport";
    wqs.lpServiceClassId = &guid;
    wqs.dwNumberOfCsAddrs = 1;
    wqs.lpcsaBuffer = &addr_info ;
    wqs.lpBlob = 0;

    if (SOCKET_ERROR == WSASetService (&wqs , RNRSERVICE_REGISTER, 0))
    {
      fprintf (stderr, "Failed to register the SDP service: ");
      print_last_error();
      return -1;
    }
    else
    {
      fprintf (stderr, "The SDP service was registered\n");
    }

    return 0;
  }
#else
  /**
   * Function used for creating the service record and registering it.
   *
   * @param dev pointer to the device struct
   * @param rc_channel the rfcomm channel
   * @return 0 on success
   */
  static int
  register_service (struct HardwareInfos *dev, int rc_channel)
  {
    /**
     * 1. initializations
     * 2. set the service ID, class, profile information
     * 3. make the service record publicly browsable
     * 4. register the RFCOMM channel
     * 5. set the name, provider and description
     * 6. register the service record to the local SDP server
     * 7. cleanup
     */
    uint8_t svc_uuid_int[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                              dev->pl_mac.mac[5], dev->pl_mac.mac[4], dev->pl_mac.mac[3],
                              dev->pl_mac.mac[2], dev->pl_mac.mac[1], dev->pl_mac.mac[0]};
    const char *service_dsc = "Bluetooth plugin services";
    const char *service_prov = "GNUnet provider";
    uuid_t root_uuid, rfcomm_uuid, svc_uuid;
    sdp_list_t *root_list = 0, *rfcomm_list = 0, *proto_list = 0,
       *access_proto_list = 0, *svc_list = 0;
    sdp_record_t *record = 0;
    sdp_data_t *channel = 0;

    record = sdp_record_alloc();

    /* Set the general service ID */
    sdp_uuid128_create (&svc_uuid, &svc_uuid_int);
    svc_list = sdp_list_append (0, &svc_uuid);
    sdp_set_service_classes (record, svc_list);
    sdp_set_service_id (record, svc_uuid);

    /* Make the service record publicly browsable */
    sdp_uuid16_create (&root_uuid, PUBLIC_BROWSE_GROUP);
    root_list = sdp_list_append (0, &root_uuid);
    sdp_set_browse_groups (record, root_list);

    /* Register the RFCOMM channel */
    sdp_uuid16_create (&rfcomm_uuid, RFCOMM_UUID);
    channel = sdp_data_alloc (SDP_UINT8, &rc_channel);
    rfcomm_list = sdp_list_append (0, &rfcomm_uuid);
    sdp_list_append (rfcomm_list, channel);
    proto_list = sdp_list_append (0, rfcomm_list);

    /* Set protocol information */
    access_proto_list = sdp_list_append (0, proto_list);
    sdp_set_access_protos (record, access_proto_list);

    /* Set the name, provider, and description */
    sdp_set_info_attr (record, dev->iface, service_prov, service_dsc);

    /* Connect to the local SDP server */
    dev->session = sdp_connect (BDADDR_ANY, BDADDR_LOCAL, SDP_RETRY_IF_BUSY);

    if (!dev->session)
    {
      fprintf (stderr, "Failed to connect to the SDP server on interface `%.*s': %s\n",
               IFNAMSIZ, dev->iface, strerror (errno));
      //FIXME exit?
      return 1;
    }

    /* Register the service record */
    if (sdp_record_register (dev->session, record, 0) < 0)
    {
      fprintf (stderr, "Failed to register a service record on interface `%.*s': %s\n",
               IFNAMSIZ, dev->iface, strerror (errno));
      //FIXME exit?
      return 1;
    }

    /* Cleanup */
    sdp_data_free (channel);
    sdp_list_free (root_list, 0);
    sdp_list_free (rfcomm_list, 0);
    sdp_list_free (proto_list, 0);
    sdp_list_free (access_proto_list, 0);
    sdp_list_free (svc_list, 0);
    sdp_record_free (record);

    return 0;
  }
#endif

#ifdef MINGW
  /**
   * Function for searching and browsing for a service. This will return the
   * port number on which the service is running.
   *
   * @param dest target address
   * @return channel
   */
  static int
  get_channel(const char *dest)
  {
    HANDLE h;
    WSAQUERYSET *wqs;
    DWORD wqs_len = sizeof (WSAQUERYSET);
    int done = 0;
    int channel = -1;
    GUID guid;
    unsigned char uuid[] = GNUNET_BLUETOOTH_SDP_UUID;
    convert_guid ((char *) uuid, &guid);

    wqs = (WSAQUERYSET*)malloc (wqs_len);
    ZeroMemory (wqs, wqs_len);

    wqs->dwSize = sizeof (WSAQUERYSET) ;
    wqs->lpServiceClassId = &guid;
    wqs->dwNameSpace = NS_BTH;
    wqs->dwNumberOfCsAddrs = 0;
    wqs->lpszContext = (LPSTR)dest;

    if (SOCKET_ERROR == WSALookupServiceBegin (wqs,  LUP_FLUSHCACHE | LUP_RETURN_ALL, &h))
    {
      if (GetLastError() == WSASERVICE_NOT_FOUND)
      {
        fprintf (stderr, "WARNING! The device with address %s wasn't found. Skipping the message!", dest);
        return -1;
      }
      else
      {
        fprintf (stderr, "Failed to find the port number: ");
        print_last_error();
        ExitProcess (2);
        return -1;
      }
    }

    /* search the sdp service */
    while (!done)
    {
      if (SOCKET_ERROR == WSALookupServiceNext (h, LUP_FLUSHCACHE | LUP_RETURN_ALL, &wqs_len, wqs))
      {
        int error = WSAGetLastError();

        switch (error)
        {
        case WSAEFAULT:
          free (wqs);
          wqs = (WSAQUERYSET*)malloc (wqs_len);
          break;
        case WSANO_DATA:
          fprintf (stderr, "Failed! The address was valid but there was no data record of requested type\n");
          done = 1;
          break;
        case WSA_E_NO_MORE:
          done = 1;
          break;
        default:
          fprintf (stderr, "Failed to look over the services: ");
          print_last_error();
          WSALookupServiceEnd (h);
          ExitProcess (2);
        }
      }
      else
      {
        channel = ((SOCKADDR_BTH*)wqs->lpcsaBuffer->RemoteAddr.lpSockaddr)->port;
      }
    }

    free (wqs) ;
    WSALookupServiceEnd (h);

    return channel;
  }
#else
  /**
   * Function used for searching and browsing for a service. This will return the
   * port number on which the service is running.
   *
   * @param dev pointer to the device struct
   * @param dest target address
   * @return channel
   */
  static int
  get_channel(struct HardwareInfos *dev, bdaddr_t dest)
  {
    /**
     * 1. detect all nearby devices
     * 2. for each device:
     * 2.1. connect to the SDP server running
     * 2.2. get a list of service records with the specific UUID
     * 2.3. for each service record get a list of the protocol sequences and get
     *       the port number
     */
    uint8_t svc_uuid_int[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             dest.b[5], dest.b[4], dest.b[3],
                             dest.b[2], dest.b[1], dest.b[0]};
    sdp_session_t *session = 0;
    sdp_list_t *search_list = 0, *attrid_list = 0, *response_list = 0, *it = 0;
    uuid_t svc_uuid;
    uint32_t range = 0x0000ffff;
    int channel = -1;

    /* Connect to the local SDP server */
    session = sdp_connect (BDADDR_ANY, &dest, 0);
    if (!session)
    {
     fprintf (stderr, "Failed to connect to the SDP server on interface `%.*s': %s\n",
              IFNAMSIZ, dev->iface, strerror (errno));
     return -1;
    }

    sdp_uuid128_create (&svc_uuid, &svc_uuid_int);
    search_list = sdp_list_append (0, &svc_uuid);
    attrid_list = sdp_list_append (0, &range);

    if (sdp_service_search_attr_req (session, search_list,
                    SDP_ATTR_REQ_RANGE, attrid_list, &response_list) == 0)
    {
      for (it = response_list; it; it = it->next)
      {
        sdp_record_t *record = (sdp_record_t*) it->data;
        sdp_list_t *proto_list = 0;
        if (sdp_get_access_protos (record, &proto_list) == 0)
        {
          channel = sdp_get_proto_port (proto_list, RFCOMM_UUID);
          sdp_list_free (proto_list, 0);
        }
        sdp_record_free (record);
      }
    }

    sdp_list_free (search_list, 0);
    sdp_list_free (attrid_list, 0);
    sdp_list_free (response_list, 0);

    sdp_close (session);

    if (-1 == channel)
      fprintf (stderr,
               "Failed to find the listening channel for interface `%.*s': %s\n",
               IFNAMSIZ,
               dev->iface,
               strerror (errno));

    return channel;
  }
#endif

/**
 * Read from the socket and put the result into the buffer for transmission to 'stdout'.
 *
 * @param sock file descriptor for reading
 * @param buf buffer to read to; first bytes will be the 'struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame',
 *            followed by the actual payload
 * @param buf_size size of the buffer
 * @param ri where to write radiotap_rx info
 * @return number of bytes written to 'buf'
 */
static ssize_t
read_from_the_socket (void *sock,
      unsigned char *buf, size_t buf_size,
            struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage *ri)
{
  unsigned char tmpbuf[buf_size];
  ssize_t count;

  #ifdef MINGW
   count = GNUNET_NETWORK_socket_recv ((struct GNUNET_NETWORK_Handle *)sock, tmpbuf, buf_size);
  #else
   count = read (*((int *)sock), tmpbuf, buf_size);
  #endif

  if (0 > count)
  {
    if (EAGAIN == errno)
      return 0;
    #if MINGW
     print_last_error();
    #else
     fprintf (stderr, "Failed to read from the HCI socket: %s\n", strerror (errno));
    #endif

    return -1;
  }

  #ifdef LINUX
   /* Get the channel used */
   int len;
   struct sockaddr_rc  rc_addr = { 0 };

   memset (&rc_addr, 0, sizeof (rc_addr));
   len = sizeof (rc_addr);
   if (0 > getsockname (*((int *)sock), (struct sockaddr *) &rc_addr, (socklen_t *) &len))
   {
     fprintf (stderr, "getsockname() call failed : %s\n", strerror (errno));
     return -1;
   }

   memset (ri, 0, sizeof (*ri));
   ri->ri_channel = rc_addr.rc_channel;
  #endif

  /* Detect CRC32 at the end */
  if (0 == check_crc_buf_osdep (tmpbuf, count - sizeof (uint32_t)))
  {
    count -= sizeof(uint32_t);
  }

  memcpy (buf, tmpbuf, count);

  return count;
}


/**
 * Open the bluetooth interface for reading/writing
 *
 * @param dev pointer to the device struct
 * @return 0 on success, non-zero on error
 */
static int
open_device (struct HardwareInfos *dev)
{
  #ifdef MINGW
    SOCKADDR_BTH addr;

    /* bind the RFCOMM socket to the interface */
    addr.addressFamily = AF_BTH;
    addr.btAddr = 0;
    addr.port = BT_PORT_ANY;

    if (GNUNET_OK !=
	GNUNET_NETWORK_socket_bind (dev->handle, (const SOCKADDR*)&addr, sizeof (SOCKADDR_BTH)))
    {
      fprintf (stderr, "Failed to bind the socket: ");
      if (GetLastError() == WSAENETDOWN)
      {
        fprintf (stderr, "Please make sure that your Bluetooth device is ON!\n");
        ExitProcess (2);
      }
      print_last_error();
      return -1;
    }

    /* start listening on the socket */
    if (GNUNET_NETWORK_socket_listen (dev->handle, 4) != GNUNET_OK)
    {
      fprintf (stderr, "Failed to listen on the socket: ");
      print_last_error();
      return -1;
    }

    /* register the sdp service */
    if (register_service(dev) != 0)
    {
      fprintf (stderr, "Failed to register a service: ");
      print_last_error();
      return 1;
    }
  #else
    int i, dev_id = -1, fd_hci;
    struct
    {
      struct hci_dev_list_req list;
      struct hci_dev_req dev[HCI_MAX_DEV];
    } request;                              //used for detecting the local devices
    struct sockaddr_rc rc_addr = { 0 };    //used for binding

    /* Initialize the neighbour structure */
    neighbours.dev_id = -1;
    for (i = 0; i < MAX_PORTS; i++)
      neighbours.fds[i] = -1;

    /* Open a HCI socket */
    fd_hci = socket (AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);

    if (fd_hci < 0)
    {
      fprintf (stderr,
               "Failed to create HCI socket: %s\n",
               strerror (errno));
      return -1;
    }

    memset (&request, 0, sizeof(request));
    request.list.dev_num = HCI_MAX_DEV;

    if (ioctl (fd_hci, HCIGETDEVLIST, (void *) &request) < 0)
    {
      fprintf (stderr,
               "ioctl(HCIGETDEVLIST) on interface `%.*s' failed: %s\n",
               IFNAMSIZ,
               dev->iface,
               strerror (errno));
      (void) close (fd_hci);
      return 1;
    }

    /* Search for a device with dev->iface name */
    for (i = 0; i < request.list.dev_num; i++)
    {
      struct hci_dev_info dev_info;

      memset (&dev_info, 0, sizeof(struct hci_dev_info));
      dev_info.dev_id = request.dev[i].dev_id;
      strncpy (dev_info.name, dev->iface, BLUEZ_DEVNAME_SIZE);

      if (ioctl (fd_hci, HCIGETDEVINFO, (void *) &dev_info))
      {
        fprintf (stderr,
                 "ioctl(HCIGETDEVINFO) on interface `%.*s' failed: %s\n",
                 IFNAMSIZ,
                 dev->iface,
                 strerror (errno));
        (void) close (fd_hci);
        return 1;
      }

      if (strncmp (dev_info.name, dev->iface, BLUEZ_DEVNAME_SIZE) == 0)
      {

        dev_id = dev_info.dev_id; //the device was found
        /**
         * Copy the MAC address to the device structure
         */
        memcpy (&dev->pl_mac, &dev_info.bdaddr, sizeof (bdaddr_t));

        /* Check if the interface is up */
        if (hci_test_bit (HCI_UP, (void *) &dev_info.flags) == 0)
        {
          /* Bring the interface up */
          if (ioctl (fd_hci, HCIDEVUP, dev_info.dev_id))
          {
            fprintf (stderr,
                     "ioctl(HCIDEVUP) on interface `%.*s' failed: %s\n",
                     IFNAMSIZ,
                     dev->iface,
                     strerror (errno));
            (void) close (fd_hci);
            return 1;
          }
        }

        /* Check if the device is discoverable */
        if (hci_test_bit (HCI_PSCAN, (void *) &dev_info.flags) == 0 ||
            hci_test_bit (HCI_ISCAN, (void *) &dev_info.flags) == 0)
        {
          /* Set interface Page Scan and Inqury Scan ON */
          struct hci_dev_req dev_req;

          memset (&dev_req, 0, sizeof (dev_req));
          dev_req.dev_id = dev_info.dev_id;
          dev_req.dev_opt = SCAN_PAGE | SCAN_INQUIRY;

          if (ioctl (fd_hci, HCISETSCAN, (unsigned long) &dev_req))
          {
            fprintf (stderr,
                     "ioctl(HCISETSCAN) on interface `%.*s' failed: %s\n",
                     IFNAMSIZ,
                     dev->iface,
                     strerror (errno));
            (void) close (fd_hci);
            return 1;
          }

        }
        break;
      }

    }

    /* Check if the interface was not found */
    if (-1 == dev_id)
    {
      fprintf (stderr,
               "The interface %s was not found\n",
               dev->iface);
      (void) close (fd_hci);
      return 1;
    }

    /* Close the hci socket */
    (void) close(fd_hci);



    /* Bind the rfcomm socket to the interface */
    memset (&rc_addr, 0, sizeof (rc_addr));
    rc_addr.rc_family = AF_BLUETOOTH;
    rc_addr.rc_bdaddr = *BDADDR_ANY;

    if (bind_socket (dev->fd_rfcomm, &rc_addr) != 0)
    {
      fprintf (stderr,
               "Failed to bind interface `%.*s': %s\n",
               IFNAMSIZ,
               dev->iface,
               strerror (errno));
      return 1;
    }

    /* Register a SDP service */
    if (register_service (dev, rc_addr.rc_channel) != 0)
    {
      fprintf (stderr,
               "Failed to register a service on interface `%.*s': %s\n",
               IFNAMSIZ,
               dev->iface, strerror (errno));
      return 1;
    }

    /* Switch socket in listening mode */
    if (listen (dev->fd_rfcomm, 5) == -1) //FIXME: probably we need a bigger number
    {
      fprintf (stderr, "Failed to listen on socket for interface `%.*s': %s\n", IFNAMSIZ,
               dev->iface, strerror (errno));
      return 1;
    }

  #endif

  return 0;
}


/**
 * Set the header to sane values to make attacks more difficult
 *
 * @param taIeeeHeader pointer to the header of the packet
 * @param dev pointer to the Hardware_Infos struct
 *
 **** copy from gnunet-helper-transport-wlan.c ****
 */
static void
mac_set (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame *taIeeeHeader,
         const struct HardwareInfos *dev)
{
  taIeeeHeader->frame_control = htons (IEEE80211_FC0_TYPE_DATA);
  taIeeeHeader->addr3 = mac_bssid_gnunet;

  #ifdef MINGW
    memcpy (&taIeeeHeader->addr2, &dev->pl_mac, sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress));
  #else
    taIeeeHeader->addr2 = dev->pl_mac;
  #endif
}

#ifdef LINUX
  /**
   * Test if the given interface name really corresponds to a bluetooth
   * device.
   *
   * @param iface name of the interface
   * @return 0 on success, 1 on error
   **** similar with the one from gnunet-helper-transport-wlan.c ****
   */
  static int
  test_bluetooth_interface (const char *iface)
  {
    char strbuf[512];
    struct stat sbuf;
    int ret;

    ret = snprintf (strbuf, sizeof (strbuf),
        "/sys/class/bluetooth/%s/subsystem",
        iface);
    if ((ret < 0) || (ret >= sizeof (strbuf)) || (0 != stat (strbuf, &sbuf)))
    {
      fprintf (stderr,
         "Did not find 802.15.1 interface `%s'. Exiting.\n",
         iface);
      exit (1);
    }
    return 0;
  }
#endif

/**
 * Test incoming packets mac for being our own.
 *
 * @param taIeeeHeader buffer of the packet
 * @param dev the Hardware_Infos struct
 * @return 0 if mac belongs to us, 1 if mac is for another target
 *
 **** same as the one from gnunet-helper-transport-wlan.c ****
 */
static int
mac_test (const struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame *taIeeeHeader,
          const struct HardwareInfos *dev)
{
  static struct GNUNET_TRANSPORT_WLAN_MacAddress all_zeros;

  if ( (0 == memcmp (&taIeeeHeader->addr3, &all_zeros, MAC_ADDR_SIZE)) ||
       (0 == memcmp (&taIeeeHeader->addr1, &all_zeros, MAC_ADDR_SIZE)) )
    return 0; /* some drivers set no Macs, then assume it is all for us! */

  if (0 != memcmp (&taIeeeHeader->addr3, &mac_bssid_gnunet, MAC_ADDR_SIZE))
    return 1; /* not a GNUnet ad-hoc package */
  if ( (0 == memcmp (&taIeeeHeader->addr1, &dev->pl_mac, MAC_ADDR_SIZE)) ||
       (0 == memcmp (&taIeeeHeader->addr1, &bc_all_mac, MAC_ADDR_SIZE)) )
    return 0; /* for us, or broadcast */
  return 1; /* not for us */
}


/**
 * Process data from the stdin. Takes the message, forces the sender MAC to be correct
 * and puts it into our buffer for transmission to the receiver.
 *
 * @param cls pointer to the device struct ('struct HardwareInfos*')
 * @param hdr pointer to the start of the packet
 *
 **** same as the one from gnunet-helper-transport-wlan.c ****
 */
static void
stdin_send_hw (void *cls, const struct GNUNET_MessageHeader *hdr)
{
  struct HardwareInfos *dev = cls;
  const struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *header;
  struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame *blueheader;
  size_t sendsize;

  sendsize = ntohs (hdr->size);
  if ( (sendsize <
  sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage)) ||
       (GNUNET_MESSAGE_TYPE_WLAN_DATA_TO_HELPER != ntohs (hdr->type)) )
  {
    fprintf (stderr, "Received malformed message\n");
    exit (1);
  }
  sendsize -= (sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage) -
               sizeof (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame));
  if (MAXLINE < sendsize)
  {
    fprintf (stderr, "Packet too big for buffer\n");
    exit (1);
  }
  header = (const struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *) hdr;
  memcpy (&write_pout.buf, &header->frame, sendsize);
  blueheader = (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame *) &write_pout.buf;

  /* payload contains MAC address, but we don't trust it, so we'll
  * overwrite it with OUR MAC address to prevent mischief */
  mac_set (blueheader, dev);
  memcpy (&blueheader->addr1, &header->frame.addr1,
          sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress));
  write_pout.size = sendsize;
}

#ifdef LINUX
  /**
   * Broadcast a HELLO message for peer discovery
   *
   * @param dev pointer to the device struct
   * @param dev pointer to the socket which was added to the set
   * @return 0 on success
   */
  static int
  send_broadcast (struct HardwareInfos *dev, int *sendsocket)
  {
    int new_device = 0;
    int loops = 0;

   search_for_devices:
    if ((neighbours.size == neighbours.pos && new_device == 1) || neighbours.size == 0)
    {
   inquiry_devices:   //skip the conditions and force a inquiry for new devices
      {
      /**
       * It means that I sent HELLO messages to all the devices from the list and I should search
       * for new ones or that this is the first time when I do a search.
       */
      inquiry_info *devices = NULL;
      int i, responses, max_responses = MAX_PORTS;

      /* sanity checks */
      if (neighbours.size >= MAX_PORTS)
      {
        fprintf (stderr, "%.*s reached the top limit for the discovarable devices\n", IFNAMSIZ, dev->iface);
        return 2;
      }

      /* Get the device id */
      if (neighbours.dev_id == -1)
      {
        char addr[19] = { 0 }; //the device MAC address

        ba2str ((bdaddr_t *) &dev->pl_mac, addr);
        neighbours.dev_id = hci_devid (addr);
        if (neighbours.dev_id < 0)
        {
          fprintf (stderr, "Failed to get the device id for interface %.*s : %s\n", IFNAMSIZ,
                  dev->iface, strerror (errno));
          return 1;
        }
      }

      devices = malloc (max_responses * sizeof (inquiry_info));
      if (devices == NULL)
      {
        fprintf (stderr, "Failed to allocate memory for inquiry info list on interface %.*s\n", IFNAMSIZ,
                dev->iface);
        return 1;
      }

      responses = hci_inquiry (neighbours.dev_id, 8, max_responses, NULL, &devices, IREQ_CACHE_FLUSH);
      if (responses < 0)
      {
        fprintf (stderr, "Failed to inquiry on interface %.*s\n", IFNAMSIZ, dev->iface);
        return 1;
      }

      fprintf (stderr, "LOG : Found %d devices\n", responses); //FIXME delete it after debugging stage

      if (responses == 0)
      {
        fprintf (stderr, "LOG : No devices discoverable\n");
        return 1;
      }

      for (i = 0; i < responses; i++)
      {
        int j;
        int found = 0;

        /* sanity check */
        if (i >= MAX_PORTS)
        {
          fprintf (stderr, "%.*s reached the top limit for the discoverable devices (after inquiry)\n", IFNAMSIZ,
                  dev->iface);
          return 2;
        }

        /* Search if the address already exists on the list */
        for (j = 0; j < neighbours.size; j++)
        {
          if (memcmp (&(devices + i)->bdaddr, &(neighbours.devices[j]), sizeof (bdaddr_t)) == 0)
          {
            found = 1;
            fprintf (stderr, "LOG : the device already exists on the list\n"); //FIXME debugging message
            break;
          }
        }

        if (found == 0)
        {
          char addr[19] = { 0 };

          ba2str (&(devices +i)->bdaddr, addr);
          fprintf (stderr, "LOG : %s was added to the list\n", addr); //FIXME debugging message
          memcpy (&(neighbours.devices[neighbours.size++]), &(devices + i)->bdaddr, sizeof (bdaddr_t));
        }
      }

      free (devices);
      }
    }

    int connection_successful = 0;
    struct sockaddr_rc addr_rc = { 0 };
    int errno_copy = 0;
    addr_rc.rc_family = AF_BLUETOOTH;

    /* Try to connect to a new device from the list */
    while (neighbours.pos < neighbours.size)
    {
      /* Check if we are already connected to this device */
      if (neighbours.fds[neighbours.pos] == -1)
      {

        memset (&addr_rc.rc_bdaddr, 0, sizeof (addr_rc.rc_bdaddr));
        memcpy (&addr_rc.rc_bdaddr, &(neighbours.devices[neighbours.pos]), sizeof (addr_rc.rc_bdaddr));

        addr_rc.rc_channel = get_channel (dev, addr_rc.rc_bdaddr);

        *sendsocket = socket (AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
        if ( (-1 < *sendsocket) &&
             (0 == connect (*sendsocket,
                            (struct sockaddr *) &addr_rc,
                            sizeof (addr_rc))) )
        {
          neighbours.fds[neighbours.pos++] = *sendsocket;
          connection_successful = 1;
          char addr[19] = { 0 };
          ba2str (&(neighbours.devices[neighbours.pos - 1]), addr);
          fprintf (stderr, "LOG : Connected to %s\n", addr);
          break;
        }
        else
        {
          char addr[19] = { 0 };
          errno_copy = errno;  //Save a copy for later

          if (-1 != *sendsocket)
          {
            (void) close (*sendsocket);
            *sendsocket = -1;
          }
          ba2str (&(neighbours.devices[neighbours.pos]), addr);
          fprintf (stderr,
                   "LOG : Couldn't connect on device %s, error : %s\n",
                   addr,
                   strerror (errno));
          if (errno != ECONNREFUSED) //FIXME be sure that this works
          {
            fprintf (stderr, "LOG : Removes %d device from the list\n", neighbours.pos);
            /* Remove the device from the list */
            memcpy (&neighbours.devices[neighbours.pos], &neighbours.devices[neighbours.size - 1], sizeof (bdaddr_t));
            memset (&neighbours.devices[neighbours.size - 1], 0, sizeof (bdaddr_t));
            neighbours.fds[neighbours.pos] = neighbours.fds[neighbours.size - 1];
            neighbours.fds[neighbours.size - 1] = -1;
            neighbours.size -= 1;
          }

          neighbours.pos += 1;

          if (neighbours.pos >= neighbours.size)
              neighbours.pos = 0;

          loops += 1;

          if (loops == MAX_LOOPS) //don't get stuck trying to connect to one device
            return 1;
        }
      }
      else
      {
        fprintf (stderr, "LOG : Search for a new device\n"); //FIXME debugging message
        neighbours.pos += 1;
      }
    }

    /* Cycle on the list */
    if (neighbours.pos == neighbours.size)
    {
      neighbours.pos = 0;
      searching_devices_count += 1;

      if (searching_devices_count == MAX_LOOPS)
      {
        fprintf (stderr, "LOG : Force to inquiry for new devices\n");
        searching_devices_count = 0;
        goto inquiry_devices;
      }
    }
   /* If a new device wasn't found, search an old one */
    if (connection_successful == 0)
    {
      int loop_check = neighbours.pos;
      while (neighbours.fds[neighbours.pos] == -1)
      {
        if (neighbours.pos == neighbours.size)
          neighbours.pos = 0;

        if (neighbours.pos == loop_check)
        {
          if (errno_copy == ECONNREFUSED)
          {
            fprintf (stderr, "LOG : No device found. Go back and search again\n"); //FIXME debugging message
            new_device = 1;
            loops += 1;
            goto search_for_devices;
          }
          else
          {
            return 1; // Skip the broadcast message
          }
        }

        neighbours.pos += 1;
      }

      *sendsocket = neighbours.fds[neighbours.pos++];
    }

    return 0;
  }
#endif

/**
 * Main function of the helper.  This code accesses a bluetooth interface
 * forwards traffic in both directions between the bluetooth interface and
 * stdin/stdout of this process.  Error messages are written to stderr.
 *
 * @param argc number of arguments, must be 2
 * @param argv arguments only argument is the name of the interface (i.e. 'hci0')
 * @return 0 on success (never happens, as we don't return unless aborted), 1 on error
 *
 **** similar to gnunet-helper-transport-wlan.c ****
 */
int
main (int argc, char *argv[])
{
#ifdef LINUX
    struct HardwareInfos dev;
    char readbuf[MAXLINE];
    int maxfd;
    fd_set rfds;
    fd_set wfds;
    int stdin_open;
    struct MessageStreamTokenizer *stdin_mst;
    int raw_eno, i;
    int crt_rfds = 0, rfds_list[MAX_PORTS];
    int broadcast, sendsocket;

    /* Assert privs so we can modify the firewall rules! */
    {
#ifdef HAVE_SETRESUID
      uid_t uid = getuid ();

      if (0 != setresuid (uid, 0, 0))
      {
	fprintf (stderr, 
		 "Failed to setresuid to root: %s\n",
		 strerror (errno));
	return 254;
      }
#else
      if (0 != seteuid (0))
      {
	fprintf (stderr, 
		 "Failed to seteuid back to root: %s\n", strerror (errno));
	return 254;
      }
#endif
    }

    /* Make use of SGID capabilities on POSIX */
    memset (&dev, 0, sizeof (dev));
    dev.fd_rfcomm = socket (AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    raw_eno = errno; /* remember for later */

    /* Now that we've dropped root rights, we can do error checking */
    if (2 != argc)
    {
      fprintf (stderr, "You must specify the name of the interface as the first \
                        and only argument to this program.\n");
      if (-1 != dev.fd_rfcomm)
        (void) close (dev.fd_rfcomm);
      return 1;
    }

    if (-1 == dev.fd_rfcomm)
    {
      fprintf (stderr, "Failed to create a RFCOMM socket: %s\n", strerror (raw_eno));
      return 1;
    }
    if (dev.fd_rfcomm >= FD_SETSIZE)
    {
      fprintf (stderr, "File descriptor too large for select (%d > %d)\n",
               dev.fd_rfcomm, FD_SETSIZE);
      (void) close (dev.fd_rfcomm);
      return 1;
    }
    if (0 != test_bluetooth_interface (argv[1]))
    {
      (void) close (dev.fd_rfcomm);
      return 1;
    }
    strncpy (dev.iface, argv[1], IFNAMSIZ);
    if (0 != open_device (&dev))
    {
      (void) close (dev.fd_rfcomm);
      return 1;
    }

    /* Drop privs */
    {
      uid_t uid = getuid ();
  #ifdef HAVE_SETRESUID
      if (0 != setresuid (uid, uid, uid))
      {
        fprintf (stderr, "Failed to setresuid: %s\n", strerror (errno));
        if (-1 != dev.fd_rfcomm)
    (void) close (dev.fd_rfcomm);
        return 1;
      }
  #else
      if (0 != (setuid (uid) | seteuid (uid)))
      {
        fprintf (stderr, "Failed to setuid: %s\n", strerror (errno));
        if (-1 != dev.fd_rfcomm)
    (void) close (dev.fd_rfcomm);
        return 1;
      }
  #endif
    }

   /* Send MAC address of the bluetooth interface to STDOUT first */
    {
      struct GNUNET_TRANSPORT_WLAN_HelperControlMessage macmsg;

      macmsg.hdr.size = htons (sizeof (macmsg));
      macmsg.hdr.type = htons (GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL);
      memcpy (&macmsg.mac, &dev.pl_mac, sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress));
      memcpy (write_std.buf, &macmsg, sizeof (macmsg));
      write_std.size = sizeof (macmsg);
    }


    stdin_mst = mst_create (&stdin_send_hw, &dev);
    stdin_open = 1;

   /**
    * TODO : I should make the time out of a mac endpoint smaller and check if the rate
    * from get_wlan_header (plugin_transport_bluetooth.c) is correct.
    */
   while (1)
    {
      maxfd = -1;
      broadcast = 0;
      sendsocket = -1;

      FD_ZERO (&rfds);
      if ((0 == write_pout.size) && (1 == stdin_open))
      {
        FD_SET (STDIN_FILENO, &rfds);
        maxfd = MAX (maxfd, STDIN_FILENO);
      }
      if (0 == write_std.size)
      {
        FD_SET (dev.fd_rfcomm, &rfds);
        maxfd = MAX (maxfd, dev.fd_rfcomm);
      }

      for (i = 0; i < crt_rfds; i++)  // it can receive messages from multiple devices
      {
        FD_SET (rfds_list[i], &rfds);
        maxfd = MAX (maxfd, rfds_list[i]);
      }
      FD_ZERO (&wfds);
      if (0 < write_std.size)
      {
        FD_SET (STDOUT_FILENO, &wfds);
        maxfd = MAX (maxfd, STDOUT_FILENO);
      }
      if (0 < write_pout.size) //it can send messages only to one device per loop
      {
        struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame *frame;
        /* Get the destination address */
        frame = (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame *) write_pout.buf;

        if (memcmp (&frame->addr1, &dev.pl_mac,
                    sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress)) == 0)
        {
          broadcast = 1;
          memset (&write_pout, 0, sizeof (write_pout)); //clear the buffer
        }
        else if (memcmp (&frame->addr1, &broadcast_address,
                  sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress)) == 0)
        {
          fprintf (stderr, "LOG : %s has a broadcast message (pos %d, size %d)\n", dev.iface, neighbours.pos, neighbours.size); //FIXME: debugging message

          if (send_broadcast(&dev, &sendsocket) != 0) //if the searching wasn't successful don't get stuck on the select stage
          {
            broadcast = 1;
            memset (&write_pout, 0, sizeof (write_pout)); //remove the message
            fprintf (stderr, "LOG : Skipping the broadcast message (pos %d, size %d)\n", neighbours.pos, neighbours.size);
          }
          else
          {
            FD_SET (sendsocket, &wfds);
            maxfd = MAX (maxfd, sendsocket);
          }
        }
        else
        {
          int found = 0;
          int pos = 0;
          /* Search if the address already exists on the list */
          for (i = 0; i < neighbours.size; i++)
          {
            if (memcmp (&frame->addr1, &(neighbours.devices[i]), sizeof (bdaddr_t)) == 0)
            {
              pos = i;
              if (neighbours.fds[i] != -1)
              {
                found = 1;  //save the position where it was found
                FD_SET (neighbours.fds[i], &wfds);
                maxfd = MAX (maxfd, neighbours.fds[i]);
                sendsocket = neighbours.fds[i];
                fprintf (stderr, "LOG: the address was found in the list\n");
                break;
              }
            }
          }
          if (found == 0)
          {
            int status;
            struct sockaddr_rc addr = { 0 };

            fprintf (stderr, "LOG : %s has a new message for %.2X:%.2X:%.2X:%.2X:%.2X:%.2X which isn't on the broadcast list\n", dev.iface,
                    frame->addr1.mac[5], frame->addr1.mac[4], frame->addr1.mac[3],
                    frame->addr1.mac[2], frame->addr1.mac[1], frame->addr1.mac[0]); //FIXME: debugging message

            sendsocket = socket (AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);

            if (sendsocket < 0)
            {
              fprintf (stderr, "Failed to create a RFCOMM socket (sending stage): %s\n",
                      strerror (errno));
              return -1;
            }

            memcpy (&addr.rc_bdaddr, &frame->addr1, sizeof (bdaddr_t));
            addr.rc_family = AF_BLUETOOTH;
            addr.rc_channel = get_channel (&dev, addr.rc_bdaddr);

            int tries = 0;
            connect_retry:
            status = connect (sendsocket, (struct sockaddr *) &addr, sizeof (addr));
            if (0 != status && errno != EAGAIN)
            {
              if (errno == ECONNREFUSED && tries < 2)
              {
                fprintf (stderr, "LOG : %.*s failed to connect. Trying again!\n", IFNAMSIZ, dev.iface);
                tries++;
                goto connect_retry;
              }
              else if (errno == EBADF)
              {
                fprintf (stderr, "LOG : %s failed to connect : %s. Skip it!\n", dev.iface, strerror (errno));
                memset (&write_pout, 0, sizeof (write_pout));
                broadcast = 1;
              }
              else
              {
                fprintf (stderr, "LOG : %s failed to connect : %s. Try again later!\n", dev.iface, strerror (errno));
                memset (&write_pout, 0, sizeof (write_pout));
                broadcast = 1;
              }

            }
            else
            {
              FD_SET (sendsocket, &wfds);
              maxfd = MAX (maxfd, sendsocket);
              fprintf (stderr, "LOG : Connection successful\n");
              if (pos != 0) // save the socket
              {
                neighbours.fds[pos] = sendsocket;
              }
              else
              {
                /* Add the new device to the discovered devices list */
                if (neighbours.size < MAX_PORTS)
                {
                  neighbours.fds[neighbours.size] = sendsocket;
                  memcpy (&(neighbours.devices[neighbours.size++]), &addr.rc_bdaddr, sizeof (bdaddr_t));
                }
                else
                {
                  fprintf (stderr, "The top limit for the discovarable devices' list was reached\n");
                }
              }
            }
          }
        }
      }

      if (broadcast == 0)
      {
        /* Select a fd which is ready for action :) */
        {
          int retval = select (maxfd + 1, &rfds, &wfds, NULL, NULL);
          if ((-1 == retval) && (EINTR == errno))
      continue;
          if (0 > retval && errno != EBADF)   // we handle BADF errors later
          {
      fprintf (stderr, "select failed: %s\n", strerror (errno));
      break;
          }
        }
        if (FD_ISSET (STDOUT_FILENO , &wfds))
        {
          ssize_t ret =
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
          fprintf (stderr, "LOG : %s sends a message to STDOUT\n", dev.iface); //FIXME: debugging message

        }
        if (-1 != sendsocket)
        {
          if (FD_ISSET (sendsocket , &wfds))
          {
            ssize_t ret = write (sendsocket,
                                 write_pout.buf + write_std.pos,
                                 write_pout.size - write_pout.pos);
            if (0 > ret) //FIXME should I first check the error type?
            {
              fprintf (stderr, "Failed to write to bluetooth device: %s. Closing the socket!\n",
                       strerror (errno));
              for (i = 0; i < neighbours.size; i++)
              {
                if (neighbours.fds[i] == sendsocket)
                {
                  (void) close(sendsocket);
                  neighbours.fds[i] = -1;
                  break;
                }
              }
              /* Remove the message */
              memset (&write_pout.buf + write_std.pos, 0, (write_pout.size - write_pout.pos));
              write_pout.pos = 0 ;
              write_pout.size = 0;
            }
            else
            {
              write_pout.pos += ret;
              if ((write_pout.pos != write_pout.size) && (0 != ret))
              {
                /* We should not get partial sends with packet-oriented devices... */
                fprintf (stderr, "Write error, partial send: %u/%u\n",
                        (unsigned int) write_pout.pos,
                        (unsigned int) write_pout.size);
                break;
              }

              if (write_pout.pos == write_pout.size)
              {
                write_pout.pos = 0;
                write_pout.size = 0;
              }
              fprintf (stderr, "LOG : %s sends a message to a DEVICE\n", dev.iface); //FIXME: debugging message
            }
          }
        }
        for (i = 0; i <= maxfd; i++)
        {
          if (FD_ISSET (i, &rfds))
          {
            if (i == STDIN_FILENO)
            {
              ssize_t ret =
          read (i, readbuf, sizeof (readbuf));
              if (0 > ret)
              {
                fprintf (stderr,
			 "Read error from STDIN: %s\n",
			 strerror (errno));
                break;
              }
              if (0 == ret)
              {
                /* stop reading... */
                stdin_open = 0;
              }
              else
              {
                mst_receive (stdin_mst, readbuf, ret);
                fprintf (stderr, "LOG : %s receives a message from STDIN\n", dev.iface); //FIXME: debugging message
              }
            }
            else if (i == dev.fd_rfcomm)
            {
              int readsocket;
              struct sockaddr_rc addr = { 0 };
              unsigned int opt = sizeof (addr);

              readsocket = accept (dev.fd_rfcomm, (struct sockaddr *) &addr, &opt);
              fprintf(stderr, "LOG : %s accepts a message\n", dev.iface); //FIXME: debugging message
              if (readsocket == -1)
              {
                fprintf (stderr, "Failed to accept a connection on interface: %.*s\n", IFNAMSIZ,
                    strerror (errno));
                break;
              }
              else
              {
                FD_SET (readsocket, &rfds);
                maxfd = MAX (maxfd, readsocket);

                if (crt_rfds < MAX_PORTS)
                  rfds_list[crt_rfds++] = readsocket;
                else
                {
                  fprintf (stderr, "The limit for the read file descriptors list was \
                                  reached\n");
                  break;
                }
              }

            }
            else
            {
              struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage *rrm;
              ssize_t ret;
              fprintf (stderr, "LOG : %s reads something from the socket\n", dev.iface);//FIXME : debugging message
              rrm = (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage *) write_std.buf;
              ret =
                  read_from_the_socket ((void *)&i, (unsigned char *) &rrm->frame,
                              sizeof (write_std.buf)
                  - sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage)
                  + sizeof (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame),
                  rrm);
              if (0 >= ret)
              {
                int j;
                FD_CLR (i, &rfds);
                close (i);
                 /* Remove the socket from the list */
                for (j = 0; j < crt_rfds; j++)
                {
                  if (rfds_list[j] == i)
                  {
                    rfds_list[j] ^= rfds_list[crt_rfds - 1];
                    rfds_list[crt_rfds - 1] ^= rfds_list[j];
                    rfds_list[j] ^= rfds_list[crt_rfds - 1];
                    crt_rfds -= 1;
                    break;
                  }
                }

                fprintf (stderr, "Read error from raw socket: %s\n", strerror (errno));
                break;
              }
              if ((0 < ret) && (0 == mac_test (&rrm->frame, &dev)))
              {
                write_std.size = ret
            + sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage)
            - sizeof (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame);
                rrm->header.size = htons (write_std.size);
                rrm->header.type = htons (GNUNET_MESSAGE_TYPE_WLAN_DATA_FROM_HELPER);
              }
            }
          }
        }
      }
    }
    /* Error handling, try to clean up a bit at least */
    mst_destroy (stdin_mst);
    stdin_mst = NULL;
    sdp_close (dev.session);
    (void) close (dev.fd_rfcomm);
    if (-1 != sendsocket)
      (void) close (sendsocket);

    for (i = 0; i < crt_rfds; i++)
      (void) close (rfds_list[i]);

    for (i = 0; i < neighbours.size; i++)
      (void) close (neighbours.fds[i]);
  #else
    struct HardwareInfos dev;
    struct GNUNET_NETWORK_Handle *sendsocket;
    struct GNUNET_NETWORK_FDSet *rfds;
    struct GNUNET_NETWORK_FDSet *wfds;
    struct GNUNET_NETWORK_Handle *rfds_list[MAX_PORTS];
    char readbuf[MAXLINE] = { 0 };
    SOCKADDR_BTH acc_addr = { 0 };
    int addr_len = sizeof (SOCKADDR_BTH);
    int broadcast, i, stdin_open, crt_rfds = 0;
    HANDLE stdin_handle = GetStdHandle (STD_INPUT_HANDLE);
    HANDLE stdout_handle = GetStdHandle (STD_OUTPUT_HANDLE);
    struct MessageStreamTokenizer *stdin_mst;

    /* check the handles */
    if (stdin_handle == INVALID_HANDLE_VALUE)
    {
      fprintf (stderr, "Failed to get the stdin handle\n");
      ExitProcess (2);
    }

    if (stdout_handle == INVALID_HANDLE_VALUE)
    {
      fprintf (stderr, "Failed to get the stdout handle\n");
      ExitProcess (2);
    }

    /* initialize windows sockets */
    initialize_windows_sockets();

    // /* test bluetooth socket family support */ --> it return false because the GNUNET_NETWORK_test_pf should also receive the type of socket (BTHPROTO_RFCOMM)
    // if (GNUNET_NETWORK_test_pf (AF_BTH) != GNUNET_OK)
    // {
    //   fprintf (stderr, "AF_BTH family is not supported\n");
    //   ExitProcess (2);
    // }

     /* create the socket */
    dev.handle = GNUNET_NETWORK_socket_create (AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);
    if (dev.handle == NULL)
    {
      fprintf (stderr, "Failed to create RFCOMM socket: ");
      print_last_error();
      ExitProcess (2);
    }


    if (open_device (&dev) == -1)
    {
      fprintf (stderr, "Failed to open the device\n");
      print_last_error();
      if (GNUNET_NETWORK_socket_close (dev.handle) != GNUNET_OK)
      {
        fprintf (stderr, "Failed to close the socket!\n");
        print_last_error();
      }
      ExitProcess (2);
    }

    if (GNUNET_OK != GNUNET_NETWORK_socket_set_blocking (dev.handle, 1) )
    {
      fprintf (stderr, "Failed to change the socket mode\n");
      ExitProcess (2);
    }

    memset (&write_std, 0, sizeof (write_std));
    memset (&write_pout, 0, sizeof (write_pout));
    stdin_open = 1;

    rfds = GNUNET_NETWORK_fdset_create ();
    wfds = GNUNET_NETWORK_fdset_create ();

  /* Send MAC address of the bluetooth interface to STDOUT first */
    {
      struct GNUNET_TRANSPORT_WLAN_HelperControlMessage macmsg;

      macmsg.hdr.size = htons (sizeof (macmsg));
      macmsg.hdr.type = htons (GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL);
      memcpy (&macmsg.mac, &dev.pl_mac, sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress_Copy));
      memcpy (write_std.buf, &macmsg, sizeof (macmsg));
      write_std.size = sizeof (macmsg);
    }


    stdin_mst = mst_create (&stdin_send_hw, &dev);
    stdin_open = 1;

    int pos = 0;
    int stdin_pos = -1;
    int stdout_pos = -1;
    while (1)
    {
      broadcast = 0;
      pos = 0;
      stdin_pos = -1;
      stdout_pos = -1;
      sendsocket = NULL; //FIXME ???memleaks

      GNUNET_NETWORK_fdset_zero (rfds);
      if ((0 == write_pout.size) && (1 == stdin_open))
      {
        stdin_pos = pos;
        pos +=1;
        GNUNET_NETWORK_fdset_handle_set (rfds, (struct GNUNET_DISK_FileHandle*) &stdin_handle);
      }

      if (0 == write_std.size)
      {
        pos += 1;
        GNUNET_NETWORK_fdset_set (rfds, dev.handle);
      }

      for (i = 0; i < crt_rfds; i++)
      {
        pos += 1;
        GNUNET_NETWORK_fdset_set (rfds, rfds_list[i]);
      }

      GNUNET_NETWORK_fdset_zero (wfds);
      if (0 < write_std.size)
      {
        stdout_pos = pos;
        GNUNET_NETWORK_fdset_handle_set (wfds, (struct GNUNET_DISK_FileHandle*) &stdout_handle);
        // printf ("%s\n", write_std.buf);
        // memset (write_std.buf, 0, write_std.size);
        // write_std.size = 0;
      }

      if (0 < write_pout.size)
      {
        if (strcmp (argv[1], "ff:ff:ff:ff:ff:ff") == 0) {
          fprintf(stderr, "LOG: BROADCAST! Skipping the message\n");
          // skip the message
          broadcast = 1;
          memset (write_pout.buf, 0, write_pout.size);
          write_pout.size = 0;
        }
        else
        {
          SOCKADDR_BTH addr;
          fprintf (stderr, "LOG : has a new message for %s\n", argv[1]);
          sendsocket = GNUNET_NETWORK_socket_create (AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);

          if (sendsocket == NULL)
          {
            fprintf (stderr, "Failed to create RFCOMM socket: \n");
            print_last_error();
            ExitProcess (2);
          }

          memset (&addr, 0, sizeof (addr));
          //addr.addressFamily = AF_BTH;
          if (SOCKET_ERROR ==
             WSAStringToAddress (argv[1], AF_BTH, NULL, (LPSOCKADDR) &addr, &addr_len))
          {
            fprintf (stderr, "Failed to translate the address: ");
            print_last_error();
            ExitProcess ( 2 ) ;
          }
          addr.port = get_channel (argv[1]);
          if (addr.port == -1)
          {
            fprintf (stderr, "Couldn't find the sdp service for the address: %s\n", argv[1]);
            memset (write_pout.buf, 0, write_pout.size);
            write_pout.size = 0;
            broadcast = 1; //skipping the select part
          }
          else
          {
            if (GNUNET_OK != GNUNET_NETWORK_socket_connect (sendsocket, (LPSOCKADDR)&addr, addr_len))
            {
              fprintf (stderr, "Failed to connect: ");
              print_last_error();
              ExitProcess (2);
            }

            if (GNUNET_OK != GNUNET_NETWORK_socket_set_blocking (sendsocket, 1) )
            {
              fprintf (stderr, "Failed to change the socket mode\n");
              ExitProcess (2);
            }

            GNUNET_NETWORK_fdset_set (wfds, sendsocket);
          }
        }
      }

      if (broadcast == 0)
      {
        int retval = GNUNET_NETWORK_socket_select (rfds, wfds, NULL, GNUNET_TIME_relative_get_forever_());
        if (retval < 0)
        {
          fprintf (stderr, "Select error\n");
          ExitProcess (2);
        }
        //if (GNUNET_NETWORK_fdset_isset (wfds, (struct GNUNET_NETWORK_Handle*)&stdout_handle))
        if (retval == stdout_pos)
        {
          fprintf(stderr, "LOG : sends a message to STDOUT\n"); //FIXME: debugging message
          //ssize_t ret;
          //ret = GNUNET_NETWORK_socket_send ((struct GNUNET_NETWORK_Handle *)&stdout_handle,  write_std.buf + write_std.pos, write_std.size - write_std.pos);
          //ret = write (STDOUT_FILENO, write_std.buf + write_std.pos,  write_std.size - write_std.pos);
          DWORD ret;
          if (FALSE == WriteFile (stdout_handle,  write_std.buf + write_std.pos, write_std.size - write_std.pos, &ret, NULL))
          {
            fprintf (stderr, "Failed to write to STDOUT: ");
            print_last_error();
            break;
          }

          if (ret <= 0)
          {
            fprintf (stderr, "Failed to write to STDOUT\n");
            ExitProcess (2);
          }

          write_std.pos += ret;
          if (write_std.pos == write_std.size)
          {
            write_std.pos = 0;
            write_std.size = 0;
          }
        }
        if (sendsocket != NULL)
        {
          if (GNUNET_NETWORK_fdset_isset (wfds, sendsocket))
          {
            ssize_t ret;
            ret = GNUNET_NETWORK_socket_send (sendsocket, write_pout.buf + write_pout.pos,
                 write_pout.size - write_pout.pos);

            if (GNUNET_SYSERR == ret)
            {
              fprintf (stderr, "Failed to send to the socket. Closing the socket. Error: \n");
              print_last_error();
              if (GNUNET_NETWORK_socket_close (sendsocket) != GNUNET_OK)
              {
                fprintf (stderr, "Failed to close the sendsocket!\n");
                print_last_error();
              }
              ExitProcess (2);
            }
            else
            {
              write_pout.pos += ret;
              if ((write_pout.pos != write_pout.size) && (0 != ret))
              {
                /* we should not get partial sends with packet-oriented devices... */
                fprintf (stderr, "Write error, partial send: %u/%u\n",
                        (unsigned int) write_pout.pos,
                       (unsigned int) write_pout.size);
                break;
              }

              if (write_pout.pos == write_pout.size)
              {
                write_pout.pos = 0;
                write_pout.size = 0;

              }
              fprintf(stderr, "LOG : sends a message to a DEVICE\n"); //FIXME: debugging message
            }
          }
        }

        //if (GNUNET_NETWORK_fdset_isset (rfds, (struct GNUNET_NETWORK_Handle*)&stdin_handle))
        if (retval == stdin_pos)
        {
          //ssize_t ret;
          //ret = GNUNET_NETWORK_socket_recv ((struct GNUNET_NETWORK_Handle *)&stdin_handle, readbuf, sizeof (write_pout.buf));
          //ret = read (STDIN_FILENO, readbuf, sizeof (readbuf));
          DWORD ret;
          if (FALSE == ReadFile (stdin_handle, readbuf, sizeof (readbuf), &ret, NULL))  /* do nothing asynchronous */
          {
            fprintf (stderr, "Read error from STDIN: ");
            print_last_error();
            break;
          }
          if (0 == ret)
          {
            /* stop reading... */
            stdin_open = 0;
          } else {
            mst_receive (stdin_mst, readbuf, ret);
            fprintf (stderr, "LOG : receives a message from STDIN\n"); //FIXME: debugging message
          }
        }
        else
        if (GNUNET_NETWORK_fdset_isset (rfds, dev.handle))
        {
          fprintf (stderr, "LOG: accepting connection\n");
          struct GNUNET_NETWORK_Handle *readsocket;
          readsocket = GNUNET_NETWORK_socket_accept (dev.handle, (LPSOCKADDR)&acc_addr, &addr_len);
          if (readsocket == NULL)
          {
            fprintf (stderr, "Accept error %d: ", GetLastError());
            print_last_error();
            ExitProcess (2);
          }
          else
          {
            if (GNUNET_OK != GNUNET_NETWORK_socket_set_blocking (readsocket, 1) )
            {
              fprintf (stderr, "Failed to change the socket mode\n");
              ExitProcess (2);
            }
            GNUNET_NETWORK_fdset_set (rfds, readsocket);

            if (crt_rfds < MAX_PORTS)
              rfds_list[crt_rfds++] = readsocket;
            else
            {
              fprintf (stderr, "The limit for the read file descriptors list was reached\n");
              break;
            }
          }
        }
        else
        for (i = 0; i < crt_rfds; i++)
        {
          if (GNUNET_NETWORK_fdset_isset (rfds, rfds_list[i]))
          {
            struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage *rrm;
            ssize_t ret;
            fprintf (stderr, "LOG: reading something from the socket\n");//FIXME : debugging message
            rrm = (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage *) write_std.buf;
            ret = read_from_the_socket (rfds_list[i], (unsigned char *) &rrm->frame,
                              sizeof (write_std.buf)
                  - sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage)
                  + sizeof (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame),
                  rrm);
            if (0 >= ret)
            {

              //TODO remove the socket from the list
              if (GNUNET_NETWORK_socket_close (rfds_list[i]) != GNUNET_OK)
              {
                fprintf (stderr, "Failed to close the sendsocket!\n");
                print_last_error();
              }

              fprintf (stderr, "Read error from raw socket: ");
              print_last_error();
              break;

            }
            if ((0 < ret) && (0 == mac_test (&rrm->frame, &dev)))
            {
              write_std.size = ret
          + sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage)
          - sizeof (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame);
              rrm->header.size = htons (write_std.size);
              rrm->header.type = htons (GNUNET_MESSAGE_TYPE_WLAN_DATA_FROM_HELPER);
            }
            break;
          }
        }
      }
    }

    mst_destroy (stdin_mst);
    stdin_mst = NULL;

    if (GNUNET_NETWORK_socket_close (dev.handle) != GNUNET_OK)
    {
      fprintf (stderr, "Failed to close the socket!\n");
      print_last_error();
    }

    for (i = 0; i < crt_rfds; i++)
    {
      if (GNUNET_NETWORK_socket_close (rfds_list[i]) != GNUNET_OK)
      {
        fprintf (stderr, "Failed to close the socket!\n");
        print_last_error();
      }
    }

    WSACleanup();
  #endif
  return 1;                     /* we never exit 'normally' */
}
