/*
   This file is part of GNUnet.
   (C) 2010, 2011, 2012 Christian Grothoff (and other contributing authors)
   Copyright (c) 2007, 2008, Andy Green <andy@warmcat.com>
   Copyright (C) 2009 Thomas d'Otreppe

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
#include "gnunet_config.h"

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

#include "gnunet_protocols.h"
#include "plugin_transport_wlan.h"

#define HARD_CODED_PORT_NUMBER 10
#define HARD_CODED_PORT_NUMBER2 10

/**
 * Maximum size of a message allowed in either direction
 * (used for our receive and sent buffers).
 */
#define MAXLINE 4096


/**
 * struct for storing the information of the hardware.  There is only
 * one of these.
 */
struct HardwareInfos
{

  /**
   * file descriptor for the rfcomm socket
   */
  int fd_rfcomm;

  /**
   * Name of the interface, not necessarily 0-terminated (!).
   */
  char iface[IFNAMSIZ];

  /**
   * MAC address of our own bluetooth interface.
   */
  struct GNUNET_TRANSPORT_WLAN_MacAddress pl_mac;
  
  /**
   * SDP session
   */
   sdp_session_t *session ;
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


/**
 * Buffer for data read from stdin to be transmitted to the bluetooth device
 */
static struct SendBuffer write_pout;

/**
 * Buffer for data read from the bluetooth device to be transmitted to stdout.
 */
static struct SendBuffer write_std;


/* *********** specialized version of server_mst.c begins here ********** */
/* ****** this is the same version as the one used in gnunet-helper-transport-wlan.c ****** */ 

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
      return GNUNET_OK;
    }
    hdr = (const struct GNUNET_MessageHeader *) &ibuf[mst->off];
    want = ntohs (hdr->size);
    if (want < sizeof (struct GNUNET_MessageHeader))
    {
      fprintf (stderr,
	       "Received invalid message from stdin\n");
      exit (1);
    }
    if (mst->curr_buf - mst->off < want)
    {
      /* need more space */
      mst->pos -= mst->off;
      memmove (ibuf, &ibuf[mst->off], mst->pos);
      mst->off = 0;
    }
    if (want > mst->curr_buf)
    {
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
      memcpy (&ibuf[mst->pos], buf, delta);
      mst->pos += delta;
      buf += delta;
      size -= delta;
    }
    if (mst->pos - mst->off < want)
    {
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
	exit (1);
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

/* *****************  end of server_mst.c clone ***************** **/


/* ****** same crc version as the one used in gnunet-helper-transport-wlan.c ****** */ 

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



/* ************** end of crc version  ***************** */




/**
 * Function for assigning a port number
 * @param socket the socket used to bind
 * @param addr pointer to the rfcomm address
 * @return 0 on success 
 */ 
static int
bind_socket (int socket, struct sockaddr_rc *addr)
{
  int port, status;
  
  /* Bind every possible port (from 0 to 30) and stop when bind doesn't fail */
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


/**
 * Function used for creating the service record and registering it.
 * @param dev pointer to the device struct
 * @param channel the rfcomm channel
 * @return 0 on success
 */
static int
register_service (struct HardwareInfos *dev, int rc_channel) 
{
  /**
   * 1. initializations
   * 2. set the service ID, class, profile information
   * 3. make the service record publicly nrowsable
   * 4. register the RFCOMM channel
   * 5. set the name, provider and description
   * 6. register the service record to the local SDP server
   * 7. cleanup
   */
  
  //FIXME: probably this is not the best idea. I should find a different uuid
  uint8_t svc_uuid_int[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                            dev->pl_mac.mac[5], dev->pl_mac.mac[4], dev->pl_mac.mac[3],
                            dev->pl_mac.mac[2], dev->pl_mac.mac[1], dev->pl_mac.mac[0]};
//  const char *service_name = "GNUnet";
  const char *service_dsc = "Bluetooth plugin services";
  const char *service_prov = "GNUnet provider";                       
  uuid_t root_uuid, rfcomm_uuid, l2cap_uuid, svc_uuid;  
  sdp_list_t *root_list = 0, *rfcomm_list = 0, *l2cap_list = 0, 
    *proto_list = 0, *access_proto_list = 0, *svc_list = 0;
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

  /* Set L2CAP information FIXME: probably not needed */
 // sdp_uuid16_create (&l2cap_uuid, L2CAP_UUID);
 // l2cap_list = sdp_list_append (0, &l2cap_uuid);
 //sdp_list_append (proto_list, l2cap_list);

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
  sdp_list_free (l2cap_list, 0);
  sdp_list_free (proto_list, 0);
  sdp_list_free (access_proto_list, 0);
  sdp_list_free (svc_list, 0);
  sdp_record_free (record);
  
  return 0;
}

/**
 * Function for searching and browsing for a service. This will return the 
 * port number on which the service is running.
 * @param dev pointer to the device struct
 * @param dest target address
 * @return channel
 */
static int
get_channel(struct HardwareInfos *dev, bdaddr_t dest) 
{
  /**
   * 1. detect all nearby devices //FIXME : Connect directly to the device with the service
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
  uint8_t channel = -1;
   
  /* Connect to the local SDP server */
  session = sdp_connect (BDADDR_ANY, &dest, 0); 
  if (!session)
  {
   fprintf (stderr, "Failed to connect to the SDP server on interface `%.*s': %s\n",
            IFNAMSIZ, dev->iface, strerror (errno));
   //FIXME exit?
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
      //TODO print some record informations to be sure everything is good
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
  
  if (channel == -1)
    fprintf (stderr, "Failed to find the listening channel for interface `%.*s': %s\n",
            IFNAMSIZ, dev->iface, strerror (errno));
  
  return channel;
}

/**
 * Read from the socket and put the result into the buffer for transmission to 'stdout'.
 * @param sock file descriptor for reading
 * @param buf buffer to read to; first bytes will be the 'struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame',
 *            followed by the actual payload
 * @param buf_size size of the buffer
 * @param ri where to write radiotap_rx info
 * @return number of bytes written to 'buf'
 */
static ssize_t 
read_from_the_socket (int sock, 
	    unsigned char *buf, size_t buf_size,
            struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage *ri)
{
 /**
  * 1. Read from the socket in a temporary buffer (check for errors)
  * 2. Detect if the crc exists
  * 3. Write the result to the buffer
  */
  unsigned char tmpbuf[buf_size];
  ssize_t count;
  int len;
  struct sockaddr_rc  rc_addr = { 0 }; 
  
  count = read (sock, tmpbuf, buf_size); 
  
  if (0 > count)
  {
    if (EAGAIN == errno)
      return 0;
     
    fprintf (stderr, "Failed to read from the HCI socket: %s\n", strerror (errno));
    return -1;
  }
  
  /* Get the channel used */
  memset (&rc_addr, 0, sizeof (rc_addr));
  len = sizeof (rc_addr);
  if (0 > getsockname (sock, (struct sockaddr *) &rc_addr, (socklen_t *) &len))
  {
    fprintf (stderr, "getsockname() call failed : %s\n", strerror (errno));
    return -1;
  }
  
  memset (ri, 0, sizeof (*ri));
  ri->ri_channel = rc_addr.rc_channel;
  
  /* detect CRC32 at the end */
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
 * @return 0 on success
 */
static int
open_device (struct HardwareInfos *dev)
{
  /**
   * 1. Open a HCI socket (if RFCOMM protocol is used. If not, the HCI socket is 
   * saved in dev->rfcomm).
   * 2. Find the device id (request a list with all the devices and find the one
   * with the dev->iface name)
   * 3. If the interface is down try to get it up
   * 4. Bind the RFCOMM socket to the interface using the bind_socket() method and register
   * a SDP service
   * 5. For now use a hard coded port number(channel) value
   * FIXME : if I use HCI sockets , should I enable RAW_SOCKET MODE?!?!?!
   */
   
  int i, dev_id = -1, fd_hci;
  struct 
  {
    struct hci_dev_list_req list;
    struct hci_dev_req dev[HCI_MAX_DEV];
  } request;                      //used for detecting the local devices
  struct sockaddr_rc rc_addr = { 0 };    //used for binding
  
  fd_hci = socket (AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);

  if (fd_hci < 0) 
  {
    fprintf (stderr, "Failed to create HCI socket: %s\n", strerror (errno));
    return -1;
  }
   	
  memset (&request, 0, sizeof(request));
  request.list.dev_num = HCI_MAX_DEV;

  if (ioctl (fd_hci, HCIGETDEVLIST, (void *) &request) < 0)
  {
    fprintf (stderr, "ioctl(HCIGETDEVLIST) on interface `%.*s' failed: %s\n",
            IFNAMSIZ, dev->iface, strerror (errno));
    return 1;
  }
	
	/* Search for a device with dev->iface name */
  for (i = 0; i < request.list.dev_num; i++)
  {
    struct hci_dev_info dev_info;

    memset (&dev_info, 0, sizeof(struct hci_dev_info));
    dev_info.dev_id = request.dev[i].dev_id;
    strncpy (dev_info.name, dev->iface, IFNAMSIZ);
    
    if (ioctl (fd_hci, HCIGETDEVINFO, (void *) &dev_info))
    {
      fprintf (stderr, "ioctl(HCIGETDEVINFO) on interface `%.*s' failed: %s\n",
             IFNAMSIZ, dev->iface, strerror (errno));
      return 1;
    }
    
    if (strcmp (dev_info.name, dev->iface) == 0)
    {
      char addr[19] = { 0 };  //the device MAC address
      
      dev_id = dev_info.dev_id; //the device was found
      
      ba2str (&dev_info.bdaddr, addr); //get the device's MAC address 
      /**
       * Copy the MAC address to the device structure
       * FIXME: probably this is not the best solution
       */
      memcpy (&dev->pl_mac, &dev_info.bdaddr, sizeof (bdaddr_t));
      
      /* Check if the interface is UP */
      if (hci_test_bit (HCI_UP, (void *) &dev_info.flags) == 0)
      {
        /* Bring interface up */ //FIXME should I check if is HCI_RUNNING ?!?!??!
        if (ioctl (fd_hci, HCIDEVUP, dev_info.dev_id))
        {
          fprintf (stderr, "ioctl(HCIDEVUP) on interface `%.*s' failed: %s\n",
             IFNAMSIZ, dev->iface, strerror (errno));
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
          fprintf (stderr, "ioctl(HCISETSCAN) on interface `%.*s' failed: %s\n",
             IFNAMSIZ, dev->iface, strerror (errno));
          return 1;
        }
        
      }
      
      //FIXME : Sniff mode!?!
      //FIXME : RAW MODE?!?
      
      break;
    }
    
  }
  
  /* Check if the interface was not found */
  if (dev_id == -1)
  {
    fprintf (stderr, "The interface %s was not found\n", dev->iface);
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
    fprintf (stderr, "Failed to bind interface `%.*s': %s\n", IFNAMSIZ,
             dev->iface, strerror (errno));
    return 1;
  }
  
  /* Register a SDP service */
  if (register_service (dev, rc_addr.rc_channel) != 0)
  {
    fprintf (stderr, "Failed to register a service on interface `%.*s': %s\n", IFNAMSIZ,
             dev->iface, strerror (errno));
    return 1;
  }
  
  /* Switch socket in listening mode */
  if (listen (dev->fd_rfcomm, 5) == -1) //FIXME: probably we need a bigger number
  {
    fprintf (stderr, "Failed to listen on socket for interface `%.*s': %s\n", IFNAMSIZ,
             dev->iface, strerror (errno));
    return 3;
  }
  
  
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
  taIeeeHeader->addr2 = dev->pl_mac;
  taIeeeHeader->addr3 = mac_bssid_gnunet;
}

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
 * Process data from the stdin.  Takes the message forces the sender MAC to be correct
 * and puts it into our buffer for transmission to the kernel. (the other device).
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
  write_pout.size = sendsize;
}


/**
 * Main function of the helper.  This code accesses a bluetooth interface
 * forwards traffic in both directions between the bluetooth interface and 
 * stdin/stdout of this process.  Error messages are written to stdout.
 *
 * @param argc number of arguments, must be 2
 * @param argv arguments only argument is the name of the interface (i.e. 'hci0')
 * @return 0 on success (never happens, as we don't return unless aborted), 1 on error
 *
 **** same as the one from gnunet-helper-transport-wlan.c ****
 */
int
main (int argc, char *argv[])
{   
  struct HardwareInfos dev;
  char readbuf[MAXLINE];
  char dest[18];
  int maxfd;
  fd_set rfds;
  fd_set wfds;
  int stdin_open;
  struct MessageStreamTokenizer *stdin_mst;
  int raw_eno, i;
  uid_t uid;

  /* Assert privs so we can modify the firewall rules! */
  uid = getuid ();
#ifdef HAVE_SETRESUID
  if (0 != setresuid (uid, 0, 0))
  {
    fprintf (stderr, "Failed to setresuid to root: %s\n", strerror (errno));
    return 254;
  }
#else
  if (0 != seteuid (0)) 
  {
    fprintf (stderr, "Failed to seteuid back to root: %s\n", strerror (errno));
    return 254;
  }
#endif

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
    fprintf (stderr, "Failed to create a HCI socket: %s\n", strerror (raw_eno));
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
  while (1)
  {
    maxfd = -1;
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
    FD_ZERO (&wfds);
    if (0 < write_std.size)
    {
      FD_SET (STDOUT_FILENO, &wfds);
      maxfd = MAX (maxfd, STDOUT_FILENO);
    }
    if (0 < write_pout.size)
    {
      int sendsocket, status;
      struct sockaddr_rc addr = { 0 };
      struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame frame;
      
      memset (dest, 0, sizeof (dest));
      
      sendsocket = socket (AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
      
      if (sendsocket < 0) 
      {
        fprintf (stderr, "Failed to create a RFCOMM socket (sending stage): %s\n", 
                strerror (errno));
        return -1;
      }
      
      /* Get the destination address */
      if (write_pout.pos == 0) //FIXME: if write_pout.pos != 0, I cannot get the destination address
      {
        //FIXME : not sure if this is correct
        memset (&frame, 0, sizeof (frame));
        memcpy (&frame, write_pout.buf + sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage)
                                      - sizeof (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame),
                        sizeof (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame));
        memcpy (&addr.rc_bdaddr, &frame.addr1, sizeof (bdaddr_t));                            
      }    
      addr.rc_family = AF_BLUETOOTH;
      addr.rc_channel = get_channel (&dev, addr.rc_bdaddr);
      
      /*TODO: use a NON-BLOCKING socket
       *    sock_flags = fcntl (sendsocket, F_GETFL, 0);
       *    fcntl( sendsocket, F_SETFL, sock_flags | O_NONBLOCK);
      */
      status = connect (sendsocket, (struct sockaddr *) &addr, sizeof (addr));
	    if (0 != status && errno != EAGAIN)
	    {
	        //fprintf (stderr, "connect error on %s\n", argv[1]);
	      perror("Connect error");
	      return -1;
	    }
      
      FD_SET (sendsocket, &wfds);
      maxfd = MAX (maxfd, sendsocket);
    }
    {
      int retval = select (maxfd + 1, &rfds, &wfds, NULL, NULL);
      if ((-1 == retval) && (EINTR == errno))
	continue;
      if (0 > retval)
      {
	fprintf (stderr, "select failed: %s\n", strerror (errno));
	break;
      }
    }
    
    for (i = 0; i <= maxfd; i++)
    {
      if (FD_ISSET (i , &wfds))
      {
        if (i == STDOUT_FILENO)
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
        } 
        else 
        {
          ssize_t ret =
	    write (i, write_pout.buf + write_std.pos, 
	           write_pout.size - write_pout.pos);
          if (0 > ret)
          {
            fprintf (stderr, "Failed to write to bluetooth device: %s\n",
                     strerror (errno));
            break;
          }
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
            (void) close (i);
          }
        }
      }

      if (FD_ISSET (i, &rfds))
      {
        if (i == STDIN_FILENO)
        {
          ssize_t ret = 
	    read (i, readbuf, sizeof (readbuf));
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
          mst_receive (stdin_mst, readbuf, ret);
        } 
        else if (i == dev.fd_rfcomm) 
        {
          int newfd;
          struct sockaddr_rc addr = { 0 };
          unsigned int opt = sizeof (addr);
          
          newfd = accept (dev.fd_rfcomm, (struct sockaddr *) &addr, &opt);
          
          if (newfd == -1)
          {
            fprintf (stderr, "Failed to accept a connection on interface: %s\n", 
                strerror (errno));
            return -1;
          } else {
            FD_SET (newfd, &rfds);
            maxfd = MAX (maxfd, newfd);
          }
          
        } 
        else 
        {
          struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage *rrm;
          ssize_t ret;

          rrm = (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage *) write_std.buf;
          ret =
              read_from_the_socket (i, (unsigned char *) &rrm->frame,
                          sizeof (write_std.buf) 
		          - sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage) 
		          + sizeof (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame), 
		          rrm);
          if (0 > ret)
          {
            fprintf (stderr, "Read error from rfcomm socket: %s\n", strerror (errno));
            break;
          }
          if ((0 < ret) && (0 == mac_test (&rrm->frame, &dev)))
          {
            write_std.size = ret 
	      + sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage) 
	      - sizeof (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame);
            rrm->header.size = htons (write_std.size);
            rrm->header.type = htons (GNUNET_MESSAGE_TYPE_WLAN_DATA_FROM_HELPER);
            (void) close (i);
          }
          if (0 == ret)
            (void) close (i);
        }
      }
    }
  }
  /* Error handling, try to clean up a bit at least */
  mst_destroy (stdin_mst);
  (void) close (dev.fd_rfcomm);
  
  return 1;                     /* we never exit 'normally' */
  
}



