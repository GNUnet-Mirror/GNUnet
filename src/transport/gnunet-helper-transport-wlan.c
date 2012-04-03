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
/**
 * @file src/transport/gnunet-helper-transport-wlan.c
 * @brief mediator between the wlan interface and gnunet; must run as root (SUID will do)
 *        This code will work under GNU/Linux only.
 * @author David Brodski
 * @author Christian Grothoff
 *
 * This program will allow receiving and sending traffic from the WLAN
 * interface.  It will force traffic to be in 'ad-hoc' mode, use the
 * proper MAC address of the WLAN interface and use a GNUnet-specific
 * SSID (and a GNUnet-specific SNAP header).  It only takes a single
 * argument, which is the name of the WLAN interface to use.  The
 * program detects if the interface is not a WLAN interface and exits
 * with an error in that case.
 *
 * Once initialized, the program will first send a 'struct
 * GNUNET_TRANSPORT_WLAN_HelperControlMessage' to 'stdout'.  That
 * message contains the MAC address of the WLAN interface.  It will
 * then read messages from the WLAN interface and send them together
 * with performance information as 'struct
 * GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage' messages to 'stdout'.
 * Furthermore, it will read a stream of messages from 'stdin' that
 * have the format from 'struct
 * GNUNET_TRANSPORT_WLAN_RadiotapSendMessage'.  Those messages will
 * then be sent via the WLAN interface; however, the sender MAC
 * address will be forced to be the correct address from our WLAN
 * card.  If 'stdin' closes, receiving from the WLAN interface will
 * continue.  If 'stdout' causes a SIGPIPE, the process dies from the
 * signal.  Errors cause an error message to be reported to 'stderr',
 * in most cases the process also exits (with status code '1').  The
 * program never terminates normally; it is safe to kill the
 * process with SIGTERM or SIGKILL at any time.
 *
 * Since it uses RAW sockets, the binary must be installed SUID or run
 * as 'root'.  In order to keep the security risk of the resulting
 * SUID binary minimal, the program ONLY opens the RAW socket with
 * root privileges, then drops them and only then starts to process
 * command line arguments.  The code also does not link against any
 * shared libraries (except libc) and is strictly minimal (except for
 * checking for errors).  The following list of people have reviewed
 * this code and considered it safe since the last modification (if
 * you reviewed it, please have your name added to the list):
 *
 * - Christian Grothoff (Apr 3rd 2012)
 */

/*-
 * we use our local copy of ieee80211_radiotap.h
 *
 * - since we can't support extensions we don't understand
 * - since linux does not include it in userspace headers
 *
 * Portions of this code were taken from the ieee80211_radiotap.h header,
 * which is
 *
 * Copyright (c) 2003, 2004 David Young.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of David Young may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID YOUNG ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL DAVID
 * YOUNG BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

/*
 * Modifications to fit into the linux IEEE 802.11 stack,
 * Mike Kershaw (dragorn@kismetwireless.net)
 */
/*
 * parts taken from aircrack-ng, parts changend.
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
#include <sys/param.h>
#include <unistd.h>
#include <stdint.h>

#include "gnunet_protocols.h"
#include "plugin_transport_wlan.h"

/**
 * Packet format type for the messages we receive from 
 * the kernel.  This is for plain messages (with no
 * performance information included).
 */
#define ARPHRD_IEEE80211        801

/**
 * Packet format type for the messages we receive from 
 * the kernel.  This is for the PRISM format.
 */
#define ARPHRD_IEEE80211_PRISM  802

/**
 * Packet format type for the messages we receive from 
 * the kernel.  This is for messages with a
 * 'struct Ieee80211RadiotapHeader' (see below).
 */
#define ARPHRD_IEEE80211_FULL   803


/**
 * Maximum size of a message allowed in either direction
 * (used for our receive and sent buffers).
 */
#define MAXLINE 4096



/* ********* structure of messages of type ARPHRD_IEEE80211_PRISM *********** */

/**
 * Device name length in PRISM frames.
 * (In the kernel, this is "WLAN_DEVNAMELEN_MAX")
 */
#define PRISM_DEVICE_NAME_LENGTH 16

/**
 * Monitor Frame (indicator that we have a 'struct PrismHeader').
 */
#define PRISM_MSGCODE_MONITOR 0x0041

/**
 * Mac time element.  In micro-seconds.
 * Drivers appear to use a 64bit counter to hold mactime internal
 * the then fill the prism header with the lower 32 bits
 */
#define PRISM_DID_MACTIME 0x2041 

/**
 * Channel element
 */
#define PRISM_DID_CHANNEL 0x3041 

/**
 * Signal element.  Should be the signal strength in dbm, some people
 * suggest that instead "100 - (strength in dbm)" is used (to make this
 * a positive integer).
 */
#define PRISM_DID_SIGNAL 0x6041 

/**
 * Noise element
 */
#define PRISM_DID_NOISE 0x7041 

/**
 * Rate element, in units/multiples of 500Khz
 */
#define PRISM_DID_RATE 0x8041 


/**
 * Value is set (supplied)
 */
#define PRISM_STATUS_OK 0 

/**
 * Value not supplied.
 */
#define PRISM_STATUS_NO_VALUE 1


/**
 * Values in the 'struct PrismHeader'.  All in host byte order (!).
 */
struct PrismValue
{
  /**
   * This has a different ID for each parameter, see
   * PRISM_DID_* constants.
   */
  uint32_t did; 
  
  /**
   * See PRISM_STATUS_*-constants.  Note that they are unusual: 0 = set;  1 = not set
   */
  uint16_t status; 
  
  /**
   * length of data (which is always a uint32_t, but presumably this can be used
   * to specify that fewer bytes are used (with values in 'len' from 0-4).  We
   * ignore this field.
   */
  uint16_t len; 

  /**
   * The data value
   */
  uint32_t data; 

} __attribute__ ((packed));


/**
 * Prism header format ('struct p80211msg' in Linux).  All in host byte order (!).
 */
struct PrismHeader
{
  /**
   * We expect this to be a PRISM_MSGCODE_*.
   */
  uint32_t msgcode;
  
  /**
   * The length of the entire header.
   */
  uint32_t msglen;     

  /**
   * Name of the device that captured the packet.
   */
  char devname[PRISM_DEVICE_NAME_LENGTH];

  /* followed by 'struct PrismValue's.  Documentation suggests that these
     are typically the hosttime, mactime, channel, rssi, sq, signal, noise,
     rate, istx and frmlen values, but documentation is sparse.  So we
     will use the 'did' fields to find out what we actually got. */

} __attribute__ ((packed));


/* ******  end of structure of messages of type ARPHRD_IEEE80211_PRISM ******* */

/* ********** structure of messages of type ARPHRD_IEEE80211_FULL *********** */

/**
 * Bits in the 'it_present' bitmask from the 'struct
 * Ieee80211RadiotapHeader'.  For each value, we give the name, data
 * type, unit and then a description below.  Note that the actual size
 * of the extension can be bigger as arguments must be padded so that
 * args of a given length must begin at a boundary of that length.
 * However, note that compound args are allowed (eg, 2 x uint16_t for
 * IEEE80211_RADIOTAP_CHANNEL) so total argument length is not a
 * reliable indicator of alignment requirement.  See also
 * 'man 9 ieee80211_radiotap'.
 */
enum RadiotapType
{

  /**
   * IEEE80211_RADIOTAP_TSFT              __le64       microseconds
   *
   *      Value in microseconds of the MAC's 64-bit 802.11 Time
   *      Synchronization Function timer when the first bit of the
   *      MPDU arrived at the MAC. For received frames, only.
   */
  IEEE80211_RADIOTAP_TSFT = 0,

  /**
   * IEEE80211_RADIOTAP_FLAGS             uint8_t           bitmap
   *
   *      Properties of transmitted and received frames. See flags
   *      defined below.
   */
  IEEE80211_RADIOTAP_FLAGS = 1,

  /**
   * IEEE80211_RADIOTAP_RATE              uint8_t           500kb/s
   *
   *      Tx/Rx data rate
   */
  IEEE80211_RADIOTAP_RATE = 2,

  /**
   * IEEE80211_RADIOTAP_CHANNEL           2 x __le16   MHz, bitmap
   *
   *      Tx/Rx frequency in MHz, followed by flags (see below).
   */
  IEEE80211_RADIOTAP_CHANNEL = 3,
  /**
   * IEEE80211_RADIOTAP_FHSS              __le16       see below
   *
   *      For frequency-hopping radios, the hop set (first byte)
   *      and pattern (second byte).
   */
  IEEE80211_RADIOTAP_FHSS = 4,

  /**
   * IEEE80211_RADIOTAP_DBM_ANTSIGNAL     s8           decibels from
   *                                                   one milliwatt (dBm)
   *
   *      RF signal power at the antenna, decibel difference from
   *      one milliwatt.
   */
  IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,

  /**
   * IEEE80211_RADIOTAP_DBM_ANTNOISE      s8           decibels from
   *                                                   one milliwatt (dBm)
   *
   *      RF noise power at the antenna, decibel difference from one
   *      milliwatt.
   */
  IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,

  /**
   * IEEE80211_RADIOTAP_LOCK_QUALITY      __le16       unitless
   *
   *      Quality of Barker code lock. Unitless. Monotonically
   *      nondecreasing with "better" lock strength. Called "Signal
   *      Quality" in datasheets.  (Is there a standard way to measure
   *      this?)
   */
  IEEE80211_RADIOTAP_LOCK_QUALITY = 7,

  /**
   * IEEE80211_RADIOTAP_TX_ATTENUATION    __le16       unitless
   *
   *      Transmit power expressed as unitless distance from max
   *      power set at factory calibration.  0 is max power.
   *      Monotonically nondecreasing with lower power levels.
   */
  IEEE80211_RADIOTAP_TX_ATTENUATION = 8,

  /**
   * IEEE80211_RADIOTAP_DB_TX_ATTENUATION __le16       decibels (dB)
   *
   *      Transmit power expressed as decibel distance from max power
   *      set at factory calibration.  0 is max power.  Monotonically
   *      nondecreasing with lower power levels.
   */
  IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,

  /**
   * IEEE80211_RADIOTAP_DBM_TX_POWER      s8           decibels from
   *                                                   one milliwatt (dBm)
   *
   *      Transmit power expressed as dBm (decibels from a 1 milliwatt
   *      reference). This is the absolute power level measured at
   *      the antenna port.
   */
  IEEE80211_RADIOTAP_DBM_TX_POWER = 10,

  /** 
   * IEEE80211_RADIOTAP_ANTENNA           uint8_t           antenna index
   *
   *      Unitless indication of the Rx/Tx antenna for this packet.
   *      The first antenna is antenna 0.
   */
  IEEE80211_RADIOTAP_ANTENNA = 11,

  /**
   * IEEE80211_RADIOTAP_DB_ANTSIGNAL      uint8_t           decibel (dB)
   *
   *      RF signal power at the antenna, decibel difference from an
   *      arbitrary, fixed reference.
   */
  IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,

  /**
   * IEEE80211_RADIOTAP_DB_ANTNOISE       uint8_t           decibel (dB)
   *
   *      RF noise power at the antenna, decibel difference from an
   *      arbitrary, fixed reference point.
   */
  IEEE80211_RADIOTAP_DB_ANTNOISE = 13,

  /**
   * IEEE80211_RADIOTAP_RX_FLAGS          __le16       bitmap
   *
   *     Properties of received frames. See flags defined below.
   */
  IEEE80211_RADIOTAP_RX_FLAGS = 14,

  /** 
   * IEEE80211_RADIOTAP_TX_FLAGS          __le16       bitmap
   *
   *     Properties of transmitted frames. See flags defined below.  
   */
  IEEE80211_RADIOTAP_TX_FLAGS = 15,

  /**
   * IEEE80211_RADIOTAP_RTS_RETRIES       uint8_t           data
   *
   *     Number of rts retries a transmitted frame used.
   */
  IEEE80211_RADIOTAP_RTS_RETRIES = 16,

  /**
   * IEEE80211_RADIOTAP_DATA_RETRIES      uint8_t           data
   *
   *     Number of unicast retries a transmitted frame used.
   */
  IEEE80211_RADIOTAP_DATA_RETRIES = 17,

  /**
   * Extension bit, used to indicate that more bits are needed for
   * the bitmask.
   */
  IEEE80211_RADIOTAP_EXT = 31
};

/**
 * Bitmask indicating an extension of the bitmask is used. 
 * (Mask corresponding to IEEE80211_RADIOTAP_EXT).
 */
#define IEEE80211_RADIOTAP_PRESENT_EXTEND_MASK (1 << IEEE80211_RADIOTAP_EXT)



/**
 * Bit in IEEE80211_RADIOTAP_FLAGS (which we might get
 * as part of a 'struct Ieee80211RadiotapHeader' extension
 * if the IEEE80211_RADIOTAP_FLAGS bit is set in
 * 'it_present').  The radiotap flags are an 8-bit field.
 *
 * Frame was sent/received during CFP (Contention Free Period)
 */
#define	IEEE80211_RADIOTAP_F_CFP	0x01

/**
 * Bit in IEEE80211_RADIOTAP_FLAGS (which we might get
 * as part of a 'struct Ieee80211RadiotapHeader' extension
 * if the IEEE80211_RADIOTAP_FLAGS bit is set in
 * 'it_present').  The radiotap flags are an 8-bit field.
 *
 * Frame was sent/received with short preamble
 */
#define	IEEE80211_RADIOTAP_F_SHORTPRE	0x02  

/**
 * Bit in IEEE80211_RADIOTAP_FLAGS (which we might get
 * as part of a 'struct Ieee80211RadiotapHeader' extension
 * if the IEEE80211_RADIOTAP_FLAGS bit is set in
 * 'it_present').  The radiotap flags are an 8-bit field.
 *
 * Frame was sent/received with WEP encryption
 */
#define	IEEE80211_RADIOTAP_F_WEP	0x04 

/**
 * Bit in IEEE80211_RADIOTAP_FLAGS (which we might get
 * as part of a 'struct Ieee80211RadiotapHeader' extension
 * if the IEEE80211_RADIOTAP_FLAGS bit is set in
 * 'it_present').  The radiotap flags are an 8-bit field.
 *
 * Frame was sent/received with fragmentation
 */
#define	IEEE80211_RADIOTAP_F_FRAG	0x08 

/**
 * Bit in IEEE80211_RADIOTAP_FLAGS (which we might get
 * as part of a 'struct Ieee80211RadiotapHeader' extension
 * if the IEEE80211_RADIOTAP_FLAGS bit is set in
 * 'it_present').  The radiotap flags are an 8-bit field.
 *
 * Frame includes FCS (CRC at the end that needs to be removeD).
 */
#define	IEEE80211_RADIOTAP_F_FCS	0x10    

/**
 * Bit in IEEE80211_RADIOTAP_FLAGS (which we might get
 * as part of a 'struct Ieee80211RadiotapHeader' extension
 * if the IEEE80211_RADIOTAP_FLAGS bit is set in
 * 'it_present').  The radiotap flags are an 8-bit field.
 *
 * Frame has padding between 802.11 header and payload
 * (to 32-bit boundary)
 */
#define	IEEE80211_RADIOTAP_F_DATAPAD	0x20    


/**
 * For IEEE80211_RADIOTAP_RX_FLAGS:
 * frame failed crc check
 */
#define IEEE80211_RADIOTAP_F_RX_BADFCS	0x0001  

/**
 * For IEEE80211_RADIOTAP_TX_FLAGS ('txflags' in 'struct RadiotapTransmissionHeader'):
 * failed due to excessive retries
 */
#define IEEE80211_RADIOTAP_F_TX_FAIL	0x0001  

/**
 * For IEEE80211_RADIOTAP_TX_FLAGS ('txflags' in 'struct RadiotapTransmissionHeader'):
 * used cts 'protection'
 */
#define IEEE80211_RADIOTAP_F_TX_CTS	0x0002  

/**
 * For IEEE80211_RADIOTAP_TX_FLAGS ('txflags' in 'struct RadiotapTransmissionHeader'):
 * used rts/cts handshake 
 */
#define IEEE80211_RADIOTAP_F_TX_RTS	0x0004  

/**
 * For IEEE80211_RADIOTAP_TX_FLAGS ('txflags' in 'struct RadiotapTransmissionHeader'):
 * frame should not be ACKed
 */
#define IEEE80211_RADIOTAP_F_TX_NOACK	0x0008

/**
 * For IEEE80211_RADIOTAP_TX_FLAGS ('txflags' in 'struct RadiotapTransmissionHeader'):
 * sequence number handled by userspace 
 */
#define IEEE80211_RADIOTAP_F_TX_NOSEQ	0x0010


/**
 * Generic header for radiotap messages (receiving and sending).  A
 * bit mask (it_present) determines which specific records follow.
 *
 * I am trying to describe precisely what the application programmer
 * should expect in the following, and for that reason I tell the
 * units and origin of each measurement (where it applies), or else I
 * use sufficiently weaselly language ("is a monotonically nondecreasing
 * function of...") that I cannot set false expectations for lawyerly
 * readers.
 *
 * The radio capture header precedes the 802.11 header.
 * All data in the header is little endian on all platforms.
 */
struct Ieee80211RadiotapHeader
{
  /**
   * Version 0. Only increases for drastic changes, introduction of
   * compatible new fields does not count.
   */
  uint8_t it_version;

  /**
   * Padding.  Set to 0.  
   */
  uint8_t it_pad;

  /**
   * length of the whole header in bytes, including it_version,
   * it_pad, it_len, and data fields.
   */
  uint16_t it_len;

  /**
   * A bitmap telling which fields are present. Set bit 31
   * (0x80000000) to extend the bitmap by another 32 bits.  Additional
   * extensions are made by setting bit 31.
   */
  uint32_t it_present;
};


/**
 * Format of the header we need to prepend to messages to be sent to the 
 * Kernel.
 */
struct RadiotapTransmissionHeader
{

  /**
   * First we begin with the 'generic' header we also get when receiving
   * messages.
   */
  struct Ieee80211RadiotapHeader header;

  /**
   * Transmission rate (we use 0, kernel makes up its mind anyway).
   */
  uint8_t rate;

  /**
   * Padding (we use 0).  There is a requirement to pad args, so that
   * args of a given length must begin at a boundary of that length.
   * As our next argument is the 'it_len' with 2 bytes, we need 1 byte
   * of padding.
   */
  uint8_t pad1;

  /**
   * Transmission flags from on the IEEE80211_RADIOTAP_F_TX_* constant family.
   */
  uint16_t txflags;

};

/**
 * The above 'struct RadiotapTransmissionHeader' should have the
 * following value for 'header.it_present' based on the presence of
 * the 'rate' and 'txflags' in the overall struct.
 */
#define IEEE80211_RADIOTAP_OUR_TRANSMISSION_HEADER_MASK ((1 << IEEE80211_RADIOTAP_RATE) | (1 << IEEE80211_RADIOTAP_TX_FLAGS))



/**
 * struct Ieee80211RadiotapHeaderIterator - tracks walk through present radiotap arguments
 * in the radiotap header.  Used when we parse radiotap packets received from the kernel.
 */
struct Ieee80211RadiotapHeaderIterator
{
  /**
   * pointer to the radiotap header we are walking through
   */
  const struct Ieee80211RadiotapHeader *rtheader;

  /**
   * pointer to current radiotap arg
   */
  const uint8_t *this_arg;

  /**
   * internal next argument pointer
   */
  const uint8_t *arg;

  /**
   * internal pointer to next present uint32_t (if IEEE80211_RADIOTAP_EXT is used).
   */
  const uint32_t *next_bitmap;

  /**
   * length of radiotap header in host byte ordering
   */
  size_t max_length;

  /**
   * internal shifter for current uint32_t bitmap, (it_present in host byte order),
   * If bit 0 is set, the 'arg_index' argument is present.
   */
  uint32_t bitmap_shifter;

  /**
   * IEEE80211_RADIOTAP_... index of current arg
   */
  unsigned int this_arg_index;

  /**
   * internal next argument index
   */
  unsigned int arg_index;

};


/* ************** end of structure of ARPHRD_IEEE80211_FULL ************** */

/* ************************** our globals ******************************* */

/**
 * struct for storing the information of the hardware.  There is only
 * one of these.
 */
struct HardwareInfos
{

  /**
   * file descriptor for the raw socket
   */
  int fd_raw;

  /**
   * Which format has the header that we're getting when receiving packets?
   * Some  ARPHRD_IEEE80211_XXX-value.
   */
  int arptype_in;

  /**
   * Name of the interface, not necessarily 0-terminated (!).
   */
  char iface[IFNAMSIZ];

  /**
   * MAC address of our own WLAN interface.
   */
  struct GNUNET_TRANSPORT_WLAN_MacAddress pl_mac;
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
 * Buffer for data read from stdin to be transmitted to the wirless card.
 */
static struct SendBuffer write_pout;

/**
 * Buffer for data read from the wireless card to be transmitted to stdout.
 */
static struct SendBuffer write_std;



/* *********** specialized version of server_mst.c begins here ********** */

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


/* ************** code for handling of ARPHRD_IEEE80211_FULL ************** */

/**
 * Radiotap header iteration
 *
 * call __ieee80211_radiotap_iterator_init() to init a semi-opaque iterator
 * struct Ieee80211RadiotapHeaderIterator (no need to init the struct beforehand)
 * then loop calling __ieee80211_radiotap_iterator_next()... it returns -1
 * if there are no more args in the header, or the next argument type index
 * that is present.  The iterator's this_arg member points to the start of the
 * argument associated with the current argument index that is present,
 * which can be found in the iterator's this_arg_index member.  This arg
 * index corresponds to the IEEE80211_RADIOTAP_... defines.
 *
 * @param iterator iterator to initialize
 * @param radiotap_header message to parse
 * @param max_length number of valid bytes in radiotap_header
 * @return 0 on success, -1 on error
 */
static int
ieee80211_radiotap_iterator_init (struct Ieee80211RadiotapHeaderIterator *iterator,
                                  const struct Ieee80211RadiotapHeader *radiotap_header, 
				  size_t max_length)
{
  if ( (iterator == NULL) ||
       (radiotap_header == NULL) )
    return -1;

  /* Linux only supports version 0 radiotap format */
  if (0 != radiotap_header->it_version)
    return -1;

  /* sanity check for allowed length and radiotap length field */
  if ( (max_length < sizeof (struct Ieee80211RadiotapHeader)) ||
       (max_length < (GNUNET_le16toh (radiotap_header->it_len))) )
    return -1;

  memset (iterator, 0, sizeof (struct Ieee80211RadiotapHeaderIterator));
  iterator->rtheader = radiotap_header;
  iterator->max_length = GNUNET_le16toh (radiotap_header->it_len);
  iterator->bitmap_shifter = GNUNET_le32toh (radiotap_header->it_present);
  iterator->arg = ((uint8_t *) radiotap_header) + sizeof (struct Ieee80211RadiotapHeader);

  /* find payload start allowing for extended bitmap(s) */
  if (0 != (iterator->bitmap_shifter & IEEE80211_RADIOTAP_PRESENT_EXTEND_MASK))
  {
    while (GNUNET_le32toh (*((uint32_t *) iterator->arg)) & IEEE80211_RADIOTAP_PRESENT_EXTEND_MASK)
    {
      iterator->arg += sizeof (uint32_t);
      /*
       * check for insanity where the present bitmaps
       * keep claiming to extend up to or even beyond the
       * stated radiotap header length
       */
      if (iterator->arg - ((uint8_t*) iterator->rtheader) > iterator->max_length)
        return -1;
    }
    iterator->arg += sizeof (uint32_t);
    /*
     * no need to check again for blowing past stated radiotap
     * header length, becuase ieee80211_radiotap_iterator_next
     * checks it before it is dereferenced
     */
  }
  /* we are all initialized happily */
  return 0;
}


/**
 * Returns the next radiotap parser iterator arg.
 *
 * This function returns the next radiotap arg index (IEEE80211_RADIOTAP_...)
 * and sets iterator->this_arg to point to the payload for the arg.  It takes
 * care of alignment handling and extended present fields.  interator->this_arg
 * can be changed by the caller.  The args pointed to are in little-endian
 * format.
 *
 * @param iterator: radiotap_iterator to move to next arg (if any)
 * @return next present arg index on success or -1 if no more or error
 */
static int
ieee80211_radiotap_iterator_next (struct Ieee80211RadiotapHeaderIterator *iterator)
{
  /*
   * small length lookup table for all radiotap types we heard of
   * starting from b0 in the bitmap, so we can walk the payload
   * area of the radiotap header
   *
   * There is a requirement to pad args, so that args
   * of a given length must begin at a boundary of that length
   * -- but note that compound args are allowed (eg, 2 x uint16_t
   * for IEEE80211_RADIOTAP_CHANNEL) so total arg length is not
   * a reliable indicator of alignment requirement.
   *
   * upper nybble: content alignment for arg
   * lower nybble: content length for arg
   */

  static const uint8_t rt_sizes[] = {
    [IEEE80211_RADIOTAP_TSFT] = 0x88,
    [IEEE80211_RADIOTAP_FLAGS] = 0x11,
    [IEEE80211_RADIOTAP_RATE] = 0x11,
    [IEEE80211_RADIOTAP_CHANNEL] = 0x24,
    [IEEE80211_RADIOTAP_FHSS] = 0x22,
    [IEEE80211_RADIOTAP_DBM_ANTSIGNAL] = 0x11,
    [IEEE80211_RADIOTAP_DBM_ANTNOISE] = 0x11,
    [IEEE80211_RADIOTAP_LOCK_QUALITY] = 0x22,
    [IEEE80211_RADIOTAP_TX_ATTENUATION] = 0x22,
    [IEEE80211_RADIOTAP_DB_TX_ATTENUATION] = 0x22,
    [IEEE80211_RADIOTAP_DBM_TX_POWER] = 0x11,
    [IEEE80211_RADIOTAP_ANTENNA] = 0x11,
    [IEEE80211_RADIOTAP_DB_ANTSIGNAL] = 0x11,
    [IEEE80211_RADIOTAP_DB_ANTNOISE] = 0x11,
    [IEEE80211_RADIOTAP_TX_FLAGS] = 0x22,
    [IEEE80211_RADIOTAP_RX_FLAGS] = 0x22,
    [IEEE80211_RADIOTAP_RTS_RETRIES] = 0x11,
    [IEEE80211_RADIOTAP_DATA_RETRIES] = 0x11
        /*
         * add more here as they are defined in
         * include/net/ieee80211_radiotap.h
         */
  };

  /*
   * for every radiotap entry we can at
   * least skip (by knowing the length)...
   */
  while (iterator->arg_index < sizeof (rt_sizes))
  {
    int hit = (0 != (iterator->bitmap_shifter & 1));

    if (hit)
    {
      unsigned int wanted_alignment;
      unsigned int unalignment;
      /*
       * arg is present, account for alignment padding
       *  8-bit args can be at any alignment
       * 16-bit args must start on 16-bit boundary
       * 32-bit args must start on 32-bit boundary
       * 64-bit args must start on 64-bit boundary
       *
       * note that total arg size can differ from alignment of
       * elements inside arg, so we use upper nybble of length table
       * to base alignment on.  First, 'wanted_alignment' is set to be
       * 1 for 8-bit, 2 for 16-bit, 4 for 32-bit and 8 for 64-bit
       * arguments.  Then, we calculate the 'unalignment' (how many
       * bytes we are over by taking the difference of 'arg' and the
       * overall starting point modulo the desired alignment.  As
       * desired alignments are powers of two, we can do modulo with
       * binary "&" (and also avoid the possibility of a division by
       * zero if the 'rt_sizes' table contains bogus entries).
       *
       * also note: these alignments are relative to the start of the
       * radiotap header.  There is no guarantee that the radiotap
       * header itself is aligned on any kind of boundary, thus we
       * need to really look at the delta here.
       */
      wanted_alignment = rt_sizes[iterator->arg_index] >> 4;
      unalignment = (((void *) iterator->arg) - ((void *) iterator->rtheader)) & (wanted_alignment - 1);
      if (0 != unalignment)
      {
	/* need padding (by 'wanted_alignment - unalignment') */
	iterator->arg_index += wanted_alignment - unalignment;
      }
      
      /*
       * this is what we will return to user, but we need to
       * move on first so next call has something fresh to test
       */     
      iterator->this_arg_index = iterator->arg_index;
      iterator->this_arg = iterator->arg;

      /* internally move on the size of this arg (using lower nybble from
	 the table) */ 
      iterator->arg += rt_sizes[iterator->arg_index] & 0x0f;
      
      /*
       * check for insanity where we are given a bitmap that
       * claims to have more arg content than the length of the
       * radiotap section.  We will normally end up equalling this
       * max_length on the last arg, never exceeding it.
       */      
      if ((((void *) iterator->arg) - ((void *) iterator->rtheader)) > iterator->max_length)
	return -1;      
    }

    /* Now, move on to next bit / next entry */
    iterator->arg_index++;

    if (0 == (iterator->arg_index % 32))
    {
      /* completed current uint32_t bitmap */
      if (0 != (iterator->bitmap_shifter & 1))
      {
        /* bit 31 was set, there is more; move to next uint32_t bitmap */
        iterator->bitmap_shifter = GNUNET_le32toh (*iterator->next_bitmap);
        iterator->next_bitmap++;
      }
      else
      {
        /* no more bitmaps: end (by setting arg_index to high, unsupported value) */
        iterator->arg_index = sizeof (rt_sizes);
      }
    }
    else
    {                           
      /* just try the next bit (while loop will move on) */
      iterator->bitmap_shifter >>= 1;
    }

    /* if we found a valid arg earlier, return it now */
    if (hit)
      return iterator->this_arg_index;
  }

  /* we don't know how to handle any more args (or there are no more),
     so we're done (this is not an error) */
  return -1;
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
 * Calculate and check crc of the wlan packet
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


/* ************end of code for handling of ARPHRD_IEEE80211_FULL ************** */


/* ************beginning of code for reading packets from kernel ************** */

/**
 * Return the channel from the frequency (in Mhz)
 *
 * @param frequency of the channel
 * @return number of the channel
 */
static int
get_channel_from_frequency (int32_t frequency)
{
  if (frequency >= 2412 && frequency <= 2472)
    return (frequency - 2407) / 5;
  if (frequency == 2484)
    return 14;
  if (frequency >= 5000 && frequency <= 6100)
    return (frequency - 5000) / 5;
  return -1;
}


/**
 * Get the channel used by our WLAN interface.
 *
 * @param dev pointer to the dev struct of the card
 * @return channel number, -1 on error
 */
static int
linux_get_channel (const struct HardwareInfos *dev)
{
  struct iwreq wrq;
  int32_t frequency;

  memset (&wrq, 0, sizeof (struct iwreq));
  strncpy (wrq.ifr_name, dev->iface, IFNAMSIZ);
  if (0 > ioctl (dev->fd_raw, SIOCGIWFREQ, &wrq))
    return -1;
  frequency = wrq.u.freq.m; /* 'iw_freq' defines 'm' as '__s32', so we keep it signed */
  if (100000000 < frequency)
    frequency /= 100000;
  else if (1000000 < frequency)
    frequency /= 1000;
  if (1000 < frequency)
    return get_channel_from_frequency (frequency);
  return frequency;
}


/**
 * Read from the raw socket (the wlan card), parse the packet and
 * put the result into the buffer for transmission to 'stdout'.
 *
 * @param dev pointer to the struct of the wlan card
 * @param buf buffer to read to; first bytes will be the 'struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame',
 *            followed by the actual payload
 * @param buf_size size of the buffer
 * @param ri where to write radiotap_rx info
 * @return number of bytes written to 'buf'
 */
static ssize_t
linux_read (struct HardwareInfos *dev, 
	    unsigned char *buf, size_t buf_size,
            struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage *ri)
{
  unsigned char tmpbuf[buf_size];
  ssize_t caplen;
  size_t n;
  int got_signal = 0;
  int got_noise = 0;
  int got_channel = 0;
  int fcs_removed = 0;

  caplen = read (dev->fd_raw, tmpbuf, buf_size);
  if (0 > caplen)
  {
    if (EAGAIN == errno)
      return 0;
    fprintf (stderr, "Failed to read from RAW socket: %s\n", strerror (errno));
    return -1;
  }

  memset (ri, 0, sizeof (*ri)); 
  switch (dev->arptype_in)
  {
  case ARPHRD_IEEE80211_PRISM:
    {
      const struct PrismHeader *ph;

      ph = (const struct PrismHeader*) tmpbuf;
      n = ph->msglen;
      if ( (n < 8) || (n >= caplen) )
	return 0; /* invalid format */
      if ( (PRISM_MSGCODE_MONITOR == ph->msgcode) &&
	   (n >= sizeof (struct PrismHeader)) )
      {
	const char *pos;
	size_t left;
	struct PrismValue pv;
	
	left = n - sizeof (struct PrismHeader);
	pos = (const char *) &ph[1];
	while (left > sizeof (struct PrismValue))
	{
	  left -= sizeof (struct PrismValue);
	  memcpy (&pv, pos, sizeof (struct PrismValue));
	  pos += sizeof (struct PrismValue);

	  switch (pv.did)
	  {
	  case PRISM_DID_NOISE:
	    if (PRISM_STATUS_OK == pv.status)
	    {
	      ri->ri_noise = pv.data;
	      got_noise = 1;
	    }
	    break;
	  case PRISM_DID_RATE:
	    if (PRISM_STATUS_OK == pv.status)
	      ri->ri_rate = pv.data * 500000;
	    break;
	  case PRISM_DID_CHANNEL:
	    if (PRISM_STATUS_OK == pv.status)
	    {
	      ri->ri_channel = pv.data;
	      got_channel = 1;
	    }
	    break;
	  case PRISM_DID_MACTIME:
	    if (PRISM_STATUS_OK == pv.status)
	      ri->ri_mactime = pv.data;
	    break;
	  case PRISM_DID_SIGNAL:
	    if (PRISM_STATUS_OK == pv.status)
	    {
	      ri->ri_power = pv.data;
	      got_signal = 1;
	    }
	    break;
	  }
	}
      } 
      if ( (n < 8) || (n >= caplen) )
	return 0; /* invalid format */
    }
    break;
  case ARPHRD_IEEE80211_FULL:
    {
      struct Ieee80211RadiotapHeaderIterator iterator;
      struct Ieee80211RadiotapHeader *rthdr;

      memset (&iterator, 0, sizeof (iterator));
      rthdr = (struct Ieee80211RadiotapHeader *) tmpbuf;
      n = GNUNET_le16toh (rthdr->it_len);
      if ( (n < sizeof (struct Ieee80211RadiotapHeader)) || (n >= caplen))
	return 0; /* invalid 'it_len' */
      if (0 != ieee80211_radiotap_iterator_init (&iterator, rthdr, caplen))
	return 0;
      /* go through the radiotap arguments we have been given by the driver */
      while (0 <= ieee80211_radiotap_iterator_next (&iterator))
      {
	switch (iterator.this_arg_index)
	{
	case IEEE80211_RADIOTAP_TSFT:
	  ri->ri_mactime = GNUNET_le64toh (*((uint64_t *) iterator.this_arg));
	  break;
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
	  if (!got_signal)
	  {
	    ri->ri_power = * ((int8_t*) iterator.this_arg);
	    got_signal = 1;	  
	  }
	  break;
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
	  if (!got_signal)
	  {
	    ri->ri_power = * ((int8_t*) iterator.this_arg);
	    got_signal = 1;
	  }
	  break;
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
	  if (!got_noise)
	  {
	    ri->ri_noise = * ((int8_t*) iterator.this_arg);
	    got_noise = 1;
	  }
	  break;
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
	  if (!got_noise)
	  {
	    ri->ri_noise = * ((int8_t*) iterator.this_arg);
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
	  {
	    uint8_t flags = *iterator.this_arg;
	    /* is the CRC visible at the end? if so, remove */
	    if (0 != (flags & IEEE80211_RADIOTAP_F_FCS))
	    {
	      fcs_removed = 1;
	      caplen -= sizeof (uint32_t);
	    }
	    break;
	  }
	case IEEE80211_RADIOTAP_RX_FLAGS:
	  {
	    uint16_t flags = ntohs (* ((uint16_t *) iterator.this_arg));
	    if (0 != (flags & IEEE80211_RADIOTAP_F_RX_BADFCS))
	      return 0;
	  }
	  break;
	} /* end of 'switch' */
      } /* end of the 'while' loop */
    }       
    break;
  case ARPHRD_IEEE80211:
    n = 0; /* no header */
    break;
  default:
    errno = ENOTSUP; /* unsupported format */
    return -1;
  }
  caplen -= n;
  if (! got_channel)
    ri->ri_channel = linux_get_channel (dev);

  /* detect CRC32 at the end, even if the flag wasn't set and remove it */
  if ( (0 == fcs_removed) && 
       (0 == check_crc_buf_osdep (tmpbuf + n, caplen - sizeof (uint32_t))) )  
  {
    /* NOTE: this heuristic can of course fail if there happens to
       be a matching checksum at the end. Would be good to have
       some data to see how often this heuristic actually works. */
    caplen -= sizeof (uint32_t);
  }
  /* copy payload to target buffer */
  memcpy (buf, tmpbuf + n, caplen);
  return caplen;
}


/* ************end of code for reading packets from kernel ************** */

/* ************other helper functions for main start here ************** */


/**
 * Open the wireless network interface for reading/writing.
 *
 * @param dev pointer to the device struct
 * @return 0 on success
 */
static int
open_device_raw (struct HardwareInfos *dev)
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
    fprintf (stderr, "ioctl(SIOCGIFINDEX) on interface `%.*s' failed: %s\n",
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
      fprintf (stderr, "ioctl(SIOCSIFFLAGS) on interface `%.*s' failed: %s\n",
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
    fprintf (stderr, "ioctl(SIOCGIFHWADDR) on interface `%.*s' failed: %s\n",
             IFNAMSIZ, dev->iface, strerror (errno));
    return 1;
  }

  memcpy (&dev->pl_mac, ifr.ifr_hwaddr.sa_data, MAC_ADDR_SIZE);
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
    fprintf (stderr, 
	     "Failed to enable promiscuous mode on interface `%.*s'\n",
             IFNAMSIZ, 
	     dev->iface);
    return 1;
  }
  return 0;
}


/**
 * Test if the given interface name really corresponds to a wireless
 * device.
 *
 * @param iface name of the interface
 * @return 0 on success, 1 on error
 */
static int
test_wlan_interface (const char *iface)
{
  char strbuf[512];
  struct stat sbuf;
  int ret;

  ret = snprintf (strbuf, sizeof (strbuf), 
		  "/sys/class/net/%s/phy80211/subsystem",
		  iface);
  if ((ret < 0) || (ret >= sizeof (strbuf)) || (0 != stat (strbuf, &sbuf)))
  {
    fprintf (stderr, 
	     "Did not find 802.11 interface `%s'. Exiting.\n", 
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
 */
static int
mac_test (const struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame *taIeeeHeader,
          const struct HardwareInfos *dev)
{
  if (0 != memcmp (&taIeeeHeader->addr3, &mac_bssid_gnunet, MAC_ADDR_SIZE))
    return 1; /* not a GNUnet ad-hoc package */
  if ( (0 == memcmp (&taIeeeHeader->addr1, &dev->pl_mac, MAC_ADDR_SIZE)) ||
       (0 == memcmp (&taIeeeHeader->addr1, &bc_all_mac, MAC_ADDR_SIZE)) )
    return 0; /* for us, or broadcast */
  return 1; /* not for us */
}


/**
 * Set the wlan header to sane values to make attacks more difficult
 *
 * @param taIeeeHeader pointer to the header of the packet
 * @param dev pointer to the Hardware_Infos struct
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
 * Process data from the stdin.  Takes the message, prepends the
 * radiotap transmission header, forces the sender MAC to be correct
 * and puts it into our buffer for transmission to the kernel.
 *
 * @param cls pointer to the device struct ('struct HardwareInfos*')
 * @param hdr pointer to the start of the packet
 */
static void
stdin_send_hw (void *cls, const struct GNUNET_MessageHeader *hdr)
{
  struct HardwareInfos *dev = cls;
  const struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *header;
  struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame *wlanheader;
  size_t sendsize;
  struct RadiotapTransmissionHeader rtheader;

  sendsize = ntohs (hdr->size);
  if ( (sendsize <
	sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage)) ||
       (GNUNET_MESSAGE_TYPE_WLAN_DATA_TO_HELPER != ntohs (hdr->type)) ) 
  {
    fprintf (stderr, "Received malformed message\n");
    exit (1);
  }
  sendsize -= (sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage) - sizeof (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame));
  if (MAXLINE < sendsize)
  {
    fprintf (stderr, "Packet too big for buffer\n");
    exit (1);
  }
  header = (const struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *) hdr;
  rtheader.header.it_version = 0;
  rtheader.header.it_pad = 0; 
  rtheader.header.it_len = GNUNET_htole16 (sizeof (rtheader));
  rtheader.header.it_present = GNUNET_htole16 (IEEE80211_RADIOTAP_OUR_TRANSMISSION_HEADER_MASK);
  rtheader.rate = header->rate; 
  rtheader.pad1 = 0;
  rtheader.txflags = GNUNET_htole16 (IEEE80211_RADIOTAP_F_TX_NOACK | IEEE80211_RADIOTAP_F_TX_NOSEQ);
  memcpy (write_pout.buf, &rtheader, sizeof (rtheader));
  memcpy (&write_pout.buf[sizeof (rtheader)], &header->frame, sendsize);
  wlanheader = (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame *) &write_pout.buf[sizeof (rtheader)];

  /* payload contains MAC address, but we don't trust it, so we'll
   * overwrite it with OUR MAC address to prevent mischief */
  mac_set (wlanheader, dev);
  write_pout.size = sendsize + sizeof (rtheader);
}


/**
 * Main function of the helper.  This code accesses a WLAN interface
 * in monitoring mode (layer 2) and then forwards traffic in both
 * directions between the WLAN interface and stdin/stdout of this
 * process.  Error messages are written to stdout.
 *
 * @param argc number of arguments, must be 2
 * @param argv arguments only argument is the name of the interface (i.e. 'mon0')
 * @return 0 on success (never happens, as we don't return unless aborted), 1 on error
 */
int
main (int argc, char *argv[])
{
  struct HardwareInfos dev;
  char readbuf[MAXLINE];
  int maxfd;
  fd_set rfds;
  fd_set wfds;
  int stdin_open;
  struct MessageStreamTokenizer *stdin_mst;
  int raw_eno;

  memset (&dev, 0, sizeof (dev));
  dev.fd_raw = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  raw_eno = errno; /* remember for later */

  /* drop privs */
  {
    uid_t uid = getuid ();
#ifdef HAVE_SETRESUID
    if (0 != setresuid (uid, uid, uid))
    {
      fprintf (stderr, "Failed to setresuid: %s\n", strerror (errno));
      if (-1 != dev.fd_raw)
	(void) close (dev.fd_raw);
      return 1;
    }
#else
    if (0 != (setuid (uid) | seteuid (uid)))
    {
      fprintf (stderr, "Failed to setuid: %s\n", strerror (errno));
      if (-1 != dev.fd_raw)
	(void) close (dev.fd_raw);
      return 1;
    }
  }
#endif

  /* now that we've dropped root rights, we can do error checking */
  if (2 != argc)
  {
    fprintf (stderr,
             "You must specify the name of the interface as the first and only argument to this program.\n");
    if (-1 != dev.fd_raw)
      (void) close (dev.fd_raw);
    return 1;
  }

  if (-1 == dev.fd_raw)
  {
    fprintf (stderr, "Failed to create raw socket: %s\n", strerror (raw_eno));
    return 1;
  }
  if (dev.fd_raw >= FD_SETSIZE)
  {
    fprintf (stderr, "File descriptor too large for select (%d > %d)\n",
             dev.fd_raw, FD_SETSIZE);
    (void) close (dev.fd_raw);
    return 1;
  }
  if (0 != test_wlan_interface (argv[1]))
  {
    (void) close (dev.fd_raw);
    return 1;
  }
  strncpy (dev.iface, argv[1], IFNAMSIZ);
  if (0 != open_device_raw (&dev))
  {
    (void) close (dev.fd_raw);
    return 1;
  }

  /* send MAC address of the WLAN interface to STDOUT first */
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
      FD_SET (dev.fd_raw, &rfds);
      maxfd = MAX (maxfd, dev.fd_raw);
    }
    FD_ZERO (&wfds);
    if (0 < write_std.size)
    {
      FD_SET (STDOUT_FILENO, &wfds);
      maxfd = MAX (maxfd, STDOUT_FILENO);
    }
    if (0 < write_pout.size)
    {
      FD_SET (dev.fd_raw, &wfds);
      maxfd = MAX (maxfd, dev.fd_raw);
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
    if (FD_ISSET (STDOUT_FILENO, &wfds))
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
    if (FD_ISSET (dev.fd_raw, &wfds))
    {
      ssize_t ret =
	write (dev.fd_raw, write_pout.buf + write_std.pos, 
	       write_pout.size - write_pout.pos);
      if (0 > ret)
      {
        fprintf (stderr, "Failed to write to WLAN device: %s\n",
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
      }
    }

    if (FD_ISSET (STDIN_FILENO, &rfds))
    {
      ssize_t ret = 
	read (STDIN_FILENO, readbuf, sizeof (readbuf));
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

    if (FD_ISSET (dev.fd_raw, &rfds))
    {
      struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage *rrm;
      ssize_t ret;

      rrm = (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage *) write_std.buf;
      ret =
          linux_read (&dev, (unsigned char *) &rrm->frame,
                      sizeof (write_std.buf) 
		      - sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage) 
		      + sizeof (struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame), 
		      rrm);
      if (0 > ret)
      {
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
  /* Error handling, try to clean up a bit at least */
  mst_destroy (stdin_mst);
  (void) close (dev.fd_raw);
  return 1;                     /* we never exit 'normally' */
}

/* end of gnunet-helper-transport-wlan.c */
