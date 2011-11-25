/*
   This file is part of GNUnet.
   (C) 2010, 2011 Christian Grothoff (and other contributing authors)
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

/**
 * @file src/transport/gnunet-transport-wlan-helper.c
 * @brief wlan layer two server; must run as root (SUID will do)
 *        This code will work under GNU/Linux only.
 * @author David Brodski
 *
 * This program serves as the mediator between the wlan interface and
 * gnunet
 */

/**
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
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "plugin_transport_wlan.h"

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;



/* Radiotap header version (from official NetBSD feed) */
#define IEEE80211RADIOTAP_VERSION	"1.5"
/* Base version of the radiotap packet header data */
#define PKTHDR_RADIOTAP_VERSION		0

/* A generic radio capture format is desirable. There is one for
 * Linux, but it is neither rigidly defined (there were not even
 * units given for some fields) nor easily extensible.
 *
 * I suggest the following extensible radio capture format. It is
 * based on a bitmap indicating which fields are present.
 *
 * I am trying to describe precisely what the application programmer
 * should expect in the following, and for that reason I tell the
 * units and origin of each measurement (where it applies), or else I
 * use sufficiently weaselly language ("is a monotonically nondecreasing
 * function of...") that I cannot set false expectations for lawyerly
 * readers.
 */

/* XXX tcpdump/libpcap do not tolerate variable-length headers,
 * yet, so we pad every radiotap header to 64 bytes. Ugh.
 */
#define IEEE80211_RADIOTAP_HDRLEN	64

/* The radio capture header precedes the 802.11 header.
 * All data in the header is little endian on all platforms.
 */
struct ieee80211_radiotap_header
{
  u8 it_version;                /* Version 0. Only increases
                                 * for drastic changes,
                                 * introduction of compatible
                                 * new fields does not count.
                                 */
  u8 it_pad;
  u16 it_len;                   /* length of the whole
                                 * header in bytes, including
                                 * it_version, it_pad,
                                 * it_len, and data fields.
                                 */
  u32 it_present;               /* A bitmap telling which
                                 * fields are present. Set bit 31
                                 * (0x80000000) to extend the
                                 * bitmap by another 32 bits.
                                 * Additional extensions are made
                                 * by setting bit 31.
                                 */
};

#define IEEE80211_RADIOTAP_PRESENT_EXTEND_MASK 0x80000000

/* Name                                 Data type    Units
 * ----                                 ---------    -----
 *
 * IEEE80211_RADIOTAP_TSFT              __le64       microseconds
 *
 *      Value in microseconds of the MAC's 64-bit 802.11 Time
 *      Synchronization Function timer when the first bit of the
 *      MPDU arrived at the MAC. For received frames, only.
 *
 * IEEE80211_RADIOTAP_CHANNEL           2 x __le16   MHz, bitmap
 *
 *      Tx/Rx frequency in MHz, followed by flags (see below).
 *
 * IEEE80211_RADIOTAP_FHSS              __le16       see below
 *
 *      For frequency-hopping radios, the hop set (first byte)
 *      and pattern (second byte).
 *
 * IEEE80211_RADIOTAP_RATE              u8           500kb/s
 *
 *      Tx/Rx data rate
 *
 * IEEE80211_RADIOTAP_DBM_ANTSIGNAL     s8           decibels from
 *                                                   one milliwatt (dBm)
 *
 *      RF signal power at the antenna, decibel difference from
 *      one milliwatt.
 *
 * IEEE80211_RADIOTAP_DBM_ANTNOISE      s8           decibels from
 *                                                   one milliwatt (dBm)
 *
 *      RF noise power at the antenna, decibel difference from one
 *      milliwatt.
 *
 * IEEE80211_RADIOTAP_DB_ANTSIGNAL      u8           decibel (dB)
 *
 *      RF signal power at the antenna, decibel difference from an
 *      arbitrary, fixed reference.
 *
 * IEEE80211_RADIOTAP_DB_ANTNOISE       u8           decibel (dB)
 *
 *      RF noise power at the antenna, decibel difference from an
 *      arbitrary, fixed reference point.
 *
 * IEEE80211_RADIOTAP_LOCK_QUALITY      __le16       unitless
 *
 *      Quality of Barker code lock. Unitless. Monotonically
 *      nondecreasing with "better" lock strength. Called "Signal
 *      Quality" in datasheets.  (Is there a standard way to measure
 *      this?)
 *
 * IEEE80211_RADIOTAP_TX_ATTENUATION    __le16       unitless
 *
 *      Transmit power expressed as unitless distance from max
 *      power set at factory calibration.  0 is max power.
 *      Monotonically nondecreasing with lower power levels.
 *
 * IEEE80211_RADIOTAP_DB_TX_ATTENUATION __le16       decibels (dB)
 *
 *      Transmit power expressed as decibel distance from max power
 *      set at factory calibration.  0 is max power.  Monotonically
 *      nondecreasing with lower power levels.
 *
 * IEEE80211_RADIOTAP_DBM_TX_POWER      s8           decibels from
 *                                                   one milliwatt (dBm)
 *
 *      Transmit power expressed as dBm (decibels from a 1 milliwatt
 *      reference). This is the absolute power level measured at
 *      the antenna port.
 *
 * IEEE80211_RADIOTAP_FLAGS             u8           bitmap
 *
 *      Properties of transmitted and received frames. See flags
 *      defined below.
 *
 * IEEE80211_RADIOTAP_ANTENNA           u8           antenna index
 *
 *      Unitless indication of the Rx/Tx antenna for this packet.
 *      The first antenna is antenna 0.
 *
 * IEEE80211_RADIOTAP_RX_FLAGS          __le16       bitmap
 *
 *     Properties of received frames. See flags defined below.
 *
 * IEEE80211_RADIOTAP_TX_FLAGS          __le16       bitmap
 *
 *     Properties of transmitted frames. See flags defined below.
 *
 * IEEE80211_RADIOTAP_RTS_RETRIES       u8           data
 *
 *     Number of rts retries a transmitted frame used.
 *
 * IEEE80211_RADIOTAP_DATA_RETRIES      u8           data
 *
 *     Number of unicast retries a transmitted frame used.
 *
 */
enum ieee80211_radiotap_type
{
  IEEE80211_RADIOTAP_TSFT = 0,
  IEEE80211_RADIOTAP_FLAGS = 1,
  IEEE80211_RADIOTAP_RATE = 2,
  IEEE80211_RADIOTAP_CHANNEL = 3,
  IEEE80211_RADIOTAP_FHSS = 4,
  IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
  IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
  IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
  IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
  IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
  IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
  IEEE80211_RADIOTAP_ANTENNA = 11,
  IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
  IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
  IEEE80211_RADIOTAP_RX_FLAGS = 14,
  IEEE80211_RADIOTAP_TX_FLAGS = 15,
  IEEE80211_RADIOTAP_RTS_RETRIES = 16,
  IEEE80211_RADIOTAP_DATA_RETRIES = 17,
  IEEE80211_RADIOTAP_EXT = 31
};

/* Channel flags. */
#define	IEEE80211_CHAN_TURBO	0x0010  /* Turbo channel */
#define	IEEE80211_CHAN_CCK	0x0020  /* CCK channel */
#define	IEEE80211_CHAN_OFDM	0x0040  /* OFDM channel */
#define	IEEE80211_CHAN_2GHZ	0x0080  /* 2 GHz spectrum channel. */
#define	IEEE80211_CHAN_5GHZ	0x0100  /* 5 GHz spectrum channel */
#define	IEEE80211_CHAN_PASSIVE	0x0200  /* Only passive scan allowed */
#define	IEEE80211_CHAN_DYN	0x0400  /* Dynamic CCK-OFDM channel */
#define	IEEE80211_CHAN_GFSK	0x0800  /* GFSK channel (FHSS PHY) */

/* For IEEE80211_RADIOTAP_FLAGS */
#define	IEEE80211_RADIOTAP_F_CFP	0x01    /* sent/received
                                                 * during CFP
                                                 */
#define	IEEE80211_RADIOTAP_F_SHORTPRE	0x02    /* sent/received
                                                 * with short
                                                 * preamble
                                                 */
#define	IEEE80211_RADIOTAP_F_WEP	0x04    /* sent/received
                                                 * with WEP encryption
                                                 */
#define	IEEE80211_RADIOTAP_F_FRAG	0x08    /* sent/received
                                                 * with fragmentation
                                                 */
#define	IEEE80211_RADIOTAP_F_FCS	0x10    /* frame includes FCS */
#define	IEEE80211_RADIOTAP_F_DATAPAD	0x20    /* frame has padding between
                                                 * 802.11 header and payload
                                                 * (to 32-bit boundary)
                                                 */
/* For IEEE80211_RADIOTAP_RX_FLAGS */
#define IEEE80211_RADIOTAP_F_RX_BADFCS	0x0001  /* frame failed crc check */

/* For IEEE80211_RADIOTAP_TX_FLAGS */
#define IEEE80211_RADIOTAP_F_TX_FAIL	0x0001  /* failed due to excessive
                                                 * retries */
#define IEEE80211_RADIOTAP_F_TX_CTS	0x0002  /* used cts 'protection' */
#define IEEE80211_RADIOTAP_F_TX_RTS	0x0004  /* used rts/cts handshake */
#define IEEE80211_RADIOTAP_F_TX_NOACK	0x0008  /* frame should not be ACKed */
#define IEEE80211_RADIOTAP_F_TX_NOSEQ	0x0010  /* sequence number handled
                                                 * by userspace */

/* Ugly macro to convert literal channel numbers into their mhz equivalents
 * There are certianly some conditions that will break this (like feeding it '30')
 * but they shouldn't arise since nothing talks on channel 30. */
#define ieee80211chan2mhz(x) \
	(((x) <= 14) ? \
	(((x) == 14) ? 2484 : ((x) * 5) + 2407) : \
	((x) + 1000) * 5)



 /* *INDENT-OFF* */
#define ___my_swab16(x) \
((u_int16_t)( \
  (((u_int16_t)(x) & (u_int16_t)0x00ffU) << 8) | \
  (((u_int16_t)(x) & (u_int16_t)0xff00U) >> 8) ))

#define ___my_swab32(x) \
((u_int32_t)( \
  (((u_int32_t)(x) & (u_int32_t)0x000000ffUL) << 24) | \
  (((u_int32_t)(x) & (u_int32_t)0x0000ff00UL) <<  8) | \
  (((u_int32_t)(x) & (u_int32_t)0x00ff0000UL) >>  8) | \
  (((u_int32_t)(x) & (u_int32_t)0xff000000UL) >> 24) ))
#define ___my_swab64(x) \
((u_int64_t)( \
  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x00000000000000ffULL) << 56) | \
  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x000000000000ff00ULL) << 40) | \
  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x0000000000ff0000ULL) << 24) | \
  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x00000000ff000000ULL) <<  8) | \
  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x000000ff00000000ULL) >>  8) | \
  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x0000ff0000000000ULL) >> 24) | \
  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x00ff000000000000ULL) >> 40) | \
  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0xff00000000000000ULL) >> 56) ))
 /* *INDENT-ON* */
    /*
     * Linux
     */
#if defined(linux) || defined(Linux) || defined(__linux__) || defined(__linux) || defined(__gnu_linux__)
#include <endian.h>
#include <unistd.h>
#include <stdint.h>

#ifndef __int8_t_defined
typedef uint64_t u_int64_t;
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;


#endif /*  */

#ifndef htole16
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htobe16(x) ___my_swab16 (x)
#define htole16(x) (x)
#define be16toh(x) ___my_swab16 (x)
#define le16toh(x) (x)

#define htobe32(x) ___my_swab32 (x)
#define htole32(x) (x)
#define be32toh(x) ___my_swab32 (x)
#define le32toh(x) (x)

#define htobe64(x) ___my_swab64 (x)
#define htole64(x) (x)
#define be64toh(x) ___my_swab64 (x)
#define le64toh(x) (x)
#else /*  */
#define htobe16(x) (x)
#define htole16(x) ___my_swab16 (x)
#define be16toh(x) (x)
#define le16toh(x) ___my_swab16 (x)

#define htobe32(x) (x)
#define htole32(x) ___my_swab32 (x)
#define be32toh(x) (x)
#define le32toh(x) ___my_swab32 (x)

#define htobe64(x) (x)
#define htole64(x) ___my_swab64 (x)
#define be64toh(x) (x)
#define le64toh(x) ___my_swab64 (x)
#endif /*  */
#endif /*  */

#endif /*  */
    /*
     * Cygwin
     */
#if defined(__CYGWIN32__)
#include <asm/byteorder.h>
#include <unistd.h>
#define __be64_to_cpu(x) ___my_swab64(x)
#define __be32_to_cpu(x) ___my_swab32(x)
#define __be16_to_cpu(x) ___my_swab16(x)
#define __cpu_to_be64(x) ___my_swab64(x)
#define __cpu_to_be32(x) ___my_swab32(x)
#define __cpu_to_be16(x) ___my_swab16(x)
#define __le64_to_cpu(x) (x)
#define __le32_to_cpu(x) (x)
#define __le16_to_cpu(x) (x)
#define __cpu_to_le64(x) (x)
#define __cpu_to_le32(x) (x)
#define __cpu_to_le16(x) (x)
#define AIRCRACK_NG_BYTE_ORDER_DEFINED
#endif /*  */
    /*
     * Windows (DDK)
     */
#if defined(__WIN__)
#include <io.h>
#define __be64_to_cpu(x) ___my_swab64(x)
#define __be32_to_cpu(x) ___my_swab32(x)
#define __be16_to_cpu(x) ___my_swab16(x)
#define __cpu_to_be64(x) ___my_swab64(x)
#define __cpu_to_be32(x) ___my_swab32(x)
#define __cpu_to_be16(x) ___my_swab16(x)
#define __le64_to_cpu(x) (x)
#define __le32_to_cpu(x) (x)
#define __le16_to_cpu(x) (x)
#define __cpu_to_le64(x) (x)
#define __cpu_to_le32(x) (x)
#define __cpu_to_le16(x) (x)
#define AIRCRACK_NG_BYTE_ORDER_DEFINED
#endif /*  */
    /*
     * MAC (Darwin)
     */
#if defined(__APPLE_CC__)
#if defined(__x86_64__) && defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define __swab64(x)      (unsigned long long) OSSwapInt64((uint64_t)x)
#define __swab32(x)      (unsigned long) OSSwapInt32((uint32_t)x)
#define __swab16(x)      (unsigned short) OSSwapInt16((uint16_t)x)
#define __be64_to_cpu(x) (unsigned long long) OSSwapBigToHostInt64((uint64_t)x)
#define __be32_to_cpu(x) (unsigned long) OSSwapBigToHostInt32((uint32_t)x)
#define __be16_to_cpu(x) (unsigned short) OSSwapBigToHostInt16((uint16_t)x)
#define __le64_to_cpu(x) (unsigned long long) OSSwapLittleToHostInt64((uint64_t)x)
#define __le32_to_cpu(x) (unsigned long) OSSwapLittleToHostInt32((uint32_t)x)
#define __le16_to_cpu(x) (unsigned short) OSSwapLittleToHostInt16((uint16_t)x)
#define __cpu_to_be64(x) (unsigned long long) OSSwapHostToBigInt64((uint64_t)x)
#define __cpu_to_be32(x) (unsigned long) OSSwapHostToBigInt32((uint32_t)x)
#define __cpu_to_be16(x) (unsigned short) OSSwapHostToBigInt16((uint16_t)x)
#define __cpu_to_le64(x) (unsigned long long) OSSwapHostToLittleInt64((uint64_t)x)
#define __cpu_to_le32(x) (unsigned long) OSSwapHostToLittleInt32((uint32_t)x)
#define __cpu_to_le16(x) (unsigned short) OSSwapHostToLittleInt16((uint16_t)x)
#else /*  */
#include <architecture/byte_order.h>
#define __swab64(x)      NXSwapLongLong(x)
#define __swab32(x)      NXSwapLong(x)
#define __swab16(x)      NXSwapShort(x)
#define __be64_to_cpu(x) NXSwapBigLongLongToHost(x)
#define __be32_to_cpu(x) NXSwapBigLongToHost(x)
#define __be16_to_cpu(x) NXSwapBigShortToHost(x)
#define __le64_to_cpu(x) NXSwapLittleLongLongToHost(x)
#define __le32_to_cpu(x) NXSwapLittleLongToHost(x)
#define __le16_to_cpu(x) NXSwapLittleShortToHost(x)
#define __cpu_to_be64(x) NXSwapHostLongLongToBig(x)
#define __cpu_to_be32(x) NXSwapHostLongToBig(x)
#define __cpu_to_be16(x) NXSwapHostShortToBig(x)
#define __cpu_to_le64(x) NXSwapHostLongLongToLittle(x)
#define __cpu_to_le32(x) NXSwapHostLongToLittle(x)
#define __cpu_to_le16(x) NXSwapHostShortToLittle(x)
#endif /*  */
#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN    4321
#define __PDP_ENDIAN    3412
#define __BYTE_ORDER    __BIG_ENDIAN
#define AIRCRACK_NG_BYTE_ORDER_DEFINED
#endif /*  */
    /*
     * Solaris
     * -------
     */
#if defined(__sparc__) && defined(__sun__)
#include <sys/byteorder.h>
#include <sys/types.h>
#include <unistd.h>
#define __be64_to_cpu(x) (x)
#define __be32_to_cpu(x) (x)
#define __be16_to_cpu(x) (x)
#define __cpu_to_be64(x) (x)
#define __cpu_to_be32(x) (x)
#define __cpu_to_be16(x) (x)
#define __le64_to_cpu(x) ___my_swab64(x)
#define __le32_to_cpu(x) ___my_swab32(x)
#define __le16_to_cpu(x) ___my_swab16(x)
#define __cpu_to_le64(x) ___my_swab64(x)
#define __cpu_to_le32(x) ___my_swab32(x)
#define __cpu_to_le16(x) ___my_swab16(x)
typedef uint64_t u_int64_t;
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;


#define AIRCRACK_NG_BYTE_ORDER_DEFINED
#endif /*  */
    /*
     * Custom stuff
     */
#if  defined(__MACH__) && !defined(__APPLE_CC__)
#include <libkern/OSByteOrder.h>
#define __cpu_to_be64(x) = OSSwapHostToBigInt64(x)
#define __cpu_to_be32(x) = OSSwapHostToBigInt32(x)
#define AIRCRACK_NG_BYTE_ORDER_DEFINED
#endif /*  */

    // FreeBSD
#ifdef __FreeBSD__
#include <machine/endian.h>
#endif /*  */
    // XXX: Is there anything to include on OpenBSD/NetBSD/DragonFlyBSD/...?

    // XXX: Mac: Check http://www.opensource.apple.com/source/CF/CF-476.18/CFByteOrder.h
    //           http://developer.apple.com/DOCUMENTATION/CoreFoundation/Reference/CFByteOrderUtils/Reference/reference.html
    //           Write to apple to ask what should be used.
#if defined(LITTLE_ENDIAN)
#define AIRCRACK_NG_LITTLE_ENDIAN LITTLE_ENDIAN
#elif defined(__LITTLE_ENDIAN)
#define AIRCRACK_NG_LITTLE_ENDIAN __LITTLE_ENDIAN
#elif defined(_LITTLE_ENDIAN)
#define AIRCRACK_NG_LITTLE_ENDIAN _LITTLE_ENDIAN
#endif /*  */
#if defined(BIG_ENDIAN)
#define AIRCRACK_NG_BIG_ENDIAN BIG_ENDIAN
#elif defined(__BIG_ENDIAN)
#define AIRCRACK_NG_BIG_ENDIAN __BIG_ENDIAN
#elif defined(_BIG_ENDIAN)
#define AIRCRACK_NG_BIG_ENDIAN _BIG_ENDIAN
#endif /*  */
#if !defined(AIRCRACK_NG_LITTLE_ENDIAN) && !defined(AIRCRACK_NG_BIG_ENDIAN)
#error Impossible to determine endianness (Little or Big endian), please contact the author.
#endif /*  */
#if defined(BYTE_ORDER)
#if (BYTE_ORDER == AIRCRACK_NG_LITTLE_ENDIAN)
#define AIRCRACK_NG_BYTE_ORDER AIRCRACK_NG_LITTLE_ENDIAN
#elif (BYTE_ORDER == AIRCRACK_NG_BIG_ENDIAN)
#define AIRCRACK_NG_BYTE_ORDER AIRCRACK_NG_BIG_ENDIAN
#endif /*  */
#elif defined(__BYTE_ORDER)
#if (__BYTE_ORDER == AIRCRACK_NG_LITTLE_ENDIAN)
#define AIRCRACK_NG_BYTE_ORDER AIRCRACK_NG_LITTLE_ENDIAN
#elif (__BYTE_ORDER == AIRCRACK_NG_BIG_ENDIAN)
#define AIRCRACK_NG_BYTE_ORDER AIRCRACK_NG_BIG_ENDIAN
#endif /*  */
#elif defined(_BYTE_ORDER)
#if (_BYTE_ORDER == AIRCRACK_NG_LITTLE_ENDIAN)
#define AIRCRACK_NG_BYTE_ORDER AIRCRACK_NG_LITTLE_ENDIAN
#elif (_BYTE_ORDER == AIRCRACK_NG_BIG_ENDIAN)
#define AIRCRACK_NG_BYTE_ORDER AIRCRACK_NG_BIG_ENDIAN
#endif /*  */
#endif /*  */
#ifndef AIRCRACK_NG_BYTE_ORDER
#error Impossible to determine endianness (Little or Big endian), please contact the author.
#endif /*  */
#if (AIRCRACK_NG_BYTE_ORDER == AIRCRACK_NG_LITTLE_ENDIAN)
#ifndef AIRCRACK_NG_BYTE_ORDER_DEFINED
#define __be64_to_cpu(x) ___my_swab64(x)
#define __be32_to_cpu(x) ___my_swab32(x)
#define __be16_to_cpu(x) ___my_swab16(x)
#define __cpu_to_be64(x) ___my_swab64(x)
#define __cpu_to_be32(x) ___my_swab32(x)
#define __cpu_to_be16(x) ___my_swab16(x)
#define __le64_to_cpu(x) (x)
#define __le32_to_cpu(x) (x)
#define __le16_to_cpu(x) (x)
#define __cpu_to_le64(x) (x)
#define __cpu_to_le32(x) (x)
#define __cpu_to_le16(x) (x)
#endif /*  */
#ifndef htobe16
#define htobe16 ___my_swab16
#endif /*  */
#ifndef htobe32
#define htobe32 ___my_swab32
#endif /*  */
#ifndef betoh16
#define betoh16 ___my_swab16
#endif /*  */
#ifndef betoh32
#define betoh32 ___my_swab32
#endif /*  */
#ifndef htole16
#define htole16(x) (x)
#endif /*  */
#ifndef htole32
#define htole32(x) (x)
#endif /*  */
#ifndef letoh16
#define letoh16(x) (x)
#endif /*  */
#ifndef letoh32
#define letoh32(x) (x)
#endif /*  */
#endif /*  */
#if (AIRCRACK_NG_BYTE_ORDER == AIRCRACK_NG_BIG_ENDIAN)
#ifndef AIRCRACK_NG_BYTE_ORDER_DEFINED
#define __be64_to_cpu(x) (x)
#define __be32_to_cpu(x) (x)
#define __be16_to_cpu(x) (x)
#define __cpu_to_be64(x) (x)
#define __cpu_to_be32(x) (x)
#define __cpu_to_be16(x) (x)
#define __le64_to_cpu(x) ___my_swab64(x)
#define __le32_to_cpu(x) ___my_swab32(x)
#define __le16_to_cpu(x) ___my_swab16(x)
#define __cpu_to_le64(x) ___my_swab64(x)
#define __cpu_to_le32(x) ___my_swab32(x)
#define __cpu_to_le16(x) ___my_swab16(x)
#endif /*  */
#ifndef htobe16
#define htobe16(x) (x)
#endif /*  */
#ifndef htobe32
#define htobe32(x) (x)
#endif /*  */
#ifndef betoh16
#define betoh16(x) (x)
#endif /*  */
#ifndef betoh32
#define betoh32(x) (x)
#endif /*  */
#ifndef htole16
#define htole16 ___my_swab16
#endif /*  */
#ifndef htole32
#define htole32 ___my_swab32
#endif /*  */
#ifndef letoh16
#define letoh16 ___my_swab16
#endif /*  */
#ifndef letoh32
#define letoh32 ___my_swab32
#endif /*  */
#endif /*  */
    // Common defines
#define cpu_to_le64 __cpu_to_le64
#define le64_to_cpu __le64_to_cpu
#define cpu_to_le32 __cpu_to_le32
#define le32_to_cpu __le32_to_cpu
#define cpu_to_le16 __cpu_to_le16
#define le16_to_cpu __le16_to_cpu
#define cpu_to_be64 __cpu_to_be64
#define be64_to_cpu __be64_to_cpu
#define cpu_to_be32 __cpu_to_be32
#define be32_to_cpu __be32_to_cpu
#define cpu_to_be16 __cpu_to_be16
#define be16_to_cpu __be16_to_cpu
#ifndef le16toh
#define le16toh le16_to_cpu
#endif /*  */
#ifndef be16toh
#define be16toh be16_to_cpu
#endif /*  */
#ifndef le32toh
#define le32toh le32_to_cpu
#endif /*  */
#ifndef be32toh
#define be32toh be32_to_cpu
#endif /*  */

#ifndef htons
#define htons be16_to_cpu
#endif /*  */
#ifndef htonl
#define htonl cpu_to_be16
#endif /*  */
#ifndef ntohs
#define ntohs cpu_to_be16
#endif /*  */
#ifndef ntohl
#define ntohl cpu_to_be32
#endif /*  */



/*
 * Radiotap header iteration
 *   implemented in src/radiotap-parser.c
 *
 * call __ieee80211_radiotap_iterator_init() to init a semi-opaque iterator
 * struct ieee80211_radiotap_iterator (no need to init the struct beforehand)
 * then loop calling __ieee80211_radiotap_iterator_next()... it returns -1
 * if there are no more args in the header, or the next argument type index
 * that is present.  The iterator's this_arg member points to the start of the
 * argument associated with the current argument index that is present,
 * which can be found in the iterator's this_arg_index member.  This arg
 * index corresponds to the IEEE80211_RADIOTAP_... defines.
 */
/**
 * struct ieee80211_radiotap_iterator - tracks walk thru present radiotap args
 * @rtheader: pointer to the radiotap header we are walking through
 * @max_length: length of radiotap header in cpu byte ordering
 * @this_arg_index: IEEE80211_RADIOTAP_... index of current arg
 * @this_arg: pointer to current radiotap arg
 * @arg_index: internal next argument index
 * @arg: internal next argument pointer
 * @next_bitmap: internal pointer to next present u32
 * @bitmap_shifter: internal shifter for curr u32 bitmap, b0 set == arg present
 */

struct ieee80211_radiotap_iterator
{
  struct ieee80211_radiotap_header *rtheader;
  int max_length;
  int this_arg_index;
  u8 *this_arg;

  int arg_index;
  u8 *arg;
  u32 *next_bitmap;
  u32 bitmap_shifter;
};


/*
 * Radiotap header iteration
 *   implemented in src/radiotap-parser.c
 *
 * call __ieee80211_radiotap_iterator_init() to init a semi-opaque iterator
 * struct ieee80211_radiotap_iterator (no need to init the struct beforehand)
 * then loop calling __ieee80211_radiotap_iterator_next()... it returns -1
 * if there are no more args in the header, or the next argument type index
 * that is present.  The iterator's this_arg member points to the start of the
 * argument associated with the current argument index that is present,
 * which can be found in the iterator's this_arg_index member.  This arg
 * index corresponds to the IEEE80211_RADIOTAP_... defines.
 */


int
ieee80211_radiotap_iterator_init (struct ieee80211_radiotap_iterator *iterator,
                                  struct ieee80211_radiotap_header
                                  *radiotap_header, int max_length)
{
  if (iterator == NULL)
    return (-EINVAL);

  if (radiotap_header == NULL)
    return (-EINVAL);
  /* Linux only supports version 0 radiotap format */

  if (radiotap_header->it_version)
    return (-EINVAL);

  /* sanity check for allowed length and radiotap length field */

  if (max_length < (le16_to_cpu (radiotap_header->it_len)))
    return (-EINVAL);

  iterator->rtheader = radiotap_header;
  iterator->max_length = le16_to_cpu (radiotap_header->it_len);
  iterator->arg_index = 0;
  iterator->bitmap_shifter = le32_to_cpu (radiotap_header->it_present);
  iterator->arg =
      ((u8 *) radiotap_header) + sizeof (struct ieee80211_radiotap_header);
  iterator->this_arg = 0;

  /* find payload start allowing for extended bitmap(s) */

  if ((iterator->bitmap_shifter & IEEE80211_RADIOTAP_PRESENT_EXTEND_MASK))
  {
    while (le32_to_cpu (*((u32 *) iterator->arg)) &
           IEEE80211_RADIOTAP_PRESENT_EXTEND_MASK)
    {
      iterator->arg += sizeof (u32);

      /*
       * check for insanity where the present bitmaps
       * keep claiming to extend up to or even beyond the
       * stated radiotap header length
       */

      if ((((void *) iterator->arg) - ((void *) iterator->rtheader)) >
          iterator->max_length)
        return (-EINVAL);

    }

    iterator->arg += sizeof (u32);

    /*
     * no need to check again for blowing past stated radiotap
     * header length, becuase ieee80211_radiotap_iterator_next
     * checks it before it is dereferenced
     */

  }

  /* we are all initialized happily */

  return (0);
}


/**
 * ieee80211_radiotap_iterator_next - return next radiotap parser iterator arg
 * @iterator: radiotap_iterator to move to next arg (if any)
 *
 * Returns: next present arg index on success or negative if no more or error
 *
 * This function returns the next radiotap arg index (IEEE80211_RADIOTAP_...)
 * and sets iterator->this_arg to point to the payload for the arg.  It takes
 * care of alignment handling and extended present fields.  interator->this_arg
 * can be changed by the caller.  The args pointed to are in little-endian
 * format.
 */

int
ieee80211_radiotap_iterator_next (struct ieee80211_radiotap_iterator *iterator)
{

  /*
   * small length lookup table for all radiotap types we heard of
   * starting from b0 in the bitmap, so we can walk the payload
   * area of the radiotap header
   *
   * There is a requirement to pad args, so that args
   * of a given length must begin at a boundary of that length
   * -- but note that compound args are allowed (eg, 2 x u16
   * for IEEE80211_RADIOTAP_CHANNEL) so total arg length is not
   * a reliable indicator of alignment requirement.
   *
   * upper nybble: content alignment for arg
   * lower nybble: content length for arg
   */

  static const u8 rt_sizes[] = {
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

  while (iterator->arg_index < (int) sizeof (rt_sizes))
  {
    int hit = 0;

    if (!(iterator->bitmap_shifter & 1))
      goto next_entry;          /* arg not present */

    /*
     * arg is present, account for alignment padding
     *  8-bit args can be at any alignment
     * 16-bit args must start on 16-bit boundary
     * 32-bit args must start on 32-bit boundary
     * 64-bit args must start on 64-bit boundary
     *
     * note that total arg size can differ from alignment of
     * elements inside arg, so we use upper nybble of length
     * table to base alignment on
     *
     * also note: these alignments are ** relative to the
     * start of the radiotap header **.  There is no guarantee
     * that the radiotap header itself is aligned on any
     * kind of boundary.
     */

    if ((((void *) iterator->arg) -
         ((void *) iterator->rtheader)) & ((rt_sizes[iterator->arg_index] >> 4)
                                           - 1))
      iterator->arg_index +=
          (rt_sizes[iterator->arg_index] >> 4) -
          ((((void *) iterator->arg) -
            ((void *) iterator->rtheader)) & ((rt_sizes[iterator->arg_index] >>
                                               4) - 1));

    /*
     * this is what we will return to user, but we need to
     * move on first so next call has something fresh to test
     */

    iterator->this_arg_index = iterator->arg_index;
    iterator->this_arg = iterator->arg;
    hit = 1;

    /* internally move on the size of this arg */

    iterator->arg += rt_sizes[iterator->arg_index] & 0x0f;

    /*
     * check for insanity where we are given a bitmap that
     * claims to have more arg content than the length of the
     * radiotap section.  We will normally end up equalling this
     * max_length on the last arg, never exceeding it.
     */

    if ((((void *) iterator->arg) - ((void *) iterator->rtheader)) >
        iterator->max_length)
      return (-EINVAL);

next_entry:

    iterator->arg_index++;
    if (((iterator->arg_index & 31) == 0))
    {
      /* completed current u32 bitmap */
      if (iterator->bitmap_shifter & 1)
      {
        /* b31 was set, there is more */
        /* move to next u32 bitmap */
        iterator->bitmap_shifter = le32_to_cpu (*iterator->next_bitmap);
        iterator->next_bitmap++;
      }
      else
      {
        /* no more bitmaps: end */
        iterator->arg_index = sizeof (rt_sizes);
      }
    }
    else
    {                           /* just try the next bit */
      iterator->bitmap_shifter >>= 1;
    }

    /* if we found a valid arg earlier, return it now */

    if (hit)
      return (iterator->this_arg_index);

  }

  /* we don't know how to handle any more args, we're done */

  return (-1);
}


const unsigned long int crc_tbl_osdep[256] = {
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


#define ARPHRD_IEEE80211        801
#define ARPHRD_IEEE80211_PRISM  802
#define ARPHRD_IEEE80211_FULL   803

#define DEBUG 1

#define MAC_ADDR_SIZE 6


#define IEEE80211_ADDR_LEN      6       /* size of 802.11 address */

#define MAXLINE 4096

struct sendbuf
{
  unsigned int pos;
  unsigned int size;
  char buf[MAXLINE * 2];
};

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
  /* possibly followed by addr4[IEEE80211_ADDR_LEN]; */
  /* see below */
} GNUNET_PACKED;

/**
 * struct for storing the information of the hardware
 */
struct Hardware_Infos
{

  /**
  * send buffer
  */
  struct sendbuf write_pout;
  /**
   * file descriptor for the raw socket
   */
  int fd_raw;

  int arptype_in;

  /**
   * Name of the interface, not necessarily 0-terminated (!).
   */
  char iface[IFNAMSIZ];

  struct MacAddress pl_mac;
};

struct RadioTapheader
{
  struct ieee80211_radiotap_header header;
  u8 rate;
  u8 pad1;
  u16 txflags;
};





/**
 * function to create GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL message for plugin
 * @param buffer pointer to buffer for the message
 * @param mac pointer to the mac address
 * @return number of bytes written
 */
int
send_mac_to_plugin (char *buffer, struct MacAddress *mac)
{

  struct Wlan_Helper_Control_Message macmsg;

  memcpy (&macmsg.mac, (char *) mac, sizeof (struct MacAddress));
  macmsg.hdr.size = htons (sizeof (struct Wlan_Helper_Control_Message));
  macmsg.hdr.type = htons (GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL);

  memcpy (buffer, &macmsg, sizeof (struct Wlan_Helper_Control_Message));
  return sizeof (struct Wlan_Helper_Control_Message);
}



// FIXME: inline?
int
getChannelFromFrequency (int frequency);

// FIXME: make nice...
/**
 * function to calculate the crc, the start of the calculation
 * @param buf buffer to calc the crc
 * @param len len of the buffer
 * @return crc sum
 */
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
/**
 * Function to check crc of the wlan packet
 * @param buf buffer of the packet
 * @param len len of the data
 * @return crc sum of the data
 */
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
/**
 * function to get the channel of a specific wlan card
 * @param dev pointer to the dev struct of the card
 * @return channel number
 */
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
/**
 * function to read from a wlan card
 * @param dev pointer to the struct of the wlan card
 * @param buf buffer to read to
 * @param buf_size size of the buffer
 * @param ri radiotap_rx info
 * @return size read from the buffer
 */
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
 * function to open the device for read/write
 * @param dev pointer to the device struct
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
    fprintf (stderr, "Failed to enable promiscuous mode on interface `%.*s'\n",
             IFNAMSIZ, dev->iface);
    return 1;
  }

  return 0;
}

/**
 * function to prepare the helper, e.g. sockets, device...
 * @param dev struct for the device
 * @param iface name of the interface
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
  if (0 == memcmp (u8aIeeeHeader->i_addr1, &dev->pl_mac, MAC_ADDR_SIZE))
    return 0;
  if (0 == memcmp (u8aIeeeHeader->i_addr1, &bc_all_mac, MAC_ADDR_SIZE))
    return 0;
  return 1;
}


/**
 * function to set the wlan header to make attacks more difficult
 * @param u8aIeeeHeader pointer to the header of the packet
 * @param dev pointer to the Hardware_Infos struct
 */
static void
mac_set (struct ieee80211_frame *u8aIeeeHeader,
         const struct Hardware_Infos *dev)
{
  u8aIeeeHeader->i_fc[0] = 0x08;
  u8aIeeeHeader->i_fc[1] = 0x00;
  memcpy (u8aIeeeHeader->i_addr2, &dev->pl_mac, MAC_ADDR_SIZE);
  memcpy (u8aIeeeHeader->i_addr3, &mac_bssid, MAC_ADDR_SIZE);

}

/**
 * function to process the data from the stdin
 * @param cls pointer to the device struct
 * @param client not used
 * @param hdr pointer to the start of the packet
 */
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
  rtheader.pad1 = 0x00;
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
    fprintf (stderr, "Function stdin_send_hw: malformed packet (too small)\n");
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
/**
 * Function to make test packets with special options
 * @param buf buffer to write the data to
 * @param dev device to send the data from
 * @return size of packet (what should be send)
 */
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
    memcpy (u8aIeeeHeader.i_addr2, &dev->pl_mac, MAC_ADDR_SIZE);
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
 * Function to start the hardware for the wlan helper
 * @param argc number of arguments
 * @param argv arguments
 * @return returns one on error
 */
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
  write_std.size = send_mac_to_plugin ((char *) &write_std.buf, &dev.pl_mac);
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

/**
 * main function of the helper
 * @param argc number of arguments
 * @param argv arguments
 * @return 0 on success, 1 on error
 */
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

/*
   *  Copyright (c) 2008, Thomas d'Otreppe
   *
   *  Common OSdep stuff
   *
   *  This program is free software; you can redistribute it and/or modify
   *  it under the terms of the GNU General Public License as published by
   *  the Free Software Foundation; either version 2 of the License, or
   *  (at your option) any later version.
   *
   *  This program is distributed in the hope that it will be useful,
   *  but WITHOUT ANY WARRANTY; without even the implied warranty of
   *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   *  GNU General Public License for more details.
   *
   *  You should have received a copy of the GNU General Public License
   *  along with this program; if not, write to the Free Software
   *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
   */

/**
 * Return the frequency in Mhz from a channel number
 * @param channel number of the channel
 * @return frequency of the channel
 */
int
getFrequencyFromChannel (int channel)
{
  static int frequencies[] = {
    -1,                         // No channel 0
    2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467,
    2472, 2484,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // Nothing from channel 15 to 34 (exclusive)
    5170, 5175, 5180, 5185, 5190, 5195, 5200, 5205, 5210, 5215, 5220, 5225,
    5230, 5235, 5240, 5245,
    5250, 5255, 5260, 5265, 5270, 5275, 5280, 5285, 5290, 5295, 5300, 5305,
    5310, 5315, 5320, 5325,
    5330, 5335, 5340, 5345, 5350, 5355, 5360, 5365, 5370, 5375, 5380, 5385,
    5390, 5395, 5400, 5405,
    5410, 5415, 5420, 5425, 5430, 5435, 5440, 5445, 5450, 5455, 5460, 5465,
    5470, 5475, 5480, 5485,
    5490, 5495, 5500, 5505, 5510, 5515, 5520, 5525, 5530, 5535, 5540, 5545,
    5550, 5555, 5560, 5565,
    5570, 5575, 5580, 5585, 5590, 5595, 5600, 5605, 5610, 5615, 5620, 5625,
    5630, 5635, 5640, 5645,
    5650, 5655, 5660, 5665, 5670, 5675, 5680, 5685, 5690, 5695, 5700, 5705,
    5710, 5715, 5720, 5725,
    5730, 5735, 5740, 5745, 5750, 5755, 5760, 5765, 5770, 5775, 5780, 5785,
    5790, 5795, 5800, 5805,
    5810, 5815, 5820, 5825, 5830, 5835, 5840, 5845, 5850, 5855, 5860, 5865,
    5870, 5875, 5880, 5885,
    5890, 5895, 5900, 5905, 5910, 5915, 5920, 5925, 5930, 5935, 5940, 5945,
    5950, 5955, 5960, 5965,
    5970, 5975, 5980, 5985, 5990, 5995, 6000, 6005, 6010, 6015, 6020, 6025,
    6030, 6035, 6040, 6045,
    6050, 6055, 6060, 6065, 6070, 6075, 6080, 6085, 6090, 6095, 6100
  };

  return ((channel > 0) &&
          (channel <
           sizeof (frequencies) / sizeof (int))) ? frequencies[channel] : -1;
}

/**
 * Return the channel from the frequency (in Mhz)
 * @param frequency of the channel
 * @return number of the channel
 */
int
getChannelFromFrequency (int frequency)
{
  if (frequency >= 2412 && frequency <= 2472)
    return (frequency - 2407) / 5;
  else if (frequency == 2484)
    return 14;
  else if (frequency >= 5000 && frequency <= 6100)
    return (frequency - 5000) / 5;
  else
    return -1;
}
