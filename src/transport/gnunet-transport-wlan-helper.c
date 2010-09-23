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
 * @file src/transport/gnunet-wlan.c
 * @brief wlan layer two server; must run as root (SUID will do)
 *        This code will work under GNU/Linux only.
 * @author David Brodski
 *
 * This program serves as the mediator between the wlan interface and
 * gnunet
 */
#include "gnunet-transport-wlan-helper.h"
#include "plugin_transport_wlan.h"
#include "ieee80211_radiotap.h"

#include <pcap.h>

//#include "radiotap.h"

// broadcast mac
static const char macbc[] = "13223344";

// mac of this node
char mac[] = "13223355";

/* wifi bitrate to use in 500kHz units */

static const u8 u8aRatesToUse[] = {

	54*2,
	48*2,
	36*2,
	24*2,
	18*2,
	12*2,
	9*2,
	11*2,
	11, // 5.5
	2*2,
	1*2
};

#define	OFFSET_FLAGS 0x10
#define	OFFSET_RATE 0x11

// this is where we store a summary of the
// information from the radiotap header

typedef struct  {
	int m_nChannel;
	int m_nChannelFlags;
	int m_nRate;
	int m_nAntenna;
	int m_nRadiotapFlags;
} __attribute__((packed)) PENUMBRA_RADIOTAP_DATA;

void
Dump(u8 * pu8, int nLength)
{
	char sz[256], szBuf[512], szChar[17], *buf, fFirst = 1;
	unsigned char baaLast[2][16];
	uint n, nPos = 0, nStart = 0, nLine = 0, nSameCount = 0;

	buf = szBuf;
	szChar[0] = '\0';

	for (n = 0; n < nLength; n++) {
		baaLast[(nLine&1)^1][n&0xf] = pu8[n];
		if ((pu8[n] < 32) || (pu8[n] >= 0x7f))
			szChar[n&0xf] = '.';
		else
			szChar[n&0xf] = pu8[n];
		szChar[(n&0xf)+1] = '\0';
		nPos += sprintf(&sz[nPos], "%02X ",
			baaLast[(nLine&1)^1][n&0xf]);
		if ((n&15) != 15)
			continue;
		if ((memcmp(baaLast[0], baaLast[1], 16) == 0) && (!fFirst)) {
			nSameCount++;
		} else {
			if (nSameCount)
				buf += sprintf(buf, "(repeated %d times)\n",
					nSameCount);
			buf += sprintf(buf, "%04x: %s %s\n",
				nStart, sz, szChar);
			nSameCount = 0;
			printf("%s", szBuf);
			buf = szBuf;
		}
		nPos = 0; nStart = n+1; nLine++;
		fFirst = 0; sz[0] = '\0'; szChar[0] = '\0';
	}
	if (nSameCount)
		buf += sprintf(buf, "(repeated %d times)\n", nSameCount);

	buf += sprintf(buf, "%04x: %s", nStart, sz);
	if (n & 0xf) {
		*buf++ = ' ';
		while (n & 0xf) {
			buf += sprintf(buf, "   ");
			n++;
		}
	}
	buf += sprintf(buf, "%s\n", szChar);
	printf("%s", szBuf);
}


void
usage(void)
{
	printf(
	    "Usage: wlan-hwd [options] <interface>\n\nOptions\n"
	    "-f/--fcs           Mark as having FCS (CRC) already\n"
	    "                   (pkt ends with 4 x sacrificial - chars)\n"
	    "Example:\n"
	    "  echo -n mon0 > /sys/class/ieee80211/phy0/add_iface\n"
	    "  iwconfig mon0 mode monitor\n"
	    "  ifconfig mon0 up\n"
	    "  wlan-hwd mon0        Spam down mon0 with\n"
	    "                       radiotap header first\n"
	    "\n");
	exit(1);
}

int flagHelp = 0, flagMarkWithFCS = 0;
int flagVerbose = 0;


/*
 * Radiotap parser
 *
 * Copyright 2007		Andy Green <andy@warmcat.com>
 */

/**
 * ieee80211_radiotap_iterator_init - radiotap parser iterator initialization
 * @param iterator: radiotap_iterator to initialize
 * @param radiotap_header: radiotap header to parse
 * @param max_length: total length we can parse into (eg, whole packet length)
 *
 * @return 0 or a negative error code if there is a problem.
 *
 * This function initializes an opaque iterator struct which can then
 * be passed to ieee80211_radiotap_iterator_next() to visit every radiotap
 * argument which is present in the header.  It knows about extended
 * present headers and handles them.
 *
 * How to use:
 * call __ieee80211_radiotap_iterator_init() to init a semi-opaque iterator
 * struct ieee80211_radiotap_iterator (no need to init the struct beforehand)
 * checking for a good 0 return code.  Then loop calling
 * __ieee80211_radiotap_iterator_next()... it returns either 0,
 * -ENOENT if there are no more args to parse, or -EINVAL if there is a problem.
 * The iterator's this_arg member points to the start of the argument
 * associated with the current argument index that is present, which can be
 * found in the iterator's this_arg_index member.  This arg index corresponds
 * to the IEEE80211_RADIOTAP_... defines.
 *
 * Radiotap header length:
 * You can find the CPU-endian total radiotap header length in
 * iterator->max_length after executing ieee80211_radiotap_iterator_init()
 * successfully.
 *
 * Example code:
 * See Documentation/networking/radiotap-headers.txt
 */

int ieee80211_radiotap_iterator_init(
    struct ieee80211_radiotap_iterator *iterator,
    struct ieee80211_radiotap_header *radiotap_header,
    int max_length)
{
	/* Linux only supports version 0 radiotap format */
	if (radiotap_header->it_version)
		return -EINVAL;

	/* sanity check for allowed length and radiotap length field */
	if (max_length < le16_to_cpu(radiotap_header->it_len))
		return -EINVAL;

	iterator->rtheader = radiotap_header;
	iterator->max_length = le16_to_cpu(radiotap_header->it_len);
	iterator->arg_index = 0;
	iterator->bitmap_shifter = le32_to_cpu(radiotap_header->it_present);
	iterator->arg = (u8 *)radiotap_header + sizeof(*radiotap_header);
	iterator->this_arg = 0;

	/* find payload start allowing for extended bitmap(s) */

	if (unlikely(iterator->bitmap_shifter & (1<<IEEE80211_RADIOTAP_EXT))) {
		while (le32_to_cpu(*((u32 *)iterator->arg)) &
				   (1<<IEEE80211_RADIOTAP_EXT)) {
			iterator->arg += sizeof(u32);

			/*
			 * check for insanity where the present bitmaps
			 * keep claiming to extend up to or even beyond the
			 * stated radiotap header length
			 */

			if (((ulong)iterator->arg -
			     (ulong)iterator->rtheader) > iterator->max_length)
				return -EINVAL;
		}

		iterator->arg += sizeof(u32);

		/*
		 * no need to check again for blowing past stated radiotap
		 * header length, because ieee80211_radiotap_iterator_next
		 * checks it before it is dereferenced
		 */
	}

	/* we are all initialized happily */

	return 0;
}


/**
 * ieee80211_radiotap_iterator_next - return next radiotap parser iterator arg
 * @param iterator: radiotap_iterator to move to next arg (if any)
 *
 * @return 0 if there is an argument to handle,
 * -ENOENT if there are no more args or -EINVAL
 * if there is something else wrong.
 *
 * This function provides the next radiotap arg index (IEEE80211_RADIOTAP_*)
 * in this_arg_index and sets this_arg to point to the
 * payload for the field.  It takes care of alignment handling and extended
 * present fields.  this_arg can be changed by the caller (eg,
 * incremented to move inside a compound argument like
 * IEEE80211_RADIOTAP_CHANNEL).  The args pointed to are in
 * little-endian format whatever the endianess of your CPU.
 */

int ieee80211_radiotap_iterator_next(
    struct ieee80211_radiotap_iterator *iterator)
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
		[IEEE80211_RADIOTAP_DB_ANTNOISE] = 0x11
		/*
		 * add more here as they are defined in
		 * include/net/ieee80211_radiotap.h
		 */
	};

	/*
	 * for every radiotap entry we can at
	 * least skip (by knowing the length)...
	 */

	while (iterator->arg_index < sizeof(rt_sizes)) {
		int hit = 0;
		int pad;

		if (!(iterator->bitmap_shifter & 1))
			goto next_entry; /* arg not present */

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

		pad = (((ulong)iterator->arg) -
			((ulong)iterator->rtheader)) &
			((rt_sizes[iterator->arg_index] >> 4) - 1);

		if (pad)
			iterator->arg_index +=
				(rt_sizes[iterator->arg_index] >> 4) - pad;

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

		if (((ulong)iterator->arg - (ulong)iterator->rtheader) >
		    iterator->max_length)
			return -EINVAL;

	next_entry:
		iterator->arg_index++;
		if (unlikely((iterator->arg_index & 31) == 0)) {
			/* completed current u32 bitmap */
			if (iterator->bitmap_shifter & 1) {
				/* b31 was set, there is more */
				/* move to next u32 bitmap */
				iterator->bitmap_shifter =
				    le32_to_cpu(*iterator->next_bitmap);
				iterator->next_bitmap++;
			} else {
				/* no more bitmaps: end */
				iterator->arg_index = sizeof(rt_sizes);
			}
		} else { /* just try the next bit */
			iterator->bitmap_shifter >>= 1;
		}

		/* if we found a valid arg earlier, return it now */
		if (hit)
			return 0;
	}

	/* we don't know how to handle any more args, we're done */
	return -ENOENT;
}



int
main(int argc, char *argv[])
{
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

	if (gethostname(szHostname, sizeof (szHostname) - 1)) {
		perror("unable to get hostname");
	}
	szHostname[sizeof (szHostname) - 1] = '\0';


	printf("Packetspammer (c)2007 Andy Green <andy@warmcat.com>  GPL2\n");

	while (1) {
		int nOptionIndex;
		static const struct option optiona[] = {
			{ "delay", required_argument, NULL, 'd' },
			{ "fcs", no_argument, &flagMarkWithFCS, 1 },
			{ "help", no_argument, &flagHelp, 1 },
			{ "verbose", no_argument, &flagVerbose, 1},
			{ 0, 0, 0, 0 }
		};
		int c = getopt_long(argc, argv, "d:hf",
			optiona, &nOptionIndex);

		if (c == -1)
			break;
		switch (c) {
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
	if (ppcap == NULL) {
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

	switch (nLinkEncap) {

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

	if (pcap_compile(ppcap, &bpfprogram, szProgram, 1, 0) == -1) {
		puts(szProgram);
		puts(pcap_geterr(ppcap));
		return (1);
	} else {
		if (pcap_setfilter(ppcap, &bpfprogram) == -1) {
			puts(szProgram);
			puts(pcap_geterr(ppcap));
		} else {
			printf("RX Filter applied\n");
		}
		pcap_freecode(&bpfprogram);
	}

	pcap_setnonblock(ppcap, 1, szErrbuf);

	printf("   (delay between packets %dus)\n", nDelay);

	memset(u8aSendBuffer, 0, sizeof (u8aSendBuffer));

	while (!fBrokenSocket) {
		u8 * pu8 = u8aSendBuffer;
		struct pcap_pkthdr * ppcapPacketHeader = NULL;
		struct ieee80211_radiotap_iterator rti;
		PENUMBRA_RADIOTAP_DATA prd;
		u8 * pu8Payload = u8aSendBuffer;
		int n, nRate;

		// receive

		retval = pcap_next_ex(ppcap, &ppcapPacketHeader,
		    (const u_char**)&pu8Payload);

		if (retval < 0) {
			fBrokenSocket = 1;
			continue;
		}

		if (retval != 1)
			goto do_tx;

		u16HeaderLen = (pu8Payload[2] + (pu8Payload[3] << 8));

		printf("rtap: ");
		Dump(pu8Payload, u16HeaderLen);

		if (ppcapPacketHeader->len <
		    (u16HeaderLen + n80211HeaderLength))
			continue;

		bytes = ppcapPacketHeader->len -
			(u16HeaderLen + n80211HeaderLength);
		if (bytes < 0)
			continue;

		if (ieee80211_radiotap_iterator_init(&rti,
		    (struct ieee80211_radiotap_header *)pu8Payload,
		    bytes) < 0)
			continue;

		while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {

			switch (rti.this_arg_index) {
			case IEEE80211_RADIOTAP_RATE:
				prd.m_nRate = (*rti.this_arg);
				break;

			case IEEE80211_RADIOTAP_CHANNEL:
				prd.m_nChannel =
				    le16_to_cpu(*((u16 *)rti.this_arg));
				prd.m_nChannelFlags =
				    le16_to_cpu(*((u16 *)(rti.this_arg + 2)));
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
		    "Ant: %d, Flags: 0x%X\n",
		    prd.m_nRate / 2, 5 * (prd.m_nRate & 1),
		    prd.m_nChannel / 1000,
		    prd.m_nChannel - ((prd.m_nChannel / 1000) * 1000),
		    prd.m_nAntenna,
		    prd.m_nRadiotapFlags);

		Dump(pu8Payload, bytes);

	do_tx:

		// transmit

		memcpy(u8aSendBuffer, u8aRadiotapHeader,
			sizeof (u8aRadiotapHeader));
		if (flagMarkWithFCS)
			pu8[OFFSET_FLAGS] |= IEEE80211_RADIOTAP_F_FCS;
		nRate = pu8[OFFSET_RATE] = u8aRatesToUse[nRateIndex++];
		if (nRateIndex >= sizeof (u8aRatesToUse))
			nRateIndex = 0;
		pu8 += sizeof (u8aRadiotapHeader);

		memcpy(pu8, u8aIeeeHeader, sizeof (u8aIeeeHeader));
		pu8 += sizeof (u8aIeeeHeader);

		pu8 += sprintf((char *)u8aSendBuffer,
		    "Packetspammer %02d"
		    "broadcast packet"
		    "#%05d -- :-D --%s ----",
		    nRate/2, nOrdinal++, szHostname);
		r = pcap_inject(ppcap, u8aSendBuffer, pu8 - u8aSendBuffer);
		if (r != (pu8-u8aSendBuffer)) {
			perror("Trouble injecting packet");
			return (1);
		}
		if (nDelay)
			usleep(nDelay);
	}



	return (0);
}
