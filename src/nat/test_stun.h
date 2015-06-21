/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2015 Christian Grothoff (and other contributing authors)

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
 * Testcase for STUN server resolution
 *
 * @file nat/test_stun.h
 * @brief Testcase for STUN library
 * @author Bruno Souza Cabral
 * @autor Mark Spencer (Original code borrowed from Asterisk)
 *
 */

#define PACKAGE		"gnunet"
#define VERSION_PACKAGE		"0.4"

#define STUN_SERVER	"stun.services.mozilla.com"
#define STUN_PORT	3478
#define STUN_COUNT	3
#define STUN_RTO	500 /* ms */
#define STUN_MRC	3

typedef struct { unsigned int id[3]; } __attribute__((packed)) stun_trans_id;

struct stun_header {
	unsigned short msgtype;
	unsigned short msglen;
	unsigned int magic;
	stun_trans_id  id;
	unsigned char  ies[0];
} __attribute__((packed));

struct stun_attr {
	unsigned short attr;
	unsigned short len;
	unsigned char  value[0];
} __attribute__((packed));

/*
 * The format normally used for addresses carried by STUN messages.
 */
struct stun_addr {
	unsigned char  unused;
	unsigned char  family;
	unsigned short port;
	unsigned int   addr;
} __attribute__((packed));

#define STUN_IGNORE		(0)
#define STUN_ACCEPT		(1)

#define STUN_MAGIC_COOKIE	0x2112A442

/* STUN message classes */
#define STUN_REQUEST		0x0000
#define STUN_INDICATION		0x0001
#define STUN_RESPONSE		0x0002
#define STUN_ERROR_RESPONSE	0x0003

/* STUN message methods */
#define STUN_BINDING		0x0001
#define STUN_SHARED_SECRET	0x0002
#define STUN_ALLOCATE		0x0003
#define STUN_REFRESH		0x0004
#define STUN_SEND		0x0006
#define STUN_DATA		0x0007
#define STUN_CREATE_PERMISSION	0x0008
#define STUN_CHANNEL_BIND	0x0009

/* Basic attribute types in stun messages.
 * Messages can also contain custom attributes (codes above 0x7fff)
 */
#define STUN_MAPPED_ADDRESS	0x0001
#define STUN_RESPONSE_ADDRESS	0x0002
#define STUN_CHANGE_ADDRESS	0x0003
#define STUN_SOURCE_ADDRESS	0x0004
#define STUN_CHANGED_ADDRESS	0x0005
#define STUN_USERNAME		0x0006
#define STUN_PASSWORD		0x0007
#define STUN_MESSAGE_INTEGRITY	0x0008
#define STUN_ERROR_CODE		0x0009
#define STUN_UNKNOWN_ATTRIBUTES	0x000a
#define STUN_REFLECTED_FROM	0x000b
#define STUN_REALM		0x0014
#define STUN_NONCE		0x0015
#define STUN_XOR_MAPPED_ADDRESS	0x0020
#define STUN_MS_VERSION		0x8008
#define STUN_MS_XOR_MAPPED_ADDRESS 0x8020
#define STUN_SOFTWARE		0x8022
#define STUN_ALTERNATE_SERVER	0x8023
#define STUN_FINGERPRINT	0x8028
