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

#define STUN_SERVER	"stun.ekiga.net"
#define STUN_PORT	3478
#define STUN_IGNORE		(0)
#define STUN_ACCEPT		(1)

#define STUN_MAGIC_COOKIE	0x2112A442

typedef struct { uint32_t id[3]; } GNUNET_PACKED stun_trans_id;

struct stun_header {
    uint16_t msgtype;
    uint16_t msglen;
    uint32_t magic;
	stun_trans_id  id;

} GNUNET_PACKED;

struct stun_attr {
    uint16_t attr;
    uint16_t len;

} GNUNET_PACKED;

/*
 * The format normally used for addresses carried by STUN messages.
 */
struct stun_addr {
    uint8_t  unused;
    uint8_t  family;
    uint16_t port;
    uint32_t   addr;
} GNUNET_PACKED;



/* STUN message classes */
typedef enum StunClasses {
    INVALID_CLASS = 0,
    STUN_REQUEST = 0x0000,
    STUN_INDICATION = 0x0001,
    STUN_RESPONSE = 0x0002,
    STUN_ERROR_RESPONSE = 0x0003
} StunClasses;

typedef enum StunMethods {
    INVALID_METHOD = 0,
    STUN_BINDING = 0x0001,
    STUN_SHARED_SECRET = 0x0002,
    STUN_ALLOCATE = 0x0003,
    STUN_REFRESH = 0x0004,
    STUN_SEND = 0x0006,
    STUN_DATA = 0x0007,
    STUN_CREATE_PERMISSION = 0x0008,
    STUN_CHANNEL_BIND = 0x0009
} StunMethods;

/* Basic attribute types in stun messages.
 * Messages can also contain custom attributes (codes above 0x7fff)
 */

typedef enum StunAttributes {
    STUN_MAPPED_ADDRESS = 0x0001,
    STUN_RESPONSE_ADDRESS = 0x0002,
    STUN_CHANGE_ADDRESS = 0x0003,
    STUN_SOURCE_ADDRESS = 0x0004,
    STUN_CHANGED_ADDRESS = 0x0005,
    STUN_USERNAME = 0x0006,
    STUN_PASSWORD = 0x0007,
    STUN_MESSAGE_INTEGRITY = 0x0008,
    STUN_ERROR_CODE = 0x0009,
    STUN_UNKNOWN_ATTRIBUTES = 0x000a,
    STUN_REFLECTED_FROM = 0x000b,
    STUN_REALM = 0x0014,
    STUN_NONCE = 0x0015,
    STUN_XOR_MAPPED_ADDRESS = 0x0020,
    STUN_MS_VERSION = 0x8008,
    STUN_MS_XOR_MAPPED_ADDRESS = 0x8020,
    STUN_SOFTWARE = 0x8022,
    STUN_ALTERNATE_SERVER = 0x8023,
    STUN_FINGERPRINT = 0x8028
} StunAttributes;

