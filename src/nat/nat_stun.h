/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2015 GNUnet e.V.

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
/**
 * Message types for STUN server resolution
 *
 * @file nat/nat_stun.h
 * @brief Testcase for STUN library
 * @author Bruno Souza Cabral
 * @autor Mark Spencer (Original code borrowed from Asterisk)
 * @author Christian Grothoff
 */


#define STUN_IGNORE		(0)
#define STUN_ACCEPT		(1)

#define STUN_MAGIC_COOKIE	0x2112A442

typedef struct {
  uint32_t id[3];
} GNUNET_PACKED stun_trans_id;


struct stun_header
{
  uint16_t msgtype;
  uint16_t msglen;
  uint32_t magic;
  stun_trans_id id;
} GNUNET_PACKED;


struct stun_attr
{
  uint16_t attr;
  uint16_t len;
} GNUNET_PACKED;


/**
 * The format normally used for addresses carried by STUN messages.
 */
struct stun_addr
{
  uint8_t  unused;

  /**
   * Address family, we expect AF_INET.
   */
  uint8_t  family;

  /**
   * Port number.
   */
  uint16_t port;
  
  /**
   * IPv4 address. Should this be "struct in_addr"?
   */
  uint32_t   addr;
} GNUNET_PACKED;


/**
 * STUN message classes 
 */
enum StunClasses {
  INVALID_CLASS = 0,
  STUN_REQUEST = 0x0000,
  STUN_INDICATION = 0x0001,
  STUN_RESPONSE = 0x0002,
  STUN_ERROR_RESPONSE = 0x0003
};

enum StunMethods {
  INVALID_METHOD = 0,
  STUN_BINDING = 0x0001,
  STUN_SHARED_SECRET = 0x0002,
  STUN_ALLOCATE = 0x0003,
  STUN_REFRESH = 0x0004,
  STUN_SEND = 0x0006,
  STUN_DATA = 0x0007,
  STUN_CREATE_PERMISSION = 0x0008,
  STUN_CHANNEL_BIND = 0x0009
};


/**
 * Basic attribute types in stun messages.
 * Messages can also contain custom attributes (codes above 0x7fff)
 */
enum StunAttributes {
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
};


/**
 * Convert a message to a StunClass
 *
 * @param msg the received message
 * @return the converted StunClass
 */
static int
decode_class(int msg)
{
  /* Sorry for the magic, but this maps the class according to rfc5245 */
  return ((msg & 0x0010) >> 4) | ((msg & 0x0100) >> 7);
}

/**
 * Convert a message to a StunMethod
 *
 * @param msg the received message
 * @return the converted StunMethod
 */
static int
decode_method(int msg)
{
  return (msg & 0x000f) | ((msg & 0x00e0) >> 1) | ((msg & 0x3e00) >> 2);
}


/**
 * Print a class and method from a STUN message
 *
 * @param msg
 * @return string with the message class and method
 */
static const char *
stun_msg2str (int msg)
{
  static const struct {
    enum StunClasses value;
    const char *name;
  } classes[] = {
    { STUN_REQUEST, "Request" },
    { STUN_INDICATION, "Indication" },
    { STUN_RESPONSE, "Response" },
    { STUN_ERROR_RESPONSE, "Error Response" },
    { 0, NULL }
  };
  static const struct {
    enum StunMethods value;
    const char *name;
  } methods[] = {
    { STUN_BINDING, "Binding" },
    { 0, NULL }
  };
  static char result[64];
  const char *msg_class = NULL;
  const char *method = NULL;
  int value;

  value = decode_class (msg);
  for (unsigned int i = 0; classes[i].name; i++)
    if (classes[i].value == value)
    {
      msg_class = classes[i].name;
      break;
    }
  value = decode_method (msg);
  for (unsigned int i = 0; methods[i].name; i++)
    if (methods[i].value == value)
    {
      method = methods[i].name;
      break;
    }
  GNUNET_snprintf (result,
                   sizeof(result),
                   "%s %s",
                   method ? : "Unknown Method",
                   msg_class ? : "Unknown Class Message");
  return result;
}


/**
 * Print attribute name
 *
 * @param msg with a attribute type
 * @return string with the attribute name
 */
static const char *
stun_attr2str (enum StunAttributes msg)
{
  static const struct {
    enum StunAttributes value;
    const char *name;
  } attrs[] = {
    { STUN_MAPPED_ADDRESS, "Mapped Address" },
    { STUN_RESPONSE_ADDRESS, "Response Address" },
    { STUN_CHANGE_ADDRESS, "Change Address" },
    { STUN_SOURCE_ADDRESS, "Source Address" },
    { STUN_CHANGED_ADDRESS, "Changed Address" },
    { STUN_USERNAME, "Username" },
    { STUN_PASSWORD, "Password" },
    { STUN_MESSAGE_INTEGRITY, "Message Integrity" },
    { STUN_ERROR_CODE, "Error Code" },
    { STUN_UNKNOWN_ATTRIBUTES, "Unknown Attributes" },
    { STUN_REFLECTED_FROM, "Reflected From" },
    { STUN_REALM, "Realm" },
    { STUN_NONCE, "Nonce" },
    { STUN_XOR_MAPPED_ADDRESS, "XOR Mapped Address" },
    { STUN_MS_VERSION, "MS Version" },
    { STUN_MS_XOR_MAPPED_ADDRESS, "MS XOR Mapped Address" },
    { STUN_SOFTWARE, "Software" },
    { STUN_ALTERNATE_SERVER, "Alternate Server" },
    { STUN_FINGERPRINT, "Fingerprint" },
    { 0, NULL }
  };

  for (unsigned int i = 0; attrs[i].name; i++)
    if (attrs[i].value == msg)
      return attrs[i].name;
  return "Unknown Attribute";
}


/* end of nat_stun.h */
