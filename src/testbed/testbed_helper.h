/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_helper.h
 * @brief Message formats for communication between testbed api and
 *          gnunet-helper-testbed process
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#ifndef TESTBED_HELPER_H
#define TESTBED_HELPER_H

GNUNET_NETWORK_STRUCT_BEGIN
/**
 * Initialization message for gnunet-helper-testbed to start testbed service
 */
    struct GNUNET_TESTBED_HelperInit
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_HELPER_INIT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The controller hostname size excluding the NULL termination character -
   * strlen (hostname); cannot be zero
   */
  uint16_t trusted_ip_size GNUNET_PACKED;

  /**
   * The hostname size excluding the NULL termination character - strlen
   * (hostname); cannot be zero
   */
  uint16_t hostname_size GNUNET_PACKED;

  /**
   * The size of the uncompressed configuration
   */
  uint16_t config_size GNUNET_PACKED;

  /* Followed by NULL terminated trusted ip */

  /* Followed by hostname of the machine on which helper runs. This is not NULL
   * terminated */

  /* Followed by serialized and compressed configuration which should be
   * config_size long when un-compressed */
};

/**
 * Reply message from helper process
 */
struct GNUNET_TESTBED_HelperReply
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_HELPER_REPLY
   */
  struct GNUNET_MessageHeader header;

  /**
   * Size of the uncompressed configuration
   */
  uint16_t config_size GNUNET_PACKED;

  /* Followed by compressed configuration which should be config_size long when
   * un-compressed */
};

GNUNET_NETWORK_STRUCT_END
#endif
/* end of testbed_helper.h */
