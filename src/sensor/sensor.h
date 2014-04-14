/*
      This file is part of GNUnet
      (C) 2012-2013 Christian Grothoff (and other contributing authors)

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
 * @file sensor/sensor.h
 * @brief example IPC messages between SENSOR API and GNS service
 * @author Omar Tarabai
 */

#include "gnunet_sensor_service.h"


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Carries a summary of a sensor
 *
 */
struct SensorInfoMessage
{
  /**
   * Message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * Length of sensor name (name follows the struct)
   */
  size_t name_len;

  /**
   * First part of version number
   */
  uint16_t version_major;

  /**
   * Second part of version number
   */
  uint16_t version_minor;

  /**
   * Length of sensor description (description itself follows)
   */
  size_t description_len;
};

GNUNET_NETWORK_STRUCT_END
