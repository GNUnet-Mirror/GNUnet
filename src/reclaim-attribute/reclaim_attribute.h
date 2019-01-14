/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

   GNUnet is free software: you can redistribute it and/or modify it
   under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License,
   or (at your option) any later version.

   GNUnet is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Affero General Public License for more details.
  
   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
   */
/**
 * @author Martin Schanzenbach
 * @file reclaim-attribute/reclaim_attribute.h
 * @brief GNUnet reclaim identity attributes
 *
 */
#ifndef RECLAIM_ATTRIBUTE_H
#define RECLAIM_ATTRIBUTE_H

#include "gnunet_reclaim_service.h"

struct Attribute
{
  /**
   * Attribute type
   */
  uint32_t attribute_type;

  /**
   * Attribute version
   */
  uint32_t attribute_version;

  /**
   * Name length
   */
  uint32_t name_len;
  
  /**
   * Data size
   */
  uint32_t data_size;

  //followed by data_size Attribute value data
};

#endif
