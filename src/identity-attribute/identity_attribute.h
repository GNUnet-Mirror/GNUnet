/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

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
 * @author Martin Schanzenbach
 * @file identity-provider/identity_attribute.h
 * @brief GNUnet Identity Provider library
 *
 */
#ifndef IDENTITY_ATTRIBUTE_H
#define IDENTITY_ATTRIBUTE_H

#include "gnunet_identity_provider_service.h"

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
