/*
      This file is part of GNUnet
      Copyright (C) 2012-2013 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.
 */
/**
 * @file credential/credential_misc.h
 * @brief Credential helper functions
 */
#ifndef CREDENTIAL_MISC_H
#define CREDENTIAL_MISC_H



char*
GNUNET_CREDENTIAL_credential_to_string (const struct GNUNET_CREDENTIAL_Credential *cred);

struct GNUNET_CREDENTIAL_Credential*
GNUNET_CREDENTIAL_credential_from_string (const char* str);

#endif
