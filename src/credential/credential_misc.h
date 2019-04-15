/*
      This file is part of GNUnet
      Copyright (C) 2012-2013 GNUnet e.V.

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
 * @file credential/credential_misc.h
 * @brief Credential helper functions
 */
#ifndef CREDENTIAL_MISC_H
#define CREDENTIAL_MISC_H

#include "gnunet_credential_service.h"

char *
GNUNET_CREDENTIAL_credential_to_string (
    const struct GNUNET_CREDENTIAL_Credential *cred);

struct GNUNET_CREDENTIAL_Credential *
GNUNET_CREDENTIAL_credential_from_string (const char *str);

#endif
