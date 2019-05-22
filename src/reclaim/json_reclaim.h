/*
   This file is part of GNUnet.
   Copyright (C) 2009-2018 GNUnet e.V.

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
 * @file rest-plugins/json_reclaim.h
 * @brief JSON handling of reclaim data
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_json_lib.h"
#include "gnunet_reclaim_service.h"
#include "gnunet_reclaim_attribute_lib.h"

/**
 * JSON Specification for Reclaim claims.
 *
 * @param ticket struct of GNUNET_RECLAIM_ATTRIBUTE_Claim to fill
 * @return JSON Specification
 */
struct GNUNET_JSON_Specification
GNUNET_RECLAIM_JSON_spec_claim (struct GNUNET_RECLAIM_ATTRIBUTE_Claim **attr);

/**
 * JSON Specification for Reclaim tickets.
 *
 * @param ticket struct of GNUNET_RECLAIM_Ticket to fill
 * @return JSON Specification
 */
struct GNUNET_JSON_Specification
GNUNET_RECLAIM_JSON_spec_ticket (struct GNUNET_RECLAIM_Ticket **ticket);
