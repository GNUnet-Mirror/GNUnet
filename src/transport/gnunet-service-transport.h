/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport.h
 * @brief globals
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_H
#define GNUNET_SERVICE_TRANSPORT_H

#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_util_lib.h"

#define VERBOSE_VALIDATION GNUNET_YES

/**
 * Statistics handle.
 */
extern struct GNUNET_STATISTICS_Handle *GST_stats;

/**
 * Configuration handle.
 */
extern const struct GNUNET_CONFIGURATION_Handle *GST_cfg;

/**
 * Configuration handle.
 */
extern struct GNUNET_PeerIdentity GST_my_identity;

/**
 * Handle to peerinfo service.
 */
extern struct GNUNET_PEERINFO_Handle *GST_peerinfo;

/**
 * Our public key.
 */
extern struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded GST_my_public_key;

/**
 * Our private key.
 */
extern struct GNUNET_CRYPTO_RsaPrivateKey *GST_my_private_key;

/**
 * ATS handle.
 */
extern struct GNUNET_ATS_SchedulingHandle *GST_ats;


#endif
/* end of file gnunet-service-transport_plugins.h */
