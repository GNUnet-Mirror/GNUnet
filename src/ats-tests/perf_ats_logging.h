/*
 This file is part of GNUnet.
 (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file ats/perf_ats_logging.c
 * @brief ats benchmark: logging for performance tests
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"

void
perf_logging_stop ()
{
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      _("Start logging\n"));
}

void
perf_logging_start ()
{
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      _("Start logging\n"));
}

/* end of file perf_ats_logging.c */
