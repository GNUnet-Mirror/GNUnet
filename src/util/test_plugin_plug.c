/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
 * @file util/test_plugin_plug.c
 * @brief plugin for testing
 */
#include "platform.h"

void *
libgnunet_plugin_test_init (void *arg)
{
  if (0 == strcmp (arg, "in"))
    return "Hello";
  return NULL;
}

void *
libgnunet_plugin_test_done (void *arg)
{
  if (0 == strcmp (arg, "out"))
    return strdup ("World");
  return NULL;
}

/* end of test_plugin_plug.c */
