/*
   This file is part of GNUnet.
   Copyright (C) 2016 GNUnet e.V.

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
 * @file conversation/gnunet_gst.c
 * @brief FIXME
 * @author Hark
 */

// which audiobackend we use
//

/*
   int audiobackend = JACK;
   int dropsilence = TRUE;
   int enough = 0;
   int usertp = TRUE;
 */

#define gst_element_factory_make(element, name) gst_element_factory_make_debug ( \
    element, name);

extern void pl_graph ();


extern GstElement *
gst_element_factory_make_debug (gchar *, gchar *);

extern GstBin *
get_audiobin (GNUNET_gstData *, int);

extern GstBin *
get_coder (GNUNET_gstData *, int);


extern gboolean
gnunet_gst_bus_call (GstBus *bus, GstMessage *msg, gpointer data);

extern void
gg_setup_gst_bus (GNUNET_gstData *d);

extern void
gg_load_configuration (GNUNET_gstData *d);

extern GstFlowReturn
on_appsink_new_sample (GstElement *, GNUNET_gstData *);
