// which audiobackend we use
//

/*
int audiobackend = JACK;
int dropsilence = TRUE;
int enough = 0;
int usertp = TRUE;
*/

#define gst_element_factory_make(element, name) gst_element_factory_make_debug (element, name);

extern void pl_graph();


extern GstElement *
 gst_element_factory_make_debug( gchar *, gchar *);

extern GstBin *
  get_audiobin(GNUNET_gstData *, int);

extern GstBin *
  get_coder(GNUNET_gstData *, int);


extern gboolean
gnunet_gst_bus_call (GstBus *bus, GstMessage *msg, gpointer data);

extern void
gg_setup_gst_bus (GNUNET_gstData * d);

extern void
gg_load_configuration (GNUNET_gstData * d);

extern GstFlowReturn
on_appsink_new_sample (GstElement *, GNUNET_gstData *);

