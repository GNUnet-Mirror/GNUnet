struct GNUNET_MQ_MessageHandlers handlers[] = {
    // ...
  GNUNET_MQ_handler_end ()
};
struct GNUNET_MQ_Handle *mq;

mq = GNUNET_CLIENT_connect (cfg,
                            "service-name",
                            handlers,
                            &error_cb,
                            NULL);
