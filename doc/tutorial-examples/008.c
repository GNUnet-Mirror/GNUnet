static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
}

static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *c,
                   struct GNUNET_MQ_Handle *mq)
{
  return c;
}

static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *c,
                      void *internal_cls)
{
  GNUNET_assert (c == internal_cls);
}
