struct GNUNET_PEERSTORE_IterateContext *
GNUNET_PEERSTORE_iterate (struct GNUNET_PEERSTORE_Handle *h,
                          const char *sub_system,
                          const struct GNUNET_PeerIdentity *peer,
                          const char *key,
                          struct GNUNET_TIME_Relative timeout,
                          GNUNET_PEERSTORE_Processor callback,
                          void *callback_cls);

