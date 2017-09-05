struct GNUNET_PEERSTORE_StoreContext *
GNUNET_PEERSTORE_store (struct GNUNET_PEERSTORE_Handle *h,
                        const char *sub_system,
                        const struct GNUNET_PeerIdentity *peer,
                        const char *key,
                        const void *value,
                        size_t size,
                        struct GNUNET_TIME_Absolute expiry,
                        enum GNUNET_PEERSTORE_StoreOption options,
                        GNUNET_PEERSTORE_Continuation cont,
                        void *cont_cls);

