static void
get_callback (void *cls,
              enum GNUNET_DHT_RouteOption options,
              enum GNUNET_BLOCK_Type type,
              uint32_t hop_count,
              uint32_t desired_replication_level,
              unsigned int path_length,
              const struct GNUNET_PeerIdentity *path,
              const struct GNUNET_HashCode * key)
{
}


static void
get_resp_callback (void *cls,
                   enum GNUNET_BLOCK_Type type,
                   const struct GNUNET_PeerIdentity *get_path,
                   unsigned int get_path_length,
                   const struct GNUNET_PeerIdentity *put_path,
                   unsigned int put_path_length,
                   struct GNUNET_TIME_Absolute exp,
                   const struct GNUNET_HashCode * key,
                   const void *data,
                   size_t size)
{
}


static void
put_callback (void *cls,
              enum GNUNET_DHT_RouteOption options,
              enum GNUNET_BLOCK_Type type,
              uint32_t hop_count,
              uint32_t desired_replication_level,
              unsigned int path_length,
              const struct GNUNET_PeerIdentity *path,
              struct GNUNET_TIME_Absolute exp,
              const struct GNUNET_HashCode * key,
              const void *data,
              size_t size)
{
}


monitor_handle = GNUNET_DHT_monitor_start (dht_handle,
                                          block_type,
                                          key,
                                          &get_callback,
                                          &get_resp_callback,
                                          &put_callback,
                                          cls);

