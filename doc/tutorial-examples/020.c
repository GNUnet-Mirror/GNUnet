static void
get_result_iterator (void *cls, struct GNUNET_TIME_Absolute expiration,
                     const struct GNUNET_HashCode *key,
                     const struct GNUNET_PeerIdentity *get_path,
                     unsigned int get_path_length,
                     const struct GNUNET_PeerIdentity *put_path,
                     unsigned int put_path_length,
                     enum GNUNET_BLOCK_Type type, size_t size,
                     const void *data)
{
  // Optionally:
  GNUNET_DHT_get_stop (get_handle);
}

get_handle =
      GNUNET_DHT_get_start (dht_handle,
                            block_type,
                            &key,
                            replication,
                            GNUNET_DHT_RO_NONE,
                            NULL,
                            0,
                            &get_result_iterator,
                            cls)

