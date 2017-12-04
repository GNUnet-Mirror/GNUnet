message_sent_cont (void *cls,
                   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  // Request has left local node
}

struct GNUNET_DHT_PutHandle *
GNUNET_DHT_put (struct GNUNET_DHT_Handle *handle,
                const struct GNUNET_HashCode *key,
                uint32_t desired_replication_level,
                enum GNUNET_DHT_RouteOption options,
                enum GNUNET_BLOCK_Type type,
                size_t size,
                const void *data,
                struct GNUNET_TIME_Absolute exp,
                struct GNUNET_TIME_Relative timeout,
                GNUNET_DHT_PutContinuation cont, void *cont_cls)

